//! Sign-in. tinyclient opens the system browser at a provider and gets the result on a
//! loopback redirect (RFC 8252), with its own PKCE pair between it and this server.
//!
//! `start` keeps a pending sign-in for 10 minutes. The provider sends the browser to `callback`,
//! which spends the pending sign-in, makes the code exchange, checks the ID token, and sends the
//! browser on to tinyclient with a one-time code that lives 60 seconds. `token` trades that code
//! and the client's verifier for a session. A provider ends sessions it started through
//! `backchannel-logout`. Codes, tokens, and secrets are never logged.

use std::collections::HashMap;

use axum::extract::rejection::{FormRejection, JsonRejection, QueryRejection};
use axum::extract::{Form, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use db::{AuthError, PgPool};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::oidc::SignIn;

pub fn routes(sign_in: SignIn) -> Router<PgPool> {
    Router::new()
        .route("/v1/auth/config", get(config))
        .route("/v1/auth/start", post(start))
        .route("/v1/auth/callback", get(callback))
        .route("/v1/auth/token", post(token))
        .route("/v1/auth/backchannel-logout", post(backchannel_logout))
        .layer(Extension(sign_in))
}

#[derive(Serialize)]
struct Config<'a> {
    methods: [&'static str; 1],
    /// The default provider's name, for clients that show one button.
    provider_name: &'a str,
    providers: Vec<ProviderEntry<'a>>,
}

#[derive(Serialize)]
struct ProviderEntry<'a> {
    id: &'a str,
    name: &'a str,
}

#[derive(Deserialize)]
struct StartBody {
    redirect_uri: String,
    code_challenge: String,
    code_challenge_method: String,
    state: String,
    invite: Option<String>,
    /// A provider id from `/v1/auth/config`. The first when absent.
    provider: Option<String>,
}

#[derive(Serialize)]
struct Started {
    authorize_url: String,
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    /// RFC 9207. When the provider sends it, it must be the provider the sign-in went to.
    iss: Option<String>,
}

#[derive(Deserialize)]
struct TokenBody {
    code: String,
    code_verifier: String,
}

#[derive(Serialize)]
struct Opened {
    token: String,
    user_id: String,
    email: Option<String>,
    display_name: String,
    role: String,
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

enum AuthApiError {
    BadRequest,
    InvalidGrant,
    /// Back-channel logout, OpenID Connect Back-Channel Logout 1.0 section 2.8.
    InvalidRequest,
    Unavailable,
}

impl IntoResponse for AuthApiError {
    fn into_response(self) -> Response {
        let (status, error) = match self {
            Self::BadRequest => (StatusCode::BAD_REQUEST, "bad_request"),
            Self::InvalidGrant => (StatusCode::BAD_REQUEST, "invalid_grant"),
            Self::InvalidRequest => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::Unavailable => (StatusCode::INTERNAL_SERVER_ERROR, "unavailable"),
        };
        (status, Json(ErrorBody { error })).into_response()
    }
}

async fn config(Extension(sign_in): Extension<SignIn>) -> Response {
    Json(Config {
        methods: ["oidc"],
        provider_name: sign_in.provider_name(),
        providers: sign_in
            .providers()
            .iter()
            .map(|provider| ProviderEntry {
                id: provider.id(),
                name: provider.name(),
            })
            .collect(),
    })
    .into_response()
}

async fn start(
    State(pool): State<PgPool>,
    Extension(sign_in): Extension<SignIn>,
    body: Result<Json<StartBody>, JsonRejection>,
) -> Result<Json<Started>, AuthApiError> {
    let Json(body) = body.map_err(|_| AuthApiError::BadRequest)?;
    let invite = body.invite.as_deref().filter(|invite| !invite.is_empty());
    let provider = sign_in
        .provider(body.provider.as_deref())
        .ok_or(AuthApiError::BadRequest)?;
    let valid = loopback_redirect(&body.redirect_uri)
        && body.code_challenge_method == "S256"
        && db::pkce_challenge_shaped(&body.code_challenge)
        && client_state_shaped(&body.state)
        && invite.is_none_or(invite_shaped);
    if !valid {
        return Err(AuthApiError::BadRequest);
    }
    let begun = provider.begin();
    db::save_pending(
        &pool,
        &db::PendingLogin {
            state: &begun.state,
            provider: provider.id(),
            verifier: &begun.verifier,
            nonce: &begun.nonce,
            client_redirect: &body.redirect_uri,
            client_challenge: &body.code_challenge,
            client_state: &body.state,
            invite,
        },
    )
    .await
    .map_err(|error| {
        tracing::warn!(%error, "pending sign-in not saved");
        AuthApiError::Unavailable
    })?;
    tracing::info!(provider = %provider.id(), invite = invite.is_some(), "sign-in started");
    Ok(Json(Started {
        authorize_url: begun.authorize_url,
    }))
}

async fn callback(
    State(pool): State<PgPool>,
    Extension(sign_in): Extension<SignIn>,
    query: Result<Query<CallbackQuery>, QueryRejection>,
) -> Response {
    let Ok(Query(query)) = query else {
        return expired();
    };
    let Some(state) = query
        .state
        .filter(|state| !state.is_empty() && state.len() <= 256)
    else {
        return expired();
    };
    let pending = match db::take_pending(&pool, &state).await {
        Ok(Some(pending)) => pending,
        Ok(None) => return expired(),
        Err(error) => {
            tracing::warn!(%error, "pending sign-in not read");
            return page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Sign-in failed",
                "Something went wrong on the server. Start again from tinyclient.",
            );
        }
    };
    let back =
        |outcome: Outcome| back_to_client(&pending.client_redirect, &pending.client_state, outcome);
    // A provider removed from the configuration since the sign-in started.
    let Some(provider) = sign_in.provider(Some(&pending.provider)) else {
        return back(Outcome::Error("failed"));
    };
    if query
        .iss
        .as_deref()
        .is_some_and(|iss| iss != provider.issuer())
    {
        tracing::warn!(provider = %provider.id(), "sign-in failed: callback iss is another issuer");
        return back(Outcome::Error("failed"));
    }

    if let Some(error) = query.error {
        let denied = matches!(
            error.as_str(),
            "access_denied" | "consent_required" | "login_required" | "interaction_required"
        );
        tracing::info!(provider = %provider.id(), denied, "provider returned an error");
        return back(if denied {
            Outcome::Error("denied")
        } else {
            Outcome::Error("failed")
        });
    }
    let Some(code) = query
        .code
        .filter(|code| !code.is_empty() && code.len() <= 2048)
    else {
        return back(Outcome::Error("failed"));
    };

    let verified = match provider
        .finish(&code, &pending.verifier, &pending.nonce)
        .await
    {
        Ok(verified) => verified,
        Err(failure) => {
            tracing::warn!(provider = %provider.id(), %failure, "sign-in failed");
            return back(Outcome::Error("failed"));
        }
    };
    let signed_in = match db::sign_in(
        &pool,
        &verified.profile,
        pending.invite_hash.as_deref(),
        verified.groups,
    )
    .await
    {
        Ok(signed_in) => signed_in,
        Err(AuthError::NotMember) => {
            tracing::info!(
                provider = %provider.id(),
                invite = pending.invite_hash.is_some(),
                "sign-in refused: not a member"
            );
            return back(Outcome::Error("not_member"));
        }
        Err(error) => {
            tracing::warn!(%error, "sign-in not recorded");
            return back(Outcome::Error("failed"));
        }
    };
    let issued = db::issue_code(
        &pool,
        &signed_in.user_id,
        &pending.client_challenge,
        &verified.profile.issuer,
        verified.profile.sid.as_deref(),
    )
    .await;
    match issued {
        Ok(code) => {
            tracing::info!(
                provider = %provider.id(),
                user_id = %signed_in.user_id,
                role = %signed_in.role,
                joined = signed_in.joined,
                "signed in at the provider"
            );
            back(Outcome::Code(code))
        }
        Err(error) => {
            tracing::warn!(%error, "one-time code not saved");
            back(Outcome::Error("failed"))
        }
    }
}

async fn token(
    State(pool): State<PgPool>,
    Extension(sign_in): Extension<SignIn>,
    body: Result<Json<TokenBody>, JsonRejection>,
) -> Result<Json<Opened>, AuthApiError> {
    let Json(body) = body.map_err(|_| AuthApiError::InvalidGrant)?;
    let opened = db::redeem_code(
        &pool,
        &body.code,
        &body.code_verifier,
        sign_in.session_days(),
    )
    .await
    .map_err(|error| match error {
        AuthError::NotMember | AuthError::InvalidGrant => AuthApiError::InvalidGrant,
        AuthError::Database(error) => {
            tracing::warn!(%error, "one-time code not redeemed");
            AuthApiError::Unavailable
        }
    })?;
    tracing::info!(user_id = %opened.identity.user_id, "session opened");
    Ok(Json(Opened {
        token: opened.token,
        user_id: opened.identity.user_id,
        email: opened.identity.email,
        display_name: opened.identity.display_name,
        role: opened.identity.role,
    }))
}

/// OpenID Connect Back-Channel Logout 1.0. The provider posts a signed `logout_token`; the
/// sessions it started for that `sid` or `sub` end. `200` with no body, else `400`.
async fn backchannel_logout(
    State(pool): State<PgPool>,
    Extension(sign_in): Extension<SignIn>,
    form: Result<Form<HashMap<String, String>>, FormRejection>,
) -> Result<StatusCode, AuthApiError> {
    let Form(form) = form.map_err(|_| AuthApiError::InvalidRequest)?;
    let token = form
        .get("logout_token")
        .filter(|token| !token.is_empty() && token.len() <= 8 * 1024)
        .ok_or(AuthApiError::InvalidRequest)?;
    let logout = sign_in.logout(token).await.map_err(|failure| {
        tracing::warn!(%failure, "back-channel logout refused");
        AuthApiError::InvalidRequest
    })?;
    let ended = db::end_provider_sessions(
        &pool,
        &logout.issuer,
        logout.subject.as_deref(),
        logout.sid.as_deref(),
    )
    .await
    .map_err(|error| {
        tracing::warn!(%error, "back-channel logout not recorded");
        AuthApiError::Unavailable
    })?;
    tracing::info!(issuer = %logout.issuer, ended, "back-channel logout");
    Ok(StatusCode::OK)
}

enum Outcome {
    Code(String),
    Error(&'static str),
}

/// `302` to tinyclient's loopback listener with the one-time code or an error, and its state.
fn back_to_client(redirect: &str, client_state: &str, outcome: Outcome) -> Response {
    // Checked by `loopback_redirect` before it was stored.
    let Ok(mut url) = Url::parse(redirect) else {
        return expired();
    };
    {
        let mut pairs = url.query_pairs_mut();
        match &outcome {
            Outcome::Code(code) => pairs.append_pair("code", code),
            Outcome::Error(error) => pairs.append_pair("error", error),
        };
        pairs.append_pair("state", client_state);
    }
    match HeaderValue::from_str(url.as_str()) {
        Ok(location) => (StatusCode::FOUND, [(header::LOCATION, location)]).into_response(),
        Err(_) => expired(),
    }
}

fn expired() -> Response {
    page(
        StatusCode::BAD_REQUEST,
        "Sign-in expired",
        "This sign-in expired. Start again from tinyclient.",
    )
}

/// A small page for the browser. Every piece of text is escaped, and it may load nothing.
fn page(status: StatusCode, title: &str, message: &str) -> Response {
    let title = escape(title);
    let message = escape(message);
    let body = format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{title}</title>\n</head>\n<body>\n<h1>{title}</h1>\n<p>{message}</p>\n</body>\n</html>\n"
    );
    (
        status,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            ),
            (
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
            ),
        ],
        body,
    )
        .into_response()
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// Exactly `http://127.0.0.1:<port>/callback` or `http://[::1]:<port>/callback`, port 1 to
/// 65535 in plain digits. No other host, scheme, path, query, or fragment.
fn loopback_redirect(redirect: &str) -> bool {
    let Some(rest) = redirect
        .strip_prefix("http://127.0.0.1:")
        .or_else(|| redirect.strip_prefix("http://[::1]:"))
    else {
        return false;
    };
    let Some((port, path)) = rest.split_once('/') else {
        return false;
    };
    let port_ok = (1..=5).contains(&port.len())
        && !port.starts_with('0')
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|port| port > 0);
    port_ok && path == "callback"
}

/// The client's own state: 16 to 128 characters from the URL unreserved set.
fn client_state_shaped(state: &str) -> bool {
    (16..=128).contains(&state.len())
        && state
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

/// An invite token as `POST /v1/invites` returns it: URL-safe base64.
fn invite_shaped(invite: &str) -> bool {
    (1..=128).contains(&invite.len())
        && invite
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::{client_state_shaped, escape, loopback_redirect};

    #[test]
    fn only_a_loopback_callback_is_a_redirect() {
        for good in [
            "http://127.0.0.1:53121/callback",
            "http://127.0.0.1:1/callback",
            "http://127.0.0.1:65535/callback",
            "http://[::1]:8080/callback",
        ] {
            assert!(loopback_redirect(good), "{good}");
        }
        for bad in [
            "http://127.0.0.1/callback",
            "http://127.0.0.1:0/callback",
            "http://127.0.0.1:65536/callback",
            "http://127.0.0.1:080/callback",
            "http://127.0.0.1:53121/callback/",
            "http://127.0.0.1:53121/callback?x=1",
            "http://127.0.0.1:53121/callback#x",
            "http://127.0.0.1:53121/other",
            "http://127.0.0.1:53121",
            "http://127.0.0.1:53121@evil.example/callback",
            "http://localhost:53121/callback",
            "https://127.0.0.1:53121/callback",
            "http://127.0.0.2:53121/callback",
            "http://[::1]/callback",
            "http://evil.example:53121/callback",
            "tinyclient://callback",
            "",
        ] {
            assert!(!loopback_redirect(bad), "{bad}");
        }
    }

    #[test]
    fn a_client_state_is_16_to_128_unreserved_characters() {
        assert!(client_state_shaped(&"a".repeat(16)));
        assert!(client_state_shaped(&"a-._~".repeat(25)));
        assert!(!client_state_shaped(&"a".repeat(15)));
        assert!(!client_state_shaped(&"a".repeat(129)));
        assert!(!client_state_shaped(&format!("{}&x=1", "a".repeat(16))));
    }

    #[test]
    fn page_text_is_escaped() {
        assert_eq!(
            escape(r#"<script>alert("x")</script> & 'y'"#),
            "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; &#39;y&#39;"
        );
    }
}
