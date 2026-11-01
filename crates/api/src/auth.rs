//! Sign-in. tinyclient opens the system browser at a provider and gets the result on a
//! loopback redirect (RFC 8252), with its own PKCE pair between it and this server.
//!
//! `start` keeps a pending sign-in for 10 minutes. The provider sends the browser to `callback`,
//! which spends the pending sign-in, makes the code exchange, checks the ID token, and sends the
//! browser on to tinyclient with a one-time code that lives 60 seconds. `token` trades that code
//! and the client's verifier for a session. A provider ends sessions it started through
//! `backchannel-logout`. Codes, tokens, and secrets are never logged.
//!
//! When the provider makes accounts (Pocket ID) and the sign-in carries an invite, `start` sends
//! the browser to `join` first, a page here that asks whether the person is new. Someone with an
//! account goes on to the provider as usual. Someone new gets one single-use sign-up link at the
//! provider, made only while the invite could still be accepted and only once per sign-in; they
//! make their account and passkey there in a new tab, then come back and continue into the
//! provider's sign-in, where their new session signs them straight in.

use std::collections::HashMap;
use std::sync::LazyLock;

use axum::extract::rejection::{FormRejection, JsonRejection, QueryRejection};
use axum::extract::{Form, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use db::{AuthError, GrantReason, PgPool, SignupClaim};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::oidc::{Provider, SignIn};

pub fn routes(sign_in: SignIn) -> Router<PgPool> {
    let mut routes = Router::new()
        .route("/v1/auth/config", get(config))
        .route("/v1/auth/start", post(start))
        .route("/v1/auth/join", get(join).post(join_new))
        .route("/v1/auth/callback", get(callback))
        .route("/v1/auth/token", post(token))
        .route("/v1/auth/backchannel-logout", post(backchannel_logout));
    // Only when TINYSERVER_AUTH turns passkeys on: otherwise these paths do not exist.
    if sign_in.passkeys().is_some() {
        routes = routes.merge(crate::passkey::routes());
    }
    routes.layer(Extension(sign_in))
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

/// `GET` and `POST /v1/auth/join`: the pending sign-in, by the state sent to the provider.
#[derive(Deserialize)]
struct JoinForm {
    state: Option<String>,
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
    // `methods` stays `["oidc"]`: tinyclient runs the same browser flow for either, and an older
    // one must not meet a value it does not know.
    let passkey = sign_in.passkeys().map(|_| ProviderEntry {
        id: crate::passkey::PROVIDER_ID,
        name: "Passkey",
    });
    Json(Config {
        methods: ["oidc"],
        provider_name: sign_in.provider_name(),
        providers: passkey
            .into_iter()
            .chain(sign_in.providers().iter().map(|provider| ProviderEntry {
                id: provider.id(),
                name: provider.name(),
            }))
            .collect(),
    })
    .into_response()
}

async fn start(
    State(pool): State<PgPool>,
    Extension(sign_in): Extension<SignIn>,
    body: Result<Json<StartBody>, JsonRejection>,
) -> Result<Json<Started>, AuthApiError> {
    let Json(body) = body.map_err(|_| {
        auth_refused("/v1/auth/start", "bad_json");
        AuthApiError::BadRequest
    })?;
    let invite = body.invite.as_deref().filter(|invite| !invite.is_empty());
    // With passkeys on, sign-in opens the passkey page unless the client names a provider.
    let passkey_page = sign_in.passkeys().is_some()
        && body
            .provider
            .as_deref()
            .is_none_or(|id| id == crate::passkey::PROVIDER_ID);
    let provider = if passkey_page {
        // The provider that stays the way in beside it, if one is configured.
        sign_in.provider(None)
    } else {
        let Some(provider) = sign_in.provider(body.provider.as_deref()) else {
            auth_refused("/v1/auth/start", "provider_missing");
            return Err(AuthApiError::BadRequest);
        };
        Some(provider)
    };
    let reason = if !loopback_redirect(&body.redirect_uri) {
        "bad_redirect"
    } else if body.code_challenge_method != "S256"
        || !db::pkce_challenge_shaped(&body.code_challenge)
    {
        "bad_pkce"
    } else if !client_state_shaped(&body.state) {
        "bad_state"
    } else if !invite.is_none_or(invite_shaped) {
        "bad_invite"
    } else {
        ""
    };
    if !reason.is_empty() {
        auth_refused("/v1/auth/start", reason);
        return Err(AuthApiError::BadRequest);
    }
    // With no provider at all the verifier and nonce have no use; the row still needs them.
    let begun = match provider {
        Some(provider) => provider.begin(),
        None => crate::oidc::Begun {
            authorize_url: String::new(),
            state: db::random_id(),
            verifier: "-".to_string(),
            nonce: "-".to_string(),
        },
    };
    let provider_id = provider.map_or(crate::passkey::PROVIDER_ID, |provider| provider.id());
    db::save_pending(
        &pool,
        &db::PendingLogin {
            state: &begun.state,
            provider: provider_id,
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
    if passkey_page {
        tracing::info!(
            provider = provider_id,
            invite = invite.is_some(),
            "sign-in started"
        );
        return Ok(Json(Started {
            authorize_url: crate::passkey::page_url(sign_in.public_url(), &begun.state),
        }));
    }
    // Someone with an invite may have no account at the provider yet. A provider that makes
    // accounts gets the question first, here.
    let ask = provider.is_some_and(|provider| invite.is_some() && provider.makes_accounts());
    tracing::info!(
        provider = provider_id,
        invite = invite.is_some(),
        ask,
        "sign-in started"
    );
    let authorize_url = if ask {
        join_url(sign_in.public_url(), &begun.state)
    } else {
        begun.authorize_url
    };
    Ok(Json(Started { authorize_url }))
}

fn auth_refused(route: &'static str, reason: &'static str) {
    tracing::warn!(route, reason, "auth refused");
}

pub(crate) fn grant_reason(reason: GrantReason) -> &'static str {
    match reason {
        GrantReason::Unknown => "unknown",
        GrantReason::Used => "used",
        GrantReason::Expired => "expired",
        GrantReason::Verifier => "verifier",
    }
}

fn join_url(public_url: &str, state: &str) -> String {
    let mut url = format!("{public_url}/v1/auth/join");
    if let Ok(mut parsed) = Url::parse(&url) {
        parsed.query_pairs_mut().append_pair("state", state);
        url = parsed.to_string();
    }
    url
}

/// The state from a join request, if it is shaped like one this server made.
fn join_state(form: Option<JoinForm>) -> Option<String> {
    form?.state.filter(|state| {
        (1..=256).contains(&state.len())
            && state
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    })
}

/// The provider a pending sign-in went to, when it still makes accounts.
fn account_maker<'a>(sign_in: &'a SignIn, leg: &db::ProviderLeg) -> Option<&'a Provider> {
    sign_in
        .provider(Some(&leg.provider))
        .filter(|provider| provider.makes_accounts())
}

/// `GET /v1/auth/join`: new here, or already have an account? Nothing is spent or made.
async fn join(
    State(pool): State<PgPool>,
    Extension(sign_in): Extension<SignIn>,
    query: Result<Query<JoinForm>, QueryRejection>,
) -> Response {
    let Some(state) = join_state(query.ok().map(|Query(form)| form)) else {
        return expired();
    };
    let leg = match db::invited_pending(&pool, &state).await {
        Ok(Some(leg)) => leg,
        Ok(None) => return expired(),
        Err(error) => {
            tracing::warn!(%error, "pending sign-in not read");
            return server_trouble();
        }
    };
    let Some(provider) = account_maker(&sign_in, &leg) else {
        return expired();
    };
    let authorize_url = provider.authorize_url(&state, &leg.nonce, &leg.verifier);
    choice_page(
        StatusCode::OK,
        provider.name(),
        &state,
        &authorize_url,
        None,
    )
}

/// `POST /v1/auth/join`: someone new. One sign-up link at the provider, for a sign-in whose
/// invite could still be accepted, and never a second for the same sign-in.
async fn join_new(
    State(pool): State<PgPool>,
    Extension(sign_in): Extension<SignIn>,
    form: Result<Form<JoinForm>, FormRejection>,
) -> Response {
    let Some(state) = join_state(form.ok().map(|Form(form)| form)) else {
        return expired();
    };
    let leg = match db::claim_signup(&pool, &state).await {
        Ok(SignupClaim::Claimed(leg)) => leg,
        Ok(SignupClaim::AlreadyMade(leg)) => {
            let Some(provider) = account_maker(&sign_in, &leg) else {
                return expired();
            };
            let authorize_url = provider.authorize_url(&state, &leg.nonce, &leg.verifier);
            return already_made_page(provider.name(), &authorize_url);
        }
        Ok(SignupClaim::InviteUnusable) => return invite_unusable(&pool, &state).await,
        Ok(SignupClaim::Gone) => return expired(),
        Err(error) => {
            tracing::warn!(%error, "sign-up not claimed");
            return server_trouble();
        }
    };
    let Some(provider) = account_maker(&sign_in, &leg) else {
        release(&pool, &state).await;
        return expired();
    };
    let authorize_url = provider.authorize_url(&state, &leg.nonce, &leg.verifier);
    match provider.signup_link().await {
        Ok(link) => {
            tracing::info!(provider = %provider.id(), "sign-up link made for an invite");
            signup_page(provider.name(), &link.0, &authorize_url)
        }
        Err(failure) => {
            tracing::warn!(provider = %provider.id(), %failure, "sign-up link not made");
            release(&pool, &state).await;
            choice_page(
                StatusCode::BAD_GATEWAY,
                provider.name(),
                &state,
                &authorize_url,
                Some("The sign-up link could not be made just now. Try again in a moment."),
            )
        }
    }
}

async fn release(pool: &PgPool, state: &str) {
    if let Err(error) = db::release_signup(pool, state).await {
        tracing::warn!(%error, "sign-up claim not released");
    }
}

/// The invite cannot be accepted any more: the sign-in ends, and tinyclient hears why.
async fn invite_unusable(pool: &PgPool, state: &str) -> Response {
    tracing::info!("sign-up refused: the invite is unknown, expired, or used up");
    match db::take_pending(pool, state).await {
        Ok(Some(pending)) => back_to_client(
            &pending.client_redirect,
            &pending.client_state,
            Outcome::Error("not_member"),
        ),
        Ok(None) => expired(),
        Err(error) => {
            tracing::warn!(%error, "pending sign-in not read");
            server_trouble()
        }
    }
}

async fn callback(
    State(pool): State<PgPool>,
    Extension(sign_in): Extension<SignIn>,
    query: Result<Query<CallbackQuery>, QueryRejection>,
) -> Response {
    let Ok(Query(query)) = query else {
        auth_refused("/v1/auth/callback", "bad_json");
        return expired();
    };
    let Some(state) = query
        .state
        .filter(|state| !state.is_empty() && state.len() <= 256)
    else {
        auth_refused("/v1/auth/callback", "bad_state");
        return expired();
    };
    let pending = match db::take_pending(&pool, &state).await {
        Ok(Some(pending)) => pending,
        Ok(None) => return expired(),
        Err(error) => {
            tracing::warn!(%error, "pending sign-in not read");
            return server_trouble();
        }
    };
    let back =
        |outcome: Outcome| back_to_client(&pending.client_redirect, &pending.client_state, outcome);
    // A provider removed from the configuration since the sign-in started.
    let Some(provider) = sign_in.provider(Some(&pending.provider)) else {
        auth_refused("/v1/auth/callback", "provider_missing");
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
        auth_refused("/v1/auth/callback", "missing_code");
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
        Err(AuthError::Banned) => {
            tracing::info!(provider = %provider.id(), "sign-in refused: banned");
            return back(Outcome::Error("banned"));
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
    let Json(body) = body.map_err(|_| {
        auth_refused("/v1/auth/token", "bad_json");
        AuthApiError::InvalidGrant
    })?;
    let opened = db::redeem_code(
        &pool,
        &body.code,
        &body.code_verifier,
        sign_in.session_days(),
    )
    .await
    .map_err(|error| match error {
        AuthError::NotMember | AuthError::Banned => AuthApiError::InvalidGrant,
        AuthError::InvalidGrant(reason) => {
            tracing::warn!(reason = grant_reason(reason), "auth grant refused");
            AuthApiError::InvalidGrant
        }
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

pub(crate) enum Outcome {
    Code(String),
    Error(&'static str),
}

/// Where tinyclient's loopback listener is told the result: the one-time code or an error, and
/// the client's own state. `None` when the stored redirect is not a URL, which
/// `loopback_redirect` rules out before it is stored.
pub(crate) fn client_url(redirect: &str, client_state: &str, outcome: &Outcome) -> Option<String> {
    let mut url = Url::parse(redirect).ok()?;
    {
        let mut pairs = url.query_pairs_mut();
        match outcome {
            Outcome::Code(code) => pairs.append_pair("code", code),
            Outcome::Error(error) => pairs.append_pair("error", error),
        };
        pairs.append_pair("state", client_state);
    }
    Some(url.to_string())
}

/// `302` to tinyclient's loopback listener with the one-time code or an error, and its state.
fn back_to_client(redirect: &str, client_state: &str, outcome: Outcome) -> Response {
    let Some(url) = client_url(redirect, client_state, &outcome) else {
        return expired();
    };
    match HeaderValue::from_str(&url) {
        Ok(location) => (StatusCode::FOUND, [(header::LOCATION, location)]).into_response(),
        Err(_) => expired(),
    }
}

pub(crate) fn expired() -> Response {
    page(
        StatusCode::BAD_REQUEST,
        "Sign-in expired",
        "This sign-in expired. Start again from tinyclient.",
    )
}

pub(crate) fn server_trouble() -> Response {
    page(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Sign-in failed",
        "Something went wrong on the server. Start again from tinyclient.",
    )
}

/// The one stylesheet every page here carries, inline. The policy allows exactly it.
pub(crate) const STYLE: &str =
    "body{margin:0;font:16px/1.5 system-ui,-apple-system,'Segoe UI',sans-serif;\
color:#1d1d1f;background:#f5f5f7;display:flex;justify-content:center}\
main{max-width:28rem;margin:4rem 1.25rem;padding:2rem;background:#fff;border-radius:12px;\
box-shadow:0 1px 3px rgba(0,0,0,.12)}\
h1{font-size:1.4rem;margin:0 0 .75rem}p{margin:.5rem 0 1rem}\
.choice{display:flex;flex-direction:column;gap:.75rem;margin-top:1.5rem}\
form{margin:0}\
.button{display:block;box-sizing:border-box;width:100%;padding:.75rem 1rem;border-radius:8px;\
border:1px solid #0a66d8;background:#0a66d8;color:#fff;font:inherit;font-weight:600;\
text-align:center;text-decoration:none;cursor:pointer}\
.button.quiet{background:#fff;color:#0a66d8}\
.step{font-weight:600;margin-top:1.5rem}.note{color:#6e6e73;font-size:.875rem}\
.alert{color:#b3261e}\
@media (prefers-color-scheme:dark){body{color:#f5f5f7;background:#1d1d1f}\
main{background:#2c2c2e;box-shadow:none}.button.quiet{background:#2c2c2e;color:#6cb0ff}\
.note{color:#a1a1a6}.alert{color:#ff8a80}}";

/// No script, nothing loaded, only the stylesheet above, forms only to here, no framing.
static POLICY: LazyLock<HeaderValue> = LazyLock::new(|| {
    let hash = STANDARD.encode(Sha256::digest(STYLE.as_bytes()));
    HeaderValue::from_str(&format!(
        "default-src 'none'; style-src 'sha256-{hash}'; form-action 'self'; \
         base-uri 'none'; frame-ancestors 'none'"
    ))
    .unwrap_or_else(|_| HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"))
});

/// A small page for the browser. Every piece of text is escaped, and it may load nothing.
fn page(status: StatusCode, title: &str, message: &str) -> Response {
    html(status, title, &format!("<p>{}</p>", escape(message)))
}

/// A page around `body`, which the caller has escaped.
fn html(status: StatusCode, title: &str, body: &str) -> Response {
    let title = escape(title);
    let page = format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta name=\"referrer\" content=\"no-referrer\">\n\
         <title>{title}</title>\n<style>{STYLE}</style>\n</head>\n<body>\n<main>\n\
         <h1>{title}</h1>\n{body}\n</main>\n</body>\n</html>\n"
    );
    (
        status,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            ),
            (header::CONTENT_SECURITY_POLICY, POLICY.clone()),
        ],
        page,
    )
        .into_response()
}

/// New here, or already have an account at `provider`?
fn choice_page(
    status: StatusCode,
    provider: &str,
    state: &str,
    authorize_url: &str,
    alert: Option<&str>,
) -> Response {
    let provider = escape(provider);
    let alert = alert
        .map(|alert| format!("<p class=\"alert\">{}</p>\n", escape(alert)))
        .unwrap_or_default();
    let body = format!(
        "{alert}<p>You have an invite. This server signs people in with {provider}.</p>\n\
         <div class=\"choice\">\n\
         <form method=\"post\" action=\"/v1/auth/join\">\n\
         <input type=\"hidden\" name=\"state\" value=\"{state}\">\n\
         <button class=\"button\" type=\"submit\">I'm new here</button>\n\
         </form>\n\
         <a class=\"button quiet\" href=\"{authorize}\">I already have an account</a>\n\
         </div>\n\
         <p class=\"note\">New here: you make a {provider} account with a passkey, then come \
         back to this page.</p>",
        state = escape(state),
        authorize = escape(authorize_url),
    );
    html(status, "Join with your invite", &body)
}

/// The sign-up link, then the way on into sign-in.
fn signup_page(provider: &str, signup_url: &str, authorize_url: &str) -> Response {
    let provider = escape(provider);
    let body = format!(
        "<p class=\"step\">1. Make your account</p>\n\
         <p>Make your {provider} account and its passkey. It opens in a new tab; keep this one.</p>\n\
         <a class=\"button\" href=\"{signup}\" target=\"_blank\" rel=\"noopener noreferrer\">\
         Make my account</a>\n\
         <p class=\"step\">2. Come back and continue</p>\n\
         <p>Once your passkey is made, continue here to finish joining.</p>\n\
         <a class=\"button quiet\" href=\"{authorize}\">Continue</a>\n\
         <p class=\"note\">The sign-up link works once, for 15 minutes.</p>",
        signup = escape(signup_url),
        authorize = escape(authorize_url),
    );
    html(StatusCode::OK, "Make your account", &body)
}

/// A second "I'm new here" on the same sign-in: no second link.
fn already_made_page(provider: &str, authorize_url: &str) -> Response {
    let body = format!(
        "<p>A sign-up link was already made for this sign-in. If you made your {provider} \
         account, continue. If not, start again from tinyclient.</p>\n\
         <a class=\"button\" href=\"{authorize}\">Continue</a>",
        provider = escape(provider),
        authorize = escape(authorize_url),
    );
    html(StatusCode::OK, "Sign-up link already made", &body)
}

/// `429` for the join form, as a page.
pub(crate) fn slow_down_page() -> Response {
    page(
        StatusCode::TOO_MANY_REQUESTS,
        "Too many tries",
        "Wait a minute, then go back and try again.",
    )
}

pub(crate) fn escape(text: &str) -> String {
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
pub(crate) fn client_state_shaped(state: &str) -> bool {
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
    use super::{client_state_shaped, escape, grant_reason, loopback_redirect};
    use db::GrantReason;

    #[test]
    fn grant_reasons_are_static() {
        assert_eq!(grant_reason(GrantReason::Expired), "expired");
        assert_eq!(grant_reason(GrantReason::Verifier), "verifier");
        assert_eq!(grant_reason(GrantReason::Unknown), "unknown");
        assert_eq!(grant_reason(GrantReason::Used), "used");
    }

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
