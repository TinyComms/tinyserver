use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use db::{PgPool, SessionError};
use serde::Serialize;

/// A session is opened by sign-in; see `auth`.
pub fn routes() -> Router<PgPool> {
    Router::new()
        .route("/v1/session", delete(close))
        .route("/v1/me", get(current))
}

#[derive(Serialize)]
pub(crate) struct Current {
    user_id: String,
    email: Option<String>,
    display_name: String,
    /// The legacy role string.
    role: String,
    owner: bool,
    roles: Vec<String>,
    /// Server-wide permission bits.
    permissions: u64,
    rank: i32,
    /// Present for a bot. A person's session omits it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    scopes: Vec<String>,
}

impl From<db::Identity> for Current {
    fn from(identity: db::Identity) -> Self {
        Self {
            user_id: identity.user_id,
            email: identity.email,
            display_name: identity.display_name,
            role: identity.role,
            owner: identity.owner,
            roles: identity.roles,
            permissions: u64::try_from(identity.permissions).unwrap_or(0),
            rank: identity.rank,
            scopes: Vec::new(),
        }
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

enum ApiError {
    Unauthorized,
    Unavailable,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error) = match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Unavailable => (StatusCode::INTERNAL_SERVER_ERROR, "unavailable"),
        };
        (status, Json(ErrorBody { error })).into_response()
    }
}

fn failure(error: SessionError, denied: ApiError) -> ApiError {
    match error {
        SessionError::Unauthorized => denied,
        SessionError::Database(error) => {
            tracing::warn!(%error, "session query failed");
            ApiError::Unavailable
        }
    }
}

async fn current(
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<Current>, ApiError> {
    match presented(&headers) {
        Some(Presented::Bearer(token)) => {
            let identity = db::current_session(&pool, token)
                .await
                .map_err(|error| failure(error, ApiError::Unauthorized))?;
            tracing::info!(user_id = %identity.user_id, "session read");
            Ok(Json(Current::from(identity)))
        }
        Some(Presented::Bot(token)) => {
            let bot = db::authenticate_bot(&pool, token)
                .await
                .map_err(|error| failure(error, ApiError::Unauthorized))?;
            tracing::info!(bot_id = %bot.id, "bot read");
            Ok(Json(Current {
                user_id: bot.id,
                email: None,
                display_name: bot.name,
                role: "bot".to_string(),
                owner: false,
                roles: Vec::new(),
                permissions: 0,
                rank: -1,
                scopes: bot.scopes,
            }))
        }
        None => Err(ApiError::Unauthorized),
    }
}

async fn close(State(pool): State<PgPool>, headers: HeaderMap) -> Result<StatusCode, ApiError> {
    let token = bearer(&headers).ok_or(ApiError::Unauthorized)?;
    let user_id = db::close_session(&pool, token)
        .await
        .map_err(|error| failure(error, ApiError::Unauthorized))?;
    tracing::info!(%user_id, "session closed");
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) fn bearer(headers: &HeaderMap) -> Option<&str> {
    match presented(headers) {
        Some(Presented::Bearer(token)) => Some(token),
        _ => None,
    }
}

pub(crate) enum Presented<'a> {
    Bearer(&'a str),
    Bot(&'a str),
}

/// `Bearer` is a person's session. `Bot` is an application token. The prefix is exact.
pub(crate) fn presented(headers: &HeaderMap) -> Option<Presented<'_>> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    if let Some(token) = value.strip_prefix("Bearer ") {
        return (!token.is_empty()).then_some(Presented::Bearer(token));
    }
    if let Some(token) = value.strip_prefix("Bot ") {
        return (!token.is_empty()).then_some(Presented::Bot(token));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::bearer;
    use axum::http::{header, HeaderMap, HeaderValue};

    #[test]
    fn authorization_is_the_exact_bearer_prefix() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer token-value"),
        );
        assert_eq!(bearer(&headers), Some("token-value"));

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("bearer token-value"),
        );
        assert_eq!(bearer(&headers), None);

        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer "));
        assert_eq!(bearer(&headers), None);

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic token-value"),
        );
        assert_eq!(bearer(&headers), None);
    }

    #[test]
    fn bot_is_its_own_prefix() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bot bot-token"),
        );
        assert!(matches!(
            super::presented(&headers),
            Some(super::Presented::Bot("bot-token"))
        ));
        assert_eq!(bearer(&headers), None);
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bot "));
        assert!(super::presented(&headers).is_none());
    }
}
