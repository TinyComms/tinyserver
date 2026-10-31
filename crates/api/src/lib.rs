//! HTTP surface. Health, sign-in, session, account, server settings, roles, rooms, people,
//! invites, bans, messages, the audit log, and the live socket.
//! Call media does not enter this crate; it talks to `sfu` over channels.

mod account;
mod admin;
mod auth;
mod bot;
mod community;
mod health;
mod limit;
mod live;
mod messages;
mod oidc;
mod session;

#[cfg(feature = "fuzz")]
pub mod fuzz;

pub use live::{Limits, Live};
pub use oidc::{ConfigError, ProviderConfig, SignIn, SignInConfig, SignupConfig};

use axum::extract::{DefaultBodyLimit, Request};
use axum::http::{header, HeaderName, HeaderValue};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::Router;
use db::PgPool;

/// The REST routes without `GET /v1/live`. Without `sign_in` there is no `/v1/auth`, so no one
/// can sign in; tests open sessions through `db`.
pub fn router(pool: PgPool, sign_in: Option<SignIn>) -> Router {
    build(pool, None, sign_in)
}

/// The REST routes and `GET /v1/live`, fed by `live`.
pub fn app(pool: PgPool, live: Live, sign_in: Option<SignIn>) -> Router {
    build(pool, Some(live), sign_in)
}

fn build(pool: PgPool, live: Option<Live>, sign_in: Option<SignIn>) -> Router {
    let mut routes = Router::new()
        .merge(health::routes(live.clone()))
        .merge(session::routes())
        .merge(account::routes())
        .merge(community::routes())
        .merge(admin::routes())
        .merge(bot::routes())
        .merge(messages::routes());
    if let Some(live) = live {
        routes = routes.merge(live::routes(live));
    }
    if let Some(sign_in) = sign_in {
        routes = routes.merge(auth::routes(sign_in));
    }
    routes
        .layer(DefaultBodyLimit::max(8 * 1024))
        .layer(middleware::from_fn(limit::guard))
        .layer(middleware::from_fn(harden))
        .with_state(pool)
}

async fn harden(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000"),
    );
    response
}
