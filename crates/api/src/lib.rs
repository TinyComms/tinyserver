//! HTTP surface. Health, sign-in, session, account, server settings, roles, rooms, people,
//! invites, bans, messages, end-to-end encrypted text, the audit log, and the live socket.
//! Call media does not enter this crate; it talks to `sfu` over channels.

mod account;
mod admin;
mod auth;
mod bot;
mod community;
mod e2ee_text;
mod health;
mod limit;
mod live;
pub mod media_sign;
mod messages;
mod observe;
mod oidc;
mod operator;
mod passkey;
mod reports;
mod scan_clamd;
mod session;

#[cfg(feature = "fuzz")]
pub mod fuzz;

pub use limit::trust_proxies;
pub use live::{Limits, Live};
pub use oidc::{ConfigError, ProviderConfig, SignIn, SignInConfig, SignupConfig};
pub use operator::Operator;
pub use passkey::{claim_url, Passkeys};
pub use scan_clamd::{engine_from_env, scanning_off, select_engine, NoScan, ScanBootError};

use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Request};
use axum::http::{header, HeaderName, HeaderValue};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::Extension;
use axum::Router;
use db::{PgPool, ScanEngine};

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
    let operator = Operator::new(pool.clone());
    let mut routes = Router::new()
        .merge(health::routes(live.clone()))
        .merge(operator::routes())
        .merge(session::routes())
        .merge(account::routes())
        .merge(community::routes())
        .merge(admin::routes())
        .merge(bot::routes())
        .merge(messages::routes())
        .merge(reports::routes())
        .merge(e2ee_text::routes());
    if let Some(live) = live {
        routes = routes.merge(live::routes(live));
    }
    if let Some(sign_in) = sign_in {
        routes = routes.merge(auth::routes(sign_in));
    }
    routes
        .route_layer(middleware::from_fn(observe::http_span))
        .layer(DefaultBodyLimit::max(8 * 1024))
        .layer(middleware::from_fn(limit::guard))
        // The suspension comes before everything that does work, the sign-in limiter too, so a
        // refused request costs nothing else.
        .layer(middleware::from_fn(operator::gate))
        .layer(middleware::from_fn(harden))
        .layer(Extension(operator))
        .layer(Extension(installed_engine()))
        .layer(Extension(Arc::new(e2ee_text::Server::default())))
        .with_state(pool)
}

fn installed_engine() -> Arc<dyn ScanEngine> {
    match engine_from_env() {
        Ok(engine) => engine,
        Err(error) => panic!("scan engine: {error}"),
    }
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
