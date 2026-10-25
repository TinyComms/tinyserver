//! HTTP surface. Health, session, account, rooms, people, invites, and the live socket.
//! Media does not enter this crate; it talks to `sfu` over channels.

mod account;
mod community;
mod health;
mod limit;
mod live;
mod session;

pub use live::{Limits, Live};

use axum::extract::{DefaultBodyLimit, Request};
use axum::http::{header, HeaderName, HeaderValue};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::Router;
use db::PgPool;

/// The REST routes without `GET /v1/live`.
pub fn router(pool: PgPool) -> Router {
    build(pool, None)
}

/// The REST routes and `GET /v1/live`, fed by `live`.
pub fn app(pool: PgPool, live: Live) -> Router {
    build(pool, Some(live))
}

fn build(pool: PgPool, live: Option<Live>) -> Router {
    let mut routes = Router::new()
        .merge(health::routes(live.clone()))
        .merge(session::routes())
        .merge(account::routes())
        .merge(community::routes());
    if let Some(live) = live {
        routes = routes.merge(live::routes(live));
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
