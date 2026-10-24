//! HTTP surface. Health and session routes. Media does not enter this crate.

mod health;
mod session;

use axum::Router;
use db::PgPool;

pub fn router(pool: PgPool) -> Router {
    Router::new()
        .merge(health::routes())
        .merge(session::routes())
        .with_state(pool)
}
