//! HTTP surface. Health, session, rooms, people, and invites. Media does not enter this crate.

mod community;
mod health;
mod session;

use axum::Router;
use db::PgPool;

pub fn router(pool: PgPool) -> Router {
    Router::new()
        .merge(health::routes())
        .merge(session::routes())
        .merge(community::routes())
        .with_state(pool)
}
