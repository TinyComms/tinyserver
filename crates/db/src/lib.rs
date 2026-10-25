//! Postgres access for tinyserver.
//!
//! Migrations and the first owner use `DATABASE_URL_MIGRATE` (`app_owner`).
//! The serving process uses `DATABASE_URL` (`app_runtime`) and row level security.

mod account;
mod bootstrap;
mod community;
mod error;
mod migrate;
mod outbox;
mod session;
mod sweep;

pub use account::{change_password, close_all_sessions, rename_me};
pub use bootstrap::{bootstrap_owner, owner_exists};
pub use community::{
    accept_invite, create_invite, create_room, delete_room, end_share, kick_from_call, list_audit,
    list_invites, list_members, list_rooms, remove_member, rename_room, revoke_invite, room_exists,
    set_member_role, Accepted, AuditRow, Caller, CommunityError, Invite, InviteIssued, Member,
    Room, Wrote,
};
pub use error::DbError;
pub use migrate::migrate;
pub use outbox::{outbox_after, outbox_bounds, OutboxBounds, OutboxRow, WAKE_CHANNEL};
pub use session::{
    close_session, current_session, open_session, Identity, OpenedSession, SessionError,
};
pub use sqlx::PgPool;
pub use sweep::{sweep, Swept};

use std::time::Duration;

use sqlx::postgres::PgPoolOptions;

/// Six connections: five for requests, one held by the live dispatcher's `LISTEN`.
pub async fn runtime_pool(url: &str) -> Result<PgPool, DbError> {
    PgPoolOptions::new()
        .max_connections(6)
        .acquire_timeout(Duration::from_secs(3))
        .connect(url)
        .await
        .map_err(DbError::from)
}

pub async fn owner_pool(url: &str) -> Result<PgPool, DbError> {
    runtime_pool(url).await
}
