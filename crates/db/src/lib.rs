//! Postgres access for tinyserver.
//!
//! Migrations and the owner invite use `DATABASE_URL_MIGRATE` (`app_owner`).
//! The serving process uses `DATABASE_URL` (`app_runtime`) and row level security.

mod account;
mod auth;
mod bootstrap;
mod community;
mod error;
mod migrate;
mod outbox;
mod session;
mod sweep;

pub use account::{close_all_sessions, rename_me};
pub use auth::{
    end_provider_sessions, issue_code, pkce_challenge_shaped, pkce_verifier_shaped, redeem_code,
    s256, save_pending, sign_in, take_pending, AuthError, Groups, Pending, PendingLogin, Profile,
    SignedIn,
};
pub use bootstrap::{owner_exists, owner_invite};
pub use community::{
    create_invite, create_room, delete_room, end_share, kick_from_call, list_audit, list_invites,
    list_members, list_rooms, remove_member, rename_room, revoke_invite, room_exists,
    set_member_role, AuditRow, Caller, CommunityError, Invite, InviteIssued, Member, Room, Wrote,
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
