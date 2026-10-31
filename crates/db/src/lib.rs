//! Postgres access for tinyserver.
//!
//! Migrations and the owner invite use `DATABASE_URL_MIGRATE` (`app_owner`).
//! The serving process uses `DATABASE_URL` (`app_runtime`) and row level security.

mod account;
mod auth;
mod bootstrap;
mod bot;
mod community;
mod error;
mod media;
mod messages;
mod migrate;
mod moderation;
mod outbox;
pub mod perm;
mod roles;
mod scan;
mod server;
mod session;
mod sweep;

pub use account::{close_all_sessions, delete_avatar, get_avatar, rename_me, set_avatar};
pub use auth::{
    claim_signup, end_provider_sessions, invited_pending, issue_code, list_identities,
    pkce_challenge_shaped, pkce_verifier_shaped, redeem_code, release_signup, relink_identity,
    s256, save_pending, sign_in, take_pending, AuthError, Groups, Pending, PendingLogin, Profile,
    ProviderLeg, Relinked, SignedIn, SignupClaim,
};
pub use bootstrap::{bootstrap, owner_exists, owner_invite, Bootstrap};
pub use bot::{authenticate_bot, create_bot, list_bots, revoke_bot, Bot, BotIssued, BotSession};
pub use community::{
    admin_role, create_invite, create_invite_with, create_room, delete_room, list_audit,
    list_invites, list_members, list_rooms, remove_member, rename_room, revoke_invite, room_exists,
    set_member_role, set_member_roles, set_override, set_owner, set_timeout, update_room,
    AuditQuery, AuditRow, Caller, CommunityError, Invite, InviteIssued, InviteOptions, Member,
    NewRoom, Override, Room, RoomPatch, Wrote, DEFAULT_INVITE_SECS,
};
pub use error::DbError;
pub use messages::{
    clear_reaction, create_channel, delete_channel, delete_message, edit_message, list_channels,
    list_directs, list_messages, mark_read, open_attachment, open_direct, post_message,
    save_attachment, set_channel_override, toggle_reaction, typing_recipients, update_channel,
    AttachmentFile, MessageError, NewAttachment,
};
pub use migrate::migrate;
pub use moderation::{
    ban, call_access, end_share, kick_from_call, list_bans, moderate_call, move_in_call,
    room_permissions, touch_seen, unban, Ban, CallAccess,
};
pub use outbox::{outbox_after, outbox_bounds, OutboxBounds, OutboxRow, WAKE_CHANNEL};
pub use roles::{
    create_role, delete_role, list_roles, order_roles, update_role, NewRole, Role, RolePatch,
};
pub use scan::{FakeEngine, ScanEngine, ScanVerdict};
pub use server::{
    create_category, delete_category, delete_icon, get_icon, get_server, list_categories,
    rename_category, set_icon, set_layout, sniff_image, update_server, Category, Icon, Layout,
    LayoutBucket, ServerPatch, ServerSettings, FILE_MAX_DEFAULT, ICON_MAX, IMAGE_MAX_DEFAULT,
    UPLOAD_MAX,
};
pub use session::{
    close_session, current_session, identity, open_session, Identity, OpenedSession, SessionError,
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
