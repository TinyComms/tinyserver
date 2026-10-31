//! Rooms, membership, invites, and the audit log.
//!
//! Every call from a signed-in person runs in a transaction that sets `app.user_id`. What they
//! may do is read from the database for that id: row level security on the tables, and the
//! `SECURITY DEFINER` functions in `migrations/0005_server.sql` for roles, owners, bans,
//! timeouts, and overrides, which check the permission and the hierarchy themselves. An invite
//! token is returned once; Postgres stores its SHA-256.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Postgres, Row, Transaction};
use thiserror::Error;

use crate::bootstrap::normalize_name;
use crate::outbox::emit;
use crate::perm;
use crate::session::{new_token, token_digest};
use crate::DbError;

pub(crate) const STAMP: &str = "YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"";

#[derive(Debug, Error)]
pub enum CommunityError {
    #[error("forbidden")]
    Forbidden,
    /// The person acted on ranks at or above the caller, or the role is not below them.
    #[error("hierarchy")]
    Hierarchy,
    #[error("not found")]
    NotFound,
    #[error("last owner")]
    LastOwner,
    #[error("invalid")]
    Invalid,
    /// @everyone cannot be deleted, renamed, or ordered.
    #[error("default role")]
    DefaultRole,
    #[error("banned")]
    Banned,
    #[error("already a member")]
    AlreadyMember,
    #[error("idempotency conflict")]
    IdempotencyConflict,
    #[error("idempotency key has no stored response")]
    Incomplete,
    #[error(transparent)]
    Database(#[from] DbError),
}

#[derive(Clone)]
pub struct Caller {
    pub user_id: String,
    /// The legacy role string. Permissions are read from the database, not from this.
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Override {
    pub role_id: String,
    pub allow: i64,
    pub deny: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Room {
    pub id: String,
    pub name: String,
    pub created_by: String,
    pub created_at: String,
    pub category_id: Option<String>,
    pub position: i32,
    pub topic: String,
    /// 0 is the server's default.
    pub user_limit: i32,
    pub bitrate_kbps: i32,
    pub ptt_only: bool,
    pub video_enabled: bool,
    /// Only apps that encrypt end to end may join its call.
    pub e2ee_required: bool,
    pub overrides: Vec<Override>,
    /// What the caller may do in this room.
    pub my_permissions: i64,
}

/// A new room. Everything but the name has the column default when left out.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NewRoom {
    pub name: String,
    pub category_id: Option<String>,
    pub topic: Option<String>,
    pub user_limit: Option<i32>,
    pub bitrate_kbps: Option<i32>,
    pub ptt_only: Option<bool>,
    pub video_enabled: Option<bool>,
    pub e2ee_required: Option<bool>,
}

impl NewRoom {
    /// A room with only a name.
    pub fn named(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ..Self::default()
        }
    }
}

/// A change to a room. `None` leaves a field as it is; `category_id: Some(None)` makes the room
/// uncategorized.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoomPatch {
    pub name: Option<String>,
    pub category_id: Option<Option<String>>,
    pub position: Option<i32>,
    pub topic: Option<String>,
    pub user_limit: Option<i32>,
    pub bitrate_kbps: Option<i32>,
    pub ptt_only: Option<bool>,
    pub video_enabled: Option<bool>,
    pub e2ee_required: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Member {
    pub user_id: String,
    pub email: Option<String>,
    pub display_name: String,
    /// The legacy role string: `owner`, `admin`, or `member`.
    pub role: String,
    pub created_at: String,
    pub owner: bool,
    pub roles: Vec<String>,
    pub last_seen_at: Option<String>,
    /// Set while a timeout runs.
    pub timeout_until: Option<String>,
    /// `invite` or `groups`; `None` for members from before it was recorded.
    pub joined_via: Option<String>,
    /// SHA-256 of their picture, when they have set one.
    pub avatar: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Invite {
    pub id: String,
    pub role: String,
    /// `None` for the owner invite that `tinyserver bootstrap` makes.
    pub created_by: Option<String>,
    pub created_by_name: Option<String>,
    /// `None` for an invite that never expires.
    pub expires_at: Option<String>,
    /// The last use.
    pub accepted_at: Option<String>,
    pub accepted_by: Option<String>,
    pub label: Option<String>,
    /// `None` is unlimited.
    pub max_uses: Option<i32>,
    pub uses: i32,
    pub role_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteIssued {
    pub id: String,
    pub token: String,
    pub role: String,
    pub expires_at: Option<String>,
    pub label: Option<String>,
    pub max_uses: Option<i32>,
    pub role_ids: Vec<String>,
}

/// What an invite gives and how long it lasts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteOptions {
    pub role_ids: Vec<String>,
    pub label: Option<String>,
    /// `None` is unlimited.
    pub max_uses: Option<i32>,
    /// `None` never expires.
    pub expires_in_secs: Option<i64>,
}

impl Default for InviteOptions {
    /// Single use for 7 days, no roles: today's member invite.
    fn default() -> Self {
        Self {
            role_ids: Vec::new(),
            label: None,
            max_uses: Some(1),
            expires_in_secs: Some(DEFAULT_INVITE_SECS),
        }
    }
}

pub const DEFAULT_INVITE_SECS: i64 = 7 * 24 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditRow {
    pub id: i64,
    pub actor_id: Option<String>,
    pub actor_name: Option<String>,
    pub action: String,
    pub subject: String,
    pub subject_user_id: Option<String>,
    pub subject_name: Option<String>,
    pub reason: Option<String>,
    pub detail: Value,
    pub created_at: String,
}

/// `GET /v1/audit` filters. `before` is a row id; `action` a prefix.
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    pub limit: i64,
    pub before: Option<i64>,
    pub actor: Option<String>,
    pub action: Option<String>,
}

impl AuditQuery {
    /// The newest `limit` rows.
    pub fn latest(limit: i64) -> Self {
        Self {
            limit,
            ..Self::default()
        }
    }
}

pub enum Wrote<T> {
    Fresh(T),
    Replay(Value),
}

// Rooms.

fn room_select(filter: &str) -> String {
    format!(
        "SELECT r.id::text, r.name, r.created_by::text,
                to_char(r.created_at AT TIME ZONE 'UTC', '{STAMP}'),
                r.category_id::text, r.position, r.topic, r.user_limit, r.bitrate_kbps,
                r.ptt_only, r.video_enabled,
                coalesce((SELECT jsonb_agg(jsonb_build_object(
                                     'role_id', o.role_id::text, 'allow', o.allow,
                                     'deny', o.deny) ORDER BY o.role_id)
                          FROM room_overrides o WHERE o.room_id = r.id), '[]'::jsonb),
                app_room_perms_of(r.id, app_uid()), r.e2ee_required
         FROM rooms r
         LEFT JOIN categories c ON c.id = r.category_id
         {filter}
         ORDER BY c.position NULLS FIRST, c.id, r.position, r.created_at, r.id"
    )
}

/// The rooms the caller may see, in layout order: uncategorized first, then each category.
pub async fn list_rooms(pool: &PgPool, caller: &Caller) -> Result<Vec<Room>, CommunityError> {
    let mut tx = scope(pool, caller).await?;
    let rooms = rooms_in(&mut tx).await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(rooms)
}

pub(crate) async fn rooms_in(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<Vec<Room>, CommunityError> {
    let rows = sqlx::query(&room_select(""))
        .fetch_all(&mut **tx)
        .await
        .map_err(from_sql)?;
    rows.iter().map(room_from).collect()
}

pub(crate) async fn room_in(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
) -> Result<Room, CommunityError> {
    let row = sqlx::query(&room_select("WHERE r.id = $1::uuid"))
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(from_sql)?;
    let Some(row) = row else {
        return Err(CommunityError::NotFound);
    };
    room_from(&row)
}

pub async fn create_room(
    pool: &PgPool,
    caller: &Caller,
    input: &NewRoom,
    idempotency_key: Option<&str>,
) -> Result<Wrote<Room>, CommunityError> {
    let name = normalize_name(&input.name).map_err(|_| CommunityError::Invalid)?;
    let topic = topic(input.topic.as_deref())?;
    let mut tx = scope(pool, caller).await?;
    require(&mut tx, perm::MANAGE_CHANNELS).await?;
    let shape = serde_json::to_string(input).map_err(|_| CommunityError::Invalid)?;
    let claim = claim(
        &mut tx,
        caller,
        "room",
        idempotency_key,
        &fingerprint(&[&name, &shape]),
    )
    .await?;
    if let Claim::Replay(body) = claim {
        tx.commit().await.map_err(from_sql)?;
        return Ok(Wrote::Replay(body));
    }
    let id: String = sqlx::query_scalar(
        "INSERT INTO rooms (name, created_by, category_id, position, topic, user_limit,
                            bitrate_kbps, ptt_only, video_enabled, e2ee_required)
         VALUES ($1, $2::uuid, $3::uuid,
                 (SELECT coalesce(max(position) + 1, 0) FROM rooms
                  WHERE category_id IS NOT DISTINCT FROM $3::uuid),
                 coalesce($4, ''), coalesce($5, 0), coalesce($6, 64), coalesce($7, false),
                 coalesce($8, true), coalesce($9, false))
         RETURNING id::text",
    )
    .bind(&name)
    .bind(&caller.user_id)
    .bind(input.category_id.as_deref())
    .bind(topic.as_deref())
    .bind(input.user_limit)
    .bind(input.bitrate_kbps)
    .bind(input.ptt_only)
    .bind(input.video_enabled)
    .bind(input.e2ee_required)
    .fetch_one(&mut *tx)
    .await
    .map_err(from_sql)?;
    let room = room_in(&mut tx, &id).await?;
    audit(
        &mut tx,
        "room.create",
        "room",
        serde_json::json!({"id": room.id, "name": room.name}),
    )
    .await?;
    finish(&mut tx, claim, &room).await?;
    emit(&mut tx, "room.created", room_event(&room)).await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(Wrote::Fresh(room))
}

pub async fn rename_room(
    pool: &PgPool,
    caller: &Caller,
    id: &str,
    name: &str,
) -> Result<Room, CommunityError> {
    let patch = RoomPatch {
        name: Some(name.to_string()),
        ..RoomPatch::default()
    };
    update_room(pool, caller, id, &patch).await
}

/// Changes any of a room's settings. Needs manage_channels in that room. A new name is also
/// sent as `room.renamed` for clients from before `room.updated`.
pub async fn update_room(
    pool: &PgPool,
    caller: &Caller,
    id: &str,
    patch: &RoomPatch,
) -> Result<Room, CommunityError> {
    let name = match &patch.name {
        Some(name) => Some(normalize_name(name).map_err(|_| CommunityError::Invalid)?),
        None => None,
    };
    let topic = topic(patch.topic.as_deref())?;
    let mut tx = scope(pool, caller).await?;
    let before = room_in(&mut tx, id).await?;
    require_room(&mut tx, id, perm::MANAGE_CHANNELS).await?;
    let (move_category, category) = match &patch.category_id {
        Some(category) => (true, category.clone()),
        None => (false, None),
    };
    let position = match (patch.position, move_category) {
        (Some(position), _) => Some(position),
        // A room moved to another category goes to its end.
        (None, true) => Some(
            sqlx::query_scalar(
                "SELECT coalesce(max(position) + 1, 0) FROM rooms
                 WHERE category_id IS NOT DISTINCT FROM $1::uuid",
            )
            .bind(category.as_deref())
            .fetch_one(&mut *tx)
            .await
            .map_err(from_sql)?,
        ),
        (None, false) => None,
    };
    let updated = sqlx::query(
        "UPDATE rooms
         SET name = coalesce($2, name),
             topic = coalesce($3, topic),
             user_limit = coalesce($4, user_limit),
             bitrate_kbps = coalesce($5, bitrate_kbps),
             ptt_only = coalesce($6, ptt_only),
             video_enabled = coalesce($7, video_enabled),
             category_id = CASE WHEN $8 THEN $9::uuid ELSE category_id END,
             position = coalesce($10, position),
             e2ee_required = coalesce($11, e2ee_required)
         WHERE id = $1::uuid",
    )
    .bind(id)
    .bind(name.as_deref())
    .bind(topic.as_deref())
    .bind(patch.user_limit)
    .bind(patch.bitrate_kbps)
    .bind(patch.ptt_only)
    .bind(patch.video_enabled)
    .bind(move_category)
    .bind(category.as_deref())
    .bind(position)
    .bind(patch.e2ee_required)
    .execute(&mut *tx)
    .await
    .map_err(from_sql)?;
    if updated.rows_affected() == 0 {
        return Err(CommunityError::NotFound);
    }
    let room = room_in(&mut tx, id).await?;
    let renamed = room.name != before.name;
    if renamed && patch_only_name(patch) {
        audit(
            &mut tx,
            "room.rename",
            "room",
            serde_json::json!({"id": room.id, "name": room.name}),
        )
        .await?;
    } else {
        audit(
            &mut tx,
            "room.update",
            "room",
            serde_json::json!({"id": room.id, "name": room.name, "changes": patch_value(patch)}),
        )
        .await?;
    }
    if renamed {
        emit(&mut tx, "room.renamed", room_event(&room)).await?;
    }
    emit(&mut tx, "room.updated", room_event(&room)).await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(room)
}

fn patch_only_name(patch: &RoomPatch) -> bool {
    *patch
        == RoomPatch {
            name: patch.name.clone(),
            ..RoomPatch::default()
        }
}

fn patch_value(patch: &RoomPatch) -> Value {
    let mut changes = serde_json::Map::new();
    if let Some(name) = &patch.name {
        changes.insert("name".into(), Value::from(name.trim()));
    }
    if let Some(category) = &patch.category_id {
        changes.insert("category_id".into(), serde_json::json!(category));
    }
    if let Some(position) = patch.position {
        changes.insert("position".into(), Value::from(position));
    }
    if let Some(topic) = &patch.topic {
        changes.insert("topic".into(), Value::from(topic.as_str()));
    }
    if let Some(limit) = patch.user_limit {
        changes.insert("user_limit".into(), Value::from(limit));
    }
    if let Some(bitrate) = patch.bitrate_kbps {
        changes.insert("bitrate_kbps".into(), Value::from(bitrate));
    }
    if let Some(ptt) = patch.ptt_only {
        changes.insert("ptt_only".into(), Value::from(ptt));
    }
    if let Some(video) = patch.video_enabled {
        changes.insert("video_enabled".into(), Value::from(video));
    }
    if let Some(required) = patch.e2ee_required {
        changes.insert("e2ee_required".into(), Value::from(required));
    }
    Value::Object(changes)
}

pub async fn delete_room(pool: &PgPool, caller: &Caller, id: &str) -> Result<(), CommunityError> {
    let mut tx = scope(pool, caller).await?;
    room_in(&mut tx, id).await?;
    require_room(&mut tx, id, perm::MANAGE_CHANNELS).await?;
    let gone: Option<String> =
        sqlx::query_scalar("DELETE FROM rooms WHERE id = $1::uuid RETURNING id::text")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(from_sql)?;
    let Some(gone) = gone else {
        return Err(CommunityError::NotFound);
    };
    audit(
        &mut tx,
        "room.delete",
        "room",
        serde_json::json!({"id": gone}),
    )
    .await?;
    emit(
        &mut tx,
        "room.deleted",
        serde_json::json!({"room_id": gone}),
    )
    .await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(())
}

/// Sets or, with `None`, clears one role's override in a room. Needs manage_roles and
/// manage_channels in the room, and the role below the caller.
pub async fn set_override(
    pool: &PgPool,
    caller: &Caller,
    room_id: &str,
    role_id: &str,
    bits: Option<(i64, i64)>,
) -> Result<Room, CommunityError> {
    let mut tx = scope(pool, caller).await?;
    room_in(&mut tx, room_id).await?;
    let (allow, deny) = match bits {
        Some((allow, deny)) => (Some(allow & perm::CHANNEL), deny & perm::CHANNEL),
        None => (None, 0),
    };
    sqlx::query("SELECT app_set_override($1::uuid, $2::uuid, $3, $4)")
        .bind(room_id)
        .bind(role_id)
        .bind(allow)
        .bind(deny)
        .execute(&mut *tx)
        .await
        .map_err(from_sql)?;
    let room = room_in(&mut tx, room_id).await?;
    emit(&mut tx, "room.updated", room_event(&room)).await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(room)
}

/// Whether a room exists and the caller may see it under `rooms_select`.
pub async fn room_exists(pool: &PgPool, caller: &Caller, id: &str) -> Result<bool, CommunityError> {
    let mut tx = scope(pool, caller).await?;
    let found = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM rooms WHERE id = $1::uuid)")
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(from_sql);
    let found = match found {
        Ok(found) => found,
        Err(CommunityError::NotFound) => false,
        Err(error) => return Err(error),
    };
    tx.commit().await.map_err(from_sql)?;
    Ok(found)
}

fn topic(topic: Option<&str>) -> Result<Option<String>, CommunityError> {
    let Some(topic) = topic else {
        return Ok(None);
    };
    let topic = topic.trim();
    if topic.chars().count() > 1024 {
        return Err(CommunityError::Invalid);
    }
    Ok(Some(topic.to_string()))
}

// Members.

fn member_select(filter: &str) -> String {
    format!(
        "SELECT u.id::text, u.email, u.display_name, app_member_role(u.id),
                to_char(m.created_at AT TIME ZONE 'UTC', '{STAMP}'),
                m.owner, app_roles_of(u.id),
                to_char(m.last_seen_at AT TIME ZONE 'UTC', '{STAMP}'),
                CASE WHEN m.timeout_until > now()
                     THEN to_char(m.timeout_until AT TIME ZONE 'UTC', '{STAMP}') END,
                m.joined_via, u.avatar_sha
         FROM memberships m
         JOIN users u ON u.id = m.user_id
         {filter}
         ORDER BY m.created_at, u.id"
    )
}

pub async fn list_members(pool: &PgPool, caller: &Caller) -> Result<Vec<Member>, CommunityError> {
    let mut tx = scope(pool, caller).await?;
    let rows = sqlx::query(&member_select(""))
        .fetch_all(&mut *tx)
        .await
        .map_err(from_sql)?;
    let members = rows
        .iter()
        .map(member_from)
        .collect::<Result<Vec<_>, _>>()?;
    tx.commit().await.map_err(from_sql)?;
    Ok(members)
}

pub(crate) async fn member_in(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
) -> Result<Member, CommunityError> {
    let row = sqlx::query(&member_select("WHERE m.user_id = $1::uuid"))
        .bind(user_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(from_sql)?;
    let Some(row) = row else {
        return Err(CommunityError::NotFound);
    };
    member_from(&row)
}

async fn member_json(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
) -> Result<Value, CommunityError> {
    let value: Option<Value> = sqlx::query_scalar("SELECT app_member_json($1::uuid)")
        .bind(user_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(from_sql)?;
    value.ok_or(CommunityError::NotFound)
}

async fn legacy_role(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
) -> Result<Option<String>, CommunityError> {
    sqlx::query_scalar("SELECT app_member_role($1::uuid)")
        .bind(user_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(from_sql)
}

/// The legacy role change. `owner` is the owner flag, `admin` adds the most senior role that
/// manages the server or its roles, `member` takes those away.
pub async fn set_member_role(
    pool: &PgPool,
    caller: &Caller,
    user_id: &str,
    role: &str,
) -> Result<String, CommunityError> {
    let role = member_role(role)?;
    let mut tx = scope(pool, caller).await?;
    let stored: String = sqlx::query_scalar("SELECT app_set_member_role($1::uuid, $2)")
        .bind(user_id)
        .bind(role)
        .fetch_one(&mut *tx)
        .await
        .map_err(from_sql)?;
    let member = member_json(&mut tx, user_id).await?;
    emit(
        &mut tx,
        "member.role",
        serde_json::json!({ "member": member }),
    )
    .await?;
    emit(
        &mut tx,
        "member.roles",
        serde_json::json!({ "member": member }),
    )
    .await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(stored)
}

/// Replaces a member's roles. Needs manage_roles; the member and every role added or removed
/// must be below the caller.
pub async fn set_member_roles(
    pool: &PgPool,
    caller: &Caller,
    user_id: &str,
    role_ids: &[String],
) -> Result<Member, CommunityError> {
    let mut tx = scope(pool, caller).await?;
    let before = legacy_role(&mut tx, user_id).await?;
    let after: Option<String> =
        sqlx::query_scalar("SELECT app_set_member_roles($1::uuid, $2::uuid[])")
            .bind(user_id)
            .bind(uuids(role_ids)?)
            .fetch_one(&mut *tx)
            .await
            .map_err(from_sql)?;
    let member = member_json(&mut tx, user_id).await?;
    emit(
        &mut tx,
        "member.roles",
        serde_json::json!({ "member": member }),
    )
    .await?;
    if before != after {
        emit(
            &mut tx,
            "member.role",
            serde_json::json!({ "member": member }),
        )
        .await?;
    }
    let row = member_in(&mut tx, user_id).await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(row)
}

/// Owners only. The last owner stays.
pub async fn set_owner(
    pool: &PgPool,
    caller: &Caller,
    user_id: &str,
    owner: bool,
) -> Result<Member, CommunityError> {
    let mut tx = scope(pool, caller).await?;
    sqlx::query("SELECT app_set_owner($1::uuid, $2)")
        .bind(user_id)
        .bind(owner)
        .execute(&mut *tx)
        .await
        .map_err(from_sql)?;
    let member = member_json(&mut tx, user_id).await?;
    emit(
        &mut tx,
        "member.role",
        serde_json::json!({ "member": member }),
    )
    .await?;
    let row = member_in(&mut tx, user_id).await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(row)
}

/// Times a member out until `until`, an RFC 3339 time at most 28 days away, or ends a timeout
/// with `None`. A timed-out member cannot be in a call.
pub async fn set_timeout(
    pool: &PgPool,
    caller: &Caller,
    user_id: &str,
    until: Option<&str>,
    reason: Option<&str>,
) -> Result<Member, CommunityError> {
    let reason = clean_reason(reason)?;
    let mut tx = scope(pool, caller).await?;
    sqlx::query("SELECT app_timeout($1::uuid, $2::timestamptz, $3)")
        .bind(user_id)
        .bind(until)
        .bind(reason.as_deref())
        .execute(&mut *tx)
        .await
        .map_err(from_sql)?;
    let row = member_in(&mut tx, user_id).await?;
    let member = member_json(&mut tx, user_id).await?;
    emit(
        &mut tx,
        "member.timeout",
        serde_json::json!({ "member": member, "timeout_until": row.timeout_until }),
    )
    .await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(row)
}

/// Kick. Also ends the person's sessions, so an invite back does not revive an old token.
pub async fn remove_member(
    pool: &PgPool,
    caller: &Caller,
    user_id: &str,
    reason: Option<&str>,
) -> Result<(), CommunityError> {
    let reason = clean_reason(reason)?;
    let mut tx = scope(pool, caller).await?;
    sqlx::query("SELECT app_remove_member($1::uuid, $2)")
        .bind(user_id)
        .bind(reason.as_deref())
        .execute(&mut *tx)
        .await
        .map_err(from_sql)?;
    sqlx::query("DELETE FROM sessions WHERE user_id = $1::uuid")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(from_sql)?;
    emit(
        &mut tx,
        "member.removed",
        serde_json::json!({"user_id": user_id}),
    )
    .await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(())
}

// Invites.

fn invite_select(filter: &str) -> String {
    format!(
        "SELECT i.id::text, i.role, i.created_by::text, cu.display_name,
                to_char(i.expires_at AT TIME ZONE 'UTC', '{STAMP}'),
                to_char(i.accepted_at AT TIME ZONE 'UTC', '{STAMP}'),
                i.accepted_by::text, i.label, i.max_uses, i.uses,
                coalesce((SELECT array_agg(x.v::text) FROM unnest(i.role_ids) AS x(v)), '{{}}')
         FROM invites i
         LEFT JOIN users cu ON cu.id = i.created_by
         {filter}
         ORDER BY i.created_at DESC, i.id"
    )
}

/// Invites that still work: unexpired and not used up. Needs create_invites or manage_invites.
pub async fn list_invites(pool: &PgPool, caller: &Caller) -> Result<Vec<Invite>, CommunityError> {
    let mut tx = scope(pool, caller).await?;
    require_any(&mut tx, perm::CREATE_INVITES | perm::MANAGE_INVITES).await?;
    let rows = sqlx::query(&invite_select(
        "WHERE (i.expires_at IS NULL OR i.expires_at > now())
           AND (i.max_uses IS NULL OR i.uses < i.max_uses)",
    ))
    .fetch_all(&mut *tx)
    .await
    .map_err(from_sql)?;
    let invites = rows
        .iter()
        .map(invite_from)
        .collect::<Result<Vec<_>, _>>()?;
    tx.commit().await.map_err(from_sql)?;
    Ok(invites)
}

/// The legacy invite: `admin` gives the role a legacy admin means, `member` none. Single use, 7
/// days.
pub async fn create_invite(
    pool: &PgPool,
    caller: &Caller,
    role: &str,
    idempotency_key: Option<&str>,
) -> Result<Wrote<InviteIssued>, CommunityError> {
    let role = invite_role(role)?;
    let mut role_ids = Vec::new();
    if role == "admin" {
        role_ids.push(admin_role(pool).await?.ok_or(CommunityError::Invalid)?);
    }
    let options = InviteOptions {
        role_ids,
        ..InviteOptions::default()
    };
    create_invite_with(pool, caller, &options, idempotency_key).await
}

/// The role a legacy `admin` means: the most senior one that manages the server or its roles.
pub async fn admin_role(pool: &PgPool) -> Result<Option<String>, CommunityError> {
    sqlx::query_scalar("SELECT app_admin_role()::text")
        .fetch_one(pool)
        .await
        .map_err(from_sql)
}

/// An invite with roles, a label, a number of uses, and an expiry. Needs create_invites; roles
/// need manage_roles and must be below the caller; no expiry needs an owner or manage_server.
pub async fn create_invite_with(
    pool: &PgPool,
    caller: &Caller,
    options: &InviteOptions,
    idempotency_key: Option<&str>,
) -> Result<Wrote<InviteIssued>, CommunityError> {
    let label = match options.label.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(label) if label.chars().count() > 80 || label.chars().any(char::is_control) => {
            return Err(CommunityError::Invalid)
        }
        Some(label) => Some(label.to_string()),
    };
    if options
        .max_uses
        .is_some_and(|uses| !(1..=1000).contains(&uses))
        || options
            .expires_in_secs
            .is_some_and(|secs| !(60..=2_592_000).contains(&secs))
    {
        return Err(CommunityError::Invalid);
    }
    let mut role_ids = options.role_ids.clone();
    role_ids.sort();
    role_ids.dedup();
    let ids = uuids(&role_ids)?;

    let mut tx = scope(pool, caller).await?;
    require(&mut tx, perm::CREATE_INVITES).await?;
    if options.expires_in_secs.is_none() {
        let allowed: bool = sqlx::query_scalar("SELECT app_owner_of(app_uid()) OR app_has($1)")
            .bind(perm::MANAGE_SERVER)
            .fetch_one(&mut *tx)
            .await
            .map_err(from_sql)?;
        if !allowed {
            return Err(CommunityError::Forbidden);
        }
    }
    let mut role = "member".to_string();
    if !ids.is_empty() {
        require(&mut tx, perm::MANAGE_ROLES).await?;
        let (known, below, admin): (i64, i64, bool) = sqlx::query_as(
            "SELECT count(*),
                    count(*) FILTER (WHERE app_owner_of(app_uid())
                                        OR position < app_rank_of(app_uid())),
                    coalesce(bool_or(permissions & $2 <> 0), false)
             FROM roles WHERE id = ANY ($1::uuid[]) AND NOT is_default",
        )
        .bind(&ids)
        .bind(perm::MANAGE_SERVER | perm::MANAGE_ROLES)
        .fetch_one(&mut *tx)
        .await
        .map_err(from_sql)?;
        if known != ids.len() as i64 {
            return Err(CommunityError::Invalid);
        }
        if below != known {
            return Err(CommunityError::Hierarchy);
        }
        if admin {
            role = "admin".to_string();
        }
    }
    let shape = serde_json::json!({
        "role_ids": role_ids,
        "label": label,
        "max_uses": options.max_uses,
        "expires_in_secs": options.expires_in_secs,
    })
    .to_string();
    let claim = claim(
        &mut tx,
        caller,
        "invite",
        idempotency_key,
        &fingerprint(&[&role, &shape]),
    )
    .await?;
    if let Claim::Replay(body) = claim {
        tx.commit().await.map_err(from_sql)?;
        return Ok(Wrote::Replay(body));
    }
    let token = new_token();
    let digest = token_digest(&token);
    let id: String = sqlx::query_scalar(
        "INSERT INTO invites (role, token_hash, created_by, expires_at, label, max_uses, role_ids)
         VALUES ($1, $2, $3::uuid,
                 CASE WHEN $4::bigint IS NULL THEN NULL
                      ELSE now() + make_interval(secs => $4::bigint) END,
                 $5, $6, $7::uuid[])
         RETURNING id::text",
    )
    .bind(&role)
    .bind(digest.as_slice())
    .bind(&caller.user_id)
    .bind(options.expires_in_secs)
    .bind(label.as_deref())
    .bind(options.max_uses)
    .bind(&ids)
    .fetch_one(&mut *tx)
    .await
    .map_err(from_sql)?;
    let row = sqlx::query(&invite_select("WHERE i.id = $1::uuid"))
        .bind(&id)
        .fetch_one(&mut *tx)
        .await
        .map_err(from_sql)?;
    let invite = invite_from(&row)?;
    let issued = InviteIssued {
        id: invite.id.clone(),
        token,
        role: invite.role.clone(),
        expires_at: invite.expires_at.clone(),
        label: invite.label.clone(),
        max_uses: invite.max_uses,
        role_ids: invite.role_ids.clone(),
    };
    audit(
        &mut tx,
        "invite.create",
        "invite",
        serde_json::json!({
            "id": issued.id,
            "role": issued.role,
            "role_ids": issued.role_ids,
            "label": issued.label,
            "max_uses": issued.max_uses,
            "expires_at": issued.expires_at,
        }),
    )
    .await?;
    finish(&mut tx, claim, &issued).await?;
    emit(
        &mut tx,
        "invite.created",
        serde_json::json!({"invite": invite_value(&invite)}),
    )
    .await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(Wrote::Fresh(issued))
}

/// Deletes an invite that is not used up. Needs manage_invites, or create_invites for one's own.
/// A used-up invite stays as the record of who joined.
pub async fn revoke_invite(pool: &PgPool, caller: &Caller, id: &str) -> Result<(), CommunityError> {
    let mut tx = scope(pool, caller).await?;
    require_any(&mut tx, perm::CREATE_INVITES | perm::MANAGE_INVITES).await?;
    let found: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT id::text, created_by::text FROM invites
         WHERE id = $1::uuid AND (max_uses IS NULL OR uses < max_uses)",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(from_sql)?;
    let Some((_, created_by)) = found else {
        return Err(CommunityError::NotFound);
    };
    let manages: bool = sqlx::query_scalar("SELECT app_has($1)")
        .bind(perm::MANAGE_INVITES)
        .fetch_one(&mut *tx)
        .await
        .map_err(from_sql)?;
    if !manages && created_by.as_deref() != Some(caller.user_id.as_str()) {
        return Err(CommunityError::Forbidden);
    }
    let gone: Option<(String, String)> = sqlx::query_as(
        "DELETE FROM invites
         WHERE id = $1::uuid
           AND (max_uses IS NULL OR uses < max_uses)
         RETURNING id::text, role",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(from_sql)?;
    let Some((id, role)) = gone else {
        return Err(CommunityError::NotFound);
    };
    audit(
        &mut tx,
        "invite.revoke",
        "invite",
        serde_json::json!({"id": id, "role": role}),
    )
    .await?;
    emit(
        &mut tx,
        "invite.revoked",
        serde_json::json!({"invite_id": id}),
    )
    .await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(())
}

// Audit.

/// Newest first, with the names of the actor and the person acted on. Needs view_audit_log.
pub async fn list_audit(
    pool: &PgPool,
    caller: &Caller,
    query: &AuditQuery,
) -> Result<Vec<AuditRow>, CommunityError> {
    let limit = query.limit.clamp(1, 200);
    let actor = match &query.actor {
        Some(actor) => Some(uuid(actor)?),
        None => None,
    };
    let action = query
        .action
        .as_deref()
        .map(str::trim)
        .filter(|action| !action.is_empty());
    let mut tx = scope(pool, caller).await?;
    require(&mut tx, perm::VIEW_AUDIT_LOG).await?;
    let rows = sqlx::query(&format!(
        "SELECT a.id, a.actor_id::text, au.display_name, a.action, a.subject,
                a.subject_user_id::text, su.display_name, a.reason, a.detail,
                to_char(a.created_at AT TIME ZONE 'UTC', '{STAMP}')
         FROM audit_log a
         LEFT JOIN users au ON au.id = a.actor_id
         LEFT JOIN users su ON su.id = a.subject_user_id
         WHERE ($2::bigint IS NULL OR a.id < $2)
           AND ($3::uuid IS NULL OR a.actor_id = $3::uuid)
           AND ($4::text IS NULL OR starts_with(a.action, $4))
         ORDER BY a.id DESC
         LIMIT $1"
    ))
    .bind(limit)
    .bind(query.before)
    .bind(actor)
    .bind(action)
    .fetch_all(&mut *tx)
    .await
    .map_err(from_sql)?;
    let rows = rows.iter().map(audit_from).collect::<Result<Vec<_>, _>>()?;
    tx.commit().await.map_err(from_sql)?;
    Ok(rows)
}

// Shared.

fn member_role(role: &str) -> Result<&str, CommunityError> {
    match role {
        "owner" | "admin" | "member" => Ok(role),
        _ => Err(CommunityError::Invalid),
    }
}

fn invite_role(role: &str) -> Result<&str, CommunityError> {
    match role {
        "admin" | "member" => Ok(role),
        _ => Err(CommunityError::Invalid),
    }
}

/// A reason for the audit log: trimmed, at most 512 characters, none when blank.
pub(crate) fn clean_reason(reason: Option<&str>) -> Result<Option<String>, CommunityError> {
    let Some(reason) = reason.map(str::trim).filter(|reason| !reason.is_empty()) else {
        return Ok(None);
    };
    if reason.chars().count() > 512 || reason.chars().any(|c| c.is_control() && c != '\n') {
        return Err(CommunityError::Invalid);
    }
    Ok(Some(reason.to_string()))
}

/// One id as Postgres reads it. Anything else is `invalid`.
pub(crate) fn uuid(text: &str) -> Result<String, CommunityError> {
    let text = text.trim();
    let shaped = text.len() == 36
        && text.chars().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        });
    if shaped {
        Ok(text.to_ascii_lowercase())
    } else {
        Err(CommunityError::Invalid)
    }
}

/// Ids checked one by one; bind them as `$n::uuid[]`.
pub(crate) fn uuids(texts: &[String]) -> Result<Vec<String>, CommunityError> {
    texts.iter().map(|text| uuid(text)).collect()
}

pub(crate) async fn scope<'a>(
    pool: &'a PgPool,
    caller: &Caller,
) -> Result<Transaction<'a, Postgres>, CommunityError> {
    let mut tx = pool.begin().await.map_err(from_sql)?;
    sqlx::query("SELECT set_config('app.user_id', $1, true), set_config('app.role', $2, true)")
        .bind(&caller.user_id)
        .bind(&caller.role)
        .execute(&mut *tx)
        .await
        .map_err(from_sql)?;
    Ok(tx)
}

/// The caller has every bit of `bits` server-wide, else `forbidden`.
pub(crate) async fn require(
    tx: &mut Transaction<'_, Postgres>,
    bits: i64,
) -> Result<(), CommunityError> {
    sqlx::query("SELECT app_require($1)")
        .bind(bits)
        .execute(&mut **tx)
        .await
        .map_err(from_sql)?;
    Ok(())
}

/// The caller has at least one bit of `bits` server-wide, else `forbidden`.
pub(crate) async fn require_any(
    tx: &mut Transaction<'_, Postgres>,
    bits: i64,
) -> Result<(), CommunityError> {
    let allowed: bool = sqlx::query_scalar("SELECT app_perms() & $1 <> 0")
        .bind(bits)
        .fetch_one(&mut **tx)
        .await
        .map_err(from_sql)?;
    if allowed {
        Ok(())
    } else {
        Err(CommunityError::Forbidden)
    }
}

/// The caller has every bit of `bits` in `room_id`, else `forbidden`.
pub(crate) async fn require_room(
    tx: &mut Transaction<'_, Postgres>,
    room_id: &str,
    bits: i64,
) -> Result<(), CommunityError> {
    let allowed: bool = sqlx::query_scalar("SELECT app_room_has($1::uuid, $2)")
        .bind(room_id)
        .bind(bits)
        .fetch_one(&mut **tx)
        .await
        .map_err(from_sql)?;
    if allowed {
        Ok(())
    } else {
        Err(CommunityError::Forbidden)
    }
}

pub(crate) async fn audit(
    tx: &mut Transaction<'_, Postgres>,
    action: &str,
    subject: &str,
    detail: Value,
) -> Result<(), CommunityError> {
    audit_about(tx, action, subject, detail, None, None).await
}

/// An audit row naming the person acted on and the reason given.
pub(crate) async fn audit_about(
    tx: &mut Transaction<'_, Postgres>,
    action: &str,
    subject: &str,
    detail: Value,
    subject_user: Option<&str>,
    reason: Option<&str>,
) -> Result<(), CommunityError> {
    sqlx::query("SELECT app_audit($1, $2, $3, $4::uuid, $5)")
        .bind(action)
        .bind(subject)
        .bind(detail)
        .bind(subject_user)
        .bind(reason)
        .execute(&mut **tx)
        .await
        .map_err(from_sql)?;
    Ok(())
}

enum Claim {
    Skip,
    Replay(Value),
    Reserved(String),
}

async fn claim(
    tx: &mut Transaction<'_, Postgres>,
    caller: &Caller,
    route: &str,
    key: Option<&str>,
    hash: &str,
) -> Result<Claim, CommunityError> {
    let Some(key) = key.map(str::trim).filter(|key| !key.is_empty()) else {
        return Ok(Claim::Skip);
    };
    if key.len() > 128 || key.chars().any(char::is_control) {
        return Err(CommunityError::Invalid);
    }
    let scoped = format!("{}\n{route}\n{key}", caller.user_id);
    sqlx::query("DELETE FROM idempotency_keys WHERE key = $1 AND expires_at <= now()")
        .bind(&scoped)
        .execute(&mut **tx)
        .await
        .map_err(from_sql)?;
    let existing: Option<(String, Option<i32>, Option<Value>)> = sqlx::query_as(
        "SELECT request_hash, status_code, response
         FROM idempotency_keys
         WHERE key = $1
         FOR UPDATE",
    )
    .bind(&scoped)
    .fetch_optional(&mut **tx)
    .await
    .map_err(from_sql)?;
    if let Some((stored, status, response)) = existing {
        if stored != hash {
            return Err(CommunityError::IdempotencyConflict);
        }
        let (Some(_status), Some(body)) = (status, response) else {
            return Err(CommunityError::Incomplete);
        };
        return Ok(Claim::Replay(body));
    }
    sqlx::query(
        "INSERT INTO idempotency_keys (key, request_hash, expires_at)
         VALUES ($1, $2, now() + interval '1 day')",
    )
    .bind(&scoped)
    .bind(hash)
    .execute(&mut **tx)
    .await
    .map_err(from_sql)?;
    Ok(Claim::Reserved(scoped))
}

async fn finish<T: Serialize>(
    tx: &mut Transaction<'_, Postgres>,
    claim: Claim,
    value: &T,
) -> Result<(), CommunityError> {
    let Claim::Reserved(key) = claim else {
        return Ok(());
    };
    let body = serde_json::to_value(value).map_err(|_| CommunityError::Invalid)?;
    sqlx::query("UPDATE idempotency_keys SET status_code = 201, response = $2 WHERE key = $1")
        .bind(key)
        .bind(body)
        .execute(&mut **tx)
        .await
        .map_err(from_sql)?;
    Ok(())
}

fn fingerprint(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// The payload of `room.created`, `room.updated`, and `room.renamed`. Without
/// `my_permissions`, which differs per person.
pub(crate) fn room_event(room: &Room) -> Value {
    serde_json::json!({"room": {
        "id": room.id,
        "name": room.name,
        "created_by": room.created_by,
        "created_at": room.created_at,
        "category_id": room.category_id,
        "position": room.position,
        "topic": room.topic,
        "user_limit": room.user_limit,
        "bitrate_kbps": room.bitrate_kbps,
        "ptt_only": room.ptt_only,
        "video_enabled": room.video_enabled,
        "e2ee_required": room.e2ee_required,
        "overrides": room.overrides,
    }})
}

fn invite_value(invite: &Invite) -> Value {
    serde_json::json!({
        "id": invite.id,
        "role": invite.role,
        "created_by": invite.created_by,
        "created_by_name": invite.created_by_name,
        "expires_at": invite.expires_at,
        "accepted_at": invite.accepted_at,
        "accepted_by": invite.accepted_by,
        "label": invite.label,
        "max_uses": invite.max_uses,
        "uses": invite.uses,
        "role_ids": invite.role_ids,
    })
}

fn room_from(row: &PgRow) -> Result<Room, CommunityError> {
    let overrides: Value = row.try_get(11).map_err(from_sql)?;
    Ok(Room {
        id: row.try_get(0).map_err(from_sql)?,
        name: row.try_get(1).map_err(from_sql)?,
        created_by: row.try_get(2).map_err(from_sql)?,
        created_at: row.try_get(3).map_err(from_sql)?,
        category_id: row.try_get(4).map_err(from_sql)?,
        position: row.try_get(5).map_err(from_sql)?,
        topic: row.try_get(6).map_err(from_sql)?,
        user_limit: row.try_get(7).map_err(from_sql)?,
        bitrate_kbps: row.try_get(8).map_err(from_sql)?,
        ptt_only: row.try_get(9).map_err(from_sql)?,
        video_enabled: row.try_get(10).map_err(from_sql)?,
        e2ee_required: row.try_get(13).map_err(from_sql)?,
        overrides: serde_json::from_value(overrides).map_err(|_| CommunityError::Invalid)?,
        my_permissions: row.try_get(12).map_err(from_sql)?,
    })
}

fn member_from(row: &PgRow) -> Result<Member, CommunityError> {
    Ok(Member {
        user_id: row.try_get(0).map_err(from_sql)?,
        email: row.try_get(1).map_err(from_sql)?,
        display_name: row.try_get(2).map_err(from_sql)?,
        role: row
            .try_get::<Option<String>, _>(3)
            .map_err(from_sql)?
            .unwrap_or_else(|| "member".to_string()),
        created_at: row.try_get(4).map_err(from_sql)?,
        owner: row.try_get(5).map_err(from_sql)?,
        roles: row.try_get(6).map_err(from_sql)?,
        last_seen_at: row.try_get(7).map_err(from_sql)?,
        timeout_until: row.try_get(8).map_err(from_sql)?,
        joined_via: row.try_get(9).map_err(from_sql)?,
        avatar: row.try_get(10).map_err(from_sql)?,
    })
}

fn invite_from(row: &PgRow) -> Result<Invite, CommunityError> {
    Ok(Invite {
        id: row.try_get(0).map_err(from_sql)?,
        role: row.try_get(1).map_err(from_sql)?,
        created_by: row.try_get(2).map_err(from_sql)?,
        created_by_name: row.try_get(3).map_err(from_sql)?,
        expires_at: row.try_get(4).map_err(from_sql)?,
        accepted_at: row.try_get(5).map_err(from_sql)?,
        accepted_by: row.try_get(6).map_err(from_sql)?,
        label: row.try_get(7).map_err(from_sql)?,
        max_uses: row.try_get(8).map_err(from_sql)?,
        uses: row.try_get(9).map_err(from_sql)?,
        role_ids: row.try_get(10).map_err(from_sql)?,
    })
}

fn audit_from(row: &PgRow) -> Result<AuditRow, CommunityError> {
    Ok(AuditRow {
        id: row.try_get(0).map_err(from_sql)?,
        actor_id: row.try_get(1).map_err(from_sql)?,
        actor_name: row.try_get(2).map_err(from_sql)?,
        action: row.try_get(3).map_err(from_sql)?,
        subject: row.try_get(4).map_err(from_sql)?,
        subject_user_id: row.try_get(5).map_err(from_sql)?,
        subject_name: row.try_get(6).map_err(from_sql)?,
        reason: row.try_get(7).map_err(from_sql)?,
        detail: row.try_get(8).map_err(from_sql)?,
        created_at: row.try_get(9).map_err(from_sql)?,
    })
}

pub(crate) fn from_sql(error: sqlx::Error) -> CommunityError {
    if let Some(kind) = classify(&error) {
        return kind;
    }
    CommunityError::Database(DbError::from(error))
}

fn classify(error: &sqlx::Error) -> Option<CommunityError> {
    let db = error.as_database_error()?;
    classify_parts(db.code()?.as_ref(), db.message())
}

fn classify_parts(code: &str, message: &str) -> Option<CommunityError> {
    Some(match code {
        "42501" if message.contains("last owner") => CommunityError::LastOwner,
        "42501" if message.contains("hierarchy") => CommunityError::Hierarchy,
        "42501" if message.contains("banned") => CommunityError::Banned,
        "42501" => CommunityError::Forbidden,
        "22023" if message.contains("default role") => CommunityError::DefaultRole,
        "P0002" | "22P02" => CommunityError::NotFound,
        // Bad values, a check constraint, a missing room or category, a bad time.
        "22023" | "23514" | "23503" | "22007" | "22008" | "22003" => CommunityError::Invalid,
        "23505" if message.contains("already a member") => CommunityError::AlreadyMember,
        // Two writes racing for one idempotency key.
        "23505" if message.contains("idempotency_keys") => CommunityError::IdempotencyConflict,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::{classify_parts, clean_reason, invite_role, member_role, uuid, CommunityError};

    #[test]
    fn an_invite_cannot_grant_owner() {
        assert!(matches!(invite_role("member"), Ok("member")));
        assert!(matches!(invite_role("admin"), Ok("admin")));
        assert!(invite_role("owner").is_err());
    }

    #[test]
    fn a_membership_role_is_one_of_three() {
        assert!(matches!(member_role("owner"), Ok("owner")));
        assert!(member_role("guest").is_err());
    }

    #[test]
    fn reasons_and_ids_are_checked() {
        assert_eq!(
            clean_reason(Some("  spam ")).expect("ok").as_deref(),
            Some("spam")
        );
        assert_eq!(clean_reason(Some("   ")).expect("ok"), None);
        assert!(clean_reason(Some(&"x".repeat(513))).is_err());
        assert!(uuid("00000000-0000-0000-0000-00000000000A").is_ok());
        assert!(uuid("nope").is_err());
    }

    #[test]
    fn database_errors_keep_their_meaning() {
        assert!(matches!(
            classify_parts("42501", "last owner"),
            Some(CommunityError::LastOwner)
        ));
        assert!(matches!(
            classify_parts("42501", "hierarchy"),
            Some(CommunityError::Hierarchy)
        ));
        assert!(matches!(
            classify_parts("42501", "banned"),
            Some(CommunityError::Banned)
        ));
        assert!(matches!(
            classify_parts("22023", "default role"),
            Some(CommunityError::DefaultRole)
        ));
        assert!(matches!(
            classify_parts("42501", "not allowed"),
            Some(CommunityError::Forbidden)
        ));
        assert!(matches!(
            classify_parts("P0002", "invite not found"),
            Some(CommunityError::NotFound)
        ));
        assert!(matches!(
            classify_parts("23505", "already a member"),
            Some(CommunityError::AlreadyMember)
        ));
        assert!(matches!(
            classify_parts("23505", "idempotency_keys_pkey"),
            Some(CommunityError::IdempotencyConflict)
        ));
        assert!(classify_parts("23505", "user_identities_pkey").is_none());
        assert!(classify_parts("XX000", "nope").is_none());
    }
}
