//! Bans, and the checks behind call moderation. Calls themselves live in memory in `api`.

use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row};

use crate::community::{audit_about, clean_reason, from_sql, require_room, scope, uuid, STAMP};
use crate::outbox::emit;
use crate::perm;
use crate::{Caller, CommunityError, DbError};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ban {
    pub user_id: String,
    pub display_name: String,
    pub email: Option<String>,
    pub reason: Option<String>,
    pub banned_by: Option<String>,
    pub banned_by_name: Option<String>,
    pub created_at: String,
    /// `None` is permanent.
    pub expires_at: Option<String>,
}

fn ban_select(filter: &str) -> String {
    format!(
        "SELECT b.user_id::text, u.display_name, u.email, b.reason, b.banned_by::text,
                bu.display_name, to_char(b.created_at AT TIME ZONE 'UTC', '{STAMP}'),
                to_char(b.expires_at AT TIME ZONE 'UTC', '{STAMP}')
         FROM bans b
         JOIN users u ON u.id = b.user_id
         LEFT JOIN users bu ON bu.id = b.banned_by
         WHERE (b.expires_at IS NULL OR b.expires_at > now()) {filter}
         ORDER BY b.created_at DESC, b.user_id"
    )
}

/// Bans in force. Needs ban_members.
pub async fn list_bans(pool: &PgPool, caller: &Caller) -> Result<Vec<Ban>, CommunityError> {
    let mut tx = scope(pool, caller).await?;
    crate::community::require(&mut tx, perm::BAN_MEMBERS).await?;
    let rows = sqlx::query(&ban_select(""))
        .fetch_all(&mut *tx)
        .await
        .map_err(from_sql)?;
    let bans = rows.iter().map(ban_from).collect::<Result<Vec<_>, _>>()?;
    tx.commit().await.map_err(from_sql)?;
    Ok(bans)
}

/// Bans `user_id` until `expires_at`, an RFC 3339 time, or for good. Removes their membership
/// and every session. Every (issuer, subject) they signed in with is refused from then on.
pub async fn ban(
    pool: &PgPool,
    caller: &Caller,
    user_id: &str,
    reason: Option<&str>,
    expires_at: Option<&str>,
) -> Result<Ban, CommunityError> {
    let user_id = uuid(user_id)?;
    let reason = clean_reason(reason)?;
    let mut tx = scope(pool, caller).await?;
    let was_member: bool = sqlx::query_scalar("SELECT app_ban($1::uuid, $2, $3::timestamptz)")
        .bind(&user_id)
        .bind(reason.as_deref())
        .bind(expires_at)
        .fetch_one(&mut *tx)
        .await
        .map_err(from_sql)?;
    let row = sqlx::query(&ban_select("AND b.user_id = $1::uuid"))
        .bind(&user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(from_sql)?;
    let ban = ban_from(&row)?;
    emit(
        &mut tx,
        "member.banned",
        serde_json::json!({ "user_id": user_id, "ban": ban }),
    )
    .await?;
    if was_member {
        emit(
            &mut tx,
            "member.removed",
            serde_json::json!({ "user_id": user_id }),
        )
        .await?;
    }
    tx.commit().await.map_err(from_sql)?;
    Ok(ban)
}

pub async fn unban(pool: &PgPool, caller: &Caller, user_id: &str) -> Result<(), CommunityError> {
    let user_id = uuid(user_id)?;
    let mut tx = scope(pool, caller).await?;
    sqlx::query("SELECT app_unban($1::uuid)")
        .bind(&user_id)
        .execute(&mut *tx)
        .await
        .map_err(from_sql)?;
    tx.commit().await.map_err(from_sql)?;
    Ok(())
}

/// What a member may do in a room's call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallAccess {
    /// Their permissions in the room.
    pub permissions: i64,
    /// The room's own limit, 0 for the server's.
    pub user_limit: i32,
    pub timed_out: bool,
    /// Only apps that encrypt end to end may join.
    pub e2ee_required: bool,
}

/// `None` when the room is missing or the member cannot see it.
pub async fn call_access(
    pool: &PgPool,
    user_id: &str,
    room_id: &str,
) -> Result<Option<CallAccess>, DbError> {
    let Ok(room_id) = uuid(room_id) else {
        return Ok(None);
    };
    let row: Option<(i64, i32, bool, bool)> = sqlx::query_as(
        "SELECT perms, user_limit, timed_out, e2ee_required
         FROM app_call_access($1::uuid, $2::uuid)",
    )
    .bind(&room_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row
        .map(
            |(permissions, user_limit, timed_out, e2ee_required)| CallAccess {
                permissions,
                user_limit,
                timed_out,
                e2ee_required,
            },
        )
        .filter(|access| perm::has(access.permissions, perm::VIEW_CHANNEL)))
}

/// Each person's permissions in a room, for people already in its call.
pub async fn room_permissions(
    pool: &PgPool,
    room_id: &str,
    user_ids: &[String],
) -> Result<Vec<(String, i64)>, DbError> {
    let Ok(room_id) = uuid(room_id) else {
        return Ok(Vec::new());
    };
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT u::text, app_room_perms_of($1::uuid, u)
         FROM unnest($2::uuid[]) AS x(u)",
    )
    .bind(&room_id)
    .bind(user_ids)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Records that these people were connected just now.
pub async fn touch_seen(pool: &PgPool, user_ids: &[String]) -> Result<(), DbError> {
    if user_ids.is_empty() {
        return Ok(());
    }
    sqlx::query("SELECT app_seen($1::uuid[])")
        .bind(user_ids)
        .execute(pool)
        .await?;
    Ok(())
}

/// Checks that the caller may act on `user_id` in `room_id`'s call with `bits` there, and
/// writes the audit row. The call itself is in memory.
pub async fn call_action(
    pool: &PgPool,
    caller: &Caller,
    action: &str,
    room_id: &str,
    user_id: &str,
    bits: i64,
    detail: serde_json::Value,
) -> Result<(), CommunityError> {
    let mut tx = scope(pool, caller).await?;
    require_room(&mut tx, room_id, bits).await?;
    sqlx::query("SELECT app_check_target($1::uuid)")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(from_sql)?;
    let mut detail = detail;
    if let Some(object) = detail.as_object_mut() {
        object.insert("room_id".into(), room_id.into());
        object.insert("user_id".into(), user_id.into());
    }
    audit_about(&mut tx, action, "call", detail, Some(user_id), None).await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(())
}

/// Disconnect from a call: disconnect_members in the room and the hierarchy.
pub async fn kick_from_call(
    pool: &PgPool,
    caller: &Caller,
    room_id: &str,
    user_id: &str,
) -> Result<(), CommunityError> {
    call_action(
        pool,
        caller,
        "call.kick",
        room_id,
        user_id,
        perm::DISCONNECT_MEMBERS,
        serde_json::json!({}),
    )
    .await
}

/// Ending someone's screen share, under the same rule as a disconnect.
pub async fn end_share(
    pool: &PgPool,
    caller: &Caller,
    room_id: &str,
    user_id: &str,
) -> Result<(), CommunityError> {
    call_action(
        pool,
        caller,
        "call.share_end",
        room_id,
        user_id,
        perm::DISCONNECT_MEMBERS,
        serde_json::json!({}),
    )
    .await
}

/// Server mute needs mute_members, server deafen deafen_members, both in the room.
pub async fn moderate_call(
    pool: &PgPool,
    caller: &Caller,
    room_id: &str,
    user_id: &str,
    server_muted: Option<bool>,
    server_deafened: Option<bool>,
) -> Result<(), CommunityError> {
    let mut bits = 0;
    if server_muted.is_some() {
        bits |= perm::MUTE_MEMBERS;
    }
    if server_deafened.is_some() {
        bits |= perm::DEAFEN_MEMBERS;
    }
    call_action(
        pool,
        caller,
        "call.server_mute",
        room_id,
        user_id,
        bits,
        serde_json::json!({ "server_muted": server_muted, "server_deafened": server_deafened }),
    )
    .await
}

/// Moving someone needs move_members in both rooms and the hierarchy.
pub async fn move_in_call(
    pool: &PgPool,
    caller: &Caller,
    from_room: &str,
    to_room: &str,
    user_id: &str,
) -> Result<(), CommunityError> {
    let mut tx = scope(pool, caller).await?;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM rooms WHERE id = $1::uuid)")
            .bind(to_room)
            .fetch_one(&mut *tx)
            .await
            .map_err(from_sql)?;
    if !exists {
        return Err(CommunityError::NotFound);
    }
    require_room(&mut tx, to_room, perm::MOVE_MEMBERS).await?;
    tx.rollback().await.map_err(from_sql)?;
    call_action(
        pool,
        caller,
        "call.move",
        from_room,
        user_id,
        perm::MOVE_MEMBERS,
        serde_json::json!({ "to_room_id": to_room }),
    )
    .await
}

fn ban_from(row: &PgRow) -> Result<Ban, CommunityError> {
    Ok(Ban {
        user_id: row.try_get(0).map_err(from_sql)?,
        display_name: row.try_get(1).map_err(from_sql)?,
        email: row.try_get(2).map_err(from_sql)?,
        reason: row.try_get(3).map_err(from_sql)?,
        banned_by: row.try_get(4).map_err(from_sql)?,
        banned_by_name: row.try_get(5).map_err(from_sql)?,
        created_at: row.try_get(6).map_err(from_sql)?,
        expires_at: row.try_get(7).map_err(from_sql)?,
    })
}
