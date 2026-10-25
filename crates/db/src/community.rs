//! Rooms, membership, invites, and the audit log.
//!
//! Every call from a signed-in person runs in a transaction that sets `app.user_id` and
//! `app.role`. Membership rows change only through the database functions. An invite token is
//! returned once; Postgres stores its SHA-256.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Postgres, Row, Transaction};
use thiserror::Error;

use crate::bootstrap::{check_password, hash_password, normalize_email, normalize_name};
use crate::outbox::emit;
use crate::session::{new_token, password_matches, token_digest};
use crate::DbError;

const STAMP: &str = "YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"";

#[derive(Debug, Error)]
pub enum CommunityError {
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("last owner")]
    LastOwner,
    #[error("invalid")]
    Invalid,
    #[error("already a member")]
    AlreadyMember,
    #[error("email taken")]
    EmailTaken,
    #[error("invalid credentials")]
    InvalidCredentials,
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
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Room {
    pub id: String,
    pub name: String,
    pub created_by: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Member {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
    pub role: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Invite {
    pub id: String,
    pub role: String,
    pub created_by: String,
    pub expires_at: String,
    pub accepted_at: Option<String>,
    pub accepted_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteIssued {
    pub id: String,
    pub token: String,
    pub role: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Accepted {
    pub token: String,
    pub user_id: String,
    pub email: String,
    pub display_name: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditRow {
    pub id: i64,
    pub actor_id: Option<String>,
    pub action: String,
    pub subject: String,
    pub detail: Value,
    pub created_at: String,
}

pub enum Wrote<T> {
    Fresh(T),
    Replay(Value),
}

pub async fn list_rooms(pool: &PgPool, caller: &Caller) -> Result<Vec<Room>, CommunityError> {
    let mut tx = scope(pool, caller).await?;
    let rows = sqlx::query(&format!(
        "SELECT id::text, name, created_by::text,
                to_char(created_at AT TIME ZONE 'UTC', '{STAMP}')
         FROM rooms
         ORDER BY created_at, id"
    ))
    .fetch_all(&mut *tx)
    .await
    .map_err(from_sql)?;
    let rooms = rows.iter().map(room_from).collect::<Result<Vec<_>, _>>()?;
    tx.commit().await.map_err(from_sql)?;
    Ok(rooms)
}

pub async fn create_room(
    pool: &PgPool,
    caller: &Caller,
    name: &str,
    idempotency_key: Option<&str>,
) -> Result<Wrote<Room>, CommunityError> {
    managers(caller)?;
    let name = normalize_name(name).map_err(|_| CommunityError::Invalid)?;
    let mut tx = scope(pool, caller).await?;
    let claim = claim(
        &mut tx,
        caller,
        "room",
        idempotency_key,
        &fingerprint(&[&name]),
    )
    .await?;
    if let Claim::Replay(body) = claim {
        tx.commit().await.map_err(from_sql)?;
        return Ok(Wrote::Replay(body));
    }
    let row = sqlx::query(&format!(
        "INSERT INTO rooms (name, created_by)
         VALUES ($1, $2::uuid)
         RETURNING id::text, name, created_by::text,
                   to_char(created_at AT TIME ZONE 'UTC', '{STAMP}')"
    ))
    .bind(&name)
    .bind(&caller.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(from_sql)?;
    let room = room_from(&row)?;
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
    managers(caller)?;
    let name = normalize_name(name).map_err(|_| CommunityError::Invalid)?;
    let mut tx = scope(pool, caller).await?;
    let row = sqlx::query(&format!(
        "UPDATE rooms
         SET name = $2
         WHERE id = $1::uuid
         RETURNING id::text, name, created_by::text,
                   to_char(created_at AT TIME ZONE 'UTC', '{STAMP}')"
    ))
    .bind(id)
    .bind(&name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(from_sql)?;
    let Some(row) = row else {
        return Err(CommunityError::NotFound);
    };
    let room = room_from(&row)?;
    audit(
        &mut tx,
        "room.rename",
        "room",
        serde_json::json!({"id": room.id, "name": room.name}),
    )
    .await?;
    emit(&mut tx, "room.renamed", room_event(&room)).await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(room)
}

pub async fn delete_room(pool: &PgPool, caller: &Caller, id: &str) -> Result<(), CommunityError> {
    managers(caller)?;
    let mut tx = scope(pool, caller).await?;
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

pub async fn list_members(pool: &PgPool, caller: &Caller) -> Result<Vec<Member>, CommunityError> {
    let mut tx = scope(pool, caller).await?;
    let rows = sqlx::query(&format!(
        "SELECT u.id::text, u.email, u.display_name, m.role,
                to_char(m.created_at AT TIME ZONE 'UTC', '{STAMP}')
         FROM memberships m
         JOIN users u ON u.id = m.user_id
         ORDER BY m.created_at, u.id"
    ))
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

pub async fn set_member_role(
    pool: &PgPool,
    caller: &Caller,
    user_id: &str,
    role: &str,
) -> Result<String, CommunityError> {
    managers(caller)?;
    let role = member_role(role)?;
    let mut tx = scope(pool, caller).await?;
    let stored: String = sqlx::query_scalar("SELECT app_set_member_role($1::uuid, $2)")
        .bind(user_id)
        .bind(role)
        .fetch_one(&mut *tx)
        .await
        .map_err(from_sql)?;
    let display_name: String =
        sqlx::query_scalar("SELECT display_name FROM users WHERE id = $1::uuid")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(from_sql)?;
    emit(
        &mut tx,
        "member.role",
        member_event(user_id, &display_name, &stored),
    )
    .await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(stored)
}

/// Also ends the person's sessions, so an invite back does not revive an old token.
pub async fn remove_member(
    pool: &PgPool,
    caller: &Caller,
    user_id: &str,
) -> Result<(), CommunityError> {
    managers(caller)?;
    let mut tx = scope(pool, caller).await?;
    sqlx::query("SELECT app_remove_member($1::uuid)")
        .bind(user_id)
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

pub async fn list_invites(pool: &PgPool, caller: &Caller) -> Result<Vec<Invite>, CommunityError> {
    managers(caller)?;
    let mut tx = scope(pool, caller).await?;
    let rows = sqlx::query(&format!(
        "SELECT id::text, role, created_by::text,
                to_char(expires_at AT TIME ZONE 'UTC', '{STAMP}'),
                to_char(accepted_at AT TIME ZONE 'UTC', '{STAMP}'),
                accepted_by::text
         FROM invites
         ORDER BY created_at DESC, id"
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

pub async fn create_invite(
    pool: &PgPool,
    caller: &Caller,
    role: &str,
    idempotency_key: Option<&str>,
) -> Result<Wrote<InviteIssued>, CommunityError> {
    managers(caller)?;
    let role = invite_role(role)?;
    let mut tx = scope(pool, caller).await?;
    let claim = claim(
        &mut tx,
        caller,
        "invite",
        idempotency_key,
        &fingerprint(&[role]),
    )
    .await?;
    if let Claim::Replay(body) = claim {
        tx.commit().await.map_err(from_sql)?;
        return Ok(Wrote::Replay(body));
    }
    let token = new_token();
    let digest = token_digest(&token);
    let row = sqlx::query(&format!(
        "INSERT INTO invites (role, token_hash, created_by, expires_at)
         VALUES ($1, $2, $3::uuid, now() + interval '7 days')
         RETURNING id::text, to_char(expires_at AT TIME ZONE 'UTC', '{STAMP}')"
    ))
    .bind(role)
    .bind(digest.as_slice())
    .bind(&caller.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(from_sql)?;
    let issued = InviteIssued {
        id: row.try_get(0).map_err(from_sql)?,
        token,
        role: role.to_string(),
        expires_at: row.try_get(1).map_err(from_sql)?,
    };
    audit(
        &mut tx,
        "invite.create",
        "invite",
        serde_json::json!({"id": issued.id, "role": issued.role}),
    )
    .await?;
    finish(&mut tx, claim, &issued).await?;
    let invite = Invite {
        id: issued.id.clone(),
        role: issued.role.clone(),
        created_by: caller.user_id.clone(),
        expires_at: issued.expires_at.clone(),
        accepted_at: None,
        accepted_by: None,
    };
    emit(
        &mut tx,
        "invite.created",
        serde_json::json!({"invite": invite_value(&invite)}),
    )
    .await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(Wrote::Fresh(issued))
}

/// Deletes an invite nobody has accepted. An accepted invite stays as the record of who joined.
pub async fn revoke_invite(pool: &PgPool, caller: &Caller, id: &str) -> Result<(), CommunityError> {
    managers(caller)?;
    let mut tx = scope(pool, caller).await?;
    let gone: Option<(String, String)> = sqlx::query_as(
        "DELETE FROM invites
         WHERE id = $1::uuid
           AND accepted_at IS NULL
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

pub async fn accept_invite(
    pool: &PgPool,
    token: &str,
    email: &str,
    password: &str,
    display_name: &str,
) -> Result<Accepted, CommunityError> {
    check_password(password).map_err(|_| CommunityError::Invalid)?;
    let email = normalize_email(email).map_err(|_| CommunityError::Invalid)?;
    let display_name = normalize_name(display_name).map_err(|_| CommunityError::Invalid)?;
    let digest = token_digest(token);

    let mut tx = pool.begin().await.map_err(from_sql)?;
    let existing: Option<(String, String, String, String)> = sqlx::query_as(
        "SELECT id::text, email, display_name, password_hash
         FROM users
         WHERE lower(email) = lower($1)",
    )
    .bind(&email)
    .fetch_optional(&mut *tx)
    .await
    .map_err(from_sql)?;

    let (user_id, email, display_name) =
        if let Some((user_id, email, display_name, hash)) = existing {
            if !password_matches(password, &hash) {
                return Err(CommunityError::InvalidCredentials);
            }
            (user_id, email, display_name)
        } else {
            let hash = hash_password(password)?;
            let user_id: String = sqlx::query_scalar(
                "INSERT INTO users (email, display_name, password_hash)
             VALUES ($1, $2, $3)
             RETURNING id::text",
            )
            .bind(&email)
            .bind(&display_name)
            .bind(&hash)
            .fetch_one(&mut *tx)
            .await
            .map_err(from_sql)?;
            (user_id, email, display_name)
        };

    let role: String = sqlx::query_scalar("SELECT app_accept_invite($1, $2::uuid)")
        .bind(digest.as_slice())
        .bind(&user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(from_sql)?;

    let session = new_token();
    let session_digest = token_digest(&session);
    sqlx::query(
        "INSERT INTO sessions (user_id, token_hash, expires_at)
         VALUES ($1::uuid, $2, now() + interval '30 days')",
    )
    .bind(&user_id)
    .bind(session_digest.as_slice())
    .execute(&mut *tx)
    .await
    .map_err(from_sql)?;
    tx.commit().await.map_err(from_sql)?;

    Ok(Accepted {
        token: session,
        user_id,
        email,
        display_name,
        role,
    })
}

pub async fn list_audit(
    pool: &PgPool,
    caller: &Caller,
    limit: i64,
) -> Result<Vec<AuditRow>, CommunityError> {
    managers(caller)?;
    let limit = limit.clamp(1, 200);
    let mut tx = scope(pool, caller).await?;
    let rows = sqlx::query(&format!(
        "SELECT id, actor_id::text, action, subject, detail,
                to_char(created_at AT TIME ZONE 'UTC', '{STAMP}')
         FROM audit_log
         ORDER BY id DESC
         LIMIT $1"
    ))
    .bind(limit)
    .fetch_all(&mut *tx)
    .await
    .map_err(from_sql)?;
    let rows = rows.iter().map(audit_from).collect::<Result<Vec<_>, _>>()?;
    tx.commit().await.map_err(from_sql)?;
    Ok(rows)
}

fn managers(caller: &Caller) -> Result<(), CommunityError> {
    match caller.role.as_str() {
        "owner" | "admin" => Ok(()),
        _ => Err(CommunityError::Forbidden),
    }
}

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

pub(crate) async fn scope<'a>(
    pool: &'a PgPool,
    caller: &Caller,
) -> Result<Transaction<'a, Postgres>, CommunityError> {
    let mut tx = pool.begin().await.map_err(from_sql)?;
    sqlx::query("SELECT set_config('app.user_id', $1, true)")
        .bind(&caller.user_id)
        .execute(&mut *tx)
        .await
        .map_err(from_sql)?;
    sqlx::query("SELECT set_config('app.role', $1, true)")
        .bind(&caller.role)
        .execute(&mut *tx)
        .await
        .map_err(from_sql)?;
    Ok(tx)
}

pub(crate) async fn audit(
    tx: &mut Transaction<'_, Postgres>,
    action: &str,
    subject: &str,
    detail: Value,
) -> Result<(), CommunityError> {
    sqlx::query(
        "INSERT INTO audit_log (actor_id, action, subject, detail)
         VALUES (nullif(current_setting('app.user_id', true), '')::uuid, $1, $2, $3)",
    )
    .bind(action)
    .bind(subject)
    .bind(detail)
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

/// The payload of `room.created` and `room.renamed`.
fn room_event(room: &Room) -> Value {
    serde_json::json!({"room": {
        "id": room.id,
        "name": room.name,
        "created_by": room.created_by,
        "created_at": room.created_at,
    }})
}

/// The payload of `member.joined`, `member.role`, and `member.renamed`. No email.
pub(crate) fn member_event(user_id: &str, display_name: &str, role: &str) -> Value {
    serde_json::json!({"member": {
        "user_id": user_id,
        "display_name": display_name,
        "role": role,
    }})
}

fn invite_value(invite: &Invite) -> Value {
    serde_json::json!({
        "id": invite.id,
        "role": invite.role,
        "created_by": invite.created_by,
        "expires_at": invite.expires_at,
        "accepted_at": invite.accepted_at,
        "accepted_by": invite.accepted_by,
    })
}

fn room_from(row: &PgRow) -> Result<Room, CommunityError> {
    Ok(Room {
        id: row.try_get(0).map_err(from_sql)?,
        name: row.try_get(1).map_err(from_sql)?,
        created_by: row.try_get(2).map_err(from_sql)?,
        created_at: row.try_get(3).map_err(from_sql)?,
    })
}

fn member_from(row: &PgRow) -> Result<Member, CommunityError> {
    Ok(Member {
        user_id: row.try_get(0).map_err(from_sql)?,
        email: row.try_get(1).map_err(from_sql)?,
        display_name: row.try_get(2).map_err(from_sql)?,
        role: row.try_get(3).map_err(from_sql)?,
        created_at: row.try_get(4).map_err(from_sql)?,
    })
}

fn invite_from(row: &PgRow) -> Result<Invite, CommunityError> {
    Ok(Invite {
        id: row.try_get(0).map_err(from_sql)?,
        role: row.try_get(1).map_err(from_sql)?,
        created_by: row.try_get(2).map_err(from_sql)?,
        expires_at: row.try_get(3).map_err(from_sql)?,
        accepted_at: row.try_get(4).map_err(from_sql)?,
        accepted_by: row.try_get(5).map_err(from_sql)?,
    })
}

fn audit_from(row: &PgRow) -> Result<AuditRow, CommunityError> {
    Ok(AuditRow {
        id: row.try_get(0).map_err(from_sql)?,
        actor_id: row.try_get(1).map_err(from_sql)?,
        action: row.try_get(2).map_err(from_sql)?,
        subject: row.try_get(3).map_err(from_sql)?,
        detail: row.try_get(4).map_err(from_sql)?,
        created_at: row.try_get(5).map_err(from_sql)?,
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
        "42501" => CommunityError::Forbidden,
        "P0002" | "22P02" => CommunityError::NotFound,
        "22023" | "23514" => CommunityError::Invalid,
        "23505" if message.contains("already a member") => CommunityError::AlreadyMember,
        "23505" => CommunityError::EmailTaken,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::{classify_parts, invite_role, member_role, CommunityError};

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
    fn database_errors_keep_their_meaning() {
        assert!(matches!(
            classify_parts("42501", "last owner"),
            Some(CommunityError::LastOwner)
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
            classify_parts("23505", "users_email_lower"),
            Some(CommunityError::EmailTaken)
        ));
        assert!(classify_parts("XX000", "nope").is_none());
    }
}
