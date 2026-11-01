//! A signed-in person's own account: display name, picture, and sessions.
//!
//! `users` and `sessions` have no row level security. Each call still runs in the caller's scope
//! so the audit row names the actor.

use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::bootstrap::normalize_name;
use crate::community::{audit, from_sql, scope};
use crate::outbox::emit;
use crate::server::{sniff_image, Icon, ICON_MAX};
use crate::session::{identity_from, IdentityRow, IDENTITY_COLUMNS};
use crate::{Caller, CommunityError, Identity};

/// Sets the caller's display name. It is trimmed and must be 1 to 80 characters.
pub async fn rename_me(
    pool: &PgPool,
    caller: &Caller,
    display_name: &str,
) -> Result<Identity, CommunityError> {
    let display_name = normalize_name(display_name).map_err(|_| CommunityError::Invalid)?;
    let mut tx = scope(pool, caller).await?;
    let updated: Option<String> = sqlx::query_scalar(
        "UPDATE users
         SET display_name = $2
         WHERE id = $1::uuid
         RETURNING id::text",
    )
    .bind(&caller.user_id)
    .bind(&display_name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(from_sql)?;
    let Some(user_id) = updated else {
        return Err(CommunityError::NotFound);
    };
    audit(
        &mut tx,
        "account.rename",
        "user",
        serde_json::json!({"user_id": user_id, "display_name": display_name}),
    )
    .await?;
    let member: Option<serde_json::Value> = sqlx::query_scalar("SELECT app_member_json($1::uuid)")
        .bind(&user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(from_sql)?;
    emit(
        &mut tx,
        "member.renamed",
        serde_json::json!({ "member": member }),
    )
    .await?;
    let row: Option<IdentityRow> = sqlx::query_as(&format!(
        "SELECT {IDENTITY_COLUMNS} FROM users u WHERE u.id = $1::uuid"
    ))
    .bind(&user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(from_sql)?;
    let identity = row
        .and_then(identity_from)
        .ok_or(CommunityError::NotFound)?;
    tx.commit().await.map_err(from_sql)?;
    Ok(identity)
}

/// The caller's picture, or `None` when they have not set one. Any member may read any member's.
pub async fn get_avatar(
    pool: &PgPool,
    caller: &Caller,
    user_id: &str,
) -> Result<Option<Icon>, CommunityError> {
    let mut tx = scope(pool, caller).await?;
    type Row = (Option<Vec<u8>>, Option<String>, Option<String>);
    let row: Option<Row> = sqlx::query_as(
        "SELECT u.avatar, u.avatar_type, u.avatar_sha
         FROM users u
         JOIN memberships m ON m.user_id = u.id
         WHERE u.id = $1::uuid",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(from_sql)?;
    tx.commit().await.map_err(from_sql)?;
    let Some(row) = row else {
        return Err(CommunityError::NotFound);
    };
    Ok(match row {
        (Some(bytes), Some(content_type), Some(sha)) => Some(Icon {
            bytes,
            content_type,
            sha,
        }),
        _ => None,
    })
}

/// Sets the caller's picture. The caller has already checked the type and the size.
pub async fn set_avatar(
    pool: &PgPool,
    caller: &Caller,
    bytes: &[u8],
    content_type: &str,
) -> Result<String, CommunityError> {
    if bytes.is_empty() || bytes.len() > ICON_MAX || sniff_image(bytes) != Some(content_type) {
        return Err(CommunityError::Invalid);
    }
    let sha: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let mut tx = scope(pool, caller).await?;
    let updated: Option<String> = sqlx::query_scalar(
        "UPDATE users
         SET avatar = $2, avatar_type = $3, avatar_sha = $4
         WHERE id = $1::uuid
         RETURNING id::text",
    )
    .bind(&caller.user_id)
    .bind(bytes)
    .bind(content_type)
    .bind(&sha)
    .fetch_optional(&mut *tx)
    .await
    .map_err(from_sql)?;
    let Some(user_id) = updated else {
        return Err(CommunityError::NotFound);
    };
    audit(
        &mut tx,
        "account.avatar",
        "user",
        serde_json::json!({"user_id": user_id, "avatar": sha, "bytes": bytes.len()}),
    )
    .await?;
    let member: Option<serde_json::Value> = sqlx::query_scalar("SELECT app_member_json($1::uuid)")
        .bind(&user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(from_sql)?;
    emit(
        &mut tx,
        "member.avatar",
        serde_json::json!({ "member": member }),
    )
    .await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(sha)
}

/// Clears the caller's picture. Fine when they had none.
pub async fn delete_avatar(pool: &PgPool, caller: &Caller) -> Result<(), CommunityError> {
    let mut tx = scope(pool, caller).await?;
    let updated: Option<String> = sqlx::query_scalar(
        "UPDATE users
         SET avatar = NULL, avatar_type = NULL, avatar_sha = NULL
         WHERE id = $1::uuid
         RETURNING id::text",
    )
    .bind(&caller.user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(from_sql)?;
    let Some(user_id) = updated else {
        return Err(CommunityError::NotFound);
    };
    audit(
        &mut tx,
        "account.avatar",
        "user",
        serde_json::json!({"user_id": user_id, "avatar": null}),
    )
    .await?;
    let member: Option<serde_json::Value> = sqlx::query_scalar("SELECT app_member_json($1::uuid)")
        .bind(&user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(from_sql)?;
    emit(
        &mut tx,
        "member.avatar",
        serde_json::json!({ "member": member }),
    )
    .await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(())
}

/// Ends every session the caller has, including the one making this call.
pub async fn close_all_sessions(pool: &PgPool, caller: &Caller) -> Result<u64, CommunityError> {
    let mut tx = scope(pool, caller).await?;
    let ended = sqlx::query("DELETE FROM sessions WHERE user_id = $1::uuid")
        .bind(&caller.user_id)
        .execute(&mut *tx)
        .await
        .map_err(from_sql)?
        .rows_affected();
    audit(
        &mut tx,
        "session.close_all",
        "session",
        serde_json::json!({"user_id": caller.user_id, "sessions_ended": ended}),
    )
    .await?;
    session_ended(&mut tx, &caller.user_id).await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(ended)
}

/// Deletes the caller's own account: their name, email, picture, provider identity, sessions,
/// bots and messages. The row stays as an empty "Deleted user" because other people's history
/// points at it. A sole owner is refused with `LastOwner`. See `0014_account_deletion.sql` for
/// what is removed and what a deletion cannot reach.
pub async fn delete_account(pool: &PgPool, caller: &Caller) -> Result<(), CommunityError> {
    if caller.role == "bot" {
        return Err(CommunityError::Forbidden);
    }
    let mut tx = scope(pool, caller).await?;
    let files: Vec<String> = sqlx::query_scalar("SELECT app_delete_account()")
        .fetch_one(&mut *tx)
        .await
        .map_err(from_sql)?;
    emit(
        &mut tx,
        "member.removed",
        serde_json::json!({"user_id": caller.user_id}),
    )
    .await?;
    tx.commit().await.map_err(from_sql)?;
    crate::messages::remove_files(&files);
    Ok(())
}

/// Tells live sockets of `user_id` to check their session now. Never sent to a client.
async fn session_ended(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: &str,
) -> Result<(), CommunityError> {
    emit(tx, "session.ended", serde_json::json!({"user_id": user_id})).await
}
