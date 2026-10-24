//! A signed-in person's own account: password, display name, and sessions.
//!
//! `users` and `sessions` have no row level security. Each call still runs in the caller's scope
//! so the audit row names the actor.

use sqlx::PgPool;

use crate::bootstrap::{check_password, hash_password, normalize_name};
use crate::community::{audit, from_sql, scope};
use crate::session::{password_matches, token_digest};
use crate::{Caller, CommunityError, Identity};

/// Replaces the caller's password and ends every other session. The session behind `token`
/// stays. A wrong current password is `InvalidCredentials`, the same as a failed sign-in.
pub async fn change_password(
    pool: &PgPool,
    caller: &Caller,
    token: &str,
    current: &str,
    new: &str,
) -> Result<u64, CommunityError> {
    check_password(new).map_err(|_| CommunityError::Invalid)?;
    if current.is_empty() || current.len() > 128 {
        return Err(CommunityError::InvalidCredentials);
    }
    let mut tx = scope(pool, caller).await?;
    let stored: Option<String> =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1::uuid FOR UPDATE")
            .bind(&caller.user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(from_sql)?;
    let Some(stored) = stored else {
        return Err(CommunityError::InvalidCredentials);
    };
    if !password_matches(current, &stored) {
        return Err(CommunityError::InvalidCredentials);
    }
    let hash = hash_password(new)?;
    sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1::uuid")
        .bind(&caller.user_id)
        .bind(&hash)
        .execute(&mut *tx)
        .await
        .map_err(from_sql)?;
    let digest = token_digest(token);
    let ended = sqlx::query("DELETE FROM sessions WHERE user_id = $1::uuid AND token_hash <> $2")
        .bind(&caller.user_id)
        .bind(digest.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(from_sql)?
        .rows_affected();
    audit(
        &mut tx,
        "account.password",
        "user",
        serde_json::json!({"user_id": caller.user_id, "sessions_ended": ended}),
    )
    .await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(ended)
}

/// Sets the caller's display name. It is trimmed and must be 1 to 80 characters.
pub async fn rename_me(
    pool: &PgPool,
    caller: &Caller,
    display_name: &str,
) -> Result<Identity, CommunityError> {
    let display_name = normalize_name(display_name).map_err(|_| CommunityError::Invalid)?;
    let mut tx = scope(pool, caller).await?;
    let row: Option<(String, String, String)> = sqlx::query_as(
        "UPDATE users
         SET display_name = $2
         WHERE id = $1::uuid
         RETURNING id::text, email, display_name",
    )
    .bind(&caller.user_id)
    .bind(&display_name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(from_sql)?;
    let Some((user_id, email, display_name)) = row else {
        return Err(CommunityError::NotFound);
    };
    audit(
        &mut tx,
        "account.rename",
        "user",
        serde_json::json!({"user_id": user_id, "display_name": display_name}),
    )
    .await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(Identity {
        user_id,
        email,
        display_name,
        role: caller.role.clone(),
    })
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
    tx.commit().await.map_err(from_sql)?;
    Ok(ended)
}
