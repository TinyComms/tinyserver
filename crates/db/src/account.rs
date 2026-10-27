//! A signed-in person's own account: display name and sessions.
//!
//! `users` and `sessions` have no row level security. Each call still runs in the caller's scope
//! so the audit row names the actor.

use sqlx::PgPool;

use crate::bootstrap::normalize_name;
use crate::community::{audit, from_sql, member_event, scope};
use crate::outbox::emit;
use crate::{Caller, CommunityError, Identity};

/// Sets the caller's display name. It is trimmed and must be 1 to 80 characters.
pub async fn rename_me(
    pool: &PgPool,
    caller: &Caller,
    display_name: &str,
) -> Result<Identity, CommunityError> {
    let display_name = normalize_name(display_name).map_err(|_| CommunityError::Invalid)?;
    let mut tx = scope(pool, caller).await?;
    let row: Option<(String, Option<String>, String)> = sqlx::query_as(
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
    emit(
        &mut tx,
        "member.renamed",
        member_event(&user_id, &display_name, &caller.role),
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
    session_ended(&mut tx, &caller.user_id).await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(ended)
}

/// Tells live sockets of `user_id` to check their session now. Never sent to a client.
async fn session_ended(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: &str,
) -> Result<(), CommunityError> {
    emit(tx, "session.ended", serde_json::json!({"user_id": user_id})).await
}
