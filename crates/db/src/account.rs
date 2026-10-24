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

#[cfg(test)]
mod tests {
    use super::{change_password, close_all_sessions, rename_me};
    use crate::{
        accept_invite, create_invite, current_session, list_audit, list_invites, open_session,
        remove_member, revoke_invite, set_member_role, Caller, CommunityError, Wrote,
    };

    #[tokio::test]
    #[ignore]
    async fn a_member_changes_a_password_a_name_and_signs_out_everywhere() {
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
        let email = std::env::var("TINYSERVER_OWNER_EMAIL").expect("TINYSERVER_OWNER_EMAIL");
        let password =
            std::env::var("TINYSERVER_OWNER_PASSWORD").expect("TINYSERVER_OWNER_PASSWORD");
        let pool = crate::runtime_pool(&url).await.expect("database");
        let opened = open_session(&pool, &email, &password)
            .await
            .expect("owner session");
        let owner = Caller {
            user_id: opened.identity.user_id,
            role: opened.identity.role,
        };

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or(0);
        let guest_email = format!("account-{stamp}@tinyserver.local");
        let first_password = "first-account-password";
        let second_password = "second-account-password";
        let mut guest_id = None;
        let mut invite_ids = Vec::new();

        let outcome = async {
            let Wrote::Fresh(spare) = create_invite(&pool, &owner, "admin", None).await? else {
                return Err(CommunityError::Invalid);
            };
            invite_ids.push(spare.id.clone());
            let Wrote::Fresh(issued) = create_invite(&pool, &owner, "member", None).await? else {
                return Err(CommunityError::Invalid);
            };
            invite_ids.push(issued.id.clone());
            let accepted =
                accept_invite(&pool, &issued.token, &guest_email, first_password, "Guest").await?;
            guest_id = Some(accepted.user_id.clone());
            let guest = Caller {
                user_id: accepted.user_id.clone(),
                role: accepted.role.clone(),
            };

            assert!(matches!(
                revoke_invite(&pool, &guest, &spare.id).await,
                Err(CommunityError::Forbidden)
            ));
            assert!(matches!(
                revoke_invite(&pool, &owner, &issued.id).await,
                Err(CommunityError::NotFound)
            ));
            assert!(matches!(
                revoke_invite(&pool, &owner, "not-a-uuid").await,
                Err(CommunityError::NotFound)
            ));
            set_member_role(&pool, &owner, &guest.user_id, "admin").await?;
            let admin = Caller {
                user_id: guest.user_id.clone(),
                role: "admin".to_string(),
            };
            revoke_invite(&pool, &admin, &spare.id).await?;
            assert!(matches!(
                revoke_invite(&pool, &admin, &spare.id).await,
                Err(CommunityError::NotFound)
            ));
            assert!(!list_invites(&pool, &owner)
                .await?
                .iter()
                .any(|invite| invite.id == spare.id));
            set_member_role(&pool, &owner, &guest.user_id, "member").await?;
            let demoted = current_session(&pool, &accepted.token)
                .await
                .map_err(|_| CommunityError::NotFound)?;
            assert_eq!(demoted.role, "member");

            let other = open_session(&pool, &guest_email, first_password)
                .await
                .map_err(|_| CommunityError::InvalidCredentials)?;
            assert!(matches!(
                change_password(
                    &pool,
                    &guest,
                    &accepted.token,
                    "wrong-password!",
                    second_password
                )
                .await,
                Err(CommunityError::InvalidCredentials)
            ));
            assert!(matches!(
                change_password(&pool, &guest, &accepted.token, first_password, "short").await,
                Err(CommunityError::Invalid)
            ));
            let ended = change_password(
                &pool,
                &guest,
                &accepted.token,
                first_password,
                second_password,
            )
            .await?;
            assert_eq!(ended, 1);
            assert!(current_session(&pool, &accepted.token).await.is_ok());
            assert!(current_session(&pool, &other.token).await.is_err());
            assert!(open_session(&pool, &guest_email, first_password)
                .await
                .is_err());

            assert!(matches!(
                rename_me(&pool, &guest, "   ").await,
                Err(CommunityError::Invalid)
            ));
            assert!(matches!(
                rename_me(&pool, &guest, &"n".repeat(81)).await,
                Err(CommunityError::Invalid)
            ));
            let renamed = rename_me(&pool, &guest, "  Moss  ").await?;
            assert_eq!(renamed.display_name, "Moss");
            assert_eq!(
                current_session(&pool, &accepted.token)
                    .await
                    .map_err(|_| CommunityError::NotFound)?
                    .display_name,
                "Moss"
            );

            let again = open_session(&pool, &guest_email, second_password)
                .await
                .map_err(|_| CommunityError::InvalidCredentials)?;
            assert_eq!(close_all_sessions(&pool, &guest).await?, 2);
            assert!(current_session(&pool, &accepted.token).await.is_err());
            assert!(current_session(&pool, &again.token).await.is_err());

            let kept = open_session(&pool, &guest_email, second_password)
                .await
                .map_err(|_| CommunityError::InvalidCredentials)?;
            remove_member(&pool, &owner, &guest.user_id).await?;
            assert!(current_session(&pool, &kept.token).await.is_err());
            let Wrote::Fresh(back) = create_invite(&pool, &owner, "member", None).await? else {
                return Err(CommunityError::Invalid);
            };
            invite_ids.push(back.id.clone());
            accept_invite(&pool, &back.token, &guest_email, second_password, "Moss").await?;
            assert!(current_session(&pool, &kept.token).await.is_err());

            let actions: Vec<String> = list_audit(&pool, &owner, 50)
                .await?
                .into_iter()
                .filter(|row| row.actor_id.as_deref() == Some(guest.user_id.as_str()))
                .map(|row| row.action)
                .collect();
            for action in [
                "invite.revoke",
                "account.password",
                "account.rename",
                "session.close_all",
            ] {
                assert!(actions.iter().any(|seen| seen == action), "{action}");
            }
            Ok(())
        }
        .await;

        if let Some(id) = guest_id.as_deref() {
            let _ = remove_member(&pool, &owner, id).await;
            if let Ok(mut tx) = crate::community::scope(&pool, &owner).await {
                for invite in &invite_ids {
                    let _ = sqlx::query("DELETE FROM invites WHERE id = $1::uuid")
                        .bind(invite)
                        .execute(&mut *tx)
                        .await;
                }
                let _ = sqlx::query("DELETE FROM users WHERE id = $1::uuid")
                    .bind(id)
                    .execute(&mut *tx)
                    .await;
                let _ = tx.commit().await;
            }
        }
        outcome.expect("account rules");
    }
}
