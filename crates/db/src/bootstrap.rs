//! The first owner. tinyserver keeps no passwords, so bootstrap makes a single-use owner invite
//! and the first person to sign in with it becomes the owner.

use sqlx::PgPool;

use crate::community::STAMP;
use crate::error::DbError;
use crate::session::{new_token, token_digest};
use crate::InviteIssued;

/// How long an owner invite lasts.
const OWNER_INVITE_HOURS: i32 = 24;

/// What `tinyserver bootstrap` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bootstrap {
    /// A new owner invite. Its token is printed once.
    Created(InviteIssued),
    /// No owner yet, and the owner invite made earlier still works until `expires_at`. Nothing
    /// was written.
    Pending { id: String, expires_at: String },
    /// There is an owner. Nothing was written.
    OwnerExists,
}

/// While there is no owner: keeps an unexpired owner invite if there is one, else makes one.
/// With `force` a new invite replaces any earlier one, owner or not; an owner from before
/// sign-in moved to OIDC has no identity and needs one to get back in. Only a new invite is
/// audited, as `bootstrap`.
///
/// Runs as `app_owner`: the invite has no creator and the runtime may not make owner invites.
pub async fn bootstrap(pool: &PgPool, force: bool) -> Result<Bootstrap, DbError> {
    let mut tx = pool.begin().await?;
    // The same lock role changes take, so two bootstraps cannot both see no owner.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('tinyserver.owners'))")
        .execute(&mut *tx)
        .await?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM memberships WHERE owner)")
        .fetch_one(&mut *tx)
        .await?;
    if exists && !force {
        return Ok(Bootstrap::OwnerExists);
    }
    if !force {
        let pending: Option<(String, String)> = sqlx::query_as(&format!(
            "SELECT id::text, to_char(expires_at AT TIME ZONE 'UTC', '{STAMP}')
             FROM invites
             WHERE role = 'owner' AND accepted_at IS NULL AND expires_at > now()
             ORDER BY created_at DESC
             LIMIT 1"
        ))
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((id, expires_at)) = pending {
            return Ok(Bootstrap::Pending { id, expires_at });
        }
    }

    let replaced: Vec<String> = sqlx::query_scalar(
        "DELETE FROM invites
         WHERE role = 'owner' AND accepted_at IS NULL
         RETURNING id::text",
    )
    .fetch_all(&mut *tx)
    .await?;
    for id in &replaced {
        sqlx::query(
            "INSERT INTO audit_log (actor_id, action, subject, detail)
             VALUES (NULL, 'invite.revoke', 'invite', jsonb_build_object('id', $1::text, 'role', 'owner'))",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("SELECT app_emit('invite.revoked', jsonb_build_object('invite_id', $1::text))")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }

    let token = new_token();
    let digest = token_digest(&token);
    let (id, expires_at): (String, String) = sqlx::query_as(&format!(
        "INSERT INTO invites (role, token_hash, created_by, expires_at, max_uses)
         VALUES ('owner', $1, NULL, now() + make_interval(hours => $2), 1)
         RETURNING id::text, to_char(expires_at AT TIME ZONE 'UTC', '{STAMP}')"
    ))
    .bind(digest.as_slice())
    .bind(OWNER_INVITE_HOURS)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO audit_log (actor_id, action, subject, detail)
         VALUES (NULL, 'bootstrap', 'invite', jsonb_build_object('id', $1::text, 'role', 'owner'))",
    )
    .bind(&id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "SELECT app_emit('invite.created', jsonb_build_object('invite', jsonb_build_object(
             'id', $1::text, 'role', 'owner', 'created_by', NULL, 'created_by_name', NULL,
             'expires_at', $2::text, 'accepted_at', NULL, 'accepted_by', NULL, 'label', NULL,
             'max_uses', 1, 'uses', 0, 'role_ids', '[]'::jsonb)))",
    )
    .bind(&id)
    .bind(&expires_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Bootstrap::Created(InviteIssued {
        id,
        token,
        role: "owner".to_string(),
        expires_at: Some(expires_at),
        label: None,
        max_uses: Some(1),
        role_ids: Vec::new(),
    }))
}

/// Makes a new owner invite good for 24 hours and returns its token, which is not stored.
/// Earlier owner invites nobody used are deleted, so only the newest one works. Without
/// `force`, an existing owner means nothing is made and this returns `None`.
pub async fn owner_invite(pool: &PgPool, force: bool) -> Result<Option<InviteIssued>, DbError> {
    let exists = owner_exists(pool).await?;
    if exists && !force {
        return Ok(None);
    }
    match bootstrap(pool, true).await? {
        Bootstrap::Created(issued) => Ok(Some(issued)),
        Bootstrap::Pending { .. } | Bootstrap::OwnerExists => Ok(None),
    }
}

/// Reads memberships past RLS, so it needs the `app_owner` pool.
pub async fn owner_exists(pool: &PgPool) -> Result<bool, DbError> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM memberships WHERE owner)")
        .fetch_one(pool)
        .await
        .map_err(DbError::from)
}

/// A display name is trimmed and 1 to 80 characters.
pub(crate) fn normalize_name(name: &str) -> Result<String, DbError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 80 {
        return Err(DbError::BadName);
    }
    Ok(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::normalize_name;

    #[test]
    fn name_is_trimmed() {
        assert_eq!(normalize_name("  Moss ").expect("name"), "Moss");
    }

    #[test]
    fn name_rejects_blank() {
        assert!(normalize_name("   ").is_err());
    }
}
