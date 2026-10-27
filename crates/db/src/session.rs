//! Login sessions. The client token is returned once. Postgres stores only its SHA-256.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use thiserror::Error;

use crate::DbError;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("unauthorized")]
    Unauthorized,
    #[error(transparent)]
    Database(#[from] DbError),
}

impl From<sqlx::Error> for SessionError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(DbError::from(error))
    }
}

pub struct Identity {
    pub user_id: String,
    /// What the provider said when the account was made. It may be missing.
    pub email: Option<String>,
    pub display_name: String,
    pub role: String,
}

pub struct OpenedSession {
    pub token: String,
    pub identity: Identity,
}

/// Where a session came from, and how long it lasts.
pub(crate) struct Origin<'a> {
    /// The provider the person signed in at.
    pub issuer: Option<&'a str>,
    /// The provider's session id, for back-channel logout.
    pub sid: Option<&'a str>,
    /// After this many days the person signs in again. Nothing extends it.
    pub days: u32,
}

/// Opens a 30-day session for a member that no provider knows about. Sign-in opens sessions
/// through a redeemed one-time code instead; see `auth`. Tests and tools use this.
pub async fn open_session(pool: &PgPool, user_id: &str) -> Result<OpenedSession, SessionError> {
    let mut tx = pool.begin().await?;
    let origin = Origin {
        issuer: None,
        sid: None,
        days: 30,
    };
    let opened = open_session_in(&mut tx, user_id, origin).await?;
    tx.commit().await?;
    Ok(opened)
}

pub(crate) async fn open_session_in(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
    origin: Origin<'_>,
) -> Result<OpenedSession, SessionError> {
    let row: Option<(String, Option<String>, String, Option<String>)> = sqlx::query_as(
        "SELECT id::text, email, display_name, app_member_role(id)
         FROM users
         WHERE id = $1::uuid",
    )
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((user_id, email, display_name, role)) = row else {
        return Err(SessionError::Unauthorized);
    };
    let Some(role) = known_role(role) else {
        return Err(SessionError::Unauthorized);
    };

    let token = new_token();
    let digest = token_digest(&token);
    sqlx::query(
        "INSERT INTO sessions (user_id, token_hash, issuer, sid, expires_at)
         VALUES ($1::uuid, $2, $3, $4, now() + make_interval(days => $5))",
    )
    .bind(&user_id)
    .bind(digest.as_slice())
    .bind(origin.issuer)
    .bind(origin.sid)
    .bind(origin.days.clamp(1, 365) as i32)
    .execute(&mut **tx)
    .await?;

    Ok(OpenedSession {
        token,
        identity: Identity {
            user_id,
            email,
            display_name,
            role,
        },
    })
}

pub async fn current_session(pool: &PgPool, token: &str) -> Result<Identity, SessionError> {
    let digest = token_digest(token);
    let row: Option<(String, Option<String>, String, Option<String>)> = sqlx::query_as(
        "SELECT u.id::text, u.email, u.display_name, app_member_role(u.id)
         FROM sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = $1
           AND s.expires_at > now()",
    )
    .bind(digest.as_slice())
    .fetch_optional(pool)
    .await?;
    let Some((user_id, email, display_name, role)) = row else {
        return Err(SessionError::Unauthorized);
    };
    let Some(role) = known_role(role) else {
        return Err(SessionError::Unauthorized);
    };
    Ok(Identity {
        user_id,
        email,
        display_name,
        role,
    })
}

/// Also emits `session.ended`, so a live socket on this token closes.
pub async fn close_session(pool: &PgPool, token: &str) -> Result<String, SessionError> {
    let digest = token_digest(token);
    let mut tx = pool.begin().await?;
    let user_id: Option<String> = sqlx::query_scalar(
        "DELETE FROM sessions
         WHERE token_hash = $1
           AND expires_at > now()
           AND app_member_role(sessions.user_id) IN ('owner', 'admin', 'member')
         RETURNING user_id::text",
    )
    .bind(digest.as_slice())
    .fetch_optional(&mut *tx)
    .await?;
    let user_id = user_id.ok_or(SessionError::Unauthorized)?;
    sqlx::query("SELECT app_emit('session.ended', jsonb_build_object('user_id', $1::text))")
        .bind(&user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(user_id)
}

fn known_role(role: Option<String>) -> Option<String> {
    match role.as_deref() {
        Some("owner" | "admin" | "member") => role,
        _ => None,
    }
}

/// 32 random bytes, URL-safe base64 without padding. Session tokens, invite tokens, sign-in
/// states, and one-time codes are all this shape.
pub(crate) fn new_token() -> String {
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).expect("the OS random number generator failed");
    URL_SAFE_NO_PAD.encode(raw)
}

/// SHA-256 of the token string the client presents, not of the raw random bytes.
pub(crate) fn token_digest(token: &str) -> [u8; 32] {
    let digest = Sha256::digest(token.as_bytes());
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    bytes
}

#[cfg(test)]
mod tests {
    use super::{known_role, new_token, token_digest};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    #[test]
    fn token_is_url_safe_unpadded_32_bytes() {
        let token = new_token();
        assert_ne!(token, new_token());
        assert!(token
            .bytes()
            .all(|byte| { matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_') }));
        let raw = URL_SAFE_NO_PAD.decode(&token).expect("token decodes");
        assert_eq!(raw.len(), 32);
        assert!(!token.contains('='));
    }

    #[test]
    fn digest_is_sha256_of_the_presented_token() {
        let digest = token_digest("abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn role_must_be_owner_admin_or_member() {
        assert_eq!(
            known_role(Some("owner".to_string())).as_deref(),
            Some("owner")
        );
        assert_eq!(
            known_role(Some("admin".to_string())).as_deref(),
            Some("admin")
        );
        assert_eq!(
            known_role(Some("member".to_string())).as_deref(),
            Some("member")
        );
        assert_eq!(known_role(None), None);
        assert_eq!(known_role(Some("Owner".to_string())), None);
    }
}
