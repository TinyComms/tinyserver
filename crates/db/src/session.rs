//! Login sessions. The client token is returned once. Postgres stores only its SHA-256.

use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordVerifier};
use argon2::Argon2;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use thiserror::Error;

use crate::DbError;

/// Not a credential. Verified when the email is missing so that path is not a fast reject.
const DUMMY_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$govK/UJB4v6x7ZWAIEQpFg$i7GfCsrOPiWiG6ih+U5rTVnC/lAZvK/GaNSMFRH7qKw";

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("invalid credentials")]
    InvalidCredentials,
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
    pub email: String,
    pub display_name: String,
    pub role: String,
}

pub struct OpenedSession {
    pub token: String,
    pub identity: Identity,
}

pub async fn open_session(
    pool: &PgPool,
    email: &str,
    password: &str,
) -> Result<OpenedSession, SessionError> {
    let email = email.trim();
    if email.len() > 254 || password.len() > 128 {
        return Err(SessionError::InvalidCredentials);
    }
    let user: Option<(String, String, String, String)> = sqlx::query_as(
        "SELECT id::text, email, display_name, password_hash
         FROM users
         WHERE lower(email) = lower($1)",
    )
    .bind(email)
    .fetch_optional(pool)
    .await?;

    let stored_hash = match &user {
        Some((_, _, _, hash)) => hash.as_str(),
        None => DUMMY_PASSWORD_HASH,
    };
    let password_ok = password_matches(password, stored_hash);
    let Some((user_id, email, display_name, _)) = user else {
        return Err(SessionError::InvalidCredentials);
    };
    if password.is_empty() || !password_ok {
        return Err(SessionError::InvalidCredentials);
    }

    let role: Option<String> = sqlx::query_scalar("SELECT app_member_role($1::uuid)")
        .bind(&user_id)
        .fetch_one(pool)
        .await?;
    let Some(role) = known_role(role) else {
        return Err(SessionError::InvalidCredentials);
    };

    let token = new_token();
    let digest = token_digest(&token);
    sqlx::query(
        "INSERT INTO sessions (user_id, token_hash, expires_at)
         VALUES ($1::uuid, $2, now() + interval '30 days')",
    )
    .bind(&user_id)
    .bind(digest.as_slice())
    .execute(pool)
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
    let row: Option<(String, String, String, Option<String>)> = sqlx::query_as(
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

pub async fn close_session(pool: &PgPool, token: &str) -> Result<String, SessionError> {
    let digest = token_digest(token);
    let user_id: Option<String> = sqlx::query_scalar(
        "DELETE FROM sessions
         WHERE token_hash = $1
           AND expires_at > now()
           AND app_member_role(sessions.user_id) IN ('owner', 'admin', 'member')
         RETURNING user_id::text",
    )
    .bind(digest.as_slice())
    .fetch_optional(pool)
    .await?;
    user_id.ok_or(SessionError::Unauthorized)
}

fn known_role(role: Option<String>) -> Option<String> {
    match role.as_deref() {
        Some("owner" | "admin" | "member") => role,
        _ => None,
    }
}

pub(crate) fn password_matches(password: &str, encoded: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(encoded) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

pub(crate) fn new_token() -> String {
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
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
    use super::{known_role, new_token, password_matches, token_digest, DUMMY_PASSWORD_HASH};
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    use argon2::Argon2;
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
    fn dummy_hash_rejects_a_password() {
        let parsed = PasswordHash::new(DUMMY_PASSWORD_HASH).expect("dummy phc");
        let rejected = Argon2::default()
            .verify_password(b"not-the-dummy-input", &parsed)
            .is_err();
        assert!(rejected);
    }

    #[test]
    fn empty_password_does_not_match_the_dummy_hash() {
        assert!(!password_matches("", DUMMY_PASSWORD_HASH));
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
