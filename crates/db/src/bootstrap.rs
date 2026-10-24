use crate::error::DbError;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use sqlx::PgPool;

pub async fn bootstrap_owner(
    pool: &PgPool,
    email: &str,
    display_name: &str,
    password: &str,
) -> Result<(), DbError> {
    let email = normalize_email(email)?;
    let display_name = normalize_name(display_name)?;
    if !(12..=128).contains(&password.len()) {
        return Err(DbError::PasswordTooShort);
    }

    let owners: i64 = sqlx::query_scalar("SELECT count(*) FROM memberships WHERE role = 'owner'")
        .fetch_one(pool)
        .await?;
    if owners > 0 {
        return Err(DbError::OwnerExists);
    }

    let hash = hash_password(password)?;
    sqlx::query(
        "WITH created AS (
             INSERT INTO users (email, display_name, password_hash)
             VALUES ($1, $2, $3)
             RETURNING id
         ),
         member AS (
             INSERT INTO memberships (user_id, role)
             SELECT id, 'owner' FROM created
             RETURNING user_id
         )
         INSERT INTO audit_log (actor_id, action, subject, detail)
         SELECT user_id, 'bootstrap', 'membership', '{}'::jsonb FROM member",
    )
    .bind(&email)
    .bind(&display_name)
    .bind(&hash)
    .execute(pool)
    .await?;
    Ok(())
}

pub(crate) fn hash_password(password: &str) -> Result<String, DbError> {
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| DbError::Hash)
}

pub(crate) fn normalize_email(email: &str) -> Result<String, DbError> {
    let email = email.trim().to_lowercase();
    if email.len() > 254 {
        return Err(DbError::BadEmail);
    }
    let Some((local, domain)) = email.split_once('@') else {
        return Err(DbError::BadEmail);
    };
    if local.is_empty()
        || domain.is_empty()
        || domain.contains('@')
        || email.chars().any(char::is_whitespace)
    {
        return Err(DbError::BadEmail);
    }
    Ok(email)
}

pub(crate) fn normalize_name(name: &str) -> Result<String, DbError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 80 {
        return Err(DbError::BadName);
    }
    Ok(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::{normalize_email, normalize_name};

    #[test]
    fn email_is_trimmed_and_lowered() {
        let email = normalize_email("  Owner@TinyServer.Local ").expect("email");
        assert_eq!(email, "owner@tinyserver.local");
    }

    #[test]
    fn email_needs_one_at() {
        assert!(normalize_email("owner").is_err());
        assert!(normalize_email("a@b@c").is_err());
    }

    #[test]
    fn name_rejects_blank() {
        assert!(normalize_name("   ").is_err());
    }
}
