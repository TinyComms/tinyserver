//! Custom community emoji and stickers (`0053_custom_emoji.sql`, issue #66).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};

use crate::community::Caller;
use crate::media::prepare_emoji;
use crate::messages::{message_sql, scoped, MessageError};

/// Caps for custom emoji and stickers.
pub const EMOJI_MAX_BYTES: usize = 256 * 1024;
pub const STICKER_MAX_BYTES: usize = 512 * 1024;
pub const STICKER_MAX_PX: i32 = 512;
pub const EMOJI_MAX_COUNT: usize = 200;
pub const STICKER_MAX_COUNT: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmojiSpan {
    pub id: String,
    pub start: usize,
    pub end: usize,
}

pub struct EmojiImage {
    pub bytes: Vec<u8>,
    pub content_type: String,
    pub sha: String,
}

/// Validates a custom emoji or sticker name: 2 to 32 lowercase ASCII alphanumerics or `_`.
pub fn validate_emoji_name(name: &str) -> Result<(), MessageError> {
    if !(2..=32).contains(&name.len())
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(MessageError::Invalid);
    }
    Ok(())
}

/// Validates a kind filter (`emoji` or `sticker`).
pub fn validate_emoji_kind(kind: &str) -> Result<&'static str, MessageError> {
    match kind {
        "emoji" => Ok("emoji"),
        "sticker" => Ok("sticker"),
        _ => Err(MessageError::Invalid),
    }
}

fn looks_like_uuid(id: &str) -> bool {
    let bytes = id.as_bytes();
    bytes.len() == 36
        && bytes[8] == b'-'
        && bytes[13] == b'-'
        && bytes[18] == b'-'
        && bytes[23] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| matches!(i, 8 | 13 | 18 | 23) || b.is_ascii_hexdigit())
}

pub async fn list_emoji(
    pool: &PgPool,
    caller: &Caller,
    kind: Option<&str>,
) -> Result<Value, MessageError> {
    let kind = match kind {
        Some(k) => Some(validate_emoji_kind(k)?),
        None => None,
    };
    let mut tx = scoped(pool, caller).await?;
    let value: Value = sqlx::query_scalar("SELECT app_list_emoji($1)")
        .bind(kind)
        .fetch_one(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(value)
}

pub async fn get_emoji(
    pool: &PgPool,
    caller: &Caller,
    id: &str,
) -> Result<Option<EmojiImage>, MessageError> {
    if !looks_like_uuid(id) {
        return Err(MessageError::NotFound);
    }
    let mut tx = scoped(pool, caller).await?;
    let row = sqlx::query("SELECT bytes, mime, sha256 FROM app_get_emoji($1::uuid)")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(row.map(|row| EmojiImage {
        bytes: row.get(0),
        content_type: row.get(1),
        sha: row.get(2),
    }))
}

pub async fn create_emoji(
    pool: &PgPool,
    caller: &Caller,
    kind: &str,
    name: &str,
    raw_bytes: &[u8],
) -> Result<Value, MessageError> {
    let kind = validate_emoji_kind(kind)?;
    validate_emoji_name(name)?;
    // Verify permission before decoding/re-encoding image bytes.
    let mut check_tx = scoped(pool, caller).await?;
    let allowed: bool = sqlx::query_scalar("SELECT app_has(524288)")
        .fetch_one(&mut *check_tx)
        .await
        .map_err(message_sql)?;
    check_tx.rollback().await.map_err(message_sql)?;
    if !allowed {
        return Err(MessageError::Forbidden);
    }

    let (rewritten, animated) = prepare_emoji(raw_bytes, kind).await?;
    let sha = format!("{:x}", Sha256::digest(&rewritten.bytes));

    let mut tx = scoped(pool, caller).await?;
    let value: Value = sqlx::query_scalar(
        "SELECT app_create_emoji($1, $2, $3, $4, $5, $6)",
    )
    .bind(kind)
    .bind(name)
    .bind(&rewritten.mime)
    .bind(&rewritten.bytes)
    .bind(&sha)
    .bind(animated)
    .fetch_one(&mut *tx)
    .await
    .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(value)
}

pub async fn rename_emoji(
    pool: &PgPool,
    caller: &Caller,
    id: &str,
    name: &str,
) -> Result<Value, MessageError> {
    if !looks_like_uuid(id) {
        return Err(MessageError::NotFound);
    }
    validate_emoji_name(name)?;
    let mut tx = scoped(pool, caller).await?;
    let value: Value = sqlx::query_scalar("SELECT app_rename_emoji($1::uuid, $2)")
        .bind(id)
        .bind(name)
        .fetch_one(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(value)
}

pub async fn delete_emoji(pool: &PgPool, caller: &Caller, id: &str) -> Result<(), MessageError> {
    if !looks_like_uuid(id) {
        return Err(MessageError::NotFound);
    }
    let mut tx = scoped(pool, caller).await?;
    sqlx::query("SELECT app_delete_emoji($1::uuid)")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_emoji_kind, validate_emoji_name};

    #[test]
    fn emoji_name_validation_accepts_2_to_32_lowercase_alnum_underscore() {
        assert!(validate_emoji_name("ok").is_ok());
        assert!(validate_emoji_name("party_parrot_99").is_ok());
        assert!(validate_emoji_name("a".repeat(32).as_str()).is_ok());
        assert!(validate_emoji_name("a").is_err());
        assert!(validate_emoji_name(&"a".repeat(33)).is_err());
        assert!(validate_emoji_name("BadCase").is_err());
        assert!(validate_emoji_name("no-dash").is_err());
        assert!(validate_emoji_name("no space").is_err());
        assert!(validate_emoji_name(":colon:").is_err());
    }

    #[test]
    fn emoji_kind_validation_accepts_emoji_and_sticker_only() {
        assert_eq!(validate_emoji_kind("emoji").unwrap(), "emoji");
        assert_eq!(validate_emoji_kind("sticker").unwrap(), "sticker");
        assert!(validate_emoji_kind("gif").is_err());
    }
}
