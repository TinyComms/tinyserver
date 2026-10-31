//! Text channels, direct messages, reactions, read cursors, and attachments.
//!
//! Permission checks live in the database functions from `0008_messages.sql`. Those functions
//! expect the schema from `0007_e2ee.sql` (roles, categories, bans, timeouts). A bot is refused
//! here, before SQL, because a bot is not a member.

use std::path::PathBuf;

use serde_json::{Map, Value};
use sqlx::{PgPool, Postgres, Row, Transaction};
use thiserror::Error;

use crate::community::{scope, Caller, CommunityError};
use crate::DbError;

#[cfg(test)]
use crate::server::{FILE_MAX_DEFAULT, IMAGE_MAX_DEFAULT};

/// The caps `server_settings` holds for this upload.
#[derive(Clone, Copy)]
struct UploadLimits {
    image: i64,
    file: i64,
}

#[cfg(test)]
impl UploadLimits {
    fn defaults() -> Self {
        Self {
            image: IMAGE_MAX_DEFAULT,
            file: FILE_MAX_DEFAULT,
        }
    }
}

#[derive(Debug, Error)]
pub enum MessageError {
    #[error("forbidden")]
    Forbidden,
    #[error("banned")]
    Banned,
    #[error("hierarchy")]
    Hierarchy,
    #[error("not found")]
    NotFound,
    #[error("invalid")]
    Invalid,
    #[error("too large")]
    TooLarge,
    #[error("unsupported media")]
    UnsupportedMedia,
    #[error("could not store the upload: {0}")]
    Store(std::io::Error),
    #[error(transparent)]
    Database(#[from] DbError),
}

/// One file a member is uploading. Bytes are written next to the row, under the upload directory.
pub struct NewAttachment {
    pub name: String,
    pub mime: String,
    pub bytes: Vec<u8>,
    pub width: Option<i32>,
    pub height: Option<i32>,
    pub duration: Option<i32>,
}

/// A file the caller is allowed to read.
pub struct AttachmentFile {
    pub name: String,
    pub mime: String,
    pub bytes: Vec<u8>,
}

struct Prepared {
    name: String,
    mime: String,
    kind: &'static str,
}

pub async fn list_channels(pool: &PgPool, caller: &Caller) -> Result<Value, MessageError> {
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(&mut tx, "SELECT app_list_channels()", |query| query).await?;
    commit(tx, value).await
}

pub async fn create_channel(
    pool: &PgPool,
    caller: &Caller,
    name: &str,
    category_id: Option<&str>,
    topic: Option<&str>,
    position: Option<i32>,
) -> Result<Value, MessageError> {
    if let Some(category_id) = category_id {
        if !is_uuid(category_id) {
            return Err(MessageError::Invalid);
        }
    }
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(
        &mut tx,
        "SELECT app_create_channel($1, $2::uuid, $3, $4)",
        |query| {
            query
                .bind(name)
                .bind(category_id)
                .bind(topic)
                .bind(position)
        },
    )
    .await?;
    commit(tx, value).await
}

pub async fn update_channel(
    pool: &PgPool,
    caller: &Caller,
    id: &str,
    patch: &Value,
) -> Result<Value, MessageError> {
    let patch = channel_patch(patch)?;
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(
        &mut tx,
        "SELECT app_update_channel($1::uuid, $2)",
        |query| query.bind(id).bind(patch),
    )
    .await?;
    commit(tx, value).await
}

pub async fn delete_channel(
    pool: &PgPool,
    caller: &Caller,
    id: &str,
) -> Result<Vec<String>, MessageError> {
    let mut tx = scoped(pool, caller).await?;
    let ids: Vec<String> = sqlx::query_scalar("SELECT app_delete_channel($1::uuid)")
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    remove_files(&ids);
    Ok(ids)
}

/// `allow == None` deletes the override. Setting one needs manage roles and manage channels.
pub async fn set_channel_override(
    pool: &PgPool,
    caller: &Caller,
    channel_id: &str,
    role_id: &str,
    allow: Option<i64>,
    deny: Option<i64>,
) -> Result<Value, MessageError> {
    if let Some(allow) = allow {
        if allow < 0 || deny.unwrap_or(0) < 0 {
            return Err(MessageError::Invalid);
        }
    }
    let deny = allow.map(|_| deny.unwrap_or(0));
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(
        &mut tx,
        "SELECT app_set_channel_override($1::uuid, $2::uuid, $3, $4)",
        |query| query.bind(channel_id).bind(role_id).bind(allow).bind(deny),
    )
    .await?;
    commit(tx, value).await
}

pub async fn list_directs(pool: &PgPool, caller: &Caller) -> Result<Value, MessageError> {
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(&mut tx, "SELECT app_list_directs()", |query| query).await?;
    commit(tx, value).await
}

/// Opens the direct conversation with `user_id`. `true` when this call created it.
pub async fn open_direct(
    pool: &PgPool,
    caller: &Caller,
    user_id: &str,
) -> Result<(Value, bool), MessageError> {
    let mut tx = scoped(pool, caller).await?;
    let row: (Value, bool) = sqlx::query_as("SELECT body, created FROM app_open_direct($1::uuid)")
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(row)
}

pub async fn list_messages(
    pool: &PgPool,
    caller: &Caller,
    conversation: &str,
    before: Option<&str>,
    limit: i32,
) -> Result<Value, MessageError> {
    let before = match before {
        Some(before) if !before.is_empty() => Some(before),
        _ => None,
    };
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(
        &mut tx,
        "SELECT app_list_messages($1::uuid, $2::uuid, $3)",
        |query| query.bind(conversation).bind(before).bind(limit),
    )
    .await?;
    commit(tx, value).await
}

pub async fn post_message(
    pool: &PgPool,
    caller: &Caller,
    conversation: &str,
    body: &str,
    reply_to: Option<&str>,
    client_id: Option<&str>,
    attachments: &[String],
) -> Result<Value, MessageError> {
    let reply_to = blank_to_none(reply_to);
    if let Some(reply_to) = reply_to {
        if !is_uuid(reply_to) {
            return Err(MessageError::Invalid);
        }
    }
    let client_id = blank_to_none(client_id);
    let attachments = uuid_list(attachments)?;
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(
        &mut tx,
        "SELECT app_post_message($1::uuid, $2, $3::uuid, $4,
            CASE WHEN $5::text[] IS NULL THEN NULL
            ELSE (SELECT coalesce(array_agg(item::uuid), '{}') FROM unnest($5::text[]) AS item) END)",
        |query| {
            query
                .bind(conversation)
                .bind(body)
                .bind(reply_to)
                .bind(client_id)
                .bind(attachments)
        },
    )
    .await?;
    commit(tx, value).await
}

pub async fn edit_message(
    pool: &PgPool,
    caller: &Caller,
    id: &str,
    body: &str,
) -> Result<Value, MessageError> {
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(&mut tx, "SELECT app_edit_message($1::uuid, $2)", |query| {
        query.bind(id).bind(body)
    })
    .await?;
    commit(tx, value).await
}

pub async fn delete_message(
    pool: &PgPool,
    caller: &Caller,
    id: &str,
) -> Result<Vec<String>, MessageError> {
    let mut tx = scoped(pool, caller).await?;
    let ids: Vec<String> = sqlx::query_scalar("SELECT app_delete_message($1::uuid)")
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    remove_files(&ids);
    Ok(ids)
}

pub async fn toggle_reaction(
    pool: &PgPool,
    caller: &Caller,
    id: &str,
    emoji: &str,
) -> Result<Value, MessageError> {
    one_emoji(emoji)?;
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(
        &mut tx,
        "SELECT app_toggle_reaction($1::uuid, $2)",
        |query| query.bind(id).bind(emoji),
    )
    .await?;
    commit(tx, value).await
}

pub async fn clear_reaction(
    pool: &PgPool,
    caller: &Caller,
    id: &str,
    emoji: &str,
) -> Result<(), MessageError> {
    one_emoji(emoji)?;
    let mut tx = scoped(pool, caller).await?;
    sqlx::query("SELECT app_clear_reaction($1::uuid, $2)")
        .bind(id)
        .bind(emoji)
        .execute(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(())
}

pub async fn mark_read(
    pool: &PgPool,
    caller: &Caller,
    conversation: &str,
    message_id: &str,
) -> Result<(), MessageError> {
    let mut tx = scoped(pool, caller).await?;
    sqlx::query("SELECT app_mark_read($1::uuid, $2::uuid)")
        .bind(conversation)
        .bind(message_id)
        .execute(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(())
}

/// The other people who should see a typing frame. Empty when the caller is alone in a channel.
pub async fn typing_recipients(
    pool: &PgPool,
    caller: &Caller,
    conversation: &str,
) -> Result<Vec<String>, MessageError> {
    let mut tx = scoped(pool, caller).await?;
    let ids: Vec<String> = sqlx::query_scalar("SELECT app_typing_recipients($1::uuid)")
        .bind(conversation)
        .fetch_one(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(ids)
}

pub async fn save_attachment(
    pool: &PgPool,
    caller: &Caller,
    upload: &NewAttachment,
) -> Result<Value, MessageError> {
    person(caller)?;
    let mut tx = scope(pool, caller).await.map_err(from_community)?;
    let limits = upload_limits(&mut tx).await?;
    let prepared = prepare(upload, limits)?;
    let row: Value = sqlx::query_scalar("SELECT app_save_attachment($1, $2, $3, $4, $5, $6, $7)")
        .bind(&prepared.name)
        .bind(&prepared.mime)
        .bind(prepared.kind)
        .bind(i32::try_from(upload.bytes.len()).map_err(|_| MessageError::TooLarge)?)
        .bind(upload.width)
        .bind(upload.height)
        .bind(upload.duration)
        .fetch_one(&mut *tx)
        .await
        .map_err(message_sql)?;
    let Some(id) = row.get("id").and_then(Value::as_str) else {
        return Err(MessageError::Invalid);
    };
    let id = id.to_string();
    write_upload(&id, &upload.bytes)?;
    if let Err(error) = tx.commit().await {
        remove_files(std::slice::from_ref(&id));
        return Err(message_sql(error));
    }
    Ok(row)
}

pub async fn open_attachment(
    pool: &PgPool,
    caller: &Caller,
    id: &str,
) -> Result<AttachmentFile, MessageError> {
    let mut tx = scoped(pool, caller).await?;
    let (name, mime): (String, String) =
        sqlx::query_as("SELECT name, mime FROM app_attachment_meta($1::uuid)")
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    let path = file_path(id)?;
    let bytes = std::fs::read(&path).map_err(|_| MessageError::NotFound)?;
    Ok(AttachmentFile { name, mime, bytes })
}

/// Attachment ids nobody linked within an hour. The rows are already gone.
pub(crate) async fn expire_orphans(pool: &PgPool) -> Result<Vec<String>, DbError> {
    let ids: Vec<String> = sqlx::query_scalar("SELECT app_drop_orphan_attachments()")
        .fetch_one(pool)
        .await?;
    Ok(ids)
}

/// Deletes `{upload_dir}/{id}` for each uuid. A bad id or a missing file is ignored.
pub(crate) fn remove_files(ids: &[String]) {
    for id in ids {
        let Ok(path) = file_path(id) else {
            continue;
        };
        let _ = std::fs::remove_file(path);
    }
}

fn person(caller: &Caller) -> Result<(), MessageError> {
    if caller.role == "bot" {
        Err(MessageError::Forbidden)
    } else {
        Ok(())
    }
}

async fn scoped<'a>(
    pool: &'a PgPool,
    caller: &Caller,
) -> Result<Transaction<'a, Postgres>, MessageError> {
    person(caller)?;
    scope(pool, caller).await.map_err(from_community)
}

async fn commit(tx: Transaction<'_, Postgres>, value: Value) -> Result<Value, MessageError> {
    tx.commit().await.map_err(message_sql)?;
    Ok(value)
}

async fn json_in<'a, F>(
    tx: &mut Transaction<'a, Postgres>,
    sql: &'a str,
    bind: F,
) -> Result<Value, MessageError>
where
    F: FnOnce(
        sqlx::query::QueryScalar<'a, Postgres, Value, sqlx::postgres::PgArguments>,
    ) -> sqlx::query::QueryScalar<'a, Postgres, Value, sqlx::postgres::PgArguments>,
{
    bind(sqlx::query_scalar(sql))
        .fetch_one(&mut **tx)
        .await
        .map_err(message_sql)
}

fn from_community(error: CommunityError) -> MessageError {
    match error {
        CommunityError::Database(error) => MessageError::Database(error),
        CommunityError::NotFound => MessageError::NotFound,
        CommunityError::Invalid => MessageError::Invalid,
        CommunityError::Banned => MessageError::Banned,
        CommunityError::Hierarchy => MessageError::Hierarchy,
        CommunityError::Forbidden
        | CommunityError::LastOwner
        | CommunityError::AlreadyMember
        | CommunityError::IdempotencyConflict
        | CommunityError::Incomplete
        | CommunityError::DefaultRole => MessageError::Forbidden,
    }
}

fn message_sql(error: sqlx::Error) -> MessageError {
    let Some(database) = error.as_database_error() else {
        return MessageError::Database(DbError::from(error));
    };
    let Some(code) = database.code() else {
        return MessageError::Database(DbError::from(error));
    };
    let message = database.message();
    match code.as_ref() {
        "42501" if message.contains("banned") => MessageError::Banned,
        "42501" if message.contains("hierarchy") => MessageError::Hierarchy,
        "42501" if message.contains("timed out") => MessageError::Forbidden,
        "42501" => MessageError::Forbidden,
        "22023" if message.contains("too large") => MessageError::TooLarge,
        "22023" if message.contains("unsupported media") => MessageError::UnsupportedMedia,
        "P0002" | "22P02" => MessageError::NotFound,
        "22023" | "23514" | "23503" => MessageError::Invalid,
        _ => MessageError::Database(DbError::from(error)),
    }
}

fn channel_patch(value: &Value) -> Result<Value, MessageError> {
    let Some(obj) = value.as_object() else {
        return Err(MessageError::Invalid);
    };
    let mut patch = Map::new();
    if let Some(name) = obj.get("name") {
        if !name.is_string() {
            return Err(MessageError::Invalid);
        }
        patch.insert("name".to_string(), name.clone());
    }
    if let Some(topic) = obj.get("topic") {
        if !topic.is_string() && !topic.is_null() {
            return Err(MessageError::Invalid);
        }
        patch.insert("topic".to_string(), topic.clone());
    }
    if let Some(position) = obj.get("position") {
        let Some(position) = position.as_i64() else {
            return Err(MessageError::Invalid);
        };
        if i32::try_from(position).is_err() {
            return Err(MessageError::Invalid);
        }
        patch.insert("position".to_string(), Value::from(position));
    }
    if let Some(category) = obj.get("category_id") {
        if let Some(id) = category.as_str() {
            if !is_uuid(id) {
                return Err(MessageError::Invalid);
            }
        } else if !category.is_null() {
            return Err(MessageError::Invalid);
        }
        patch.insert("category_id".to_string(), category.clone());
    }
    if patch.is_empty() {
        return Err(MessageError::Invalid);
    }
    Ok(Value::Object(patch))
}

fn blank_to_none(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn uuid_list(ids: &[String]) -> Result<Option<Vec<String>>, MessageError> {
    if ids.is_empty() {
        return Ok(None);
    }
    if ids.iter().any(|id| !is_uuid(id)) {
        return Err(MessageError::Invalid);
    }
    Ok(Some(ids.to_vec()))
}

fn is_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    bytes.iter().enumerate().all(|(index, byte)| match index {
        8 | 13 | 18 | 23 => *byte == b'-',
        _ => byte.is_ascii_hexdigit(),
    })
}

async fn upload_limits(tx: &mut Transaction<'_, Postgres>) -> Result<UploadLimits, MessageError> {
    let row = sqlx::query("SELECT image_max_bytes, file_max_bytes FROM server_settings")
        .fetch_optional(&mut **tx)
        .await
        .map_err(message_sql)?;
    let Some(row) = row else {
        return Err(MessageError::Forbidden);
    };
    Ok(UploadLimits {
        image: row.try_get(0).map_err(message_sql)?,
        file: row.try_get(1).map_err(message_sql)?,
    })
}

fn prepare(upload: &NewAttachment, limits: UploadLimits) -> Result<Prepared, MessageError> {
    let name = clean_name(&upload.name)?;
    let mime = normalize_mime(&upload.mime)?;
    for value in [upload.width, upload.height, upload.duration] {
        if value.unwrap_or(0) < 0 {
            return Err(MessageError::Invalid);
        }
    }
    let classified =
        crate::media::classify(&name, &mime, &upload.bytes, crate::media::Archives::Denied)?;
    let limit = match classified.kind {
        "image" | "gif" => limits.image,
        _ => limits.file,
    };
    if !within(upload.bytes.len(), limit) {
        return Err(MessageError::TooLarge);
    }
    Ok(Prepared {
        name: classified.name,
        mime: classified.mime,
        kind: classified.kind,
    })
}

fn clean_name(name: &str) -> Result<String, MessageError> {
    let Some(base) = name.trim().rsplit(['/', '\\']).next() else {
        return Err(MessageError::Invalid);
    };
    let base = base.trim();
    if base.is_empty() || base.chars().count() > 200 || base.chars().any(char::is_control) {
        return Err(MessageError::Invalid);
    }
    Ok(base.to_string())
}

fn normalize_mime(mime: &str) -> Result<String, MessageError> {
    let Some(mime) = mime.split(';').next() else {
        return Err(MessageError::Invalid);
    };
    let mime = mime.trim().to_ascii_lowercase();
    if mime.is_empty()
        || mime.len() > 127
        || mime.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(MessageError::Invalid);
    }
    if mime == "image/jpg" {
        Ok("image/jpeg".to_string())
    } else {
        Ok(mime)
    }
}

fn within(len: usize, limit: i64) -> bool {
    i64::try_from(len).is_ok_and(|len| len <= limit)
}

fn upload_dir() -> String {
    std::env::var("TINYSERVER_UPLOAD_DIR").unwrap_or_else(|_| "uploads".to_string())
}

fn file_path(id: &str) -> Result<PathBuf, MessageError> {
    if !is_uuid(id) {
        return Err(MessageError::Invalid);
    }
    Ok(PathBuf::from(upload_dir()).join(id))
}

fn write_upload(id: &str, bytes: &[u8]) -> Result<(), MessageError> {
    let path = file_path(id)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(MessageError::Store)?;
    }
    if let Err(error) = std::fs::write(&path, bytes) {
        let _ = std::fs::remove_file(&path);
        return Err(MessageError::Store(error));
    }
    Ok(())
}

/// One unicode grapheme, 1 to 16 scalars, with no ASCII control.
fn one_emoji(emoji: &str) -> Result<(), MessageError> {
    let count = emoji.chars().count();
    if !(1..=16).contains(&count)
        || emoji.chars().any(|ch| ch.is_ascii_control())
        || !one_grapheme(emoji)
    {
        return Err(MessageError::Invalid);
    }
    Ok(())
}

fn one_grapheme(text: &str) -> bool {
    let mut chars = text.chars().peekable();
    let Some(first) = chars.next() else {
        return false;
    };
    if is_joiner(first) || is_extend(first) || first.is_ascii_control() {
        return false;
    }
    if is_regional(first) {
        if chars.peek().is_some_and(|next| is_regional(*next)) {
            chars.next();
        }
        return chars.next().is_none();
    }
    while let Some(next) = chars.peek().copied() {
        if is_extend(next) {
            chars.next();
            continue;
        }
        if is_joiner(next) {
            chars.next();
            let Some(base) = chars.next() else {
                return false;
            };
            if is_joiner(base) || is_extend(base) || base.is_ascii_control() || is_regional(base) {
                return false;
            }
            continue;
        }
        return false;
    }
    true
}

fn is_joiner(c: char) -> bool {
    c == '\u{200D}'
}

fn is_regional(c: char) -> bool {
    ('\u{1F1E6}'..='\u{1F1FF}').contains(&c)
}

fn is_extend(c: char) -> bool {
    matches!(
        c,
        '\u{0300}'..='\u{036F}'
            | '\u{1AB0}'..='\u{1AFF}'
            | '\u{1DC0}'..='\u{1DFF}'
            | '\u{20D0}'..='\u{20FF}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FE20}'..='\u{FE2F}'
            | '\u{1F3FB}'..='\u{1F3FF}'
            | '\u{E0020}'..='\u{E007F}'
            | '\u{E0100}'..='\u{E01EF}'
    )
}

#[cfg(test)]
mod tests {
    use super::{one_emoji, MessageError, NewAttachment, UploadLimits};

    #[test]
    fn an_emoji_is_one_grapheme() {
        assert!(one_emoji("👍").is_ok());
        assert!(one_emoji("👍🏻").is_ok());
        assert!(one_emoji("🇺🇸").is_ok());
        assert!(one_emoji("❤️").is_ok());
        assert!(one_emoji("1️⃣").is_ok());
        assert!(one_emoji("👨‍👩‍👧").is_ok());
        assert!(one_emoji("a\u{0301}").is_ok());
        assert!(one_emoji("").is_err());
        assert!(one_emoji("👍👍").is_err());
        assert!(one_emoji("ab").is_err());
        assert!(one_emoji("\n").is_err());
        assert!(one_emoji("👍\n").is_err());
    }

    #[test]
    fn an_oversized_file_is_too_large() {
        let upload = NewAttachment {
            name: "notes.txt".to_string(),
            mime: "text/plain".to_string(),
            bytes: vec![0_u8; FILE_MAX_PLUS],
            width: None,
            height: None,
            duration: None,
        };
        assert!(matches!(
            super::prepare(&upload, UploadLimits::defaults()),
            Err(MessageError::TooLarge)
        ));
    }

    const FILE_MAX_PLUS: usize = super::FILE_MAX_DEFAULT as usize + 1;
}
