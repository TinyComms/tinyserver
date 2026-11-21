//! Text channels, direct messages, reactions, read cursors, and attachments.
//!
//! Permission checks live in the database functions from `0008_messages.sql`. Those functions
//! expect the schema from `0007_e2ee.sql` (roles, categories, bans, timeouts). A bot is refused
//! here, before SQL, because a bot is not a member.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde_json::{Map, Value};
use sqlx::{PgPool, Postgres, Row, Transaction};
use thiserror::Error;
use tokio::sync::Semaphore;

use crate::community::{scope, Caller, CommunityError};
use crate::scan::{ScanEngine, ScanVerdict};
use crate::DbError;

#[cfg(test)]
use crate::server::{FILE_MAX_DEFAULT, IMAGE_MAX_DEFAULT};

/// The caps `server_settings` holds for this upload.
#[derive(Clone, Copy)]
struct UploadLimits {
    image: i64,
    file: i64,
    archives: crate::media::Archives,
}

#[cfg(test)]
impl UploadLimits {
    fn defaults() -> Self {
        Self {
            image: IMAGE_MAX_DEFAULT,
            file: FILE_MAX_DEFAULT,
            archives: crate::media::Archives::Denied,
        }
    }
}

#[derive(Debug, Error)]
pub enum MessageError {
    #[error("generation changed")]
    GenerationChanged,
    #[error("repair unavailable")]
    RepairUnavailable,
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
    #[error("scanning")]
    Scanning,
    #[error("blocked")]
    Blocked,
    #[error("unavailable")]
    Unavailable,
    /// A plaintext write to an encrypted conversation, or a new plaintext conversation while the
    /// server requires encryption. There is no fallback.
    #[error("e2ee required")]
    E2eeRequired,
    /// Ciphertext for a plaintext conversation.
    #[error("not e2ee")]
    NotE2ee,
    #[error("stale epoch")]
    StaleEpoch,
    /// A commit that does not apply exactly the proposals signed for its epoch.
    #[error("proposals changed")]
    ProposalsChanged,
    #[error("no group")]
    NoGroup,
    #[error("group exists")]
    GroupExists,
    #[error("not in group")]
    NotInGroup,
    #[error("device exists")]
    DeviceExists,
    #[error("cross signature required")]
    CrossSignatureRequired,
    #[error("too many key packages")]
    TooManyKeys,
    /// A sealed upload past the per-person rate or daily volume.
    #[error("slow down")]
    SlowDown,
    #[error("e2ee is off")]
    E2eeOff,
    #[error("bad device")]
    BadDevice,
    #[error("too many devices")]
    TooManyDevices,
    /// An MLS object that is not what it must be, or a request that does not match the group.
    #[error("bad e2ee")]
    BadE2ee,
    /// An encrypted channel whose audience has more devices than one group may hold.
    #[error("e2ee group too large")]
    GroupTooLarge,
    /// A client-chosen id that is already some upload's.
    #[error("id taken")]
    IdTaken,
    /// A community root key is set, and a different one was given without saying to replace it.
    #[error("root exists")]
    RootExists,
    /// This pair already has an encrypted direct, so the plaintext one stays plaintext.
    #[error("e2ee twin")]
    E2eeTwin,
    /// A device link already carries its one archive.
    #[error("archive exists")]
    ArchiveExists,
    /// The conversation already holds the most pins it may (50).
    #[error("pin limit")]
    PinLimit,
    /// The caller already holds the most blocks they may (1000).
    #[error("block limit")]
    BlockLimit,
    /// The community already holds the most emoji or stickers it may (200 per kind).
    #[error("emoji limit")]
    EmojiLimit,
    /// An emoji or sticker with this name already exists.
    #[error("name taken")]
    NameTaken,
    #[error("could not store the upload: {0}")]
    Store(std::io::Error),
    #[error(transparent)]
    Database(#[from] DbError),
}

/// One mention span in a plaintext message. Offsets are UTF-8 byte offsets into the trimmed body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MentionInput {
    pub kind: String,
    pub id: Option<String>,
    pub start: i32,
    pub end: i32,
}

/// One sender-supplied link preview on a plaintext message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewInput {
    pub url: String,
    pub site: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub image_attachment_id: Option<String>,
}

/// A plaintext message post.
pub struct NewMessage<'a> {
    pub body: &'a str,
    pub reply_to: Option<&'a str>,
    pub thread_id: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub attachments: &'a [String],
    pub mentions: Option<&'a [MentionInput]>,
    pub previews: Option<&'a [PreviewInput]>,
    pub emoji: &'a [crate::EmojiSpan],
    pub sticker_id: Option<&'a str>,
}

/// A plaintext message edit. At least one of `body` or `previews` must be present.
pub struct MessageEdit<'a> {
    pub body: Option<&'a str>,
    pub mentions: Option<&'a [MentionInput]>,
    pub previews: Option<&'a [PreviewInput]>,
}

/// Maximum number of mention entries accepted on one message.
pub const MENTIONS_MAX: usize = 50;
/// Maximum number of link previews accepted on one message.
pub const PREVIEWS_MAX: usize = 3;
pub const PREVIEW_URL_MAX: usize = 2048;
pub const PREVIEW_SITE_MAX: usize = 100;
pub const PREVIEW_TITLE_MAX: usize = 200;
pub const PREVIEW_DESCRIPTION_MAX: usize = 500;

/// Parameters for `GET /v1/search`.
pub struct SearchQuery<'a> {
    pub q: &'a str,
    pub conversation_id: Option<&'a str>,
    pub author_id: Option<&'a str>,
    pub before: Option<&'a str>,
    pub limit: Option<i32>,
}

/// Default and maximum page size for message search.
pub const SEARCH_DEFAULT_LIMIT: i32 = 25;
pub const SEARCH_MAX_LIMIT: i32 = 50;
pub const SEARCH_QUERY_MIN: usize = 2;
pub const SEARCH_QUERY_MAX: usize = 200;

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
    e2ee: bool,
) -> Result<Value, MessageError> {
    if let Some(category_id) = category_id {
        if !is_uuid(category_id) {
            return Err(MessageError::Invalid);
        }
    }
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(
        &mut tx,
        "SELECT app_create_channel($1, $2::uuid, $3, $4, $5)",
        |query| {
            query
                .bind(name)
                .bind(category_id)
                .bind(topic)
                .bind(position)
                .bind(e2ee)
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

/// Opens the direct conversation with `user_id`, encrypted or not as asked: a pair may have one
/// of each. `true` when this call created it.
pub async fn open_direct(
    pool: &PgPool,
    caller: &Caller,
    user_id: &str,
    e2ee: bool,
) -> Result<(Value, bool), MessageError> {
    let mut tx = scoped(pool, caller).await?;
    let row: (Value, bool) =
        sqlx::query_as("SELECT body, created FROM app_open_direct($1::uuid, $2)")
            .bind(user_id)
            .bind(e2ee)
            .fetch_one(&mut *tx)
            .await
            .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(row)
}

/// Turns a plaintext conversation into an encrypted one. Messages already stored stay plaintext.
/// Already encrypted answers the conversation again.
pub async fn upgrade_conversation(
    pool: &PgPool,
    caller: &Caller,
    conversation: &str,
) -> Result<Value, MessageError> {
    if !is_uuid(conversation) {
        return Err(MessageError::Invalid);
    }
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(&mut tx, "SELECT app_e2ee_upgrade($1::uuid)", |query| {
        query.bind(conversation)
    })
    .await?;
    commit(tx, value).await
}

pub async fn list_messages(
    pool: &PgPool,
    caller: &Caller,
    conversation: &str,
    before: Option<&str>,
    limit: i32,
) -> Result<Value, MessageError> {
    list_messages_filtered(pool, caller, conversation, before, limit, false).await
}

pub async fn list_messages_filtered(
    pool: &PgPool,
    caller: &Caller,
    conversation: &str,
    before: Option<&str>,
    limit: i32,
    threads_only: bool,
) -> Result<Value, MessageError> {
    let before = match before {
        Some(before) if !before.is_empty() => Some(before),
        _ => None,
    };
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(
        &mut tx,
        "SELECT app_list_messages_filtered($1::uuid, $2::uuid, $3, $4)",
        |query| {
            query
                .bind(conversation)
                .bind(before)
                .bind(limit)
                .bind(threads_only)
        },
    )
    .await?;
    commit(tx, value).await
}

/// Searches plaintext messages the caller may read, newest first.
/// Bots are refused (`Forbidden`). Rate-limited to 30 searches/min (`SlowDown`).
pub async fn search_messages(
    pool: &PgPool,
    caller: &Caller,
    params: &SearchQuery<'_>,
) -> Result<Value, MessageError> {
    let valid = validate_search(params)?;
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(
        &mut tx,
        "SELECT app_search_messages($1, $2::uuid, $3::uuid, $4::uuid, $5)",
        |query| {
            query
                .bind(valid.q)
                .bind(valid.conversation_id)
                .bind(valid.author_id)
                .bind(valid.before)
                .bind(valid.limit)
        },
    )
    .await?;
    commit(tx, value).await
}

struct ValidatedSearch<'a> {
    q: &'a str,
    conversation_id: Option<&'a str>,
    author_id: Option<&'a str>,
    before: Option<&'a str>,
    limit: i32,
}

fn validate_search<'a>(params: &SearchQuery<'a>) -> Result<ValidatedSearch<'a>, MessageError> {
    let q = params.q.trim();
    let len = q.chars().count();
    if !(SEARCH_QUERY_MIN..=SEARCH_QUERY_MAX).contains(&len) || q.chars().any(char::is_control) {
        return Err(MessageError::Invalid);
    }
    let conversation_id = blank_to_none(params.conversation_id);
    if let Some(id) = conversation_id {
        if !is_uuid(id) {
            return Err(MessageError::Invalid);
        }
    }
    let author_id = blank_to_none(params.author_id);
    if let Some(id) = author_id {
        if !is_uuid(id) {
            return Err(MessageError::Invalid);
        }
    }
    let before = blank_to_none(params.before);
    if let Some(id) = before {
        if !is_uuid(id) {
            return Err(MessageError::Invalid);
        }
    }
    let limit = params.limit.unwrap_or(SEARCH_DEFAULT_LIMIT);
    if !(1..=SEARCH_MAX_LIMIT).contains(&limit) {
        return Err(MessageError::Invalid);
    }
    Ok(ValidatedSearch {
        q,
        conversation_id,
        author_id,
        before,
        limit,
    })
}

pub async fn list_thread_messages(
    pool: &PgPool,
    caller: &Caller,
    root_id: &str,
    before: Option<&str>,
    limit: i32,
) -> Result<Value, MessageError> {
    if !is_uuid(root_id) {
        return Err(MessageError::NotFound);
    }
    let before = match before {
        Some(before) if !before.is_empty() => Some(before),
        _ => None,
    };
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(
        &mut tx,
        "SELECT app_list_thread_messages($1::uuid, $2::uuid, $3)",
        |query| query.bind(root_id).bind(before).bind(limit),
    )
    .await?;
    commit(tx, value).await
}

pub async fn mark_thread_read(
    pool: &PgPool,
    caller: &Caller,
    root_id: &str,
    message_id: &str,
) -> Result<(), MessageError> {
    if !is_uuid(root_id) {
        return Err(MessageError::NotFound);
    }
    if !is_uuid(message_id) {
        return Err(MessageError::Invalid);
    }
    let mut tx = scoped(pool, caller).await?;
    sqlx::query("SELECT app_mark_thread_read($1::uuid, $2::uuid)")
        .bind(root_id)
        .bind(message_id)
        .execute(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(())
}

pub async fn follow_thread(
    pool: &PgPool,
    caller: &Caller,
    root_id: &str,
) -> Result<(), MessageError> {
    if !is_uuid(root_id) {
        return Err(MessageError::NotFound);
    }
    let mut tx = scoped(pool, caller).await?;
    sqlx::query("SELECT app_follow_thread($1::uuid)")
        .bind(root_id)
        .execute(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(())
}

pub async fn unfollow_thread(
    pool: &PgPool,
    caller: &Caller,
    root_id: &str,
) -> Result<(), MessageError> {
    if !is_uuid(root_id) {
        return Err(MessageError::NotFound);
    }
    let mut tx = scoped(pool, caller).await?;
    sqlx::query("SELECT app_unfollow_thread($1::uuid)")
        .bind(root_id)
        .execute(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(())
}

pub async fn list_followed_threads(pool: &PgPool, caller: &Caller) -> Result<Value, MessageError> {
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(&mut tx, "SELECT app_list_followed_threads()", |query| query).await?;
    commit(tx, value).await
}

pub async fn post_message(
    pool: &PgPool,
    caller: &Caller,
    conversation: &str,
    input: &NewMessage<'_>,
) -> Result<Value, MessageError> {
    let reply_to = blank_to_none(input.reply_to);
    if let Some(reply_to) = reply_to {
        if !is_uuid(reply_to) {
            return Err(MessageError::Invalid);
        }
    }
    let sticker_id = blank_to_none(input.sticker_id);
    if let Some(sticker_id) = sticker_id {
        if !is_uuid(sticker_id) {
            return Err(MessageError::Invalid);
        }
    }
    let thread_id = blank_to_none(input.thread_id);
    if let Some(thread_id) = thread_id {
        if !is_uuid(thread_id) {
            return Err(MessageError::Invalid);
        }
    }
    let client_id = blank_to_none(input.client_id);
    let attachments = uuid_list(input.attachments)?;
    let trimmed = input.body.trim();
    let mentions_json = match input.mentions {
        Some(list) => Some(prepare_mentions(trimmed, list)?),
        None => None,
    };
    let previews_json = match input.previews {
        Some(list) => Some(prepare_previews(Some(trimmed), list)?),
        None => None,
    };
    let emoji_json = serde_json::to_value(input.emoji).map_err(|_| MessageError::Invalid)?;
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(
        &mut tx,
        "SELECT app_post_message_thread($1::uuid, $2, $3::uuid, $4,
            CASE WHEN $5::text[] IS NULL THEN NULL
            ELSE (SELECT coalesce(array_agg(item::uuid), '{}') FROM unnest($5::text[]) AS item) END,
            $6, $7::uuid, $8::uuid, $9, $10)",
        |query| {
            query
                .bind(conversation)
                .bind(input.body)
                .bind(reply_to)
                .bind(client_id)
                .bind(attachments)
                .bind(emoji_json)
                .bind(sticker_id)
                .bind(thread_id)
                .bind(mentions_json)
                .bind(previews_json)
        },
    )
    .await?;
    commit(tx, value).await
}

pub async fn edit_message(
    pool: &PgPool,
    caller: &Caller,
    id: &str,
    edit: &MessageEdit<'_>,
) -> Result<Value, MessageError> {
    if edit.body.is_none() && edit.previews.is_none() {
        return Err(MessageError::Invalid);
    }
    let trimmed = edit.body.map(str::trim);
    let mentions_json = match (trimmed, edit.mentions) {
        (Some(body), Some(list)) => Some(prepare_mentions(body, list)?),
        (None, Some(_)) => return Err(MessageError::Invalid),
        (_, None) => None,
    };
    let previews_json = match edit.previews {
        Some(list) => Some(prepare_previews(trimmed, list)?),
        None => None,
    };
    let mut tx = scoped(pool, caller).await?;
    let (message, removed): (Value, Vec<String>) = sqlx::query_as(
        "SELECT r_message, r_removed_files FROM app_edit_message($1::uuid, $2, $3, $4)",
    )
    .bind(id)
    .bind(edit.body)
    .bind(mentions_json)
    .bind(previews_json)
    .fetch_one(&mut *tx)
    .await
    .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    remove_files(&removed);
    Ok(message)
}

/// Validates sender-supplied link previews. When `body` is known (`Some`), every preview's `url`
/// must appear in `body`; SQL re-checks against the stored body on edits that omit `body`.
fn prepare_previews(body: Option<&str>, previews: &[PreviewInput]) -> Result<Value, MessageError> {
    if previews.len() > PREVIEWS_MAX {
        return Err(MessageError::Invalid);
    }
    let mut out = Vec::with_capacity(previews.len());
    for preview in previews {
        let url = preview.url.as_str();
        if url.is_empty()
            || url.chars().count() > PREVIEW_URL_MAX
            || url.chars().any(char::is_control)
        {
            return Err(MessageError::Invalid);
        }
        let parsed = url::Url::parse(url).map_err(|_| MessageError::Invalid)?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host().is_none() {
            return Err(MessageError::Invalid);
        }
        if let Some(body) = body {
            if !body.contains(url) {
                return Err(MessageError::Invalid);
            }
        }
        let mut obj = Map::new();
        obj.insert("url".to_string(), Value::String(url.to_string()));
        if let Some(site) = preview.site.as_deref() {
            if site.chars().count() > PREVIEW_SITE_MAX || site.chars().any(char::is_control) {
                return Err(MessageError::Invalid);
            }
            if !site.is_empty() {
                obj.insert("site".to_string(), Value::String(site.to_string()));
            }
        }
        if let Some(title) = preview.title.as_deref() {
            if title.chars().count() > PREVIEW_TITLE_MAX || title.chars().any(char::is_control) {
                return Err(MessageError::Invalid);
            }
            if !title.is_empty() {
                obj.insert("title".to_string(), Value::String(title.to_string()));
            }
        }
        if let Some(desc) = preview.description.as_deref() {
            if desc.chars().count() > PREVIEW_DESCRIPTION_MAX || desc.chars().any(char::is_control)
            {
                return Err(MessageError::Invalid);
            }
            if !desc.is_empty() {
                obj.insert("description".to_string(), Value::String(desc.to_string()));
            }
        }
        if let Some(img) = blank_to_none(preview.image_attachment_id.as_deref()) {
            if !is_uuid(img) {
                return Err(MessageError::Invalid);
            }
            obj.insert(
                "image_attachment_id".to_string(),
                Value::String(img.to_string()),
            );
        }
        out.push(Value::Object(obj));
    }
    Ok(Value::Array(out))
}

/// Validates mention entries and drops spans that fall outside `body` or split a UTF-8 code point.
/// More than [`MENTIONS_MAX`] entries or an unknown `kind` is [`MessageError::Invalid`].
fn prepare_mentions(body: &str, mentions: &[MentionInput]) -> Result<Value, MessageError> {
    if mentions.len() > MENTIONS_MAX {
        return Err(MessageError::Invalid);
    }
    let mut out = Vec::with_capacity(mentions.len());
    for entry in mentions {
        if !matches!(entry.kind.as_str(), "user" | "role" | "everyone") {
            return Err(MessageError::Invalid);
        }
        let Ok(start) = usize::try_from(entry.start) else {
            continue;
        };
        let Ok(end) = usize::try_from(entry.end) else {
            continue;
        };
        if start >= end
            || end > body.len()
            || !body.is_char_boundary(start)
            || !body.is_char_boundary(end)
        {
            continue;
        }
        let mut obj = Map::new();
        obj.insert("kind".to_string(), Value::String(entry.kind.clone()));
        if entry.kind != "everyone" {
            let Some(id) = entry.id.as_deref().map(str::trim).filter(|s| is_uuid(s)) else {
                continue;
            };
            obj.insert("id".to_string(), Value::String(id.to_string()));
        }
        obj.insert("start".to_string(), Value::from(entry.start));
        obj.insert("end".to_string(), Value::from(entry.end));
        out.push(Value::Object(obj));
    }
    Ok(Value::Array(out))
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

pub async fn toggle_custom_reaction(
    pool: &PgPool,
    caller: &Caller,
    id: &str,
    emoji_id: &str,
) -> Result<Value, MessageError> {
    if !is_uuid(emoji_id) {
        return Err(MessageError::Invalid);
    }
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(
        &mut tx,
        "SELECT app_toggle_custom_reaction($1::uuid, $2::uuid)",
        |query| query.bind(id).bind(emoji_id),
    )
    .await?;
    commit(tx, value).await
}

pub async fn clear_custom_reaction(
    pool: &PgPool,
    caller: &Caller,
    id: &str,
    emoji_id: &str,
) -> Result<(), MessageError> {
    if !is_uuid(emoji_id) {
        return Err(MessageError::Invalid);
    }
    let mut tx = scoped(pool, caller).await?;
    sqlx::query("SELECT app_clear_custom_reaction($1::uuid, $2::uuid)")
        .bind(id)
        .bind(emoji_id)
        .execute(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(())
}

/// Pins one message, in a channel with `manage_channels` there or as either person of a direct.
/// Idempotent. The 51st pin of one conversation is [`MessageError::PinLimit`].
pub async fn pin_message(pool: &PgPool, caller: &Caller, id: &str) -> Result<(), MessageError> {
    let mut tx = scoped(pool, caller).await?;
    sqlx::query("SELECT app_pin_message($1::uuid)")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(())
}

/// Takes one pin back. Idempotent: a message that is not pinned answers `Ok` too.
pub async fn unpin_message(pool: &PgPool, caller: &Caller, id: &str) -> Result<(), MessageError> {
    let mut tx = scoped(pool, caller).await?;
    sqlx::query("SELECT app_unpin_message($1::uuid)")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(())
}

/// The pinned messages of one conversation, newest pin first, at most 50.
pub async fn list_pins(
    pool: &PgPool,
    caller: &Caller,
    conversation: &str,
) -> Result<Value, MessageError> {
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(&mut tx, "SELECT app_list_pins($1::uuid)", |query| {
        query.bind(conversation)
    })
    .await?;
    commit(tx, value).await
}

/// The caller's own block list: `[{user_id, display_name, created_at}]`.
pub async fn list_blocks(pool: &PgPool, caller: &Caller) -> Result<Value, MessageError> {
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(&mut tx, "SELECT app_list_blocks()", |query| query).await?;
    commit(tx, value).await
}

/// Blocks `user_id`. Idempotent. Refuses self-block (`Invalid`), missing user (`NotFound`),
/// and past the per-person cap (`BlockLimit`).
pub async fn block_user(pool: &PgPool, caller: &Caller, user_id: &str) -> Result<(), MessageError> {
    if !is_uuid(user_id) {
        return Err(MessageError::NotFound);
    }
    let mut tx = scoped(pool, caller).await?;
    sqlx::query("SELECT app_block_user($1::uuid)")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(())
}

/// Unblocks `user_id`. Idempotent.
pub async fn unblock_user(
    pool: &PgPool,
    caller: &Caller,
    user_id: &str,
) -> Result<(), MessageError> {
    if !is_uuid(user_id) {
        return Ok(());
    }
    let mut tx = scoped(pool, caller).await?;
    sqlx::query("SELECT app_unblock_user($1::uuid)")
        .bind(user_id)
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
    engine: &Arc<dyn ScanEngine>,
) -> Result<Value, MessageError> {
    person(caller)?;
    // The limits come from a short transaction of their own. The connection goes back to the
    // pool before the image is re-encoded and the file is scanned, which can take seconds, and
    // is taken again only to store the row.
    let limits = {
        let mut tx = scope(pool, caller).await.map_err(from_community)?;
        let limits = upload_limits(&mut tx).await?;
        tx.commit().await.map_err(message_sql)?;
        limits
    };
    let prepared = prepare(upload, limits)?;
    let rewritten = if matches!(prepared.kind, "image" | "gif") {
        // Decoding is CPU work and takes its turn among the process's decodes (at most two at
        // once); it holds no database connection while it waits or runs.
        let raster = crate::media::rewrite_raster_in_turn(&upload.bytes, &prepared.mime).await?;
        Some(raster)
    } else {
        None
    };
    if rewritten
        .as_ref()
        .is_some_and(|raster| !within(raster.bytes.len(), limits.image))
    {
        return Err(MessageError::TooLarge);
    }
    let bytes = rewritten
        .as_ref()
        .map(|raster| raster.bytes.as_slice())
        .unwrap_or(&upload.bytes);
    let mime = rewritten
        .as_ref()
        .map(|raster| raster.mime.as_str())
        .unwrap_or(&prepared.mime);
    let kind = rewritten
        .as_ref()
        .map(|raster| raster.kind)
        .unwrap_or(prepared.kind);
    let width = rewritten
        .as_ref()
        .map(|raster| Some(raster.width))
        .unwrap_or(upload.width);
    let height = rewritten
        .as_ref()
        .map(|raster| Some(raster.height))
        .unwrap_or(upload.height);
    // Scanned before any row exists or any connection is held. A blocked or unscannable file
    // never reaches the database; the row below is stored only for bytes that came back clean.
    match scan_bytes(engine, bytes, mime, kind).await {
        ScanVerdict::Clean => {}
        ScanVerdict::Blocked { .. } => return Err(MessageError::Blocked),
        ScanVerdict::Unavailable => return Err(MessageError::Unavailable),
    }
    let mut tx = scope(pool, caller).await.map_err(from_community)?;
    let mut row: Value =
        sqlx::query_scalar("SELECT app_save_attachment($1, $2, $3, $4, $5, $6, $7)")
            .bind(&prepared.name)
            .bind(mime)
            .bind(kind)
            .bind(i32::try_from(bytes.len()).map_err(|_| MessageError::TooLarge)?)
            .bind(width)
            .bind(height)
            .bind(upload.duration)
            .fetch_one(&mut *tx)
            .await
            .map_err(message_sql)?;
    let Some(id) = row.get("id").and_then(Value::as_str) else {
        return Err(MessageError::Invalid);
    };
    let id = id.to_string();
    if let Err(error) = write_upload(&id, bytes) {
        abort_upload(tx, &id).await;
        return Err(error);
    }
    if let Err(error) = set_scan(&mut tx, &id, "scanning").await {
        abort_upload(tx, &id).await;
        return Err(error);
    }
    if let Err(error) = set_scan(&mut tx, &id, "clean").await {
        abort_upload(tx, &id).await;
        return Err(error);
    }
    if let Some(obj) = row.as_object_mut() {
        obj.insert("scan_status".into(), Value::from("clean"));
    }
    if let Err(error) = tx.commit().await {
        remove_files(std::slice::from_ref(&id));
        return Err(message_sql(error));
    }
    Ok(row)
}

/// A sealed upload: the bytes of an end-to-end encrypted attachment, stored exactly as they came.
/// There is no type check, no sniffing, no image decode and no scan: the server cannot read
/// them, and it does not say it can. They are written once to their final path, with no
/// plaintext temporary file, and can only be linked into an encrypted conversation.
pub async fn save_sealed_attachment(
    pool: &PgPool,
    caller: &Caller,
    bytes: &[u8],
    id: Option<&str>,
) -> Result<Value, MessageError> {
    if bytes.is_empty() || id.is_some_and(|id| !is_uuid(id)) {
        return Err(MessageError::Invalid);
    }
    let size = i32::try_from(bytes.len()).map_err(|_| MessageError::TooLarge)?;
    let mut tx = scoped(pool, caller).await?;
    let row: Value = sqlx::query_scalar("SELECT app_save_sealed_attachment($1, $2::uuid)")
        .bind(size)
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(message_sql)?;
    let Some(id) = row.get("id").and_then(Value::as_str) else {
        return Err(MessageError::Invalid);
    };
    let id = id.to_string();
    if let Err(error) = write_upload(&id, bytes) {
        abort_upload(tx, &id).await;
        return Err(error);
    }
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

/// Deletes memberless group conversations left behind by kick, ban, or account deletion and
/// returns the attachment file ids to remove from disk.
pub(crate) async fn sweep_empty_groups(pool: &PgPool) -> Result<Vec<String>, DbError> {
    let ids: Vec<String> = sqlx::query_scalar("SELECT app_group_sweep()")
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

pub(crate) async fn scoped<'a>(
    pool: &'a PgPool,
    caller: &Caller,
) -> Result<Transaction<'a, Postgres>, MessageError> {
    person(caller)?;
    scope(pool, caller).await.map_err(from_community)
}

pub(crate) async fn commit(
    tx: Transaction<'_, Postgres>,
    value: Value,
) -> Result<Value, MessageError> {
    tx.commit().await.map_err(message_sql)?;
    Ok(value)
}

pub(crate) async fn json_in<'a, F>(
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

pub(crate) fn message_sql(error: sqlx::Error) -> MessageError {
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
        "P0423" => MessageError::Scanning,
        "P0403" => MessageError::Blocked,
        "P0503" => MessageError::Unavailable,
        "P0E01" => MessageError::E2eeRequired,
        "P0E02" => MessageError::NotE2ee,
        "P0E03" => MessageError::StaleEpoch,
        "P0E04" => MessageError::ProposalsChanged,
        "P0E05" => MessageError::NoGroup,
        "P0E06" => MessageError::GroupExists,
        "P0E07" => MessageError::NotInGroup,
        "P0E08" => MessageError::DeviceExists,
        "P0E09" => MessageError::CrossSignatureRequired,
        "P0E10" => MessageError::TooManyKeys,
        "P0E11" => MessageError::SlowDown,
        "P0E12" => MessageError::E2eeOff,
        "P0E13" => MessageError::BadDevice,
        "P0E14" => MessageError::TooManyDevices,
        "P0E15" => MessageError::BadE2ee,
        "P0E16" => MessageError::GroupTooLarge,
        "P0E17" => MessageError::IdTaken,
        "P0E18" => MessageError::RootExists,
        "P0E19" => MessageError::E2eeTwin,
        "P0E20" => MessageError::ArchiveExists,
        "P0E21" => MessageError::GenerationChanged,
        "P0E22" => MessageError::RepairUnavailable,
        "P0E23" => MessageError::PinLimit,
        "P0E24" => MessageError::BlockLimit,
        "P0E25" => MessageError::EmojiLimit,
        "23505" => MessageError::NameTaken,
        "P0002" | "22P02" => MessageError::NotFound,
        "22023" | "23514" | "23503" => MessageError::Invalid,
        _ => MessageError::Database(DbError::from(error)),
    }
}

fn channel_patch(value: &Value) -> Result<Value, MessageError> {
    let Some(obj) = value.as_object() else {
        return Err(MessageError::Invalid);
    };
    // Encryption is not a channel patch. Turning it on is POST /v1/conversations/{id}/e2ee,
    // and there is no way to turn it off.
    if obj.contains_key("e2ee") {
        return Err(MessageError::Invalid);
    }
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

pub(crate) fn blank_to_none(value: Option<&str>) -> Option<&str> {
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

pub(crate) fn is_uuid(value: &str) -> bool {
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
    let row =
        sqlx::query("SELECT image_max_bytes, file_max_bytes, allow_archives FROM server_settings")
            .fetch_optional(&mut **tx)
            .await
            .map_err(message_sql)?;
    let Some(row) = row else {
        return Err(MessageError::Forbidden);
    };
    let allow_archives: bool = row.try_get(2).map_err(message_sql)?;
    Ok(UploadLimits {
        image: row.try_get(0).map_err(message_sql)?,
        file: row.try_get(1).map_err(message_sql)?,
        archives: if allow_archives {
            crate::media::Archives::Allowed
        } else {
            crate::media::Archives::Denied
        },
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
    let classified = crate::media::classify(&name, &mime, &upload.bytes, limits.archives)?;
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

pub(crate) fn upload_dir() -> String {
    std::env::var("TINYSERVER_UPLOAD_DIR").unwrap_or_else(|_| "uploads".to_string())
}

fn file_path(id: &str) -> Result<PathBuf, MessageError> {
    if !is_uuid(id) {
        return Err(MessageError::Invalid);
    }
    Ok(PathBuf::from(upload_dir()).join(id))
}

pub(crate) fn write_upload(id: &str, bytes: &[u8]) -> Result<(), MessageError> {
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

async fn set_scan(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    status: &str,
) -> Result<(), MessageError> {
    sqlx::query("SELECT app_set_attachment_scan($1::uuid, $2)")
        .bind(id)
        .bind(status)
        .execute(&mut **tx)
        .await
        .map_err(message_sql)?;
    Ok(())
}

pub(crate) async fn abort_upload(tx: Transaction<'_, Postgres>, id: &str) {
    remove_files(&[id.to_string()]);
    let _ = tx.rollback().await;
}

async fn scan_bytes(
    engine: &Arc<dyn ScanEngine>,
    bytes: &[u8],
    mime: &str,
    kind: &str,
) -> ScanVerdict {
    scan_with(engine, bytes, mime, kind, scan_slots(), scan_timeout()).await
}

async fn scan_with(
    engine: &Arc<dyn ScanEngine>,
    bytes: &[u8],
    mime: &str,
    kind: &str,
    slots: &Arc<Semaphore>,
    limit: Duration,
) -> ScanVerdict {
    let deadline = tokio::time::Instant::now() + limit;
    // Waiting for a slot shares the request deadline. Timing out here does not start a scan.
    let Ok(Ok(permit)) = tokio::time::timeout_at(deadline, Arc::clone(slots).acquire_owned()).await
    else {
        return ScanVerdict::Unavailable;
    };
    let engine = Arc::clone(engine);
    let bytes = bytes.to_vec();
    let mime = mime.to_owned();
    let kind = kind.to_owned();
    // The permit stays in the blocking task. The request can return Unavailable when `deadline`
    // passes; the slot is not free until `scan` returns. The clamd socket has its own deadline,
    // so the thread ends and drops the permit.
    let scan = tokio::task::spawn_blocking(move || {
        let verdict = engine.scan(&bytes, &mime, &kind);
        drop(permit);
        verdict
    });
    match tokio::time::timeout_at(deadline, scan).await {
        Ok(Ok(verdict)) => verdict,
        _ => ScanVerdict::Unavailable,
    }
}

pub fn scan_timeout() -> Duration {
    let parsed = std::env::var("TINYSERVER_SCAN_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok());
    let ms = match parsed {
        Some(0) | None => 8_000,
        Some(ms) => ms.min(15_000),
    };
    Duration::from_millis(ms)
}

fn scan_slots() -> &'static Arc<Semaphore> {
    static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SLOTS.get_or_init(|| Arc::new(Semaphore::new(3)))
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::Semaphore;

    use super::{one_emoji, scan_with, MessageError, NewAttachment, UploadLimits};
    use crate::scan::{ScanEngine, ScanVerdict};

    struct Stall {
        entered: Arc<AtomicBool>,
        release: Arc<AtomicBool>,
    }

    impl ScanEngine for Stall {
        fn scan(&self, _bytes: &[u8], _mime: &str, _kind: &str) -> ScanVerdict {
            self.entered.store(true, Ordering::SeqCst);
            while !self.release.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
            ScanVerdict::Clean
        }
    }

    struct LetGo(Arc<AtomicBool>);

    impl Drop for LetGo {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn scan_slot_stays_taken_until_the_scan_returns() {
        let slots = Arc::new(Semaphore::new(3));
        let release = Arc::new(AtomicBool::new(false));
        let _let_go = LetGo(Arc::clone(&release));
        let mut entered = Vec::new();
        let mut tasks = Vec::new();
        for _ in 0..3 {
            let flag = Arc::new(AtomicBool::new(false));
            entered.push(Arc::clone(&flag));
            let engine: Arc<dyn ScanEngine> = Arc::new(Stall {
                entered: flag,
                release: Arc::clone(&release),
            });
            let slots = Arc::clone(&slots);
            tasks.push(tokio::spawn(async move {
                scan_with(
                    &engine,
                    b"hello",
                    "text/plain",
                    "file",
                    &slots,
                    Duration::from_millis(80),
                )
                .await
            }));
        }

        let started = std::time::Instant::now();
        while entered.iter().any(|flag| !flag.load(Ordering::SeqCst)) {
            if started.elapsed() > Duration::from_secs(2) {
                panic!("scans did not start");
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let fourth_entered = Arc::new(AtomicBool::new(false));
        let fourth_engine: Arc<dyn ScanEngine> = Arc::new(Stall {
            entered: Arc::clone(&fourth_entered),
            release: Arc::clone(&release),
        });
        let fourth_slots = Arc::clone(&slots);
        let fourth = tokio::spawn(async move {
            scan_with(
                &fourth_engine,
                b"hello",
                "text/plain",
                "file",
                &fourth_slots,
                Duration::from_millis(200),
            )
            .await
        });

        let fourth_verdict = match fourth.await {
            Ok(verdict) => verdict,
            Err(error) => panic!("fourth scan task: {error}"),
        };
        assert!(matches!(fourth_verdict, ScanVerdict::Unavailable));
        assert!(
            !fourth_entered.load(Ordering::SeqCst),
            "a fourth scan must not start while three are outstanding"
        );

        for task in tasks {
            let verdict = match task.await {
                Ok(verdict) => verdict,
                Err(error) => panic!("scan task: {error}"),
            };
            assert!(matches!(verdict, ScanVerdict::Unavailable));
        }

        let still_held = tokio::time::timeout(
            Duration::from_millis(50),
            Arc::clone(&slots).acquire_owned(),
        )
        .await;
        assert!(
            still_held.is_err(),
            "the slot stays taken until the scan returns"
        );

        release.store(true, Ordering::SeqCst);
        let mut freed = 0;
        let released = tokio::time::timeout(Duration::from_secs(2), async {
            while freed < 3 {
                let Ok(permit) = Arc::clone(&slots).acquire_owned().await else {
                    break;
                };
                drop(permit);
                freed += 1;
            }
        })
        .await;
        assert!(
            released.is_ok() && freed == 3,
            "slots return once the scans finish"
        );
        assert!(
            !fourth_entered.load(Ordering::SeqCst),
            "the fourth scan already returned and must not start later"
        );
    }

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

    #[test]
    fn mentions_drop_bad_spans_and_reject_over_limit_or_unknown_kind() {
        let uid = "11111111-1111-4111-8111-111111111111".to_string();
        let body = "hi @Mara 🎉";
        let prepared = super::prepare_mentions(
            body,
            &[
                super::MentionInput {
                    kind: "user".into(),
                    id: Some(uid.clone()),
                    start: 3,
                    end: 8,
                },
                // Out of bounds: dropped.
                super::MentionInput {
                    kind: "user".into(),
                    id: Some(uid.clone()),
                    start: 0,
                    end: 99,
                },
                // Splits the 4-byte emoji: dropped.
                super::MentionInput {
                    kind: "user".into(),
                    id: Some(uid.clone()),
                    start: 9,
                    end: 10,
                },
                // Bad uuid: dropped.
                super::MentionInput {
                    kind: "user".into(),
                    id: Some("not-a-uuid".into()),
                    start: 0,
                    end: 2,
                },
                // Valid everyone.
                super::MentionInput {
                    kind: "everyone".into(),
                    id: None,
                    start: 0,
                    end: 2,
                },
            ],
        )
        .expect("ok");
        assert_eq!(prepared.as_array().map(Vec::len), Some(2));

        let unknown = super::prepare_mentions(
            body,
            &[super::MentionInput {
                kind: "channel".into(),
                id: None,
                start: 0,
                end: 2,
            }],
        );
        assert!(matches!(unknown, Err(MessageError::Invalid)));

        let too_many: Vec<_> = (0..=super::MENTIONS_MAX)
            .map(|_| super::MentionInput {
                kind: "everyone".into(),
                id: None,
                start: 0,
                end: 2,
            })
            .collect();
        assert!(matches!(
            super::prepare_mentions(body, &too_many),
            Err(MessageError::Invalid)
        ));
    }

    #[test]
    fn search_query_validates_length_controls_uuids_and_limit() {
        let ok = super::validate_search(&super::SearchQuery {
            q: "  lantern  ",
            conversation_id: None,
            author_id: None,
            before: None,
            limit: None,
        })
        .expect("ok");
        assert_eq!(ok.q, "lantern");
        assert_eq!(ok.limit, super::SEARCH_DEFAULT_LIMIT);

        for bad in [
            super::SearchQuery {
                q: "a",
                conversation_id: None,
                author_id: None,
                before: None,
                limit: None,
            },
            super::SearchQuery {
                q: "hi\nthere",
                conversation_id: None,
                author_id: None,
                before: None,
                limit: None,
            },
            super::SearchQuery {
                q: "lantern",
                conversation_id: Some("not-a-uuid"),
                author_id: None,
                before: None,
                limit: None,
            },
            super::SearchQuery {
                q: "lantern",
                conversation_id: None,
                author_id: None,
                before: None,
                limit: Some(51),
            },
            super::SearchQuery {
                q: "lantern",
                conversation_id: None,
                author_id: None,
                before: None,
                limit: Some(0),
            },
        ] {
            assert!(matches!(
                super::validate_search(&bad),
                Err(MessageError::Invalid)
            ));
        }
    }

    #[test]
    fn previews_enforce_scheme_body_presence_caps_and_controls() {
        let body = "see https://example.com/a and http://example.org/b";
        let ok = super::prepare_previews(
            Some(body),
            &[super::PreviewInput {
                url: "https://example.com/a".into(),
                site: Some("Example".into()),
                title: Some("Title".into()),
                description: Some("Desc".into()),
                image_attachment_id: Some("11111111-1111-4111-8111-111111111111".into()),
            }],
        )
        .expect("ok");
        assert_eq!(ok.as_array().map(Vec::len), Some(1));

        // URL not in body -> Invalid.
        assert!(matches!(
            super::prepare_previews(
                Some(body),
                &[super::PreviewInput {
                    url: "https://other.example/c".into(),
                    site: None,
                    title: None,
                    description: None,
                    image_attachment_id: None,
                }]
            ),
            Err(MessageError::Invalid)
        ));

        // Non-http(s) scheme -> Invalid.
        assert!(matches!(
            super::prepare_previews(
                Some("javascript:alert(1)"),
                &[super::PreviewInput {
                    url: "javascript:alert(1)".into(),
                    site: None,
                    title: None,
                    description: None,
                    image_attachment_id: None,
                }]
            ),
            Err(MessageError::Invalid)
        ));

        // Over-long fields & control characters -> Invalid.
        for bad in [
            super::PreviewInput {
                url: "https://example.com/a".into(),
                site: Some("s".repeat(101)),
                title: None,
                description: None,
                image_attachment_id: None,
            },
            super::PreviewInput {
                url: "https://example.com/a".into(),
                site: None,
                title: Some("t".repeat(201)),
                description: None,
                image_attachment_id: None,
            },
            super::PreviewInput {
                url: "https://example.com/a".into(),
                site: None,
                title: None,
                description: Some("d".repeat(501)),
                image_attachment_id: None,
            },
            super::PreviewInput {
                url: "https://example.com/a".into(),
                site: None,
                title: Some("bad\ntitle".into()),
                description: None,
                image_attachment_id: None,
            },
            super::PreviewInput {
                url: "https://example.com/a".into(),
                site: None,
                title: None,
                description: None,
                image_attachment_id: Some("not-a-uuid".into()),
            },
        ] {
            assert!(matches!(
                super::prepare_previews(Some(body), &[bad]),
                Err(MessageError::Invalid)
            ));
        }

        // More than 3 previews -> Invalid.
        let four: Vec<_> = (0..4)
            .map(|_| super::PreviewInput {
                url: "https://example.com/a".into(),
                site: None,
                title: None,
                description: None,
                image_attachment_id: None,
            })
            .collect();
        assert!(matches!(
            super::prepare_previews(Some(body), &four),
            Err(MessageError::Invalid)
        ));
    }
}
