//! Device linking: the short-lived relay between a person's new device and one they already have,
//! and the archive of history the old one hands over.
//!
//! Everything here is a call to a `SECURITY DEFINER` function from `migrations/0035`, which checks
//! that the caller made the link. The bytes are opaque: this crate stores and returns them, and
//! never logs them, their length, or a link id.

use std::path::PathBuf;

use sqlx::PgPool;

use crate::messages::{message_sql, scoped, upload_dir, MessageError};
use crate::{Caller, DbError};

/// A link id is 16 bytes.
pub const LINK_ID_LEN: usize = 16;
/// The largest message, decoded.
pub const LINK_MESSAGE_MAX: usize = 8 * 1024;

/// One relayed message. `sender` is the label the client gave it, `new` or `old`.
#[derive(Debug, Clone)]
pub struct LinkMessage {
    pub seq: i32,
    pub sender: String,
    pub data: Vec<u8>,
}

/// A stored archive: its file name under `{upload_dir}/links/` and its length.
#[derive(Debug, Clone)]
pub struct LinkArchive {
    pub name: String,
    pub bytes: u64,
}

fn id_arg(id: &[u8]) -> Result<&[u8], MessageError> {
    if id.len() == LINK_ID_LEN {
        Ok(id)
    } else {
        Err(MessageError::NotFound)
    }
}

/// Where archives live: `{upload_dir}/links`. The media routes read only `{upload_dir}/{uuid}`,
/// so nothing in here is reachable through them, and the scanner never sees these bytes.
pub fn link_dir() -> PathBuf {
    PathBuf::from(upload_dir()).join("links")
}

/// The path of an archive, or `None` for a name that is not 64 lowercase hex characters.
pub fn link_archive_path(name: &str) -> Option<PathBuf> {
    name_ok(name).then(|| link_dir().join(name))
}

/// The path an archive is written to before it is complete.
pub fn link_archive_part(name: &str) -> Option<PathBuf> {
    name_ok(name).then(|| link_dir().join(format!("{name}.part")))
}

fn name_ok(name: &str) -> bool {
    name.len() == 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Deletes an archive and any partial copy of it. A missing file is not an error.
pub fn remove_link_archive(name: &str) {
    for path in [link_archive_path(name), link_archive_part(name)]
        .into_iter()
        .flatten()
    {
        let _ = std::fs::remove_file(path);
    }
}

/// Makes a link. Returns when it expires, as the API writes times.
pub async fn create_link(
    pool: &PgPool,
    caller: &Caller,
    id: &[u8],
) -> Result<String, MessageError> {
    let id = id_arg(id)?;
    let mut tx = scoped(pool, caller).await?;
    let expires: String = sqlx::query_scalar("SELECT app_e2ee_link_create($1)")
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(expires)
}

/// Stores one message. Returns its number.
pub async fn post_link_message(
    pool: &PgPool,
    caller: &Caller,
    id: &[u8],
    sender: &str,
    data: &[u8],
) -> Result<i32, MessageError> {
    let id = id_arg(id)?;
    let mut tx = scoped(pool, caller).await?;
    let seq: i32 = sqlx::query_scalar("SELECT app_e2ee_link_post($1, $2, $3)")
        .bind(id)
        .bind(sender)
        .bind(data)
        .fetch_one(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(seq)
}

/// The messages after `after`, in order. `not found` once the link expired or went.
pub async fn link_messages(
    pool: &PgPool,
    caller: &Caller,
    id: &[u8],
    after: i32,
) -> Result<Vec<LinkMessage>, MessageError> {
    let id = id_arg(id)?;
    let mut tx = scoped(pool, caller).await?;
    let rows: Vec<(i32, String, Vec<u8>)> =
        sqlx::query_as("SELECT r_seq, r_sender, r_data FROM app_e2ee_link_messages($1, $2)")
            .bind(id)
            .bind(after)
            .fetch_all(&mut *tx)
            .await
            .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(rows
        .into_iter()
        .map(|(seq, sender, data)| LinkMessage { seq, sender, data })
        .collect())
}

/// Deletes the caller's link, its messages and its archive file. Idempotent: a link that is
/// already gone, or is someone else's, is left as it is and is not an error.
pub async fn delete_link(pool: &PgPool, caller: &Caller, id: &[u8]) -> Result<(), MessageError> {
    if id.len() != LINK_ID_LEN {
        return Ok(());
    }
    let mut tx = scoped(pool, caller).await?;
    let name: Option<String> = sqlx::query_scalar("SELECT app_e2ee_link_delete($1)")
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    if let Some(name) = name {
        remove_link_archive(&name);
    }
    Ok(())
}

/// Claims the link's one archive under `name`, for `bytes` bytes.
pub async fn begin_link_archive(
    pool: &PgPool,
    caller: &Caller,
    id: &[u8],
    name: &str,
    bytes: u64,
) -> Result<(), MessageError> {
    let id = id_arg(id)?;
    let bytes = i64::try_from(bytes).map_err(|_| MessageError::TooLarge)?;
    let mut tx = scoped(pool, caller).await?;
    sqlx::query("SELECT app_e2ee_link_archive_begin($1, $2, $3)")
        .bind(id)
        .bind(name)
        .bind(bytes)
        .execute(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(())
}

/// Gives up an upload that did not finish, and deletes what was written of it.
pub async fn abort_link_archive(
    pool: &PgPool,
    caller: &Caller,
    id: &[u8],
    name: &str,
) -> Result<(), MessageError> {
    remove_link_archive(name);
    let id = id_arg(id)?;
    let mut tx = scoped(pool, caller).await?;
    sqlx::query("SELECT app_e2ee_link_archive_abort($1, $2)")
        .bind(id)
        .bind(name)
        .execute(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(())
}

/// Marks a complete upload ready. `not found`, with the file deleted, when the link went while it
/// was being written.
pub async fn finish_link_archive(
    pool: &PgPool,
    caller: &Caller,
    id: &[u8],
    name: &str,
) -> Result<(), MessageError> {
    let id = id_arg(id)?;
    let mut tx = scoped(pool, caller).await?;
    let done: bool = sqlx::query_scalar("SELECT app_e2ee_link_archive_done($1, $2)")
        .bind(id)
        .bind(name)
        .fetch_one(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    if done {
        Ok(())
    } else {
        remove_link_archive(name);
        Err(MessageError::NotFound)
    }
}

/// The caller's stored archive, while it may still be read.
pub async fn link_archive(
    pool: &PgPool,
    caller: &Caller,
    id: &[u8],
) -> Result<LinkArchive, MessageError> {
    let id = id_arg(id)?;
    let mut tx = scoped(pool, caller).await?;
    let (name, bytes): (String, i64) =
        sqlx::query_as("SELECT r_name, r_bytes FROM app_e2ee_link_archive($1)")
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    let bytes = u64::try_from(bytes).map_err(|_| MessageError::NotFound)?;
    Ok(LinkArchive { name, bytes })
}

/// The largest archive a link may carry, for `GET /v1/capabilities`.
pub async fn link_archive_max(pool: &PgPool) -> Result<i64, DbError> {
    let max: i64 = sqlx::query_scalar("SELECT app_e2ee_link_archive_max()")
        .fetch_one(pool)
        .await?;
    Ok(max)
}

/// What the periodic sweep does for links: deletes expired messages and links, deletes the
/// archives of links an hour past expiry, then deletes any archive file no row names. Returns how
/// many archive files went.
pub(crate) async fn sweep_links(pool: &PgPool) -> Result<i64, DbError> {
    let expired: Vec<Option<String>> = sqlx::query_scalar("SELECT app_e2ee_link_sweep()")
        .fetch_all(pool)
        .await?;
    let mut removed = 0i64;
    for name in expired.iter().flatten() {
        remove_link_archive(name);
        removed += 1;
    }
    // The directory is listed before the names are read. A file is made only after its row
    // names it, so a file seen here whose name is not in the list has no row.
    let Ok(entries) = std::fs::read_dir(link_dir()) else {
        return Ok(removed);
    };
    let files: Vec<(PathBuf, String)> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_str()?.to_string();
            Some((entry.path(), name))
        })
        .collect();
    let live: Vec<String> = sqlx::query_scalar("SELECT app_e2ee_link_archive_names()")
        .fetch_all(pool)
        .await?;
    for (path, file) in files {
        let base = file.strip_suffix(".part").unwrap_or(&file);
        if !live.iter().any(|name| name == base) && std::fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}
