//! Device linking: a person's new device and a device they already have exchange a few sealed
//! messages through the server, and the old one hands over an archive of history. The protocol
//! is `docs/e2ee-text.md` section 5.
//!
//! The server relays bytes it cannot read. Only sessions of the person who made a link can touch
//! it; anyone else gets the same `404` as a link that does not exist. Nothing here logs a link
//! id, a message, the archive, or the length of any of them: a failure logs the person, the
//! route, and a fixed reason.
//!
//! The archive is a file under `{upload_dir}/links/`, named by random bytes that are not the link
//! id. It never passes the scanner, and the media routes cannot name it: they read only
//! `{upload_dir}/{uuid}`.

use std::collections::HashMap;
use std::io::SeekFrom;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Extension, Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use db::{Caller, PgPool, LINK_ID_LEN, LINK_MESSAGE_MAX};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Notify;

use crate::e2ee_text::mls::{self, Refused};
use crate::e2ee_text::Limiter;
use crate::messages::{lift, member, Error};

/// Links one person may make at once, and one more back every 30 seconds. The database also holds
/// them to 5 open at a time.
const LINK_BURST: f64 = 10.0;
const LINK_REFILL_PER_SEC: f64 = 1.0 / 30.0;
/// Messages one person may post at once, and one more back each second. A link takes 16 at most.
const POST_BURST: f64 = 32.0;
const POST_REFILL_PER_SEC: f64 = 1.0;
/// The longest a read waits for a message.
const WAIT_MAX_SECS: u64 = 25;
/// Reads one person may have waiting at once. Past it, a read answers at once.
const WAITERS_PER_PERSON: usize = 4;
/// A waiting read looks again this often, even with no wake-up, so it sees an expiry.
const RECHECK: Duration = Duration::from_secs(2);
/// A message body: 8 KiB as base64, and the fields around it.
const MESSAGE_BODY: usize = 16 * 1024;
/// What one read of the archive file, and one piece of the response, holds.
const CHUNK: usize = 64 * 1024;

/// What the link routes share: their limits, and a wake-up per link for reads that wait.
pub(crate) struct Links {
    create: Limiter,
    post: Limiter,
    wakers: Mutex<HashMap<[u8; LINK_ID_LEN], Arc<Notify>>>,
    waiting: Mutex<HashMap<String, usize>>,
}

impl Default for Links {
    fn default() -> Self {
        Self {
            create: Limiter::new(LINK_BURST, LINK_REFILL_PER_SEC),
            post: Limiter::new(POST_BURST, POST_REFILL_PER_SEC),
            wakers: Mutex::new(HashMap::new()),
            waiting: Mutex::new(HashMap::new()),
        }
    }
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

impl Links {
    fn waker(&self, id: &[u8; LINK_ID_LEN]) -> Arc<Notify> {
        locked(&self.wakers).entry(*id).or_default().clone()
    }

    /// Drops the wake-up of a link once no read holds it.
    fn release(&self, id: &[u8; LINK_ID_LEN], waker: Arc<Notify>) {
        let mut wakers = locked(&self.wakers);
        drop(waker);
        if wakers
            .get(id)
            .is_some_and(|held| Arc::strong_count(held) == 1)
        {
            wakers.remove(id);
        }
    }

    fn wake(&self, id: &[u8; LINK_ID_LEN]) {
        if let Some(waker) = locked(&self.wakers).get(id) {
            waker.notify_waiters();
        }
    }

    /// A place among the person's waiting reads, or `None` when they have all of theirs.
    fn wait_slot<'a>(&'a self, user_id: &str) -> Option<WaitSlot<'a>> {
        let mut waiting = locked(&self.waiting);
        let count = waiting.entry(user_id.to_string()).or_default();
        if *count >= WAITERS_PER_PERSON {
            return None;
        }
        *count += 1;
        Some(WaitSlot {
            links: self,
            user_id: user_id.to_string(),
        })
    }
}

struct WaitSlot<'a> {
    links: &'a Links,
    user_id: String,
}

impl Drop for WaitSlot<'_> {
    fn drop(&mut self) {
        let mut waiting = locked(&self.links.waiting);
        if let Some(count) = waiting.get_mut(&self.user_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                waiting.remove(&self.user_id);
            }
        }
    }
}

pub fn routes() -> Router<PgPool> {
    Router::new()
        .route("/v1/e2ee/links", post(create))
        .route("/v1/e2ee/links/{id}", delete(remove))
        .route(
            "/v1/e2ee/links/{id}/messages",
            get(messages)
                .post(post_message)
                .layer(DefaultBodyLimit::max(MESSAGE_BODY)),
        )
        // The body is read as a stream, so the 8 KiB default never applies; the cap is the
        // server's `e2ee_link_archive_max`, checked against Content-Length and while reading.
        .route("/v1/e2ee/links/{id}/archive", get(archive).put(put_archive))
}

/// A link id as the client writes it: 16 bytes, base64url without padding. Anything else is a
/// link that does not exist.
fn link_id(text: &str) -> Option<[u8; LINK_ID_LEN]> {
    if text.len() != 22 {
        return None;
    }
    URL_SAFE_NO_PAD.decode(text).ok()?.try_into().ok()
}

fn failed(user_id: &str, route: &'static str, error: &Error) {
    let reason = crate::messages::message_reason(error);
    tracing::warn!(user_id, route, reason, "e2ee link failed");
}

fn allow(limiter: &Limiter, user_id: &str) -> Result<(), Error> {
    if limiter.take(user_id, Instant::now()) {
        Ok(())
    } else {
        Err(Error::SlowDown)
    }
}

/// 32 random bytes as lowercase hex: an archive's file name.
fn archive_name() -> Result<String, Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| Error::Unavailable)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

async fn create(
    State(pool): State<PgPool>,
    Extension(links): Extension<Arc<Links>>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Value>), Error> {
    let caller = member(&pool, &headers).await?;
    let result = async {
        allow(&links.create, &caller.user_id)?;
        let mut id = [0u8; LINK_ID_LEN];
        getrandom::fill(&mut id).map_err(|_| Error::Unavailable)?;
        let expires = db::create_link(&pool, &caller, &id).await.map_err(lift)?;
        Ok(json!({ "link_id": URL_SAFE_NO_PAD.encode(id), "expires_at": expires }))
    }
    .await;
    result
        .map(|value| (StatusCode::CREATED, Json(value)))
        .inspect_err(|error| failed(&caller.user_id, "links.create", error))
}

#[derive(Deserialize)]
struct MessageBody {
    from: String,
    data: String,
}

async fn post_message(
    State(pool): State<PgPool>,
    Extension(links): Extension<Arc<Links>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<MessageBody>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let caller = member(&pool, &headers).await?;
    let result = async {
        let id = link_id(&id).ok_or(Error::NotFound)?;
        allow(&links.post, &caller.user_id)?;
        if !matches!(body.from.as_str(), "new" | "old") {
            return Err(Error::Invalid);
        }
        let data = mls::decode(&body.data, LINK_MESSAGE_MAX).map_err(|refusal| match refusal {
            Refused::TooLarge => Error::TooLarge,
            Refused::Bad => Error::Invalid,
        })?;
        if data.is_empty() {
            return Err(Error::Invalid);
        }
        let seq = db::post_link_message(&pool, &caller, &id, &body.from, &data)
            .await
            .map_err(lift)?;
        links.wake(&id);
        Ok(seq)
    }
    .await;
    result
        .map(|seq| (StatusCode::CREATED, Json(json!({ "seq": seq }))))
        .inspect_err(|error| failed(&caller.user_id, "links.post", error))
}

#[derive(Deserialize)]
struct MessagesQuery {
    after: Option<i32>,
    wait: Option<u64>,
}

/// The messages after `after`. With `wait`, and none yet, holds the request open until one is
/// posted or `wait` seconds (at most 25) pass, then answers `[]`.
async fn messages(
    State(pool): State<PgPool>,
    Extension(links): Extension<Arc<Links>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<MessagesQuery>,
) -> Result<Json<Value>, Error> {
    let caller = member(&pool, &headers).await?;
    let Some(id) = link_id(&id) else {
        let error = Error::NotFound;
        failed(&caller.user_id, "links.messages", &error);
        return Err(error);
    };
    let after = query.after.unwrap_or(0);
    let wait = Duration::from_secs(query.wait.unwrap_or(0).min(WAIT_MAX_SECS));
    let slot = if wait.is_zero() {
        None
    } else {
        links.wait_slot(&caller.user_id)
    };
    let rows = match slot {
        Some(_slot) => {
            let waker = links.waker(&id);
            let rows = wait_for(&pool, &caller, &id, after, wait, &waker).await;
            links.release(&id, waker);
            rows
        }
        None => db::link_messages(&pool, &caller, &id, after)
            .await
            .map_err(lift),
    }
    .inspect_err(|error| failed(&caller.user_id, "links.messages", error))?;
    let rows: Vec<Value> = rows
        .iter()
        .map(|row| json!({ "seq": row.seq, "from": row.sender, "data": mls::encode(&row.data) }))
        .collect();
    Ok(Json(Value::Array(rows)))
}

async fn wait_for(
    pool: &PgPool,
    caller: &Caller,
    id: &[u8; LINK_ID_LEN],
    after: i32,
    wait: Duration,
    waker: &Notify,
) -> Result<Vec<db::LinkMessage>, Error> {
    let deadline = Instant::now() + wait;
    loop {
        // Armed before the read, so a post between the read and the wait still wakes it.
        let notified = waker.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let rows = db::link_messages(pool, caller, id, after)
            .await
            .map_err(lift)?;
        let left = deadline.saturating_duration_since(Instant::now());
        if !rows.is_empty() || left.is_zero() {
            return Ok(rows);
        }
        tokio::select! {
            () = &mut notified => {}
            () = tokio::time::sleep(left.min(RECHECK)) => {}
        }
    }
}

/// Deletes the link, its messages and its archive. `204` whether or not there was one to delete,
/// and for someone else's link, which is left alone.
async fn remove(
    State(pool): State<PgPool>,
    Extension(links): Extension<Arc<Links>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, Error> {
    let caller = member(&pool, &headers).await?;
    let Some(id) = link_id(&id) else {
        return Ok(StatusCode::NO_CONTENT);
    };
    db::delete_link(&pool, &caller, &id)
        .await
        .map_err(lift)
        .inspect_err(|error| failed(&caller.user_id, "links.delete", error))?;
    links.wake(&id);
    Ok(StatusCode::NO_CONTENT)
}

/// Stores the link's one archive, streamed to disk. The request must say its length, be
/// `application/octet-stream`, and deliver exactly that many bytes.
async fn put_archive(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Body,
) -> Result<Response, Error> {
    let caller = member(&pool, &headers).await?;
    store_archive(&pool, &caller, &id, &headers, body)
        .await
        .inspect_err(|error| failed(&caller.user_id, "links.archive.put", error))
}

async fn store_archive(
    pool: &PgPool,
    caller: &Caller,
    id: &str,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, Error> {
    let id = link_id(id).ok_or(Error::NotFound)?;
    let octets = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| {
            value
                .trim()
                .eq_ignore_ascii_case("application/octet-stream")
        });
    if !octets {
        return Err(Error::UnsupportedMedia);
    }
    let Some(length) = headers.get(header::CONTENT_LENGTH) else {
        return Ok((
            StatusCode::LENGTH_REQUIRED,
            Json(json!({ "error": "length_required" })),
        )
            .into_response());
    };
    let length: u64 = length
        .to_str()
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .ok_or(Error::Invalid)?;
    if length == 0 {
        return Err(Error::Invalid);
    }
    let name = archive_name()?;
    db::begin_link_archive(pool, caller, &id, &name, length)
        .await
        .map_err(lift)?;
    match write_archive(&name, length, body).await {
        Ok(()) => {}
        Err(error) => {
            let _ = db::abort_link_archive(pool, caller, &id, &name).await;
            return Err(error);
        }
    }
    db::finish_link_archive(pool, caller, &id, &name)
        .await
        .map_err(lift)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Writes the body to `{name}.part`, then renames it to `{name}` once every declared byte is on
/// disk. A body longer or shorter than declared is refused, and the caller deletes what was
/// written.
async fn write_archive(name: &str, length: u64, body: Body) -> Result<(), Error> {
    let (Some(part), Some(path)) = (db::link_archive_part(name), db::link_archive_path(name))
    else {
        return Err(Error::Unavailable);
    };
    if let Some(dir) = part.parent() {
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|_| Error::Unavailable)?;
    }
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&part).await.map_err(|_| Error::Unavailable)?;
    let mut written: u64 = 0;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        // The client went away, or sent more than it said.
        let chunk = chunk.map_err(|_| Error::Invalid)?;
        written = written.saturating_add(chunk.len() as u64);
        if written > length {
            return Err(Error::TooLarge);
        }
        file.write_all(&chunk)
            .await
            .map_err(|_| Error::Unavailable)?;
    }
    if written != length {
        return Err(Error::Invalid);
    }
    file.flush().await.map_err(|_| Error::Unavailable)?;
    file.sync_all().await.map_err(|_| Error::Unavailable)?;
    drop(file);
    // A link deleted mid-upload has taken the partial file with it.
    tokio::fs::rename(&part, &path)
        .await
        .map_err(|_| Error::NotFound)
}

/// The link's archive, whole or one byte range of it.
async fn archive(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, Error> {
    let caller = member(&pool, &headers).await?;
    serve_archive(&pool, &caller, &id, &headers)
        .await
        .inspect_err(|error| failed(&caller.user_id, "links.archive.get", error))
}

async fn serve_archive(
    pool: &PgPool,
    caller: &Caller,
    id: &str,
    headers: &HeaderMap,
) -> Result<Response, Error> {
    let id = link_id(id).ok_or(Error::NotFound)?;
    let stored = db::link_archive(pool, caller, &id).await.map_err(lift)?;
    let path: PathBuf = db::link_archive_path(&stored.name).ok_or(Error::NotFound)?;
    let mut file = tokio::fs::File::open(&path)
        .await
        .map_err(|_| Error::NotFound)?;
    let total = file.metadata().await.map_err(|_| Error::NotFound)?.len();
    if total != stored.bytes {
        return Err(Error::NotFound);
    }
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
        .map_or(Range::Whole, |value| parse_range(value, total));
    let (status, start, len) = match range {
        Range::Whole => (StatusCode::OK, 0, total),
        Range::Part(start, end) => (StatusCode::PARTIAL_CONTENT, start, end - start + 1),
        Range::Unsatisfiable => {
            let mut response = StatusCode::RANGE_NOT_SATISFIABLE.into_response();
            if let Ok(value) = HeaderValue::from_str(&format!("bytes */{total}")) {
                response.headers_mut().insert(header::CONTENT_RANGE, value);
            }
            return Ok(response);
        }
    };
    if start > 0 {
        file.seek(SeekFrom::Start(start))
            .await
            .map_err(|_| Error::Unavailable)?;
    }
    let stream = futures_util::stream::unfold((file, len), |(mut file, left)| async move {
        if left == 0 {
            return None;
        }
        let want = usize::try_from(left).map_or(CHUNK, |left| left.min(CHUNK));
        let mut buffer = vec![0u8; want];
        match file.read(&mut buffer).await {
            Ok(0) => Some((
                Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
                (file, 0),
            )),
            Ok(read) => {
                buffer.truncate(read);
                Some((Ok(Bytes::from(buffer)), (file, left - read as u64)))
            }
            Err(error) => Some((Err(error), (file, 0))),
        }
    });
    let mut response = (status, Body::from_stream(stream)).into_response();
    let out = response.headers_mut();
    out.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    out.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if let Ok(value) = HeaderValue::from_str(&len.to_string()) {
        out.insert(header::CONTENT_LENGTH, value);
    }
    if status == StatusCode::PARTIAL_CONTENT {
        let end = start + len - 1;
        if let Ok(value) = HeaderValue::from_str(&format!("bytes {start}-{end}/{total}")) {
            out.insert(header::CONTENT_RANGE, value);
        }
    }
    Ok(response)
}

#[derive(Debug, PartialEq, Eq)]
enum Range {
    Whole,
    /// First and last byte, inclusive.
    Part(u64, u64),
    Unsatisfiable,
}

/// One `bytes=` range of a file `total` bytes long: `a-b`, `a-`, or `-n` (the last `n`). A range
/// this does not read, or more than one, is the whole file, as RFC 9110 allows.
fn parse_range(value: &str, total: u64) -> Range {
    let Some(spec) = value.trim().strip_prefix("bytes=") else {
        return Range::Whole;
    };
    if spec.contains(',') {
        return Range::Whole;
    }
    let Some((first, last)) = spec.trim().split_once('-') else {
        return Range::Whole;
    };
    let (first, last) = (first.trim(), last.trim());
    if first.is_empty() {
        let Ok(suffix) = last.parse::<u64>() else {
            return Range::Whole;
        };
        if suffix == 0 || total == 0 {
            return Range::Unsatisfiable;
        }
        return Range::Part(total.saturating_sub(suffix), total - 1);
    }
    let Ok(start) = first.parse::<u64>() else {
        return Range::Whole;
    };
    let end = if last.is_empty() {
        total.saturating_sub(1)
    } else {
        let Ok(end) = last.parse::<u64>() else {
            return Range::Whole;
        };
        if end < start {
            return Range::Whole;
        }
        end.min(total.saturating_sub(1))
    };
    if start >= total {
        return Range::Unsatisfiable;
    }
    Range::Part(start, end)
}

#[cfg(test)]
mod tests {
    use super::{link_id, parse_range, Range};

    #[test]
    fn link_ids_are_sixteen_bytes_of_base64url() {
        assert_eq!(link_id("AAAAAAAAAAAAAAAAAAAAAA"), Some([0u8; 16]));
        assert_eq!(link_id("_____________________w"), Some([0xff; 16]));
        // Padding, the standard alphabet, the wrong length, and a uuid are no link.
        assert_eq!(link_id("AAAAAAAAAAAAAAAAAAAAAA=="), None);
        assert_eq!(link_id("+++++++++++++++++++++w"), None);
        assert_eq!(link_id("AAAAAAAAAAAAAAAAAAAAA"), None);
        assert_eq!(link_id("00000000-0000-4000-8000-000000000001"), None);
        assert_eq!(link_id(""), None);
    }

    #[test]
    fn ranges() {
        assert_eq!(parse_range("bytes=0-9", 100), Range::Part(0, 9));
        assert_eq!(parse_range("bytes=90-", 100), Range::Part(90, 99));
        assert_eq!(parse_range("bytes=-10", 100), Range::Part(90, 99));
        assert_eq!(parse_range("bytes=-1000", 100), Range::Part(0, 99));
        assert_eq!(parse_range("bytes=50-1000", 100), Range::Part(50, 99));
        assert_eq!(parse_range("bytes=100-", 100), Range::Unsatisfiable);
        assert_eq!(parse_range("bytes=-0", 100), Range::Unsatisfiable);
        // What this does not read is the whole file.
        assert_eq!(parse_range("bytes=0-1,5-6", 100), Range::Whole);
        assert_eq!(parse_range("bytes=9-0", 100), Range::Whole);
        assert_eq!(parse_range("items=0-9", 100), Range::Whole);
        assert_eq!(parse_range("bytes=x-9", 100), Range::Whole);
    }
}
