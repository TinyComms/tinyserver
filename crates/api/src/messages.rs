//! Text channels, direct messages, and the files attached to them.
//!
//! Upload bytes stay on this request. Live frames carry ids, never the file.

use std::sync::Arc;

use axum::body::to_bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use db::{
    clear_reaction, create_channel, delete_channel, delete_message, edit_message, list_channels,
    list_directs, list_messages, mark_read, open_attachment, open_direct, post_message,
    save_attachment, set_channel_override, toggle_reaction, update_channel, Caller, MessageError,
    NewAttachment, PgPool, ScanEngine,
};
use serde::Deserialize;
use serde_json::Value;

use crate::community::{caller, ApiError};
use crate::media_sign;

/// A file plus its multipart headers. A little over the largest cap an admin may set.
const UPLOAD_BODY: usize = db::UPLOAD_MAX as usize + 1024 * 1024;

pub fn routes() -> Router<PgPool> {
    let media = Router::new()
        .route("/v1/media", axum::routing::post(upload))
        .layer(DefaultBodyLimit::max(UPLOAD_BODY));
    Router::new()
        .route("/v1/channels", get(channels).post(add_channel))
        .route(
            "/v1/channels/{id}",
            axum::routing::patch(rename_channel).delete(remove_channel),
        )
        .route(
            "/v1/channels/{id}/overrides/{role_id}",
            axum::routing::put(put_override).delete(remove_override),
        )
        .route("/v1/directs", get(directs).post(add_direct))
        .route(
            "/v1/conversations/{id}/messages",
            get(messages).post(add_message),
        )
        .route(
            "/v1/messages/{id}",
            axum::routing::patch(edit).delete(remove_message),
        )
        .route(
            "/v1/messages/{id}/reactions",
            axum::routing::put(react).delete(unreact),
        )
        .route("/v1/conversations/{id}/read", axum::routing::post(read))
        .route("/v1/media/{id}", get(download))
        .merge(media)
}

#[derive(Deserialize)]
struct ChannelBody {
    name: String,
    category_id: Option<String>,
    topic: Option<String>,
    position: Option<i32>,
}

#[derive(Deserialize)]
struct DirectBody {
    user_id: String,
}

#[derive(Deserialize)]
struct PageQuery {
    before: Option<String>,
    limit: Option<i32>,
}

#[derive(Deserialize)]
struct PostBody {
    body: Option<String>,
    reply_to: Option<String>,
    client_id: Option<String>,
    attachment_ids: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct EditBody {
    body: String,
}

#[derive(Deserialize)]
struct EmojiBody {
    emoji: String,
}

#[derive(Deserialize)]
struct ReadBody {
    message_id: String,
}

#[derive(Deserialize)]
struct OverrideBody {
    allow: Option<i64>,
    deny: Option<i64>,
}

#[derive(Deserialize, Default)]
struct MediaQuery {
    ex: Option<String>,
    #[serde(rename = "is")]
    issued: Option<String>,
    hm: Option<String>,
}

#[derive(serde::Serialize)]
struct ErrorBody {
    error: &'static str,
}

enum Error {
    Unauthorized,
    Forbidden,
    Banned,
    Hierarchy,
    NotFound,
    Invalid,
    TooLarge,
    UnsupportedMedia,
    Scanning,
    Blocked,
    Unavailable,
    ServiceUnavailable,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, error) = match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::Banned => (StatusCode::FORBIDDEN, "banned"),
            Self::Hierarchy => (StatusCode::FORBIDDEN, "hierarchy"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Invalid => (StatusCode::BAD_REQUEST, "invalid"),
            Self::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "too_large"),
            Self::UnsupportedMedia => (StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media"),
            Self::Scanning => (StatusCode::LOCKED, "scanning"),
            Self::Blocked => (StatusCode::FORBIDDEN, "blocked"),
            Self::Unavailable => (StatusCode::INTERNAL_SERVER_ERROR, "unavailable"),
            Self::ServiceUnavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        };
        (status, Json(ErrorBody { error })).into_response()
    }
}

fn lift(error: MessageError) -> Error {
    match error {
        MessageError::Forbidden => Error::Forbidden,
        MessageError::Banned => Error::Banned,
        MessageError::Hierarchy => Error::Hierarchy,
        MessageError::NotFound => Error::NotFound,
        MessageError::Invalid => Error::Invalid,
        MessageError::TooLarge => Error::TooLarge,
        MessageError::UnsupportedMedia => Error::UnsupportedMedia,
        MessageError::Scanning => Error::Scanning,
        MessageError::Blocked => Error::Blocked,
        MessageError::Unavailable => Error::ServiceUnavailable,
        MessageError::Store(error) => {
            tracing::warn!(%error, "attachment store failed");
            Error::Unavailable
        }
        MessageError::Database(error) => {
            tracing::warn!(%error, "message query failed");
            Error::Unavailable
        }
    }
}

fn from_api(error: ApiError) -> Error {
    match error {
        ApiError::Unauthorized => Error::Unauthorized,
        ApiError::Forbidden => Error::Forbidden,
        ApiError::Hierarchy => Error::Hierarchy,
        ApiError::Banned => Error::Banned,
        ApiError::NotFound => Error::NotFound,
        ApiError::Invalid | ApiError::DefaultRole => Error::Invalid,
        ApiError::TooLarge => Error::TooLarge,
        ApiError::UnsupportedMedia => Error::UnsupportedMedia,
        ApiError::Unavailable => Error::Unavailable,
        ApiError::LastOwner | ApiError::AlreadyMember | ApiError::IdempotencyConflict => {
            Error::Unavailable
        }
    }
}

async fn member(pool: &PgPool, headers: &HeaderMap) -> Result<Caller, Error> {
    caller(pool, headers).await.map_err(from_api)
}

fn signed(mut value: Value) -> Json<Value> {
    media_sign::overlay(&mut value);
    Json(value)
}

async fn channels(State(pool): State<PgPool>, headers: HeaderMap) -> Result<Json<Value>, Error> {
    let caller = member(&pool, &headers).await?;
    list_channels(&pool, &caller)
        .await
        .map(signed)
        .map_err(lift)
}

async fn add_channel(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(body): Json<ChannelBody>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let caller = member(&pool, &headers).await?;
    let channel = create_channel(
        &pool,
        &caller,
        &body.name,
        body.category_id.as_deref(),
        body.topic.as_deref(),
        body.position,
    )
    .await
    .map_err(lift)?;
    Ok((StatusCode::CREATED, signed(channel)))
}

async fn rename_channel(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(patch): Json<Value>,
) -> Result<Json<Value>, Error> {
    let caller = member(&pool, &headers).await?;
    update_channel(&pool, &caller, &id, &patch)
        .await
        .map(signed)
        .map_err(lift)
}

async fn remove_channel(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, Error> {
    let caller = member(&pool, &headers).await?;
    delete_channel(&pool, &caller, &id).await.map_err(lift)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn put_override(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path((channel_id, role_id)): Path<(String, String)>,
    Json(body): Json<OverrideBody>,
) -> Result<Json<Value>, Error> {
    let caller = member(&pool, &headers).await?;
    set_channel_override(&pool, &caller, &channel_id, &role_id, body.allow, body.deny)
        .await
        .map(Json)
        .map_err(lift)
}

async fn remove_override(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path((channel_id, role_id)): Path<(String, String)>,
) -> Result<Json<Value>, Error> {
    let caller = member(&pool, &headers).await?;
    set_channel_override(&pool, &caller, &channel_id, &role_id, None, None)
        .await
        .map(Json)
        .map_err(lift)
}

async fn directs(State(pool): State<PgPool>, headers: HeaderMap) -> Result<Json<Value>, Error> {
    let caller = member(&pool, &headers).await?;
    list_directs(&pool, &caller).await.map(signed).map_err(lift)
}

async fn add_direct(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(body): Json<DirectBody>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let caller = member(&pool, &headers).await?;
    let (direct, created) = open_direct(&pool, &caller, &body.user_id)
        .await
        .map_err(lift)?;
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, signed(direct)))
}

async fn messages(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(page): Query<PageQuery>,
) -> Result<Json<Value>, Error> {
    let caller = member(&pool, &headers).await?;
    list_messages(
        &pool,
        &caller,
        &id,
        page.before.as_deref(),
        page.limit.unwrap_or(50),
    )
    .await
    .map(signed)
    .map_err(lift)
}

async fn add_message(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<PostBody>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let caller = member(&pool, &headers).await?;
    let attachments = body.attachment_ids.unwrap_or_default();
    let message = post_message(
        &pool,
        &caller,
        &id,
        body.body.as_deref().unwrap_or(""),
        body.reply_to.as_deref(),
        body.client_id.as_deref(),
        &attachments,
    )
    .await
    .map_err(lift)?;
    Ok((StatusCode::CREATED, signed(message)))
}

async fn edit(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<EditBody>,
) -> Result<Json<Value>, Error> {
    let caller = member(&pool, &headers).await?;
    edit_message(&pool, &caller, &id, &body.body)
        .await
        .map(signed)
        .map_err(lift)
}

async fn remove_message(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, Error> {
    let caller = member(&pool, &headers).await?;
    delete_message(&pool, &caller, &id).await.map_err(lift)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn react(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<EmojiBody>,
) -> Result<Json<Value>, Error> {
    let caller = member(&pool, &headers).await?;
    toggle_reaction(&pool, &caller, &id, &body.emoji)
        .await
        .map(Json)
        .map_err(lift)
}

async fn unreact(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<EmojiBody>,
) -> Result<StatusCode, Error> {
    let caller = member(&pool, &headers).await?;
    clear_reaction(&pool, &caller, &id, &body.emoji)
        .await
        .map_err(lift)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn read(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ReadBody>,
) -> Result<StatusCode, Error> {
    let caller = member(&pool, &headers).await?;
    mark_read(&pool, &caller, &id, &body.message_id)
        .await
        .map_err(lift)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn upload(
    State(pool): State<PgPool>,
    Extension(engine): Extension<Arc<dyn ScanEngine>>,
    headers: HeaderMap,
    request: Request,
) -> Result<(StatusCode, Json<Value>), Error> {
    let caller = member(&pool, &headers).await?;
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .ok_or(Error::Invalid)?;
    let body = to_bytes(request.into_body(), UPLOAD_BODY)
        .await
        .map_err(|_| Error::TooLarge)?;
    let upload = parse_upload(content_type, &body).map_err(lift)?;
    let saved = save_attachment(&pool, &caller, &upload, engine.as_ref())
        .await
        .map_err(lift)?;
    Ok((StatusCode::CREATED, signed(saved)))
}

async fn download(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<MediaQuery>,
) -> Result<Response, Error> {
    let caller = member(&pool, &headers).await?;
    if query.ex.is_some() || query.issued.is_some() || query.hm.is_some() {
        let (Some(ex), Some(issued), Some(hm)) = (
            query.ex.as_deref(),
            query.issued.as_deref(),
            query.hm.as_deref(),
        ) else {
            return Err(Error::Unauthorized);
        };
        let Some(secret) = media_sign::load_secret() else {
            return Err(Error::Unauthorized);
        };
        let Ok(ex) = ex.parse::<i64>() else {
            return Err(Error::Unauthorized);
        };
        let Ok(issued) = issued.parse::<i64>() else {
            return Err(Error::Unauthorized);
        };
        if !media_sign::verify(&secret, &id, ex, issued, hm, media_sign::unix_now()) {
            return Err(Error::Unauthorized);
        }
    }
    let file = open_attachment(&pool, &caller, &id).await.map_err(lift)?;
    Ok(file_response(file.name, file.mime, file.bytes))
}

fn file_response(name: String, mime: String, bytes: Vec<u8>) -> Response {
    let inline = matches!(
        mime.as_str(),
        "image/png" | "image/jpeg" | "image/webp" | "image/gif"
    );
    let mime = HeaderValue::from_str(&mime)
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
    let fallback = if inline { "inline" } else { "attachment" };
    let disposition = HeaderValue::from_str(&content_disposition(&name, inline))
        .unwrap_or_else(|_| HeaderValue::from_static(fallback));
    let mut response = (StatusCode::OK, bytes).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, mime);
    headers.insert(header::CONTENT_DISPOSITION, disposition);
    response
}

fn content_disposition(name: &str, inline: bool) -> String {
    let ascii: String = name
        .chars()
        .map(|c| {
            if c.is_ascii() && c != '"' && c != '\\' && !c.is_control() {
                c
            } else {
                '_'
            }
        })
        .collect();
    let mut encoded = String::new();
    for byte in name.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') {
            encoded.push(char::from(*byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    let kind = if inline { "inline" } else { "attachment" };
    format!("{kind}; filename=\"{ascii}\"; filename*=UTF-8''{encoded}")
}

fn parse_upload(content_type: &str, body: &[u8]) -> Result<NewAttachment, MessageError> {
    let boundary = boundary(content_type).ok_or(MessageError::Invalid)?;
    let parts = split_parts(body, &boundary).ok_or(MessageError::Invalid)?;
    if parts.is_empty() || parts.len() > 8 {
        return Err(MessageError::Invalid);
    }
    let mut file: Option<NewAttachment> = None;
    let mut width = None;
    let mut height = None;
    let mut duration = None;
    for part in parts {
        let parsed = parse_part(part).ok_or(MessageError::Invalid)?;
        match parsed.name.as_str() {
            "file" => {
                let Some(name) = parsed.filename else {
                    return Err(MessageError::Invalid);
                };
                if file.is_some() || name.is_empty() {
                    return Err(MessageError::Invalid);
                }
                file = Some(NewAttachment {
                    name,
                    mime: parsed
                        .mime
                        .unwrap_or_else(|| "application/octet-stream".to_string()),
                    bytes: parsed.body,
                    width: None,
                    height: None,
                    duration: None,
                });
            }
            "width" => width = Some(field_i32(&parsed.body)?),
            "height" => height = Some(field_i32(&parsed.body)?),
            "duration" => duration = Some(field_i32(&parsed.body)?),
            _ => {}
        }
    }
    let mut file = file.ok_or(MessageError::Invalid)?;
    file.width = width;
    file.height = height;
    file.duration = duration;
    Ok(file)
}

fn field_i32(body: &[u8]) -> Result<i32, MessageError> {
    let text = std::str::from_utf8(body).map_err(|_| MessageError::Invalid)?;
    let text = text.trim();
    if text.is_empty() {
        return Err(MessageError::Invalid);
    }
    text.parse::<i32>().map_err(|_| MessageError::Invalid)
}

struct Part {
    name: String,
    filename: Option<String>,
    mime: Option<String>,
    body: Vec<u8>,
}

fn boundary(content_type: &str) -> Option<String> {
    let (kind, params) = content_type.split_once(';').unwrap_or((content_type, ""));
    if !kind.trim().eq_ignore_ascii_case("multipart/form-data") {
        return None;
    }
    let raw = param(params, "boundary")?;
    if raw.is_empty() || raw.len() > 70 || raw.bytes().any(|byte| byte < 0x20) {
        return None;
    }
    Some(raw)
}

fn split_parts<'a>(body: &'a [u8], boundary: &str) -> Option<Vec<&'a [u8]>> {
    let open = format!("--{boundary}");
    let next = format!("\r\n--{boundary}");
    let open = open.as_bytes();
    let next = next.as_bytes();
    let start = find_slice(body, open)?;
    if body[..start].iter().any(|byte| !byte.is_ascii_whitespace()) {
        return None;
    }
    let mut cursor = start + open.len();
    if body.get(cursor..cursor + 2) == Some(b"--") {
        return None;
    }
    cursor = skip_line(body, cursor)?;
    let mut parts = Vec::new();
    loop {
        let relative = find_slice(&body[cursor..], next)?;
        parts.push(&body[cursor..cursor + relative]);
        cursor += relative + next.len();
        if body.get(cursor..cursor + 2) == Some(b"--") {
            return Some(parts);
        }
        cursor = skip_line(body, cursor)?;
    }
}

fn skip_line(body: &[u8], cursor: usize) -> Option<usize> {
    if body.get(cursor..cursor + 2) == Some(b"\r\n") {
        Some(cursor + 2)
    } else if body.get(cursor) == Some(&b'\n') {
        Some(cursor + 1)
    } else {
        None
    }
}

fn parse_part(part: &[u8]) -> Option<Part> {
    let split = find_slice(part, b"\r\n\r\n")?;
    if split > 8 * 1024 {
        return None;
    }
    let headers = std::str::from_utf8(&part[..split]).ok()?;
    let body = part[split + 4..].to_vec();
    let disposition = header_value(headers, "content-disposition")?;
    let name = param(disposition, "name")?;
    if name.is_empty() {
        return None;
    }
    Some(Part {
        name,
        filename: param(disposition, "filename"),
        mime: header_value(headers, "content-type").map(str::to_string),
        body,
    })
}

fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case(name) {
            Some(value.trim())
        } else {
            None
        }
    })
}

fn param(header: &str, name: &str) -> Option<String> {
    for piece in split_semi(header) {
        let piece = piece.trim();
        let Some((key, value)) = piece.split_once('=') else {
            continue;
        };
        if !key.trim().eq_ignore_ascii_case(name) {
            continue;
        }
        let value = value.trim();
        if let Some(stripped) = value.strip_prefix('"') {
            let end = stripped.find('"').unwrap_or(stripped.len());
            return Some(stripped[..end].to_string());
        }
        return Some(value.to_string());
    }
    None
}

fn split_semi(header: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for c in header.chars() {
        if c == '"' {
            quoted = !quoted;
            current.push(c);
            continue;
        }
        if c == ';' && !quoted {
            parts.push(std::mem::take(&mut current));
            continue;
        }
        current.push(c);
    }
    parts.push(current);
    parts
}

fn find_slice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::parse_upload;

    #[test]
    fn a_multipart_body_keeps_the_file_and_its_size() {
        let body = b"\
--abc\r\n\
Content-Disposition: form-data; name=\"file\"; filename=\"wave.gif\"\r\n\
Content-Type: image/gif\r\n\
\r\n\
GIF89a\r\n\
--abc\r\n\
Content-Disposition: form-data; name=\"width\"\r\n\
\r\n\
12\r\n\
--abc--\r\n";
        let upload = parse_upload("multipart/form-data; boundary=abc", body).expect("parse");
        assert_eq!(upload.name, "wave.gif");
        assert_eq!(upload.mime, "image/gif");
        assert_eq!(upload.bytes, b"GIF89a");
        assert_eq!(upload.width, Some(12));
        assert_eq!(upload.height, None);
    }
}
