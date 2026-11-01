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
    save_attachment, save_sealed_attachment, set_channel_override, toggle_reaction, update_channel,
    Caller, MessageError, NewAttachment, PgPool, ScanEngine,
};
use serde::Deserialize;
use serde_json::Value;

use crate::community::{caller, ApiError};
use crate::media_sign;

/// A file plus its multipart headers. A little over the largest cap an admin may set.
const UPLOAD_BODY: usize = db::UPLOAD_MAX as usize + 1024 * 1024;

/// A message post: the largest ciphertext as base64, and the fields around it.
const MESSAGE_BODY: usize = 48 * 1024;

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
            // A ciphertext post is up to 20 KiB, 27 KiB as base64.
            get(messages)
                .post(add_message)
                .layer(DefaultBodyLimit::max(MESSAGE_BODY)),
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
    /// End-to-end encrypted, fixed for the life of the channel. Absent is plaintext.
    e2ee: Option<bool>,
}

#[derive(Deserialize)]
struct DirectBody {
    user_id: String,
    /// The encrypted direct with this person rather than the plaintext one.
    e2ee: Option<bool>,
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
    // An encrypted conversation takes these and no body. See docs/e2ee-text.md.
    ciphertext: Option<String>,
    epoch: Option<u64>,
    device_id: Option<String>,
    kind: Option<String>,
    target_id: Option<String>,
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

pub(crate) enum Error {
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
    E2eeRequired,
    NotE2ee,
    StaleEpoch,
    ProposalsChanged,
    NoGroup,
    GroupExists,
    NotInGroup,
    DeviceExists,
    CrossSignatureRequired,
    TooManyKeys,
    SlowDown,
    E2eeOff,
    BadDevice,
    TooManyDevices,
    BadE2ee,
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
            Self::E2eeRequired => (StatusCode::BAD_REQUEST, "e2ee_required"),
            Self::NotE2ee => (StatusCode::BAD_REQUEST, "not_e2ee"),
            Self::StaleEpoch => (StatusCode::CONFLICT, "stale_epoch"),
            Self::ProposalsChanged => (StatusCode::CONFLICT, "proposals_changed"),
            Self::NoGroup => (StatusCode::CONFLICT, "no_group"),
            Self::GroupExists => (StatusCode::CONFLICT, "group_exists"),
            Self::NotInGroup => (StatusCode::FORBIDDEN, "not_in_group"),
            Self::DeviceExists => (StatusCode::CONFLICT, "device_exists"),
            Self::CrossSignatureRequired => (StatusCode::BAD_REQUEST, "cross_signature_required"),
            Self::TooManyKeys => (StatusCode::BAD_REQUEST, "too_many_keys"),
            Self::SlowDown => (StatusCode::TOO_MANY_REQUESTS, "slow_down"),
            Self::E2eeOff => (StatusCode::BAD_REQUEST, "e2ee_off"),
            Self::BadDevice => (StatusCode::BAD_REQUEST, "bad_device"),
            Self::TooManyDevices => (StatusCode::BAD_REQUEST, "too_many_devices"),
            Self::BadE2ee => (StatusCode::BAD_REQUEST, "bad_e2ee"),
        };
        (status, Json(ErrorBody { error })).into_response()
    }
}

pub(crate) fn message_reason(error: &Error) -> &'static str {
    match error {
        Error::Unauthorized => "unauthorized",
        Error::Forbidden => "forbidden",
        Error::Banned => "banned",
        Error::Hierarchy => "hierarchy",
        Error::NotFound => "not_found",
        Error::Invalid => "invalid",
        Error::TooLarge => "too_large",
        Error::UnsupportedMedia => "unsupported_media",
        Error::Scanning => "scanning",
        Error::Blocked => "blocked",
        Error::Unavailable | Error::ServiceUnavailable => "unavailable",
        Error::E2eeRequired => "e2ee_required",
        Error::NotE2ee => "not_e2ee",
        Error::StaleEpoch => "stale_epoch",
        Error::ProposalsChanged => "proposals_changed",
        Error::NoGroup => "no_group",
        Error::GroupExists => "group_exists",
        Error::NotInGroup => "not_in_group",
        Error::DeviceExists => "device_exists",
        Error::CrossSignatureRequired => "cross_signature_required",
        Error::TooManyKeys => "too_many_keys",
        Error::SlowDown => "slow_down",
        Error::E2eeOff => "e2ee_off",
        Error::BadDevice => "bad_device",
        Error::TooManyDevices => "too_many_devices",
        Error::BadE2ee => "bad_e2ee",
    }
}

fn message_failed(user_id: &str, room_id: &str, error: &Error) {
    let reason = message_reason(error);
    tracing::warn!(user_id, room_id, reason, "message failed");
}

fn upload_failed(user_id: &str, error: &Error, bytes: usize) {
    let reason = message_reason(error);
    tracing::warn!(user_id, reason, bytes, "upload failed");
}

pub(crate) fn lift(error: MessageError) -> Error {
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
        MessageError::E2eeRequired => Error::E2eeRequired,
        MessageError::NotE2ee => Error::NotE2ee,
        MessageError::StaleEpoch => Error::StaleEpoch,
        MessageError::ProposalsChanged => Error::ProposalsChanged,
        MessageError::NoGroup => Error::NoGroup,
        MessageError::GroupExists => Error::GroupExists,
        MessageError::NotInGroup => Error::NotInGroup,
        MessageError::DeviceExists => Error::DeviceExists,
        MessageError::CrossSignatureRequired => Error::CrossSignatureRequired,
        MessageError::TooManyKeys => Error::TooManyKeys,
        MessageError::SlowDown => Error::SlowDown,
        MessageError::E2eeOff => Error::E2eeOff,
        MessageError::BadDevice => Error::BadDevice,
        MessageError::TooManyDevices => Error::TooManyDevices,
        MessageError::BadE2ee => Error::BadE2ee,
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

pub(crate) async fn member(pool: &PgPool, headers: &HeaderMap) -> Result<Caller, Error> {
    caller(pool, headers).await.map_err(from_api)
}

pub(crate) fn signed(mut value: Value) -> Json<Value> {
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
        body.e2ee.unwrap_or(false),
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
    let (direct, created) = open_direct(&pool, &caller, &body.user_id, body.e2ee.unwrap_or(false))
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
    .map_err(|error| {
        let error = lift(error);
        message_failed(&caller.user_id, &id, &error);
        error
    })
}

async fn add_message(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<PostBody>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let caller = member(&pool, &headers).await?;
    let attachments = body.attachment_ids.unwrap_or_default();
    // Any of these says the request is ciphertext. There is no mixing it with a body.
    if body.ciphertext.is_some()
        || body.epoch.is_some()
        || body.device_id.is_some()
        || body.kind.is_some()
        || body.target_id.is_some()
    {
        return crate::e2ee_text::post_ciphertext(
            &pool,
            &caller,
            &id,
            crate::e2ee_text::PostFields {
                ciphertext: body.ciphertext.as_deref(),
                epoch: body.epoch,
                device_id: body.device_id.as_deref(),
                kind: body.kind.as_deref(),
                target_id: body.target_id.as_deref(),
                client_id: body.client_id.as_deref(),
                reply_to: body.reply_to.as_deref(),
                attachments: &attachments,
                has_body: body.body.is_some(),
            },
        )
        .await
        .inspect_err(|error| {
            message_failed(&caller.user_id, &id, error);
        });
    }
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
    .map_err(|error| {
        let error = lift(error);
        message_failed(&caller.user_id, &id, &error);
        error
    })?;
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
        .map_err(|error| {
            let error = lift(error);
            message_failed(&caller.user_id, "", &error);
            error
        })
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
        .map_err(|error| {
            let error = lift(error);
            message_failed(&caller.user_id, "", &error);
            error
        })
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
        .map_err(|error| {
            let error = lift(error);
            message_failed(&caller.user_id, "", &error);
            error
        })?;
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
        .map_err(|error| {
            let error = lift(error);
            message_failed(&caller.user_id, "", &error);
            error
        })?;
    Ok(StatusCode::NO_CONTENT)
}

async fn upload(
    State(pool): State<PgPool>,
    Extension(engine): Extension<Arc<dyn ScanEngine>>,
    headers: HeaderMap,
    request: Request,
) -> Result<(StatusCode, Json<Value>), Error> {
    let caller = member(&pool, &headers).await?;
    let content_type = match headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    {
        Some(content_type) => content_type,
        None => {
            let error = Error::Invalid;
            upload_failed(&caller.user_id, &error, 0);
            return Err(error);
        }
    };
    let body = match to_bytes(request.into_body(), UPLOAD_BODY).await {
        Ok(body) => body,
        Err(_) => {
            let error = Error::TooLarge;
            upload_failed(&caller.user_id, &error, UPLOAD_BODY);
            return Err(error);
        }
    };
    let bytes = body.len();
    let parsed = parse_upload(content_type, &body).map_err(|error| {
        let error = lift(error);
        upload_failed(&caller.user_id, &error, bytes);
        error
    })?;
    let saved = match parsed {
        Parsed::Plain(upload) => save_attachment(&pool, &caller, &upload, &engine).await,
        // Opaque bytes: no type check, no decode, no scan, and so no engine.
        Parsed::Sealed(sealed) => save_sealed_attachment(&pool, &caller, &sealed).await,
    }
    .map_err(|error| {
        let error = lift(error);
        upload_failed(&caller.user_id, &error, bytes);
        error
    })?;
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

/// What a multipart upload is: a file to check and scan, or sealed bytes to store as they are.
enum Parsed {
    Plain(NewAttachment),
    Sealed(Vec<u8>),
}

fn parse_upload(content_type: &str, body: &[u8]) -> Result<Parsed, MessageError> {
    let boundary = boundary(content_type).ok_or(MessageError::Invalid)?;
    let parts = split_parts(body, &boundary).ok_or(MessageError::Invalid)?;
    if parts.is_empty() || parts.len() > 8 {
        return Err(MessageError::Invalid);
    }
    let mut file: Option<NewAttachment> = None;
    let mut sealed = false;
    let mut width = None;
    let mut height = None;
    let mut duration = None;
    for part in parts {
        let parsed = parse_part(part).ok_or(MessageError::Invalid)?;
        match parsed.name.as_str() {
            "file" => {
                // The name is read after the loop: a sealed upload has none worth reading.
                if file.is_some() {
                    return Err(MessageError::Invalid);
                }
                file = Some(NewAttachment {
                    name: parsed.filename.unwrap_or_default(),
                    mime: parsed
                        .mime
                        .unwrap_or_else(|| "application/octet-stream".to_string()),
                    bytes: parsed.body,
                    width: None,
                    height: None,
                    duration: None,
                });
            }
            "sealed" => sealed = field_sealed(&parsed.body)?,
            "width" => width = Some(field_i32(&parsed.body)?),
            "height" => height = Some(field_i32(&parsed.body)?),
            "duration" => duration = Some(field_i32(&parsed.body)?),
            _ => {}
        }
    }
    let mut file = file.ok_or(MessageError::Invalid)?;
    if sealed {
        return Ok(Parsed::Sealed(file.bytes));
    }
    if file.name.is_empty() {
        return Err(MessageError::Invalid);
    }
    file.width = width;
    file.height = height;
    file.duration = duration;
    Ok(Parsed::Plain(file))
}

/// `sealed=1` is sealed; `0` is not; anything else is not a form this server knows.
fn field_sealed(body: &[u8]) -> Result<bool, MessageError> {
    match std::str::from_utf8(body).map(str::trim) {
        Ok("1") => Ok(true),
        Ok("0") => Ok(false),
        _ => Err(MessageError::Invalid),
    }
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
    use super::{parse_upload, Parsed};

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
        let Parsed::Plain(upload) =
            parse_upload("multipart/form-data; boundary=abc", body).expect("parse")
        else {
            panic!("a plain upload");
        };
        assert_eq!(upload.name, "wave.gif");
        assert_eq!(upload.mime, "image/gif");
        assert_eq!(upload.bytes, b"GIF89a");
        assert_eq!(upload.width, Some(12));
        assert_eq!(upload.height, None);
    }
}
