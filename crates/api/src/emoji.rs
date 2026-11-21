//! Custom community emoji and stickers (`GET/POST /v1/emoji`, `GET/PATCH/DELETE /v1/emoji/{id}`).

use axum::body::to_bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use db::PgPool;
use serde::Deserialize;
use serde_json::Value;

use crate::messages::{lift, member, parse_multipart_parts, Error};

/// Room for multipart headers around a 512 KiB sticker upload.
const EMOJI_BODY_LIMIT: usize = db::STICKER_MAX_BYTES + 64 * 1024;

pub fn routes() -> Router<PgPool> {
    let upload = Router::new()
        .route("/v1/emoji", get(list).post(create))
        .layer(DefaultBodyLimit::max(EMOJI_BODY_LIMIT));
    Router::new()
        .merge(upload)
        .route(
            "/v1/emoji/{id}",
            get(fetch).patch(rename).delete(remove),
        )
}

#[derive(Deserialize, Default)]
struct ListQuery {
    kind: Option<String>,
}

#[derive(Deserialize)]
struct RenameBody {
    name: String,
}

async fn list(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, Error> {
    let caller = member(&pool, &headers).await?;
    db::list_emoji(&pool, &caller, query.kind.as_deref())
        .await
        .map(Json)
        .map_err(lift)
}

async fn fetch(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, Error> {
    let caller = member(&pool, &headers).await?;
    let Some(image) = db::get_emoji(&pool, &caller, &id).await.map_err(lift)? else {
        return Err(Error::NotFound);
    };
    let etag = format!("\"{}\"", image.sha);
    let etag = HeaderValue::from_str(&etag).map_err(|_| Error::Unavailable)?;
    let cache = HeaderValue::from_static("private, max-age=31536000, immutable");
    let fresh = headers
        .get(header::IF_NONE_MATCH)
        .is_some_and(|seen| seen == etag);
    if fresh {
        return Ok((
            StatusCode::NOT_MODIFIED,
            [(header::ETAG, etag), (header::CACHE_CONTROL, cache)],
        )
            .into_response());
    }
    let content_type =
        HeaderValue::from_str(&image.content_type).map_err(|_| Error::Unavailable)?;
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::ETAG, etag),
            (header::CACHE_CONTROL, cache),
        ],
        image.bytes,
    )
        .into_response())
}

async fn create(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    request: Request,
) -> Result<(StatusCode, Json<Value>), Error> {
    let caller = member(&pool, &headers).await?;
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .ok_or(Error::Invalid)?;
    let body = to_bytes(request.into_body(), EMOJI_BODY_LIMIT)
        .await
        .map_err(|_| Error::TooLarge)?;
    let parts = parse_multipart_parts(content_type, &body).map_err(lift)?;

    let mut name: Option<String> = None;
    let mut kind: Option<String> = None;
    let mut file: Option<Vec<u8>> = None;
    for part in parts {
        match part.name.as_str() {
            "name" => {
                let text = std::str::from_utf8(&part.body).map_err(|_| Error::Invalid)?;
                name = Some(text.trim().to_string());
            }
            "kind" => {
                let text = std::str::from_utf8(&part.body).map_err(|_| Error::Invalid)?;
                kind = Some(text.trim().to_string());
            }
            "file" => {
                if file.is_some() {
                    return Err(Error::Invalid);
                }
                file = Some(part.body);
            }
            _ => {}
        }
    }
    let name = name.ok_or(Error::Invalid)?;
    let file = file.ok_or(Error::Invalid)?;
    let kind = kind.as_deref().unwrap_or("emoji");

    let created = db::create_emoji(&pool, &caller, kind, &name, &file)
        .await
        .map_err(lift)?;
    Ok((StatusCode::CREATED, Json(created)))
}

async fn rename(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<RenameBody>,
) -> Result<Json<Value>, Error> {
    let caller = member(&pool, &headers).await?;
    db::rename_emoji(&pool, &caller, &id, &body.name)
        .await
        .map(Json)
        .map_err(lift)
}

async fn remove(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, Error> {
    let caller = member(&pool, &headers).await?;
    db::delete_emoji(&pool, &caller, &id).await.map_err(lift)?;
    Ok(StatusCode::NO_CONTENT)
}
