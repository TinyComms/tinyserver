use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, put};
use axum::{Json, Router};
use db::{close_all_sessions, delete_avatar, get_avatar, rename_me, set_avatar, PgPool};
use serde::{Deserialize, Serialize};

use crate::community::{caller, icon_failure, lift, ApiError};
use crate::session::Current;

pub fn routes() -> Router<PgPool> {
    Router::new()
        .route("/v1/me", patch(rename))
        .route(
            "/v1/me/avatar",
            put(put_avatar)
                .delete(clear_avatar)
                .layer(DefaultBodyLimit::max(db::ICON_MAX)),
        )
        .route("/v1/users/{user_id}/avatar", get(avatar))
        .route("/v1/sessions", delete(sign_out_everywhere))
}

#[derive(Deserialize)]
struct NameBody {
    display_name: String,
}

async fn rename(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(body): Json<NameBody>,
) -> Result<Json<Current>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    let identity = rename_me(&pool, &caller, &body.display_name)
        .await
        .map_err(lift)?;
    tracing::info!(user_id = %caller.user_id, "display name changed");
    Ok(Json(Current::from(identity)))
}

#[derive(Serialize)]
struct AvatarBody {
    avatar: String,
}

/// The body is the image itself: PNG, JPEG, or WebP, at most 256 KiB.
async fn put_avatar(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<AvatarBody>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    let bytes = body.map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::TooLarge
        } else {
            ApiError::Invalid
        }
    })?;
    if bytes.len() > db::ICON_MAX {
        return Err(ApiError::TooLarge);
    }
    let stored = db::prepare_icon(&bytes).map_err(icon_failure)?;
    let avatar = set_avatar(&pool, &caller, &stored.bytes, &stored.mime)
        .await
        .map_err(lift)?;
    tracing::info!(user_id = %caller.user_id, bytes = stored.bytes.len(), "avatar set");
    Ok(Json(AvatarBody { avatar }))
}

async fn clear_avatar(
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let caller = caller(&pool, &headers).await?;
    delete_avatar(&pool, &caller).await.map_err(lift)?;
    tracing::info!(user_id = %caller.user_id, "avatar removed");
    Ok(StatusCode::NO_CONTENT)
}

async fn avatar(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<Response, ApiError> {
    let caller = caller(&pool, &headers).await?;
    let Some(icon) = get_avatar(&pool, &caller, &user_id).await.map_err(lift)? else {
        return Err(ApiError::NotFound);
    };
    let etag = format!("\"{}\"", icon.sha);
    let etag = HeaderValue::from_str(&etag).map_err(|_| ApiError::Unavailable)?;
    let fresh = headers
        .get(header::IF_NONE_MATCH)
        .is_some_and(|seen| seen == etag);
    if fresh {
        return Ok((StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response());
    }
    let content_type =
        HeaderValue::from_str(&icon.content_type).map_err(|_| ApiError::Unavailable)?;
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::ETAG, etag),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, max-age=3600"),
            ),
        ],
        icon.bytes,
    )
        .into_response())
}

async fn sign_out_everywhere(
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let caller = caller(&pool, &headers).await?;
    let ended = close_all_sessions(&pool, &caller).await.map_err(lift)?;
    tracing::info!(user_id = %caller.user_id, ended, "sessions closed");
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn account_routes_share_paths_without_overlap() {
        // Lib tests share a process. Leave the flag set. Selector tests pass
        // the socket and allow_fake in arguments and do not read this variable.
        std::env::set_var("TINYSERVER_ALLOW_FAKE_SCAN", "1");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://nobody@127.0.0.1:1/none")
            .expect("lazy pool");
        let _ = crate::router(pool, None);
    }
}
