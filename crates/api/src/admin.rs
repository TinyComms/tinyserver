//! Server settings and icon, capabilities, roles, bans, categories, and the channel layout.

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, put};
use axum::{Json, Router};
use db::{LayoutBucket, NewRole, PgPool, RolePatch, ServerPatch};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::community::{bits, caller, lift, nullable, ApiError};

/// What `GET /v1/capabilities` lists. A client that gets 404 there talks to an older server.
pub const FEATURES: &[&str] = &[
    "server",
    "roles",
    "categories",
    "bans",
    "timeouts",
    "invite_options",
    "audit_query",
    "voice_moderation",
];

pub fn routes() -> Router<PgPool> {
    Router::new()
        .route("/v1/capabilities", get(capabilities))
        .route("/v1/server", get(server).patch(edit_server))
        .route(
            "/v1/server/icon",
            get(icon)
                .put(put_icon)
                .delete(delete_icon)
                // The only route with a body bigger than the 8 KiB everything else gets.
                .layer(DefaultBodyLimit::max(db::ICON_MAX)),
        )
        .route("/v1/roles", get(roles).post(add_role))
        .route("/v1/roles/order", put(order_roles))
        .route("/v1/roles/{id}", patch(edit_role).delete(remove_role))
        .route("/v1/bans", get(bans).post(add_ban))
        .route("/v1/bans/{user_id}", delete(remove_ban))
        .route("/v1/categories", get(categories).post(add_category))
        .route(
            "/v1/categories/{id}",
            patch(rename_category).delete(remove_category),
        )
        .route("/v1/layout", put(layout))
}

#[derive(Serialize)]
struct Capabilities {
    version: &'static str,
    features: &'static [&'static str],
}

async fn capabilities(
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<Capabilities>, ApiError> {
    caller(&pool, &headers).await?;
    Ok(Json(Capabilities {
        version: env!("CARGO_PKG_VERSION"),
        features: FEATURES,
    }))
}

#[derive(Deserialize)]
struct ServerBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    welcome: Option<String>,
    #[serde(default, deserialize_with = "nullable")]
    default_room_id: Option<Option<String>>,
    #[serde(default, deserialize_with = "nullable")]
    afk_room_id: Option<Option<String>>,
    #[serde(default)]
    afk_timeout_secs: Option<i32>,
}

async fn server(
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<db::ServerSettings>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    db::get_server(&pool, &caller).await.map(Json).map_err(lift)
}

async fn edit_server(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(body): Json<ServerBody>,
) -> Result<Json<db::ServerSettings>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    let patch = ServerPatch {
        name: body.name,
        description: body.description,
        welcome: body.welcome,
        default_room_id: body.default_room_id,
        afk_room_id: body.afk_room_id,
        afk_timeout_secs: body.afk_timeout_secs,
    };
    let settings = db::update_server(&pool, &caller, &patch)
        .await
        .map_err(lift)?;
    tracing::info!(user_id = %caller.user_id, "server settings changed");
    Ok(Json(settings))
}

async fn icon(State(pool): State<PgPool>, headers: HeaderMap) -> Result<Response, ApiError> {
    let caller = caller(&pool, &headers).await?;
    let Some(icon) = db::get_icon(&pool, &caller).await.map_err(lift)? else {
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
        [(header::CONTENT_TYPE, content_type), (header::ETAG, etag)],
        icon.bytes,
    )
        .into_response())
}

#[derive(Serialize)]
struct IconBody {
    icon: Option<String>,
}

/// The body is the image itself: PNG, JPEG, or WebP, at most 256 KiB.
async fn put_icon(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<IconBody>, ApiError> {
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
    let content_type = db::sniff_image(&bytes).ok_or(ApiError::UnsupportedMedia)?;
    let sha = db::set_icon(&pool, &caller, &bytes, content_type)
        .await
        .map_err(lift)?;
    tracing::info!(user_id = %caller.user_id, bytes = bytes.len(), "server icon set");
    Ok(Json(IconBody { icon: Some(sha) }))
}

async fn delete_icon(
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let caller = caller(&pool, &headers).await?;
    db::delete_icon(&pool, &caller).await.map_err(lift)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct RoleBody {
    name: String,
    #[serde(default)]
    color: Option<String>,
    #[serde(default)]
    permissions: Option<u64>,
    #[serde(default)]
    hoist: Option<bool>,
}

#[derive(Deserialize)]
struct RolePatchBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, deserialize_with = "nullable")]
    color: Option<Option<String>>,
    #[serde(default)]
    permissions: Option<u64>,
    #[serde(default)]
    hoist: Option<bool>,
}

#[derive(Deserialize)]
struct OrderBody {
    ids: Vec<String>,
}

async fn roles(
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<Vec<db::Role>>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    db::list_roles(&pool, &caller).await.map(Json).map_err(lift)
}

async fn add_role(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(body): Json<RoleBody>,
) -> Result<(StatusCode, Json<db::Role>), ApiError> {
    let caller = caller(&pool, &headers).await?;
    let input = NewRole {
        name: body.name,
        color: body.color,
        permissions: body.permissions.map(bits),
        hoist: body.hoist,
    };
    let role = db::create_role(&pool, &caller, &input)
        .await
        .map_err(lift)?;
    tracing::info!(user_id = %caller.user_id, role = %role.id, "role created");
    Ok((StatusCode::CREATED, Json(role)))
}

async fn edit_role(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<RolePatchBody>,
) -> Result<Json<db::Role>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    let patch = RolePatch {
        name: body.name,
        color: body.color,
        permissions: body.permissions.map(bits),
        hoist: body.hoist,
    };
    let role = db::update_role(&pool, &caller, &id, &patch)
        .await
        .map_err(lift)?;
    tracing::info!(user_id = %caller.user_id, role = %id, "role changed");
    Ok(Json(role))
}

async fn remove_role(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let caller = caller(&pool, &headers).await?;
    db::delete_role(&pool, &caller, &id).await.map_err(lift)?;
    tracing::info!(user_id = %caller.user_id, role = %id, "role deleted");
    Ok(StatusCode::NO_CONTENT)
}

async fn order_roles(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(body): Json<OrderBody>,
) -> Result<Json<Vec<db::Role>>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    let roles = db::order_roles(&pool, &caller, &body.ids)
        .await
        .map_err(lift)?;
    tracing::info!(user_id = %caller.user_id, "roles reordered");
    Ok(Json(roles))
}

#[derive(Deserialize)]
struct BanBody {
    user_id: String,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    expires_at: Option<String>,
}

async fn bans(
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<Vec<db::Ban>>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    db::list_bans(&pool, &caller).await.map(Json).map_err(lift)
}

async fn add_ban(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(body): Json<BanBody>,
) -> Result<(StatusCode, Json<db::Ban>), ApiError> {
    let caller = caller(&pool, &headers).await?;
    let ban = db::ban(
        &pool,
        &caller,
        &body.user_id,
        body.reason.as_deref(),
        body.expires_at.as_deref(),
    )
    .await
    .map_err(lift)?;
    tracing::info!(user_id = %caller.user_id, banned = %ban.user_id, "member banned");
    Ok((StatusCode::CREATED, Json(ban)))
}

async fn remove_ban(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let caller = caller(&pool, &headers).await?;
    db::unban(&pool, &caller, &user_id).await.map_err(lift)?;
    tracing::info!(user_id = %caller.user_id, unbanned = %user_id, "ban lifted");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct NameBody {
    name: String,
}

async fn categories(
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<Vec<db::Category>>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    db::list_categories(&pool, &caller)
        .await
        .map(Json)
        .map_err(lift)
}

async fn add_category(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(body): Json<NameBody>,
) -> Result<(StatusCode, Json<db::Category>), ApiError> {
    let caller = caller(&pool, &headers).await?;
    let category = db::create_category(&pool, &caller, &body.name)
        .await
        .map_err(lift)?;
    Ok((StatusCode::CREATED, Json(category)))
}

async fn rename_category(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<NameBody>,
) -> Result<Json<db::Category>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    db::rename_category(&pool, &caller, &id, &body.name)
        .await
        .map(Json)
        .map_err(lift)
}

async fn remove_category(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let caller = caller(&pool, &headers).await?;
    db::delete_category(&pool, &caller, &id)
        .await
        .map_err(lift)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct LayoutBody {
    categories: Vec<BucketBody>,
}

#[derive(Deserialize)]
struct BucketBody {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    room_ids: Vec<String>,
}

async fn layout(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(body): Json<LayoutBody>,
) -> Result<Json<Value>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    let buckets: Vec<LayoutBucket> = body
        .categories
        .into_iter()
        .map(|bucket| LayoutBucket {
            category_id: bucket.id,
            room_ids: bucket.room_ids,
        })
        .collect();
    let layout = db::set_layout(&pool, &caller, &buckets)
        .await
        .map_err(lift)?;
    tracing::info!(user_id = %caller.user_id, "layout changed");
    serde_json::to_value(layout)
        .map(Json)
        .map_err(|_| ApiError::Unavailable)
}
