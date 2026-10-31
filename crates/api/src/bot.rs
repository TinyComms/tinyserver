//! Application bots. An owner or admin creates one and gets the token once.
//! The bot sends `Authorization: Bot <token>`.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use db::{create_bot, list_bots, revoke_bot, PgPool};
use serde::Deserialize;

use crate::community::{caller, lift, ApiError};

pub fn routes() -> Router<PgPool> {
    Router::new()
        .route("/v1/bots", get(bots).post(add))
        .route("/v1/bots/{id}", axum::routing::delete(revoke))
}

#[derive(Deserialize)]
struct NewBot {
    name: String,
    #[serde(default)]
    scopes: Vec<String>,
    /// Discord-style permission bits. When set, this replaces `scopes`.
    #[serde(default)]
    permissions: Option<i64>,
}

async fn bots(
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<Vec<db::Bot>>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    list_bots(&pool, &caller).await.map(Json).map_err(lift)
}

async fn add(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(body): Json<NewBot>,
) -> Result<(StatusCode, Json<db::BotIssued>), ApiError> {
    let caller = caller(&pool, &headers).await?;
    let issued = create_bot(&pool, &caller, &body.name, &body.scopes, body.permissions)
        .await
        .map_err(lift)?;
    tracing::info!(user_id = %caller.user_id, bot_id = %issued.id, "bot created");
    Ok((StatusCode::CREATED, Json(issued)))
}

async fn revoke(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let caller = caller(&pool, &headers).await?;
    revoke_bot(&pool, &caller, &id).await.map_err(lift)?;
    tracing::info!(user_id = %caller.user_id, bot_id = %id, "bot revoked");
    Ok(StatusCode::NO_CONTENT)
}
