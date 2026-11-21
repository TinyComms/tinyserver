//! Group conversation HTTP routes: `/v1/groups`, `/v1/groups/{id}`,
//! `/v1/groups/{id}/members`, `/v1/groups/{id}/members/me`.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use db::{add_group_member, get_group, leave_group, list_groups, open_group, rename_group, PgPool};
use serde::Deserialize;
use serde_json::Value;

use crate::messages::{lift, member, signed, Error};

pub fn routes() -> Router<PgPool> {
    Router::new()
        .route("/v1/groups", get(groups).post(create_or_find_group))
        .route("/v1/groups/{id}", get(one_group).patch(patch_group))
        .route("/v1/groups/{id}/members", post(add_member))
        .route("/v1/groups/{id}/members/me", delete(leave))
}

#[derive(Deserialize)]
struct OpenGroupBody {
    user_ids: Vec<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    e2ee: Option<bool>,
}

#[derive(Deserialize)]
struct RenameGroupBody {
    name: String,
}

#[derive(Deserialize)]
struct AddMemberBody {
    user_id: String,
}

async fn groups(State(pool): State<PgPool>, headers: HeaderMap) -> Result<Json<Value>, Error> {
    let caller = member(&pool, &headers).await?;
    list_groups(&pool, &caller).await.map(signed).map_err(lift)
}

async fn create_or_find_group(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(body): Json<OpenGroupBody>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let caller = member(&pool, &headers).await?;
    let (group, created) = open_group(
        &pool,
        &caller,
        &body.user_ids,
        body.name.as_deref(),
        body.e2ee.unwrap_or(false),
    )
    .await
    .map_err(lift)?;
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, signed(group)))
}

async fn one_group(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, Error> {
    let caller = member(&pool, &headers).await?;
    get_group(&pool, &caller, &id)
        .await
        .map(signed)
        .map_err(lift)
}

async fn patch_group(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<RenameGroupBody>,
) -> Result<Json<Value>, Error> {
    let caller = member(&pool, &headers).await?;
    rename_group(&pool, &caller, &id, &body.name)
        .await
        .map(signed)
        .map_err(lift)
}

async fn add_member(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<AddMemberBody>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let caller = member(&pool, &headers).await?;
    let (group, added) = add_group_member(&pool, &caller, &id, &body.user_id)
        .await
        .map_err(lift)?;
    let status = if added {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, signed(group)))
}

async fn leave(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, Error> {
    let caller = member(&pool, &headers).await?;
    leave_group(&pool, &caller, &id).await.map_err(lift)?;
    Ok(StatusCode::NO_CONTENT)
}
