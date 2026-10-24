use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use db::{
    accept_invite, create_invite, create_room, delete_room, list_audit, list_invites, list_members,
    list_rooms, remove_member, rename_room, set_member_role, Caller, CommunityError, PgPool,
    SessionError, Wrote,
};
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

use crate::session::bearer;

pub fn routes() -> Router<PgPool> {
    Router::new()
        .route("/v1/rooms", get(rooms).post(add_room))
        .route(
            "/v1/rooms/{id}",
            axum::routing::patch(rename).delete(remove_room),
        )
        .route("/v1/members", get(members))
        .route(
            "/v1/members/{id}",
            axum::routing::patch(role).delete(remove_member_route),
        )
        .route("/v1/invites", get(invites).post(add_invite))
        .route("/v1/invites/accept", axum::routing::post(accept))
        .route("/v1/audit", get(audit))
}

#[derive(Deserialize)]
struct NameBody {
    name: String,
}

#[derive(Deserialize, Serialize)]
struct RoleBody {
    role: String,
}

#[derive(Deserialize)]
struct AcceptBody {
    token: String,
    email: String,
    password: String,
    display_name: String,
}

#[derive(Deserialize)]
struct AuditQuery {
    limit: Option<i64>,
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

enum ApiError {
    Unauthorized,
    Forbidden,
    NotFound,
    Invalid,
    LastOwner,
    AlreadyMember,
    EmailTaken,
    InvalidCredentials,
    IdempotencyConflict,
    Unavailable,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error) = match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Invalid => (StatusCode::BAD_REQUEST, "invalid"),
            Self::LastOwner => (StatusCode::CONFLICT, "last_owner"),
            Self::AlreadyMember => (StatusCode::CONFLICT, "already_member"),
            Self::EmailTaken => (StatusCode::CONFLICT, "email_taken"),
            Self::InvalidCredentials => (StatusCode::UNAUTHORIZED, "invalid_credentials"),
            Self::IdempotencyConflict => (StatusCode::CONFLICT, "idempotency_conflict"),
            Self::Unavailable => (StatusCode::INTERNAL_SERVER_ERROR, "unavailable"),
        };
        (status, Json(ErrorBody { error })).into_response()
    }
}

fn lift(error: CommunityError) -> ApiError {
    match error {
        CommunityError::Forbidden => ApiError::Forbidden,
        CommunityError::NotFound => ApiError::NotFound,
        CommunityError::LastOwner => ApiError::LastOwner,
        CommunityError::Invalid => ApiError::Invalid,
        CommunityError::AlreadyMember => ApiError::AlreadyMember,
        CommunityError::EmailTaken => ApiError::EmailTaken,
        CommunityError::InvalidCredentials => ApiError::InvalidCredentials,
        CommunityError::IdempotencyConflict => ApiError::IdempotencyConflict,
        CommunityError::Incomplete => ApiError::Unavailable,
        CommunityError::Database(error) => {
            tracing::warn!(%error, "community query failed");
            ApiError::Unavailable
        }
    }
}

fn session_failure(error: SessionError) -> ApiError {
    match error {
        SessionError::InvalidCredentials | SessionError::Unauthorized => ApiError::Unauthorized,
        SessionError::Database(error) => {
            tracing::warn!(%error, "session query failed");
            ApiError::Unavailable
        }
    }
}

async fn caller(pool: &PgPool, headers: &HeaderMap) -> Result<Caller, ApiError> {
    let token = bearer(headers).ok_or(ApiError::Unauthorized)?;
    let identity = db::current_session(pool, token)
        .await
        .map_err(session_failure)?;
    Ok(Caller {
        user_id: identity.user_id,
        role: identity.role,
    })
}

fn idempotency_key(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get("idempotency-key")?.to_str().ok()?;
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn created<T: Serialize>(wrote: Wrote<T>) -> Result<(StatusCode, Json<Value>), ApiError> {
    let body = match wrote {
        Wrote::Fresh(value) => serde_json::to_value(value).map_err(|_| ApiError::Unavailable)?,
        Wrote::Replay(value) => value,
    };
    Ok((StatusCode::CREATED, Json(body)))
}

async fn rooms(
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<Vec<db::Room>>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    list_rooms(&pool, &caller).await.map(Json).map_err(lift)
}

async fn add_room(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(body): Json<NameBody>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let caller = caller(&pool, &headers).await?;
    let wrote = create_room(&pool, &caller, &body.name, idempotency_key(&headers))
        .await
        .map_err(lift)?;
    if matches!(wrote, Wrote::Fresh(_)) {
        tracing::info!(user_id = %caller.user_id, "room created");
    }
    created(wrote)
}

async fn rename(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<NameBody>,
) -> Result<Json<db::Room>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    rename_room(&pool, &caller, &id, &body.name)
        .await
        .map(Json)
        .map_err(lift)
}

async fn remove_room(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let caller = caller(&pool, &headers).await?;
    delete_room(&pool, &caller, &id).await.map_err(lift)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn members(
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<Vec<db::Member>>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    list_members(&pool, &caller).await.map(Json).map_err(lift)
}

async fn role(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<RoleBody>,
) -> Result<Json<RoleBody>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    let role = set_member_role(&pool, &caller, &id, &body.role)
        .await
        .map_err(lift)?;
    tracing::info!(user_id = %caller.user_id, member = %id, %role, "role changed");
    Ok(Json(RoleBody { role }))
}

async fn remove_member_route(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let caller = caller(&pool, &headers).await?;
    remove_member(&pool, &caller, &id).await.map_err(lift)?;
    tracing::info!(user_id = %caller.user_id, member = %id, "member removed");
    Ok(StatusCode::NO_CONTENT)
}

async fn invites(
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<Vec<db::Invite>>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    list_invites(&pool, &caller).await.map(Json).map_err(lift)
}

async fn add_invite(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(body): Json<RoleBody>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let caller = caller(&pool, &headers).await?;
    let wrote = create_invite(&pool, &caller, &body.role, idempotency_key(&headers))
        .await
        .map_err(lift)?;
    if matches!(wrote, Wrote::Fresh(_)) {
        tracing::info!(user_id = %caller.user_id, "invite created");
    }
    created(wrote)
}

async fn accept(
    State(pool): State<PgPool>,
    Json(body): Json<AcceptBody>,
) -> Result<Json<db::Accepted>, ApiError> {
    let accepted = accept_invite(
        &pool,
        &body.token,
        &body.email,
        &body.password,
        &body.display_name,
    )
    .await
    .map_err(lift)?;
    tracing::info!(user_id = %accepted.user_id, "invite accepted");
    Ok(Json(accepted))
}

async fn audit(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Vec<db::AuditRow>>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    list_audit(&pool, &caller, query.limit.unwrap_or(50))
        .await
        .map(Json)
        .map_err(lift)
}
