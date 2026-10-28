//! Rooms, people, invites, and the audit log. Server settings, roles, bans, and categories are
//! in `admin`.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, put};
use axum::{Json, Router};
use db::{
    create_invite, create_invite_with, create_room, delete_room, list_audit, list_invites,
    list_members, list_rooms, remove_member, revoke_invite, set_member_role, set_member_roles,
    set_override, set_owner, set_timeout, update_room, AuditQuery, Caller, CommunityError,
    InviteOptions, NewRoom, PgPool, RoomPatch, SessionError, Wrote,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::session::bearer;

pub fn routes() -> Router<PgPool> {
    Router::new()
        .route("/v1/rooms", get(rooms).post(add_room))
        .route("/v1/rooms/{id}", patch(edit_room).delete(remove_room))
        .route(
            "/v1/rooms/{id}/overrides/{role_id}",
            put(put_override).delete(delete_override),
        )
        .route("/v1/members", get(members))
        .route("/v1/members/{id}", patch(role).delete(remove_member_route))
        .route("/v1/members/{id}/roles", put(member_roles))
        .route("/v1/members/{id}/owner", put(member_owner))
        .route("/v1/members/{id}/timeout", put(member_timeout))
        .route("/v1/invites", get(invites).post(add_invite))
        .route("/v1/invites/{id}", delete(revoke))
        .route("/v1/audit", get(audit))
}

/// `Some(None)` for an explicit `null`, `None` when the field is missing. Use with
/// `#[serde(default, deserialize_with = "nullable")]`.
pub(crate) fn nullable<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
struct RoomBody {
    name: String,
    #[serde(default)]
    category_id: Option<String>,
    #[serde(default)]
    topic: Option<String>,
    #[serde(default)]
    user_limit: Option<i32>,
    #[serde(default)]
    bitrate_kbps: Option<i32>,
    #[serde(default)]
    ptt_only: Option<bool>,
    #[serde(default)]
    video_enabled: Option<bool>,
}

#[derive(Deserialize)]
struct RoomPatchBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, deserialize_with = "nullable")]
    category_id: Option<Option<String>>,
    #[serde(default)]
    position: Option<i32>,
    #[serde(default)]
    topic: Option<String>,
    #[serde(default)]
    user_limit: Option<i32>,
    #[serde(default)]
    bitrate_kbps: Option<i32>,
    #[serde(default)]
    ptt_only: Option<bool>,
    #[serde(default)]
    video_enabled: Option<bool>,
}

#[derive(Deserialize)]
struct OverrideBody {
    #[serde(default)]
    allow: u64,
    #[serde(default)]
    deny: u64,
}

#[derive(Deserialize, Serialize)]
struct RoleBody {
    role: String,
}

#[derive(Deserialize)]
struct RolesBody {
    role_ids: Vec<String>,
}

#[derive(Deserialize)]
struct OwnerBody {
    owner: bool,
}

#[derive(Deserialize)]
struct TimeoutBody {
    #[serde(default)]
    until: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize)]
struct ReasonQuery {
    reason: Option<String>,
}

/// The legacy `{role}` or the new fields; both may come together.
#[derive(Deserialize)]
struct InviteBody {
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    role_ids: Option<Vec<String>>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default, deserialize_with = "nullable")]
    max_uses: Option<Option<i32>>,
    #[serde(default, deserialize_with = "nullable")]
    expires_in_secs: Option<Option<i64>>,
}

#[derive(Deserialize)]
struct AuditParams {
    limit: Option<i64>,
    before: Option<i64>,
    actor: Option<String>,
    action: Option<String>,
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

pub(crate) enum ApiError {
    Unauthorized,
    Forbidden,
    Hierarchy,
    NotFound,
    Invalid,
    DefaultRole,
    Banned,
    LastOwner,
    AlreadyMember,
    IdempotencyConflict,
    TooLarge,
    UnsupportedMedia,
    Unavailable,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error) = match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::Hierarchy => (StatusCode::FORBIDDEN, "hierarchy"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Invalid => (StatusCode::BAD_REQUEST, "invalid"),
            Self::DefaultRole => (StatusCode::BAD_REQUEST, "default_role"),
            Self::Banned => (StatusCode::FORBIDDEN, "banned"),
            Self::LastOwner => (StatusCode::CONFLICT, "last_owner"),
            Self::AlreadyMember => (StatusCode::CONFLICT, "already_member"),
            Self::IdempotencyConflict => (StatusCode::CONFLICT, "idempotency_conflict"),
            Self::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "too_large"),
            Self::UnsupportedMedia => (StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media"),
            Self::Unavailable => (StatusCode::INTERNAL_SERVER_ERROR, "unavailable"),
        };
        (status, Json(ErrorBody { error })).into_response()
    }
}

pub(crate) fn lift(error: CommunityError) -> ApiError {
    match error {
        CommunityError::Forbidden => ApiError::Forbidden,
        CommunityError::Hierarchy => ApiError::Hierarchy,
        CommunityError::NotFound => ApiError::NotFound,
        CommunityError::LastOwner => ApiError::LastOwner,
        CommunityError::Invalid => ApiError::Invalid,
        CommunityError::DefaultRole => ApiError::DefaultRole,
        CommunityError::Banned => ApiError::Banned,
        CommunityError::AlreadyMember => ApiError::AlreadyMember,
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
        SessionError::Unauthorized => ApiError::Unauthorized,
        SessionError::Database(error) => {
            tracing::warn!(%error, "session query failed");
            ApiError::Unavailable
        }
    }
}

pub(crate) async fn caller(pool: &PgPool, headers: &HeaderMap) -> Result<Caller, ApiError> {
    let token = bearer(headers).ok_or(ApiError::Unauthorized)?;
    let identity = db::current_session(pool, token)
        .await
        .map_err(session_failure)?;
    Ok(Caller {
        user_id: identity.user_id,
        role: identity.role,
    })
}

pub(crate) fn idempotency_key(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get("idempotency-key")?.to_str().ok()?;
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

pub(crate) fn created<T: Serialize>(
    wrote: Wrote<T>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let body = match wrote {
        Wrote::Fresh(value) => serde_json::to_value(value).map_err(|_| ApiError::Unavailable)?,
        Wrote::Replay(value) => value,
    };
    Ok((StatusCode::CREATED, Json(body)))
}

/// Permission bits from a client: unknown bits are dropped, and anything over 2^53 is not a
/// JSON number a client can send exactly.
pub(crate) fn bits(value: u64) -> i64 {
    (value & db::perm::ALL as u64) as i64
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
    Json(body): Json<RoomBody>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let caller = caller(&pool, &headers).await?;
    let input = NewRoom {
        name: body.name,
        category_id: body.category_id,
        topic: body.topic,
        user_limit: body.user_limit,
        bitrate_kbps: body.bitrate_kbps,
        ptt_only: body.ptt_only,
        video_enabled: body.video_enabled,
    };
    let wrote = create_room(&pool, &caller, &input, idempotency_key(&headers))
        .await
        .map_err(lift)?;
    if matches!(wrote, Wrote::Fresh(_)) {
        tracing::info!(user_id = %caller.user_id, "room created");
    }
    created(wrote)
}

async fn edit_room(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<RoomPatchBody>,
) -> Result<Json<db::Room>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    let patch = RoomPatch {
        name: body.name,
        category_id: body.category_id,
        position: body.position,
        topic: body.topic,
        user_limit: body.user_limit,
        bitrate_kbps: body.bitrate_kbps,
        ptt_only: body.ptt_only,
        video_enabled: body.video_enabled,
    };
    update_room(&pool, &caller, &id, &patch)
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

async fn put_override(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path((id, role_id)): Path<(String, String)>,
    Json(body): Json<OverrideBody>,
) -> Result<Json<db::Room>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    let room = set_override(
        &pool,
        &caller,
        &id,
        &role_id,
        Some((bits(body.allow), bits(body.deny))),
    )
    .await
    .map_err(lift)?;
    tracing::info!(user_id = %caller.user_id, room = %id, role = %role_id, "override set");
    Ok(Json(room))
}

async fn delete_override(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path((id, role_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let caller = caller(&pool, &headers).await?;
    set_override(&pool, &caller, &id, &role_id, None)
        .await
        .map_err(lift)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn members(
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<Vec<db::Member>>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    list_members(&pool, &caller).await.map(Json).map_err(lift)
}

/// The legacy role change: `{role}` in, `{role}` out.
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

async fn member_roles(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<RolesBody>,
) -> Result<Json<db::Member>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    let member = set_member_roles(&pool, &caller, &id, &body.role_ids)
        .await
        .map_err(lift)?;
    tracing::info!(user_id = %caller.user_id, member = %id, "roles changed");
    Ok(Json(member))
}

async fn member_owner(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<OwnerBody>,
) -> Result<Json<db::Member>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    let member = set_owner(&pool, &caller, &id, body.owner)
        .await
        .map_err(lift)?;
    tracing::info!(user_id = %caller.user_id, member = %id, owner = body.owner, "owner changed");
    Ok(Json(member))
}

async fn member_timeout(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<TimeoutBody>,
) -> Result<Json<db::Member>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    let member = set_timeout(
        &pool,
        &caller,
        &id,
        body.until.as_deref(),
        body.reason.as_deref(),
    )
    .await
    .map_err(lift)?;
    tracing::info!(user_id = %caller.user_id, member = %id, "timeout changed");
    Ok(Json(member))
}

async fn remove_member_route(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<ReasonQuery>,
) -> Result<StatusCode, ApiError> {
    let caller = caller(&pool, &headers).await?;
    remove_member(&pool, &caller, &id, query.reason.as_deref())
        .await
        .map_err(lift)?;
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
    Json(body): Json<InviteBody>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let caller = caller(&pool, &headers).await?;
    let legacy_only = body.role_ids.is_none()
        && body.label.is_none()
        && body.max_uses.is_none()
        && body.expires_in_secs.is_none();
    let key = idempotency_key(&headers);
    let wrote = match (&body.role, legacy_only) {
        (Some(role), true) => create_invite(&pool, &caller, role, key).await,
        (None, true) => create_invite(&pool, &caller, "member", key).await,
        (role, false) => {
            let defaults = InviteOptions::default();
            let mut role_ids = body.role_ids.clone().unwrap_or_default();
            match role.as_deref() {
                None | Some("member") => {}
                Some("admin") => {
                    let admin = db::admin_role(&pool).await.map_err(lift)?;
                    role_ids.push(admin.ok_or(ApiError::Invalid)?);
                }
                Some(_) => return Err(ApiError::Invalid),
            }
            let options = InviteOptions {
                role_ids,
                label: body.label.clone(),
                max_uses: body.max_uses.unwrap_or(defaults.max_uses),
                expires_in_secs: body.expires_in_secs.unwrap_or(defaults.expires_in_secs),
            };
            create_invite_with(&pool, &caller, &options, key).await
        }
    }
    .map_err(lift)?;
    if matches!(wrote, Wrote::Fresh(_)) {
        tracing::info!(user_id = %caller.user_id, "invite created");
    }
    created(wrote)
}

async fn revoke(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let caller = caller(&pool, &headers).await?;
    revoke_invite(&pool, &caller, &id).await.map_err(lift)?;
    tracing::info!(user_id = %caller.user_id, invite = %id, "invite revoked");
    Ok(StatusCode::NO_CONTENT)
}

async fn audit(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Query(params): Query<AuditParams>,
) -> Result<Json<Vec<db::AuditRow>>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    let query = AuditQuery {
        limit: params.limit.unwrap_or(50),
        before: params.before,
        actor: params.actor.filter(|actor| !actor.trim().is_empty()),
        action: params.action,
    };
    list_audit(&pool, &caller, &query)
        .await
        .map(Json)
        .map_err(lift)
}
