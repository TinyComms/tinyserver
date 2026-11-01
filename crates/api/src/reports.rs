//! Abuse reports: `POST /v1/reports`, `GET /v1/reports`, `GET /v1/reports/{id}`,
//! `PATCH /v1/reports/{id}`. See `docs/privacy/abuse-response.md` for what they are for and what
//! they do not do.
//!
//! No handler here logs a note, evidence, a moderator's note or who a report is about. Filing a
//! report logs its kind and nothing that names the reporter. The 8 KiB JSON limit the rest of the
//! API has is raised for filing only, to leave room for evidence.

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use db::{
    file_report, get_report, list_reports, update_report, NewReport, PgPool, ReportDetail,
    ReportError, ReportPatch, ReportQuery, ReportSummary,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::community::{caller, lift, ApiError};

/// Evidence is 32 KiB of text at most; JSON escaping can double it, and the rest is small.
const BODY_LIMIT: usize = 80 * 1024;

pub fn routes() -> Router<PgPool> {
    Router::new()
        .route(
            "/v1/reports",
            get(list)
                .post(file)
                .layer(DefaultBodyLimit::max(BODY_LIMIT)),
        )
        .route("/v1/reports/{id}", get(read).patch(work))
}

/// `slow_down` is this route's own answer, the one the sign-in routes already use.
enum Failure {
    SlowDown,
    Api(ApiError),
}

impl From<ApiError> for Failure {
    fn from(error: ApiError) -> Self {
        Self::Api(error)
    }
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        match self {
            Self::SlowDown => (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error": "slow_down"})),
            )
                .into_response(),
            Self::Api(error) => error.into_response(),
        }
    }
}

fn failure(error: ReportError) -> Failure {
    match error {
        ReportError::RateLimited => Failure::SlowDown,
        ReportError::TooLarge => ApiError::TooLarge.into(),
        ReportError::Community(error) => lift(error).into(),
    }
}

#[derive(Deserialize)]
struct FileBody {
    kind: String,
    target_id: String,
    category: String,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    evidence: Option<String>,
}

/// Any member can file. The answer names no one: not the person reported, not a moderator.
async fn file(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(body): Json<FileBody>,
) -> Result<(StatusCode, Json<Value>), Failure> {
    let caller = caller(&pool, &headers).await?;
    let input = NewReport {
        kind: body.kind,
        target_id: body.target_id,
        category: body.category,
        note: body.note,
        evidence: body.evidence,
    };
    let filed = file_report(&pool, &caller, &input).await.map_err(failure)?;
    if !filed.duplicate {
        // The kind only. Not who filed it, not who it is about, not what it says.
        tracing::info!(kind = %filed.kind, "report filed");
    }
    let status = if filed.duplicate {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((status, Json(json!(filed))))
}

#[derive(Deserialize)]
struct ListQuery {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    before: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
}

async fn list(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<ReportSummary>>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    let query = ReportQuery {
        status: query.status,
        kind: query.kind,
        before: query.before,
        limit: query.limit.unwrap_or(50),
    };
    list_reports(&pool, &caller, &query)
        .await
        .map(Json)
        .map_err(lift)
}

async fn read(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ReportDetail>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    get_report(&pool, &caller, &id)
        .await
        .map(Json)
        .map_err(lift)
}

#[derive(Deserialize)]
struct WorkBody {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    link_audit_id: Option<i64>,
    #[serde(default)]
    preserve: Option<bool>,
}

async fn work(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<WorkBody>,
) -> Result<Json<ReportDetail>, Failure> {
    let caller = caller(&pool, &headers).await?;
    let patch = ReportPatch {
        status: body.status,
        note: body.note,
        link_audit_id: body.link_audit_id,
        preserve: body.preserve,
    };
    let updated = update_report(&pool, &caller, &id, &patch)
        .await
        .map_err(failure)?;
    // The moderator and the report id. Not the target, and not a word of what was written.
    tracing::info!(user_id = %caller.user_id, report_id = %id, "report worked");
    Ok(Json(updated))
}
