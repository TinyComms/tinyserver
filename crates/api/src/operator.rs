//! Obeys the operator's suspension (`db::operator_state`) on every route.
//!
//! * `offline`: only `GET /health` and `GET /v1/status` answer. Everything else, the live
//!   socket included, is `503 {"error":"suspended"}` with the notice.
//! * `read_only`: reads go through. Of the writes, only signing in and out, deleting one's own
//!   account and filing an abuse report do; the rest are `503 {"error":"read_only"}`.
//!
//! The state is read from the database at most every `TINYSERVER_OPERATOR_REFRESH_MS`
//! (2000 by default, `0` for every request), so a change reaches every request within that.
//! When it cannot be read the last state read is kept; before the first read that is `normal`.
//! The serving process cannot change it: its role may only read the row.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::Request;
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use db::{Mode, OperatorState, PgPool};
use serde::Serialize;

const DEFAULT_REFRESH: Duration = Duration::from_millis(2000);

#[derive(Clone)]
pub struct Operator {
    pool: PgPool,
    refresh: Duration,
    cached: Arc<Mutex<Cached>>,
}

struct Cached {
    read_at: Option<Instant>,
    state: Arc<OperatorState>,
}

impl Operator {
    pub fn new(pool: PgPool) -> Self {
        let refresh = std::env::var("TINYSERVER_OPERATOR_REFRESH_MS")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .map_or(DEFAULT_REFRESH, |ms| Duration::from_millis(ms.min(60_000)));
        Self {
            pool,
            refresh,
            cached: Arc::new(Mutex::new(Cached {
                read_at: None,
                state: Arc::new(OperatorState::normal()),
            })),
        }
    }

    /// The state, read again when the last read is older than the refresh period.
    pub async fn current(&self) -> Arc<OperatorState> {
        {
            let cached = self.lock();
            if cached
                .read_at
                .is_some_and(|at| at.elapsed() < self.refresh && !self.refresh.is_zero())
            {
                return Arc::clone(&cached.state);
            }
        }
        match db::operator_state(&self.pool).await {
            Ok(state) => {
                let state = Arc::new(state);
                let mut cached = self.lock();
                cached.read_at = Some(Instant::now());
                cached.state = Arc::clone(&state);
                state
            }
            Err(error) => {
                tracing::warn!(%error, "operator state not read; keeping the last one");
                Arc::clone(&self.lock().state)
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Cached> {
        self.cached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[derive(Serialize)]
struct Status<'a> {
    mode: &'static str,
    notice: Option<&'a str>,
    since: Option<&'a str>,
}

#[derive(Serialize)]
struct Refused<'a> {
    error: &'static str,
    mode: &'static str,
    notice: Option<&'a str>,
}

pub fn routes() -> Router<PgPool> {
    Router::new().route("/v1/status", get(status))
}

/// What the community is doing now, for members and for a client before it signs in. No
/// session needed: the notice is meant for everyone who reaches the server. A hold is not here.
async fn status(Extension(operator): Extension<Operator>) -> Response {
    let state = operator.current().await;
    Json(Status {
        mode: state.mode.as_str(),
        notice: state.notice.as_deref(),
        since: (state.mode != Mode::Normal && !state.since.is_empty())
            .then_some(state.since.as_str()),
    })
    .into_response()
}

pub async fn gate(
    Extension(operator): Extension<Operator>,
    request: Request,
    next: Next,
) -> Response {
    let state = operator.current().await;
    let allowed = match state.mode {
        Mode::Normal => true,
        Mode::ReadOnly => read_only_allows(request.method(), request.uri().path()),
        Mode::Offline => always_open(request.method(), request.uri().path()),
    };
    if allowed {
        return next.run(request).await;
    }
    let error = if state.mode == Mode::Offline {
        "suspended"
    } else {
        "read_only"
    };
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(Refused {
            error,
            mode: state.mode.as_str(),
            notice: state.notice.as_deref(),
        }),
    )
        .into_response()
}

fn always_open(method: &Method, path: &str) -> bool {
    matches!(*method, Method::GET | Method::HEAD) && matches!(path, "/health" | "/v1/status")
}

fn read_only_allows(method: &Method, path: &str) -> bool {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return true;
    }
    match *method {
        // Signing in, and the provider's back-channel logout.
        Method::POST => path.starts_with("/v1/auth/") || path == "/v1/reports",
        // Signing out here or everywhere, and deleting one's own account.
        Method::DELETE => matches!(path, "/v1/session" | "/v1/sessions" | "/v1/me"),
        _ => false,
    }
}

/// What the live socket refuses while read-only: anything that writes or speaks.
pub(crate) fn read_only_frame_allowed(kind: &str) -> bool {
    matches!(
        kind,
        "ping" | "call.leave" | "call.state" | "call.quality" | "call.e2ee"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_leaves_only_health_and_status() {
        assert!(always_open(&Method::GET, "/health"));
        assert!(always_open(&Method::GET, "/v1/status"));
        assert!(!always_open(&Method::POST, "/v1/status"));
        assert!(!always_open(&Method::GET, "/v1/live"));
        assert!(!always_open(&Method::GET, "/v1/me"));
        assert!(!always_open(&Method::POST, "/v1/auth/start"));
    }

    #[test]
    fn read_only_lets_reads_sign_in_out_reports_and_deletion_through() {
        assert!(read_only_allows(&Method::GET, "/v1/channels"));
        assert!(read_only_allows(&Method::GET, "/v1/live"));
        assert!(read_only_allows(&Method::POST, "/v1/auth/start"));
        assert!(read_only_allows(&Method::POST, "/v1/auth/token"));
        assert!(read_only_allows(&Method::POST, "/v1/reports"));
        assert!(read_only_allows(&Method::DELETE, "/v1/session"));
        assert!(read_only_allows(&Method::DELETE, "/v1/sessions"));
        assert!(read_only_allows(&Method::DELETE, "/v1/me"));
        assert!(!read_only_allows(&Method::PATCH, "/v1/reports/x"));
        assert!(!read_only_allows(&Method::POST, "/v1/media"));
        assert!(!read_only_allows(&Method::POST, "/v1/channels"));
        assert!(!read_only_allows(&Method::PATCH, "/v1/me"));
        assert!(!read_only_allows(&Method::POST, "/v1/invites"));
        assert!(!read_only_allows(&Method::PUT, "/v1/layout"));
        assert!(!read_only_allows(&Method::DELETE, "/v1/rooms/x"));
    }

    #[test]
    fn read_only_live_frames() {
        assert!(read_only_frame_allowed("ping"));
        assert!(read_only_frame_allowed("call.leave"));
        assert!(!read_only_frame_allowed("call.join"));
        assert!(!read_only_frame_allowed("call.offer"));
        assert!(!read_only_frame_allowed("typing"));
        assert!(!read_only_frame_allowed("call.kick"));
    }
}
