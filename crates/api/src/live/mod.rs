//! `GET /v1/live`: one WebSocket per signed-in device. Durable events come from the outbox in
//! seq order, presence from memory. The frames are in `docs/calls.md`.

mod frame;
mod hub;
mod socket;

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{rejection::WebSocketUpgradeRejection, WebSocketUpgrade};
use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use db::{PgPool, SessionError};
use serde::Serialize;

use crate::session::bearer;
use hub::Hub;

/// Caps and timers for live sockets. `Default` is what the server runs.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// A further socket for the same person closes their oldest with `4008 replaced`.
    pub sockets_per_user: usize,
    /// A socket over this is refused with 503 before the upgrade.
    pub sockets_total: usize,
    /// The largest frame or message a client may send. Bigger closes the socket.
    pub frame_bytes: usize,
    /// No traffic from the client for this long closes the socket.
    pub idle: Duration,
    /// How often a socket re-reads its session.
    pub recheck: Duration,
    /// How long a person stays online after their last socket closes.
    pub presence_grace: Duration,
    /// A send that takes longer drops the socket.
    pub send_timeout: Duration,
    /// More missed events than this on resume gets `resync` instead.
    pub replay_max: i64,
    /// The dispatcher reads the outbox this often even without a wake.
    pub poll: Duration,
    /// Client messages a second, and the burst above that.
    pub messages_per_second: u32,
    pub message_burst: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            sockets_per_user: 3,
            sockets_total: 1024,
            frame_bytes: 64 * 1024,
            idle: Duration::from_secs(60),
            recheck: Duration::from_secs(60),
            presence_grace: Duration::from_secs(10),
            send_timeout: Duration::from_secs(10),
            replay_max: 1000,
            poll: Duration::from_secs(5),
            messages_per_second: 20,
            message_burst: 40,
        }
    }
}

/// The live socket hub. Cheap to clone.
#[derive(Clone)]
pub struct Live {
    hub: Arc<Hub>,
}

impl Live {
    /// Starts the outbox dispatcher. Call it inside a Tokio runtime.
    pub fn start(pool: PgPool, limits: Limits) -> Self {
        Self {
            hub: Hub::start(pool, limits),
        }
    }

    /// Closes every socket with `1012 restart`, refuses new ones, and stops the dispatcher.
    pub fn close(&self) {
        self.hub.close();
    }

    /// Waits until every socket and the dispatcher have stopped. False if `timeout` passed first.
    pub async fn closed(&self, timeout: Duration) -> bool {
        self.hub.closed(timeout).await
    }

    /// Sockets open now.
    pub fn sockets(&self) -> usize {
        self.hub.sockets()
    }
}

pub(crate) fn routes<S: Clone + Send + Sync + 'static>(live: Live) -> Router<S> {
    Router::new()
        .route("/v1/live", get(upgrade))
        .with_state(live)
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

fn refuse(status: StatusCode, error: &'static str) -> Response {
    (status, Json(ErrorBody { error })).into_response()
}

/// The session is checked before the upgrade, so a bad token is a plain 401.
async fn upgrade(
    State(live): State<Live>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let hub = live.hub;
    let Some(token) = bearer(&headers) else {
        return refuse(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    let identity = match db::current_session(&hub.pool, token).await {
        Ok(identity) => identity,
        Err(SessionError::Unauthorized | SessionError::InvalidCredentials) => {
            return refuse(StatusCode::UNAUTHORIZED, "unauthorized");
        }
        Err(SessionError::Database(error)) => {
            tracing::warn!(%error, "live session check failed");
            return refuse(StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
        }
    };
    let Ok(since) = parse_since(query.as_deref()) else {
        return refuse(StatusCode::BAD_REQUEST, "invalid");
    };
    let ws = match ws {
        Ok(ws) => ws,
        Err(rejection) => return rejection.into_response(),
    };
    if hub.closing() {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, "restarting");
    }
    let Some(slot) = hub.reserve() else {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, "busy");
    };
    let me = socket::Me {
        token: token.to_string(),
        user_id: identity.user_id,
        role: identity.role,
    };
    let frame = hub.limits.frame_bytes;
    ws.max_message_size(frame)
        .max_frame_size(frame)
        .on_upgrade(move |socket| socket::run(hub, socket, slot, me, since))
}

/// `since` is a seq the client already has. Other parameters are ignored.
fn parse_since(query: Option<&str>) -> Result<Option<i64>, ()> {
    let Some(query) = query else {
        return Ok(None);
    };
    let mut since = None;
    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix("since=") {
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(());
            }
            since = Some(value.parse::<i64>().map_err(|_| ())?);
        }
    }
    Ok(since)
}

#[cfg(test)]
mod tests {
    use super::parse_since;

    #[test]
    fn since_is_a_non_negative_seq() {
        assert_eq!(parse_since(None), Ok(None));
        assert_eq!(parse_since(Some("")), Ok(None));
        assert_eq!(parse_since(Some("since=0")), Ok(Some(0)));
        assert_eq!(parse_since(Some("x=1&since=42")), Ok(Some(42)));
        assert!(parse_since(Some("since=")).is_err());
        assert!(parse_since(Some("since=-1")).is_err());
        assert!(parse_since(Some("since=1e3")).is_err());
        assert!(parse_since(Some("since=99999999999999999999")).is_err());
    }
}
