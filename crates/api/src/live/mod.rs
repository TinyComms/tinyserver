//! `GET /v1/live`: one WebSocket per signed-in device, or per bot token. Durable events come
//! from the outbox in seq order, presence, call occupancy, and call signaling from memory. The
//! frames are in `docs/calls.md`. A bot is not a member. It receives room events when it has
//! `rooms.read` and member events when it has `members.read`.

mod call;
mod e2ee;
pub(crate) mod frame;
mod group_call;
mod hub;
mod presence;
mod ring;
mod socket;

use std::collections::HashSet;
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

use crate::session::{presented, Presented};
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
    /// How long a socket holding a call seat has to answer a ping when the same session opens
    /// another. No answer moves the seat to the new socket.
    pub seat_proof: Duration,
    /// A send that takes longer drops the socket.
    pub send_timeout: Duration,
    /// More missed events than this on resume gets `resync` instead.
    pub replay_max: i64,
    /// The dispatcher reads the outbox this often even without a wake.
    pub poll: Duration,
    /// Client messages a second, and the burst above that.
    pub messages_per_second: u32,
    pub message_burst: u32,
    /// Optional operator ceiling on people in one room's call. `None` means no fixed room
    /// cap (a room's own `user_limit` still applies). A join past it gets `room_full`.
    pub call_room_max: Option<usize>,
    /// Optional operator ceiling on people in calls on the server. `None` means admission is
    /// bounded by measured capacity (egress budget and media thread load). A join past it
    /// gets `server_full`.
    pub call_server_max: Option<usize>,
    /// Server upload budget for calls, in kb/s. `None` means no upload budget.
    pub call_egress_kbps: Option<u32>,
    /// Receive audio slots per listener (default 11), used to project audio egress.
    pub call_audio_slots: usize,
    /// Joins and leaves one socket may make at once, and how often it gets one more back.
    pub call_move_burst: u32,
    pub call_move_every: Duration,
    /// `call.watch` updates one socket may send at once, and how often it gets one more back.
    pub call_watch_burst: u32,
    pub call_watch_every: Duration,
    /// How often who was connected is written to `last_seen_at`, in one batch.
    pub seen_every: Duration,
    /// End-to-end encryption key packages and `invalid`s one socket may send at once, and how
    /// often it gets one more back.
    pub e2ee_rekey_burst: u32,
    pub e2ee_rekey_every: Duration,
    /// `presence.set` frames one socket may send at once, and how often it gets one more back.
    pub presence_burst: u32,
    pub presence_every: Duration,
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
            seat_proof: Duration::from_secs(3),
            send_timeout: Duration::from_secs(10),
            replay_max: 1000,
            poll: Duration::from_secs(5),
            messages_per_second: 20,
            message_burst: 40,
            call_room_max: None,
            call_server_max: None,
            call_egress_kbps: None,
            call_audio_slots: 11,
            call_move_burst: 5,
            call_move_every: Duration::from_secs(3),
            call_watch_burst: 20,
            call_watch_every: Duration::from_millis(200),
            seen_every: Duration::from_secs(30),
            e2ee_rekey_burst: 5,
            e2ee_rekey_every: Duration::from_secs(2),
            presence_burst: 5,
            presence_every: Duration::from_secs(2),
        }
    }
}

/// The live socket hub. Cheap to clone.
#[derive(Clone)]
pub struct Live {
    hub: Arc<Hub>,
}

impl Live {
    /// Starts the outbox dispatcher, without media. A join with an offer gets
    /// `media_unavailable`. Call it inside a Tokio runtime.
    pub fn start(pool: PgPool, limits: Limits) -> Self {
        Self {
            hub: Hub::start(pool, limits, None),
        }
    }

    /// Starts the outbox dispatcher and follows the SFU from `sfu::start`.
    pub fn with_media(
        pool: PgPool,
        limits: Limits,
        media: sfu::Media,
        events: tokio::sync::mpsc::Receiver<sfu::Event>,
    ) -> Self {
        Self {
            hub: Hub::start(pool, limits, Some((media, events))),
        }
    }

    /// `off` without an SFU, `up` while it runs, `down` once it stopped.
    pub fn media(&self) -> &'static str {
        self.hub.media_status()
    }

    /// The SFU stopped by itself. Calls cannot start again until the process does.
    pub fn media_failed(&self) -> bool {
        self.hub.media_failed()
    }

    /// The media transports up now. Empty without an SFU or once it stopped.
    pub fn transports(&self) -> Vec<&'static str> {
        self.hub
            .media
            .as_ref()
            .map(sfu::Media::transports)
            .unwrap_or_default()
    }

    /// Maximum receive video slots per listener when media is configured.
    pub fn video_slots(&self) -> Option<usize> {
        self.hub.media.as_ref().map(sfu::Media::video_slots)
    }

    /// Closes every socket with `1012 restart`, refuses new ones, and stops the dispatcher
    /// and the SFU.
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
/// `Authorization: Bot <token>` opens the same socket when the bot token is live.
async fn upgrade(
    State(live): State<Live>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let hub = live.hub;
    let me = match presented(&headers) {
        Some(Presented::Bearer(token)) => {
            let identity = match db::current_session(&hub.pool, token).await {
                Ok(identity) => identity,
                Err(error) => return session_unavailable(error),
            };
            socket::Me {
                token: token.to_string(),
                session: call::session_of(token),
                user_id: identity.user_id,
                role: identity.role,
                permissions: identity.permissions,
                scopes: Vec::new(),
            }
        }
        Some(Presented::Bot(token)) => {
            let bot = match db::authenticate_bot(&hub.pool, token).await {
                Ok(bot) => bot,
                Err(error) => return session_unavailable(error),
            };
            socket::Me {
                token: token.to_string(),
                session: call::session_of(token),
                user_id: bot.id,
                role: "bot".to_string(),
                permissions: 0,
                scopes: bot.scopes,
            }
        }
        None => return live_refused("unauthorized"),
    };
    let Ok(since) = parse_since(query.as_deref()) else {
        return live_refused("invalid");
    };
    let features = parse_features(query.as_deref());
    let ws = match ws {
        Ok(ws) => ws,
        Err(rejection) => {
            tracing::warn!(reason = "invalid", "live refused");
            return rejection.into_response();
        }
    };
    if hub.closing() {
        return live_refused("restarting");
    }
    if tokio::time::timeout(Duration::from_secs(5), hub.ready())
        .await
        .is_err()
    {
        return live_refused("unavailable");
    }
    let Some(slot) = hub.reserve() else {
        return live_refused("busy");
    };
    let frame = hub.limits.frame_bytes;
    ws.max_message_size(frame)
        .max_frame_size(frame)
        .on_upgrade(move |socket| socket::run(hub, socket, slot, me, since, features))
}

fn live_refused(reason: &'static str) -> Response {
    tracing::warn!(reason, "live refused");
    let status = match reason {
        "unauthorized" => StatusCode::UNAUTHORIZED,
        "invalid" => StatusCode::BAD_REQUEST,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };
    refuse(status, reason)
}

fn session_unavailable(error: SessionError) -> Response {
    match error {
        SessionError::Unauthorized => live_refused("unauthorized"),
        SessionError::Database(error) => {
            tracing::warn!(%error, "live session check failed");
            refuse(StatusCode::INTERNAL_SERVER_ERROR, "unavailable")
        }
    }
}

/// Known live-socket feature names an app may declare via `?features=...`.
const LIVE_FEATURES: &[&str] = &["group_calls"];
const MAX_FEATURES: usize = 16;
const MAX_FEATURE_LEN: usize = 32;

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

/// Comma-separated lower-case live feature names from `?features=...`.
/// Unknown or malformed values are ignored, never a refusal. At most 16 names of at most 32 bytes.
fn parse_features(query: Option<&str>) -> HashSet<String> {
    let mut out = HashSet::new();
    let Some(query) = query else {
        return out;
    };
    let mut seen = 0usize;
    for pair in query.split('&') {
        let Some(value) = pair.strip_prefix("features=") else {
            continue;
        };
        for name in value.split(',') {
            if seen >= MAX_FEATURES {
                return out;
            }
            seen += 1;
            if name.is_empty()
                || name.len() > MAX_FEATURE_LEN
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            {
                continue;
            }
            if LIVE_FEATURES.contains(&name) {
                out.insert(name.to_string());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{parse_features, parse_since};

    #[test]
    fn since_is_a_non_negative_seq() {
        assert_eq!(parse_since(None), Ok(None));
        assert_eq!(parse_since(Some("")), Ok(None));
        assert_eq!(parse_since(Some("since=0")), Ok(Some(0)));
        assert_eq!(parse_since(Some("x=1&since=42")), Ok(Some(42)));
        assert_eq!(
            parse_since(Some("since=42&features=group_calls")),
            Ok(Some(42))
        );
        assert!(parse_since(Some("since=")).is_err());
        assert!(parse_since(Some("since=-1")).is_err());
        assert!(parse_since(Some("since=1e3")).is_err());
        assert!(parse_since(Some("since=99999999999999999999")).is_err());
    }

    #[test]
    fn features_parses_known_names_and_ignores_the_rest() {
        assert!(parse_features(None).is_empty());
        assert!(parse_features(Some("")).is_empty());
        assert!(parse_features(Some("features=")).is_empty());
        assert!(parse_features(Some("since=10")).is_empty());

        let one = parse_features(Some("features=group_calls"));
        assert_eq!(one.len(), 1);
        assert!(one.contains("group_calls"));

        let with_since = parse_features(Some(
            "since=99&features=unknown_one,group_calls,GROUP_CALLS",
        ));
        assert_eq!(with_since.len(), 1);
        assert!(with_since.contains("group_calls"));

        // Over the 16-item cap: the 17th entry is ignored even if it is known.
        let sixteen_unknown = vec!["x"; 16].join(",");
        let over_cap = format!("features={sixteen_unknown},group_calls");
        assert!(parse_features(Some(&over_cap)).is_empty());

        // Over 32 bytes is ignored.
        let too_long = "a".repeat(33);
        assert!(parse_features(Some(&format!("features={too_long}"))).is_empty());
    }
}
