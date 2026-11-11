//! One span per matched request: a random id and the route template. The URI, the query, and
//! the headers stay off the span. A request that runs over a second logs one line (see `http_span`).

use std::future::Future;
use std::time::{Duration, Instant};

use axum::extract::{MatchedPath, Request};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::Response;
use tracing::Instrument;

/// 16 random bytes, hex. A failed read still returns 32 hex characters from the clock.
pub(crate) fn request_id() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::fill(&mut bytes).is_err() {
        let tick = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        bytes[..8].copy_from_slice(&tick.to_le_bytes());
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(32);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

/// A request that writes a chat message, an edit, a reaction or an upload.
fn is_send(method: &Method, route: &str) -> bool {
    method != Method::GET
        && !route.starts_with("/v1/e2ee/links")
        && (route == "/v1/media"
            || route.ends_with("/messages")
            || route.starts_with("/v1/messages/")
            || route.ends_with("/reactions"))
}

/// A request that runs longer than this is logged: a send as a `warn`, any other as a `debug`.
const SLOW: Duration = Duration::from_millis(1000);

/// The span of one request. When the request ends, a slow one says so: the route template, the
/// status, and how long it ran, split into time spent on the CPU (`busy_ms`) and time spent
/// waiting on the database, a lock or the network (`idle_ms`). A send over a second is a `warn`,
/// so it shows at the default level; any other slow request is a `debug`. A fast request logs
/// nothing. No user id, no URI, no query, no header and no body is on the line.
pub(crate) async fn http_span(request: Request, next: Next) -> Response {
    let req_id = request_id();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("unknown")
        .to_string();
    let send = is_send(request.method(), &route);
    let span = tracing::info_span!("http", req_id = %req_id, route = %route);
    let started = Instant::now();
    let mut busy = Duration::ZERO;
    let future = next.run(request).instrument(span);
    tokio::pin!(future);
    let response = std::future::poll_fn(|context| {
        let polled = Instant::now();
        let ready = future.as_mut().poll(context);
        busy += polled.elapsed();
        ready
    })
    .await;
    let total = started.elapsed();
    if total >= SLOW {
        let status = response.status().as_u16();
        let ms = total.as_millis();
        let busy_ms = busy.as_millis();
        let idle_ms = ms.saturating_sub(busy_ms);
        if send {
            tracing::warn!(%route, status, ms, busy_ms, idle_ms, "slow send");
        } else {
            tracing::debug!(%route, status, ms, busy_ms, idle_ms, "slow request");
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::{is_send, request_id};
    use axum::http::Method;

    #[test]
    fn only_writes_to_messages_reactions_and_uploads_are_sends() {
        assert!(is_send(&Method::POST, "/v1/conversations/{id}/messages"));
        assert!(is_send(&Method::PATCH, "/v1/messages/{id}"));
        assert!(is_send(&Method::PUT, "/v1/messages/{id}/reactions"));
        assert!(is_send(&Method::POST, "/v1/media"));
        assert!(!is_send(&Method::GET, "/v1/conversations/{id}/messages"));
        assert!(!is_send(&Method::POST, "/v1/e2ee/links/{id}/messages"));
        assert!(!is_send(&Method::POST, "/v1/channels"));
    }

    #[test]
    fn request_id_is_32_hex_characters() {
        let id = request_id();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|character| character.is_ascii_hexdigit()));
    }
}
