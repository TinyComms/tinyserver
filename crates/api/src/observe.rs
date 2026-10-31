//! One span per matched request: a random id and the route template. The URI, the query, and
//! the headers stay off the span.

use axum::extract::{MatchedPath, Request};
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

pub(crate) async fn http_span(request: Request, next: Next) -> Response {
    let req_id = request_id();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("unknown")
        .to_string();
    let span = tracing::info_span!("http", req_id = %req_id, route = %route);
    next.run(request).instrument(span).await
}

#[cfg(test)]
mod tests {
    use super::request_id;

    #[test]
    fn request_id_is_32_hex_characters() {
        let id = request_id();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|character| character.is_ascii_hexdigit()));
    }
}
