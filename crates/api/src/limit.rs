//! Caps the unauthenticated posts a scanner can force through password hashing.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

const PER_KEY: usize = 5;
const GLOBAL: usize = 30;
const WINDOW: Duration = Duration::from_secs(60);

static SESSION: LazyLock<Gate> = LazyLock::new(|| Gate::new(PER_KEY, GLOBAL, WINDOW));
static ACCEPT: LazyLock<Gate> = LazyLock::new(|| Gate::new(PER_KEY, GLOBAL, WINDOW));

struct Gate {
    per_key: usize,
    global_limit: usize,
    window: Duration,
    keys: Mutex<HashMap<String, Vec<Instant>>>,
    global_hits: Mutex<Vec<Instant>>,
}

impl Gate {
    fn new(per_key: usize, global_limit: usize, window: Duration) -> Self {
        Self {
            per_key,
            global_limit,
            window,
            keys: Mutex::new(HashMap::new()),
            global_hits: Mutex::new(Vec::new()),
        }
    }

    fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut keys = lock(&self.keys);
        let mut global = lock(&self.global_hits);
        prune(&mut global, now, self.window);
        let hits = keys.entry(key.to_string()).or_default();
        prune(hits, now, self.window);
        if hits.len() >= self.per_key || global.len() >= self.global_limit {
            if hits.is_empty() {
                keys.remove(key);
            }
            return false;
        }
        hits.push(now);
        global.push(now);
        true
    }
}

#[derive(Serialize)]
struct SlowDown {
    error: &'static str,
}

pub async fn guard(request: Request<Body>, next: Next) -> Response {
    let limited = request.method() == Method::POST
        && matches!(request.uri().path(), "/v1/session" | "/v1/invites/accept");
    if limited {
        let gate = if request.uri().path() == "/v1/session" {
            &*SESSION
        } else {
            &*ACCEPT
        };
        if !gate.allow(&client_key(request.headers())) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(SlowDown { error: "slow_down" }),
            )
                .into_response();
        }
    }
    next.run(request).await
}

fn client_key(headers: &HeaderMap) -> String {
    let Some(value) = headers
        .get("cf-connecting-ip")
        .and_then(|value| value.to_str().ok())
    else {
        return "direct".to_string();
    };
    let value = value.trim();
    let shaped = value.len() <= 64
        && !value.is_empty()
        && value
            .chars()
            .all(|character| character.is_ascii_hexdigit() || character == '.' || character == ':');
    if shaped {
        value.to_string()
    } else {
        "direct".to_string()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

fn prune(hits: &mut Vec<Instant>, now: Instant, window: Duration) {
    hits.retain(|hit| now.saturating_duration_since(*hit) < window);
}

#[cfg(test)]
mod tests {
    use super::{client_key, Gate};
    use axum::http::{HeaderMap, HeaderValue};
    use std::time::Duration;

    #[test]
    fn one_address_stops_and_a_second_address_shares_the_global_cap() {
        let gate = Gate::new(2, 3, Duration::from_secs(60));
        assert!(gate.allow("a"));
        assert!(gate.allow("a"));
        assert!(!gate.allow("a"));
        assert!(gate.allow("b"));
        assert!(!gate.allow("b"));
    }

    #[test]
    fn a_client_address_is_the_cloudflare_header_or_one_shared_bucket() {
        let mut headers = HeaderMap::new();
        assert_eq!(client_key(&headers), "direct");
        headers.insert("cf-connecting-ip", HeaderValue::from_static("203.0.113.8"));
        assert_eq!(client_key(&headers), "203.0.113.8");
        headers.insert(
            "cf-connecting-ip",
            HeaderValue::from_static("not an address"),
        );
        assert_eq!(client_key(&headers), "direct");
    }
}
