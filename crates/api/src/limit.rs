//! Caps the sign-in posts one client can make: each `start` stores a pending sign-in, each
//! `token` tries a one-time code, and each `join` may ask the provider for a sign-up link.

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
/// No password hashing sits behind these any more, so the shared cap is looser than the
/// per-address one: a pending sign-in is one small row, and a code try is one indexed delete.
const GLOBAL: usize = 120;
const WINDOW: Duration = Duration::from_secs(60);

static START: LazyLock<Gate> = LazyLock::new(|| Gate::new(PER_KEY, GLOBAL, WINDOW));
static TOKEN: LazyLock<Gate> = LazyLock::new(|| Gate::new(PER_KEY, GLOBAL, WINDOW));
/// Tighter: each try that gets through may make a sign-up link at the provider.
static JOIN: LazyLock<Gate> = LazyLock::new(|| Gate::new(JOIN_PER_KEY, JOIN_GLOBAL, WINDOW));
const JOIN_PER_KEY: usize = 3;
const JOIN_GLOBAL: usize = 30;

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
        // Allowed hits are capped by the global limit, so this walk stays small.
        keys.retain(|_, hits| {
            prune(hits, now, self.window);
            !hits.is_empty()
        });
        let used = keys.get(key).map_or(0, Vec::len);
        if used >= self.per_key || global.len() >= self.global_limit {
            return false;
        }
        keys.entry(key.to_string()).or_default().push(now);
        global.push(now);
        true
    }
}

#[derive(Serialize)]
struct SlowDown {
    error: &'static str,
}

pub async fn guard(request: Request<Body>, next: Next) -> Response {
    let gate = match (request.method(), request.uri().path()) {
        (&Method::POST, "/v1/auth/start") => Some(&*START),
        (&Method::POST, "/v1/auth/token") => Some(&*TOKEN),
        (&Method::POST, "/v1/auth/join") => Some(&*JOIN),
        _ => None,
    };
    if let Some(gate) = gate {
        if !gate.allow(&client_key(request.headers())) {
            if request.uri().path() == "/v1/auth/join" {
                return crate::auth::slow_down_page();
            }
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
    use super::{client_key, lock, Gate};
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
    fn an_address_whose_hits_aged_out_is_forgotten() {
        let gate = Gate::new(2, 30, Duration::from_millis(20));
        assert!(gate.allow("a"));
        assert!(gate.allow("b"));
        std::thread::sleep(Duration::from_millis(40));
        assert!(gate.allow("c"));
        assert_eq!(lock(&gate.keys).len(), 1);
    }

    #[test]
    fn a_denied_address_leaves_no_entry() {
        let gate = Gate::new(1, 1, Duration::from_secs(60));
        assert!(gate.allow("a"));
        assert!(!gate.allow("b"));
        assert_eq!(lock(&gate.keys).len(), 1);
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
