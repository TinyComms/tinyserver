//! A tiny stand-in for Pocket ID's sign-up token API on a real port: `POST /api/signup-tokens`
//! with an `X-API-Key`, answered as Pocket ID v2.19 does (`201` and the token). It counts what it
//! was asked for, and can be told to fail.

use std::sync::{Arc, Mutex, MutexGuard};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use tokio::task::JoinHandle;

pub const API_KEY: &str = "test-pocket-id-static-api-key-0123456789";

/// One request the API took: the key it carried and its JSON body.
#[derive(Clone, Debug)]
pub struct Asked {
    pub api_key: Option<String>,
    pub body: Value,
}

struct Inner {
    asked: Vec<Asked>,
    /// Answer every request with this status and no token.
    fail: Option<StatusCode>,
    issued: Vec<String>,
}

pub struct PocketId {
    pub address: String,
    inner: Arc<Mutex<Inner>>,
    task: JoinHandle<()>,
}

impl Drop for PocketId {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl PocketId {
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind pocket id");
        let address = format!("http://{}", listener.local_addr().expect("address"));
        let inner = Arc::new(Mutex::new(Inner {
            asked: Vec::new(),
            fail: None,
            issued: Vec::new(),
        }));
        let app = Router::new()
            .route("/api/signup-tokens", post(signup_tokens))
            .with_state(inner.clone());
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            address,
            inner,
            task,
        }
    }

    /// Sign-up through this API, with the right key.
    pub fn signup(&self, group_ids: &[&str]) -> api::SignupConfig {
        api::SignupConfig {
            api_url: Some(self.address.clone()),
            api_key: API_KEY.to_string(),
            group_ids: group_ids.iter().map(|id| id.to_string()).collect(),
        }
    }

    pub fn asked(&self) -> Vec<Asked> {
        lock(&self.inner).asked.clone()
    }

    /// The tokens it handed out, in order.
    pub fn issued(&self) -> Vec<String> {
        lock(&self.inner).issued.clone()
    }

    pub fn fail_with(&self, status: Option<StatusCode>) {
        lock(&self.inner).fail = status;
    }
}

fn lock(inner: &Mutex<Inner>) -> MutexGuard<'_, Inner> {
    inner.lock().unwrap_or_else(|poison| poison.into_inner())
}

async fn signup_tokens(
    State(inner): State<Arc<Mutex<Inner>>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let api_key = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let body: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let mut inner = lock(&inner);
    inner.asked.push(Asked {
        api_key: api_key.clone(),
        body: body.clone(),
    });
    if api_key.as_deref() != Some(API_KEY) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Invalid API key"})),
        )
            .into_response();
    }
    if let Some(status) = inner.fail {
        return (status, Json(json!({"error": "nope"}))).into_response();
    }
    // Pocket ID's binding: usageLimit 1 to 100, ttl a positive duration up to 31 days.
    let usage_ok = body["usageLimit"]
        .as_i64()
        .is_some_and(|usage| (1..=100).contains(&usage));
    if !usage_ok || !body["ttl"].is_string() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid"}))).into_response();
    }
    let token = format!("SignupTok{:07}", inner.issued.len() + 1);
    inner.issued.push(token.clone());
    (
        StatusCode::CREATED,
        Json(json!({
            "id": format!("id-{token}"),
            "token": token,
            "expiresAt": "2026-10-28T12:15:00Z",
            "usageLimit": body["usageLimit"],
            "usageCount": 0,
            "userGroups": [],
            "createdAt": "2026-10-28T12:00:00Z",
        })),
    )
        .into_response()
}
