//! The Cloudflare Realtime TURN credentials API: short-lived TURN credentials for one
//! participant's allocation, minted at `call.join` and revoked when they leave. The SFU's
//! RFC 5766 client (`sfu::turn`) authenticates its allocation with the username and
//! credential from here; the URLs name what Cloudflare relays.
//!
//! Relay mode is opt-in per host: without the key id and the API token nothing here is
//! called, and the SFU advertises its own addresses as always.
//!
//! The live socket and the SFU wire this in with the relay slice's next step; until then
//! only the tests here construct it.

#![allow(dead_code)]

use std::time::Duration;

use reqwest::Client;
use serde_json::json;

/// The relay mode's settings. `server/src/main.rs` builds it from
/// `TINYSERVER_TURN_KEY_ID` and `TINYSERVER_TURN_API_TOKEN_FILE`; without both, relay mode
/// is off and the SFU advertises its own addresses as always. The base URL is the API root,
/// oversteerable for tests.
#[derive(Debug, Clone)]
pub(crate) struct TurnConfig {
    pub key_id: String,
    pub token: String,
    pub base: String,
}

/// One participant's TURN credentials, as the SFU's RFC 5766 client consumes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IceServers {
    pub urls: Vec<String>,
    pub username: String,
    pub credential: String,
}

#[derive(Debug)]
pub(crate) enum TurnApiError {
    /// The API answered, but not with success.
    Status(reqwest::StatusCode),
    /// The API could not be reached or its answer was not JSON.
    Transport(reqwest::Error),
    /// The answer had no usable credentials.
    Shape,
}

/// The client for one host's TURN key. Cheap to clone.
#[derive(Clone)]
pub(crate) struct TurnApi {
    client: Client,
    base: String,
    key_id: String,
    token: String,
}

impl TurnApi {
    pub fn new(config: TurnConfig) -> Self {
        Self {
            client: Client::new(),
            base: config.base,
            key_id: config.key_id,
            token: config.token,
        }
    }

    /// Mints one participant's credentials. The TTL is the call length this host expects;
    /// the credentials are revoked when the participant leaves, or expire.
    pub async fn generate(&self, ttl: Duration) -> Result<IceServers, TurnApiError> {
        let url = format!(
            "{}/turn/keys/{}/credentials/generate-ice-servers",
            self.base, self.key_id
        );
        let response = self
            .client
            .post(url)
            .bearer_auth(&self.token)
            .json(&json!({"ttl": ttl.as_secs()}))
            .send()
            .await
            .map_err(TurnApiError::Transport)?;
        if !response.status().is_success() {
            return Err(TurnApiError::Status(response.status()));
        }
        let value: serde_json::Value = response.json().await.map_err(TurnApiError::Transport)?;
        // Cloudflare has shipped two shapes: `iceServers` as one object and as an array. The
        // entry with a username and a credential is the one the allocation authenticates
        // with.
        let entries = match value.get("iceServers") {
            Some(serde_json::Value::Array(list)) => list.clone(),
            Some(entry @ serde_json::Value::Object(_)) => vec![entry.clone()],
            _ => return Err(TurnApiError::Shape),
        };
        let entry = entries
            .iter()
            .find(|entry| {
                !entry
                    .get("username")
                    .and_then(|value| value.as_str())
                    .unwrap_or("")
                    .is_empty()
                    && !entry
                        .get("credential")
                        .and_then(|value| value.as_str())
                        .unwrap_or("")
                        .is_empty()
            })
            .ok_or(TurnApiError::Shape)?;
        let urls = entry
            .get("urls")
            .and_then(|value| value.as_array())
            .map(|list| {
                list.iter()
                    .filter_map(|value| value.as_str().map(str::to_owned))
                    .collect::<Vec<_>>()
            })
            .ok_or(TurnApiError::Shape)?;
        if urls.is_empty() {
            return Err(TurnApiError::Shape);
        }
        let username = entry
            .get("username")
            .and_then(|value| value.as_str())
            .ok_or(TurnApiError::Shape)?
            .to_owned();
        let credential = entry
            .get("credential")
            .and_then(|value| value.as_str())
            .ok_or(TurnApiError::Shape)?
            .to_owned();
        Ok(IceServers {
            urls,
            username,
            credential,
        })
    }

    /// Revokes a participant's credentials before their TTL runs out. A missing credential
    /// is fine: revoking is the tidying up after a call, not a promise.
    pub async fn revoke(&self, username: &str) -> Result<(), TurnApiError> {
        let url = format!(
            "{}/turn/keys/{}/credentials/{}/revoke",
            self.base, self.key_id, username
        );
        let response = self
            .client
            .post(url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(TurnApiError::Transport)?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(TurnApiError::Status(response.status()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{header, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::json;
    use std::net::{IpAddr, Ipv4Addr};

    /// A fake Cloudflare that checks the bearer token and answers both response shapes.
    async fn spawn_fake(shape: &'static str) -> String {
        async fn revoke() -> Response {
            StatusCode::NO_CONTENT.into_response()
        }
        let listener = tokio::net::TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind");
        let base = format!(
            "http://127.0.0.1:{}",
            listener.local_addr().expect("addr").port()
        );
        let app =
            Router::new()
                .route(
                    "/turn/keys/the-key/credentials/generate-ice-servers",
                    post(
                        move |headers: axum::http::HeaderMap,
                              body: Option<Json<serde_json::Value>>| async move {
                            if headers
                                .get(header::AUTHORIZATION)
                                .and_then(|value| value.to_str().ok())
                                != Some("Bearer the-token")
                            {
                                return StatusCode::UNAUTHORIZED.into_response();
                            }
                            if body
                                .as_ref()
                                .and_then(|Json(body)| body.get("ttl"))
                                .is_none()
                            {
                                return StatusCode::BAD_REQUEST.into_response();
                            }
                            let ice_servers = match shape {
                                "object" => json!({
                                    "urls": ["turn:turn.cloudflare.com:3478?transport=udp"],
                                    "username": "the-username",
                                    "credential": "the-credential"
                                }),
                                _ => json!([{
                                    "urls": ["turn:turn.cloudflare.com:3478?transport=udp"],
                                    "username": "the-username",
                                    "credential": "the-credential"
                                }]),
                            };
                            (
                                StatusCode::CREATED,
                                Json(json!({ "iceServers": ice_servers })),
                            )
                                .into_response()
                        },
                    ),
                )
                .route(
                    "/turn/keys/the-key/credentials/the-username/revoke",
                    post(revoke),
                );
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        base
    }

    fn api(base: &str) -> TurnApi {
        TurnApi::new(TurnConfig {
            key_id: "the-key".into(),
            token: "the-token".into(),
            base: base.to_owned(),
        })
    }

    #[tokio::test]
    async fn generate_normalizes_the_object_shape() {
        let base = spawn_fake("object").await;
        let ice = api(&base)
            .generate(Duration::from_secs(4 * 3600))
            .await
            .expect("the credentials");
        assert_eq!(ice.username, "the-username");
        assert_eq!(ice.credential, "the-credential");
        assert_eq!(
            ice.urls,
            vec!["turn:turn.cloudflare.com:3478?transport=udp"]
        );
    }

    #[tokio::test]
    async fn generate_normalizes_the_array_shape() {
        let base = spawn_fake("array").await;
        let ice = api(&base)
            .generate(Duration::from_secs(600))
            .await
            .expect("the credentials");
        assert_eq!(ice.username, "the-username");
        assert_eq!(ice.credential, "the-credential");
    }

    #[tokio::test]
    async fn a_wrong_token_is_a_status_error() {
        let base = spawn_fake("object").await;
        let wrong = TurnApi::new(TurnConfig {
            key_id: "the-key".into(),
            token: "wrong".into(),
            base: base.to_owned(),
        });
        match wrong.generate(Duration::from_secs(600)).await {
            Err(TurnApiError::Status(status)) => {
                assert_eq!(status, StatusCode::UNAUTHORIZED)
            }
            other => panic!("not a status error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn revoke_answers_204_and_is_ok() {
        let base = spawn_fake("object").await;
        api(&base).revoke("the-username").await.expect("revoked");
    }
}
