//! Sign-in limits against a real Postgres and the fake provider. See `common`.
//!
//! Its own binary, because the limiter is process-wide and the other tests sign in.

mod common;

use axum::http::{Method, StatusCode};
use common::oidc::Provider;
use common::{run, Call};
use serde_json::json;

#[tokio::test]
async fn a_sixth_try_in_a_minute_is_told_to_slow_down() {
    run(|db| async move {
        let provider = Provider::start().await;
        let app = api::router(db.runtime.clone(), Some(provider.sign_in().await));
        let slow_down = json!({"error": "slow_down"});
        let address = common::fresh_address();

        let start = json!({
            "redirect_uri": "http://127.0.0.1:53121/callback",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
            "state": "client-state-0123456789",
        });
        for _ in 0..5 {
            let (status, _) = Call::new(Method::POST, "/v1/auth/start")
                .address(&address)
                .json(start.clone())
                .send(&app)
                .await;
            assert_eq!(status, StatusCode::OK);
        }
        let (status, body) = Call::new(Method::POST, "/v1/auth/start")
            .address(&address)
            .json(start.clone())
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body, slow_down);
        let (status, _) = Call::new(Method::POST, "/v1/auth/start")
            .json(start)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "another address is not limited");

        let token = json!({"code": "nope", "code_verifier": "v".repeat(43)});
        for _ in 0..5 {
            let (status, _) = Call::new(Method::POST, "/v1/auth/token")
                .address(&address)
                .json(token.clone())
                .send(&app)
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
        let (status, body) = Call::new(Method::POST, "/v1/auth/token")
            .address(&address)
            .json(token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body, slow_down);
    })
    .await;
}
