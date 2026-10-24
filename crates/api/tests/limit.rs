//! Sign-in and invite acceptance limits against a real Postgres. See `common`.
//!
//! Its own binary, because the limiter is process-wide and the other tests sign in.

mod common;

use axum::http::{Method, StatusCode};
use common::{first_owner, run, Call, OWNER_EMAIL};
use serde_json::json;

#[tokio::test]
async fn a_sixth_try_in_a_minute_is_told_to_slow_down() {
    run(|db| async move {
        first_owner(&db).await;
        let app = api::router(db.runtime.clone());
        let slow_down = json!({"error": "slow_down"});

        let address = common::fresh_address();
        let login = json!({"email": OWNER_EMAIL, "password": "wrong-password-here"});
        for _ in 0..5 {
            let (status, _) = Call::new(Method::POST, "/v1/session")
                .address(&address)
                .json(login.clone())
                .send(&app)
                .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        let (status, body) = Call::new(Method::POST, "/v1/session")
            .address(&address)
            .json(login.clone())
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body, slow_down);

        let (status, _) = Call::new(Method::POST, "/v1/session")
            .json(login)
            .send(&app)
            .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "another address is not limited"
        );

        let accept = json!({
            "token": "nope",
            "email": "guest@tinyserver.test",
            "password": "short",
            "display_name": "Guest",
        });
        for _ in 0..5 {
            let (status, _) = Call::new(Method::POST, "/v1/invites/accept")
                .address(&address)
                .json(accept.clone())
                .send(&app)
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
        let (status, body) = Call::new(Method::POST, "/v1/invites/accept")
            .address(&address)
            .json(accept)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body, slow_down);
    })
    .await;
}
