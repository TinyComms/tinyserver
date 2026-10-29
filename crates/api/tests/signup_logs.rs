//! Pocket ID sign-up never puts its API key or a sign-up token in the logs. Alone in its own test
//! binary, so it can hold the one global log subscriber and see every line at every level.

mod common;

use std::sync::{Arc, Mutex, MutexGuard};

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use common::oidc::{self, Provider};
use common::pocket::{self, PocketId};
use common::{first_owner, run, Call};
use http_body_util::BodyExt;
use openidconnect::{CsrfToken, PkceCodeChallenge};
use serde_json::json;
use tower::ServiceExt;

/// What the subscriber wrote.
#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl Logs {
    fn lock(&self) -> MutexGuard<'_, Vec<u8>> {
        self.0.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.lock()).into_owned()
    }
}

impl std::io::Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.lock().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

async fn post_join(app: &Router, state: &str, address: &str) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/auth/join")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("cf-connecting-ip", address)
                .body(Body::from(format!("state={state}")))
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn the_api_key_and_signup_tokens_never_reach_the_logs() {
    let logs = Logs::default();
    let writer = logs.clone();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .init();

    let issued: Arc<Mutex<Vec<String>>> = Arc::default();
    let seen = issued.clone();
    run(|db| async move {
        let owner = first_owner(&db).await;
        let provider = Provider::start().await;
        let pocket = PocketId::start().await;
        let mut config = provider.provider_config("default");
        config.signup = Some(pocket.signup(&[]));
        let debug = format!("{config:?}");
        assert!(!debug.contains(pocket::API_KEY), "{debug}");
        let sign_in = api::SignIn::discover(oidc::config(vec![config]))
            .await
            .expect("discover");
        let app = api::router(db.runtime.clone(), Some(sign_in));

        let invite = match db::create_invite(&db.runtime, &owner, "member", None).await {
            Ok(db::Wrote::Fresh(issued)) => issued.token,
            _ => panic!("invite"),
        };
        let (challenge, _) = PkceCodeChallenge::new_random_sha256();
        let (status, body) = Call::new(Method::POST, "/v1/auth/start")
            .json(json!({
                "redirect_uri": "http://127.0.0.1:53121/callback",
                "code_challenge": challenge.as_str(),
                "code_challenge_method": "S256",
                "state": CsrfToken::new_random_len(24).secret(),
                "invite": invite,
            }))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let opened = url::Url::parse(body["authorize_url"].as_str().expect("url")).expect("url");
        assert_eq!(opened.path(), "/v1/auth/join");
        let state = opened
            .query_pairs()
            .find(|(name, _)| name == "state")
            .map(|(_, state)| state.into_owned())
            .expect("state");
        let address = common::fresh_address();

        // The provider fails once: no link, the claim is given back, and a retry works.
        pocket.fail_with(Some(StatusCode::INTERNAL_SERVER_ERROR));
        let (status, page) = post_join(&app, &state, &address).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(page.contains("I'm new here"), "{page}");
        pocket.fail_with(None);
        let (status, page) = post_join(&app, &state, &address).await;
        assert_eq!(status, StatusCode::OK);
        let token = pocket.issued()[0].clone();
        assert!(page.contains(&token));
        assert_eq!(pocket.asked().len(), 2);
        seen.lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(token);

        // Three tries a minute from one address; the fourth is turned away before anything.
        let (status, page) = post_join(&app, &state, &address).await;
        assert_eq!(status, StatusCode::OK);
        assert!(page.contains("already made"), "{page}");
        let (status, page) = post_join(&app, &state, &address).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(page.contains("Too many tries"), "{page}");
        assert_eq!(pocket.asked().len(), 2);
    })
    .await;

    if std::env::var("TEST_DATABASE_URL").is_err() {
        return;
    }
    let text = logs.text();
    assert!(text.contains("sign-up link made for an invite"), "{text}");
    assert!(text.contains("sign-up link not made"), "{text}");
    assert!(!text.contains(pocket::API_KEY), "{text}");
    for token in issued
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .iter()
    {
        assert!(!text.contains(token.as_str()), "{text}");
    }
}
