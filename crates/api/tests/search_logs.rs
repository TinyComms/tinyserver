//! Search queries never reach a log line (issue #69). Alone in its own test binary so it can hold
//! the one global tracing subscriber and inspect every emitted line.

mod common;

use std::sync::{Arc, Mutex, MutexGuard};

use axum::http::{Method, StatusCode};
use common::{first_owner, run, session, Call};

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

const CANARY: &str = "SEARCH-CANARY-9c41f2";

#[tokio::test]
async fn search_query_never_reaches_the_logs() {
    let logs = Logs::default();
    let writer = logs.clone();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .init();

    run(|db| async move {
        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let app = api::router(db.runtime.clone(), None);

        // Valid search.
        let (status, _) = Call::new(Method::GET, &format!("/v1/search?q={CANARY}"))
            .token(&owner_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK);

        // Invalid search (bad conversation id -> 400).
        let (status, _) = Call::new(
            Method::GET,
            &format!("/v1/search?q={CANARY}&conversation_id=not-a-uuid"),
        )
        .token(&owner_token)
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Missing conversation -> 404.
        let (status, _) = Call::new(
            Method::GET,
            &format!("/v1/search?q={CANARY}&conversation_id=00000000-0000-4000-8000-000000000000"),
        )
        .token(&owner_token)
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    })
    .await;

    if std::env::var("TEST_DATABASE_URL").is_err() {
        return;
    }
    let text = logs.text();
    assert!(!text.contains(CANARY), "search query reached logs:\n{text}");
}
