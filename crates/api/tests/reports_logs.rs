//! Report text never reaches a log. Alone in its own test binary, so it can hold the one global
//! log subscriber and see every line at every level, including the database driver's.
//!
//! The server's own redaction layer (`crates/server/src/log_policy.rs`) is a second line: it
//! drops fields named `evidence`, `note` and the like, and has its own unit test. This test is
//! the first line: the API and database code never emit the text in the first place, on success
//! or on any of the ways a request can fail.

mod common;

use std::sync::{Arc, Mutex, MutexGuard};

use axum::http::{Method, StatusCode};
use common::{first_owner, join, run, session, Call};
use db::perm;
use serde_json::{json, Value};

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

const EVIDENCE: &str = "EVIDENCE-MARKER-7f3a";
const NOTE: &str = "REPORTER-NOTE-MARKER-91bc";
const MODERATOR: &str = "MODERATOR-NOTE-MARKER-44de";
const OVERSIZE: &str = "OVERSIZE-MARKER-0b17";

#[tokio::test]
async fn evidence_and_notes_never_reach_the_logs() {
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
        let (moderator, moderator_token) = join(&db, &owner, "mod@tinyserver.test", "member").await;
        let (_ada, ada_token) = join(&db, &owner, "ada@tinyserver.test", "member").await;
        let (bea, _) = join(&db, &owner, "bea@tinyserver.test", "member").await;
        let (status, role) = Call::new(Method::POST, "/v1/roles")
            .token(&owner_token)
            .json(json!({"name": "Moderator", "permissions": perm::MANAGE_REPORTS}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{role}");
        let (status, _) = Call::new(
            Method::PUT,
            &format!("/v1/members/{}/roles", moderator.user_id),
        )
        .token(&owner_token)
        .json(json!({"role_ids": [role["id"]]}))
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::OK);

        let post = |token: &str, body: Value| {
            let app = app.clone();
            let token = token.to_string();
            async move {
                Call::new(Method::POST, "/v1/reports")
                    .token(&token)
                    .json(body)
                    .send(&app)
                    .await
            }
        };
        // Filed with evidence and a note.
        let (status, filed) = post(
            &ada_token,
            json!({"kind": "member", "target_id": bea.user_id, "category": "harassment",
                   "note": NOTE, "evidence": EVIDENCE}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{filed}");
        let id = filed["id"].as_str().expect("id").to_string();

        // Refused in each way a request can be refused, with the text in the body.
        let nobody = "00000000-0000-4000-8000-000000000000";
        let oversize = format!("{OVERSIZE}{}", "x".repeat(40 * 1024));
        let nul_note = format!("{NOTE}\u{0}");
        for (token, body, want) in [
            (
                ada_token.as_str(),
                json!({"kind": "nonsense", "target_id": bea.user_id, "category": "spam",
                       "note": NOTE, "evidence": EVIDENCE}),
                StatusCode::BAD_REQUEST,
            ),
            (
                ada_token.as_str(),
                json!({"kind": "member", "target_id": bea.user_id, "category": "spam",
                       "evidence": oversize}),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                ada_token.as_str(),
                json!({"kind": "member", "target_id": nobody, "category": "spam",
                       "note": NOTE, "evidence": EVIDENCE}),
                StatusCode::NOT_FOUND,
            ),
            (
                "not-a-session",
                json!({"kind": "member", "target_id": bea.user_id, "category": "spam",
                       "note": NOTE, "evidence": EVIDENCE}),
                StatusCode::UNAUTHORIZED,
            ),
            (
                ada_token.as_str(),
                json!({"kind": "member", "target_id": bea.user_id, "category": "spam",
                       "note": nul_note, "evidence": EVIDENCE}),
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let (status, answer) = post(token, body).await;
            assert_eq!(status, want, "{answer}");
        }

        // Over the limit: twelve channels to report, of which the eleventh report in the hour is
        // refused.
        for n in 0..12 {
            let (status, _) = Call::new(Method::POST, "/v1/channels")
                .token(&owner_token)
                .json(json!({"name": format!("c{n}")}))
                .send(&app)
                .await;
            assert_eq!(status, StatusCode::CREATED);
        }
        let (_, channels) = Call::new(Method::GET, "/v1/channels")
            .token(&ada_token)
            .send(&app)
            .await;
        let mut refused = 0;
        for channel in channels.as_array().expect("channels") {
            let (status, _) = post(
                &ada_token,
                json!({"kind": "channel", "target_id": channel["id"], "category": "spam",
                       "note": NOTE, "evidence": EVIDENCE}),
            )
            .await;
            if status == StatusCode::TOO_MANY_REQUESTS {
                refused += 1;
            }
        }
        assert!(refused > 0, "the rate limit was not reached");

        // A moderator reads it and writes about it; a non-moderator is refused.
        let (status, _) = Call::new(Method::PATCH, &format!("/v1/reports/{id}"))
            .token(&moderator_token)
            .json(json!({"status": "reviewing", "note": MODERATOR}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = Call::new(Method::PATCH, &format!("/v1/reports/{id}"))
            .token(&ada_token)
            .json(json!({"note": MODERATOR}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = Call::new(Method::PATCH, &format!("/v1/reports/{id}"))
            .token(&moderator_token)
            .json(json!({"status": "bogus", "note": MODERATOR}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = Call::new(Method::GET, &format!("/v1/reports/{id}"))
            .token(&moderator_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK);

        // The reporter deletes their account, and the sweep runs: the scrubbing and retention
        // paths log nothing either.
        let (status, _) = Call::new(Method::DELETE, "/v1/me")
            .token(&ada_token)
            .json(json!({"confirm": "delete my account"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        db::sweep(&db.runtime).await.expect("sweep");
    })
    .await;

    let text = logs.text();
    // The capture works: the lines a successful filing and a moderator's work write are in it,
    // so an empty log is not what passed. When the database variables are not set the test body
    // is skipped and so is this check.
    if std::env::var("TEST_DATABASE_URL").is_err() {
        return;
    }
    assert!(text.contains("report filed"), "nothing captured:\n{text}");
    assert!(text.contains("report worked"), "nothing captured:\n{text}");
    for marker in [EVIDENCE, NOTE, MODERATOR, OVERSIZE] {
        assert!(!text.contains(marker), "{marker} reached the logs");
    }
}
