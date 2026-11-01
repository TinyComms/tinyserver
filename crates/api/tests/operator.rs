//! The operator's hooks: suspension read-only and offline with a notice, resume, and the legal
//! hold, as `tinyserver operator` sets them through `db` and the serving process obeys them.
//! Also how they meet abuse reports: a report can still be filed read-only, and a hold keeps
//! resolved reports past their retention. See `migrations/0016_operator.sql`.

mod common;

use axum::http::{Method, StatusCode};
use axum::Router;
use common::{first_owner, join, run, session, Call, TestDb};
use db::Mode;
use serde_json::{json, Value};

struct World {
    app: Router,
    owner: String,
    ada: String,
    ada_id: String,
    bea_id: String,
    channel: String,
}

async fn call(
    app: &Router,
    token: &str,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let call = Call::new(method, path).token(token);
    match body {
        Some(body) => call.json(body).send(app).await,
        None => call.send(app).await,
    }
}

async fn world(db: &TestDb) -> World {
    // Every request reads the state again, so a change shows at once.
    std::env::set_var("TINYSERVER_OPERATOR_REFRESH_MS", "0");
    let owner = first_owner(db).await;
    let owner_token = session(db, &owner.user_id).await;
    let (ada, ada_token) = join(db, &owner, "ada@tinyserver.test", "member").await;
    let (bea, _) = join(db, &owner, "bea@tinyserver.test", "member").await;
    let app = api::router(db.runtime.clone(), None);
    let (status, channel) = call(
        &app,
        &owner_token,
        Method::POST,
        "/v1/channels",
        Some(json!({"name": "general"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{channel}");
    World {
        app,
        owner: owner_token,
        ada: ada_token,
        ada_id: ada.user_id,
        bea_id: bea.user_id,
        channel: channel["id"].as_str().expect("channel").to_string(),
    }
}

async fn post(w: &World, token: &str, body: &str) -> (StatusCode, Value) {
    call(
        &w.app,
        token,
        Method::POST,
        &format!("/v1/conversations/{}/messages", w.channel),
        Some(json!({"body": body})),
    )
    .await
}

async fn messages(w: &World, token: &str) -> (StatusCode, Value) {
    call(
        &w.app,
        token,
        Method::GET,
        &format!("/v1/conversations/{}/messages", w.channel),
        None,
    )
    .await
}

async fn status(w: &World) -> Value {
    let (code, body) = Call::new(Method::GET, "/v1/status").send(&w.app).await;
    assert_eq!(code, StatusCode::OK, "{body}");
    body
}

async fn report_bea(w: &World) -> (StatusCode, Value) {
    call(
        &w.app,
        &w.ada,
        Method::POST,
        "/v1/reports",
        Some(json!({"kind": "member", "target_id": w.bea_id, "category": "spam"})),
    )
    .await
}

#[tokio::test]
async fn a_new_community_is_normal_and_says_so_without_a_session() {
    run(|db| async move {
        let w = world(&db).await;
        let body = status(&w).await;
        assert_eq!(
            body,
            json!({"mode": "normal", "notice": null, "since": null})
        );
        let state = db::operator_state(&db.runtime).await.expect("state");
        assert_eq!(state.mode, Mode::Normal);
        assert!(!state.legal_hold);
        let (code, _) = post(&w, &w.ada, "hello").await;
        assert_eq!(code, StatusCode::CREATED);
    })
    .await;
}

#[tokio::test]
async fn read_only_lets_members_read_and_report_and_refuses_every_other_write() {
    run(|db| async move {
        let w = world(&db).await;
        let (code, _) = post(&w, &w.ada, "before").await;
        assert_eq!(code, StatusCode::CREATED);

        let notice = "This community is read-only while a report is reviewed.";
        let state = db::set_operator_mode(&db.owner, Mode::ReadOnly, Some(notice))
            .await
            .expect("suspend");
        assert_eq!(state.mode, Mode::ReadOnly);

        let body = status(&w).await;
        assert_eq!(body["mode"], "read_only");
        assert_eq!(body["notice"], notice);
        assert!(body["since"].as_str().is_some_and(|s| s.ends_with('Z')));

        // Reading goes on.
        let (code, listed) = messages(&w, &w.ada).await;
        assert_eq!(code, StatusCode::OK, "{listed}");
        assert!(listed.to_string().contains("before"));
        let (code, _) = call(&w.app, &w.ada, Method::GET, "/v1/me", None).await;
        assert_eq!(code, StatusCode::OK);

        // Writing does not, for a member or for the owner, and the notice comes with the refusal.
        for token in [&w.ada, &w.owner] {
            let (code, refused) = post(&w, token, "during").await;
            assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE, "{refused}");
            assert_eq!(refused["error"], "read_only");
            assert_eq!(refused["notice"], notice);
        }
        let refused = [
            (
                Method::POST,
                "/v1/channels".to_string(),
                json!({"name": "x"}),
            ),
            (
                Method::PATCH,
                "/v1/me".to_string(),
                json!({"display_name": "X"}),
            ),
            (
                Method::POST,
                "/v1/invites".to_string(),
                json!({"role": "member"}),
            ),
            (
                Method::PATCH,
                "/v1/server".to_string(),
                json!({"name": "Y"}),
            ),
        ];
        for (method, path, body) in refused {
            let (code, _) = call(&w.app, &w.owner, method.clone(), &path, Some(body)).await;
            assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE, "{method} {path}");
        }
        // Nothing was written behind the refusal.
        let (_, listed) = messages(&w, &w.ada).await;
        assert!(!listed.to_string().contains("during"));

        // A report about abuse can still be filed: that is often why a community is restricted.
        let (code, filed) = report_bea(&w).await;
        assert_eq!(code, StatusCode::CREATED, "{filed}");
        // Working a report is a write like any other.
        let id = filed["id"].as_str().expect("report");
        let (code, _) = call(
            &w.app,
            &w.owner,
            Method::PATCH,
            &format!("/v1/reports/{id}"),
            Some(json!({"status": "reviewing"})),
        )
        .await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);

        // Resume, and writing works again; the notice is gone.
        let state = db::set_operator_mode(&db.owner, Mode::Normal, Some("ignored"))
            .await
            .expect("resume");
        assert_eq!(state.notice, None);
        assert_eq!(status(&w).await["mode"], "normal");
        let (code, _) = post(&w, &w.ada, "after").await;
        assert_eq!(code, StatusCode::CREATED);
    })
    .await;
}

#[tokio::test]
async fn read_only_still_lets_a_person_sign_out_and_delete_their_account() {
    run(|db| async move {
        let w = world(&db).await;
        db::set_operator_mode(&db.owner, Mode::ReadOnly, Some("Read only."))
            .await
            .expect("suspend");
        let (code, body) = call(
            &w.app,
            &w.ada,
            Method::DELETE,
            "/v1/me",
            Some(json!({"confirm": "delete my account"})),
        )
        .await;
        assert_eq!(code, StatusCode::NO_CONTENT, "{body}");
        let deleted: bool =
            sqlx::query_scalar("SELECT deleted_at IS NOT NULL FROM users WHERE id = $1::uuid")
                .bind(&w.ada_id)
                .fetch_one(&db.owner)
                .await
                .expect("tombstone");
        assert!(deleted, "the account was not deleted");
        let (code, _) = call(&w.app, &w.owner, Method::DELETE, "/v1/session", None).await;
        assert!(code.is_success(), "{code}");
    })
    .await;
}

#[tokio::test]
async fn offline_answers_only_the_notice_and_the_health_check() {
    run(|db| async move {
        let w = world(&db).await;
        let notice = "Suspended for a policy violation. The owner has been told why.";
        db::set_operator_mode(&db.owner, Mode::Offline, Some(notice))
            .await
            .expect("offline");
        let body = status(&w).await;
        assert_eq!(body["mode"], "offline");
        assert_eq!(body["notice"], notice);

        let (code, _) = Call::new(Method::GET, "/health").send(&w.app).await;
        assert_ne!(code, StatusCode::SERVICE_UNAVAILABLE);
        for (method, path) in [
            (Method::GET, "/v1/me".to_string()),
            (
                Method::GET,
                format!("/v1/conversations/{}/messages", w.channel),
            ),
            (Method::GET, "/v1/live".to_string()),
            (Method::POST, "/v1/auth/start".to_string()),
            (Method::POST, "/v1/reports".to_string()),
            (Method::DELETE, "/v1/me".to_string()),
        ] {
            let (code, refused) =
                call(&w.app, &w.ada, method.clone(), &path, Some(json!({}))).await;
            assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE, "{method} {path}");
            assert_eq!(refused["error"], "suspended", "{method} {path}");
            assert_eq!(refused["notice"], notice);
        }
        // Not even an unknown path says more than the notice.
        let (code, refused) = Call::new(Method::GET, "/v1/nothing").send(&w.app).await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(refused["error"], "suspended");

        db::set_operator_mode(&db.owner, Mode::Normal, None)
            .await
            .expect("resume");
        let (code, _) = messages(&w, &w.ada).await;
        assert_eq!(code, StatusCode::OK);
    })
    .await;
}

#[tokio::test]
async fn only_the_owner_role_changes_the_state_and_a_suspension_needs_a_notice() {
    run(|db| async move {
        let _w = world(&db).await;
        // The serving process's role can read the row and nothing else.
        for statement in [
            "UPDATE operator_state SET mode = 'normal', notice = NULL",
            "UPDATE operator_state SET legal_hold = false, legal_hold_since = NULL",
            "DELETE FROM operator_state",
            "INSERT INTO operator_state (id) VALUES (true)",
            "INSERT INTO operator_events (action) VALUES ('resume')",
        ] {
            let error = sqlx::query(statement)
                .execute(&db.runtime)
                .await
                .expect_err(statement);
            assert_eq!(common::sqlstate(&error), "42501", "{statement}");
        }
        let error = sqlx::query("SELECT count(*) FROM operator_events")
            .execute(&db.runtime)
            .await
            .expect_err("the runtime reads the operator's record");
        assert_eq!(common::sqlstate(&error), "42501");
        // And the db functions, given the runtime pool, fail the same way.
        assert!(db::set_operator_mode(&db.runtime, Mode::Offline, Some("x"))
            .await
            .is_err());
        assert!(db::set_legal_hold(&db.runtime, true, None).await.is_err());

        // One row, always.
        let error = sqlx::query("INSERT INTO operator_state (id) VALUES (true)")
            .execute(&db.owner)
            .await
            .expect_err("a second row");
        assert_eq!(common::sqlstate(&error), "23505");

        assert!(matches!(
            db::set_operator_mode(&db.owner, Mode::ReadOnly, None).await,
            Err(db::OperatorError::NeedsNotice)
        ));
        assert!(matches!(
            db::set_operator_mode(&db.owner, Mode::Offline, Some("   ")).await,
            Err(db::OperatorError::BadNotice)
        ));
        assert!(matches!(
            db::set_operator_mode(&db.owner, Mode::Offline, Some(&"x".repeat(501))).await,
            Err(db::OperatorError::BadNotice)
        ));
        let state = db::operator_state(&db.owner).await.expect("state");
        assert_eq!(
            state.mode,
            Mode::Normal,
            "a refused change changed something"
        );

        // Every change is in the operator's record.
        db::set_operator_mode(&db.owner, Mode::Offline, Some("Down."))
            .await
            .expect("offline");
        db::set_operator_mode(&db.owner, Mode::Normal, None)
            .await
            .expect("resume");
        let actions: Vec<String> =
            sqlx::query_scalar("SELECT action FROM operator_events ORDER BY id")
                .fetch_all(&db.owner)
                .await
                .expect("events");
        assert_eq!(actions, ["suspend", "resume"]);
    })
    .await;
}

#[tokio::test]
async fn a_legal_hold_keeps_resolved_reports_and_is_not_shown_to_members() {
    run(|db| async move {
        let w = world(&db).await;
        let (code, filed) = report_bea(&w).await;
        assert_eq!(code, StatusCode::CREATED, "{filed}");
        let id = filed["id"].as_str().expect("report").to_string();
        let (code, _) = call(
            &w.app,
            &w.owner,
            Method::PATCH,
            &format!("/v1/reports/{id}"),
            Some(json!({"status": "dismissed"})),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        sqlx::query(
            "UPDATE reports SET resolved_at = now() - interval '200 days' WHERE id = $1::uuid",
        )
        .bind(&id)
        .execute(&db.owner)
        .await
        .expect("age");

        let reason = "Preservation request 2026-123, until 2027-02-01";
        let state = db::set_legal_hold(&db.owner, true, Some(reason))
            .await
            .expect("hold");
        assert!(state.legal_hold);
        // The sweep keeps the report while the hold stands, though it is past retention.
        assert_eq!(db::sweep(&db.runtime).await.expect("sweep").reports, 0);
        let kept: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM reports WHERE id = $1::uuid)")
                .bind(&id)
                .fetch_one(&db.owner)
                .await
                .expect("exists");
        assert!(kept, "a report expired under a legal hold");

        // Members see neither the hold nor its reason, read-only or not.
        let body = status(&w).await;
        assert!(!body.to_string().contains("hold"), "{body}");
        assert!(!body.to_string().contains("2026-123"), "{body}");
        // The serving process's row has no reason in it at all.
        let row: Value = sqlx::query_scalar("SELECT to_jsonb(s) FROM operator_state s")
            .fetch_one(&db.runtime)
            .await
            .expect("row");
        assert!(!row.to_string().contains("2026-123"), "{row}");
        let recorded: Option<String> = sqlx::query_scalar(
            "SELECT reason FROM operator_events WHERE action = 'hold' ORDER BY id DESC LIMIT 1",
        )
        .fetch_one(&db.owner)
        .await
        .expect("record");
        assert_eq!(recorded.as_deref(), Some(reason));

        // An owner's hold on a report is counted for the operator too.
        assert_eq!(db::held_reports(&db.owner).await.expect("held"), 0);
        sqlx::query("UPDATE reports SET preserve = true, preserved_at = now() WHERE id = $1::uuid")
            .bind(&id)
            .execute(&db.owner)
            .await
            .expect("preserve");
        assert_eq!(db::held_reports(&db.owner).await.expect("held"), 1);
        sqlx::query("UPDATE reports SET preserve = false, preserved_at = NULL WHERE id = $1::uuid")
            .bind(&id)
            .execute(&db.owner)
            .await
            .expect("unpreserve");

        // Released, the next sweep takes the expired report.
        let state = db::set_legal_hold(&db.owner, false, None)
            .await
            .expect("release");
        assert!(!state.legal_hold);
        assert_eq!(db::sweep(&db.runtime).await.expect("sweep").reports, 1);
    })
    .await;
}

#[tokio::test]
async fn a_change_reaches_the_server_within_the_refresh_period() {
    run(|db| async move {
        let w = world(&db).await;
        std::env::set_var("TINYSERVER_OPERATOR_REFRESH_MS", "60000");
        // A router built now caches what it reads for a minute.
        let app = api::router(db.runtime.clone(), None);
        let (code, _) = Call::new(Method::GET, "/v1/status").send(&app).await;
        assert_eq!(code, StatusCode::OK);
        db::set_operator_mode(&db.owner, Mode::Offline, Some("Down."))
            .await
            .expect("offline");
        let (_, cached) = Call::new(Method::GET, "/v1/status").send(&app).await;
        assert_eq!(cached["mode"], "normal", "the cache was not used");
        // A router that reads every time sees it at once.
        std::env::set_var("TINYSERVER_OPERATOR_REFRESH_MS", "0");
        let fresh = api::router(db.runtime.clone(), None);
        let (_, now) = Call::new(Method::GET, "/v1/status").send(&fresh).await;
        assert_eq!(now["mode"], "offline");
        let _ = w;
    })
    .await;
}
