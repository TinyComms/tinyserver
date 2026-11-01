//! Abuse reports: who can file, who can see, what is kept and for how long. See
//! `docs/privacy/abuse-response.md` and `0015_abuse_reports.sql`. Each test names the property it
//! protects and fails when it stops holding.

mod common;

use std::str::FromStr;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use common::{first_owner, join, run, session, Call, TestDb};
use db::perm;
use serde_json::{json, Value};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Connection, Executor, PgConnection, PgPool};
use tower::ServiceExt;

struct Person {
    user_id: String,
    token: String,
}

struct World {
    app: Router,
    owner: Person,
    /// Holds manage_reports and view_audit_log, nothing else.
    moderator: Person,
    ada: Person,
    bea: Person,
    cy: Person,
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
    let owner = first_owner(db).await;
    let owner_token = session(db, &owner.user_id).await;
    let app = api::router(db.runtime.clone(), None);
    let (moderator, moderator_token) = join(db, &owner, "mod@tinyserver.test", "member").await;
    let (ada, ada_token) = join(db, &owner, "ada@tinyserver.test", "member").await;
    let (bea, bea_token) = join(db, &owner, "bea@tinyserver.test", "member").await;
    let (cy, cy_token) = join(db, &owner, "cy@tinyserver.test", "member").await;
    let role = new_role(
        &app,
        &owner_token,
        "Moderator",
        perm::MANAGE_REPORTS | perm::VIEW_AUDIT_LOG,
    )
    .await;
    give_role(&app, &owner_token, &moderator.user_id, &role).await;
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
        channel: channel["id"].as_str().expect("channel").to_string(),
        owner: Person {
            user_id: owner.user_id,
            token: owner_token,
        },
        moderator: Person {
            user_id: moderator.user_id,
            token: moderator_token,
        },
        ada: Person {
            user_id: ada.user_id,
            token: ada_token,
        },
        bea: Person {
            user_id: bea.user_id,
            token: bea_token,
        },
        cy: Person {
            user_id: cy.user_id,
            token: cy_token,
        },
    }
}

async fn new_role(app: &Router, token: &str, name: &str, permissions: i64) -> String {
    let (status, role) = call(
        app,
        token,
        Method::POST,
        "/v1/roles",
        Some(json!({"name": name, "permissions": permissions})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{role}");
    role["id"].as_str().expect("role").to_string()
}

async fn give_role(app: &Router, owner_token: &str, user_id: &str, role: &str) {
    let (status, member) = call(
        app,
        owner_token,
        Method::PUT,
        &format!("/v1/members/{user_id}/roles"),
        Some(json!({"role_ids": [role]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{member}");
}

async fn say(world: &World, token: &str, body: &str) -> String {
    let (status, message) = call(
        &world.app,
        token,
        Method::POST,
        &format!("/v1/conversations/{}/messages", world.channel),
        Some(json!({"body": body})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{message}");
    message["id"].as_str().expect("message").to_string()
}

async fn report(world: &World, token: &str, body: Value) -> (StatusCode, Value) {
    call(&world.app, token, Method::POST, "/v1/reports", Some(body)).await
}

async fn report_member(world: &World, token: &str, about: &str) -> String {
    let (status, filed) = report(
        world,
        token,
        json!({"kind": "member", "target_id": about, "category": "harassment"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{filed}");
    filed["id"].as_str().expect("report").to_string()
}

async fn audit(world: &World, token: &str, query: &str) -> Vec<Value> {
    let (status, rows) = call(
        &world.app,
        token,
        Method::GET,
        &format!("/v1/audit?limit=200{query}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{rows}");
    rows.as_array().expect("rows").clone()
}

async fn work(world: &World, token: &str, id: &str, body: Value) -> (StatusCode, Value) {
    call(
        &world.app,
        token,
        Method::PATCH,
        &format!("/v1/reports/{id}"),
        Some(body),
    )
    .await
}

/// A request that may be refused before the API's own JSON error handling, so the body is not
/// parsed.
async fn post_raw(app: &Router, token: &str, body: String) -> StatusCode {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/reports")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("cf-connecting-ip", common::fresh_address())
        .body(Body::from(body))
        .expect("request");
    app.clone()
        .oneshot(request)
        .await
        .expect("response")
        .status()
}

#[tokio::test]
async fn a_member_can_report_a_message_a_member_and_a_channel() {
    run(|db| async move {
        let w = world(&db).await;
        let message = say(&w, &w.bea.token, "the thing bea said").await;

        let (status, filed) = report(
            &w,
            &w.ada.token,
            json!({
                "kind": "message", "target_id": message, "category": "harassment",
                "note": "this was aimed at me",
                "evidence": "bea: the thing bea said (as ada's client saw it)",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{filed}");
        assert_eq!(filed["status"], "open");
        assert_eq!(filed["kind"], "message");
        assert_eq!(filed["evidence_unverified"], true, "{filed}");
        assert_eq!(filed["duplicate"], false);
        // The reporter is told nothing about who is involved.
        let text = filed.to_string();
        assert!(!text.contains(&w.bea.user_id), "{text}");
        assert!(!text.contains(&w.ada.user_id), "{text}");
        assert!(!text.contains("reporter") && !text.contains("reported"), "{text}");
        let first = filed["id"].as_str().expect("id").to_string();

        // The same thing again while the first is open is the first, and is not a new row.
        let (status, again) = report(
            &w,
            &w.ada.token,
            json!({"kind": "message", "target_id": message, "category": "spam"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{again}");
        assert_eq!(again["id"], first);
        assert_eq!(again["duplicate"], true);

        let (status, member) = report(
            &w,
            &w.ada.token,
            json!({"kind": "member", "target_id": w.cy.user_id, "category": "impersonation"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{member}");
        assert_eq!(
            member["evidence_unverified"], false,
            "no evidence, nothing unverified: {member}"
        );
        let (status, channel) = report(
            &w,
            &w.cy.token,
            json!({"kind": "channel", "target_id": w.channel, "category": "spam"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{channel}");

        // A moderator reads the message report: what was said by the reporter, flagged
        // unverified, and the id and author of the message but not its text.
        let (status, detail) = call(
            &w.app,
            &w.moderator.token,
            Method::GET,
            &format!("/v1/reports/{first}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{detail}");
        assert_eq!(detail["kind"], "message");
        assert_eq!(detail["category"], "harassment");
        assert_eq!(detail["note"], "this was aimed at me");
        assert_eq!(
            detail["evidence"],
            "bea: the thing bea said (as ada's client saw it)"
        );
        assert_eq!(detail["evidence_unverified"], true);
        assert_eq!(detail["message_id"], message);
        assert_eq!(detail["channel_id"], w.channel);
        assert_eq!(detail["reported"]["user_id"], w.bea.user_id);
        assert_eq!(detail["reporter"]["user_id"], w.ada.user_id);
        // Reporting a message does not copy it: with no evidence sent, none is stored.
        let (_, bare) = call(
            &w.app,
            &w.moderator.token,
            Method::GET,
            &format!("/v1/reports/{}", member["id"].as_str().expect("id")),
            None,
        )
        .await;
        assert_eq!(bare["evidence"], Value::Null);
        assert_eq!(bare["note"], Value::Null);
        let stored_anywhere: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM reports WHERE row_to_json(reports)::text LIKE '%the thing bea said%'
             AND id <> $1::uuid",
        )
        .bind(&first)
        .fetch_one(&db.owner)
        .await
        .expect("count");
        assert_eq!(stored_anywhere, 0);

        // The list is a summary: it says whether there is evidence and carries none.
        let (status, list) = call(
            &w.app,
            &w.moderator.token,
            Method::GET,
            "/v1/reports",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{list}");
        let list = list.as_array().expect("list");
        assert_eq!(list.len(), 3);
        assert!(list.iter().all(|row| row.get("evidence").is_none()));
        assert!(list.iter().all(|row| row.get("note").is_none()));
        let with_evidence: Vec<_> = list.iter().filter(|row| row["has_evidence"] == true).collect();
        assert_eq!(with_evidence.len(), 1);
        assert_eq!(with_evidence[0]["evidence_unverified"], true);
        let (_, only_channel) = call(
            &w.app,
            &w.moderator.token,
            Method::GET,
            "/v1/reports?kind=channel&status=open",
            None,
        )
        .await;
        assert_eq!(only_channel.as_array().expect("list").len(), 1);
        let (status, _) = call(
            &w.app,
            &w.moderator.token,
            Method::GET,
            "/v1/reports?status=bogus",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Old clients do not know the feature, new ones can ask for it.
        let (_, caps) = call(&w.app, &w.ada.token, Method::GET, "/v1/capabilities", None).await;
        let features = caps["features"].as_array().expect("features");
        assert!(features.contains(&json!("abuse_reports")), "{caps}");
        for old in ["server", "roles", "bans", "audit_query", "file_scan"] {
            assert!(features.contains(&json!(old)), "{old}");
        }
    })
    .await;
}

#[tokio::test]
async fn what_can_and_cannot_be_reported() {
    run(|db| async move {
        let w = world(&db).await;
        let own = say(&w, &w.ada.token, "ada's own message").await;
        let nobody = "00000000-0000-4000-8000-000000000000";

        for (body, want) in [
            // Yourself.
            (json!({"kind": "member", "target_id": w.ada.user_id, "category": "spam"}), StatusCode::BAD_REQUEST),
            (json!({"kind": "message", "target_id": own, "category": "spam"}), StatusCode::BAD_REQUEST),
            // Something that is not there.
            (json!({"kind": "member", "target_id": nobody, "category": "spam"}), StatusCode::NOT_FOUND),
            (json!({"kind": "message", "target_id": nobody, "category": "spam"}), StatusCode::NOT_FOUND),
            (json!({"kind": "channel", "target_id": nobody, "category": "spam"}), StatusCode::NOT_FOUND),
            // Not a thing the API knows.
            (json!({"kind": "room", "target_id": nobody, "category": "spam"}), StatusCode::BAD_REQUEST),
            (json!({"kind": "member", "target_id": w.bea.user_id, "category": "meh"}), StatusCode::BAD_REQUEST),
            (json!({"kind": "member", "target_id": "not-a-uuid", "category": "spam"}), StatusCode::BAD_REQUEST),
            // Control characters in text.
            (json!({"kind": "member", "target_id": w.bea.user_id, "category": "spam", "note": "a\u{0}b"}), StatusCode::BAD_REQUEST),
            (json!({"kind": "member", "target_id": w.bea.user_id, "category": "spam", "evidence": "a\u{7}b"}), StatusCode::BAD_REQUEST),
        ] {
            let (status, answer) = report(&w, &w.ada.token, body.clone()).await;
            assert_eq!(status, want, "{body} -> {answer}");
        }
        // Nothing was stored by any refusal.
        let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM reports")
            .fetch_one(&db.owner)
            .await
            .expect("count");
        assert_eq!(stored, 0);

        // A channel the reporter cannot view cannot be reported, and its messages cannot be
        // reported either: a report is not a way to learn that something exists.
        let (_, roles) = call(&w.app, &w.owner.token, Method::GET, "/v1/roles", None).await;
        let everyone = roles
            .as_array()
            .expect("roles")
            .iter()
            .find(|role| role["default"] == true)
            .expect("@everyone")["id"]
            .as_str()
            .expect("id")
            .to_string();
        let (status, private) = call(
            &w.app,
            &w.owner.token,
            Method::POST,
            "/v1/channels",
            Some(json!({"name": "staff"})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{private}");
        let private = private["id"].as_str().expect("channel").to_string();
        let (status, hidden) = call(
            &w.app,
            &w.owner.token,
            Method::PUT,
            &format!("/v1/channels/{private}/overrides/{everyone}"),
            Some(json!({"allow": 0, "deny": perm::VIEW_CHANNEL})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{hidden}");
        let (status, secret) = call(
            &w.app,
            &w.owner.token,
            Method::POST,
            &format!("/v1/conversations/{private}/messages"),
            Some(json!({"body": "staff only"})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{secret}");
        let secret = secret["id"].as_str().expect("message").to_string();
        for (kind, target) in [("channel", &private), ("message", &secret)] {
            let (status, answer) = report(
                &w,
                &w.ada.token,
                json!({"kind": kind, "target_id": target, "category": "other"}),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{kind}: {answer}");
        }

        // A direct message can be reported by the two people in it and by no one else.
        let (status, direct) = call(
            &w.app,
            &w.bea.token,
            Method::POST,
            "/v1/directs",
            Some(json!({"user_id": w.cy.user_id})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{direct}");
        let direct = direct["id"].as_str().expect("direct").to_string();
        let (status, dm) = call(
            &w.app,
            &w.bea.token,
            Method::POST,
            &format!("/v1/conversations/{direct}/messages"),
            Some(json!({"body": "a private line"})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{dm}");
        let dm = dm["id"].as_str().expect("dm").to_string();
        let (status, answer) = report(
            &w,
            &w.ada.token,
            json!({"kind": "message", "target_id": dm, "category": "other"}),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");
        let (status, answer) = report(
            &w,
            &w.cy.token,
            json!({"kind": "message", "target_id": dm, "category": "harassment"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{answer}");
        let (_, detail) = call(
            &w.app,
            &w.moderator.token,
            Method::GET,
            &format!("/v1/reports/{}", answer["id"].as_str().expect("id")),
            None,
        )
        .await;
        assert_eq!(detail["direct_id"], direct);
        assert_eq!(detail["reported"]["user_id"], w.bea.user_id);
        // The moderator still cannot read the direct itself.
        let (status, _) = call(
            &w.app,
            &w.moderator.token,
            Method::GET,
            &format!("/v1/conversations/{direct}/messages"),
            None,
        )
        .await;
        assert_ne!(status, StatusCode::OK);
        assert!(!detail.to_string().contains("a private line"));

    })
    .await;
}

#[tokio::test]
async fn the_reported_member_cannot_see_or_infer_the_reporter() {
    run(|db| async move {
        let w = world(&db).await;
        let message = say(&w, &w.bea.token, "something bea said").await;
        let (_, filed) = report(
            &w,
            &w.ada.token,
            json!({"kind": "message", "target_id": message, "category": "harassment",
                   "note": "ADA-NOTE", "evidence": "ADA-EVIDENCE"}),
        )
        .await;
        let id = filed["id"].as_str().expect("id").to_string();

        // Bea holds no moderator permission: nothing to list, nothing to read.
        let (status, listed) = call(&w.app, &w.bea.token, Method::GET, "/v1/reports", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{listed}");
        let (status, read) = call(
            &w.app,
            &w.bea.token,
            Method::GET,
            &format!("/v1/reports/{id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{read}");

        // Make bea a moderator, with the audit log too. A report about her is still invisible,
        // and she cannot tell it exists: 404, the same as an id nobody has.
        let role = new_role(
            &w.app,
            &w.owner.token,
            "Moderator 2",
            perm::MANAGE_REPORTS | perm::VIEW_AUDIT_LOG,
        )
        .await;
        give_role(&w.app, &w.owner.token, &w.bea.user_id, &role).await;
        let other = report_member(&w, &w.ada.token, &w.cy.user_id).await;

        let (status, listed) = call(&w.app, &w.bea.token, Method::GET, "/v1/reports", None).await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        let ids: Vec<&str> = listed
            .as_array()
            .expect("list")
            .iter()
            .map(|row| row["id"].as_str().expect("id"))
            .collect();
        assert_eq!(ids, vec![other.as_str()], "bea sees only reports about others");
        let (status, read) = call(
            &w.app,
            &w.bea.token,
            Method::GET,
            &format!("/v1/reports/{id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{read}");
        let (status, missing) = call(
            &w.app,
            &w.bea.token,
            Method::GET,
            "/v1/reports/00000000-0000-4000-8000-000000000000",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(missing, read, "a hidden report answers like a missing one");
        let (status, worked) = work(&w, &w.bea.token, &id, json!({"status": "dismissed"})).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{worked}");
        let (status, worked) = work(&w, &w.bea.token, &id, json!({"preserve": true})).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{worked}");
        let status_now: String = sqlx::query_scalar("SELECT status FROM reports WHERE id = $1::uuid")
            .bind(&id)
            .fetch_one(&db.owner)
            .await
            .expect("status");
        assert_eq!(status_now, "open");

        // A moderator works it and writes about it; bea's view of the audit log has none of it.
        let (status, _) = work(
            &w,
            &w.moderator.token,
            &id,
            json!({"status": "reviewing", "note": "MOD-NOTE"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let bea_sees = audit(&w, &w.bea.token, "").await;
        assert!(
            bea_sees
                .iter()
                .filter(|row| row["action"].as_str().is_some_and(|a| a.starts_with("report.")))
                .all(|row| row["subject_user_id"] != json!(w.bea.user_id)),
            "{bea_sees:?}"
        );
        let bea_text = serde_json::to_string(&bea_sees).expect("json");
        // Other rows (ada joining the server) name ada, as they always have. A row about a
        // report must not.
        let report_rows: Vec<&Value> = bea_sees
            .iter()
            .filter(|row| row["action"].as_str().is_some_and(|a| a.starts_with("report.")))
            .collect();
        assert!(!report_rows.is_empty(), "bea sees the rows about reports on others");
        assert!(
            !serde_json::to_string(&report_rows)
                .expect("json")
                .contains(&w.ada.user_id),
            "the reporter is in a report row"
        );
        for secret in ["ADA-NOTE", "ADA-EVIDENCE", "MOD-NOTE", &id] {
            assert!(!bea_text.contains(secret), "{secret} reached bea");
        }

        // The same at the database, not only the handlers: as app_runtime with bea's id.
        let mut tx = db.runtime.begin().await.expect("tx");
        sqlx::query("SELECT set_config('app.user_id', $1, true)")
            .bind(&w.bea.user_id)
            .execute(&mut *tx)
            .await
            .expect("who");
        let visible: Vec<String> = sqlx::query_scalar("SELECT id::text FROM reports")
            .fetch_all(&mut *tx)
            .await
            .expect("reports");
        assert_eq!(visible, vec![other.clone()]);
        let notes: i64 = sqlx::query_scalar("SELECT count(*) FROM report_notes")
            .fetch_one(&mut *tx)
            .await
            .expect("notes");
        assert_eq!(notes, 0, "a note on a report about bea is as hidden as the report");
        let rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_log WHERE action LIKE 'report.%' AND subject_user_id = $1::uuid",
        )
        .bind(&w.bea.user_id)
        .fetch_one(&mut *tx)
        .await
        .expect("audit");
        assert_eq!(rows, 0);
        tx.rollback().await.expect("rollback");

        // The log of filing has no actor: moderators see that a report was made, not by whom.
        let owner_sees = audit(&w, &w.owner.token, "&action=report.").await;
        let created: Vec<_> = owner_sees
            .iter()
            .filter(|row| row["action"] == "report.create")
            .collect();
        assert_eq!(created.len(), 2);
        for row in &created {
            assert_eq!(row["actor_id"], Value::Null, "{row}");
        }
        let owner_text = serde_json::to_string(&owner_sees).expect("json");
        assert!(!owner_text.contains(&w.ada.user_id), "{owner_text}");
        for secret in ["ADA-NOTE", "ADA-EVIDENCE", "MOD-NOTE"] {
            assert!(!owner_text.contains(secret), "{secret} is in the audit log");
        }
    })
    .await;
}

#[tokio::test]
async fn only_moderators_work_reports_and_the_runtime_role_cannot_write_them() {
    run(|db| async move {
        let w = world(&db).await;
        let id = report_member(&w, &w.ada.token, &w.bea.user_id).await;

        for token in [&w.ada.token, &w.bea.token, &w.cy.token] {
            let (status, _) = call(&w.app, token, Method::GET, "/v1/reports", None).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            let (status, _) = call(
                &w.app,
                token,
                Method::GET,
                &format!("/v1/reports/{id}"),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            let (status, _) = work(&w, token, &id, json!({"status": "dismissed"})).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }
        // A bot, even one granted every scope and every permission bit, can neither file nor
        // read: bots are not members.
        let (status, issued) = call(
            &w.app,
            &w.owner.token,
            Method::POST,
            "/v1/bots",
            Some(json!({"name": "Herald", "permissions": perm::ALL})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{issued}");
        let bot_token = issued["token"].as_str().expect("token");
        let (status, _) = Call::new(Method::GET, "/v1/reports")
            .bot(bot_token)
            .send(&w.app)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = Call::new(Method::POST, "/v1/reports")
            .bot(bot_token)
            .json(json!({"kind": "member", "target_id": w.bea.user_id, "category": "spam"}))
            .send(&w.app)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // The reporter cannot read their own report back either.
        let (status, _) = call(
            &w.app,
            &w.ada.token,
            Method::GET,
            &format!("/v1/reports/{id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // No session at all.
        let response = w
            .app
            .clone()
            .oneshot(
                Request::get("/v1/reports")
                    .header("cf-connecting-ip", common::fresh_address())
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // manage_server alone is not enough on a server that was set up after this feature: the
        // moderator permission is its own bit. (Upgraded servers are covered by the upgrade
        // test.)
        let role = new_role(&w.app, &w.owner.token, "Admin-ish", perm::MANAGE_SERVER).await;
        give_role(&w.app, &w.owner.token, &w.cy.user_id, &role).await;
        let (status, _) = call(&w.app, &w.cy.token, Method::GET, "/v1/reports", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = call(&w.app, &w.moderator.token, Method::GET, "/v1/reports", None).await;
        assert_eq!(status, StatusCode::OK);

        // The runtime role reads through row level security and cannot write at all.
        let mut conn = db.runtime.acquire().await.expect("connection");
        for sql in [
            "INSERT INTO reports (kind, category) VALUES ('member', 'spam')",
            "UPDATE reports SET status = 'dismissed'",
            "DELETE FROM reports",
            "INSERT INTO report_notes (report_id, body) SELECT id, 'x' FROM reports",
            "UPDATE report_notes SET body = 'y'",
            "DELETE FROM report_notes",
        ] {
            let error = sqlx::query(sql).execute(&mut *conn).await.expect_err(sql);
            assert_eq!(common::sqlstate(&error), "42501", "{sql}: {error}");
        }
    })
    .await;
}

#[tokio::test]
async fn triage_notes_links_and_holds_are_audited() {
    run(|db| async move {
        let w = world(&db).await;
        let id = report_member(&w, &w.ada.token, &w.bea.user_id).await;
        let moderator = &w.moderator.token;

        let (status, now) = work(
            &w,
            moderator,
            &id,
            json!({"status": "reviewing", "note": "looking into it"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{now}");
        assert_eq!(now["status"], "reviewing");
        assert_eq!(now["resolved_at"], Value::Null);
        assert_eq!(now["notes"][0]["body"], "looking into it");
        assert_eq!(now["notes"][0]["author"]["user_id"], w.moderator.user_id);

        // An enforcement action to link: the owner times bea out and kicks nobody.
        let until = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let (status, timed) = call(
            &w.app,
            &w.owner.token,
            Method::PUT,
            &format!("/v1/members/{}/timeout", w.bea.user_id),
            Some(json!({"until": until, "reason": "cooling off"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{timed}");
        let (status, timed_cy) = call(
            &w.app,
            &w.owner.token,
            Method::PUT,
            &format!("/v1/members/{}/timeout", w.cy.user_id),
            Some(json!({"until": until})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{timed_cy}");
        let timeouts = audit(&w, &w.owner.token, "&action=member.timeout").await;
        let about = |user: &str| -> i64 {
            timeouts
                .iter()
                .find(|row| row["subject_user_id"] == json!(user))
                .and_then(|row| row["id"].as_i64())
                .expect("timeout row")
        };
        let bea_action = about(&w.bea.user_id);
        let cy_action = about(&w.cy.user_id);
        let role_row = audit(&w, &w.owner.token, "&action=role.create").await[0]["id"]
            .as_i64()
            .expect("role row");

        // Only an enforcement action, and only about the person reported.
        for (link, label) in [
            (cy_action, "an action about someone else"),
            (role_row, "an audit row that is not enforcement"),
            (999_999, "a row that does not exist"),
        ] {
            let (status, refused) = work(&w, moderator, &id, json!({"link_audit_id": link})).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{label}: {refused}");
        }
        let (status, linked) = work(
            &w,
            moderator,
            &id,
            json!({"link_audit_id": bea_action, "status": "actioned"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{linked}");
        assert_eq!(linked["linked_audit_ids"], json!([bea_action]));
        assert_eq!(linked["status"], "actioned");
        assert!(linked["resolved_at"].is_string(), "{linked}");
        // Linking twice adds nothing.
        let (_, twice) = work(&w, moderator, &id, json!({"link_audit_id": bea_action})).await;
        assert_eq!(twice["linked_audit_ids"], json!([bea_action]));

        // Reopening clears the resolution time; any status moves to any other.
        let (_, reopened) = work(&w, moderator, &id, json!({"status": "open"})).await;
        assert_eq!(reopened["resolved_at"], Value::Null);
        let (_, dismissed) = work(&w, moderator, &id, json!({"status": "dismissed"})).await;
        assert!(dismissed["resolved_at"].is_string());

        // Nothing to change, an unknown status, and an over-long note are refused.
        for body in [
            json!({}),
            json!({"status": "closed"}),
            json!({"note": "x".repeat(2001)}),
            json!({"note": "   "}),
        ] {
            let (status, refused) = work(&w, moderator, &id, body.clone()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {refused}");
        }

        // A legal hold is the owner's alone, and is audited both ways.
        let (status, refused) = work(&w, moderator, &id, json!({"preserve": true})).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
        // A refusal changes nothing, not even the other fields in the same request.
        let (status, _) = work(
            &w,
            moderator,
            &id,
            json!({"preserve": true, "note": "should not be written"}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (_, detail) = call(
            &w.app,
            moderator,
            Method::GET,
            &format!("/v1/reports/{id}"),
            None,
        )
        .await;
        assert_eq!(detail["preserve"], false);
        assert_eq!(detail["notes"].as_array().expect("notes").len(), 1);
        let (status, held) = work(&w, &w.owner.token, &id, json!({"preserve": true})).await;
        assert_eq!(status, StatusCode::OK, "{held}");
        assert_eq!(held["preserve"], true);
        assert_eq!(held["preserved_by"]["user_id"], w.owner.user_id);
        assert!(held["preserved_at"].is_string());
        // The moderator cannot lift it.
        let (status, _) = work(&w, moderator, &id, json!({"preserve": false})).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (_, released) = work(&w, &w.owner.token, &id, json!({"preserve": false})).await;
        assert_eq!(released["preserve"], false);
        assert_eq!(released["preserved_by"], Value::Null);

        let rows = audit(&w, moderator, "&action=report.").await;
        let actions: Vec<&str> = rows
            .iter()
            .map(|row| row["action"].as_str().expect("action"))
            .collect();
        for expected in [
            "report.create",
            "report.triage",
            "report.annotate",
            "report.link",
            "report.preserve",
            "report.unpreserve",
        ] {
            assert!(actions.contains(&expected), "{expected} not in {actions:?}");
        }
        // reviewing, actioned, open, dismissed.
        assert_eq!(actions.iter().filter(|a| **a == "report.triage").count(), 4);
        assert_eq!(actions.iter().filter(|a| **a == "report.link").count(), 1);
        let triage = rows
            .iter()
            .find(|row| row["action"] == "report.triage")
            .expect("triage row");
        assert_eq!(triage["actor_id"], json!(w.moderator.user_id));
        assert_eq!(triage["detail"]["report_id"], json!(id));
        // The audit trail carries ids and transitions, never the text a moderator wrote.
        let text = serde_json::to_string(&rows).expect("json");
        assert!(!text.contains("looking into it"));
        // Someone with view_audit_log and without manage_reports sees none of it.
        let auditor = new_role(&w.app, &w.owner.token, "Auditor", perm::VIEW_AUDIT_LOG).await;
        give_role(&w.app, &w.owner.token, &w.cy.user_id, &auditor).await;
        let seen_by_auditor = audit(&w, &w.cy.token, "").await;
        assert!(
            !seen_by_auditor.iter().any(|row| row["action"]
                .as_str()
                .is_some_and(|a| a.starts_with("report."))),
            "{seen_by_auditor:?}"
        );
        assert!(
            !seen_by_auditor.is_empty(),
            "the auditor still sees other rows"
        );
    })
    .await;
}

#[tokio::test]
async fn reports_are_rate_limited_per_reporter() {
    run(|db| async move {
        let w = world(&db).await;
        let mut messages = Vec::new();
        for n in 0..12 {
            messages.push(say(&w, &w.bea.token, &format!("message {n}")).await);
        }
        // Ten an hour.
        for message in &messages[..10] {
            let (status, filed) = report(
                &w,
                &w.ada.token,
                json!({"kind": "message", "target_id": message, "category": "spam"}),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED, "{filed}");
        }
        let (status, slow) = report(
            &w,
            &w.ada.token,
            json!({"kind": "message", "target_id": messages[10], "category": "spam"}),
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{slow}");
        assert_eq!(slow["error"], "slow_down");
        // Repeating one already filed is not a new report and is not refused.
        let (status, again) = report(
            &w,
            &w.ada.token,
            json!({"kind": "message", "target_id": messages[0], "category": "spam"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{again}");
        // The limit is per person: someone else is not slowed down.
        let (status, other) = report(
            &w,
            &w.cy.token,
            json!({"kind": "message", "target_id": messages[10], "category": "spam"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{other}");
        let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM reports")
            .fetch_one(&db.owner)
            .await
            .expect("count");
        assert_eq!(stored, 11, "the refused report was not stored");

        // Fifty a day, counted across the hours. Fifty reports made two hours ago leave the
        // hourly allowance free and the daily one used up.
        sqlx::query(
            "INSERT INTO reports (kind, category, reporter_id, reported_user_id, status,
                                  resolved_at, created_at)
             SELECT 'member', 'spam', $1::uuid, $2::uuid, 'dismissed',
                    now() - interval '2 hours', now() - interval '2 hours'
             FROM generate_series(1, 50)",
        )
        .bind(&w.bea.user_id)
        .bind(&w.cy.user_id)
        .execute(&db.owner)
        .await
        .expect("backdated reports");
        let (status, slow) = report(
            &w,
            &w.bea.token,
            json!({"kind": "member", "target_id": w.ada.user_id, "category": "spam"}),
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{slow}");
        // The same fifty a day and an hour later is a different day's quota: age them out.
        sqlx::query("UPDATE reports SET created_at = now() - interval '25 hours' WHERE reporter_id = $1::uuid")
            .bind(&w.bea.user_id)
            .execute(&db.owner)
            .await
            .expect("age");
        let (status, filed) = report(
            &w,
            &w.bea.token,
            json!({"kind": "member", "target_id": w.ada.user_id, "category": "spam"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{filed}");
    })
    .await;
}

#[tokio::test]
async fn reports_are_size_limited() {
    run(|db| async move {
        let w = world(&db).await;
        let target = w.bea.user_id.clone();
        let file = |note: Option<String>, evidence: Option<String>| {
            json!({"kind": "member", "target_id": target, "category": "other",
                   "note": note, "evidence": evidence})
        };

        // At the limit is fine: 2000 characters of note, 32 KiB of evidence.
        let (status, ok) = report(
            &w,
            &w.ada.token,
            file(Some("n".repeat(2000)), Some("e".repeat(32 * 1024))),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{ok}");
        let id = ok["id"].as_str().expect("id").to_string();
        let (_, detail) = call(
            &w.app,
            &w.moderator.token,
            Method::GET,
            &format!("/v1/reports/{id}"),
            None,
        )
        .await;
        assert_eq!(
            detail["evidence"].as_str().expect("evidence").len(),
            32 * 1024
        );

        // One over is refused with its own status, and nothing is stored for it.
        let (status, long) =
            report(&w, &w.cy.token, file(None, Some("e".repeat(32 * 1024 + 1)))).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{long}");
        assert_eq!(long["error"], "too_large");
        let (status, long) = report(&w, &w.cy.token, file(Some("n".repeat(2001)), None)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{long}");
        assert_eq!(long["error"], "invalid");
        // A multibyte note is counted in characters, evidence in bytes.
        let (status, wide) = report(&w, &w.cy.token, file(Some("é".repeat(2000)), None)).await;
        assert_eq!(status, StatusCode::CREATED, "{wide}");
        let (status, wide) = report(
            &w,
            &w.ada.token,
            json!({"kind": "channel", "target_id": w.channel, "category": "other",
                   "evidence": "é".repeat(16 * 1024 + 1)}),
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{wide}");

        // A body past what the route reads at all is cut off before it is parsed.
        let huge = json!({"kind": "member", "target_id": target, "category": "other",
                          "evidence": "e".repeat(200 * 1024)})
        .to_string();
        assert_eq!(
            post_raw(&w.app, &w.cy.token, huge).await,
            StatusCode::PAYLOAD_TOO_LARGE
        );

        // The same route is the only one with the larger limit: another JSON route still stops
        // at 8 KiB.
        let status = {
            let request = Request::builder()
                .method(Method::POST)
                .uri("/v1/channels")
                .header("authorization", format!("Bearer {}", w.owner.token))
                .header("content-type", "application/json")
                .header("cf-connecting-ip", common::fresh_address())
                .body(Body::from(
                    json!({"name": "x", "topic": "t".repeat(20 * 1024)}).to_string(),
                ))
                .expect("request");
            w.app
                .clone()
                .oneshot(request)
                .await
                .expect("response")
                .status()
        };
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

        let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM reports")
            .fetch_one(&db.owner)
            .await
            .expect("count");
        assert_eq!(stored, 2);
    })
    .await;
}

/// Back-dates `resolved_at` and `created_at`, as the clock cannot be moved.
async fn age(db: &TestDb, id: &str, days: i32) {
    sqlx::query(
        "UPDATE reports
         SET resolved_at = CASE WHEN resolved_at IS NULL THEN NULL
                                ELSE now() - make_interval(days => $2) END,
             created_at = now() - make_interval(days => $2 + 1)
         WHERE id = $1::uuid",
    )
    .bind(id)
    .bind(days)
    .execute(&db.owner)
    .await
    .expect("age report");
}

async fn exists(db: &TestDb, id: &str) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM reports WHERE id = $1::uuid)")
        .bind(id)
        .fetch_one(&db.owner)
        .await
        .expect("exists")
}

#[tokio::test]
async fn the_sweep_deletes_old_resolved_reports_and_keeps_held_ones() {
    run(|db| async move {
        let w = world(&db).await;
        // Five reports, from five different people about five different things.
        let dismissed = report_member(&w, &w.ada.token, &w.bea.user_id).await;
        let actioned = report_member(&w, &w.ada.token, &w.cy.user_id).await;
        let held = report_member(&w, &w.bea.token, &w.cy.user_id).await;
        let open = report_member(&w, &w.cy.token, &w.bea.user_id).await;
        let recent = report_member(&w, &w.cy.token, &w.ada.user_id).await;
        let moderator = &w.moderator.token;
        let (status, _) = work(
            &w,
            moderator,
            &dismissed,
            json!({"status": "dismissed", "note": "not a violation"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        work(&w, moderator, &actioned, json!({"status": "actioned"})).await;
        work(&w, moderator, &held, json!({"status": "dismissed"})).await;
        let (status, _) = work(&w, &w.owner.token, &held, json!({"preserve": true})).await;
        assert_eq!(status, StatusCode::OK);
        work(&w, moderator, &recent, json!({"status": "dismissed"})).await;

        for id in [&dismissed, &actioned, &held, &open] {
            age(&db, id, 100).await;
        }
        // Resolved 10 days ago: inside the default 90.
        age(&db, &recent, 10).await;

        let swept = db::sweep(&db.runtime).await.expect("sweep");
        assert_eq!(swept.reports, 2, "{swept:?}");
        assert!(
            !exists(&db, &dismissed).await,
            "old dismissed report survived"
        );
        assert!(
            !exists(&db, &actioned).await,
            "old actioned report survived"
        );
        assert!(exists(&db, &held).await, "a report on hold was deleted");
        assert!(
            exists(&db, &open).await,
            "an open report was deleted by age"
        );
        assert!(exists(&db, &recent).await, "a recent report was deleted");
        // Their notes went with them.
        let notes: i64 = sqlx::query_scalar("SELECT count(*) FROM report_notes")
            .fetch_one(&db.owner)
            .await
            .expect("notes");
        assert_eq!(notes, 0);
        // A held report is listed, with its hold.
        let (_, list) = call(&w.app, moderator, Method::GET, "/v1/reports", None).await;
        let held_row = list
            .as_array()
            .expect("list")
            .iter()
            .find(|row| row["id"] == json!(held))
            .expect("held report is listed");
        assert_eq!(held_row["preserve"], true);
        // The sweep says what it did in the audit log, with a count and no ids of reports.
        let expired = audit(&w, moderator, "&action=report.expire").await;
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0]["detail"]["count"], 2);
        assert_eq!(expired[0]["actor_id"], Value::Null);

        // A second sweep has nothing to do.
        assert_eq!(db::sweep(&db.runtime).await.expect("sweep").reports, 0);

        // Releasing the hold lets the next sweep take it.
        work(&w, &w.owner.token, &held, json!({"preserve": false})).await;
        assert_eq!(db::sweep(&db.runtime).await.expect("sweep").reports, 1);
        assert!(!exists(&db, &held).await);

        // The retention is the operator's: 7 days from 'recent' resolved 10 days ago.
        let guard = RetentionEnv::set("7");
        assert_eq!(db::retention_days(), 7);
        assert_eq!(db::sweep(&db.runtime).await.expect("sweep").reports, 1);
        assert!(!exists(&db, &recent).await);
        assert!(exists(&db, &open).await, "an open report is never aged out");
        drop(guard);
        assert_eq!(db::retention_days(), 90);

        // The database function itself refuses a retention below a week.
        let error = sqlx::query("SELECT app_reports_sweep(1)")
            .execute(&db.runtime)
            .await
            .expect_err("a day");
        assert_eq!(common::sqlstate(&error), "22023");
    })
    .await;
}

struct RetentionEnv;

impl RetentionEnv {
    fn set(days: &str) -> Self {
        std::env::set_var("TINYSERVER_REPORT_RETENTION_DAYS", days);
        Self
    }
}

impl Drop for RetentionEnv {
    fn drop(&mut self) {
        std::env::remove_var("TINYSERVER_REPORT_RETENTION_DAYS");
    }
}

async fn delete_me(app: &Router, token: &str) {
    let (status, answer) = call(
        app,
        token,
        Method::DELETE,
        "/v1/me",
        Some(json!({"confirm": "delete my account"})),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{answer}");
}

type Row = (Option<String>, Option<String>, Option<String>, i64);

async fn row(db: &TestDb, id: &str) -> Row {
    sqlx::query_as(
        "SELECT reporter_id::text, note, evidence,
                (SELECT count(*) FROM report_notes WHERE report_id = $1::uuid)
         FROM reports WHERE id = $1::uuid",
    )
    .bind(id)
    .fetch_one(&db.owner)
    .await
    .expect("report row")
}

#[tokio::test]
async fn a_reporter_deleting_their_account_loses_the_link_and_a_hold_keeps_the_report() {
    run(|db| async move {
        let w = world(&db).await;
        let filed = |about: &str, tag: &str| {
            json!({"kind": "member", "target_id": about, "category": "harassment",
                   "note": format!("{tag}-NOTE"), "evidence": format!("{tag}-EVIDENCE")})
        };
        let (_, plain) = report(&w, &w.ada.token, filed(&w.bea.user_id, "PLAIN")).await;
        let (_, hold) = report(&w, &w.ada.token, filed(&w.cy.user_id, "HOLD")).await;
        let plain = plain["id"].as_str().expect("id").to_string();
        let hold = hold["id"].as_str().expect("id").to_string();
        let (status, _) = work(&w, &w.owner.token, &hold, json!({"preserve": true})).await;
        assert_eq!(status, StatusCode::OK);
        work(
            &w,
            &w.moderator.token,
            &plain,
            json!({"note": "moderator remark"}),
        )
        .await;

        delete_me(&w.app, &w.ada.token).await;

        // Not preserved: the reporter link and the reporter's own words are gone. The report
        // stays, so a moderator can still see that something was reported and act on it. The
        // moderators' own note is theirs and stays.
        let (reporter, note, evidence, notes) = row(&db, &plain).await;
        assert_eq!((reporter, note, evidence), (None, None, None));
        assert_eq!(notes, 1);
        // Preserved: the report is intact except that it no longer points at the reporter.
        let (reporter, note, evidence, _) = row(&db, &hold).await;
        assert_eq!(reporter, None);
        assert_eq!(note.as_deref(), Some("HOLD-NOTE"));
        assert_eq!(evidence.as_deref(), Some("HOLD-EVIDENCE"));
        let (_, shown) = call(
            &w.app,
            &w.moderator.token,
            Method::GET,
            &format!("/v1/reports/{hold}"),
            None,
        )
        .await;
        assert_eq!(shown["reporter"], Value::Null);
        assert_eq!(shown["evidence"], "HOLD-EVIDENCE");
        assert_eq!(shown["evidence_unverified"], true);
        let (_, shown) = call(
            &w.app,
            &w.moderator.token,
            Method::GET,
            &format!("/v1/reports/{plain}"),
            None,
        )
        .await;
        assert_eq!(shown["reporter"], Value::Null);
        assert_eq!(shown["has_evidence"], false);
        // No row anywhere names her as the reporter.
        let any: i64 =
            sqlx::query_scalar("SELECT count(*) FROM reports WHERE reporter_id = $1::uuid")
                .bind(&w.ada.user_id)
                .fetch_one(&db.owner)
                .await
                .expect("count");
        assert_eq!(any, 0);
    })
    .await;
}

#[tokio::test]
async fn a_person_reported_deleting_their_account_takes_the_evidence_with_them_unless_held() {
    run(|db| async move {
        let w = world(&db).await;
        let filed = |tag: &str| {
            json!({"kind": "member", "target_id": w.cy.user_id, "category": "harassment",
                   "note": format!("{tag}-NOTE"), "evidence": format!("{tag}-EVIDENCE")})
        };
        let (_, plain) = report(&w, &w.ada.token, filed("PLAIN")).await;
        let (_, hold) = report(&w, &w.bea.token, filed("HOLD")).await;
        let plain = plain["id"].as_str().expect("id").to_string();
        let hold = hold["id"].as_str().expect("id").to_string();
        for id in [&plain, &hold] {
            work(
                &w,
                &w.moderator.token,
                id,
                json!({"note": "moderator remark"}),
            )
            .await;
        }
        work(&w, &w.owner.token, &hold, json!({"preserve": true})).await;
        work(
            &w,
            &w.moderator.token,
            &plain,
            json!({"status": "dismissed"}),
        )
        .await;
        work(
            &w,
            &w.moderator.token,
            &hold,
            json!({"status": "dismissed"}),
        )
        .await;

        delete_me(&w.app, &w.cy.token).await;

        // Not preserved: the evidence, the reporter's note and the moderators' notes go. The
        // row stays with its kind, category and outcome.
        let (reporter, note, evidence, notes) = row(&db, &plain).await;
        assert_eq!((note, evidence, notes), (None, None, 0));
        assert_eq!(reporter.as_deref(), Some(w.ada.user_id.as_str()));
        let (_, shown) = call(
            &w.app,
            &w.moderator.token,
            Method::GET,
            &format!("/v1/reports/{plain}"),
            None,
        )
        .await;
        assert_eq!(shown["status"], "dismissed");
        assert_eq!(shown["category"], "harassment");
        assert_eq!(shown["has_evidence"], false);
        // Preserved: nothing changed.
        let (reporter, note, evidence, notes) = row(&db, &hold).await;
        assert_eq!(reporter.as_deref(), Some(w.bea.user_id.as_str()));
        assert_eq!(note.as_deref(), Some("HOLD-NOTE"));
        assert_eq!(evidence.as_deref(), Some("HOLD-EVIDENCE"));
        assert_eq!(notes, 1);
        // A hold survives the sweep and the deletion together.
        age(&db, &hold, 400).await;
        db::sweep(&db.runtime).await.expect("sweep");
        assert!(exists(&db, &hold).await);
    })
    .await;
}

#[tokio::test]
async fn a_banned_or_removed_member_cannot_file_and_a_timed_out_one_can() {
    run(|db| async move {
        let w = world(&db).await;
        let until = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let (status, _) = call(
            &w.app,
            &w.owner.token,
            Method::PUT,
            &format!("/v1/members/{}/timeout", w.ada.user_id),
            Some(json!({"until": until})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, filed) = report(
            &w,
            &w.ada.token,
            json!({"kind": "member", "target_id": w.bea.user_id, "category": "spam"}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "a timed-out member may report: {filed}"
        );

        let (status, _) = call(
            &w.app,
            &w.owner.token,
            Method::POST,
            "/v1/bans",
            Some(json!({"user_id": w.cy.user_id})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, _) = report(
            &w,
            &w.cy.token,
            json!({"kind": "member", "target_id": w.bea.user_id, "category": "spam"}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a banned member has no session"
        );
    })
    .await;
}

#[tokio::test]
async fn existing_clients_and_roles_are_unaffected() {
    run(|db| async move {
        let w = world(&db).await;
        // Every bit an older client knows is still accepted exactly as before, and the new bit
        // is never added to a role on the way.
        let role = new_role(
            &w.app,
            &w.owner.token,
            "Old style",
            1_048_575 & !perm::MANAGE_SERVER,
        )
        .await;
        let (_, roles) = call(&w.app, &w.owner.token, Method::GET, "/v1/roles", None).await;
        let find = |id: &str| -> i64 {
            roles
                .as_array()
                .expect("roles")
                .iter()
                .find(|r| r["id"] == json!(id))
                .and_then(|r| r["permissions"].as_i64())
                .expect("role")
        };
        assert_eq!(find(&role), 1_048_575 & !perm::MANAGE_SERVER);
        let everyone = roles
            .as_array()
            .expect("roles")
            .iter()
            .find(|r| r["default"] == true)
            .and_then(|r| r["permissions"].as_i64())
            .expect("everyone");
        assert_eq!(everyone, perm::EVERYONE);
        assert_eq!(everyone & perm::MANAGE_REPORTS, 0);

        // The owner, and the "Admin" role every upgraded server has, can work reports.
        let (_, me) = call(&w.app, &w.owner.token, Method::GET, "/v1/me", None).await;
        assert_eq!(me["permissions"], perm::ALL);
        assert_eq!(perm::ALL & perm::MANAGE_REPORTS, perm::MANAGE_REPORTS);
        let admin_role: i64 = sqlx::query_scalar(
            "SELECT permissions FROM roles WHERE name = 'Admin' AND NOT is_default",
        )
        .fetch_one(&db.owner)
        .await
        .expect("admin role");
        assert_eq!(admin_role, perm::ALL);
        let (status, _) = call(&w.app, &w.owner.token, Method::GET, "/v1/reports", None).await;
        assert_eq!(status, StatusCode::OK);
        // A permission over 2^21 is dropped as unknown bits always were.
        let (status, role) = call(
            &w.app,
            &w.owner.token,
            Method::POST,
            "/v1/roles",
            Some(json!({"name": "Too much", "permissions": (1u64 << 40) | 1})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{role}");
        assert_eq!(role["permissions"], 1);
    })
    .await;
}

// The upgrade path: a database at migration 0014 with roles that exist today, then 0015.

async fn upgrade_run<F, Fut>(test: F)
where
    F: FnOnce(TestDb) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let (Ok(migrate_url), Ok(runtime_url)) = (
        std::env::var("TEST_DATABASE_URL_MIGRATE"),
        std::env::var("TEST_DATABASE_URL"),
    ) else {
        eprintln!("skipped: TEST_DATABASE_URL_MIGRATE and TEST_DATABASE_URL are not set");
        return;
    };
    std::env::set_var("TINYSERVER_MEDIA_HMAC_SECRET", common::MEDIA_HMAC_SECRET);
    std::env::set_var("TINYSERVER_ALLOW_FAKE_SCAN", "1");
    std::env::remove_var("TINYSERVER_CLAMD_SOCKET");
    let admin = PgConnectOptions::from_str(&migrate_url).expect("migrate url");
    let base_runtime = PgConnectOptions::from_str(&runtime_url).expect("runtime url");
    let mut connection = PgConnection::connect_with(&admin).await.expect("connect");
    let name: String = sqlx::query_scalar(
        "SELECT 'tinyserver_test_' || replace(gen_random_uuid()::text, '-', '')",
    )
    .fetch_one(&mut connection)
    .await
    .expect("name");
    connection
        .execute(format!("CREATE DATABASE {name}").as_str())
        .await
        .expect("create database");
    let owner: PgPool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(admin.clone().database(&name))
        .await
        .expect("owner pool");
    let runtime: PgPool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(base_runtime.clone().database(&name))
        .await
        .expect("runtime pool");
    // Everything before the reports migration.
    let mut before = migrations().await;
    before.migrations = std::borrow::Cow::Owned(
        before
            .migrations
            .iter()
            .filter(|migration| migration.version <= 14)
            .cloned()
            .collect(),
    );
    let outcome = match before.run(&owner).await {
        Ok(()) => Some(
            tokio::spawn(test(TestDb {
                owner: owner.clone(),
                runtime: runtime.clone(),
            }))
            .await,
        ),
        Err(_) => None,
    };
    runtime.close().await;
    owner.close().await;
    let ended = "SELECT pg_terminate_backend(pid) FROM pg_stat_activity
                 WHERE datname = $1 AND usename = current_user AND pid <> pg_backend_pid()";
    if let Ok(mut as_runtime) = PgConnection::connect_with(&base_runtime).await {
        let _ = sqlx::query(ended)
            .bind(&name)
            .execute(&mut as_runtime)
            .await;
        let _ = as_runtime.close().await;
    }
    let _ = sqlx::query(ended)
        .bind(&name)
        .execute(&mut connection)
        .await;
    for attempt in 1..=10 {
        match connection
            .execute(format!("DROP DATABASE IF EXISTS {name}").as_str())
            .await
        {
            Ok(_) => break,
            Err(error) if attempt == 10 => eprintln!("could not drop {name}: {error}"),
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    let _ = connection.close().await;
    match outcome {
        None => panic!("could not migrate to 0014"),
        Some(Err(error)) => std::panic::resume_unwind(error.into_panic()),
        Some(Ok(())) => {}
    }
}

#[tokio::test]
async fn upgrading_grants_manage_reports_to_owners_and_manage_server_roles_only() {
    upgrade_run(|db| async move {
        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let app = api::router(db.runtime.clone(), None);
        let (helper, helper_token) = join(&db, &owner, "helper@tinyserver.test", "member").await;
        let (plain, plain_token) = join(&db, &owner, "plain@tinyserver.test", "member").await;
        let (loud, loud_token) = join(&db, &owner, "loud@tinyserver.test", "member").await;

        // Roles as they exist on a server today, before the feature: the old bit set.
        let manager = new_role_old(&db, "Manager", perm::MANAGE_SERVER | perm::VIEW_CHANNEL).await;
        let plain_role = new_role_old(&db, "Plain", perm::MANAGE_ROLES | perm::KICK_MEMBERS).await;
        // Straight into the table: this database is older than the current code, and the
        // members route reads columns and functions a later migration adds.
        for (user, role) in [(&helper.user_id, &manager), (&plain.user_id, &plain_role)] {
            sqlx::query("INSERT INTO member_roles (user_id, role_id) VALUES ($1::uuid, $2::uuid)")
                .bind(user)
                .bind(role)
                .execute(&db.owner)
                .await
                .expect("give role");
        }
        // Someone gave @everyone manage_server. That must not turn into everyone's reports.
        sqlx::query("UPDATE roles SET permissions = permissions | 524288 WHERE is_default")
            .execute(&db.owner)
            .await
            .expect("everyone manage_server");
        let before_admin: i64 =
            sqlx::query_scalar("SELECT permissions FROM roles WHERE name = 'Admin'")
                .fetch_one(&db.owner)
                .await
                .expect("admin");
        assert_eq!(before_admin, 1_048_575);
        let before_owner: i64 = sqlx::query_scalar("SELECT app_perms_of($1::uuid)")
            .bind(&owner.user_id)
            .fetch_one(&db.owner)
            .await
            .expect("owner perms");
        assert_eq!(before_owner, 1_048_575);
        let _ = loud;

        migrations()
            .await
            .run(&db.owner)
            .await
            .expect("upgrade to latest");

        // A role with manage_server gets it, and keeps what it had.
        assert_eq!(
            role_perms(&db, &manager).await,
            perm::MANAGE_SERVER | perm::VIEW_CHANNEL | perm::MANAGE_REPORTS
        );
        // A role without it does not.
        assert_eq!(
            role_perms(&db, &plain_role).await,
            perm::MANAGE_ROLES | perm::KICK_MEMBERS
        );
        // @everyone keeps its bits and does not gain the new one, even with manage_server.
        let everyone: i64 = sqlx::query_scalar("SELECT permissions FROM roles WHERE is_default")
            .fetch_one(&db.owner)
            .await
            .expect("everyone");
        assert_eq!(everyone, perm::EVERYONE | perm::MANAGE_SERVER);
        assert_eq!(everyone & perm::MANAGE_REPORTS, 0);
        // The Admin role from the three-role days has every bit.
        let admin: i64 = sqlx::query_scalar("SELECT permissions FROM roles WHERE name = 'Admin'")
            .fetch_one(&db.owner)
            .await
            .expect("admin");
        assert_eq!(admin, perm::ALL);
        // Owners have it through the owner flag.
        let owner_perms: i64 = sqlx::query_scalar("SELECT app_perms_of($1::uuid)")
            .bind(&owner.user_id)
            .fetch_one(&db.owner)
            .await
            .expect("owner perms");
        assert_eq!(owner_perms, perm::ALL);
        // And through the API, for real people.
        let (status, _) = call(&app, &owner_token, Method::GET, "/v1/reports", None).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(&app, &helper_token, Method::GET, "/v1/reports", None).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a manage_server role is a moderator after the upgrade"
        );
        let (status, _) = call(&app, &plain_token, Method::GET, "/v1/reports", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = call(&app, &loud_token, Method::GET, "/v1/reports", None).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a plain member is not a moderator because @everyone has manage_server"
        );
    })
    .await;
}

/// A role as 0014 makes one: straight into the table, because the API would need the new bit's
/// range check and this is the shape of data that is already there.
async fn new_role_old(db: &TestDb, name: &str, permissions: i64) -> String {
    sqlx::query_scalar(
        "INSERT INTO roles (name, position, permissions)
         VALUES ($1, (SELECT max(position) + 1 FROM roles), $2)
         RETURNING id::text",
    )
    .bind(name)
    .bind(permissions)
    .fetch_one(&db.owner)
    .await
    .expect("role")
}

async fn role_perms(db: &TestDb, id: &str) -> i64 {
    sqlx::query_scalar("SELECT permissions FROM roles WHERE id = $1::uuid")
        .bind(id)
        .fetch_one(&db.owner)
        .await
        .expect("permissions")
}

/// The migrations as files, read now, so this test does not depend on what was compiled in.
async fn migrations() -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator::new(std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../db/migrations"
    )))
    .await
    .expect("read migrations")
}
