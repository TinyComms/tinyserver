//! Group conversations: find-or-create, list, get, rename, add member, leave, live events,
//! audit privacy, capabilities, and compatibility with directs.

mod common;

use std::collections::HashSet;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use common::live::{connect, durable, ping, serve, Ws};
use common::{first_owner, join, run, session, Call};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

async fn next_type(ws: &mut Ws, kind: &str) -> Value {
    for _ in 0..32 {
        let value = durable(ws).await;
        if value["type"] == kind {
            return value;
        }
    }
    panic!("did not receive {kind}");
}

async fn upload_text(app: &Router, token: &str, name: &str, bytes: &[u8]) -> String {
    let boundary = "TinyGroupBoundary";
    let mut body = Vec::new();
    body.extend(format!("--{boundary}\r\n").as_bytes());
    body.extend(
        format!(
            "Content-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: text/plain\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend(bytes);
    body.extend(format!("\r\n--{boundary}--\r\n").as_bytes());
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/media")
        .header("authorization", format!("Bearer {token}"))
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .expect("request");
    let response = app.clone().oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let value: Value = serde_json::from_slice(&bytes).expect("json");
    value["id"].as_str().expect("attachment id").to_string()
}

#[tokio::test]
async fn group_find_or_create_concurrent_rename_isolation_and_capabilities() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let (a, a_token) = join(&db, &owner, "a-grp@tinyserver.test", "member").await;
        let (b, b_token) = join(&db, &owner, "b-grp@tinyserver.test", "member").await;
        let (c, c_token) = join(&db, &owner, "c-grp@tinyserver.test", "member").await;
        let (d, _d_token) = join(&db, &owner, "d-grp@tinyserver.test", "member").await;
        let app = api::router(db.runtime.clone(), None);

        // GET /v1/capabilities lists "groups".
        let (st, caps) = Call::new(Method::GET, "/v1/capabilities")
            .token(&a_token)
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::OK, "{caps}");
        let features = caps["features"].as_array().expect("features");
        assert!(features.iter().any(|f| f == "groups"), "{caps}");

        // e2ee: true is refused with 400 e2ee_off until #57 lands.
        let (st, err) = Call::new(Method::POST, "/v1/groups")
            .token(&a_token)
            .json(json!({"user_ids": [b.user_id, c.user_id], "e2ee": true}))
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{err}");
        assert_eq!(err["error"], "e2ee_off");

        // Fewer than two others, self, or duplicate -> 400 invalid.
        for bad in [
            json!({"user_ids": [b.user_id]}),
            json!({"user_ids": [a.user_id, b.user_id]}),
            json!({"user_ids": [b.user_id, b.user_id]}),
        ] {
            let (st, err) = Call::new(Method::POST, "/v1/groups")
                .token(&a_token)
                .json(bad)
                .send(&app)
                .await;
            assert_eq!(st, StatusCode::BAD_REQUEST, "{err}");
            assert_eq!(err["error"], "invalid");
        }

        // A creates {A,B,C}: 201.
        let (st, g1) = Call::new(Method::POST, "/v1/groups")
            .token(&a_token)
            .json(json!({"user_ids": [b.user_id, c.user_id], "name": "Alpha"}))
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::CREATED, "{g1}");
        let gid = g1["id"].as_str().expect("group id").to_string();
        assert_eq!(g1["name"], "Alpha");
        assert_eq!(g1["e2ee"], false);
        assert_eq!(g1["plaintext_history"], false);
        assert_eq!(g1["unread"], 0);
        assert!(g1.get("peer").is_none());
        assert!(g1.get("peer_read").is_none());
        assert!(g1.get("last_call").is_none());

        // A creates {A,B,C} again: 200, same id, name unchanged.
        let (st, g2) = Call::new(Method::POST, "/v1/groups")
            .token(&a_token)
            .json(json!({"user_ids": [b.user_id, c.user_id], "name": "Ignored"}))
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::OK, "{g2}");
        assert_eq!(g2["id"], gid);
        assert_eq!(g2["name"], "Alpha");

        // B creates {B,A,C}: 200, same id.
        let (st, g3) = Call::new(Method::POST, "/v1/groups")
            .token(&b_token)
            .json(json!({"user_ids": [a.user_id, c.user_id]}))
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::OK, "{g3}");
        assert_eq!(g3["id"], gid);

        // Two concurrent creates for {A,B,D}: one 201, one 200, one row.
        let (r1, r2) = tokio::join!(
            Call::new(Method::POST, "/v1/groups")
                .token(&a_token)
                .json(json!({"user_ids": [b.user_id, d.user_id]}))
                .send(&app),
            Call::new(Method::POST, "/v1/groups")
                .token(&b_token)
                .json(json!({"user_ids": [a.user_id, d.user_id]}))
                .send(&app),
        );
        let statuses: HashSet<StatusCode> = [r1.0, r2.0].into_iter().collect();
        assert_eq!(
            statuses,
            [StatusCode::CREATED, StatusCode::OK].into_iter().collect(),
            "r1={r1:?} r2={r2:?}"
        );
        assert_eq!(r1.1["id"], r2.1["id"]);

        // Rename works and emits group.updated.
        let (st, renamed) = Call::new(Method::PATCH, &format!("/v1/groups/{gid}"))
            .token(&c_token)
            .json(json!({"name": "Beta"}))
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::OK, "{renamed}");
        assert_eq!(renamed["name"], "Beta");

        // Live isolation: owner O outside the group gets 404 on group, messages, media,
        // and receives no group.* or message.* frame.
        let server = serve(&db, api::Limits::default()).await;
        let (mut ws_o, _) = connect(&server, &owner_token, None).await;
        let (mut ws_b, _) = connect(&server, &b_token, None).await;

        let file_id = upload_text(&app, &a_token, "secret.txt", b"group-only").await;
        let (st, msg) = Call::new(Method::POST, &format!("/v1/conversations/{gid}/messages"))
            .token(&a_token)
            .json(json!({"body": "private to abc", "attachment_ids": [file_id]}))
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::CREATED, "{msg}");

        let frame_b = next_type(&mut ws_b, "message.created").await;
        assert_eq!(frame_b["conversation_id"], gid);
        assert_eq!(frame_b["kind"], "group");
        // Owner's socket sees nothing before pong.
        ping(&mut ws_o).await;

        let (st, _) = Call::new(Method::GET, &format!("/v1/groups/{gid}"))
            .token(&owner_token)
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::NOT_FOUND);
        let (st, _) = Call::new(Method::GET, &format!("/v1/conversations/{gid}/messages"))
            .token(&owner_token)
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::NOT_FOUND);
        let (st, _) = Call::new(Method::GET, &format!("/v1/media/{file_id}"))
            .token(&owner_token)
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::NOT_FOUND);

        // Every group outbox row written so far has a non-NULL, non-empty audience.
        let bad_outbox: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM outbox
             WHERE (topic LIKE 'group.%' OR payload ->> 'kind' = 'group')
               AND (audience IS NULL OR cardinality(audience) = 0)",
        )
        .fetch_one(&db.owner)
        .await
        .expect("outbox check");
        assert_eq!(bad_outbox, 0);

        // GET /v1/directs returns only directs (each with peer), never groups.
        let (st, direct) = Call::new(Method::POST, "/v1/directs")
            .token(&a_token)
            .json(json!({"user_id": b.user_id}))
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::CREATED, "{direct}");
        let (st, directs) = Call::new(Method::GET, "/v1/directs")
            .token(&a_token)
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::OK, "{directs}");
        let directs = directs.as_array().expect("directs array");
        assert_eq!(directs.len(), 1);
        assert!(directs[0]["peer"]["user_id"].is_string());

        // Bots are refused with 403 forbidden.
        let (st, bot) = Call::new(Method::POST, "/v1/bots")
            .token(&owner_token)
            .json(json!({"name": "Helper", "scopes": ["rooms.read"]}))
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::CREATED, "{bot}");
        let bot_token = bot["token"].as_str().expect("bot token");
        let (st, _) = Call::new(Method::GET, "/v1/groups")
            .bot(bot_token)
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::FORBIDDEN);
    })
    .await;
}

#[tokio::test]
async fn group_add_convergence_tiebreak_leave_last_delete_and_audit_privacy() {
    run(|db| async move {
        let upload_dir = std::env::temp_dir().join(format!(
            "tinyserver-groups-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&upload_dir).expect("upload dir");
        std::env::set_var("TINYSERVER_UPLOAD_DIR", &upload_dir);

        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let (a, a_token) = join(&db, &owner, "a-g60@tinyserver.test", "member").await;
        let (b, b_token) = join(&db, &owner, "b-g60@tinyserver.test", "member").await;
        let (c, c_token) = join(&db, &owner, "c-g60@tinyserver.test", "member").await;
        let (d, d_token) = join(&db, &owner, "d-g60@tinyserver.test", "member").await;
        let app = api::router(db.runtime.clone(), None);
        let server = serve(&db, api::Limits::default()).await;

        // Create {A,B,C} and post a message before adding D.
        let (st, g_abc) = Call::new(Method::POST, "/v1/groups")
            .token(&a_token)
            .json(json!({"user_ids": [b.user_id, c.user_id], "name": "Original"}))
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::CREATED, "{g_abc}");
        let gid_abc = g_abc["id"].as_str().expect("gid").to_string();

        let (st, m1) = Call::new(
            Method::POST,
            &format!("/v1/conversations/{gid_abc}/messages"),
        )
        .token(&a_token)
        .json(json!({"body": "before D joined"}))
        .send(&app)
        .await;
        assert_eq!(st, StatusCode::CREATED, "{m1}");
        let m1_id = m1["id"].as_str().expect("m1 id").to_string();

        // Mark read in group emits nothing.
        let before_read: i64 = sqlx::query_scalar("SELECT coalesce(max(id), 0) FROM outbox")
            .fetch_one(&db.owner)
            .await
            .expect("outbox");
        let (st, _) = Call::new(Method::POST, &format!("/v1/conversations/{gid_abc}/read"))
            .token(&b_token)
            .json(json!({"message_id": m1_id}))
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::NO_CONTENT);
        let after_read: i64 = sqlx::query_scalar("SELECT coalesce(max(id), 0) FROM outbox")
            .fetch_one(&db.owner)
            .await
            .expect("outbox");
        assert_eq!(before_read, after_read);

        // Also create a separate {A,B,C,D} first.
        let (st, g_abcd) = Call::new(Method::POST, "/v1/groups")
            .token(&a_token)
            .json(json!({"user_ids": [b.user_id, c.user_id, d.user_id], "name": "Four"}))
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::CREATED, "{g_abcd}");
        let gid_abcd = g_abcd["id"].as_str().expect("gid_abcd").to_string();

        // Connect sockets for A and D, then A adds D to gid_abc (converges with gid_abcd).
        let (mut ws_a, _) = connect(&server, &a_token, None).await;
        let (mut ws_d, _) = connect(&server, &d_token, None).await;

        let (st, added) = Call::new(Method::POST, &format!("/v1/groups/{gid_abc}/members"))
            .token(&a_token)
            .json(json!({"user_id": d.user_id}))
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::CREATED, "{added}");

        // Re-adding D is 200 idempotent.
        let (st, again) = Call::new(Method::POST, &format!("/v1/groups/{gid_abc}/members"))
            .token(&a_token)
            .json(json!({"user_id": d.user_id}))
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::OK, "{again}");

        let ev_a = next_type(&mut ws_a, "group.member_added").await;
        let ev_d = next_type(&mut ws_d, "group.member_added").await;
        assert_eq!(ev_a["group_id"], gid_abc);
        assert_eq!(ev_a["user_id"], d.user_id);
        assert_eq!(ev_d["group_id"], gid_abc);

        // D's unread is 0, and D can read earlier plaintext history.
        let (st, d_view) = Call::new(Method::GET, &format!("/v1/groups/{gid_abc}"))
            .token(&d_token)
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::OK, "{d_view}");
        assert_eq!(d_view["unread"], 0);
        let (st, hist) = Call::new(
            Method::GET,
            &format!("/v1/conversations/{gid_abc}/messages"),
        )
        .token(&d_token)
        .send(&app)
        .await;
        assert_eq!(st, StatusCode::OK, "{hist}");
        assert_eq!(hist[0]["body"], "before D joined");

        // Tie-break: gid_abc has a message while gid_abcd does not -> create {A,B,C,D} returns gid_abc.
        let (st, picked) = Call::new(Method::POST, "/v1/groups")
            .token(&a_token)
            .json(json!({"user_ids": [b.user_id, c.user_id, d.user_id]}))
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::OK, "{picked}");
        assert_eq!(picked["id"], gid_abc);

        // Post a newer message in gid_abcd -> now create {A,B,C,D} returns gid_abcd.
        let file_id = upload_text(&app, &a_token, "cleanup.txt", b"bye").await;
        let file_path = upload_dir.join(&file_id);
        assert!(file_path.exists());
        let (st, _) = Call::new(
            Method::POST,
            &format!("/v1/conversations/{gid_abcd}/messages"),
        )
        .token(&a_token)
        .json(json!({"body": "newer", "attachment_ids": [file_id]}))
        .send(&app)
        .await;
        assert_eq!(st, StatusCode::CREATED);
        let (st, picked2) = Call::new(Method::POST, "/v1/groups")
            .token(&a_token)
            .json(json!({"user_ids": [b.user_id, c.user_id, d.user_id]}))
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::OK, "{picked2}");
        assert_eq!(picked2["id"], gid_abcd);

        // Leave gid_abcd one by one until last member deletes it and cleans up files.
        let (mut ws_c, _) = connect(&server, &c_token, None).await;
        let (st, _) = Call::new(Method::DELETE, &format!("/v1/groups/{gid_abcd}/members/me"))
            .token(&c_token)
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::NO_CONTENT);
        let left_c = next_type(&mut ws_c, "group.member_left").await;
        assert_eq!(left_c["group_id"], gid_abcd);
        assert_eq!(left_c["user_id"], c.user_id);
        let (st, _) = Call::new(Method::GET, &format!("/v1/groups/{gid_abcd}"))
            .token(&c_token)
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::NOT_FOUND);

        for tok in [&b_token, &d_token] {
            let (st, _) = Call::new(Method::DELETE, &format!("/v1/groups/{gid_abcd}/members/me"))
                .token(tok)
                .send(&app)
                .await;
            assert_eq!(st, StatusCode::NO_CONTENT);
        }
        // Last member A leaves -> group.deleted and file removed from disk.
        let (st, _) = Call::new(Method::DELETE, &format!("/v1/groups/{gid_abcd}/members/me"))
            .token(&a_token)
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::NO_CONTENT);
        let deleted_ev = next_type(&mut ws_a, "group.deleted").await;
        assert_eq!(deleted_ev["group_id"], gid_abcd);
        assert!(!file_path.exists(), "attachment file must be removed on last leave");

        // Audit rows for group.* contain no user id other than actor_id (subject_user_id is NULL,
        // detail contains no member user ids).
        let (st, audit) = Call::new(Method::GET, "/v1/audit?action=group.")
            .token(&owner_token)
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::OK, "{audit}");
        let rows = audit.as_array().expect("audit rows");
        assert!(!rows.is_empty());
        for row in rows {
            assert!(row["subject_user_id"].is_null(), "{row}");
            let detail_str = row["detail"].to_string();
            for uid in [&a.user_id, &b.user_id, &c.user_id, &d.user_id] {
                assert!(
                    !detail_str.contains(uid.as_str()),
                    "audit detail leaked member id: {row}"
                );
            }
        }

        let _ = std::fs::remove_dir_all(&upload_dir);
    })
    .await;
}

#[tokio::test]
async fn group_kick_ban_account_delete_emit_member_left_while_timeout_does_not() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let (a, a_token) = join(&db, &owner, "a-g60k@tinyserver.test", "member").await;
        let (b, _b_token) = join(&db, &owner, "b-g60k@tinyserver.test", "member").await;
        let (c, _c_token) = join(&db, &owner, "c-g60k@tinyserver.test", "member").await;
        let (d, d_token) = join(&db, &owner, "d-g60k@tinyserver.test", "member").await;
        let (e, e_token) = join(&db, &owner, "e-g60k@tinyserver.test", "member").await;
        let app = api::router(db.runtime.clone(), None);
        let server = serve(&db, api::Limits::default()).await;

        let (st, grp) = Call::new(Method::POST, "/v1/groups")
            .token(&a_token)
            .json(json!({"user_ids": [b.user_id, c.user_id, d.user_id, e.user_id]}))
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::CREATED, "{grp}");
        let gid = grp["id"].as_str().expect("gid").to_string();

        let (mut ws_a, _) = connect(&server, &a_token, None).await;

        // Timeout E: no group.member_left, E can read and cannot post.
        sqlx::query(
            "UPDATE memberships SET timeout_until = now() + interval '1 day' WHERE user_id = $1::uuid",
        )
        .bind(&e.user_id)
        .execute(&db.owner)
        .await
        .expect("timeout");
        let (st, _) = Call::new(Method::GET, &format!("/v1/groups/{gid}"))
            .token(&e_token)
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::OK);
        let (st, _) = Call::new(Method::POST, &format!("/v1/conversations/{gid}/messages"))
            .token(&e_token)
            .json(json!({"body": "blocked"}))
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::FORBIDDEN);
        ping(&mut ws_a).await;

        // Kick B -> A receives group.member_left for B.
        let (st, _) = Call::new(Method::DELETE, &format!("/v1/members/{}", b.user_id))
            .token(&owner_token)
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::NO_CONTENT);
        let ev = next_type(&mut ws_a, "group.member_left").await;
        assert_eq!(ev["group_id"], gid);
        assert_eq!(ev["user_id"], b.user_id);

        // Ban C -> A receives group.member_left for C.
        let (st, _) = Call::new(Method::POST, "/v1/bans")
            .token(&owner_token)
            .json(json!({"user_id": c.user_id}))
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::CREATED);
        let ev = next_type(&mut ws_a, "group.member_left").await;
        assert_eq!(ev["group_id"], gid);
        assert_eq!(ev["user_id"], c.user_id);

        // Account delete D -> A receives group.member_left for D.
        let (st, _) = Call::new(Method::DELETE, "/v1/me")
            .token(&d_token)
            .json(json!({"confirm": "delete my account"}))
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::NO_CONTENT);
        let ev = next_type(&mut ws_a, "group.member_left").await;
        assert_eq!(ev["group_id"], gid);
        assert_eq!(ev["user_id"], d.user_id);

        assert_ne!(a.user_id, e.user_id);
    })
    .await;
}
