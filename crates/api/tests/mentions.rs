//! Mentions in plaintext messages, role mentionability, `mention_everyone`, and unread mention
//! counts (issue #68).

mod common;

use axum::http::{Method, StatusCode};
use common::{first_owner, join, run, session, Call};
use db::perm;
use serde_json::{json, Value};

async fn send_message(
    app: &axum::Router,
    token: &str,
    conversation_id: &str,
    body: Value,
) -> (StatusCode, Value) {
    Call::new(
        Method::POST,
        &format!("/v1/conversations/{conversation_id}/messages"),
    )
    .token(token)
    .json(body)
    .send(app)
    .await
}

async fn get_json(app: &axum::Router, token: &str, path: &str) -> Value {
    let (status, body) = Call::new(Method::GET, path).token(token).send(app).await;
    assert_eq!(status, StatusCode::OK, "{path}: {body}");
    body
}

#[tokio::test]
async fn mentions_validate_store_count_and_clear_on_read_edit_and_delete() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let (_alice, alice_token) = join(&db, &owner, "alice@tinyserver.test", "member").await;
        let (bob, bob_token) = join(&db, &owner, "bob@tinyserver.test", "member").await;
        let (carol, carol_token) = join(&db, &owner, "carol@tinyserver.test", "member").await;
        let app = api::router(db.runtime.clone(), None);

        // Capability advertises `mentions`.
        let caps = get_json(&app, &owner_token, "/v1/capabilities").await;
        let features = caps["features"].as_array().expect("features");
        assert!(features.iter().any(|f| f == "mentions"), "{caps}");

        // Create a channel.
        let (status, chan) = Call::new(Method::POST, "/v1/channels")
            .token(&owner_token)
            .json(json!({"name": "lobby"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{chan}");
        let chan_id = chan["id"].as_str().expect("id").to_string();
        assert_eq!(chan["mentions"].as_i64(), Some(0));

        // Create two roles: one mentionable, one not.
        let (status, pingable) = Call::new(Method::POST, "/v1/roles")
            .token(&owner_token)
            .json(json!({"name": "Helpers", "mentionable": true}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{pingable}");
        assert_eq!(pingable["mentionable"], true);
        let pingable_id = pingable["id"].as_str().expect("id").to_string();

        let (status, quiet_role) = Call::new(Method::POST, "/v1/roles")
            .token(&owner_token)
            .json(json!({"name": "Quiet"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{quiet_role}");
        assert_eq!(quiet_role["mentionable"], false);
        let quiet_role_id = quiet_role["id"].as_str().expect("id").to_string();

        // Assign Carol to both roles.
        let (status, _) = Call::new(
            Method::PUT,
            &format!("/v1/members/{}/roles", carol.user_id),
        )
        .token(&owner_token)
        .json(json!({"role_ids": [&pingable_id, &quiet_role_id]}))
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::OK);

        // Alice (ordinary member, no mention_everyone) mentions Bob, Helpers (mentionable),
        // Quiet (not mentionable -> dropped), everyone (no perm -> dropped),
        // an unknown user (dropped), and an out-of-bounds span (dropped).
        let text = "Hey @Bob @Helpers @Quiet @everyone";
        let (status, msg) = send_message(
            &app,
            &alice_token,
            &chan_id,
            json!({
                "body": text,
                "mentions": [
                    {"kind": "user", "id": bob.user_id, "start": 4, "end": 8},
                    {"kind": "role", "id": pingable_id, "start": 9, "end": 17},
                    {"kind": "role", "id": quiet_role_id, "start": 18, "end": 24},
                    {"kind": "everyone", "start": 25, "end": 34},
                    {"kind": "user", "id": "00000000-0000-4000-8000-000000000000", "start": 0, "end": 3},
                    {"kind": "user", "id": bob.user_id, "start": 0, "end": 999}
                ]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{msg}");
        let msg_id = msg["id"].as_str().expect("id").to_string();
        let mentions = msg["mentions"].as_array().expect("mentions");
        assert_eq!(mentions.len(), 2, "{msg}");
        assert_eq!(mentions[0]["kind"], "user");
        assert_eq!(mentions[0]["id"], bob.user_id);
        assert_eq!(mentions[1]["kind"], "role");
        assert_eq!(mentions[1]["id"], pingable_id);

        // Unread mention counts: Bob has 1, Carol has 1 (via Helpers), Alice has 0 (author),
        // Owner has 0 (everyone was dropped).
        let find_chan = |list: &Value| -> Value {
            list.as_array()
                .expect("channels")
                .iter()
                .find(|c| c["id"] == chan_id)
                .expect("chan")
                .clone()
        };
        assert_eq!(
            find_chan(&get_json(&app, &bob_token, "/v1/channels").await)["mentions"].as_i64(),
            Some(1)
        );
        assert_eq!(
            find_chan(&get_json(&app, &carol_token, "/v1/channels").await)["mentions"].as_i64(),
            Some(1)
        );
        assert_eq!(
            find_chan(&get_json(&app, &alice_token, "/v1/channels").await)["mentions"].as_i64(),
            Some(0)
        );
        assert_eq!(
            find_chan(&get_json(&app, &owner_token, "/v1/channels").await)["mentions"].as_i64(),
            Some(0)
        );

        // Bob marks read -> his mention count drops to 0.
        let (status, _) = Call::new(Method::POST, &format!("/v1/conversations/{chan_id}/read"))
            .token(&bob_token)
            .json(json!({"message_id": msg_id}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(
            find_chan(&get_json(&app, &bob_token, "/v1/channels").await)["mentions"].as_i64(),
            Some(0)
        );

        // Alice edits the message to remove all mentions -> Carol's mention count drops to 0.
        let (status, edited) = Call::new(Method::PATCH, &format!("/v1/messages/{msg_id}"))
            .token(&alice_token)
            .json(json!({"body": "never mind", "mentions": []}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{edited}");
        assert_eq!(edited["mentions"].as_array().map(Vec::len), Some(0));
        assert_eq!(
            find_chan(&get_json(&app, &carol_token, "/v1/channels").await)["mentions"].as_i64(),
            Some(0)
        );

        // Owner posts an @everyone + non-mentionable role mention (owner has mention_everyone).
        let (status, ev_msg) = send_message(
            &app,
            &owner_token,
            &chan_id,
            json!({
                "body": "@everyone @Quiet",
                "mentions": [
                    {"kind": "everyone", "start": 0, "end": 9},
                    {"kind": "role", "id": quiet_role_id, "start": 10, "end": 16}
                ]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{ev_msg}");
        let ev_msg_id = ev_msg["id"].as_str().expect("id").to_string();
        assert_eq!(ev_msg["mentions"].as_array().map(Vec::len), Some(2));
        assert_eq!(
            find_chan(&get_json(&app, &bob_token, "/v1/channels").await)["mentions"].as_i64(),
            Some(1)
        );

        // Deleting that message clears Bob's unread mention count.
        let (status, _) = Call::new(Method::DELETE, &format!("/v1/messages/{ev_msg_id}"))
            .token(&owner_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(
            find_chan(&get_json(&app, &bob_token, "/v1/channels").await)["mentions"].as_i64(),
            Some(0)
        );

        // Private channel: mentioning a member who cannot view the channel is dropped.
        let roles = get_json(&app, &owner_token, "/v1/roles").await;
        let everyone_id = roles
            .as_array()
            .expect("roles")
            .iter()
            .find(|r| r["default"] == true)
            .expect("@everyone")["id"]
            .as_str()
            .expect("id")
            .to_string();
        let (status, priv_chan) = Call::new(Method::POST, "/v1/channels")
            .token(&owner_token)
            .json(json!({"name": "secret"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{priv_chan}");
        let priv_id = priv_chan["id"].as_str().expect("id").to_string();
        let (status, _) = Call::new(
            Method::PUT,
            &format!("/v1/channels/{priv_id}/overrides/{everyone_id}"),
        )
        .token(&owner_token)
        .json(json!({"allow": 0, "deny": perm::VIEW_CHANNEL}))
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, priv_msg) = send_message(
            &app,
            &owner_token,
            &priv_id,
            json!({
                "body": "hi @Bob",
                "mentions": [{"kind": "user", "id": bob.user_id, "start": 3, "end": 7}]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{priv_msg}");
        assert_eq!(priv_msg["mentions"].as_array().map(Vec::len), Some(0));

        // Account deletion clears mention rows pointing at the deleted user.
        let (status, m2) = send_message(
            &app,
            &owner_token,
            &chan_id,
            json!({
                "body": "bye @Bob",
                "mentions": [{"kind": "user", "id": bob.user_id, "start": 4, "end": 8}]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{m2}");
        let m2_id = m2["id"].as_str().expect("id").to_string();
        assert_eq!(m2["mentions"].as_array().map(Vec::len), Some(1));

        let (status, _) = Call::new(Method::DELETE, "/v1/me")
            .token(&bob_token)
            .json(json!({"confirm": "delete my account"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let page = get_json(
            &app,
            &owner_token,
            &format!("/v1/conversations/{chan_id}/messages"),
        )
        .await;
        let fetched = page
            .as_array()
            .expect("page")
            .iter()
            .find(|m| m["id"] == m2_id)
            .expect("m2");
        assert_eq!(fetched["mentions"].as_array().map(Vec::len), Some(0));
    })
    .await;
}

#[tokio::test]
async fn mentions_reject_over_limit_and_refuse_plaintext_on_ciphertext_posts() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let app = api::router(db.runtime.clone(), None);

        let (status, chan) = Call::new(Method::POST, "/v1/channels")
            .token(&owner_token)
            .json(json!({"name": "caps"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED);
        let chan_id = chan["id"].as_str().expect("id").to_string();

        // 51 mentions -> 400 invalid.
        let too_many: Vec<Value> = (0..51)
            .map(|_| json!({"kind": "everyone", "start": 0, "end": 2}))
            .collect();
        let (status, err) = send_message(
            &app,
            &owner_token,
            &chan_id,
            json!({"body": "hi there", "mentions": too_many}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
        assert_eq!(err["error"], "invalid");

        // Encrypted channel refuses plaintext mentions on a ciphertext post.
        let (status, e2ee_chan) = Call::new(Method::POST, "/v1/channels")
            .token(&owner_token)
            .json(json!({"name": "sealed", "e2ee": true}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{e2ee_chan}");
        let e2ee_id = e2ee_chan["id"].as_str().expect("id").to_string();

        let (status, err) = send_message(
            &app,
            &owner_token,
            &e2ee_id,
            json!({
                "ciphertext": "AAAA",
                "epoch": 0,
                "device_id": "00000000-0000-4000-8000-000000000001",
                "kind": "message",
                "mentions": [{"kind": "everyone", "start": 0, "end": 1}]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
        assert_eq!(err["error"], "e2ee_required");
    })
    .await;
}
