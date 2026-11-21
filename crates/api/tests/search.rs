//! Server-side message search over plaintext conversations (issue #69).

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
async fn search_respects_permissions_edits_deletes_encryption_and_pagination() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let (alice, alice_token) = join(&db, &owner, "alice@tinyserver.test", "member").await;
        let (bob, bob_token) = join(&db, &owner, "bob@tinyserver.test", "member").await;
        let app = api::router(db.runtime.clone(), None);

        // Capability advertises `message_search`.
        let caps = get_json(&app, &owner_token, "/v1/capabilities").await;
        let features = caps["features"].as_array().expect("features");
        assert!(features.iter().any(|f| f == "message_search"), "{caps}");

        // Public channel + hidden channel.
        let (status, pub_chan) = Call::new(Method::POST, "/v1/channels")
            .token(&owner_token)
            .json(json!({"name": "public"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED);
        let pub_id = pub_chan["id"].as_str().expect("id").to_string();

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
        assert_eq!(status, StatusCode::CREATED);
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

        // Direct between owner and bob (alice is not in it).
        let (status, dm) = Call::new(Method::POST, "/v1/directs")
            .token(&owner_token)
            .json(json!({"user_id": bob.user_id}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED);
        let dm_id = dm["id"].as_str().expect("id").to_string();

        // Post messages with the word "lantern" in all three.
        let (_, m_pub1) = send_message(
            &app,
            &owner_token,
            &pub_id,
            json!({"body": "first lantern"}),
        )
        .await;
        let m_pub1_id = m_pub1["id"].as_str().expect("id").to_string();
        let (_, m_pub2) = send_message(
            &app,
            &alice_token,
            &pub_id,
            json!({"body": "second lantern"}),
        )
        .await;
        let m_pub2_id = m_pub2["id"].as_str().expect("id").to_string();
        let (_, _) = send_message(
            &app,
            &owner_token,
            &priv_id,
            json!({"body": "secret lantern"}),
        )
        .await;
        let (_, _) =
            send_message(&app, &bob_token, &dm_id, json!({"body": "direct lantern"})).await;

        // Alice sees only the two public hits, newest first, and skipped_encrypted = false.
        let res = get_json(&app, &alice_token, "/v1/search?q=lantern").await;
        assert_eq!(res["skipped_encrypted"], false);
        assert_eq!(res["more"], false);
        let hits = res["hits"].as_array().expect("hits");
        assert_eq!(hits.len(), 2, "{res}");
        assert_eq!(hits[0]["message"]["id"], m_pub2_id);
        assert_eq!(hits[1]["message"]["id"], m_pub1_id);
        assert_eq!(hits[0]["kind"], "channel");
        assert_eq!(hits[0]["conversation_id"], pub_id);

        // Pagination with limit=1 and before=.
        let p1 = get_json(&app, &alice_token, "/v1/search?q=lantern&limit=1").await;
        assert_eq!(p1["more"], true);
        assert_eq!(p1["hits"][0]["message"]["id"], m_pub2_id);
        let p2 = get_json(
            &app,
            &alice_token,
            &format!("/v1/search?q=lantern&limit=1&before={m_pub2_id}"),
        )
        .await;
        assert_eq!(p2["more"], false);
        assert_eq!(p2["hits"][0]["message"]["id"], m_pub1_id);

        // Author filter.
        let by_alice = get_json(
            &app,
            &alice_token,
            &format!("/v1/search?q=lantern&author_id={}", alice.user_id),
        )
        .await;
        assert_eq!(by_alice["hits"].as_array().map(Vec::len), Some(1));
        assert_eq!(by_alice["hits"][0]["message"]["id"], m_pub2_id);

        // Alice searching the hidden channel gets 404.
        let (status, _) = Call::new(
            Method::GET,
            &format!("/v1/search?q=lantern&conversation_id={priv_id}"),
        )
        .token(&alice_token)
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Edit m_pub2: found by new word, not old.
        let (status, _) = Call::new(Method::PATCH, &format!("/v1/messages/{m_pub2_id}"))
            .token(&alice_token)
            .json(json!({"body": "bright compass"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK);
        let after_edit = get_json(&app, &alice_token, "/v1/search?q=lantern").await;
        assert_eq!(after_edit["hits"].as_array().map(Vec::len), Some(1));
        let found_new = get_json(&app, &alice_token, "/v1/search?q=compass").await;
        assert_eq!(found_new["hits"].as_array().map(Vec::len), Some(1));
        assert_eq!(found_new["hits"][0]["message"]["id"], m_pub2_id);

        // Delete m_pub1: no longer returned.
        let (status, _) = Call::new(Method::DELETE, &format!("/v1/messages/{m_pub1_id}"))
            .token(&owner_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let after_del = get_json(&app, &alice_token, "/v1/search?q=lantern").await;
        assert_eq!(after_del["hits"].as_array().map(Vec::len), Some(0));

        // Create an encrypted channel -> skipped_encrypted becomes true.
        let (status, e2ee_chan) = Call::new(Method::POST, "/v1/channels")
            .token(&owner_token)
            .json(json!({"name": "sealed", "e2ee": true}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED);
        let e2ee_id = e2ee_chan["id"].as_str().expect("id").to_string();

        let with_e2ee = get_json(&app, &alice_token, "/v1/search?q=compass").await;
        assert_eq!(with_e2ee["skipped_encrypted"], true);
        let scoped_e2ee = get_json(
            &app,
            &alice_token,
            &format!("/v1/search?q=compass&conversation_id={e2ee_id}"),
        )
        .await;
        assert_eq!(scoped_e2ee["skipped_encrypted"], true);
        assert_eq!(scoped_e2ee["hits"].as_array().map(Vec::len), Some(0));
    })
    .await;
}

#[tokio::test]
async fn search_rate_limits_past_thirty_per_minute_and_validates_query() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let app = api::router(db.runtime.clone(), None);

        // Too short (1 char) -> 400 invalid.
        let (status, err) = Call::new(Method::GET, "/v1/search?q=a")
            .token(&owner_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
        assert_eq!(err["error"], "invalid");

        // 30 searches succeed; 31st is 429 slow_down.
        for i in 0..30 {
            let (status, body) = Call::new(Method::GET, "/v1/search?q=hello")
                .token(&owner_token)
                .send(&app)
                .await;
            assert_eq!(status, StatusCode::OK, "search {i}: {body}");
        }
        let (status, err) = Call::new(Method::GET, "/v1/search?q=hello")
            .token(&owner_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{err}");
        assert_eq!(err["error"], "slow_down");
    })
    .await;
}
