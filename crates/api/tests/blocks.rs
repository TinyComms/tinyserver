//! Member blocking (`0048_blocks.sql`, issue #65): REST routes, direct message/reaction/typing
//! refusal, direct call ring refusal, unread exclusion, privacy from the blocked user and owner,
//! unblock restoration, and account deletion cascade.

mod common;

use axum::http::{Method, StatusCode};
use common::live::{answer, connect, durable, ping, serve};
use common::{first_owner, join, run, session, Call};
use serde_json::json;

#[tokio::test]
async fn blocking_stops_directs_rings_and_unread_and_stays_private() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let (alice, alice_token) = join(&db, &owner, "alice@tinyserver.test", "member").await;
        let (bob, bob_token) = join(&db, &owner, "bob@tinyserver.test", "member").await;
        let (carol, _carol_token) = join(&db, &owner, "carol@tinyserver.test", "member").await;

        let server = serve(&db, api::Limits::default()).await;
        let app = api::router(db.runtime.clone(), None);

        // Capability is advertised.
        let (status, caps) = Call::new(Method::GET, "/v1/capabilities")
            .token(&owner_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert!(caps["features"]
            .as_array()
            .expect("features")
            .iter()
            .any(|f| f == "blocks"));

        // Bots are refused on block routes.
        let (status, bot) = Call::new(Method::POST, "/v1/bots")
            .token(&owner_token)
            .json(json!({"name": "helper", "scopes": ["members.read"]}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{bot}");
        let bot_token = bot["token"].as_str().expect("bot token").to_string();
        let (status, _) = Call::new(Method::GET, "/v1/blocks")
            .bot(&bot_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = Call::new(Method::PUT, &format!("/v1/blocks/{}", alice.user_id))
            .bot(&bot_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Self-block is 400 invalid; missing user is 404 not_found.
        let (status, _) = Call::new(Method::PUT, &format!("/v1/blocks/{}", bob.user_id))
            .token(&bob_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = Call::new(
            Method::PUT,
            "/v1/blocks/00000000-0000-0000-0000-000000000001",
        )
        .token(&bob_token)
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Open a direct between Alice and Bob and post one message before blocking.
        let (status, direct) = Call::new(Method::POST, "/v1/directs")
            .token(&alice_token)
            .json(json!({"user_id": bob.user_id}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{direct}");
        let direct_id = direct["id"].as_str().expect("direct id").to_string();

        let (status, msg) = Call::new(
            Method::POST,
            &format!("/v1/conversations/{direct_id}/messages"),
        )
        .token(&alice_token)
        .json(json!({"body": "before block"}))
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::CREATED, "{msg}");
        let msg_id = msg["id"].as_str().expect("msg id").to_string();

        // Connect live sockets for Alice and Bob.
        let (mut alice_ws, _) = connect(&server, &alice_token, None).await;
        let (mut bob_ws, _) = connect(&server, &bob_token, None).await;

        // Bob blocks Alice (and idempotent repeat).
        let (status, _) = Call::new(Method::PUT, &format!("/v1/blocks/{}", alice.user_id))
            .token(&bob_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = Call::new(Method::PUT, &format!("/v1/blocks/{}", alice.user_id))
            .token(&bob_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Bob receives `block.updated`; Alice receives nothing.
        let ev = durable(&mut bob_ws).await;
        assert_eq!(ev["type"], "block.updated");
        assert_eq!(ev["user_id"], alice.user_id);
        assert_eq!(ev["blocked"], true);
        ping(&mut alice_ws).await;

        // Only Bob sees the block; Alice and Owner see empty lists.
        let (status, bob_blocks) = Call::new(Method::GET, "/v1/blocks")
            .token(&bob_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bob_blocks.as_array().map(Vec::len), Some(1));
        assert_eq!(bob_blocks[0]["user_id"], alice.user_id);

        let (_, alice_blocks) = Call::new(Method::GET, "/v1/blocks")
            .token(&alice_token)
            .send(&app)
            .await;
        assert_eq!(alice_blocks.as_array().map(Vec::len), Some(0));

        let (_, owner_blocks) = Call::new(Method::GET, "/v1/blocks")
            .token(&owner_token)
            .send(&app)
            .await;
        assert_eq!(owner_blocks.as_array().map(Vec::len), Some(0));

        // Alice cannot post or react in the direct; Bob cannot post either; both can still read.
        let (status, _) = Call::new(
            Method::POST,
            &format!("/v1/conversations/{direct_id}/messages"),
        )
        .token(&alice_token)
        .json(json!({"body": "blocked post"}))
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _) = Call::new(
            Method::POST,
            &format!("/v1/conversations/{direct_id}/messages"),
        )
        .token(&bob_token)
        .json(json!({"body": "one-way blocked"}))
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _) = Call::new(Method::PUT, &format!("/v1/messages/{msg_id}/reactions"))
            .token(&alice_token)
            .json(json!({"emoji": "👍"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, history) = Call::new(
            Method::GET,
            &format!("/v1/conversations/{direct_id}/messages"),
        )
        .token(&alice_token)
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(history.as_array().map(Vec::len), Some(1));

        // Bob blocks Carol (no existing direct) -> Carol cannot open a new direct with Bob.
        let (status, _) = Call::new(Method::PUT, &format!("/v1/blocks/{}", carol.user_id))
            .token(&bob_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let carol_token = session(&db, &carol.user_id).await;
        let (status, _) = Call::new(Method::POST, "/v1/directs")
            .token(&carol_token)
            .json(json!({"user_id": bob.user_id}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Alice's `call.ring` to Bob is refused and does not ring Bob.
        let reply = answer(
            &mut alice_ws,
            json!({"type": "call.ring", "ref": "r1", "direct_id": direct_id}),
        )
        .await;
        assert_eq!(reply["type"], "error");
        assert_eq!(reply["ref"], "r1");
        ping(&mut bob_ws).await;

        // Channel unread for Bob ignores Alice's messages.
        let (_, channels) = Call::new(Method::GET, "/v1/channels")
            .token(&bob_token)
            .send(&app)
            .await;
        let general_id = channels[0]["id"].as_str().expect("general id").to_string();
        let (status, _) = Call::new(
            Method::POST,
            &format!("/v1/conversations/{general_id}/messages"),
        )
        .token(&alice_token)
        .json(json!({"body": "in general"}))
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let (_, channels_for_bob) = Call::new(Method::GET, "/v1/channels")
            .token(&bob_token)
            .send(&app)
            .await;
        let bob_general = channels_for_bob
            .as_array()
            .expect("channels")
            .iter()
            .find(|c| c["id"] == general_id)
            .expect("general");
        assert_eq!(bob_general["unread"].as_i64(), Some(0));

        // Unblocking restores everything and emits `block.updated {blocked: false}`.
        let (status, _) = Call::new(Method::DELETE, &format!("/v1/blocks/{}", alice.user_id))
            .token(&bob_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let mut ev = durable(&mut bob_ws).await;
        while ev["type"] != "block.updated" {
            ev = durable(&mut bob_ws).await;
        }
        assert_eq!(ev["user_id"], alice.user_id);
        assert_eq!(ev["blocked"], false);

        let (status, _) = Call::new(
            Method::POST,
            &format!("/v1/conversations/{direct_id}/messages"),
        )
        .token(&alice_token)
        .json(json!({"body": "after unblock"}))
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::CREATED);

        // Deleting Bob's account cascades his remaining block rows (Carol).
        let (status, _) = Call::new(Method::DELETE, "/v1/me")
            .token(&bob_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let remaining: i64 =
            sqlx::query_scalar("SELECT count(*) FROM blocks WHERE blocker_id = $1::uuid")
                .bind(&bob.user_id)
                .fetch_one(&db.owner)
                .await
                .expect("count blocks");
        assert_eq!(remaining, 0);
    })
    .await;
}
