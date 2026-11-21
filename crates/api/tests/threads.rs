//! Channel threads (`0054_channel_threads.sql`, issue #73).

mod common;

use axum::http::{Method, StatusCode};
use common::{first_owner, join, run, session, Call};
use db::perm;
use serde_json::json;

#[tokio::test]
async fn channel_threads_filtering_summary_read_cursor_follows_and_permissions() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let (alice, alice_token) = join(&db, &owner, "alice@tinyserver.test", "member").await;
        let (bob, bob_token) = join(&db, &owner, "bob@tinyserver.test", "member").await;
        let app = api::router(db.runtime.clone(), None);

        // Capability advertised.
        let (status, caps) = Call::new(Method::GET, "/v1/capabilities")
            .token(&alice_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{caps}");
        assert!(caps["features"]
            .as_array()
            .expect("features")
            .iter()
            .any(|f| f == "threads"));

        // Two channels + one direct.
        let (_, ch1) = Call::new(Method::POST, "/v1/channels")
            .token(&owner_token)
            .json(json!({"name": "ch1"}))
            .send(&app)
            .await;
        let ch1_id = ch1["id"].as_str().expect("ch1").to_string();

        let (_, ch2) = Call::new(Method::POST, "/v1/channels")
            .token(&owner_token)
            .json(json!({"name": "ch2"}))
            .send(&app)
            .await;
        let ch2_id = ch2["id"].as_str().expect("ch2").to_string();

        let (_, dm) = Call::new(Method::POST, "/v1/directs")
            .token(&owner_token)
            .json(json!({"user_id": alice.user_id}))
            .send(&app)
            .await;
        let dm_id = dm["id"].as_str().expect("dm").to_string();

        // Owner posts root in ch1 and another message in ch1.
        let (status, root) = Call::new(
            Method::POST,
            &format!("/v1/conversations/{ch1_id}/messages"),
        )
        .token(&owner_token)
        .json(json!({"body": "root topic"}))
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::CREATED, "{root}");
        let root_id = root["id"].as_str().expect("root id").to_string();

        let (status, _) = Call::new(
            Method::POST,
            &format!("/v1/conversations/{ch1_id}/messages"),
        )
        .token(&owner_token)
        .json(json!({"body": "second channel message"}))
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::CREATED);

        // Alice replies in the thread.
        let (status, reply1) = Call::new(
            Method::POST,
            &format!("/v1/conversations/{ch1_id}/messages"),
        )
        .token(&alice_token)
        .json(json!({"body": "first reply", "thread_id": root_id}))
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::CREATED, "{reply1}");
        let reply1_id = reply1["id"].as_str().expect("reply1 id").to_string();
        assert_eq!(reply1["thread_id"], root_id);

        // Reply to a reply is refused (400).
        let (status, _) = Call::new(
            Method::POST,
            &format!("/v1/conversations/{ch1_id}/messages"),
        )
        .token(&alice_token)
        .json(json!({"body": "nested", "thread_id": reply1_id}))
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Root in another channel is refused (404).
        let (status, _) = Call::new(
            Method::POST,
            &format!("/v1/conversations/{ch2_id}/messages"),
        )
        .token(&alice_token)
        .json(json!({"body": "wrong channel", "thread_id": root_id}))
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Thread reply in a direct is refused (400).
        let (_, dm_msg) = Call::new(Method::POST, &format!("/v1/conversations/{dm_id}/messages"))
            .token(&owner_token)
            .json(json!({"body": "hi dm"}))
            .send(&app)
            .await;
        let dm_msg_id = dm_msg["id"].as_str().expect("dm msg").to_string();
        let (status, _) = Call::new(Method::POST, &format!("/v1/conversations/{dm_id}/messages"))
            .token(&alice_token)
            .json(json!({"body": "dm thread", "thread_id": dm_msg_id}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // ?threads=1 omits thread replies; plain history includes them.
        let (status, filtered) = Call::new(
            Method::GET,
            &format!("/v1/conversations/{ch1_id}/messages?threads=1"),
        )
        .token(&bob_token)
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::OK);
        let filtered_arr = filtered.as_array().expect("filtered");
        assert_eq!(filtered_arr.len(), 2);
        assert_eq!(filtered_arr[0]["id"], root_id);
        assert_eq!(filtered_arr[0]["thread"]["replies"], 1);
        assert_eq!(filtered_arr[0]["thread"]["unread"], 1);
        assert_eq!(filtered_arr[0]["thread"]["participants"][0], alice.user_id);

        let (status, plain) =
            Call::new(Method::GET, &format!("/v1/conversations/{ch1_id}/messages"))
                .token(&bob_token)
                .send(&app)
                .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(plain.as_array().expect("plain").len(), 3);

        // Thread list returns the reply.
        let (status, thread_list) =
            Call::new(Method::GET, &format!("/v1/messages/{root_id}/thread"))
                .token(&bob_token)
                .send(&app)
                .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(thread_list.as_array().expect("thread_list").len(), 1);
        assert_eq!(thread_list[0]["id"], reply1_id);

        // Bob marks thread read -> clears thread unread without touching channel unread.
        let (status, _) = Call::new(Method::POST, &format!("/v1/messages/{root_id}/thread/read"))
            .token(&bob_token)
            .json(json!({"message_id": reply1_id}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let (_, after_read) = Call::new(
            Method::GET,
            &format!("/v1/conversations/{ch1_id}/messages?threads=1"),
        )
        .token(&bob_token)
        .send(&app)
        .await;
        assert_eq!(after_read[0]["thread"]["unread"], 0);

        let (_, channels) = Call::new(Method::GET, "/v1/channels")
            .token(&bob_token)
            .send(&app)
            .await;
        let ch1_row = channels
            .as_array()
            .expect("channels")
            .iter()
            .find(|c| c["id"] == ch1_id)
            .expect("ch1 row");
        assert_eq!(
            ch1_row["unread"], 2,
            "channel unread untouched by thread read"
        );

        // Owner and Alice auto-followed; Bob follows explicitly then unfollows.
        let (status, owner_threads) = Call::new(Method::GET, "/v1/threads")
            .token(&owner_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(owner_threads.as_array().expect("threads").len(), 1);
        assert_eq!(owner_threads[0]["message_id"], root_id);

        let (status, _) = Call::new(
            Method::PUT,
            &format!("/v1/messages/{root_id}/thread/follow"),
        )
        .token(&bob_token)
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let (_, bob_threads) = Call::new(Method::GET, "/v1/threads")
            .token(&bob_token)
            .send(&app)
            .await;
        assert_eq!(bob_threads.as_array().expect("bob threads").len(), 1);

        let (status, _) = Call::new(
            Method::DELETE,
            &format!("/v1/messages/{root_id}/thread/follow"),
        )
        .token(&bob_token)
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let (_, bob_threads) = Call::new(Method::GET, "/v1/threads")
            .token(&bob_token)
            .send(&app)
            .await;
        assert_eq!(bob_threads.as_array().expect("bob threads").len(), 0);

        // Deny view_channel on ch1 for @everyone -> Bob gets 404 everywhere.
        let (_, roles) = Call::new(Method::GET, "/v1/roles")
            .token(&owner_token)
            .send(&app)
            .await;
        let everyone_id = roles
            .as_array()
            .expect("roles")
            .iter()
            .find(|r| r["default"] == true)
            .expect("everyone")["id"]
            .as_str()
            .expect("id")
            .to_string();
        let (status, _) = Call::new(
            Method::PUT,
            &format!("/v1/channels/{ch1_id}/overrides/{everyone_id}"),
        )
        .token(&owner_token)
        .json(json!({"allow": 0, "deny": perm::VIEW_CHANNEL}))
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::OK);

        for (method, path, body) in [
            (Method::GET, format!("/v1/messages/{root_id}/thread"), None),
            (
                Method::POST,
                format!("/v1/messages/{root_id}/thread/read"),
                Some(json!({"message_id": reply1_id})),
            ),
            (
                Method::PUT,
                format!("/v1/messages/{root_id}/thread/follow"),
                None,
            ),
            (
                Method::DELETE,
                format!("/v1/messages/{root_id}/thread/follow"),
                None,
            ),
        ] {
            let mut call = Call::new(method, &path).token(&bob_token);
            if let Some(body) = body {
                call = call.json(body);
            }
            let (status, _) = call.send(&app).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path} for hidden channel");
        }
        let _ = bob;
    })
    .await;
}
