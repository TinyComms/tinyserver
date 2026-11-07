//! Self conversations are encrypted device mailboxes, never two-person calls.

mod common;

use api::Limits;
use common::live::{ask, connect, durable, owner_token, ping, serve};
use common::{first_owner, join, run};
use serde_json::{json, Value};

#[tokio::test]
async fn a_self_conversation_cannot_ring_or_make_its_person_busy() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let token = owner_token(&db).await;
        let (peer, peer_token) = join(&db, &owner, "peer@self-call.test", "member").await;
        let (direct, _) = db::open_direct(&db.runtime, &owner, &peer.user_id, false)
            .await
            .expect("ordinary direct");
        let server = serve(&db, Limits::default()).await;
        let made = reqwest::Client::new()
            .post(format!("http://{}/v1/e2ee/self", server.addr))
            .bearer_auth(&token)
            .send()
            .await
            .expect("self conversation");
        assert_eq!(made.status(), 201);
        let made: Value = serde_json::from_str(&made.text().await.expect("body")).expect("json");
        let self_id = made["conversation_id"].as_str().expect("self id");
        let (mut caller, _) = connect(&server, &token, None).await;
        let (mut sibling, _) = connect(&server, &token, None).await;
        let (mut callee, _) = connect(&server, &peer_token, None).await;

        let refused = ask(
            &mut caller,
            json!({"type": "call.ring", "ref": "self", "direct_id": self_id}),
        )
        .await;
        assert_eq!(
            refused,
            json!({"type": "error", "ref": "self", "code": "not_found"})
        );
        // The next non-presence frame must be pong: no ring fanout to either session.
        for socket in [&mut caller, &mut sibling, &mut callee] {
            ping(socket).await;
        }
        let (mut reconnect, ready) = connect(&server, &token, None).await;
        assert!(ready["ring"].is_null(), "{ready}");
        assert!(ready["direct_call"].is_null(), "{ready}");
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM direct_call_log")
            .fetch_one(&db.owner)
            .await
            .expect("history");
        assert_eq!(count, 0, "the refused self ring writes no history");

        let reply = ask(
            &mut caller,
            json!({"type": "call.ring", "ref": "pair", "direct_id": direct["id"]}),
        )
        .await;
        assert_eq!(reply, json!({"type": "ok", "ref": "pair"}));
        let ringing = durable(&mut caller).await;
        assert_eq!(ringing["type"], "call.ringing");
        assert_eq!(ringing["caller_id"], owner.user_id);
        assert_eq!(ringing["callee_id"], peer.user_id);
        for socket in [&mut sibling, &mut callee, &mut reconnect] {
            let event = durable(socket).await;
            assert_eq!(event["type"], "call.ringing");
            assert_eq!(event["ring_id"], ringing["ring_id"]);
        }
    })
    .await;
}
