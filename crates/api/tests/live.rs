//! `GET /v1/live` through a bound listener against a real Postgres. See `common` for the
//! environment.

mod common;

use std::time::Duration;

use api::Limits;
use common::live::*;
use common::{first_owner, join, run, PASSWORD};
use db::Wrote;
use futures_util::SinkExt;
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::{self, Message};

#[tokio::test]
async fn a_socket_gets_ready_and_answers_ping() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let server = serve(&db, Limits::default()).await;
        let token = owner_token(&db).await;

        let (mut ws, ready) = connect(&server, &token, None).await;
        assert!(ready["seq"].is_i64(), "{ready}");
        assert_eq!(
            ready["me"],
            json!({"user_id": owner.user_id, "role": "owner"})
        );
        assert_eq!(ready["online"], json!([owner.user_id]));
        assert_eq!(ready["calls"], json!([]));

        ping(&mut ws).await;
        ws.send(Message::text(r#"{"type":"call.candidate","ref":"7"}"#))
            .await
            .expect("send");
        assert_eq!(
            durable(&mut ws).await,
            json!({"type": "error", "ref": "7", "code": "unknown_type"})
        );
        ws.send(Message::text(r#"{"type":"call.join","ref":"8"}"#))
            .await
            .expect("send");
        assert_eq!(
            durable(&mut ws).await,
            json!({"type": "error", "ref": "8", "code": "bad_frame"})
        );
        ws.send(Message::text("not json")).await.expect("send");
        assert_eq!(
            durable(&mut ws).await,
            json!({"type": "error", "code": "bad_frame"})
        );
    })
    .await;
}

#[tokio::test]
async fn a_bad_token_is_refused_before_the_upgrade() {
    run(|db| async move {
        first_owner(&db).await;
        let server = serve(&db, Limits::default()).await;
        let token = owner_token(&db).await;

        for (token, query, status) in [
            ("not-a-session", "", 401),
            ("", "", 401),
            (token.as_str(), "?since=-1", 400),
        ] {
            match attempt(&server, token, query).await {
                Err(tungstenite::Error::Http(response)) => {
                    assert_eq!(response.status().as_u16(), status, "{token} {query}");
                }
                Err(error) => panic!("unexpected error: {error}"),
                Ok(_) => panic!("upgraded with {token:?} {query:?}"),
            }
        }
    })
    .await;
}

#[tokio::test]
async fn a_room_the_owner_makes_reaches_a_member() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let (member, member_token) = join(&db, &owner, "member@tinyserver.test", "member").await;
        let server = serve(&db, Limits::default()).await;

        let (mut ws, ready) = connect(&server, &member_token, None).await;
        let made = room(&db, &owner, "Lobby").await;
        let event = durable(&mut ws).await;
        assert_eq!(event["type"], "room.created", "{event}");
        assert!(seq(&event) > seq(&ready));
        assert_eq!(
            event["room"],
            json!({
                "id": made.id,
                "name": "Lobby",
                "created_by": owner.user_id,
                "created_at": made.created_at,
            })
        );

        db::rename_me(&db.runtime, &member, "Renamed")
            .await
            .expect("rename");
        let event = durable(&mut ws).await;
        assert_eq!(event["type"], "member.renamed", "{event}");
        assert_eq!(
            event["member"],
            json!({"user_id": member.user_id, "display_name": "Renamed", "role": "member"})
        );
    })
    .await;
}

#[tokio::test]
async fn invite_events_reach_admins_and_not_members() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let (_, admin_token) = join(&db, &owner, "admin@tinyserver.test", "admin").await;
        let (member, member_token) = join(&db, &owner, "member@tinyserver.test", "member").await;
        let server = serve(&db, Limits::default()).await;
        let (mut admin_ws, _) = connect(&server, &admin_token, None).await;
        let (mut member_ws, _) = connect(&server, &member_token, None).await;

        let Ok(Wrote::Fresh(issued)) = db::create_invite(&db.runtime, &owner, "member", None).await
        else {
            panic!("invite");
        };
        let event = durable(&mut admin_ws).await;
        assert_eq!(event["type"], "invite.created", "{event}");
        assert_eq!(event["invite"]["id"], issued.id);
        assert_eq!(event["invite"]["role"], "member");
        assert_eq!(event["invite"]["accepted_by"], Value::Null);

        db::accept_invite(
            &db.runtime,
            &issued.token,
            "new@tinyserver.test",
            PASSWORD,
            "New",
        )
        .await
        .expect("accept");
        let event = durable(&mut admin_ws).await;
        assert_eq!(event["type"], "invite.accepted", "{event}");
        let joined_id = event["invite"]["accepted_by"].clone();
        assert!(joined_id.is_string(), "{event}");
        let event = durable(&mut admin_ws).await;
        assert_eq!(event["type"], "member.joined", "{event}");
        assert_eq!(
            event["member"],
            json!({"user_id": joined_id, "display_name": "New", "role": "member"})
        );

        let Ok(Wrote::Fresh(second)) = db::create_invite(&db.runtime, &owner, "admin", None).await
        else {
            panic!("invite");
        };
        db::revoke_invite(&db.runtime, &owner, &second.id)
            .await
            .expect("revoke");
        assert_eq!(durable(&mut admin_ws).await["type"], "invite.created");
        let event = durable(&mut admin_ws).await;
        assert_eq!(
            event,
            json!({"type": "invite.revoked", "seq": event["seq"], "invite_id": second.id})
        );

        room(&db, &owner, "After").await;
        // The member saw the join but none of the invite events.
        assert_eq!(durable(&mut member_ws).await["type"], "member.joined");
        assert_eq!(durable(&mut member_ws).await["type"], "room.created");

        // A member promoted to admin starts getting invite events on the same socket.
        db::set_member_role(&db.runtime, &owner, &member.user_id, "admin")
            .await
            .expect("promote");
        let event = durable(&mut member_ws).await;
        assert_eq!(event["type"], "member.role", "{event}");
        assert_eq!(event["member"]["role"], "admin");
        db::create_invite(&db.runtime, &owner, "member", None)
            .await
            .expect("invite");
        assert_eq!(durable(&mut member_ws).await["type"], "invite.created");
    })
    .await;
}

#[tokio::test]
async fn a_socket_resumes_from_since() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let (_, member_token) = join(&db, &owner, "member@tinyserver.test", "member").await;
        let server = serve(&db, Limits::default()).await;

        let (mut ws, ready) = connect(&server, &member_token, None).await;
        let since = seq(&ready);
        ws.close(None).await.expect("close");

        let made = room(&db, &owner, "First").await;
        db::rename_room(&db.runtime, &owner, &made.id, "Second")
            .await
            .expect("rename");

        let (mut ws, ready) = connect(&server, &member_token, Some(since)).await;
        assert_eq!(seq(&ready), since);
        let created = durable(&mut ws).await;
        assert_eq!(created["type"], "room.created", "{created}");
        assert_eq!(created["room"]["name"], "First");
        let renamed = durable(&mut ws).await;
        assert_eq!(renamed["type"], "room.renamed", "{renamed}");
        assert_eq!(renamed["room"]["name"], "Second");
        assert!(since < seq(&created) && seq(&created) < seq(&renamed));

        // Caught up, the same socket carries what happens next.
        db::delete_room(&db.runtime, &owner, &made.id)
            .await
            .expect("delete");
        let deleted = durable(&mut ws).await;
        assert_eq!(
            deleted,
            json!({"type": "room.deleted", "seq": deleted["seq"], "room_id": made.id})
        );
        assert!(seq(&deleted) > seq(&renamed));

        // Resuming from the newest seq replays nothing.
        ws.close(None).await.expect("close");
        let (mut ws, ready) = connect(&server, &member_token, Some(seq(&deleted))).await;
        assert_eq!(seq(&ready), seq(&deleted));
        ping(&mut ws).await;
    })
    .await;
}

#[tokio::test]
async fn too_old_a_since_gets_resync() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let (_, member_token) = join(&db, &owner, "member@tinyserver.test", "member").await;
        room(&db, &owner, "Old").await;
        let kept: i64 = sqlx::query_scalar("SELECT count(*) FROM outbox")
            .fetch_one(&db.owner)
            .await
            .expect("count");
        sqlx::query("UPDATE outbox SET created_at = now() - interval '2 days'")
            .execute(&db.owner)
            .await
            .expect("age the outbox");
        let swept = db::sweep(&db.runtime).await.expect("sweep");
        assert_eq!(swept.events, kept);
        assert!(kept >= 3);
        let server = serve(&db, Limits::default()).await;

        let mut ws = attempt(&server, &member_token, "?since=0")
            .await
            .expect("connect");
        assert_eq!(frame(&mut ws).await, json!({"type": "resync"}));
        assert_eq!(close_code(&mut ws).await, 4002);

        // A seq the server never issued is also resync.
        let mut ws = attempt(&server, &member_token, "?since=999999")
            .await
            .expect("connect");
        assert_eq!(frame(&mut ws).await, json!({"type": "resync"}));
        assert_eq!(close_code(&mut ws).await, 4002);

        // Without since, the socket starts at the pruned head.
        let (_, ready) = connect(&server, &member_token, None).await;
        assert!(seq(&ready) >= kept);
    })
    .await;
}

#[tokio::test]
async fn a_removed_member_is_closed_with_4003() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let (member, member_token) = join(&db, &owner, "member@tinyserver.test", "member").await;
        let server = serve(&db, Limits::default()).await;
        let token = owner_token(&db).await;
        let (mut owner_ws, _) = connect(&server, &token, None).await;
        let (mut ws, _) = connect(&server, &member_token, None).await;

        db::remove_member(&db.runtime, &owner, &member.user_id)
            .await
            .expect("remove");
        let event = durable(&mut ws).await;
        assert_eq!(event["type"], "member.removed", "{event}");
        assert_eq!(event["user_id"], member.user_id);
        assert_eq!(close_code(&mut ws).await, 4003);

        let event = durable(&mut owner_ws).await;
        assert_eq!(event["type"], "member.removed", "{event}");
        ping(&mut owner_ws).await;

        match attempt(&server, &member_token, "").await {
            Err(tungstenite::Error::Http(response)) => assert_eq!(response.status(), 401),
            other => panic!("expected 401, got {:?}", other.map(|_| ())),
        }
    })
    .await;
}

#[tokio::test]
async fn sign_out_and_a_password_change_close_other_sockets() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let (member, first) = join(&db, &owner, "member@tinyserver.test", "member").await;
        let second = db::open_session(&db.runtime, "member@tinyserver.test", PASSWORD)
            .await
            .expect("second session")
            .token;
        let third = db::open_session(&db.runtime, "member@tinyserver.test", PASSWORD)
            .await
            .expect("third session")
            .token;
        let server = serve(&db, Limits::default()).await;
        let (mut first_ws, _) = connect(&server, &first, None).await;
        let (mut second_ws, _) = connect(&server, &second, None).await;
        let (mut third_ws, _) = connect(&server, &third, None).await;

        db::close_session(&db.runtime, &third)
            .await
            .expect("sign out");
        assert_eq!(close_code(&mut third_ws).await, 4001);

        db::change_password(
            &db.runtime,
            &member,
            &first,
            PASSWORD,
            "another-test-password",
        )
        .await
        .expect("change password");
        assert_eq!(close_code(&mut second_ws).await, 4001);
        ping(&mut first_ws).await;

        db::close_all_sessions(&db.runtime, &member)
            .await
            .expect("sign out everywhere");
        assert_eq!(close_code(&mut first_ws).await, 4001);
    })
    .await;
}

#[tokio::test]
async fn a_session_deleted_without_an_event_closes_on_the_next_check() {
    run(|db| async move {
        first_owner(&db).await;
        let limits = Limits {
            recheck: Duration::from_millis(200),
            ..Limits::default()
        };
        let server = serve(&db, limits).await;
        let token = owner_token(&db).await;
        let (mut ws, _) = connect(&server, &token, None).await;
        ping(&mut ws).await;

        sqlx::query("DELETE FROM sessions")
            .execute(&db.owner)
            .await
            .expect("delete sessions");
        assert_eq!(close_code(&mut ws).await, 4001);
    })
    .await;
}

#[tokio::test]
async fn two_sockets_for_one_person_are_one_presence() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let (member, member_token) = join(&db, &owner, "member@tinyserver.test", "member").await;
        let limits = Limits {
            presence_grace: Duration::from_millis(200),
            ..Limits::default()
        };
        let server = serve(&db, limits).await;
        let token = owner_token(&db).await;
        let (mut watcher, ready) = connect(&server, &token, None).await;
        assert_eq!(ready["online"], json!([owner.user_id]));

        let (mut one, _) = connect(&server, &member_token, None).await;
        assert_eq!(
            frame(&mut watcher).await,
            json!({"type": "presence", "user_id": member.user_id, "online": true})
        );
        let (mut two, _) = connect(&server, &member_token, None).await;
        room(&db, &owner, "Marker").await;
        assert_eq!(frame(&mut watcher).await["type"], "room.created");

        let (_, ready) = connect(&server, &token, None).await;
        let mut expected = vec![owner.user_id.clone(), member.user_id.clone()];
        expected.sort();
        assert_eq!(ready["online"], json!(expected));

        one.close(None).await.expect("close");
        tokio::time::sleep(Duration::from_millis(400)).await;
        room(&db, &owner, "Still online").await;
        assert_eq!(frame(&mut watcher).await["type"], "room.created");

        two.close(None).await.expect("close");
        assert_eq!(
            frame(&mut watcher).await,
            json!({"type": "presence", "user_id": member.user_id, "online": false})
        );
    })
    .await;
}

#[tokio::test]
async fn a_rolled_back_write_emits_nothing() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let server = serve(&db, Limits::default()).await;
        let token = owner_token(&db).await;
        let (mut ws, _) = connect(&server, &token, None).await;

        let mut tx = db.runtime.begin().await.expect("begin");
        sqlx::query("SELECT app_emit('room.created', '{\"room\": {\"name\": \"Ghost\"}}')")
            .execute(&mut *tx)
            .await
            .expect("emit");
        tx.rollback().await.expect("rollback");
        let refused = db::set_member_role(&db.runtime, &owner, &owner.user_id, "member").await;
        assert!(matches!(refused, Err(db::CommunityError::LastOwner)));

        room(&db, &owner, "Real").await;
        let event = durable(&mut ws).await;
        assert_eq!(event["room"]["name"], "Real", "{event}");
    })
    .await;
}

#[tokio::test]
async fn the_runtime_role_cannot_write_the_outbox_directly() {
    run(|db| async move {
        first_owner(&db).await;
        let error =
            sqlx::query("INSERT INTO outbox (topic, payload) VALUES ('room.created', '{}')")
                .execute(&db.runtime)
                .await
                .expect_err("insert is revoked");
        assert_eq!(common::sqlstate(&error), "42501");
        let error = sqlx::query("DELETE FROM outbox")
            .execute(&db.runtime)
            .await
            .expect_err("delete is revoked");
        assert_eq!(common::sqlstate(&error), "42501");
    })
    .await;
}

#[tokio::test]
async fn a_fourth_socket_closes_the_oldest() {
    run(|db| async move {
        first_owner(&db).await;
        let server = serve(&db, Limits::default()).await;
        let token = owner_token(&db).await;
        let (mut oldest, _) = connect(&server, &token, None).await;
        let (mut b, _) = connect(&server, &token, None).await;
        let (mut c, _) = connect(&server, &token, None).await;
        let (mut d, _) = connect(&server, &token, None).await;
        assert_eq!(close_code(&mut oldest).await, 4008);
        for ws in [&mut b, &mut c, &mut d] {
            ping(ws).await;
        }
    })
    .await;
}

#[tokio::test]
async fn the_total_cap_refuses_before_the_upgrade() {
    run(|db| async move {
        first_owner(&db).await;
        let limits = Limits {
            sockets_total: 1,
            ..Limits::default()
        };
        let server = serve(&db, limits).await;
        let token = owner_token(&db).await;
        let (mut ws, _) = connect(&server, &token, None).await;
        match attempt(&server, &token, "").await {
            Err(tungstenite::Error::Http(response)) => assert_eq!(response.status(), 503),
            other => panic!("expected 503, got {:?}", other.map(|_| ())),
        }
        ping(&mut ws).await;
    })
    .await;
}

#[tokio::test]
async fn an_oversized_frame_closes_the_socket() {
    run(|db| async move {
        first_owner(&db).await;
        let server = serve(&db, Limits::default()).await;
        let token = owner_token(&db).await;
        let (mut ws, _) = connect(&server, &token, None).await;
        let big = format!(r#"{{"type":"ping","pad":"{}"}}"#, "x".repeat(70 * 1024));
        let _ = ws.send(Message::text(big)).await;
        let code = close_code(&mut ws).await;
        assert_eq!(code, 1009);
    })
    .await;
}

#[tokio::test]
async fn closing_the_hub_closes_sockets_with_restart() {
    run(|db| async move {
        first_owner(&db).await;
        let server = serve(&db, Limits::default()).await;
        let token = owner_token(&db).await;
        let (mut ws, _) = connect(&server, &token, None).await;

        server.live.close();
        assert_eq!(close_code(&mut ws).await, 1012);
        assert!(server.live.closed(WAIT).await);
        assert_eq!(server.live.sockets(), 0);
        match attempt(&server, &token, "").await {
            Err(tungstenite::Error::Http(response)) => assert_eq!(response.status(), 503),
            other => panic!("expected 503, got {:?}", other.map(|_| ())),
        }
    })
    .await;
}

#[tokio::test]
async fn a_join_reaches_everyone_and_later_ready_frames() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let (member, member_token) = join(&db, &owner, "member@tinyserver.test", "member").await;
        let lobby = room(&db, &owner, "Lobby").await;
        let server = serve(&db, Limits::default()).await;
        let token = owner_token(&db).await;
        let (mut owner_ws, ready) = connect(&server, &token, None).await;
        assert_eq!(ready["calls"], json!([]));
        let (mut member_ws, _) = connect(&server, &member_token, None).await;

        enter(&mut member_ws, &lobby.id, &member.user_id).await;
        assert_eq!(durable(&mut owner_ws).await, joined(&lobby.id, &member.user_id));

        let (_, ready) = connect(&server, &token, None).await;
        assert_eq!(
            ready["calls"],
            json!([occupancy(&lobby.id, &[&member.user_id])])
        );

        let reply = ask(
            &mut member_ws,
            json!({"type": "call.join", "ref": 1, "room_id": "00000000-0000-0000-0000-000000000000"}),
        )
        .await;
        assert_eq!(reply, json!({"type": "error", "ref": 1, "code": "not_found"}));
        let reply = ask(
            &mut member_ws,
            json!({"type": "call.join", "ref": 2, "room_id": "not-a-uuid"}),
        )
        .await;
        assert_eq!(reply, json!({"type": "error", "ref": 2, "code": "not_found"}));

        let reply = ask(&mut member_ws, json!({"type": "call.leave", "ref": 3})).await;
        assert_eq!(reply, json!({"type": "ok", "ref": 3}));
        let gone = left(&lobby.id, &member.user_id, "left");
        assert_eq!(durable(&mut member_ws).await, gone);
        assert_eq!(durable(&mut owner_ws).await, gone);
    })
    .await;
}

#[tokio::test]
async fn joining_another_room_leaves_the_first() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let (member, member_token) = join(&db, &owner, "member@tinyserver.test", "member").await;
        let lobby = room(&db, &owner, "Lobby").await;
        let games = room(&db, &owner, "Games").await;
        let server = serve(&db, Limits::default()).await;
        let token = owner_token(&db).await;
        let (mut owner_ws, _) = connect(&server, &token, None).await;
        let (mut member_ws, _) = connect(&server, &member_token, None).await;

        enter(&mut member_ws, &lobby.id, &member.user_id).await;
        assert_eq!(
            durable(&mut owner_ws).await,
            joined(&lobby.id, &member.user_id)
        );

        let reply = ask(
            &mut member_ws,
            json!({"type": "call.join", "ref": "m", "room_id": games.id}),
        )
        .await;
        assert_eq!(reply, json!({"type": "ok", "ref": "m"}));
        for ws in [&mut member_ws, &mut owner_ws] {
            assert_eq!(
                durable(ws).await,
                left(&lobby.id, &member.user_id, "joined_elsewhere")
            );
            assert_eq!(durable(ws).await, joined(&games.id, &member.user_id));
        }
        let (_, ready) = connect(&server, &token, None).await;
        assert_eq!(
            ready["calls"],
            json!([occupancy(&games.id, &[&member.user_id])])
        );
    })
    .await;
}

#[tokio::test]
async fn a_second_socket_for_one_person_is_one_seat() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let (member, member_token) = join(&db, &owner, "member@tinyserver.test", "member").await;
        let lobby = room(&db, &owner, "Lobby").await;
        let limits = Limits {
            presence_grace: Duration::from_millis(200),
            ..Limits::default()
        };
        let server = serve(&db, limits).await;
        let token = owner_token(&db).await;
        let (mut owner_ws, _) = connect(&server, &token, None).await;
        let (mut first, _) = connect(&server, &member_token, None).await;
        let (mut second, _) = connect(&server, &member_token, None).await;

        enter(&mut first, &lobby.id, &member.user_id).await;
        assert_eq!(
            durable(&mut owner_ws).await,
            joined(&lobby.id, &member.user_id)
        );
        assert_eq!(
            durable(&mut second).await,
            joined(&lobby.id, &member.user_id)
        );

        // The seat moves to the second socket with nothing sent to anyone.
        let reply = ask(
            &mut second,
            json!({"type": "call.join", "ref": "again", "room_id": lobby.id}),
        )
        .await;
        assert_eq!(reply, json!({"type": "ok", "ref": "again"}));
        ping(&mut owner_ws).await;

        // The first socket closing does not end a seat it no longer holds.
        first.close(None).await.expect("close");
        tokio::time::sleep(Duration::from_millis(600)).await;
        ping(&mut owner_ws).await;
        let (_, ready) = connect(&server, &token, None).await;
        assert_eq!(
            ready["calls"],
            json!([occupancy(&lobby.id, &[&member.user_id])])
        );
    })
    .await;
}

#[tokio::test]
async fn a_dropped_socket_leaves_its_call_after_the_grace() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let (member, member_token) = join(&db, &owner, "member@tinyserver.test", "member").await;
        let lobby = room(&db, &owner, "Lobby").await;
        let limits = Limits {
            presence_grace: Duration::from_millis(300),
            ..Limits::default()
        };
        let server = serve(&db, limits).await;
        let token = owner_token(&db).await;
        let (mut owner_ws, _) = connect(&server, &token, None).await;
        let (mut member_ws, _) = connect(&server, &member_token, None).await;
        enter(&mut member_ws, &lobby.id, &member.user_id).await;
        assert_eq!(
            durable(&mut owner_ws).await,
            joined(&lobby.id, &member.user_id)
        );

        drop(member_ws);
        let dropped = tokio::time::Instant::now();
        assert_eq!(
            durable(&mut owner_ws).await,
            left(&lobby.id, &member.user_id, "disconnected")
        );
        assert!(dropped.elapsed() >= Duration::from_millis(250));
        let (_, ready) = connect(&server, &token, None).await;
        assert_eq!(ready["calls"], json!([]));
    })
    .await;
}

#[tokio::test]
async fn caps_refuse_a_full_room_and_a_full_server() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let lobby = room(&db, &owner, "Lobby").await;
        let games = room(&db, &owner, "Games").await;
        let mut people = Vec::new();
        for n in 0..3 {
            people.push(join(&db, &owner, &format!("p{n}@tinyserver.test"), "member").await);
        }
        let limits = Limits {
            call_room_max: 2,
            call_server_max: 3,
            ..Limits::default()
        };
        let server = serve(&db, limits).await;
        let mut sockets = Vec::new();
        for (_, token) in &people {
            sockets.push(connect(&server, token, None).await.0);
        }
        let (mut owner_ws, _) = connect(&server, &owner_token(&db).await, None).await;

        for (ws, (person, _)) in sockets.iter_mut().zip(&people).take(2) {
            let reply = answer(
                ws,
                json!({"type": "call.join", "ref": "j", "room_id": lobby.id}),
            )
            .await;
            assert_eq!(
                reply,
                json!({"type": "ok", "ref": "j"}),
                "{}",
                person.user_id
            );
        }
        let third = &mut sockets[2];
        let reply = answer(
            third,
            json!({"type": "call.join", "ref": "x", "room_id": lobby.id}),
        )
        .await;
        assert_eq!(reply, json!({"type": "error", "ref": "x", "code": "full"}));
        let reply = ask(
            third,
            json!({"type": "call.join", "ref": "y", "room_id": games.id}),
        )
        .await;
        assert_eq!(reply, json!({"type": "ok", "ref": "y"}));

        let reply = answer(
            &mut owner_ws,
            json!({"type": "call.join", "ref": "z", "room_id": games.id}),
        )
        .await;
        assert_eq!(
            reply,
            json!({"type": "error", "ref": "z", "code": "server_full"})
        );
    })
    .await;
}

#[tokio::test]
async fn joins_and_leaves_past_the_burst_get_slow_down() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let lobby = room(&db, &owner, "Lobby").await;
        let limits = Limits {
            call_move_burst: 2,
            call_move_every: Duration::from_secs(60),
            ..Limits::default()
        };
        let server = serve(&db, limits).await;
        let (mut ws, _) = connect(&server, &owner_token(&db).await, None).await;

        enter(&mut ws, &lobby.id, &owner.user_id).await;
        let reply = ask(&mut ws, json!({"type": "call.leave", "ref": "l"})).await;
        assert_eq!(reply, json!({"type": "ok", "ref": "l"}));
        assert_eq!(
            durable(&mut ws).await,
            left(&lobby.id, &owner.user_id, "left")
        );
        let reply = ask(
            &mut ws,
            json!({"type": "call.join", "ref": "f", "room_id": lobby.id}),
        )
        .await;
        assert_eq!(
            reply,
            json!({"type": "error", "ref": "f", "code": "slow_down"})
        );
        ping(&mut ws).await;
    })
    .await;
}

#[tokio::test]
async fn deleting_a_room_empties_its_call() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let (member, member_token) = join(&db, &owner, "member@tinyserver.test", "member").await;
        let lobby = room(&db, &owner, "Lobby").await;
        let server = serve(&db, Limits::default()).await;
        let token = owner_token(&db).await;
        let (mut owner_ws, _) = connect(&server, &token, None).await;
        let (mut member_ws, _) = connect(&server, &member_token, None).await;
        enter(&mut owner_ws, &lobby.id, &owner.user_id).await;
        assert_eq!(
            durable(&mut member_ws).await,
            joined(&lobby.id, &owner.user_id)
        );
        enter(&mut member_ws, &lobby.id, &member.user_id).await;
        assert_eq!(
            durable(&mut owner_ws).await,
            joined(&lobby.id, &member.user_id)
        );

        db::delete_room(&db.runtime, &owner, &lobby.id)
            .await
            .expect("delete room");
        // Durable and call frames travel on separate paths, so their order is not fixed.
        let mut seen = Vec::new();
        for _ in 0..3 {
            let mut value = durable(&mut member_ws).await;
            if let Some(object) = value.as_object_mut() {
                object.remove("seq");
            }
            seen.push(value);
        }
        for expected in [
            json!({"type": "room.deleted", "room_id": lobby.id}),
            left(&lobby.id, &owner.user_id, "room_deleted"),
            left(&lobby.id, &member.user_id, "room_deleted"),
        ] {
            assert!(seen.contains(&expected), "{expected} not in {seen:?}");
        }
        let (_, ready) = connect(&server, &token, None).await;
        assert_eq!(ready["calls"], json!([]));
    })
    .await;
}

#[tokio::test]
async fn a_removed_member_leaves_their_call() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let (member, member_token) = join(&db, &owner, "member@tinyserver.test", "member").await;
        let lobby = room(&db, &owner, "Lobby").await;
        let server = serve(&db, Limits::default()).await;
        let token = owner_token(&db).await;
        let (mut owner_ws, _) = connect(&server, &token, None).await;
        let (mut member_ws, _) = connect(&server, &member_token, None).await;
        enter(&mut member_ws, &lobby.id, &member.user_id).await;
        assert_eq!(
            durable(&mut owner_ws).await,
            joined(&lobby.id, &member.user_id)
        );

        db::remove_member(&db.runtime, &owner, &member.user_id)
            .await
            .expect("remove");
        assert_eq!(close_code(&mut member_ws).await, 4003);
        let gone = left(&lobby.id, &member.user_id, "removed");
        loop {
            let value = durable(&mut owner_ws).await;
            if value["type"] == "call.left" {
                assert_eq!(value, gone);
                break;
            }
            assert_eq!(value["type"], "member.removed", "{value}");
        }
        let (_, ready) = connect(&server, &token, None).await;
        assert_eq!(ready["calls"], json!([]));
    })
    .await;
}

#[tokio::test]
async fn owners_and_admins_kick_and_the_kick_is_audited() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let (admin, admin_token) = join(&db, &owner, "admin@tinyserver.test", "admin").await;
        let (member, member_token) = join(&db, &owner, "member@tinyserver.test", "member").await;
        let lobby = room(&db, &owner, "Lobby").await;
        let server = serve(&db, Limits::default()).await;
        let (mut owner_ws, _) = connect(&server, &owner_token(&db).await, None).await;
        let (mut admin_ws, _) = connect(&server, &admin_token, None).await;
        let (mut member_ws, _) = connect(&server, &member_token, None).await;
        enter(&mut owner_ws, &lobby.id, &owner.user_id).await;
        assert_eq!(durable(&mut admin_ws).await, joined(&lobby.id, &owner.user_id));
        assert_eq!(durable(&mut member_ws).await, joined(&lobby.id, &owner.user_id));
        enter(&mut member_ws, &lobby.id, &member.user_id).await;
        assert_eq!(durable(&mut admin_ws).await, joined(&lobby.id, &member.user_id));
        assert_eq!(durable(&mut owner_ws).await, joined(&lobby.id, &member.user_id));

        let kick = |user_id: &str, reference: &str| {
            json!({"type": "call.kick", "ref": reference, "room_id": lobby.id, "user_id": user_id})
        };
        let reply = ask(&mut member_ws, kick(&owner.user_id, "m")).await;
        assert_eq!(reply, json!({"type": "error", "ref": "m", "code": "forbidden"}));
        let reply = ask(&mut admin_ws, kick(&owner.user_id, "o")).await;
        assert_eq!(reply, json!({"type": "error", "ref": "o", "code": "forbidden"}));
        let reply = ask(&mut admin_ws, kick(&admin.user_id, "n")).await;
        assert_eq!(reply, json!({"type": "error", "ref": "n", "code": "not_found"}));

        let reply = ask(&mut admin_ws, kick(&member.user_id, "k")).await;
        assert_eq!(reply, json!({"type": "ok", "ref": "k"}));
        let gone = left(&lobby.id, &member.user_id, "kicked");
        for ws in [&mut admin_ws, &mut member_ws, &mut owner_ws] {
            assert_eq!(durable(ws).await, gone);
        }
        ping(&mut member_ws).await;

        let rows: Vec<(Option<String>, String, Value)> = sqlx::query_as(
            "SELECT actor_id::text, subject, detail FROM audit_log
             WHERE action LIKE 'call.%' ORDER BY id",
        )
        .fetch_all(&db.owner)
        .await
        .expect("audit");
        assert_eq!(
            rows,
            vec![(
                Some(admin.user_id.clone()),
                "call".to_string(),
                json!({"room_id": lobby.id, "user_id": member.user_id}),
            )]
        );
    })
    .await;
}

#[tokio::test]
async fn closing_the_hub_ends_every_call() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let lobby = room(&db, &owner, "Lobby").await;
        let server = serve(&db, Limits::default()).await;
        let (mut ws, _) = connect(&server, &owner_token(&db).await, None).await;
        enter(&mut ws, &lobby.id, &owner.user_id).await;

        server.live.close();
        assert_eq!(close_code(&mut ws).await, 1012);
        assert!(server.live.closed(WAIT).await);
    })
    .await;
}
