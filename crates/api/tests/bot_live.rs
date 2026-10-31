//! A bot opens `GET /v1/live` with `Authorization: Bot <token>`. It is not a member.
//! `rooms.read` receives room events, `members.read` receives member events, and any
//! other scope receives neither. A bot cannot change a call.

mod common;

use std::time::Duration;

use api::Limits;
use common::live::*;
use common::{first_owner, join, run, TestDb};
use db::Caller;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{self, Message};

async fn issue(db: &TestDb, owner: &Caller, name: &str, scopes: &[&str]) -> db::BotIssued {
    let scopes: Vec<String> = scopes.iter().map(|scope| (*scope).to_string()).collect();
    db::create_bot(&db.runtime, owner, name, &scopes, None)
        .await
        .expect("bot")
}

async fn open_bot(server: &Server, token: &str) -> Result<Ws, tungstenite::Error> {
    let mut request = format!("ws://{}/v1/live", server.addr)
        .into_client_request()
        .expect("request");
    request.headers_mut().insert(
        "authorization",
        format!("Bot {token}").parse().expect("header"),
    );
    tokio_tungstenite::connect_async(request)
        .await
        .map(|(ws, _)| ws)
}

async fn connect_bot(server: &Server, token: &str) -> (Ws, Value) {
    let mut ws = open_bot(server, token).await.expect("connect");
    let ready = frame(&mut ws).await;
    assert_eq!(ready["type"], "ready", "{ready}");
    (ws, ready)
}

fn status_of(error: tungstenite::Error) -> u16 {
    match error {
        tungstenite::Error::Http(response) => response.status().as_u16(),
        other => panic!("unexpected error: {other}"),
    }
}

/// Text frames that arrive after the socket has had a moment to forward queued events.
async fn quiet(ws: &mut Ws) -> Vec<Value> {
    let mut found = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_millis(400), ws.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => {
                found.push(serde_json::from_str(text.as_str()).expect("json"));
            }
            Ok(Some(Ok(Message::Close(close)))) => panic!("closed: {close:?}"),
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(error))) => panic!("socket error: {error}"),
            Ok(None) => panic!("socket ended"),
            Err(_) => return found,
        }
    }
}

/// Reads until every `kinds` value has arrived once. Order does not matter.
async fn saw_all(ws: &mut Ws, kinds: &[&str]) -> Vec<Value> {
    let mut need: Vec<&str> = kinds.to_vec();
    let mut seen = Vec::new();
    while !need.is_empty() {
        let value = frame(ws).await;
        let kind = value["type"].as_str().unwrap_or("").to_string();
        need.retain(|want| *want != kind);
        seen.push(value);
    }
    seen
}

/// Frames that arrive with a ping, including `presence`, up to and not including `pong`.
async fn besides_pong(ws: &mut Ws) -> Vec<Value> {
    ws.send(Message::text(r#"{"type":"ping"}"#))
        .await
        .expect("send ping");
    let mut found = Vec::new();
    loop {
        let value = frame(ws).await;
        if value["type"] == "pong" {
            found.extend(quiet(ws).await);
            return found;
        }
        found.push(value);
    }
}

async fn not_a_member(db: &TestDb, bot_id: &str) {
    let members: i64 =
        sqlx::query_scalar("SELECT count(*) FROM memberships WHERE user_id = $1::uuid")
            .bind(bot_id)
            .fetch_one(&db.owner)
            .await
            .expect("memberships");
    assert_eq!(members, 0);
}

#[tokio::test]
async fn a_bot_with_rooms_read_receives_room_events() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let (member, member_token) = join(&db, &owner, "member@tinyserver.test", "member").await;
        let server = serve(
            &db,
            Limits {
                poll: Duration::from_millis(20),
                ..Limits::default()
            },
        )
        .await;
        let lobby = room(&db, &owner, "Lobby").await;
        let (mut member_ws, _) = connect(&server, &member_token, None).await;
        enter(&mut member_ws, &lobby.id, &member.user_id).await;

        let bot = issue(&db, &owner, "Herald", &["rooms.read"]).await;
        let (mut bot_ws, ready) = connect_bot(&server, &bot.token).await;
        assert_eq!(ready["me"], json!({"user_id": bot.id, "role": "bot"}));
        assert_eq!(ready["online"], json!([]));
        assert_eq!(
            ready["calls"],
            json!([occupancy(&lobby.id, &[member.user_id.as_str()])])
        );
        not_a_member(&db, &bot.id).await;

        let made = room(&db, &owner, "Library").await;
        let event = durable(&mut bot_ws).await;
        assert_eq!(event["type"], "room.created", "{event}");
        assert_eq!(event["room"]["id"], made.id);
        assert_eq!(event["room"]["name"], "Library");

        let seen = durable(&mut member_ws).await;
        assert_eq!(seen["type"], "room.created", "{seen}");

        db::rename_me(&db.runtime, &member, "Renamed")
            .await
            .expect("rename");
        let renamed = durable(&mut member_ws).await;
        assert_eq!(renamed["type"], "member.renamed", "{renamed}");

        let (_other, other_token) = join(&db, &owner, "other@tinyserver.test", "member").await;
        let _other_ws = connect(&server, &other_token, None).await;
        saw_all(&mut member_ws, &["member.joined", "presence"]).await;

        let extra = besides_pong(&mut bot_ws).await;
        assert!(extra.is_empty(), "room scope leaked: {extra:?}");
    })
    .await;
}

#[tokio::test]
async fn a_bot_with_members_read_receives_member_events() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let (member, member_token) = join(&db, &owner, "member@tinyserver.test", "member").await;
        let server = serve(&db, Limits { poll: Duration::from_millis(20), ..Limits::default() }).await;
        let lobby = room(&db, &owner, "Lobby").await;
        let (mut member_ws, _) = connect(&server, &member_token, None).await;
        enter(&mut member_ws, &lobby.id, &member.user_id).await;

        let bot = issue(&db, &owner, "Roll", &["members.read"]).await;
        let (mut bot_ws, ready) = connect_bot(&server, &bot.token).await;
        assert_eq!(ready["me"]["role"], "bot");
        assert_eq!(ready["calls"], json!([]));
        let online = ready["online"].as_array().expect("online");
        assert!(
            online.iter().any(|id| id == &member.user_id),
            "member missing from online: {ready}"
        );

        let (other, other_token) = join(&db, &owner, "other@tinyserver.test", "member").await;
        let _other_ws = connect(&server, &other_token, None).await;
        let seen = saw_all(&mut bot_ws, &["member.joined", "presence"]).await;
        assert!(
            seen.iter().any(|frame| {
                frame["type"] == "member.joined" && frame["member"]["user_id"] == other.user_id
            }),
            "missing member.joined: {seen:?}"
        );
        assert!(
            seen.iter().any(|frame| {
                frame["type"] == "presence"
                    && frame["user_id"] == other.user_id
                    && frame["online"] == true
            }),
            "missing presence: {seen:?}"
        );
        assert!(
            seen.iter()
                .all(|frame| frame["type"] == "member.joined" || frame["type"] == "presence"),
            "member scope leaked: {seen:?}"
        );

        db::rename_me(&db.runtime, &member, "Renamed")
            .await
            .expect("rename");
        let event = durable(&mut bot_ws).await;
        assert_eq!(event["type"], "member.renamed", "{event}");
        assert_eq!(
            event["member"],
            json!({"user_id": member.user_id, "display_name": "Renamed", "role": "member", "owner": false, "roles": [], "avatar": null})
        );

        let _ = room(&db, &owner, "Library").await;
        saw_all(&mut member_ws, &["member.renamed", "room.created"]).await;

        ping(&mut bot_ws).await;
        let extra = quiet(&mut bot_ws).await;
        assert!(extra.is_empty(), "member scope leaked: {extra:?}");
    })
    .await;
}

#[tokio::test]
async fn a_bot_with_no_scope_stays_up_and_receives_no_room_or_member_payload() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let (member, member_token) = join(&db, &owner, "member@tinyserver.test", "member").await;
        let server = serve(&db, Limits { poll: Duration::from_millis(20), ..Limits::default() }).await;
        let lobby = room(&db, &owner, "Lobby").await;
        let (mut member_ws, _) = connect(&server, &member_token, None).await;
        enter(&mut member_ws, &lobby.id, &member.user_id).await;

        let bot = issue(&db, &owner, "Mute", &[]).await;
        let (mut bot_ws, ready) = connect_bot(&server, &bot.token).await;
        assert_eq!(
            ready["me"],
            json!({"user_id": bot.id, "role": "bot"})
        );
        assert_eq!(ready["online"], json!([]));
        assert_eq!(ready["calls"], json!([]));
        not_a_member(&db, &bot.id).await;

        db::rename_me(&db.runtime, &member, "Renamed")
            .await
            .expect("rename");
        let _ = room(&db, &owner, "Library").await;
        let renamed = durable(&mut member_ws).await;
        assert_eq!(renamed["type"], "member.renamed", "{renamed}");
        let created = durable(&mut member_ws).await;
        assert_eq!(created["type"], "room.created", "{created}");

        let (other, other_token) = join(&db, &owner, "other@tinyserver.test", "member").await;
        let (mut other_ws, _) = connect(&server, &other_token, None).await;
        enter(&mut other_ws, &lobby.id, &other.user_id).await;
        saw_all(
            &mut member_ws,
            &["member.joined", "presence", "call.joined"],
        )
        .await;

        let extra = besides_pong(&mut bot_ws).await;
        assert!(extra.is_empty(), "empty scope received: {extra:?}");

        for (kind, body) in [
            (
                "call.join",
                json!({"type": "call.join", "ref": "j", "room_id": lobby.id}),
            ),
            (
                "call.offer",
                json!({"type": "call.offer", "ref": "o", "sdp": "v=0"}),
            ),
            (
                "call.leave",
                json!({"type": "call.leave", "ref": "l"}),
            ),
            (
                "call.state",
                json!({"type": "call.state", "ref": "s", "muted": true, "deafened": false}),
            ),
            (
                "call.kick",
                json!({"type": "call.kick", "ref": "k", "room_id": lobby.id, "user_id": member.user_id}),
            ),
        ] {
            let reference = body["ref"].clone();
            let reply = answer(&mut bot_ws, body).await;
            assert_eq!(reply["type"], "error", "{kind} {reply}");
            assert_eq!(reply["code"], "forbidden", "{kind} {reply}");
            assert_eq!(reply["ref"], reference, "{kind}");
        }
        ping(&mut bot_ws).await;
    })
    .await;
}

#[tokio::test]
async fn a_revoked_or_unknown_bot_token_is_unauthorized() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let server = serve(
            &db,
            Limits {
                poll: Duration::from_millis(20),
                ..Limits::default()
            },
        )
        .await;
        let bot = issue(&db, &owner, "Herald", &["rooms.read"]).await;
        db::revoke_bot(&db.runtime, &owner, &bot.id)
            .await
            .expect("revoke");

        let revoked = open_bot(&server, &bot.token).await.expect_err("revoked");
        assert_eq!(status_of(revoked), 401);
        let unknown = open_bot(&server, "not-a-bot").await.expect_err("unknown");
        assert_eq!(status_of(unknown), 401);
    })
    .await;
}

#[tokio::test]
async fn an_unknown_scope_grants_no_room_or_member_events() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let (member, member_token) = join(&db, &owner, "member@tinyserver.test", "member").await;
        let server = serve(
            &db,
            Limits {
                poll: Duration::from_millis(20),
                ..Limits::default()
            },
        )
        .await;
        let (mut member_ws, _) = connect(&server, &member_token, None).await;

        let bot = issue(&db, &owner, "Writer", &[]).await;
        sqlx::query("UPDATE bots SET scopes = ARRAY['rooms.write'] WHERE id = $1::uuid")
            .bind(&bot.id)
            .execute(&db.owner)
            .await
            .expect("scope");
        let (mut bot_ws, ready) = connect_bot(&server, &bot.token).await;
        assert_eq!(ready["online"], json!([]));
        assert_eq!(ready["calls"], json!([]));

        db::rename_me(&db.runtime, &member, "Renamed")
            .await
            .expect("rename");
        let _ = room(&db, &owner, "Library").await;
        assert_eq!(durable(&mut member_ws).await["type"], "member.renamed");
        assert_eq!(durable(&mut member_ws).await["type"], "room.created");

        let extra = besides_pong(&mut bot_ws).await;
        assert!(extra.is_empty(), "unknown scope received: {extra:?}");
    })
    .await;
}
