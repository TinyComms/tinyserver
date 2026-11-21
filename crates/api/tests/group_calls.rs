//! Integration tests for group calls (#63): ringing, late join with real SFU + DAVE MLS
//! Welcome/Remove, old-client compatibility, mid-call group removal, and `group_call_log` /
//! `group.call` / `last_call`.

mod common;

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;
use std::time::Duration;

use api::{Limits, Live};
use axum::http::{Method, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use common::live::*;
use common::{first_owner, join, run, Call, TestDb};
use davey::{DaveSession, ProposalsOperationType};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use sfu::client::{Client, Running};
use sha2::{Digest, Sha256};
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;

const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;
const SLOTS: usize = 11;

fn hashed(label: &[u8], id: &str) -> u64 {
    let digest = Sha256::new()
        .chain_update(label)
        .chain_update(id.as_bytes())
        .finalize();
    u64::from_be_bytes(digest[..8].try_into().expect("8 bytes"))
}

fn mls_user(user_id: &str) -> u64 {
    hashed(b"tiny-e2ee-v1 user ", user_id)
}

fn mls_room(room_id: &str) -> u64 {
    hashed(b"tiny-e2ee-v1 room ", room_id)
}

fn media_config() -> sfu::Config {
    let mut config = sfu::Config::new(SocketAddr::from((LOOPBACK, 0)), LOOPBACK.into());
    config.connect_timeout = Duration::from_millis(2000);
    config.consent_timeout = Duration::from_secs(5);
    config
}

async fn serve_media(db: &TestDb) -> Server {
    let (media, events) = sfu::start(media_config()).expect("start the SFU");
    let live = Live::with_media(db.runtime.clone(), Limits::default(), media, events);
    serve_live(db, live).await
}

async fn send(ws: &mut Ws, value: Value) {
    ws.send(Message::text(value.to_string()))
        .await
        .expect("send");
}

async fn until<T>(ws: &mut Ws, mut pick: impl FnMut(&Value) -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let message = tokio::time::timeout_at(deadline, ws.next())
            .await
            .expect("a matching frame in time")
            .expect("socket open")
            .expect("frame");
        let Message::Text(text) = message else {
            assert!(!message.is_close(), "closed: {message:?}");
            continue;
        };
        let value: Value = serde_json::from_str(text.as_str()).expect("json");
        if let Some(found) = pick(&value) {
            return found;
        }
    }
}

struct GroupApp {
    ws: Ws,
    user_id: String,
    room_id: String,
    _running: Running,
    session: Option<DaveSession>,
    welcomes: usize,
    commits: Vec<u64>,
    seen_types: Vec<String>,
}

async fn dial_group(mut ws: Ws, user_id: &str, group_id: &str, room_id: &str) -> GroupApp {
    let mut client = Client::new(SocketAddr::from((LOOPBACK, 0)), SLOTS).expect("client");
    send(
        &mut ws,
        json!({
            "type": "call.join",
            "ref": "jg",
            "group_id": group_id,
            "sdp": client.offer(),
            "e2ee": 1,
        }),
    )
    .await;
    let answer = until(&mut ws, |v| {
        (v["type"] == "call.answer" || v["type"] == "error").then(|| v.clone())
    })
    .await;
    assert_eq!(answer["type"], "call.answer", "{answer}");
    client
        .accept(answer["sdp"].as_str().expect("sdp"))
        .expect("accept answer");
    let running = client.start(b'g').expect("client thread");
    let deadline = Instant::now() + WAIT;
    while !running.connected() {
        assert!(Instant::now() < deadline, "media did not connect");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    GroupApp {
        ws,
        user_id: user_id.to_string(),
        room_id: room_id.to_string(),
        _running: running,
        session: None,
        welcomes: 0,
        commits: Vec::new(),
        seen_types: Vec::new(),
    }
}

impl GroupApp {
    fn ready(&self) -> bool {
        self.session.as_ref().is_some_and(DaveSession::is_ready)
    }

    fn epoch(&self) -> Option<u64> {
        self.session
            .as_ref()
            .and_then(DaveSession::epoch)
            .map(|e| e.as_u64())
    }

    fn code(&self) -> Option<String> {
        self.session
            .as_ref()
            .and_then(DaveSession::voice_privacy_code)
            .map(str::to_string)
    }

    async fn turn(&mut self, roster: &[u64]) {
        let Ok(Some(Ok(Message::Text(text)))) =
            tokio::time::timeout(Duration::from_millis(20), self.ws.next()).await
        else {
            return;
        };
        let frame: Value = serde_json::from_str(text.as_str()).expect("json");
        if let Some(kind) = frame["type"].as_str() {
            self.seen_types.push(kind.to_string());
        }
        if frame["type"] == "call.e2ee" {
            self.mls(&frame, roster).await;
        }
    }

    async fn mls(&mut self, frame: &Value, roster: &[u64]) {
        assert_eq!(frame["room_id"], self.room_id.as_str());
        let data = || {
            STANDARD
                .decode(frame["data"].as_str().expect("data"))
                .expect("b64")
        };
        match frame["op"].as_str().expect("op") {
            "start" => {
                let sender = STANDARD
                    .decode(frame["external_sender"].as_str().expect("sender"))
                    .expect("b64");
                let mut session = DaveSession::new(
                    NonZeroU16::new(1).expect("one"),
                    mls_user(&self.user_id),
                    mls_room(&self.room_id),
                    None,
                )
                .expect("session");
                session.set_external_sender(&sender).expect("sender");
                let package = session.create_key_package().expect("key package");
                self.session = Some(session);
                send(
                    &mut self.ws,
                    json!({
                        "type": "call.e2ee",
                        "op": "key_package",
                        "data": STANDARD.encode(package),
                    }),
                )
                .await;
            }
            "proposals" => {
                let payload = data();
                let session = self.session.as_mut().expect("session");
                let made = session
                    .process_proposals(ProposalsOperationType::APPEND, &payload[1..], Some(roster))
                    .expect("proposals")
                    .expect("a commit");
                let mut fields = json!({
                    "type": "call.e2ee",
                    "op": "commit",
                    "epoch": frame["epoch"],
                    "data": STANDARD.encode(&made.commit),
                });
                if let Some(welcome) = &made.welcome {
                    fields["welcome"] = json!(STANDARD.encode(welcome));
                }
                send(&mut self.ws, fields).await;
            }
            "commit" => {
                self.commits.push(frame["epoch"].as_u64().expect("epoch"));
                self.session
                    .as_mut()
                    .expect("session")
                    .process_commit(&data())
                    .expect("commit applies");
            }
            "welcome" => {
                self.welcomes += 1;
                self.session
                    .as_mut()
                    .expect("session")
                    .process_welcome(&data())
                    .expect("welcome applies");
            }
            other => panic!("unexpected call.e2ee op {other}"),
        }
    }
}

async fn pump(apps: &mut [&mut GroupApp], roster: &[u64], done: impl Fn(&[&mut GroupApp]) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done(apps) {
        assert!(Instant::now() < deadline, "MLS did not settle in time");
        for app in apps.iter_mut() {
            app.turn(roster).await;
        }
    }
}

#[tokio::test]
async fn group_call_lifecycle_mls_late_join_and_log() {
    run(|db| async move {
        let app = api::app(
            db.runtime.clone(),
            Live::start(db.runtime.clone(), Limits::default()),
            None,
        );
        let owner = first_owner(&db).await;
        let (a, a_tok) = join(&db, &owner, "A", "a@example.com").await;
        let (b, b_tok) = join(&db, &owner, "B", "b@example.com").await;
        let (c, c_tok) = join(&db, &owner, "C", "c@example.com").await;
        let (d, d_tok) = join(&db, &owner, "D", "d@example.com").await;

        let (st, created) = Call::new(Method::POST, "/v1/groups")
            .token(&a_tok)
            .json(json!({"user_ids": [b.user_id, c.user_id, d.user_id], "name": "CallCrew"}))
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::CREATED, "{created}");
        let gid = created["id"].as_str().expect("group id").to_string();

        let server = serve_media(&db).await;
        let (mut ws_a, _) = connect(&server, &a_tok, None).await;
        let (mut ws_b, _) = connect(&server, &b_tok, None).await;
        let (mut ws_c, _) = connect(&server, &c_tok, None).await;
        // D is offline at start.

        // A starts the group call.
        let reply = answer(
            &mut ws_a,
            json!({"type": "call.group.start", "ref": "s1", "group_id": gid}),
        )
        .await;
        assert_eq!(reply, json!({"type": "ok", "ref": "s1"}));

        let started_a = until(&mut ws_a, |v| {
            (v["type"] == "call.group.started").then(|| v.clone())
        })
        .await;
        let call_id = started_a["call_id"].as_str().expect("call_id").to_string();
        let room_id = format!("g:{call_id}");

        let started_b = until(&mut ws_b, |v| {
            (v["type"] == "call.group.started").then(|| v.clone())
        })
        .await;
        assert_eq!(started_b["call_id"], call_id);
        let started_c = until(&mut ws_c, |v| {
            (v["type"] == "call.group.started").then(|| v.clone())
        })
        .await;
        assert_eq!(started_c["call_id"], call_id);

        // C declines.
        let dec = answer(
            &mut ws_c,
            json!({"type": "call.group.decline", "ref": "d1", "group_id": gid, "call_id": call_id}),
        )
        .await;
        assert_eq!(dec, json!({"type": "ok", "ref": "d1"}));

        // A and B join with real media & DAVE MLS.
        let mut app_a = dial_group(ws_a, &a.user_id, &gid, &room_id).await;
        let mut app_b = dial_group(ws_b, &b.user_id, &gid, &room_id).await;
        let roster_ab = [mls_user(&a.user_id), mls_user(&b.user_id)];
        pump(&mut [&mut app_a, &mut app_b], &roster_ab, |xs| {
            xs.iter().all(|x| x.ready()) && xs[0].code() == xs[1].code()
        })
        .await;

        // D connects late, sees the live call in ready.group_calls, joins late and gets a Welcome.
        let (ws_d, ready_d) = connect(&server, &d_tok, None).await;
        let group_calls = ready_d["group_calls"]
            .as_array()
            .expect("ready.group_calls");
        assert_eq!(group_calls.len(), 1);
        assert_eq!(group_calls[0]["group_id"], gid);
        assert_eq!(group_calls[0]["call_id"], call_id);

        let mut app_d = dial_group(ws_d, &d.user_id, &gid, &room_id).await;
        let roster_abd = [
            mls_user(&a.user_id),
            mls_user(&b.user_id),
            mls_user(&d.user_id),
        ];
        pump(
            &mut [&mut app_a, &mut app_b, &mut app_d],
            &roster_abd,
            |xs| {
                xs.iter().all(|x| x.ready()) && xs[0].code() == xs[2].code() && xs[2].welcomes >= 1
            },
        )
        .await;
        let epoch_before_leave = app_b.epoch().expect("epoch");

        // A leaves: call continues, A is removed by the next commit, B & D converge on a higher epoch.
        send(
            &mut app_a.ws,
            json!({"type": "call.leave", "ref": "la", "group_id": gid, "call_id": call_id}),
        )
        .await;
        let roster_bd = [mls_user(&b.user_id), mls_user(&d.user_id)];
        pump(&mut [&mut app_b, &mut app_d], &roster_bd, |xs| {
            xs.iter()
                .all(|x| x.epoch().is_some_and(|e| e > epoch_before_leave))
                && xs[0].code() == xs[1].code()
        })
        .await;

        // B and D leave: call ends cleanly.
        send(
            &mut app_b.ws,
            json!({"type": "call.leave", "ref": "lb", "group_id": gid, "call_id": call_id}),
        )
        .await;
        send(
            &mut app_d.ws,
            json!({"type": "call.leave", "ref": "ld", "group_id": gid, "call_id": call_id}),
        )
        .await;

        let ended = until(&mut ws_c, |v| {
            (v["type"] == "call.group.ended").then(|| v.clone())
        })
        .await;
        assert_eq!(ended["group_id"], gid);
        assert_eq!(ended["call_id"], call_id);
        assert_eq!(ended["outcome"], "ended");

        // Durable group.call event arrives once.
        let durable_call = until(&mut ws_c, |v| {
            (v["type"] == "group.call").then(|| v.clone())
        })
        .await;
        assert_eq!(durable_call["group_id"], gid);
        assert_eq!(durable_call["call_id"], call_id);
        assert_eq!(durable_call["outcome"], "ended");

        // Exactly one row in group_call_log, and GET /v1/groups/{id} returns last_call with mine.
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM group_call_log WHERE id = $1::uuid")
                .bind(&call_id)
                .fetch_one(&db.owner)
                .await
                .expect("count");
        assert_eq!(count, 1);

        let (st, fetched) = Call::new(Method::GET, &format!("/v1/groups/{gid}"))
            .token(&c_tok)
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::OK, "{fetched}");
        assert_eq!(fetched["last_call"]["call_id"], call_id);
        assert_eq!(fetched["last_call"]["outcome"], "ended");
        assert_eq!(fetched["last_call"]["mine"], "declined");
    })
    .await;
}

#[tokio::test]
async fn old_client_sees_only_safe_frame_types_and_mid_call_removal_ends_seat() {
    run(|db| async move {
        let server = serve(&db, Limits::default()).await;
        let app = api::app(db.runtime.clone(), server.live.clone(), None);
        let owner = first_owner(&db).await;
        let (_a, a_tok) = join(&db, &owner, "A", "a@example.com").await;
        let (b, b_tok) = join(&db, &owner, "B", "b@example.com").await;
        let (c, c_tok) = join(&db, &owner, "C", "c@example.com").await;

        let (st, created) = Call::new(Method::POST, "/v1/groups")
            .token(&a_tok)
            .json(json!({"user_ids": [b.user_id, c.user_id]}))
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::CREATED, "{created}");
        let gid = created["id"].as_str().expect("gid").to_string();

        let (mut ws_a, _) = connect(&server, &a_tok, None).await;
        let (mut ws_b, _) = connect(&server, &b_tok, None).await;
        let (mut ws_c, ready_c) = connect(&server, &c_tok, None).await;
        assert!(ready_c.get("ring").is_none());
        assert!(ready_c.get("direct_call").is_none());
        assert!(ready_c["calls"].as_array().expect("calls").is_empty());

        assert_eq!(
            answer(
                &mut ws_a,
                json!({"type": "call.group.start", "ref": "s", "group_id": gid})
            )
            .await,
            json!({"type": "ok", "ref": "s"})
        );
        let started = until(&mut ws_a, |v| {
            (v["type"] == "call.group.started").then(|| v.clone())
        })
        .await;
        let call_id = started["call_id"].as_str().expect("call_id").to_string();

        assert_eq!(
            answer(
                &mut ws_a,
                json!({"type": "call.join", "ref": "ja", "group_id": gid})
            )
            .await,
            json!({"type": "ok", "ref": "ja"})
        );
        assert_eq!(
            answer(
                &mut ws_b,
                json!({"type": "call.join", "ref": "jb", "group_id": gid})
            )
            .await,
            json!({"type": "ok", "ref": "jb"})
        );

        // B leaves the group via HTTP while seated -> receives call.group.left with reason "removed".
        let (st, _) = Call::new(Method::DELETE, &format!("/v1/groups/{gid}/members/me"))
            .token(&b_tok)
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::NO_CONTENT);

        let left_b = until(&mut ws_b, |v| {
            (v["type"] == "call.group.left" && v["user_id"] == b.user_id).then(|| v.clone())
        })
        .await;
        assert_eq!(left_b["group_id"], gid);
        assert_eq!(left_b["call_id"], call_id);
        assert_eq!(left_b["reason"], "removed");

        // A leaves to end the call.
        assert_eq!(
            answer(&mut ws_a, json!({"type": "call.leave", "ref": "la"})).await,
            json!({"type": "ok", "ref": "la"})
        );

        // Drain C (a socket speaking only pre-group-call frames) until call.group.ended and verify
        // exact set of frame types — never call.joined, call.left, call.ringing, or call.state.
        let mut types = HashSet::new();
        loop {
            let v = frame(&mut ws_c).await;
            let t = v["type"].as_str().expect("type").to_string();
            let done = t == "call.group.ended";
            types.insert(t);
            if done {
                break;
            }
        }
        for forbidden in [
            "call.joined",
            "call.left",
            "call.state",
            "call.ringing",
            "call.accepted",
        ] {
            assert!(
                !types.contains(forbidden),
                "old client received forbidden frame type {forbidden}: {types:?}"
            );
        }
        assert!(types.contains("call.group.started"));
        assert!(types.contains("call.group.joined"));
        assert!(types.contains("call.group.left"));
        assert!(types.contains("call.group.ended"));
    })
    .await;
}

/// Joins a direct call with real media + DAVE MLS.
async fn dial_direct(mut ws: Ws, user_id: &str, direct_id: &str, room_id: &str) -> GroupApp {
    let mut client = Client::new(SocketAddr::from((LOOPBACK, 0)), SLOTS).expect("client");
    send(
        &mut ws,
        json!({
            "type": "call.join",
            "ref": "jd",
            "direct_id": direct_id,
            "sdp": client.offer(),
            "e2ee": 1,
        }),
    )
    .await;
    let answer = until(&mut ws, |v| {
        (v["type"] == "call.answer" || v["type"] == "error").then(|| v.clone())
    })
    .await;
    assert_eq!(answer["type"], "call.answer", "{answer}");
    client
        .accept(answer["sdp"].as_str().expect("sdp"))
        .expect("accept answer");
    let running = client.start(b'd').expect("client thread");
    let deadline = Instant::now() + WAIT;
    while !running.connected() {
        assert!(Instant::now() < deadline, "media did not connect");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    GroupApp {
        ws,
        user_id: user_id.to_string(),
        room_id: room_id.to_string(),
        _running: running,
        session: None,
        welcomes: 0,
        commits: Vec::new(),
        seen_types: Vec::new(),
    }
}

#[tokio::test]
async fn direct_call_moves_into_group_call_with_real_media_and_mls() {
    run(|db| async move {
        let server = serve_media(&db).await;
        let app = api::app(db.runtime.clone(), server.live.clone(), None);
        let owner = first_owner(&db).await;
        let (a, a_tok) = join(&db, &owner, "A", "a@example.com").await;
        let (b, b_tok) = join(&db, &owner, "B", "b@example.com").await;
        let (c, c_tok) = join(&db, &owner, "C", "c@example.com").await;

        let (st, direct) = Call::new(Method::POST, "/v1/directs")
            .token(&a_tok)
            .json(json!({"user_id": b.user_id}))
            .send(&app)
            .await;
        assert!(
            st == StatusCode::CREATED || st == StatusCode::OK,
            "{direct}"
        );
        let direct_id = direct["id"].as_str().expect("direct_id").to_string();

        let (mut ws_a, _) = connect(&server, &a_tok, None).await;
        let (mut ws_b, _) = connect(&server, &b_tok, None).await;
        let (mut ws_c, _) = connect(&server, &c_tok, None).await;

        // A rings B, B accepts, both join direct call with real media + MLS.
        assert_eq!(
            answer(
                &mut ws_a,
                json!({"type": "call.ring", "ref": "r1", "direct_id": direct_id})
            )
            .await,
            json!({"type": "ok", "ref": "r1"})
        );
        let ringing = until(&mut ws_b, |v| {
            (v["type"] == "call.ringing").then(|| v.clone())
        })
        .await;
        let ring_id = ringing["ring_id"].as_str().expect("ring_id").to_string();
        assert_eq!(
            answer(
                &mut ws_b,
                json!({"type": "call.accept", "ref": "ac", "direct_id": direct_id})
            )
            .await,
            json!({"type": "ok", "ref": "ac"})
        );
        let direct_room = format!("d:{ring_id}");
        let mut dir_a = dial_direct(ws_a, &a.user_id, &direct_id, &direct_room).await;
        let mut dir_b = dial_direct(ws_b, &b.user_id, &direct_id, &direct_room).await;
        let roster_ab = [mls_user(&a.user_id), mls_user(&b.user_id)];
        pump(&mut [&mut dir_a, &mut dir_b], &roster_ab, |xs| {
            xs.iter().all(|x| x.ready()) && xs[0].code() == xs[1].code()
        })
        .await;
        let direct_code = dir_a.code().expect("direct code");

        // A creates group {A, B, C} and starts group call from the live direct call.
        let (st, created) = Call::new(Method::POST, "/v1/groups")
            .token(&a_tok)
            .json(json!({"user_ids": [b.user_id, c.user_id], "name": "Escalated"}))
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::CREATED, "{created}");
        let gid = created["id"].as_str().expect("gid").to_string();

        assert_eq!(
            answer(
                &mut dir_a.ws,
                json!({
                    "type": "call.group.start",
                    "ref": "mv",
                    "group_id": gid,
                    "from_direct": {"direct_id": direct_id, "ring_id": ring_id},
                }),
            )
            .await,
            json!({"type": "ok", "ref": "mv"})
        );
        let started = until(&mut dir_a.ws, |v| {
            (v["type"] == "call.group.started").then(|| v.clone())
        })
        .await;
        assert_eq!(started["moved_from"]["direct_id"], direct_id);
        assert_eq!(started["moved_from"]["ring_id"], ring_id);
        let call_id = started["call_id"].as_str().expect("call_id").to_string();
        let group_room = format!("g:{call_id}");

        let started_c = until(&mut ws_c, |v| {
            (v["type"] == "call.group.started").then(|| v.clone())
        })
        .await;
        assert_eq!(started_c["call_id"], call_id);

        // Both A and B move into g:{call_id}, and C answers and joins -> fresh MLS group & privacy code!
        let mut grp_a = dial_group(dir_a.ws, &a.user_id, &gid, &group_room).await;
        let mut grp_b = dial_group(dir_b.ws, &b.user_id, &gid, &group_room).await;
        let mut grp_c = dial_group(ws_c, &c.user_id, &gid, &group_room).await;
        let roster_abc = [
            mls_user(&a.user_id),
            mls_user(&b.user_id),
            mls_user(&c.user_id),
        ];
        pump(
            &mut [&mut grp_a, &mut grp_b, &mut grp_c],
            &roster_abc,
            |xs| {
                xs.iter().all(|x| x.ready())
                    && xs[0].code() == xs[1].code()
                    && xs[1].code() == xs[2].code()
            },
        )
        .await;
        assert_ne!(grp_a.code().expect("group code"), direct_code);

        // End the group call and verify one `ended` row in direct_call_log and one in group_call_log.
        for ws in [&mut grp_a.ws, &mut grp_b.ws, &mut grp_c.ws] {
            send(
                ws,
                json!({"type": "call.leave", "ref": "lv", "group_id": gid, "call_id": call_id}),
            )
            .await;
        }
        let _ = until(&mut grp_c.ws, |v| {
            (v["type"] == "call.group.ended").then(|| v.clone())
        })
        .await;
        let _ = until(&mut grp_c.ws, |v| {
            (v["type"] == "group.call").then(|| v.clone())
        })
        .await;

        let direct_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM direct_call_log WHERE id = $1::uuid AND outcome = 'ended'",
        )
        .bind(&ring_id)
        .fetch_one(&db.owner)
        .await
        .expect("direct_call_log");
        assert_eq!(direct_rows, 1);

        let group_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM group_call_log WHERE id = $1::uuid AND outcome = 'ended'",
        )
        .bind(&call_id)
        .fetch_one(&db.owner)
        .await
        .expect("group_call_log");
        assert_eq!(group_rows, 1);
    })
    .await;
}

#[tokio::test]
async fn old_client_peer_ends_with_peer_left_when_direct_moves_to_group() {
    run(|db| async move {
        let server = serve_media(&db).await;
        let app = api::app(db.runtime.clone(), server.live.clone(), None);
        let owner = first_owner(&db).await;
        let (a, a_tok) = join(&db, &owner, "A", "a@example.com").await;
        let (b, b_tok) = join(&db, &owner, "B", "b@example.com").await;
        let (c, _c_tok) = join(&db, &owner, "C", "c@example.com").await;

        let (st, direct) = Call::new(Method::POST, "/v1/directs")
            .token(&a_tok)
            .json(json!({"user_id": b.user_id}))
            .send(&app)
            .await;
        assert!(
            st == StatusCode::CREATED || st == StatusCode::OK,
            "{direct}"
        );
        let direct_id = direct["id"].as_str().expect("direct_id").to_string();

        let (mut ws_a, _) = connect(&server, &a_tok, None).await;
        let (mut ws_b, _) = connect(&server, &b_tok, None).await;

        assert_eq!(
            answer(
                &mut ws_a,
                json!({"type": "call.ring", "ref": "r", "direct_id": direct_id})
            )
            .await,
            json!({"type": "ok", "ref": "r"})
        );
        let ringing = until(&mut ws_b, |v| {
            (v["type"] == "call.ringing").then(|| v.clone())
        })
        .await;
        let ring_id = ringing["ring_id"].as_str().expect("ring_id").to_string();
        assert_eq!(
            answer(
                &mut ws_b,
                json!({"type": "call.accept", "ref": "ac", "direct_id": direct_id})
            )
            .await,
            json!({"type": "ok", "ref": "ac"})
        );
        let direct_room = format!("d:{ring_id}");
        let mut dir_a = dial_direct(ws_a, &a.user_id, &direct_id, &direct_room).await;
        let mut dir_b = dial_direct(ws_b, &b.user_id, &direct_id, &direct_room).await;

        let (st, created) = Call::new(Method::POST, "/v1/groups")
            .token(&a_tok)
            .json(json!({"user_ids": [b.user_id, c.user_id]}))
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::CREATED, "{created}");
        let gid = created["id"].as_str().expect("gid").to_string();

        // A starts group call from direct and moves; old-client B ignores call.group.*.
        assert_eq!(
            answer(
                &mut dir_a.ws,
                json!({
                    "type": "call.group.start",
                    "ref": "mv",
                    "group_id": gid,
                    "from_direct": {"direct_id": direct_id, "ring_id": ring_id},
                }),
            )
            .await,
            json!({"type": "ok", "ref": "mv"})
        );
        let started = until(&mut dir_a.ws, |v| {
            (v["type"] == "call.group.started").then(|| v.clone())
        })
        .await;
        let call_id = started["call_id"].as_str().expect("call_id").to_string();
        let group_room = format!("g:{call_id}");
        let _grp_a = dial_group(dir_a.ws, &a.user_id, &gid, &group_room).await;

        // Wait up to 20s for B to see A leave as `moved` and B's own seat end with `peer_left`.
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut saw_a_moved = false;
        let mut saw_b_peer_left = false;
        while !saw_b_peer_left {
            let msg = tokio::time::timeout_at(deadline, dir_b.ws.next())
                .await
                .expect("B's direct seat did not end with peer_left in time")
                .expect("socket open")
                .expect("frame");
            let Message::Text(text) = msg else {
                continue;
            };
            let v: Value = serde_json::from_str(text.as_str()).expect("json");
            if v["type"] == "call.left" && v["user_id"] == a.user_id {
                assert_eq!(v["reason"], "moved");
                saw_a_moved = true;
            }
            if v["type"] == "call.left" && v["user_id"] == b.user_id {
                assert_eq!(v["reason"], "peer_left");
                saw_b_peer_left = true;
            }
        }
        assert!(saw_a_moved);
    })
    .await;
}

#[tokio::test]
async fn adding_member_to_running_group_call_sends_started_ring_and_welcome() {
    run(|db| async move {
        let server = serve_media(&db).await;
        let app = api::app(db.runtime.clone(), server.live.clone(), None);
        let owner = first_owner(&db).await;
        let (a, a_tok) = join(&db, &owner, "A", "a@example.com").await;
        let (b, b_tok) = join(&db, &owner, "B", "b@example.com").await;
        let (c, _c_tok) = join(&db, &owner, "C", "c@example.com").await;
        let (d, d_tok) = join(&db, &owner, "D", "d@example.com").await;

        let (st, created) = Call::new(Method::POST, "/v1/groups")
            .token(&a_tok)
            .json(json!({"user_ids": [b.user_id, c.user_id]}))
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::CREATED, "{created}");
        let gid = created["id"].as_str().expect("gid").to_string();

        let (mut ws_a, _) = connect(&server, &a_tok, None).await;
        let (ws_b, _) = connect(&server, &b_tok, None).await;
        let (mut ws_d, _) = connect(&server, &d_tok, None).await;

        assert_eq!(
            answer(
                &mut ws_a,
                json!({"type": "call.group.start", "ref": "s", "group_id": gid})
            )
            .await,
            json!({"type": "ok", "ref": "s"})
        );
        let started = until(&mut ws_a, |v| {
            (v["type"] == "call.group.started").then(|| v.clone())
        })
        .await;
        let call_id = started["call_id"].as_str().expect("call_id").to_string();
        let room_id = format!("g:{call_id}");

        let mut app_a = dial_group(ws_a, &a.user_id, &gid, &room_id).await;
        let mut app_b = dial_group(ws_b, &b.user_id, &gid, &room_id).await;
        let roster_ab = [mls_user(&a.user_id), mls_user(&b.user_id)];
        pump(&mut [&mut app_a, &mut app_b], &roster_ab, |xs| {
            xs.iter().all(|x| x.ready()) && xs[0].code() == xs[1].code()
        })
        .await;

        // Add D to the group mid-call: D immediately receives call.group.started.
        let (st, _) = Call::new(Method::POST, &format!("/v1/groups/{gid}/members"))
            .token(&a_tok)
            .json(json!({"user_id": d.user_id}))
            .send(&app)
            .await;
        assert_eq!(st, StatusCode::CREATED);

        let started_d = until(&mut ws_d, |v| {
            (v["type"] == "call.group.started").then(|| v.clone())
        })
        .await;
        assert_eq!(started_d["call_id"], call_id);

        // Seated A rings D via call.group.ring.
        send(
            &mut app_a.ws,
            json!({
                "type": "call.group.ring",
                "ref": "rd",
                "group_id": gid,
                "call_id": call_id,
                "user_ids": [d.user_id],
            }),
        )
        .await;
        let ring_d = until(&mut ws_d, |v| {
            (v["type"] == "call.group.ring" && v["user_id"] == d.user_id).then(|| v.clone())
        })
        .await;
        assert_eq!(ring_d["state"], "ringing");
        assert_eq!(ring_d["by"], a.user_id);

        // D joins and receives a Welcome, converging on the same privacy code as A and B.
        let mut app_d = dial_group(ws_d, &d.user_id, &gid, &room_id).await;
        let roster_abd = [
            mls_user(&a.user_id),
            mls_user(&b.user_id),
            mls_user(&d.user_id),
        ];
        pump(
            &mut [&mut app_a, &mut app_b, &mut app_d],
            &roster_abd,
            |xs| {
                xs.iter().all(|x| x.ready()) && xs[0].code() == xs[2].code() && xs[2].welcomes >= 1
            },
        )
        .await;
    })
    .await;
}
