//! Calls with media: headless str0m clients join over the live socket and send audio through
//! the SFU on loopback. See `common` for the environment.

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use api::{Limits, Live};
use axum::http::{Method, StatusCode};
use common::live::*;
use common::{first_owner, join, run, Call, TestDb};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use sfu::client::{Client, Frame, Running, VideoFrame};
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;

const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;
const SLOTS: usize = 11;

fn media_config() -> sfu::Config {
    let mut config = sfu::Config::new(SocketAddr::from((LOOPBACK, 0)), LOOPBACK.into());
    config.connect_timeout = Duration::from_millis(1500);
    // A silent str0m client still sends a STUN check or RTCP about every 3 s.
    config.consent_timeout = Duration::from_secs(5);
    config
}

async fn serve_media(db: &TestDb) -> Server {
    serve_media_with(db, media_config()).await
}

async fn serve_media_with(db: &TestDb, config: sfu::Config) -> Server {
    let (media, events) = sfu::start(config).expect("start the SFU");
    let live = Live::with_media(db.runtime.clone(), Limits::default(), media, events);
    serve_live(db, live).await
}

/// Reads frames until `pick` returns something, skipping the rest. Panics after 10 s, which
/// is longer than the consent timeout.
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

/// Waits for this socket's `call.slots` with `want` entries and returns `user_id` to mid.
async fn slots(ws: &mut Ws, call_id: &str, want: usize) -> Vec<(String, String)> {
    until(ws, |value| {
        let audio = value["audio"].as_array()?;
        if value["type"] != "call.slots" || value["call_id"] != call_id || audio.len() != want {
            return None;
        }
        assert_eq!(value["video"], Value::Null);
        Some(
            audio
                .iter()
                .map(|slot| {
                    let user_id = slot["user_id"].as_str().unwrap_or_default().to_string();
                    let mid = slot["mid"].as_str().unwrap_or_default().to_string();
                    (user_id, mid)
                })
                .collect(),
        )
    })
    .await
}

fn mid_for(slots: &[(String, String)], user_id: &str) -> String {
    slots
        .iter()
        .find(|(holder, _)| holder == user_id)
        .map(|(_, mid)| mid.clone())
        .expect("a slot for that person")
}

/// One person in a call with media.
struct Person {
    ws: Ws,
    user_id: String,
    call_id: String,
    running: Running,
}

/// Joins `room_id` with a fresh offer, takes the answer, and waits until the client side of
/// media is up. The SFU may see it a round trip later.
async fn dial(ws: Ws, user_id: &str, room_id: &str, marker: u8) -> Person {
    let client = Client::new(SocketAddr::from((LOOPBACK, 0)), SLOTS).expect("client");
    dial_with(ws, client, user_id, room_id, marker).await
}

/// `dial` with `client`, which may be a TCP one.
async fn dial_with(
    mut ws: Ws,
    mut client: Client,
    user_id: &str,
    room_id: &str,
    marker: u8,
) -> Person {
    let request =
        json!({"type": "call.join", "ref": "j", "room_id": room_id, "sdp": client.offer()});
    ws.send(Message::text(request.to_string()))
        .await
        .expect("send");
    let answer = until(&mut ws, |value| {
        (value["type"] == "call.answer" || value["type"] == "error").then(|| value.clone())
    })
    .await;
    assert_eq!(answer["type"], "call.answer", "{answer}");
    assert_eq!(answer["ref"], "j");
    let call_id = answer["call_id"].as_str().expect("call id").to_string();
    let sdp = answer["sdp"].as_str().expect("sdp");
    assert!(sdp.contains("a=ice-lite"), "{sdp}");
    assert!(sdp.contains("127.0.0.1"), "{sdp}");
    client.accept(sdp).expect("accept the answer");
    let running = client.start(marker).expect("client thread");
    let deadline = Instant::now() + WAIT;
    while !running.connected() {
        assert!(Instant::now() < deadline, "media did not connect");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Person {
        ws,
        user_id: user_id.to_string(),
        call_id,
        running,
    }
}

/// Waits until `person` has received a frame tagged `marker` on `mid`.
async fn hears(person: &Person, mid: &str, marker: u8) {
    let want = Frame {
        mid: mid.to_string(),
        marker,
    };
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if person.running.take().contains(&want) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no frame from {marker} on mid {mid} within 2 s");
}

/// Frames `person` receives over `period`, from a clean start.
async fn heard_over(person: &Person, period: Duration) -> Vec<Frame> {
    person.running.take();
    tokio::time::sleep(period).await;
    person.running.take()
}

/// Waits until `person` has received a camera frame from `marker`, and returns the frames
/// from the first one of `marker`'s on.
async fn sees(person: &Person, marker: u8) -> Vec<VideoFrame> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut seen = Vec::new();
    while Instant::now() < deadline {
        seen.extend(person.running.take_video());
        if let Some(first) = seen.iter().position(|frame| frame.marker == marker) {
            return seen.split_off(first);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no camera frame from {marker} within 3 s");
}

/// Turns `person`'s camera on or off with `call.offer`, and takes the answer.
async fn camera(person: &mut Person, on: bool) {
    let offer = person.running.camera(on).expect("a camera offer");
    let request = json!({"type": "call.offer", "ref": "o", "sdp": offer});
    person
        .ws
        .send(Message::text(request.to_string()))
        .await
        .expect("send");
    let reply = until(&mut person.ws, |value| {
        (value["type"] == "call.answer" || value["type"] == "error").then(|| value.clone())
    })
    .await;
    assert_eq!(reply["type"], "call.answer", "{reply}");
    assert_eq!(reply["call_id"], person.call_id.as_str());
    let sdp = reply["sdp"].as_str().expect("sdp");
    person.running.accept(sdp).expect("accept the answer");
}

/// Waits for this socket's `call.slots` whose video slot carries `user_id`, or nobody.
async fn video_slot(ws: &mut Ws, call_id: &str, user_id: Option<&str>) -> Value {
    until(ws, |value| {
        let holder = value["video"]["user_id"].as_str();
        (value["type"] == "call.slots" && value["call_id"] == call_id && holder == user_id)
            .then(|| value["video"].clone())
    })
    .await
}

/// The owner, two members, and two rooms, on a server with media.
struct Cast {
    server: Server,
    owner: (String, String),
    members: Vec<(String, String)>,
    lobby: String,
    other: String,
}

async fn cast(db: &TestDb) -> Cast {
    let owner = first_owner(db).await;
    let (one, one_token) = join(db, &owner, "one@tinyserver.test", "member").await;
    let (two, two_token) = join(db, &owner, "two@tinyserver.test", "member").await;
    let lobby = room(db, &owner, "Lobby").await;
    let other = room(db, &owner, "Other").await;
    let server = serve_media(db).await;
    Cast {
        server,
        owner: (owner.user_id, owner_token(db).await),
        members: vec![(one.user_id, one_token), (two.user_id, two_token)],
        lobby: lobby.id,
        other: other.id,
    }
}

async fn socket(cast: &Cast, who: &(String, String)) -> Ws {
    connect(&cast.server, &who.1, None).await.0
}

#[tokio::test]
async fn two_clients_in_a_room_hear_each_other_and_another_room_hears_neither() {
    run(|db| async move {
        let cast = cast(&db).await;
        let ws = socket(&cast, &cast.owner).await;
        let mut a = dial(ws, &cast.owner.0, &cast.lobby, b'A').await;
        let ws = socket(&cast, &cast.members[0]).await;
        let mut b = dial(ws, &cast.members[0].0, &cast.lobby, b'B').await;
        let ws = socket(&cast, &cast.members[1]).await;
        let c = dial(ws, &cast.members[1].0, &cast.other, b'C').await;

        let a_slots = slots(&mut a.ws, &a.call_id, 1).await;
        let b_slots = slots(&mut b.ws, &b.call_id, 1).await;
        for person in [&a, &b, &c] {
            person.running.sending(true);
        }
        hears(&b, &mid_for(&b_slots, &a.user_id), b'A').await;
        hears(&a, &mid_for(&a_slots, &b.user_id), b'B').await;
        let at_c = heard_over(&c, Duration::from_millis(500)).await;
        assert!(at_c.is_empty(), "another room heard {at_c:?}");

        let speaking = until(&mut b.ws, |value| {
            (value["type"] == "call.speaking").then(|| value.clone())
        })
        .await;
        assert_eq!(speaking["room_id"], cast.lobby.as_str());

        let (_, ready) = connect(&cast.server, &cast.owner.1, None).await;
        let rooms = ready["calls"].as_array().expect("calls");
        assert_eq!(rooms.len(), 2, "{ready}");
    })
    .await;
}

#[tokio::test]
async fn leaving_stops_forwarding() {
    run(|db| async move {
        let cast = cast(&db).await;
        let ws = socket(&cast, &cast.owner).await;
        let mut a = dial(ws, &cast.owner.0, &cast.lobby, b'A').await;
        let ws = socket(&cast, &cast.members[0]).await;
        let mut b = dial(ws, &cast.members[0].0, &cast.lobby, b'B').await;
        let b_slots = slots(&mut b.ws, &b.call_id, 1).await;
        a.running.sending(true);
        hears(&b, &mid_for(&b_slots, &a.user_id), b'A').await;

        let reply = answer(&mut a.ws, json!({"type": "call.leave", "ref": "l"})).await;
        assert_eq!(reply, json!({"type": "ok", "ref": "l"}));
        slots(&mut b.ws, &b.call_id, 0).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let after = heard_over(&b, Duration::from_millis(400)).await;
        assert!(after.is_empty(), "still forwarded after leaving: {after:?}");
    })
    .await;
}

#[tokio::test]
async fn a_kick_removes_media() {
    run(|db| async move {
        let cast = cast(&db).await;
        let ws = socket(&cast, &cast.owner).await;
        let mut a = dial(ws, &cast.owner.0, &cast.lobby, b'A').await;
        let ws = socket(&cast, &cast.members[0]).await;
        let mut b = dial(ws, &cast.members[0].0, &cast.lobby, b'B').await;
        let a_slots = slots(&mut a.ws, &a.call_id, 1).await;
        b.running.sending(true);
        hears(&a, &mid_for(&a_slots, &b.user_id), b'B').await;

        let kick =
            json!({"type": "call.kick", "ref": "k", "room_id": cast.lobby, "user_id": b.user_id});
        let reply = answer(&mut a.ws, kick).await;
        assert_eq!(reply, json!({"type": "ok", "ref": "k"}));
        let gone = left(&cast.lobby, &b.user_id, "kicked");
        until(&mut b.ws, |value| (*value == gone).then_some(())).await;
        slots(&mut a.ws, &a.call_id, 0).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let after = heard_over(&a, Duration::from_millis(400)).await;
        assert!(
            after.is_empty(),
            "a kicked client was still forwarded: {after:?}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_participant_that_never_connects_is_dropped() {
    run(|db| async move {
        let cast = cast(&db).await;
        let mut watcher = socket(&cast, &cast.members[0]).await;
        let mut ws = socket(&cast, &cast.owner).await;
        let client = Client::new(SocketAddr::from((LOOPBACK, 0)), SLOTS).expect("client");
        let request =
            json!({"type": "call.join", "ref": "j", "room_id": cast.lobby, "sdp": client.offer()});
        let reply = ask(&mut ws, request).await;
        assert_eq!(reply["type"], "call.answer", "{reply}");
        let started = Instant::now();
        let dropped = left(&cast.lobby, &cast.owner.0, "media_timeout");
        until(&mut watcher, |value| (*value == dropped).then_some(())).await;
        assert!(started.elapsed() >= Duration::from_secs(1), "too soon");
        let (_, ready) = connect(&cast.server, &cast.owner.1, None).await;
        assert_eq!(ready["calls"], json!([]));
    })
    .await;
}

#[tokio::test]
async fn a_killed_client_leaves_with_media_lost() {
    run(|db| async move {
        let cast = cast(&db).await;
        let ws = socket(&cast, &cast.owner).await;
        let mut a = dial(ws, &cast.owner.0, &cast.lobby, b'A').await;
        let ws = socket(&cast, &cast.members[0]).await;
        let b = dial(ws, &cast.members[0].0, &cast.lobby, b'B').await;
        let a_slots = slots(&mut a.ws, &a.call_id, 1).await;
        // Heard through the SFU, so the SFU has it connected too, not only the client.
        b.running.sending(true);
        hears(&a, &mid_for(&a_slots, &b.user_id), b'B').await;

        b.running.stop();
        // `call.left` comes on the broadcast and `call.slots` on the socket's own channel, so
        // either may arrive first.
        let lost = left(&cast.lobby, &cast.members[0].0, "media_lost");
        let (mut saw_left, mut saw_slots) = (false, false);
        until(&mut a.ws, |value| {
            saw_left |= *value == lost;
            saw_slots |= value["type"] == "call.slots"
                && value["call_id"] == a.call_id.as_str()
                && value["audio"] == json!([]);
            (saw_left && saw_slots).then_some(())
        })
        .await;
    })
    .await;
}

#[tokio::test]
async fn mute_is_shown_to_everyone_and_stops_forwarding() {
    run(|db| async move {
        let cast = cast(&db).await;
        let ws = socket(&cast, &cast.owner).await;
        let mut a = dial(ws, &cast.owner.0, &cast.lobby, b'A').await;
        let ws = socket(&cast, &cast.members[0]).await;
        let mut b = dial(ws, &cast.members[0].0, &cast.lobby, b'B').await;
        let b_slots = slots(&mut b.ws, &b.call_id, 1).await;
        a.running.sending(true);
        hears(&b, &mid_for(&b_slots, &a.user_id), b'A').await;

        let mute = json!({"type": "call.state", "ref": "m", "muted": true, "deafened": false});
        let reply = answer(&mut a.ws, mute).await;
        assert_eq!(reply, json!({"type": "ok", "ref": "m"}));
        let shown = json!({"type": "call.state", "room_id": cast.lobby, "user_id": a.user_id, "muted": true, "deafened": false, "camera": false});
        until(&mut b.ws, |value| (*value == shown).then_some(())).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let muted = heard_over(&b, Duration::from_millis(400)).await;
        assert!(muted.is_empty(), "muted but forwarded: {muted:?}");

        let (_, ready) = connect(&cast.server, &cast.owner.1, None).await;
        assert_eq!(ready["calls"][0]["participants"][0]["muted"], true);
        let reply = answer(&mut a.ws, json!({"type": "call.state", "ref": "x"})).await;
        assert_eq!(reply["code"], "bad_frame");
    })
    .await;
}

#[tokio::test]
async fn offers_are_checked() {
    run(|db| async move {
        let cast = cast(&db).await;
        let mut ws = socket(&cast, &cast.owner).await;
        let plain = json!({"type": "call.join", "ref": 1, "room_id": cast.lobby});
        assert_eq!(
            answer(&mut ws, plain).await,
            json!({"type": "error", "ref": 1, "code": "bad_frame"})
        );
        let bad = json!({"type": "call.join", "ref": 2, "room_id": cast.lobby, "sdp": "not sdp"});
        assert_eq!(
            answer(&mut ws, bad).await,
            json!({"type": "error", "ref": 2, "code": "bad_sdp"})
        );
        let early = json!({"type": "call.offer", "ref": 3, "sdp": "v=0"});
        assert_eq!(
            answer(&mut ws, early).await,
            json!({"type": "error", "ref": 3, "code": "not_found"})
        );

        let mut a = dial(ws, &cast.owner.0, &cast.lobby, b'A').await;
        let offer = json!({"type": "call.offer", "ref": 4, "sdp": "not sdp"});
        assert_eq!(
            answer(&mut a.ws, offer).await,
            json!({"type": "error", "ref": 4, "code": "bad_sdp"})
        );
        let offer = json!({"type": "call.offer", "ref": 5});
        assert_eq!(answer(&mut a.ws, offer).await["code"], "bad_frame");
    })
    .await;
}

#[tokio::test]
async fn without_media_an_offer_is_refused_and_health_says_off() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let lobby = room(&db, &owner, "Lobby").await;
        let server = serve(&db, Limits::default()).await;
        let (mut ws, _) = connect(&server, &owner_token(&db).await, None).await;
        let join = json!({"type": "call.join", "ref": 1, "room_id": lobby.id, "sdp": "v=0"});
        assert_eq!(
            answer(&mut ws, join).await,
            json!({"type": "error", "ref": 1, "code": "media_unavailable"})
        );
        enter(&mut ws, &lobby.id, &owner.user_id).await;

        let app = api::app(db.runtime.clone(), server.live.clone());
        let (status, body) = Call::new(Method::GET, "/health").send(&app).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["media"], "off");
        assert_eq!(body["transports"], json!([]));

        let media = serve_media(&db).await;
        let app = api::app(db.runtime.clone(), media.live.clone());
        let (status, body) = Call::new(Method::GET, "/health").send(&app).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["media"], "up");
        assert_eq!(body["transports"], json!(["udp", "tcp"]));
        media.live.close();
        let deadline = Instant::now() + WAIT;
        loop {
            let (status, body) = Call::new(Method::GET, "/health").send(&app).await;
            if body["media"] == "down" {
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(body["transports"], json!([]));
                break;
            }
            assert!(Instant::now() < deadline, "media still {body}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
}

#[tokio::test]
async fn a_client_with_only_tcp_is_heard_through_the_live_socket() {
    run(|db| async move {
        let cast = cast(&db).await;
        let ws = socket(&cast, &cast.owner).await;
        let client = Client::tcp(LOOPBACK.into(), SLOTS).expect("TCP client");
        let mut a = dial_with(ws, client, &cast.owner.0, &cast.lobby, b'A').await;
        let ws = socket(&cast, &cast.members[0]).await;
        let mut b = dial(ws, &cast.members[0].0, &cast.lobby, b'B').await;
        let a_slots = slots(&mut a.ws, &a.call_id, 1).await;
        let b_slots = slots(&mut b.ws, &b.call_id, 1).await;
        a.running.sending(true);
        b.running.sending(true);
        hears(&b, &mid_for(&b_slots, &a.user_id), b'A').await;
        hears(&a, &mid_for(&a_slots, &b.user_id), b'B').await;
    })
    .await;
}

#[tokio::test]
async fn the_answer_has_the_lan_candidate_when_set() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let lobby = room(&db, &owner, "Lobby").await;
        let mut config = media_config();
        config.lan_ip = Some(Ipv4Addr::new(192, 0, 2, 10).into());
        let server = serve_media_with(&db, config).await;
        let (mut ws, _) = connect(&server, &owner_token(&db).await, None).await;
        let client = Client::new(SocketAddr::from((LOOPBACK, 0)), SLOTS).expect("client");
        let join =
            json!({"type": "call.join", "ref": 1, "room_id": lobby.id, "sdp": client.offer()});
        let reply = ask(&mut ws, join).await;
        assert_eq!(reply["type"], "call.answer", "{reply}");
        let sdp = reply["sdp"].as_str().expect("sdp");
        let lan: Vec<&str> = sdp
            .lines()
            .filter(|line| line.starts_with("a=candidate") && line.contains("192.0.2.10"))
            .collect();
        assert_eq!(lan.len(), 2, "{sdp}");
        assert!(lan.iter().any(|line| line.contains(" udp ")), "{sdp}");
        assert!(lan.iter().any(|line| line.contains(" tcp ")), "{sdp}");

        let app = api::app(db.runtime.clone(), server.live.clone());
        let (_, body) = Call::new(Method::GET, "/health").send(&app).await;
        assert_eq!(body["transports"], json!(["udp", "tcp", "lan"]));
    })
    .await;
}

#[tokio::test]
async fn oversized_and_crowded_offers_are_bad_sdp() {
    run(|db| async move {
        let cast = cast(&db).await;
        let mut ws = socket(&cast, &cast.owner).await;
        let crowded = Client::new(SocketAddr::from((LOOPBACK, 0)), 12).expect("client");
        let join =
            json!({"type": "call.join", "ref": 1, "room_id": cast.lobby, "sdp": crowded.offer()});
        assert_eq!(
            answer(&mut ws, join).await,
            json!({"type": "error", "ref": 1, "code": "bad_sdp"})
        );
        let client = Client::new(SocketAddr::from((LOOPBACK, 0)), SLOTS).expect("client");
        let padded = format!("{}a=x:{}\r\n", client.offer(), "y".repeat(32 * 1024));
        let join = json!({"type": "call.join", "ref": 2, "room_id": cast.lobby, "sdp": padded});
        assert_eq!(
            answer(&mut ws, join).await,
            json!({"type": "error", "ref": 2, "code": "bad_sdp"})
        );
        let (_, ready) = connect(&cast.server, &cast.owner.1, None).await;
        assert_eq!(ready["calls"], json!([]), "a refused offer took a seat");

        let mut a = dial(ws, &cast.owner.0, &cast.lobby, b'A').await;
        let offer = json!({"type": "call.offer", "ref": 3, "sdp": crowded.offer()});
        assert_eq!(
            answer(&mut a.ws, offer).await,
            json!({"type": "error", "ref": 3, "code": "bad_sdp"})
        );
    })
    .await;
}

#[tokio::test]
async fn rapid_offers_get_slow_down() {
    run(|db| async move {
        let cast = cast(&db).await;
        let ws = socket(&cast, &cast.owner).await;
        let mut a = dial(ws, &cast.owner.0, &cast.lobby, b'A').await;
        // The join took one of five; four offers pass the rate and fail as SDP.
        let mut codes = Vec::new();
        for n in 0..6 {
            let offer = json!({"type": "call.offer", "ref": n, "sdp": "v=0"});
            let reply = answer(&mut a.ws, offer).await;
            codes.push(reply["code"].as_str().unwrap_or_default().to_string());
        }
        assert_eq!(
            codes,
            [
                "bad_sdp",
                "bad_sdp",
                "bad_sdp",
                "bad_sdp",
                "slow_down",
                "slow_down"
            ]
        );
    })
    .await;
}

#[tokio::test]
async fn a_camera_is_shown_to_everyone_and_reaches_the_other_listener() {
    run(|db| async move {
        let cast = cast(&db).await;
        let ws = socket(&cast, &cast.owner).await;
        let mut a = dial(ws, &cast.owner.0, &cast.lobby, b'A').await;
        let ws = socket(&cast, &cast.members[0]).await;
        let mut b = dial(ws, &cast.members[0].0, &cast.lobby, b'B').await;
        slots(&mut b.ws, &b.call_id, 1).await;

        camera(&mut a, true).await;
        let shown = json!({"type": "call.state", "room_id": cast.lobby, "user_id": a.user_id, "muted": false, "deafened": false, "camera": true});
        until(&mut b.ws, |value| (*value == shown).then_some(())).await;
        let video = video_slot(&mut b.ws, &b.call_id, Some(&a.user_id)).await;
        assert_eq!(video["kind"], "camera");
        let frames = sees(&b, b'A').await;
        assert!(frames[0].keyframe, "the first frame is not a keyframe");
        assert!(frames.iter().all(|frame| video["mid"] == frame.mid.as_str()));
        let (_, ready) = connect(&cast.server, &cast.owner.1, None).await;
        let participants = &ready["calls"][0]["participants"];
        assert_eq!(participants[0]["camera"], true, "{ready}");
        assert_eq!(participants[1]["camera"], false, "{ready}");

        let low = json!({"type": "call.quality", "ref": "q", "video": "low"});
        assert_eq!(answer(&mut b.ws, low).await, json!({"type": "ok", "ref": "q"}));
        let bad = json!({"type": "call.quality", "ref": "q", "video": "max"});
        assert_eq!(answer(&mut b.ws, bad).await["code"], "bad_frame");

        camera(&mut a, false).await;
        let hidden = json!({"type": "call.state", "room_id": cast.lobby, "user_id": a.user_id, "muted": false, "deafened": false, "camera": false});
        until(&mut b.ws, |value| (*value == hidden).then_some(())).await;
        video_slot(&mut b.ws, &b.call_id, None).await;
    })
    .await;
}

#[tokio::test]
async fn call_quality_needs_a_call_with_media() {
    run(|db| async move {
        let cast = cast(&db).await;
        let mut ws = socket(&cast, &cast.owner).await;
        let quality = json!({"type": "call.quality", "ref": 1, "video": "off"});
        assert_eq!(
            answer(&mut ws, quality).await,
            json!({"type": "error", "ref": 1, "code": "not_found"})
        );
    })
    .await;
}

#[tokio::test]
async fn a_tcp_client_receives_video_through_the_live_socket() {
    run(|db| async move {
        let cast = cast(&db).await;
        let ws = socket(&cast, &cast.owner).await;
        let mut a = dial(ws, &cast.owner.0, &cast.lobby, b'A').await;
        let ws = socket(&cast, &cast.members[0]).await;
        let client = Client::tcp(LOOPBACK.into(), SLOTS).expect("TCP client");
        let mut b = dial_with(ws, client, &cast.members[0].0, &cast.lobby, b'B').await;
        camera(&mut a, true).await;
        video_slot(&mut b.ws, &b.call_id, Some(&a.user_id)).await;
        assert!(sees(&b, b'A').await[0].keyframe);
    })
    .await;
}
