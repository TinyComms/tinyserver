//! The app on a bound port and a WebSocket client for `GET /v1/live`.

use std::net::SocketAddr;
use std::time::Duration;

use api::{Limits, Live};
use db::{Caller, Wrote};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use super::{TestDb, OWNER_EMAIL, OWNER_PASSWORD};

pub type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub const WAIT: Duration = Duration::from_secs(5);

/// The app on a real port. Dropping it closes the hub, so a failed test still frees its
/// database connections.
pub struct Server {
    pub addr: SocketAddr,
    pub live: Live,
    task: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.live.close();
        self.task.abort();
    }
}

pub async fn serve(db: &TestDb, limits: Limits) -> Server {
    serve_live(db, Live::start(db.runtime.clone(), limits)).await
}

/// Serves `live`, which may have media.
pub async fn serve_live(db: &TestDb, live: Live) -> Server {
    let app = api::app(db.runtime.clone(), live.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("address");
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Server { addr, live, task }
}

pub async fn attempt(server: &Server, token: &str, query: &str) -> Result<Ws, tungstenite::Error> {
    let mut request = format!("ws://{}/v1/live{query}", server.addr)
        .into_client_request()
        .expect("request");
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {token}").parse().expect("header"),
    );
    tokio_tungstenite::connect_async(request)
        .await
        .map(|(ws, _)| ws)
}

/// Connects and returns the socket and its `ready` frame.
pub async fn connect(server: &Server, token: &str, since: Option<i64>) -> (Ws, Value) {
    let query = since.map(|seq| format!("?since={seq}")).unwrap_or_default();
    let mut ws = attempt(server, token, &query).await.expect("connect");
    let ready = frame(&mut ws).await;
    assert_eq!(ready["type"], "ready", "{ready}");
    (ws, ready)
}

/// The next text frame. Panics on a close or after `WAIT`.
pub async fn frame(ws: &mut Ws) -> Value {
    loop {
        let message = tokio::time::timeout(WAIT, ws.next())
            .await
            .expect("a frame in time")
            .expect("socket open")
            .expect("frame");
        match message {
            Message::Text(text) => return serde_json::from_str(text.as_str()).expect("json"),
            Message::Close(close) => panic!("closed: {close:?}"),
            _ => {}
        }
    }
}

/// The next frame that is not `presence`.
pub async fn durable(ws: &mut Ws) -> Value {
    loop {
        let value = frame(ws).await;
        if value["type"] != "presence" {
            return value;
        }
    }
}

/// Reads until the server closes and returns the close code. Text frames before it are skipped.
pub async fn close_code(ws: &mut Ws) -> u16 {
    loop {
        let message = tokio::time::timeout(WAIT, ws.next())
            .await
            .expect("a close in time");
        match message {
            Some(Ok(Message::Close(Some(close)))) => return u16::from(close.code),
            Some(Ok(Message::Close(None))) | None => return 0,
            Some(Ok(_)) => {}
            Some(Err(error)) => panic!("socket error before close: {error}"),
        }
    }
}

pub async fn ping(ws: &mut Ws) {
    ws.send(Message::text(r#"{"type":"ping"}"#))
        .await
        .expect("send ping");
    assert_eq!(durable(ws).await, json!({"type": "pong"}));
}

pub async fn owner_token(db: &TestDb) -> String {
    db::open_session(&db.runtime, OWNER_EMAIL, OWNER_PASSWORD)
        .await
        .expect("owner session")
        .token
}

pub async fn room(db: &TestDb, owner: &Caller, name: &str) -> db::Room {
    let Ok(Wrote::Fresh(room)) = db::create_room(&db.runtime, owner, name, None).await else {
        panic!("create room");
    };
    room
}

pub fn seq(value: &Value) -> i64 {
    value["seq"].as_i64().expect("seq")
}

/// Sends a request and returns the next frame that is not `presence`.
pub async fn ask(ws: &mut Ws, request: Value) -> Value {
    ws.send(Message::text(request.to_string()))
        .await
        .expect("send");
    durable(ws).await
}

/// Sends a request and returns its `ok` or `error`, skipping frames before it.
pub async fn answer(ws: &mut Ws, request: Value) -> Value {
    let mut value = ask(ws, request).await;
    while value["type"] != "ok" && value["type"] != "error" {
        value = durable(ws).await;
    }
    value
}

/// Joins `room_id` and checks the reply and the caller's own `call.joined`.
pub async fn enter(ws: &mut Ws, room_id: &str, user_id: &str) {
    let reply = ask(
        ws,
        json!({"type": "call.join", "ref": "j", "room_id": room_id}),
    )
    .await;
    assert_eq!(reply, json!({"type": "ok", "ref": "j"}));
    assert_eq!(durable(ws).await, joined(room_id, user_id));
}

pub fn joined(room_id: &str, user_id: &str) -> Value {
    json!({"type": "call.joined", "room_id": room_id, "user_id": user_id})
}

pub fn left(room_id: &str, user_id: &str, reason: &str) -> Value {
    json!({"type": "call.left", "room_id": room_id, "user_id": user_id, "reason": reason})
}

pub fn occupancy(room_id: &str, user_ids: &[&str]) -> Value {
    let participants: Vec<Value> = user_ids
        .iter()
        .map(|user_id| json!({"user_id": user_id, "muted": false, "deafened": false, "camera": false, "sharing": false}))
        .collect();
    json!({"room_id": room_id, "participants": participants})
}
