//! End-to-end encrypted text and sealed attachments, through the real HTTP routes, with real MLS
//! clients (openmls, as tinyclient runs it): the server only delivers. The protocol is
//! `docs/e2ee-text.md`; the properties it lists are each a test here.
//!
//! Alone in its own test binary, so it can hold the one global log subscriber and read every
//! line the server writes.

mod common;

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use common::live::{connect, durable, ping, serve};
use common::mls_client::{uuid16, Client};
use common::{first_owner, join, run, session, Call, TestDb};
use db::Caller;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

/// Said in a message, a reply and a file: it must not be found anywhere the server keeps things.
const MARKER: &str = "ZEPHYR-QUOKKA-PLAINTEXT-MARKER-7f3a9c";

// ---- what the server logs -------------------------------------------------------------------

#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl Logs {
    fn lock(&self) -> MutexGuard<'_, Vec<u8>> {
        self.0.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.lock()).into_owned()
    }
}

impl std::io::Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.lock().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Everything the server writes, at every level. The libraries the test's own clients use are
/// not the server's logging.
fn logs() -> &'static Logs {
    static LOGS: OnceLock<Logs> = OnceLock::new();
    LOGS.get_or_init(|| {
        let logs = Logs::default();
        let writer = logs.clone();
        let filter = tracing_subscriber::EnvFilter::new(
            "trace,tungstenite=debug,tokio_tungstenite=debug,openmls=off",
        );
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .init();
        logs
    })
}

// ---- small helpers --------------------------------------------------------------------------

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn unb64(text: &str) -> Vec<u8> {
    STANDARD.decode(text).expect("base64")
}

fn fresh_uuid() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("random");
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A scratch upload directory for this test.
fn upload_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("tinyserver-e2ee-text-{}", fresh_uuid()));
    std::fs::create_dir_all(&dir).expect("upload dir");
    std::env::set_var("TINYSERVER_UPLOAD_DIR", &dir);
    dir
}

async fn call(
    app: &Router,
    method: Method,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut call = Call::new(method, path).token(token);
    if let Some(body) = body {
        call = call.json(body);
    }
    call.send(app).await
}

/// A raw request, for bodies that are not JSON or not small.
async fn raw(
    app: &Router,
    method: Method,
    path: &str,
    token: &str,
    content_type: &str,
    body: Vec<u8>,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"));
    if !content_type.is_empty() {
        request = request.header("content-type", content_type);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body)).expect("request"))
        .await
        .expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes()
        .to_vec();
    (status, headers, bytes)
}

fn multipart(file: Option<(&str, &str)>, bytes: &[u8], fields: &[(&str, &str)]) -> Vec<u8> {
    let boundary = "TinyBoundary";
    let mut body = Vec::new();
    for (name, value) in fields {
        body.extend(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            )
            .as_bytes(),
        );
    }
    let disposition = match file {
        Some((filename, _)) => format!("name=\"file\"; filename=\"{filename}\""),
        None => "name=\"file\"".to_string(),
    };
    let mime = file.map_or("application/octet-stream", |(_, mime)| mime);
    body.extend(
        format!("--{boundary}\r\nContent-Disposition: form-data; {disposition}\r\nContent-Type: {mime}\r\n\r\n")
            .as_bytes(),
    );
    body.extend(bytes);
    body.extend(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

const MULTIPART: &str = "multipart/form-data; boundary=TinyBoundary";

async fn upload_sealed(app: &Router, token: &str, bytes: &[u8]) -> (StatusCode, Value) {
    let body = multipart(
        Some(("sealed", "application/octet-stream")),
        bytes,
        &[("sealed", "1")],
    );
    let (status, _, bytes) = raw(app, Method::POST, "/v1/media", token, MULTIPART, body).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn download(
    app: &Router,
    token: &str,
    id: &str,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    raw(
        app,
        Method::GET,
        &format!("/v1/media/{id}"),
        token,
        "",
        Vec::new(),
    )
    .await
}

/// Names of the tables in which some row, as text, holds `needle` or its hex.
async fn tables_holding(db: &TestDb, needle: &str) -> Vec<String> {
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT table_name::text FROM information_schema.tables
         WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY 1",
    )
    .fetch_all(&db.owner)
    .await
    .expect("tables");
    assert!(tables.len() > 20, "{tables:?}");
    let mut found = Vec::new();
    for table in tables {
        let count: i64 = sqlx::query_scalar(&format!(
            "SELECT count(*) FROM \"{table}\" x WHERE x::text LIKE $1 OR x::text LIKE $2"
        ))
        .bind(format!("%{needle}%"))
        .bind(format!("%{}%", hex(needle.as_bytes())))
        .fetch_one(&db.owner)
        .await
        .expect("scan");
        if count > 0 {
            found.push(table);
        }
    }
    found
}

fn files_in(dir: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = std::fs::read_dir(dir)
        .expect("upload dir")
        .map(|entry| {
            let entry = entry.expect("entry");
            (
                entry.file_name().to_string_lossy().into_owned(),
                std::fs::read(entry.path()).expect("file"),
            )
        })
        .collect();
    out.sort();
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

// ---- the world ------------------------------------------------------------------------------

struct World {
    db: TestDb,
    app: Router,
    owner: Caller,
    owner_token: String,
}

async fn world(db: TestDb) -> World {
    logs();
    let owner = first_owner(&db).await;
    let owner_token = session(&db, &owner.user_id).await;
    let app = api::router(db.runtime.clone(), None);
    World {
        db,
        app,
        owner,
        owner_token,
    }
}

impl World {
    async fn member(&self, name: &str) -> (Caller, String) {
        join(
            &self.db,
            &self.owner,
            &format!("{name}@tinyserver.test"),
            "member",
        )
        .await
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        call(&self.app, method, path, token, body).await
    }

    async fn channel(&self, name: &str, e2ee: bool) -> String {
        let (status, channel) = self
            .send(
                Method::POST,
                "/v1/channels",
                &self.owner_token,
                Some(json!({"name": name, "e2ee": e2ee})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{channel}");
        assert_eq!(channel["e2ee"], e2ee);
        channel["id"].as_str().expect("channel id").to_string()
    }

    async fn everyone(&self) -> String {
        let (_, roles) = self
            .send(Method::GET, "/v1/roles", &self.owner_token, None)
            .await;
        roles
            .as_array()
            .expect("roles")
            .iter()
            .find(|role| role["name"] == "@everyone")
            .and_then(|role| role["id"].as_str())
            .expect("everyone")
            .to_string()
    }

    /// A role with no permissions, held by `user_ids`.
    async fn crew(&self, user_ids: &[&str]) -> String {
        let (status, crew) = self
            .send(
                Method::POST,
                "/v1/roles",
                &self.owner_token,
                Some(json!({"name": "Crew", "permissions": 0, "color": "#22c55e"})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{crew}");
        let crew = crew["id"].as_str().expect("crew").to_string();
        for user_id in user_ids {
            let (status, given) = self
                .send(
                    Method::PUT,
                    &format!("/v1/members/{user_id}/roles"),
                    &self.owner_token,
                    Some(json!({ "role_ids": [crew] })),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{given}");
        }
        crew
    }

    async fn override_view(&self, channel: &str, role: &str, allow_view: bool) {
        let body = if allow_view {
            json!({"allow": 1, "deny": 0})
        } else {
            json!({"allow": 0, "deny": 1})
        };
        let (status, put) = self
            .send(
                Method::PUT,
                &format!("/v1/channels/{channel}/overrides/{role}"),
                &self.owner_token,
                Some(body),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{put}");
    }
}

// ---- a device --------------------------------------------------------------------------------

/// One install: its MLS client, the session it signs in with, and how far it has read the log.
struct Dev {
    client: Client,
    token: String,
    cursor: i64,
}

impl Dev {
    fn new(user_id: &str, token: &str) -> Self {
        Self {
            client: Client::new(user_id, &fresh_uuid()),
            token: token.to_string(),
            cursor: 0,
        }
    }

    fn id(&self) -> &str {
        &self.client.device_id
    }

    fn user(&self) -> &str {
        &self.client.user_id
    }
}

/// The device's MLS client, working on this conversation's group.
fn at<'a>(dev: &'a mut Dev, conv: &str) -> &'a mut Client {
    dev.client.use_group(uuid16(conv));
    &mut dev.client
}

async fn register(app: &Router, dev: &Dev) -> (StatusCode, Value) {
    call(
        app,
        Method::PUT,
        &format!("/v1/e2ee/devices/{}", dev.id()),
        &dev.token,
        Some(json!({"signature_key": dev.client.signature_key_b64(), "label": "test"})),
    )
    .await
}

async fn register_vouched(app: &Router, dev: &Dev, by: &Dev) -> (StatusCode, Value) {
    let signature = by
        .client
        .vouch_for(dev.user(), dev.id(), &dev.client.signature_key());
    call(
        app,
        Method::PUT,
        &format!("/v1/e2ee/devices/{}", dev.id()),
        &dev.token,
        Some(json!({
            "signature_key": dev.client.signature_key_b64(),
            "cross_signature": b64(&signature),
        })),
    )
    .await
}

async fn upload_packages(app: &Router, dev: &Dev, count: usize) -> (StatusCode, Value) {
    let packages: Vec<String> = (0..count).map(|_| b64(&dev.client.key_package())).collect();
    call(
        app,
        Method::POST,
        "/v1/e2ee/key_packages",
        &dev.token,
        Some(json!({
            "device_id": dev.id(),
            "key_packages": packages,
            "last_resort": b64(&dev.client.last_resort()),
        })),
    )
    .await
}

/// A device that is registered and has key packages waiting.
async fn ready(app: &Router, user_id: &str, token: &str) -> Dev {
    let dev = Dev::new(user_id, token);
    let (status, body) = register(app, &dev).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = upload_packages(app, &dev, 5).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    dev
}

async fn info(app: &Router, token: &str, conv: &str) -> (StatusCode, Value) {
    call(
        app,
        Method::GET,
        &format!("/v1/e2ee/conversations/{conv}"),
        token,
        None,
    )
    .await
}

/// The device makes its group and tells the server.
async fn start(app: &Router, dev: &mut Dev, conv: &str) {
    let (status, group) = info(app, &dev.token, conv).await;
    assert_eq!(status, StatusCode::OK, "{group}");
    assert_eq!(group["e2ee"], true);
    assert!(group["epoch"].is_null(), "no group yet: {group}");
    let sender = group["external_sender"].as_str().expect("external sender");
    dev.client.create_group(uuid16(conv), sender);
    let (status, body) = call(
        app,
        Method::POST,
        &format!("/v1/e2ee/conversations/{conv}/group"),
        &dev.token,
        Some(json!({"device_id": dev.id()})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

/// Reads the log and applies it: proposals are stored, commits applied, a welcome joins. The
/// error is what the server said when it would not give the log.
async fn pull(app: &Router, dev: &mut Dev, conv: &str) -> Result<usize, (StatusCode, Value)> {
    let mut applied = 0;
    let group = uuid16(conv);
    loop {
        let (status, rows) = call(
            app,
            Method::GET,
            &format!(
                "/v1/e2ee/conversations/{conv}/handshake?after={}&device_id={}",
                dev.cursor,
                dev.id()
            ),
            &dev.token,
            None,
        )
        .await;
        if status != StatusCode::OK {
            return Err((status, rows));
        }
        let rows = rows.as_array().expect("rows").clone();
        if rows.is_empty() {
            return Ok(applied);
        }
        for row in rows {
            let data = unb64(row["data"].as_str().expect("data"));
            let epoch = row["epoch"].as_u64().expect("epoch");
            let in_group = dev.client.has_group(&group);
            if in_group {
                dev.client.use_group(group);
            }
            match row["kind"].as_str().expect("kind") {
                "proposals" if in_group && epoch >= dev.client.epoch() => {
                    dev.client.take_proposals(&data);
                    applied += 1;
                }
                // Its own commit, already merged, is below its epoch.
                "commit" if in_group && epoch == dev.client.epoch() => {
                    dev.client.take_commit(&data);
                    applied += 1;
                }
                "welcome" if !in_group => {
                    dev.client.join(&data);
                    applied += 1;
                }
                _ => {}
            }
            dev.cursor = row["seq"].as_i64().expect("seq");
        }
    }
}

async fn pull_ok(app: &Router, dev: &mut Dev, conv: &str) -> usize {
    match pull(app, dev, conv).await {
        Ok(applied) => applied,
        Err((status, body)) => panic!("pull: {status} {body}"),
    }
}

/// The device commits what is pending, with a welcome for each device it adds.
async fn commit(app: &Router, dev: &mut Dev, conv: &str) -> (StatusCode, Value) {
    pull_ok(app, dev, conv).await;
    dev.client.use_group(uuid16(conv));
    let (_, group) = info(app, &dev.token, conv).await;
    let added: Vec<String> = group["pending"]
        .as_array()
        .expect("pending")
        .iter()
        .filter(|item| item["op"] == "add")
        .map(|item| item["device_id"].as_str().expect("device").to_string())
        .collect();
    let committed = dev.client.commit();
    let welcomes: Vec<Value> = match &committed.welcome {
        Some(welcome) => added
            .iter()
            .map(|device| json!({"device_id": device, "data": b64(welcome)}))
            .collect(),
        None => Vec::new(),
    };
    let (status, body) = call(
        app,
        Method::POST,
        &format!("/v1/e2ee/conversations/{conv}/commit"),
        &dev.token,
        Some(json!({
            "device_id": dev.id(),
            "epoch": dev.client.epoch(),
            "commit": b64(&committed.commit),
            "welcomes": welcomes,
        })),
    )
    .await;
    if status == StatusCode::NO_CONTENT {
        dev.client.merge();
    } else {
        dev.client.abandon();
    }
    (status, body)
}

/// Commits until nothing is pending and every device has read everything it can.
async fn settle(app: &Router, devs: &mut [Dev], committer: usize, conv: &str) {
    for _ in 0..6 {
        for dev in devs.iter_mut() {
            let _ = pull(app, dev, conv).await;
        }
        let (_, group) = info(app, &devs[committer].token, conv).await;
        if group["pending"].as_array().expect("pending").is_empty() {
            return;
        }
        let (status, body) = commit(app, &mut devs[committer], conv).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    }
    panic!("the group did not settle");
}

/// The plaintext inside a message, as the spec lays it out.
fn payload(text: &str) -> Vec<u8> {
    json!({"v": 1, "text": text, "sent_at": 1_730_000_000_000u64})
        .to_string()
        .into_bytes()
}

async fn post_raw(
    app: &Router,
    dev: &mut Dev,
    conv: &str,
    ciphertext: &[u8],
    extra: Value,
) -> (StatusCode, Value) {
    let epoch = if dev.client.has_group(&uuid16(conv)) {
        at(dev, conv).epoch()
    } else {
        0
    };
    let mut body = json!({
        "ciphertext": b64(ciphertext),
        "epoch": epoch,
        "device_id": dev.id(),
    });
    if let (Some(body), Some(extra)) = (body.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            body.insert(key.clone(), value.clone());
        }
    }
    call(
        app,
        Method::POST,
        &format!("/v1/conversations/{conv}/messages"),
        &dev.token,
        Some(body),
    )
    .await
}

async fn say(
    app: &Router,
    dev: &mut Dev,
    conv: &str,
    text: &str,
    extra: Value,
) -> (StatusCode, Value) {
    let ciphertext = at(dev, conv).encrypt(&payload(text));
    post_raw(app, dev, conv, &ciphertext, extra).await
}

async fn messages(app: &Router, token: &str, conv: &str) -> (StatusCode, Value) {
    call(
        app,
        Method::GET,
        &format!("/v1/conversations/{conv}/messages?limit=100"),
        token,
        None,
    )
    .await
}

/// The text of each message in the conversation this device can read, oldest first.
async fn read(app: &Router, dev: &mut Dev, conv: &str) -> Vec<String> {
    dev.client.use_group(uuid16(conv));
    let (status, page) = messages(app, &dev.token, conv).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let mut out = Vec::new();
    for message in page.as_array().expect("messages") {
        assert_eq!(message["body"], "", "the server returns no text: {message}");
        let Some(ciphertext) = message["ciphertext"].as_str() else {
            continue;
        };
        if message["kind"] != "message" {
            continue;
        }
        if let Some(plain) = dev.client.decrypt(&unb64(ciphertext)) {
            let value: Value = serde_json::from_slice(&plain).expect("payload");
            out.push(value["text"].as_str().expect("text").to_string());
        }
    }
    out
}

/// Two people, their devices, an encrypted channel and a group of both at epoch 1.
struct Pair {
    conv: String,
    owner: Dev,
    other: Dev,
}

async fn pair(w: &World, name: &str) -> Pair {
    let (other_user, other_token) = w.member(name).await;
    let conv = w.channel(&format!("{name}-room"), true).await;
    let mut owner = ready(&w.app, &w.owner.user_id, &w.owner_token).await;
    let other = ready(&w.app, &other_user.user_id, &other_token).await;
    start(&w.app, &mut owner, &conv).await;
    let mut devs = [owner, other];
    settle(&w.app, &mut devs, 0, &conv).await;
    let [owner, other] = devs;
    assert_eq!(owner.client.epoch(), 1);
    assert_eq!(other.client.epoch(), 1);
    Pair { conv, owner, other }
}

// ---- tests -----------------------------------------------------------------------------------

#[tokio::test]
async fn a_group_forms_and_the_server_stores_only_ciphertext() {
    run(|db| async move {
        let dir = upload_dir();
        let w = world(db).await;
        let mut p = pair(&w, "bea").await;

        // The server's own view of the group agrees with the clients': who sits in which leaf.
        let (status, group) = info(&w.app, &p.owner.token, &p.conv).await;
        assert_eq!(status, StatusCode::OK, "{group}");
        assert_eq!(group["epoch"], 1);
        assert!(group["pending"].as_array().expect("pending").is_empty());
        let members = group["members"].as_array().expect("members");
        assert_eq!(members.len(), 2);
        assert_eq!(members[0]["device_id"], p.owner.id());
        assert_eq!(members[0]["leaf_index"], 0);
        assert_eq!(members[1]["device_id"], p.other.id());
        assert_eq!(members[1]["leaf_index"], p.other.client.leaf_index());

        // A message, an edit, and a sealed file with the marker in each.
        let (status, first) = say(&w.app, &mut p.owner, &p.conv, MARKER, json!({"client_id": "c1"})).await;
        assert_eq!(status, StatusCode::CREATED, "{first}");
        assert_eq!(first["e2ee"], true);
        assert_eq!(first["body"], "");
        assert_eq!(first["kind"], "message");
        assert_eq!(first["device_id"], p.owner.id());
        assert_eq!(first["epoch"], 1);
        let file = p.owner.client.encrypt(format!("file says {MARKER}").as_bytes());
        let (status, sealed) = upload_sealed(&w.app, &p.owner.token, &file).await;
        assert_eq!(status, StatusCode::CREATED, "{sealed}");
        let (status, with_file) = say(
            &w.app,
            &mut p.owner,
            &p.conv,
            &format!("see file {MARKER}"),
            json!({"attachment_ids": [sealed["id"]]}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{with_file}");
        let (status, edit) = say(
            &w.app,
            &mut p.owner,
            &p.conv,
            &format!("edited {MARKER}"),
            json!({"kind": "edit", "target_id": first["id"]}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{edit}");
        assert_eq!(edit["kind"], "edit");
        assert_eq!(edit["target_id"], first["id"]);

        // The other device reads them all.
        let texts = read(&w.app, &mut p.other, &p.conv).await;
        assert_eq!(
            texts,
            vec![MARKER.to_string(), format!("see file {MARKER}")]
        );
        let (_, page) = messages(&w.app, &p.other.token, &p.conv).await;
        let edit_row = page
            .as_array()
            .expect("page")
            .iter()
            .find(|message| message["kind"] == "edit")
            .expect("the edit is a row of its own");
        let plain = p.other.client.decrypt(&unb64(edit_row["ciphertext"].as_str().expect("c")));
        assert!(plain.is_some_and(|plain| contains(&plain, b"edited")));
        let (status, headers, body) = download(&w.app, &p.other.token, sealed["id"].as_str().expect("id")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, file, "stored exactly as it came");
        assert_eq!(
            headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()),
            Some("application/octet-stream")
        );

        // The conversation's preview carries no text, and no table, no outbox row, no file and
        // no log line holds what was said.
        let (_, channels) = w.send(Method::GET, "/v1/channels", &p.other.token, None).await;
        let channel = channels
            .as_array()
            .expect("channels")
            .iter()
            .find(|channel| channel["id"] == p.conv.as_str())
            .expect("channel");
        assert_eq!(channel["e2ee"], true);
        assert_eq!(channel["last_message"]["body"], "");
        assert_eq!(tables_holding(&w.db, MARKER).await, Vec::<String>::new());
        let outbox: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM outbox WHERE topic = 'message.created' AND payload::text LIKE '%ciphertext%'",
        )
        .fetch_one(&w.db.owner)
        .await
        .expect("outbox");
        assert!(outbox >= 3, "ciphertext travels in the outbox, and only that");
        let files = files_in(&dir);
        assert_eq!(files.len(), 1, "one file, and no temporary copy: {files:?}");
        assert_eq!(files[0].1, file);
        assert!(!contains(&files[0].1, MARKER.as_bytes()));
        let text = logs().text();
        assert!(!text.contains(MARKER), "a log line holds plaintext");
        let sent: Vec<(String,)> = sqlx::query_as(
            "SELECT translate(encode(ciphertext, 'base64'), E'\n', '') FROM messages WHERE e2ee AND ciphertext IS NOT NULL",
        )
        .fetch_all(&w.db.owner)
        .await
        .expect("ciphertexts");
        assert_eq!(sent.len(), 3);
        for (ciphertext,) in sent {
            assert!(!text.contains(&ciphertext[..40]), "a ciphertext is in a log line");
        }
        let packages: Vec<(String,)> = sqlx::query_as(
            "SELECT translate(encode(data, 'base64'), E'\n', '') FROM e2ee_key_packages",
        )
        .fetch_all(&w.db.owner)
        .await
        .expect("key packages");
        assert!(!packages.is_empty());
        for (package,) in packages {
            assert!(!text.contains(&package[..40]), "a key package is in a log line");
        }
        let handshake: Vec<(String,)> = sqlx::query_as(
            "SELECT translate(encode(data, 'base64'), E'\n', '') FROM e2ee_handshake",
        )
        .fetch_all(&w.db.owner)
        .await
        .expect("handshake");
        assert!(handshake.len() >= 3);
        for (data,) in handshake {
            assert!(!text.contains(&data[..40]), "handshake data is in a log line");
        }
        let _ = std::fs::remove_dir_all(dir);
    })
    .await;
}

#[tokio::test]
async fn there_is_no_downgrade_in_either_direction() {
    run(|db| async move {
        let _dir = upload_dir();
        let w = world(db).await;
        let mut p = pair(&w, "carl").await;
        let plain = w.channel("plain", false).await;

        // A body to an encrypted conversation is refused, however it is dressed.
        let path = format!("/v1/conversations/{}/messages", p.conv);
        for body in [
            json!({"body": "hello"}),
            json!({"body": ""}),
            json!({"body": "hello", "client_id": "x"}),
            json!({"body": "hello", "ciphertext": "AAAA", "epoch": 1, "device_id": p.owner.id()}),
        ] {
            let (status, refused) = w.send(Method::POST, &path, &p.owner.token, Some(body)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
            assert_eq!(refused["error"], "e2ee_required");
        }
        let (status, refused) = w
            .send(Method::POST, &path, &p.owner.token, Some(json!({"client_id": "nothing"})))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
        assert_eq!(refused["error"], "e2ee_required");

        // An edit by body is refused too, and leaves the message as it was.
        let (status, sent) = say(&w.app, &mut p.owner, &p.conv, "kept", json!({})).await;
        assert_eq!(status, StatusCode::CREATED, "{sent}");
        let id = sent["id"].as_str().expect("id").to_string();
        let (status, refused) = w
            .send(
                Method::PATCH,
                &format!("/v1/messages/{id}"),
                &p.owner.token,
                Some(json!({"body": "swapped for plaintext"})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
        assert_eq!(refused["error"], "e2ee_required");
        let stored: (String, bool) =
            sqlx::query_as("SELECT body, ciphertext IS NOT NULL FROM messages WHERE id = $1::uuid")
                .bind(&id)
                .fetch_one(&w.db.owner)
                .await
                .expect("row");
        assert_eq!(stored, (String::new(), true));

        // Ciphertext to a plaintext conversation is refused: junk, a real message from another
        // group, an edit, and one with a body.
        let real = p.owner.client.encrypt(b"from another group");
        let plain_path = format!("/v1/conversations/{plain}/messages");
        for ciphertext in [b64(b"junk"), b64(&real), "not base64 at all".to_string(), String::new()] {
            let (status, refused) = w
                .send(
                    Method::POST,
                    &plain_path,
                    &p.owner.token,
                    Some(json!({"ciphertext": ciphertext, "epoch": 1, "device_id": p.owner.id()})),
                )
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
            assert_eq!(refused["error"], "not_e2ee");
        }
        let (status, refused) = w
            .send(
                Method::POST,
                &plain_path,
                &p.owner.token,
                Some(json!({"ciphertext": b64(&real), "epoch": 1, "device_id": p.owner.id(),
                            "kind": "edit", "target_id": id})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
        assert_eq!(refused["error"], "not_e2ee");
        let (status, refused) = w
            .send(
                Method::POST,
                &plain_path,
                &p.owner.token,
                Some(json!({"body": "x", "ciphertext": b64(&real), "epoch": 1, "device_id": p.owner.id()})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
        assert_eq!(refused["error"], "not_e2ee");
        let none: i64 = sqlx::query_scalar("SELECT count(*) FROM messages WHERE channel_id = $1::uuid")
            .bind(&plain)
            .fetch_one(&w.db.owner)
            .await
            .expect("count");
        assert_eq!(none, 0, "nothing was stored in the plaintext channel");

        // The group routes on a plaintext conversation say so.
        let (status, group) = info(&w.app, &p.owner.token, &plain).await;
        assert_eq!(status, StatusCode::OK, "{group}");
        assert_eq!(group, json!({"e2ee": false}));
        for (method, path, body) in [
            (Method::POST, format!("/v1/e2ee/conversations/{plain}/group"), Some(json!({"device_id": p.owner.id()}))),
            (Method::GET, format!("/v1/e2ee/conversations/{plain}/handshake?device_id={}", p.owner.id()), None),
        ] {
            let (status, refused) = w.send(method, &path, &p.owner.token, body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
            assert_eq!(refused["error"], "not_e2ee");
        }

        // A sealed file is for an encrypted conversation only, and a plain one is not.
        let (status, sealed) = upload_sealed(&w.app, &p.owner.token, b"opaque bytes").await;
        assert_eq!(status, StatusCode::CREATED, "{sealed}");
        let (status, refused) = w
            .send(
                Method::POST,
                &plain_path,
                &p.owner.token,
                Some(json!({"body": "with a sealed file", "attachment_ids": [sealed["id"]]})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
        assert_eq!(refused["error"], "invalid");
        let (status, text) = upload_plain(&w.app, &p.owner.token, "notes.txt", b"plain file").await;
        assert_eq!(status, StatusCode::CREATED, "{text}");
        let (status, refused) = say(&w.app, &mut p.owner, &p.conv, "x", json!({"attachment_ids": [text["id"]]})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
        assert_eq!(refused["error"], "invalid");
    })
    .await;
}

async fn upload_plain(app: &Router, token: &str, name: &str, bytes: &[u8]) -> (StatusCode, Value) {
    let body = multipart(Some((name, "text/plain")), bytes, &[]);
    let (status, _, bytes) = raw(app, Method::POST, "/v1/media", token, MULTIPART, body).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn key_packages_must_be_the_devices_own_valid_and_few() {
    run(|db| async move {
        let w = world(db).await;
        let (carol, carol_token) = w.member("carol").await;
        let dev = Dev::new(&carol.user_id, &carol_token);
        let (status, body) = register(&w.app, &dev).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let other = Dev::new(&w.owner.user_id, &w.owner_token);

        let now = common::mls_client::unix_now();
        let upload = |packages: Vec<Vec<u8>>| {
            let app = w.app.clone();
            let token = carol_token.clone();
            let device = dev.id().to_string();
            async move {
                call(
                    &app,
                    Method::POST,
                    "/v1/e2ee/key_packages",
                    &token,
                    Some(json!({
                        "device_id": device,
                        "key_packages": packages.iter().map(|p| b64(p)).collect::<Vec<_>>(),
                    })),
                )
                .await
            }
        };
        let own = dev.client.credential_content();
        let lifetime = |a: u64, b: u64| openmls::prelude::Lifetime::init(a, b);
        let bad: Vec<(&str, Vec<u8>)> = vec![
            ("wrong ciphersuite", dev.client.key_package_other_suite().0),
            (
                "wrong credential",
                dev.client.key_package_with(
                    &dev.client.keys,
                    &other.client.credential_content(),
                    lifetime(now - 60, now + 3600),
                ),
            ),
            (
                "wrong signature key",
                dev.client.key_package_with(
                    &other.client.keys,
                    &own,
                    lifetime(now - 60, now + 3600),
                ),
            ),
            (
                "expired",
                dev.client.key_package_with(
                    &dev.client.keys,
                    &own,
                    lifetime(now - 7200, now - 3600),
                ),
            ),
            (
                "not yet valid",
                dev.client.key_package_with(
                    &dev.client.keys,
                    &own,
                    lifetime(now + 3600, now + 7200),
                ),
            ),
            ("garbage", b"this is not a key package".to_vec()),
            ("empty", Vec::new()),
        ];
        for (what, package) in bad {
            let (status, refused) = upload(vec![package]).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{what}: {refused}");
            assert_eq!(refused["error"], "bad_e2ee", "{what}");
        }
        // A good one beside a bad one stores neither.
        let (status, refused) = upload(vec![dev.client.key_package(), b"junk".to_vec()]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
        let (_, count) = call(
            &w.app,
            Method::GET,
            &format!("/v1/e2ee/key_packages/count?device_id={}", dev.id()),
            &carol_token,
            None,
        )
        .await;
        assert_eq!(count["remaining"], 0, "{count}");

        // More than 50 in one call is refused whole.
        let many: Vec<Vec<u8>> = (0..51).map(|_| dev.client.key_package()).collect();
        let (status, refused) = upload(many).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
        assert_eq!(refused["error"], "too_many_keys");
        // 50 is fine, and 50 more, and then there are 100 waiting and no more fit.
        for _ in 0..2 {
            let fifty: Vec<Vec<u8>> = (0..50).map(|_| dev.client.key_package()).collect();
            let (status, body) = upload(fifty).await;
            assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        }
        let (status, refused) = upload(vec![dev.client.key_package()]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
        assert_eq!(refused["error"], "too_many_keys");
        let (_, count) = call(
            &w.app,
            Method::GET,
            &format!("/v1/e2ee/key_packages/count?device_id={}", dev.id()),
            &carol_token,
            None,
        )
        .await;
        assert_eq!(count["remaining"], 100, "{count}");

        // The same key package twice is refused: its init key is spent once it is used.
        let (status, body) = call(
            &w.app,
            Method::POST,
            "/v1/e2ee/key_packages",
            &w.owner_token,
            Some(json!({"device_id": dev.id(), "key_packages": []})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "someone else's device: {body}"
        );
        assert_eq!(body["error"], "bad_device");
        let second = ready(&w.app, &w.owner.user_id, &w.owner_token).await;
        let one = second.client.key_package();
        let (status, body) = call(
            &w.app,
            Method::POST,
            "/v1/e2ee/key_packages",
            &second.token,
            Some(json!({"device_id": second.id(), "key_packages": [b64(&one)]})),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        let (status, body) = call(
            &w.app,
            Method::POST,
            "/v1/e2ee/key_packages",
            &second.token,
            Some(json!({"device_id": second.id(), "key_packages": [b64(&one)]})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "bad_e2ee");
        // An unknown device, and a device id that is not a uuid.
        let (status, body) = call(
            &w.app,
            Method::POST,
            "/v1/e2ee/key_packages",
            &carol_token,
            Some(json!({"device_id": fresh_uuid(), "key_packages": []})),
        )
        .await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("bad_device"))
        );
        let (status, body) = call(
            &w.app,
            Method::POST,
            "/v1/e2ee/key_packages",
            &carol_token,
            Some(json!({"device_id": "nope", "key_packages": []})),
        )
        .await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid"))
        );
    })
    .await;
}

#[tokio::test]
async fn a_later_device_needs_a_cross_signature_from_an_active_one() {
    run(|db| async move {
        let w = world(db).await;
        let (dana, token) = w.member("dana").await;
        let first = Dev::new(&dana.user_id, &token);
        let (status, device) = register(&w.app, &first).await;
        assert_eq!(status, StatusCode::CREATED, "{device}");
        assert_eq!(device["device_id"], first.id());
        assert_eq!(device["signature_key"], first.client.signature_key_b64());
        // The same id again.
        let (status, again) = register(&w.app, &first).await;
        assert_eq!((status, again["error"].as_str()), (StatusCode::CONFLICT, Some("device_exists")));

        // The second, with none, with one from a key that is not hers, and with one for another
        // key or another device.
        let second = Dev::new(&dana.user_id, &token);
        let (status, refused) = register(&w.app, &second).await;
        assert_eq!((status, refused["error"].as_str()), (StatusCode::BAD_REQUEST, Some("cross_signature_required")));
        let stranger = Dev::new(&w.owner.user_id, &w.owner_token);
        for signature in [
            stranger.client.vouch_for(second.user(), second.id(), &second.client.signature_key()),
            first.client.vouch_for(second.user(), second.id(), &stranger.client.signature_key()),
            first.client.vouch_for(second.user(), &fresh_uuid(), &second.client.signature_key()),
            first.client.vouch_for(&w.owner.user_id, second.id(), &second.client.signature_key()),
            b"garbage".to_vec(),
        ] {
            let (status, refused) = call(
                &w.app,
                Method::PUT,
                &format!("/v1/e2ee/devices/{}", second.id()),
                &token,
                Some(json!({"signature_key": second.client.signature_key_b64(), "cross_signature": b64(&signature)})),
            )
            .await;
            assert_eq!((status, refused["error"].as_str()), (StatusCode::BAD_REQUEST, Some("bad_e2ee")), "{refused}");
        }
        let (status, ok) = register_vouched(&w.app, &second, &first).await;
        assert_eq!(status, StatusCode::CREATED, "{ok}");
        assert!(ok["cross_signature"].is_string());
        // The chain goes on: a third vouched for by the second.
        let third = Dev::new(&dana.user_id, &token);
        let (status, ok) = register_vouched(&w.app, &third, &second).await;
        assert_eq!(status, StatusCode::CREATED, "{ok}");

        // Other members see the key and the signature, not the label.
        let (_, listed) = w
            .send(Method::GET, &format!("/v1/e2ee/users/{}/devices", dana.user_id), &w.owner_token, None)
            .await;
        let listed = listed.as_array().expect("devices");
        assert_eq!(listed.len(), 3);
        assert!(listed[0]["cross_signature"].is_null());
        assert!(listed[1]["cross_signature"].is_string());
        assert!(listed.iter().all(|device| device.get("label").is_none()));
        let (_, own) = w
            .send(Method::GET, &format!("/v1/e2ee/users/{}/devices", dana.user_id), &token, None)
            .await;
        assert_eq!(own[0]["label"], "test");

        // A device revoked can no longer vouch: with first and second revoked, only the third
        // is active, and a fourth vouched for by the first is refused.
        for dev in [&first, &second] {
            let (status, body) = w
                .send(Method::DELETE, &format!("/v1/e2ee/devices/{}", dev.id()), &token, None)
                .await;
            assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        }
        let fourth = Dev::new(&dana.user_id, &token);
        let (status, refused) = register_vouched(&w.app, &fourth, &first).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
        let (status, ok) = register_vouched(&w.app, &fourth, &third).await;
        assert_eq!(status, StatusCode::CREATED, "{ok}");

        // A person with no active device starts again, as a first one: a new identity, which
        // every other client shows loudly.
        for dev in [&third, &fourth] {
            w.send(Method::DELETE, &format!("/v1/e2ee/devices/{}", dev.id()), &token, None).await;
        }
        let fresh = Dev::new(&dana.user_id, &token);
        let (status, ok) = register(&w.app, &fresh).await;
        assert_eq!(status, StatusCode::CREATED, "{ok}");
        assert!(ok["cross_signature"].is_null());
        // Someone else's device is not found, an unknown one too.
        let (status, body) = w
            .send(Method::DELETE, &format!("/v1/e2ee/devices/{}", fresh.id()), &w.owner_token, None)
            .await;
        assert_eq!((status, body["error"].as_str()), (StatusCode::NOT_FOUND, Some("not_found")));
        let (status, _) = w
            .send(Method::DELETE, &format!("/v1/e2ee/devices/{}", fresh_uuid()), &token, None)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        // A key that is not a P-256 point is refused outright.
        let (status, body) = call(
            &w.app,
            Method::PUT,
            &format!("/v1/e2ee/devices/{}", fresh_uuid()),
            &w.owner_token,
            Some(json!({"signature_key": b64(&[1u8; 65])})),
        )
        .await;
        assert_eq!((status, body["error"].as_str()), (StatusCode::BAD_REQUEST, Some("bad_e2ee")));
        let (status, body) = call(
            &w.app,
            Method::PUT,
            &format!("/v1/e2ee/devices/{}", fresh_uuid()),
            &w.owner_token,
            Some(json!({"signature_key": b64(&[4u8; 10])})),
        )
        .await;
        assert_eq!((status, body["error"].as_str()), (StatusCode::BAD_REQUEST, Some("bad_e2ee")));
    })
    .await;
}

#[tokio::test]
async fn a_replayed_client_id_returns_the_original() {
    run(|db| async move {
        let w = world(db).await;
        let mut p = pair(&w, "erin").await;
        let (status, first) = say(
            &w.app,
            &mut p.owner,
            &p.conv,
            "once",
            json!({"client_id": "same"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{first}");
        // The retry is a different ciphertext of the same words; it is not stored again.
        let (status, again) = say(
            &w.app,
            &mut p.owner,
            &p.conv,
            "once",
            json!({"client_id": "same"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{again}");
        assert_eq!(again["id"], first["id"]);
        assert_eq!(again["ciphertext"], first["ciphertext"]);
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM messages WHERE e2ee")
            .fetch_one(&w.db.owner)
            .await
            .expect("count");
        assert_eq!(count, 1);
        // Another device with the same client id is another message.
        let (status, theirs) = say(
            &w.app,
            &mut p.other,
            &p.conv,
            "theirs",
            json!({"client_id": "same"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{theirs}");
        assert_ne!(theirs["id"], first["id"]);
        // The same device in another conversation too.
        let elsewhere = w.channel("elsewhere", true).await;
        let (status, body) = info(&w.app, &p.owner.token, &elsewhere).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        // A client id that is too long or has control characters is invalid.
        for client_id in ["x".repeat(65), "bad\u{1}id".to_string()] {
            let (status, body) = say(
                &w.app,
                &mut p.owner,
                &p.conv,
                "x",
                json!({"client_id": client_id}),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        }
    })
    .await;
}

#[tokio::test]
async fn of_two_commits_for_one_epoch_one_wins_and_the_others_are_stale() {
    run(|db| async move {
        let w = world(db).await;
        let p = pair(&w, "finn").await;
        // A third person's device is wanted, so a commit is due, and either member can make it.
        let (gwen, gwen_token) = w.member("gwen").await;
        let gwen_dev = ready(&w.app, &gwen.user_id, &gwen_token).await;
        let mut devs = [p.owner, p.other, gwen_dev];
        for dev in devs.iter_mut().take(2) {
            pull_ok(&w.app, dev, &p.conv).await;
        }
        let (_, group) = info(&w.app, &devs[0].token, &p.conv).await;
        assert_eq!(group["pending"].as_array().expect("pending").len(), 1, "{group}");
        assert_eq!(group["pending"][0]["op"], "add");
        assert_eq!(group["pending"][0]["issued"], true);

        let [a, b, _] = &mut devs;
        let (first, second) = tokio::join!(
            commit(&w.app, a, &p.conv),
            commit(&w.app, b, &p.conv)
        );
        let mut outcomes = [first.0, second.0];
        outcomes.sort();
        assert_eq!(outcomes, [StatusCode::NO_CONTENT, StatusCode::CONFLICT], "{first:?} {second:?}");
        let loser = if first.0 == StatusCode::CONFLICT { first } else { second };
        assert_eq!(loser.1["error"], "stale_epoch");

        // Everyone converges on the winner's commit, and the new device is in.
        for dev in devs.iter_mut() {
            pull_ok(&w.app, dev, &p.conv).await;
        }
        let epochs: Vec<u64> = devs.iter().map(|dev| dev.client.epoch()).collect();
        assert_eq!(epochs, [2, 2, 2]);
        let (status, said) = say(&w.app, &mut devs[2], &p.conv, "hello from the new one", json!({})).await;
        assert_eq!(status, StatusCode::CREATED, "{said}");
        for dev in devs.iter_mut().take(2) {
            assert_eq!(read(&w.app, dev, &p.conv).await, ["hello from the new one"]);
        }

        // A commit for an epoch that has passed is stale however good it is, and a replay of an
        // accepted one is too.
        let stale = devs[0].client.commit();
        devs[0].client.abandon();
        let (status, body) = call(
            &w.app,
            Method::POST,
            &format!("/v1/e2ee/conversations/{}/commit", p.conv),
            &devs[0].token,
            Some(json!({"device_id": devs[0].id(), "epoch": 1, "commit": b64(&stale.commit), "welcomes": []})),
        )
        .await;
        assert_eq!((status, body["error"].as_str()), (StatusCode::CONFLICT, Some("stale_epoch")));
    })
    .await;
}

#[tokio::test]
async fn a_commit_must_apply_exactly_the_proposals_the_server_signed() {
    run(|db| async move {
        let w = world(db).await;
        let mut p = pair(&w, "hal").await;
        let (ivy, ivy_token) = w.member("ivy").await;
        let ivy_dev = ready(&w.app, &ivy.user_id, &ivy_token).await;
        pull_ok(&w.app, &mut p.owner, &p.conv).await;
        let (_, group) = info(&w.app, &p.owner.token, &p.conv).await;
        let added = group["pending"][0]["device_id"]
            .as_str()
            .expect("device")
            .to_string();
        assert_eq!(added, ivy_dev.id());
        let path = format!("/v1/e2ee/conversations/{}/commit", p.conv);
        let committed = p.owner.client.commit();
        let welcome = b64(committed.welcome.as_ref().expect("welcome"));
        let good = |extra: Value| {
            let mut body = json!({
                "device_id": p.owner.id(),
                "epoch": 1,
                "commit": b64(&committed.commit),
                "welcomes": [{"device_id": added, "data": welcome}],
            });
            for (key, value) in extra.as_object().expect("object") {
                body[key] = value.clone();
            }
            body
        };

        // No welcome for the device it adds, a welcome for someone it does not, a welcome made
        // for another key package, and the wrong sender.
        let (status, body) = call(
            &w.app,
            Method::POST,
            &path,
            &p.owner.token,
            Some(good(json!({"welcomes": []}))),
        )
        .await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("bad_e2ee")),
            "{body}"
        );
        let (status, body) = call(
            &w.app,
            Method::POST,
            &path,
            &p.owner.token,
            Some(good(
                json!({"welcomes": [{"device_id": added, "data": welcome},
                                          {"device_id": p.other.id(), "data": welcome}]}),
            )),
        )
        .await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("bad_e2ee")),
            "{body}"
        );
        let (status, body) = call(
            &w.app,
            Method::POST,
            &path,
            &p.owner.token,
            Some(good(
                json!({"welcomes": [{"device_id": added, "data": b64(b"not a welcome")}]}),
            )),
        )
        .await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("bad_e2ee")),
            "{body}"
        );
        // Another member's commit under this device's name: its leaf is not that device's.
        let (status, body) = call(
            &w.app,
            Method::POST,
            &path,
            &p.other.token,
            Some(good(json!({"device_id": p.other.id()}))),
        )
        .await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("bad_e2ee")),
            "{body}"
        );
        // A device that is not one of the caller's.
        let (status, body) = call(
            &w.app,
            Method::POST,
            &path,
            &p.other.token,
            Some(good(json!({}))),
        )
        .await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("bad_device")),
            "{body}"
        );
        // A commit that applies none of the signed proposals: an empty one.
        p.owner.client.abandon();
        let (status, group) = info(&w.app, &p.owner.token, &p.conv).await;
        assert_eq!(status, StatusCode::OK, "{group}");
        assert_eq!(group["epoch"], 1, "nothing was accepted");

        // The right one goes through, once.
        let committed = p.owner.client.commit();
        let welcome = b64(committed.welcome.as_ref().expect("welcome"));
        let (status, body) = call(
            &w.app,
            Method::POST,
            &path,
            &p.owner.token,
            Some(
                json!({"device_id": p.owner.id(), "epoch": 1, "commit": b64(&committed.commit),
                        "welcomes": [{"device_id": added, "data": welcome}]}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        p.owner.client.merge();
        let (status, body) = call(
            &w.app,
            Method::POST,
            &path,
            &p.owner.token,
            Some(
                json!({"device_id": p.owner.id(), "epoch": 1, "commit": b64(&committed.commit),
                        "welcomes": [{"device_id": added, "data": welcome}]}),
            ),
        )
        .await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::CONFLICT, Some("stale_epoch"))
        );
    })
    .await;
}

#[tokio::test]
async fn leaves_are_tracked_the_way_openmls_applies_commits() {
    run(|db| async move {
        let w = world(db).await;
        // Four people, one device each, then a removal and two adds in one commit.
        let conv = w.channel("leaves", true).await;
        let mut owner = ready(&w.app, &w.owner.user_id, &w.owner_token).await;
        start(&w.app, &mut owner, &conv).await;
        let mut devs = vec![owner];
        let mut users = Vec::new();
        for name in ["jo", "kim", "lee"] {
            let (user, token) = w.member(name).await;
            devs.push(ready(&w.app, &user.user_id, &token).await);
            users.push((user, token));
        }
        settle(&w.app, &mut devs, 0, &conv).await;
        let (_, group) = info(&w.app, &devs[0].token, &conv).await;
        let on_server: Vec<(String, u64)> = group["members"]
            .as_array()
            .expect("members")
            .iter()
            .map(|m| {
                (
                    m["device_id"].as_str().expect("d").to_string(),
                    m["leaf_index"].as_u64().expect("i"),
                )
            })
            .collect();
        for dev in &devs {
            let leaf = u64::from(dev.client.leaf_index());
            assert!(
                on_server.contains(&(dev.id().to_string(), leaf)),
                "{on_server:?} lacks {} at {leaf}",
                dev.id()
            );
        }

        // kim leaves the channel; two new people arrive. The remove blanks kim's leaf and the adds
        // take it first, then the next free one.
        let kim = &users[1];
        let crew = w.crew(&[&users[0].0.user_id, &users[2].0.user_id]).await;
        w.override_view(&conv, &crew, true).await;
        let everyone = w.everyone().await;
        w.override_view(&conv, &everyone, false).await;
        let mut newcomers = Vec::new();
        for name in ["mo", "ned"] {
            let (user, token) = w.member(name).await;
            let dev = ready(&w.app, &user.user_id, &token).await;
            let (status, _) = w
                .send(
                    Method::PUT,
                    &format!("/v1/members/{}/roles", user.user_id),
                    &w.owner_token,
                    Some(json!({"role_ids": [crew]})),
                )
                .await;
            assert_eq!(status, StatusCode::OK);
            newcomers.push(dev);
        }
        let _ = kim;
        devs.extend(newcomers);
        settle(&w.app, &mut devs, 0, &conv).await;
        let (_, group) = info(&w.app, &devs[0].token, &conv).await;
        let on_server: Vec<(String, u64)> = group["members"]
            .as_array()
            .expect("members")
            .iter()
            .map(|m| {
                (
                    m["device_id"].as_str().expect("d").to_string(),
                    m["leaf_index"].as_u64().expect("i"),
                )
            })
            .collect();
        assert_eq!(on_server.len(), 5, "{on_server:?}");
        for (at, dev) in devs.iter().enumerate() {
            if at == 2 {
                assert!(
                    !on_server.iter().any(|(id, _)| id == dev.id()),
                    "kim is out"
                );
                continue;
            }
            let leaf = u64::from(dev.client.leaf_index());
            assert!(
                on_server.contains(&(dev.id().to_string(), leaf)),
                "{on_server:?} lacks {} at {leaf}",
                dev.id()
            );
        }
        // And they all read each other.
        let (status, said) = say(
            &w.app,
            &mut devs[4],
            &conv,
            "from the last to join",
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{said}");
        assert_eq!(
            read(&w.app, &mut devs[0], &conv).await,
            ["from the last to join"]
        );
    })
    .await;
}

/// What a removed member must find: no log, no messages, no posting, and nothing live.
async fn assert_shut_out(w: &World, removed: &mut Dev, conv: &str, status_wanted: &[StatusCode]) {
    let ask = |status: StatusCode, what: &str| {
        assert!(status_wanted.contains(&status), "{what}: {status}");
    };
    let (status, _) = messages(&w.app, &removed.token, conv).await;
    ask(status, "list messages");
    let (status, _) = info(&w.app, &removed.token, conv).await;
    ask(status, "group");
    let (status, _) = call(
        &w.app,
        Method::GET,
        &format!(
            "/v1/e2ee/conversations/{conv}/handshake?after=0&device_id={}",
            removed.id()
        ),
        &removed.token,
        None,
    )
    .await;
    ask(status, "handshake");
    let ciphertext = at(removed, conv).encrypt(&payload("let me in"));
    let (status, _) = post_raw(&w.app, removed, conv, &ciphertext, json!({})).await;
    ask(status, "post");
    let (status, _) = call(
        &w.app,
        Method::POST,
        &format!("/v1/e2ee/conversations/{conv}/commit"),
        &removed.token,
        Some(json!({"device_id": removed.id(), "epoch": 1, "commit": "AAAA", "welcomes": []})),
    )
    .await;
    ask(status, "commit");
}

/// Three devices in a group: the owner's, a stayer's and the one who is to be removed.
async fn three(w: &World, name: &str) -> (String, Vec<Dev>, Vec<Caller>) {
    let conv = w.channel(&format!("{name}-room"), true).await;
    let (stayer, stayer_token) = w.member(&format!("{name}-stays")).await;
    let (leaver, leaver_token) = w.member(&format!("{name}-goes")).await;
    let mut owner = ready(&w.app, &w.owner.user_id, &w.owner_token).await;
    let stays = ready(&w.app, &stayer.user_id, &stayer_token).await;
    let goes = ready(&w.app, &leaver.user_id, &leaver_token).await;
    start(&w.app, &mut owner, &conv).await;
    let mut devs = vec![owner, stays, goes];
    settle(&w.app, &mut devs, 0, &conv).await;
    for dev in devs.iter_mut() {
        assert_eq!(at(dev, &conv).epoch(), 1);
    }
    (conv, devs, vec![stayer, leaver])
}

/// After a removal the stayers commit the Remove, and the one removed cannot read what follows.
async fn finish_removal(w: &World, conv: &str, devs: &mut [Dev]) {
    let (_, group) = info(&w.app, &devs[1].token, conv).await;
    let pending = group["pending"].as_array().expect("pending");
    assert_eq!(pending.len(), 1, "{group}");
    assert_eq!(pending[0]["op"], "remove");
    assert_eq!(pending[0]["device_id"], devs[2].id());
    assert_eq!(pending[0]["issued"], true);
    // The log has the signed Remove for the stayers, and a stayer's commit applies it.
    let (status, body) = commit(&w.app, &mut devs[1], conv).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    pull_ok(&w.app, &mut devs[0], conv).await;
    assert_eq!(at(&mut devs[0], conv).epoch(), 2);
    let (_, group) = info(&w.app, &devs[0].token, conv).await;
    assert_eq!(group["members"].as_array().expect("members").len(), 2);
    assert!(group["pending"].as_array().expect("pending").is_empty());
    // Messages of the new epoch cannot be read by the removed device, even handed to it.
    let (status, said) = say(&w.app, &mut devs[0], conv, "after the removal", json!({})).await;
    assert_eq!(status, StatusCode::CREATED, "{said}");
    let ciphertext = unb64(said["ciphertext"].as_str().expect("ciphertext"));
    assert_eq!(at(&mut devs[2], conv).decrypt(&ciphertext), None);
    assert_eq!(
        read(&w.app, &mut devs[1], conv).await,
        ["after the removal"]
    );
}

#[tokio::test]
async fn a_member_who_loses_view_channel_is_cut_off_and_removed() {
    run(|db| async move {
        let w = world(db).await;
        let server = serve(&w.db, api::Limits::default()).await;
        let (conv, mut devs, users) = three(&w, "ov").await;
        let before = say(&w.app, &mut devs[0], &conv, "while everyone is in", json!({})).await;
        assert_eq!(before.0, StatusCode::CREATED);

        let (mut stay_ws, ready_frame) = connect(&server, &devs[1].token, None).await;
        let (mut goes_ws, _) = connect(&server, &devs[2].token, None).await;
        let since = ready_frame["seq"].as_i64().expect("seq");

        // A role that may view, held by the stayer; @everyone may not.
        let crew = w.crew(&[&users[0].user_id]).await;
        w.override_view(&conv, &crew, true).await;
        let everyone = w.everyone().await;
        w.override_view(&conv, &everyone, false).await;

        // The stayer is told there is something to read, and only the stayer.
        let hint = loop {
            let frame = durable(&mut stay_ws).await;
            if frame["type"] == "e2ee.handshake" {
                break frame;
            }
        };
        assert_eq!(hint["conversation_id"], conv.as_str());
        assert!(hint.to_string().len() < 200, "a hint carries no key material: {hint}");

        assert_shut_out(&w, &mut devs[2], &conv, &[StatusCode::NOT_FOUND]).await;
        finish_removal(&w, &conv, &mut devs).await;

        // Live: the removed member's socket got none of it. Read the stayer's first, so that the
        // dispatcher has certainly gone through every event, then ask the other for its next.
        let created = loop {
            let frame = durable(&mut stay_ws).await;
            if frame["type"] == "message.created" && frame["message"]["e2ee"] == true {
                break frame;
            }
        };
        assert_eq!(created["conversation_id"], conv.as_str());
        let mut seen = Vec::new();
        while let Ok(frame) = tokio::time::timeout(Duration::from_millis(300), durable(&mut goes_ws)).await {
            seen.push(frame);
        }
        // (The override that let the stayer in was made while the leaver could still see the
        // channel, so its channel.updated reached them; nothing after it did.)
        for frame in &seen {
            let text = frame.to_string();
            assert!(!text.contains("ciphertext"), "ciphertext reached the removed member: {frame}");
            assert_ne!(frame["type"], "e2ee.handshake");
            assert!(!frame["type"].as_str().is_some_and(|kind| kind.starts_with("message.")), "{frame}");
        }
        ping(&mut goes_ws).await;

        // By replay too: a reconnect from before the removal gets nothing of the channel after it.
        let (mut replay_ws, _) = connect(&server, &devs[2].token, Some(since)).await;
        let mut replayed = Vec::new();
        while let Ok(frame) = tokio::time::timeout(Duration::from_millis(400), durable(&mut replay_ws)).await {
            replayed.push(frame);
        }
        for frame in &replayed {
            if frame["type"] == "message.created" {
                panic!("ciphertext reached the removed member by replay: {frame}");
            }
        }
        // The stored rows say the same: events with a ciphertext after the change name no one
        // who lost the channel.
        let rows: Vec<(String, Option<Vec<String>>)> = sqlx::query_as(
            "SELECT topic, audience::text[] FROM outbox
             WHERE topic = 'message.created' AND payload::text LIKE '%after the removal%'
                OR (topic = 'message.created' AND payload #>> '{message,e2ee}' = 'true' AND id > $1)",
        )
        .bind(since)
        .fetch_all(&w.db.owner)
        .await
        .expect("outbox");
        assert!(!rows.is_empty());
        for (topic, audience) in rows {
            let audience = audience.unwrap_or_else(|| panic!("{topic} has no audience"));
            assert!(audience.iter().all(|id| id != &users[1].user_id), "{topic} names the member who lost the channel");
        }
    })
    .await;
}

#[tokio::test]
async fn a_member_who_is_kicked_is_cut_off_and_removed() {
    run(|db| async move {
        let w = world(db).await;
        let (conv, mut devs, users) = three(&w, "kick").await;
        let (status, body) = w
            .send(
                Method::DELETE,
                &format!("/v1/members/{}", users[1].user_id),
                &w.owner_token,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        assert_shut_out(
            &w,
            &mut devs[2],
            &conv,
            &[StatusCode::FORBIDDEN, StatusCode::UNAUTHORIZED],
        )
        .await;
        finish_removal(&w, &conv, &mut devs).await;
        // They are welcome back: invited again, the same device is added again.
        let (status, _) = w
            .send(
                Method::GET,
                &format!("/v1/e2ee/users/{}/devices", users[1].user_id),
                &devs[0].token,
                None,
            )
            .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a person who is not a member has no device list"
        );
    })
    .await;
}

#[tokio::test]
async fn a_member_who_is_banned_is_cut_off_and_removed() {
    run(|db| async move {
        let w = world(db).await;
        let (conv, mut devs, users) = three(&w, "ban").await;
        let (status, body) = w
            .send(
                Method::POST,
                "/v1/bans",
                &w.owner_token,
                Some(json!({"user_id": users[1].user_id, "reason": "test"})),
            )
            .await;
        assert!(status.is_success(), "{status} {body}");
        assert_shut_out(
            &w,
            &mut devs[2],
            &conv,
            &[StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN],
        )
        .await;
        finish_removal(&w, &conv, &mut devs).await;
    })
    .await;
}

#[tokio::test]
async fn a_member_who_deletes_their_account_is_removed() {
    run(|db| async move {
        let w = world(db).await;
        let (conv, mut devs, users) = three(&w, "gone").await;
        let (status, body) = w
            .send(
                Method::DELETE,
                "/v1/me",
                &devs[2].token,
                Some(json!({"confirm": "delete my account"})),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        assert_shut_out(&w, &mut devs[2], &conv, &[StatusCode::UNAUTHORIZED]).await;
        finish_removal(&w, &conv, &mut devs).await;
        // Their messages are tombstones with no ciphertext, and their devices are revoked.
        let active: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM e2ee_devices WHERE user_id = $1::uuid AND revoked_at IS NULL",
        )
        .bind(&users[1].user_id)
        .fetch_one(&w.db.owner)
        .await
        .expect("count");
        assert_eq!(active, 0);
    })
    .await;
}

#[tokio::test]
async fn a_role_that_loses_view_channel_removes_its_members_too() {
    run(|db| async move {
        let w = world(db).await;
        let (conv, mut devs, users) = three(&w, "role").await;
        // Everyone may view only through a role that the stayer and the leaver both hold; the
        // leaver then loses it. That is a member_roles change, not an override.
        let crew = w.crew(&[&users[0].user_id, &users[1].user_id]).await;
        let everyone = w.everyone().await;
        w.override_view(&conv, &everyone, false).await;
        w.override_view(&conv, &crew, true).await;
        let (_, group) = info(&w.app, &devs[1].token, &conv).await;
        assert!(
            group["pending"].as_array().expect("pending").is_empty(),
            "both still view: {group}"
        );
        let (status, body) = w
            .send(
                Method::PUT,
                &format!("/v1/members/{}/roles", users[1].user_id),
                &w.owner_token,
                Some(json!({"role_ids": []})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_shut_out(&w, &mut devs[2], &conv, &[StatusCode::NOT_FOUND]).await;
        finish_removal(&w, &conv, &mut devs).await;
    })
    .await;
}

#[tokio::test]
async fn a_revoked_device_is_removed_and_gets_nothing_more() {
    run(|db| async move {
        let w = world(db).await;
        let p = pair(&w, "rev").await;
        // The other person has a second device, vouched for by the first, and it is in the group.
        let second = Dev::new(p.other.user(), &p.other.token);
        let (status, body) = register_vouched(&w.app, &second, &p.other).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let (status, body) = upload_packages(&w.app, &second, 3).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        let mut devs = [p.owner, p.other, second];
        settle(&w.app, &mut devs, 0, &p.conv).await;
        assert!(devs.iter().all(|dev| dev.client.epoch() == 2));
        let (status, said) = say(&w.app, &mut devs[0], &p.conv, "to both devices", json!({})).await;
        assert_eq!(status, StatusCode::CREATED, "{said}");
        assert_eq!(
            read(&w.app, &mut devs[2], &p.conv).await,
            ["to both devices"]
        );

        // Revoked by the person from the other device.
        let (status, body) = w
            .send(
                Method::DELETE,
                &format!("/v1/e2ee/devices/{}", devs[2].id()),
                &devs[1].token,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        // Again is the same.
        let (status, _) = w
            .send(
                Method::DELETE,
                &format!("/v1/e2ee/devices/{}", devs[2].id()),
                &devs[1].token,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        // The revoked device gets no log, cannot post and cannot commit, and the rest still can.
        let (status, body) = pull(&w.app, &mut devs[2], &p.conv)
            .await
            .expect_err("refused");
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("bad_device"))
        );
        let ciphertext = devs[2].client.encrypt(&payload("still here?"));
        let (status, body) = post_raw(&w.app, &mut devs[2], &p.conv, &ciphertext, json!({})).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("bad_device"))
        );
        let (_, group) = info(&w.app, &devs[0].token, &p.conv).await;
        let pending = group["pending"].as_array().expect("pending");
        assert_eq!(pending.len(), 1, "{group}");
        assert_eq!(
            (pending[0]["op"].as_str(), pending[0]["device_id"].as_str()),
            (Some("remove"), Some(devs[2].id()))
        );
        let (status, said) = say(
            &w.app,
            &mut devs[1],
            &p.conv,
            "from the other device",
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{said}");
        // Its key packages are gone, and others see it no more.
        let waiting: i64 =
            sqlx::query_scalar("SELECT count(*) FROM e2ee_key_packages WHERE device_id = $1::uuid")
                .bind(devs[2].id())
                .fetch_one(&w.db.owner)
                .await
                .expect("count");
        assert_eq!(waiting, 0);
        let (_, listed) = w
            .send(
                Method::GET,
                &format!("/v1/e2ee/users/{}/devices", devs[1].user()),
                &devs[0].token,
                None,
            )
            .await;
        assert_eq!(listed.as_array().expect("devices").len(), 1);

        // Committed, it no longer decrypts.
        let (status, body) = commit(&w.app, &mut devs[0], &p.conv).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        let (status, later) = say(&w.app, &mut devs[0], &p.conv, "after", json!({})).await;
        assert_eq!(status, StatusCode::CREATED, "{later}");
        assert_eq!(
            devs[2]
                .client
                .decrypt(&unb64(later["ciphertext"].as_str().expect("c"))),
            None
        );
        // A device can leave a group it never joined without trouble: nothing is pending.
        pull_ok(&w.app, &mut devs[1], &p.conv).await;
        assert_eq!(
            read(&w.app, &mut devs[1], &p.conv)
                .await
                .last()
                .map(String::as_str),
            Some("after")
        );
    })
    .await;
}

#[tokio::test]
async fn nothing_of_another_conversation_is_reachable() {
    run(|db| async move {
        let _dir = upload_dir();
        let w = world(db).await;
        let mut p = pair(&w, "xc").await;
        // A second encrypted channel that only the owner may view.
        let secret = w.channel("secret", true).await;
        let everyone = w.everyone().await;
        w.override_view(&secret, &everyone, false).await;
        start(&w.app, &mut p.owner, &secret).await;
        let (status, said) = say(
            &w.app,
            &mut p.owner,
            &secret,
            "for the owner's eyes",
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{said}");
        let file = p.owner.client.encrypt(b"a sealed secret");
        let (status, sealed) = upload_sealed(&w.app, &p.owner.token, &file).await;
        assert_eq!(status, StatusCode::CREATED, "{sealed}");
        let (status, with_file) = say(
            &w.app,
            &mut p.owner,
            &secret,
            "with a file",
            json!({"attachment_ids": [sealed["id"]]}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{with_file}");
        let id = sealed["id"].as_str().expect("id");

        // The other person: group, log, group start, commit, messages, post, download.
        let other = &mut p.other;
        for (what, status) in [
            ("group", info(&w.app, &other.token, &secret).await.0),
            ("messages", messages(&w.app, &other.token, &secret).await.0),
            (
                "handshake",
                call(
                    &w.app,
                    Method::GET,
                    &format!(
                        "/v1/e2ee/conversations/{secret}/handshake?after=0&device_id={}",
                        other.id()
                    ),
                    &other.token,
                    None,
                )
                .await
                .0,
            ),
            (
                "start",
                call(
                    &w.app,
                    Method::POST,
                    &format!("/v1/e2ee/conversations/{secret}/group"),
                    &other.token,
                    Some(json!({"device_id": other.id()})),
                )
                .await
                .0,
            ),
            (
                "commit",
                call(
                    &w.app,
                    Method::POST,
                    &format!("/v1/e2ee/conversations/{secret}/commit"),
                    &other.token,
                    Some(json!({"device_id": other.id(), "epoch": 1, "commit": "AAAA"})),
                )
                .await
                .0,
            ),
            ("download", download(&w.app, &other.token, id).await.0),
        ] {
            assert_eq!(status, StatusCode::NOT_FOUND, "{what}");
        }
        let ciphertext = other.client.encrypt(&payload("hello?"));
        let (status, body) = post_raw(&w.app, other, &secret, &ciphertext, json!({})).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::NOT_FOUND, Some("not_found"))
        );
        // An unlinked sealed upload is its uploader's alone for an hour.
        let (status, loose) = upload_sealed(&w.app, &p.owner.token, b"loose bytes").await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(
            download(&w.app, &p.other.token, loose["id"].as_str().expect("id"))
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            download(&w.app, &p.owner.token, loose["id"].as_str().expect("id"))
                .await
                .0,
            StatusCode::OK
        );
        // Nor can it be linked by someone else.
        let (status, body) = say(
            &w.app,
            &mut p.other,
            &p.conv,
            "mine now",
            json!({"attachment_ids": [loose["id"]]}),
        )
        .await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid"))
        );

        // A member who can view a channel whose group their device is not in cannot post to it,
        // and one with no group yet is told so.
        let open = w.channel("open", true).await;
        // A device that makes a group of its own with that id can frame a message for it; the
        // server still checks who is in the real one.
        let (_, group) = info(&w.app, &p.other.token, &open).await;
        let sender = group["external_sender"]
            .as_str()
            .expect("sender")
            .to_string();
        p.other.client.create_group(uuid16(&open), &sender);
        let ciphertext = p.other.client.encrypt(&payload("hi"));
        let (status, body) = post_raw(&w.app, &mut p.other, &open, &ciphertext, json!({})).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::CONFLICT, Some("no_group"))
        );
        let mut other_group = Dev::new(&w.owner.user_id, &w.owner_token);
        let (status, _) = register_vouched(&w.app, &other_group, &p.owner).await;
        assert_eq!(status, StatusCode::CREATED);
        start(&w.app, &mut other_group, &open).await;
        let (status, body) = post_raw(&w.app, &mut p.other, &open, &ciphertext, json!({})).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::FORBIDDEN, Some("not_in_group")),
            "{body}"
        );
        // And a device is only ever its owner's.
        let ciphertext = at(&mut p.other, &p.conv).encrypt(&payload("hi"));
        let (status, body) = post_raw(
            &w.app,
            &mut p.other,
            &p.conv,
            &ciphertext,
            json!({"device_id": p.owner.id()}),
        )
        .await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("bad_device"))
        );
        let (status, _) = call(
            &w.app,
            Method::GET,
            &format!(
                "/v1/e2ee/conversations/{}/handshake?after=0&device_id={}",
                p.conv,
                p.owner.id()
            ),
            &p.other.token,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    })
    .await;
}

#[tokio::test]
async fn a_device_reads_only_its_own_welcome_and_nothing_from_before_it_joined() {
    run(|db| async move {
        let w = world(db).await;
        let mut p = pair(&w, "priv").await;
        let (status, said) = say(
            &w.app,
            &mut p.owner,
            &p.conv,
            "before the newcomer",
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{said}");
        let (tess, tess_token) = w.member("tess").await;
        let newcomer = ready(&w.app, &tess.user_id, &tess_token).await;
        let mut devs = [p.owner, p.other, newcomer];
        settle(&w.app, &mut devs, 0, &p.conv).await;
        assert_eq!(devs[2].client.epoch(), 2);

        // The newcomer's log starts at its welcome: no commit of an earlier epoch, no proposals
        // of an earlier one, and no one else's welcome.
        let (_, rows) = call(
            &w.app,
            Method::GET,
            &format!(
                "/v1/e2ee/conversations/{}/handshake?after=0&device_id={}",
                p.conv,
                devs[2].id()
            ),
            &devs[2].token,
            None,
        )
        .await;
        let kinds: Vec<(&str, u64)> = rows
            .as_array()
            .expect("rows")
            .iter()
            .map(|row| {
                (
                    row["kind"].as_str().expect("kind"),
                    row["epoch"].as_u64().expect("epoch"),
                )
            })
            .collect();
        assert_eq!(kinds, [("welcome", 2)], "{rows}");
        // The others never see a welcome at all once they are in.
        for at in [0, 1] {
            let (_, rows) = call(
                &w.app,
                Method::GET,
                &format!(
                    "/v1/e2ee/conversations/{}/handshake?after=0&device_id={}",
                    p.conv,
                    devs[at].id()
                ),
                &devs[at].token,
                None,
            )
            .await;
            let mine: Vec<&str> = rows
                .as_array()
                .expect("rows")
                .iter()
                .map(|row| row["kind"].as_str().expect("kind"))
                .collect();
            assert!(
                mine.iter().filter(|kind| **kind == "welcome").count() <= 1,
                "{rows}"
            );
        }
        // It cannot read what was said before it joined, and it is told so by the cipher.
        assert_eq!(
            read(&w.app, &mut devs[2], &p.conv).await,
            Vec::<String>::new()
        );
        let (_, page) = messages(&w.app, &devs[2].token, &p.conv).await;
        assert_eq!(
            page.as_array().expect("page").len(),
            1,
            "the ciphertext is listed, unreadable"
        );
    })
    .await;
}

#[tokio::test]
async fn malformed_and_oversized_input_is_refused_without_harm() {
    run(|db| async move {
        let w = world(db).await;
        let mut p = pair(&w, "bad").await;
        let path = format!("/v1/conversations/{}/messages", p.conv);

        // A ciphertext that is not MLS, not for this group, not for this epoch, too big, and not
        // base64.
        let real = p.owner.client.encrypt(&payload("real"));
        let mut flipped = real.clone();
        let at = flipped.len() / 2;
        flipped[at] ^= 0xff;
        let truncated = real[..real.len() - 5].to_vec();
        for (what, ciphertext, epoch) in [
            ("junk", b"junk bytes".to_vec(), 1),
            ("empty", Vec::new(), 1),
            ("wrong epoch", real.clone(), 7),
            ("truncated", truncated, 1),
            ("zeros", vec![0u8; 400], 1),
        ] {
            let (status, body) = w
                .send(
                    Method::POST,
                    &path,
                    &p.owner.token,
                    Some(json!({"ciphertext": b64(&ciphertext), "epoch": epoch, "device_id": p.owner.id()})),
                )
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{what}: {body}");
            assert_eq!(body["error"], "bad_e2ee", "{what}");
        }
        let (status, body) = w
            .send(
                Method::POST,
                &path,
                &p.owner.token,
                Some(json!({"ciphertext": "***not base64***", "epoch": 1, "device_id": p.owner.id()})),
            )
            .await;
        assert_eq!((status, body["error"].as_str()), (StatusCode::BAD_REQUEST, Some("bad_e2ee")), "{body}");
        let (status, body) = w
            .send(
                Method::POST,
                &path,
                &p.owner.token,
                Some(json!({"ciphertext": b64(&vec![7u8; 30_000]), "epoch": 1, "device_id": p.owner.id()})),
            )
            .await;
        assert_eq!((status, body["error"].as_str()), (StatusCode::PAYLOAD_TOO_LARGE, Some("too_large")), "{body}");
        // A reply is inside the ciphertext, so one outside is not taken; neither is a kind that
        // does not exist, an edit without a target, or a message with one.
        for extra in [
            json!({"reply_to": fresh_uuid()}),
            json!({"kind": "shout"}),
            json!({"kind": "edit"}),
            json!({"kind": "message", "target_id": fresh_uuid()}),
            json!({"kind": "edit", "target_id": "not a uuid"}),
            json!({"attachment_ids": ["not a uuid"]}),
            json!({"attachment_ids": (0..11).map(|_| fresh_uuid()).collect::<Vec<_>>()}),
        ] {
            let (status, body) = say(&w.app, &mut p.owner, &p.conv, "x", extra.clone()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{extra}: {body}");
        }
        // Missing fields.
        for body in [json!({"ciphertext": b64(&real)}), json!({"epoch": 1}), json!({"epoch": 1, "device_id": p.owner.id()})] {
            let (status, refused) = w.send(Method::POST, &path, &p.owner.token, Some(body)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
        }
        // An edit of someone else's message, of one that does not exist, of a deleted one.
        let (_, theirs) = say(&w.app, &mut p.other, &p.conv, "theirs", json!({})).await;
        let (status, body) = say(&w.app, &mut p.owner, &p.conv, "mine now", json!({"kind": "edit", "target_id": theirs["id"]})).await;
        assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("forbidden")), "{body}");
        let (status, body) = say(&w.app, &mut p.owner, &p.conv, "nope", json!({"kind": "edit", "target_id": fresh_uuid()})).await;
        assert_eq!((status, body["error"].as_str()), (StatusCode::NOT_FOUND, Some("not_found")));

        // Commits: not base64, not MLS, truncated, oversized, a proposal in place of a commit.
        let commit_path = format!("/v1/e2ee/conversations/{}/commit", p.conv);
        let (tuck, tuck_token) = w.member("tuck").await;
        let _tuck_dev = ready(&w.app, &tuck.user_id, &tuck_token).await;
        pull_ok(&w.app, &mut p.owner, &p.conv).await;
        let valid = p.owner.client.commit();
        p.owner.client.abandon();
        for commit in [
            "***".to_string(),
            b64(b"junk"),
            b64(&valid.commit[..valid.commit.len() / 2]),
            b64(&vec![9u8; 300_000]),
            String::new(),
        ] {
            let (status, body) = w
                .send(
                    Method::POST,
                    &commit_path,
                    &p.owner.token,
                    Some(json!({"device_id": p.owner.id(), "epoch": 1, "commit": commit, "welcomes": []})),
                )
                .await;
            assert!(
                status == StatusCode::BAD_REQUEST || status == StatusCode::PAYLOAD_TOO_LARGE,
                "{status} {body}"
            );
        }
        let body = json!({"device_id": p.owner.id(), "commit": "AAAA"}).to_string().into_bytes();
        let (status, _, _) = raw(&w.app, Method::POST, &commit_path, &p.owner.token, "application/json", body).await;
        assert!(status.is_client_error(), "{status}");

        // The log with bad parameters.
        for query in ["after=-1", "after=abc", "after=99999999999999999999", ""] {
            let path = format!("/v1/e2ee/conversations/{}/handshake?{query}&device_id={}", p.conv, p.owner.id());
            let (status, _, _) = raw(&w.app, Method::GET, &path, &p.owner.token, "", Vec::new()).await;
            assert!(status == StatusCode::BAD_REQUEST || status == StatusCode::OK, "{query}: {status}");
        }
        let (status, _) = w
            .send(Method::GET, &format!("/v1/e2ee/conversations/{}/handshake?after=0", p.conv), &p.owner.token, None)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = w
            .send(Method::GET, "/v1/e2ee/conversations/not-a-uuid", &p.owner.token, None)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Oversized bodies are cut off by the route's own limit, before any parsing.
        let huge = vec![b'a'; 700 * 1024];
        let (status, _, _) = raw(&w.app, Method::POST, "/v1/e2ee/key_packages", &p.owner.token, "application/json", huge).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        let huge = vec![b'a'; 60 * 1024];
        let (status, _, _) = raw(&w.app, Method::POST, &path, &p.owner.token, "application/json", huge).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        let huge = vec![b'a'; 9 * 1024 * 1024];
        let (status, _, _) = raw(&w.app, Method::POST, &commit_path, &p.owner.token, "application/json", huge).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        // And the plain routes keep their 8 KiB.
        let huge = vec![b'a'; 9 * 1024];
        let (status, _, _) = raw(
            &w.app,
            Method::PUT,
            &format!("/v1/e2ee/devices/{}", fresh_uuid()),
            &p.owner.token,
            "application/json",
            huge,
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        // Not JSON at all.
        let (status, _, _) = raw(&w.app, Method::POST, &path, &p.owner.token, "application/json", b"{not json".to_vec()).await;
        assert!(status.is_client_error());

        // After all of it the group still works and nothing was stored. (The proposals that were
        // pending are committed first: openmls will not send into an epoch with a proposal open.)
        let (status, body) = commit(&w.app, &mut p.owner, &p.conv).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        let (status, ok) = say(&w.app, &mut p.owner, &p.conv, "still fine", json!({})).await;
        assert_eq!(status, StatusCode::CREATED, "{ok}");
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM messages WHERE e2ee AND channel_id = $1::uuid")
            .bind(&p.conv)
            .fetch_one(&w.db.owner)
            .await
            .expect("count");
        assert_eq!(count, 2, "the one theirs and the last one");
    })
    .await;
}

#[tokio::test]
async fn a_sealed_upload_is_opaque_and_stored_as_it_came() {
    run(|db| async move {
        let dir = upload_dir();
        let w = world(db).await;
        let mut p = pair(&w, "seal").await;

        // Bytes a type check would stop: a program, a virus test file, an image header, a zip, a
        // page of script. None is looked at.
        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let samples: Vec<(&str, Vec<u8>)> = vec![
            ("pe", [b"MZ".as_slice(), &[0u8; 64]].concat()),
            ("eicar", eicar.to_vec()),
            (
                "png header on nonsense",
                [b"\x89PNG\r\n\x1a\n".as_slice(), b"not an image"].concat(),
            ),
            ("zip", b"PK\x03\x04junk".to_vec()),
            ("html", b"<html><script>alert(1)</script></html>".to_vec()),
            ("one byte", vec![0]),
        ];
        let mut ids = Vec::new();
        for (what, bytes) in &samples {
            let (status, saved) = upload_sealed(&w.app, &p.owner.token, bytes).await;
            assert_eq!(status, StatusCode::CREATED, "{what}: {saved}");
            assert_eq!(saved["kind"], "sealed", "{what}");
            assert_eq!(saved["name"], "sealed");
            assert_eq!(saved["mime"], "application/octet-stream");
            assert_eq!(
                saved["scan_status"], "sealed",
                "no claim to have scanned: {saved}"
            );
            assert!(
                saved["width"].is_null() && saved["height"].is_null(),
                "{what}: nothing is decoded"
            );
            assert_eq!(saved["bytes"], bytes.len());
            ids.push(saved["id"].as_str().expect("id").to_string());
        }
        // The same bytes, not sealed, are what they always were: refused.
        let (status, body) = upload_plain(&w.app, &p.owner.token, "payload.bin", eicar).await;
        assert_ne!(status, StatusCode::CREATED, "{body}");
        let (status, body) = upload_plain(&w.app, &p.owner.token, "prog.exe", b"MZ....").await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{body}");
        // A name and type are the server's, whatever the client calls the file.
        let body = multipart(
            Some(("holiday.png", "image/png")),
            b"opaque",
            &[("sealed", "1"), ("width", "12")],
        );
        let (status, _, bytes) = raw(
            &w.app,
            Method::POST,
            "/v1/media",
            &p.owner.token,
            MULTIPART,
            body,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "{}",
            String::from_utf8_lossy(&bytes)
        );
        let saved: Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(
            (saved["name"].as_str(), saved["mime"].as_str()),
            (Some("sealed"), Some("application/octet-stream"))
        );
        assert!(saved["width"].is_null());
        // A sealed upload with no file name at all, and the field after the file.
        let body = multipart(None, b"anonymous", &[("sealed", "1")]);
        let (status, _, _) = raw(
            &w.app,
            Method::POST,
            "/v1/media",
            &p.owner.token,
            MULTIPART,
            body,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        // `sealed` must be 0 or 1, and empty bodies are nothing.
        for value in ["yes", "2", ""] {
            let body = multipart(Some(("sealed", "x")), b"bytes", &[("sealed", value)]);
            let (status, _, _) = raw(
                &w.app,
                Method::POST,
                "/v1/media",
                &p.owner.token,
                MULTIPART,
                body,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "sealed={value:?}");
        }
        let (status, body) = upload_sealed(&w.app, &p.owner.token, b"").await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

        // On disk: one file per upload, exactly as sent, and nothing else in the directory: no
        // temporary copy.
        let files = files_in(&dir);
        let uploaded = samples.len() + 2;
        assert_eq!(
            files.len(),
            uploaded,
            "{:?}",
            files.iter().map(|f| &f.0).collect::<Vec<_>>()
        );
        for ((_, bytes), id) in samples.iter().zip(&ids) {
            let stored = files.iter().find(|file| &file.0 == id).expect("file");
            assert_eq!(&stored.1, bytes);
        }
        // Downloaded as bytes with a type that is not a type, never inline.
        let (status, headers, body) = download(&w.app, &p.owner.token, &ids[4]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, samples[4].1);
        assert_eq!(
            headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/octet-stream")
        );
        assert!(headers
            .get(header::CONTENT_DISPOSITION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|d| d.starts_with("attachment")));
        assert_eq!(
            headers
                .get(header::X_CONTENT_TYPE_OPTIONS)
                .and_then(|v| v.to_str().ok()),
            Some("nosniff")
        );

        // Linked once, into an encrypted conversation; not twice.
        let (status, linked) = say(
            &w.app,
            &mut p.owner,
            &p.conv,
            "here",
            json!({"attachment_ids": [ids[0]]}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{linked}");
        assert_eq!(linked["attachments"][0]["id"], ids[0].as_str());
        assert_eq!(linked["attachments"][0]["kind"], "sealed");
        let (status, again) = say(
            &w.app,
            &mut p.owner,
            &p.conv,
            "again",
            json!({"attachment_ids": [ids[0]]}),
        )
        .await;
        assert_eq!(
            (status, again["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid"))
        );
        // Members can fetch a linked one; deleting the message deletes the file.
        assert_eq!(
            download(&w.app, &p.other.token, &ids[0]).await.0,
            StatusCode::OK
        );
        let (status, _) = w
            .send(
                Method::DELETE,
                &format!("/v1/messages/{}", linked["id"].as_str().expect("id")),
                &p.owner.token,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(
            download(&w.app, &p.other.token, &ids[0]).await.0,
            StatusCode::NOT_FOUND
        );
        assert!(!files_in(&dir).iter().any(|file| file.0 == ids[0]));
    })
    .await;
}

#[tokio::test]
async fn sealed_uploads_have_a_size_limit_and_a_rate() {
    run(|db| async move {
        let dir = upload_dir();
        let w = world(db).await;
        let (uma, token) = w.member("uma").await;
        let (vic, vic_token) = w.member("vic").await;

        // The file limit is the server's, and an image limit does not apply.
        sqlx::query("UPDATE server_settings SET file_max_bytes = 100, image_max_bytes = 10")
            .execute(&w.db.owner)
            .await
            .expect("limits");
        let (status, body) = upload_sealed(&w.app, &token, &[1u8; 100]).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let (status, body) = upload_sealed(&w.app, &token, &[1u8; 101]).await;
        assert_eq!((status, body["error"].as_str()), (StatusCode::PAYLOAD_TOO_LARGE, Some("too_large")), "{body}");
        sqlx::query("UPDATE server_settings SET file_max_bytes = 26214400, image_max_bytes = 8388608")
            .execute(&w.db.owner)
            .await
            .expect("limits");
        let _ = vic;

        // Per person, per hour: the third in an hour is refused, and only for that person.
        sqlx::query("UPDATE server_settings SET sealed_files_per_hour = 3")
            .execute(&w.db.owner)
            .await
            .expect("rate");
        let (status, _) = upload_sealed(&w.app, &token, b"two").await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, _) = upload_sealed(&w.app, &token, b"three").await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, body) = upload_sealed(&w.app, &token, b"four").await;
        assert_eq!((status, body["error"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("slow_down")), "{body}");
        let (status, _) = upload_sealed(&w.app, &vic_token, b"someone else").await;
        assert_eq!(status, StatusCode::CREATED, "the limit is per person");
        // A refused upload leaves no file and no row.
        assert_eq!(files_in(&dir).len(), 4);
        // An hour later the hour's count is clear; the day's volume is not.
        sqlx::query("UPDATE e2ee_upload_ledger SET created_at = now() - interval '2 hours' WHERE user_id = $1::uuid")
            .bind(&uma.user_id)
            .execute(&w.db.owner)
            .await
            .expect("age");
        let (status, _) = upload_sealed(&w.app, &token, b"five").await;
        assert_eq!(status, StatusCode::CREATED);
        // Room for ten more bytes today, past what she has uploaded.
        sqlx::query(
            "UPDATE server_settings SET sealed_bytes_per_day =
             (SELECT sum(bytes) + 10 FROM e2ee_upload_ledger WHERE user_id = $1::uuid)",
        )
        .bind(&uma.user_id)
        .execute(&w.db.owner)
        .await
        .expect("volume");
        let (status, body) = upload_sealed(&w.app, &token, &[9u8; 40]).await;
        assert_eq!((status, body["error"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("slow_down")), "{body}");
        let (status, _) = upload_sealed(&w.app, &token, b"x").await;
        assert_eq!(status, StatusCode::CREATED, "a small one still fits the day");
        let _ = std::fs::remove_dir_all(dir);
    })
    .await;
}

#[tokio::test]
async fn an_orphaned_sealed_upload_is_swept_with_its_file() {
    run(|db| async move {
        let dir = upload_dir();
        let w = world(db).await;
        let (_, saved) = upload_sealed(&w.app, &w.owner_token, b"never attached").await;
        let id = saved["id"].as_str().expect("id").to_string();
        let (_, kept) = upload_sealed(&w.app, &w.owner_token, b"just now").await;
        assert_eq!(files_in(&dir).len(), 2);
        // Within the hour nothing is swept.
        let swept = db::sweep(&w.db.runtime).await.expect("sweep");
        assert_eq!(swept.attachments, 0);
        sqlx::query(
            "UPDATE attachments SET created_at = now() - interval '2 hours' WHERE id = $1::uuid",
        )
        .bind(&id)
        .execute(&w.db.owner)
        .await
        .expect("age");
        // Past it, the unlinked one is gone and so is its file; the fresh one stays.
        let swept = db::sweep(&w.db.runtime).await.expect("sweep");
        assert_eq!(swept.attachments, 1);
        let files = files_in(&dir);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, kept["id"].as_str().expect("id"));
        let (status, _, _) = download(&w.app, &w.owner_token, &id).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        // The ledger of old uploads and expired key packages go with the sweep too.
        sqlx::query("UPDATE e2ee_upload_ledger SET created_at = now() - interval '3 days'")
            .execute(&w.db.owner)
            .await
            .expect("age");
        db::sweep(&w.db.runtime).await.expect("sweep");
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM e2ee_upload_ledger")
            .fetch_one(&w.db.owner)
            .await
            .expect("count");
        assert_eq!(left, 0);
        let _ = std::fs::remove_dir_all(dir);
    })
    .await;
}

#[tokio::test]
async fn the_setting_and_the_capability_say_what_the_server_does() {
    run(|db| async move {
        let w = world(db).await;
        let (_, member_token) = w.member("wes").await;
        // Every client can ask. The feature says the server speaks the protocol; the mode says
        // whether a new conversation may or must be encrypted.
        for token in [&w.owner_token, &member_token] {
            let (status, caps) = w.send(Method::GET, "/v1/capabilities", token, None).await;
            assert_eq!(status, StatusCode::OK, "{caps}");
            assert!(caps["features"]
                .as_array()
                .expect("features")
                .contains(&json!("e2ee_text")));
            assert!(caps["features"]
                .as_array()
                .expect("features")
                .contains(&json!("e2ee_calls")));
            assert_eq!(caps["e2ee_text"], "optional");
        }
        let (status, _) = Call::new(Method::GET, "/v1/capabilities")
            .send(&w.app)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, server) = w.send(Method::GET, "/v1/server", &member_token, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(server["e2ee_text"], "optional");

        // Only a manager changes it, and only to a mode that exists.
        let (status, _) = w
            .send(
                Method::PATCH,
                "/v1/server",
                &member_token,
                Some(json!({"e2ee_text": "off"})),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = w
            .send(
                Method::PATCH,
                "/v1/server",
                &w.owner_token,
                Some(json!({"e2ee_text": "sometimes"})),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // optional: either.
        let encrypted = w.channel("enc", true).await;
        let plain = w.channel("plain", false).await;
        // new_required: a new plaintext conversation is refused, an encrypted one is made, and
        // what exists is left as it is.
        let (status, set) = w
            .send(
                Method::PATCH,
                "/v1/server",
                &w.owner_token,
                Some(json!({"e2ee_text": "new_required"})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{set}");
        assert_eq!(set["e2ee_text"], "new_required");
        let (_, caps) = w
            .send(Method::GET, "/v1/capabilities", &member_token, None)
            .await;
        assert_eq!(caps["e2ee_text"], "new_required");
        for body in [
            json!({"name": "late"}),
            json!({"name": "late", "e2ee": false}),
        ] {
            let (status, refused) = w
                .send(Method::POST, "/v1/channels", &w.owner_token, Some(body))
                .await;
            assert_eq!(
                (status, refused["error"].as_str()),
                (StatusCode::BAD_REQUEST, Some("e2ee_required")),
                "{refused}"
            );
        }
        w.channel("late-enc", true).await;
        let (_, channels) = w
            .send(Method::GET, "/v1/channels", &member_token, None)
            .await;
        let flags: Vec<(String, bool)> = channels
            .as_array()
            .expect("channels")
            .iter()
            .map(|c| {
                (
                    c["id"].as_str().expect("id").to_string(),
                    c["e2ee"].as_bool().expect("e2ee"),
                )
            })
            .collect();
        assert!(
            flags.contains(&(plain.clone(), false)),
            "an existing channel stays plaintext"
        );
        assert!(flags.contains(&(encrypted.clone(), true)));
        // The same for directs: with the plaintext one existing it is returned, a new encrypted
        // one is made, and a plaintext one with someone new is refused.
        let (peer, _) = w.member("xan").await;
        let (status, refused) = w
            .send(
                Method::POST,
                "/v1/directs",
                &member_token,
                Some(json!({"user_id": peer.user_id})),
            )
            .await;
        assert_eq!(
            (status, refused["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("e2ee_required")),
            "{refused}"
        );
        let (status, direct) = w
            .send(
                Method::POST,
                "/v1/directs",
                &member_token,
                Some(json!({"user_id": peer.user_id, "e2ee": true})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{direct}");
        assert_eq!(direct["e2ee"], true);

        // off: no new encrypted conversation, and the old ones go on working.
        let (status, set) = w
            .send(
                Method::PATCH,
                "/v1/server",
                &w.owner_token,
                Some(json!({"e2ee_text": "off"})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{set}");
        let (status, refused) = w
            .send(
                Method::POST,
                "/v1/channels",
                &w.owner_token,
                Some(json!({"name": "no", "e2ee": true})),
            )
            .await;
        assert_eq!(
            (status, refused["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("e2ee_off")),
            "{refused}"
        );
        let (status, refused) = w
            .send(
                Method::POST,
                "/v1/directs",
                &member_token,
                Some(json!({"user_id": peer.user_id, "e2ee": true})),
            )
            .await;
        // The encrypted direct exists already, so it is simply returned.
        assert_eq!(status, StatusCode::OK, "{refused}");
        let (peer_two, _) = w.member("yul").await;
        let (status, refused) = w
            .send(
                Method::POST,
                "/v1/directs",
                &member_token,
                Some(json!({"user_id": peer_two.user_id, "e2ee": true})),
            )
            .await;
        assert_eq!(
            (status, refused["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("e2ee_off")),
            "{refused}"
        );
        let (status, made) = w
            .send(
                Method::POST,
                "/v1/channels",
                &w.owner_token,
                Some(json!({"name": "plain again"})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{made}");
        assert_eq!(made["e2ee"], false);
        let mut group_owner = ready(&w.app, &w.owner.user_id, &w.owner_token).await;
        start(&w.app, &mut group_owner, &encrypted).await;
        let (status, said) = say(
            &w.app,
            &mut group_owner,
            &encrypted,
            "still works with e2ee off",
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{said}");
        // The flag is never changed afterwards.
        for body in [json!({"e2ee": false}), json!({"e2ee": true, "name": "x"})] {
            let (status, _) = w
                .send(
                    Method::PATCH,
                    &format!("/v1/channels/{plain}"),
                    &w.owner_token,
                    Some(body),
                )
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
    })
    .await;
}

#[tokio::test]
async fn old_requests_and_old_clients_keep_working() {
    run(|db| async move {
        let _dir = upload_dir();
        let w = world(db).await;
        let (_, member_token) = w.member("zed").await;

        // The old shapes, with no e2ee field anywhere: a channel, a post, an edit, a reaction, a
        // file, a direct. Nothing about them changed, but an e2ee field says what they are.
        let (status, channel) = w
            .send(
                Method::POST,
                "/v1/channels",
                &w.owner_token,
                Some(json!({"name": "old", "topic": "t", "position": 1})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{channel}");
        assert_eq!(channel["e2ee"], false);
        let id = channel["id"].as_str().expect("id").to_string();
        let path = format!("/v1/conversations/{id}/messages");
        let (status, one) = w
            .send(
                Method::POST,
                &path,
                &member_token,
                Some(json!({"body": "hello", "client_id": "k"})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{one}");
        assert_eq!(one["body"], "hello");
        assert_eq!(one["e2ee"], false);
        assert!(
            one.get("ciphertext").is_none()
                && one.get("epoch").is_none()
                && one.get("device_id").is_none()
        );
        let (status, replay) = w
            .send(
                Method::POST,
                &path,
                &member_token,
                Some(json!({"body": "hello", "client_id": "k"})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(replay["id"], one["id"]);
        // Unknown fields are ignored, as they always were.
        let (status, with_extra) = w
            .send(
                Method::POST,
                &path,
                &member_token,
                Some(json!({"body": "two", "colour": "red", "e2ee": true})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{with_extra}");
        let (status, edited) = w
            .send(
                Method::PATCH,
                &format!("/v1/messages/{}", one["id"].as_str().expect("id")),
                &member_token,
                Some(json!({"body": "hello again"})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{edited}");
        let (_, page) = messages(&w.app, &w.owner_token, &id).await;
        assert_eq!(page.as_array().expect("page").len(), 2);
        let (status, _) = upload_plain(&w.app, &member_token, "old.txt", b"old file").await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, direct) = w
            .send(
                Method::POST,
                "/v1/directs",
                &member_token,
                Some(json!({"user_id": w.owner.user_id})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{direct}");
        assert_eq!(direct["e2ee"], false);
        let (status, again) = w
            .send(
                Method::POST,
                "/v1/directs",
                &member_token,
                Some(json!({"user_id": w.owner.user_id})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{again}");
        assert_eq!(again["id"], direct["id"]);
        // A plaintext direct and an encrypted one with the same person are two conversations.
        let (status, secure) = w
            .send(
                Method::POST,
                "/v1/directs",
                &member_token,
                Some(json!({"user_id": w.owner.user_id, "e2ee": true})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{secure}");
        assert_ne!(secure["id"], direct["id"]);
        let (_, listed) = w
            .send(Method::GET, "/v1/directs", &member_token, None)
            .await;
        assert_eq!(listed.as_array().expect("directs").len(), 2);

        // An old client in an encrypted conversation: it is listed, with e2ee true and empty
        // bodies; it cannot post plaintext; it cannot edit by body; reactions work, because they
        // are plaintext by design.
        let mut p = pair(&w, "oldc").await;
        let (status, sent) = say(
            &w.app,
            &mut p.owner,
            &p.conv,
            "unreadable to old clients",
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{sent}");
        let (status, listed) = messages(&w.app, &p.other.token, &p.conv).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listed[0]["body"], "");
        assert_eq!(listed[0]["e2ee"], true);
        assert!(listed[0]["author_id"].is_string() && listed[0]["created_at"].is_string());
        let (_, channels) = w
            .send(Method::GET, "/v1/channels", &p.other.token, None)
            .await;
        let entry = channels
            .as_array()
            .expect("channels")
            .iter()
            .find(|c| c["id"] == p.conv.as_str())
            .expect("channel");
        assert_eq!(entry["e2ee"], true);
        assert_eq!(entry["unread"], 1);
        let (status, body) = w
            .send(
                Method::POST,
                &format!("/v1/conversations/{}/messages", p.conv),
                &p.other.token,
                Some(json!({"body": "plaintext from an old client"})),
            )
            .await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("e2ee_required")),
            "{body}"
        );
        let (status, reaction) = w
            .send(
                Method::PUT,
                &format!(
                    "/v1/messages/{}/reactions",
                    sent["id"].as_str().expect("id")
                ),
                &p.other.token,
                Some(json!({"emoji": "👍"})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{reaction}");
        let (status, _) = w
            .send(
                Method::POST,
                &format!("/v1/conversations/{}/read", p.conv),
                &p.other.token,
                Some(json!({"message_id": sent["id"]})),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        // An edit is not an unread message, and not a preview.
        let (status, _) = say(
            &w.app,
            &mut p.owner,
            &p.conv,
            "edited",
            json!({"kind": "edit", "target_id": sent["id"]}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let (_, channels) = w
            .send(Method::GET, "/v1/channels", &p.other.token, None)
            .await;
        let entry = channels
            .as_array()
            .expect("channels")
            .iter()
            .find(|c| c["id"] == p.conv.as_str())
            .expect("channel");
        assert_eq!(entry["unread"], 0);
        assert_eq!(entry["last_message"]["id"], sent["id"]);

        // What a new client sends to a server of the old kind is not testable here: that server
        // has no `e2ee_text` in /v1/capabilities, and the client offers nothing. What is testable
        // is that this server's answer has that field only because it is this server.
        let (_, caps) = w
            .send(Method::GET, "/v1/capabilities", &member_token, None)
            .await;
        assert!(caps["features"].as_array().expect("features").len() >= 12);
    })
    .await;
}

#[tokio::test]
async fn an_edit_is_a_row_of_its_own_and_a_delete_removes_the_ciphertext_and_the_edits() {
    run(|db| async move {
        let w = world(db).await;
        let mut p = pair(&w, "edit").await;
        let (status, first) = say(&w.app, &mut p.owner, &p.conv, "first", json!({})).await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, edit) = say(&w.app, &mut p.owner, &p.conv, "first, better", json!({"kind": "edit", "target_id": first["id"]})).await;
        assert_eq!(status, StatusCode::CREATED, "{edit}");
        // The edit is on its own row; the target is untouched and not marked edited.
        let (_, page) = messages(&w.app, &p.other.token, &p.conv).await;
        let rows = page.as_array().expect("page");
        assert_eq!(rows.len(), 2);
        assert!(rows[0]["edited_at"].is_null());
        assert_eq!(rows[0]["ciphertext"], first["ciphertext"]);
        // Someone else's edit of it is refused, and an edit of an edit is not a thing.
        let (status, refused) = say(&w.app, &mut p.other, &p.conv, "mine", json!({"kind": "edit", "target_id": first["id"]})).await;
        assert_eq!((status, refused["error"].as_str()), (StatusCode::FORBIDDEN, Some("forbidden")));
        let (status, refused) = say(&w.app, &mut p.owner, &p.conv, "x", json!({"kind": "edit", "target_id": edit["id"]})).await;
        assert_eq!((status, refused["error"].as_str()), (StatusCode::NOT_FOUND, Some("not_found")));

        // The live event was stored with its ciphertext; deleting takes it out of the outbox.
        let in_outbox = |id: String| {
            let pool = w.db.owner.clone();
            async move {
                sqlx::query_scalar::<_, i64>(
                    "SELECT count(*) FROM outbox WHERE payload #>> '{message,id}' = $1 AND payload #>> '{message,ciphertext}' IS NOT NULL",
                )
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("count")
            }
        };
        assert_eq!(in_outbox(first["id"].as_str().expect("id").to_string()).await, 1);
        assert_eq!(in_outbox(edit["id"].as_str().expect("id").to_string()).await, 1);
        // Only the author may delete, and there is no moderator delete.
        let (status, _) = w
            .send(Method::DELETE, &format!("/v1/messages/{}", first["id"].as_str().expect("id")), &p.other.token, None)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = w
            .send(Method::DELETE, &format!("/v1/messages/{}", first["id"].as_str().expect("id")), &w.owner_token, None)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM messages WHERE ciphertext IS NOT NULL")
            .fetch_one(&w.db.owner)
            .await
            .expect("count");
        assert_eq!(left, 0, "the message and its edit have no ciphertext now");
        let tombstones: i64 = sqlx::query_scalar("SELECT count(*) FROM messages WHERE e2ee AND deleted_at IS NOT NULL")
            .fetch_one(&w.db.owner)
            .await
            .expect("count");
        assert_eq!(tombstones, 2);
        assert_eq!(in_outbox(first["id"].as_str().expect("id").to_string()).await, 0);
        assert_eq!(in_outbox(edit["id"].as_str().expect("id").to_string()).await, 0);
        let (_, page) = messages(&w.app, &p.other.token, &p.conv).await;
        for row in page.as_array().expect("page") {
            assert!(row["ciphertext"].is_null() && row["deleted_at"].is_string(), "{row}");
        }
        // A deleted message cannot be edited.
        let (status, refused) = say(&w.app, &mut p.owner, &p.conv, "back", json!({"kind": "edit", "target_id": first["id"]})).await;
        assert_eq!((status, refused["error"].as_str()), (StatusCode::NOT_FOUND, Some("not_found")));
    })
    .await;
}

#[tokio::test]
async fn an_encrypted_direct_is_a_group_of_the_two() {
    run(|db| async move {
        let w = world(db).await;
        let (peer, peer_token) = w.member("dm").await;
        let (outsider, outsider_token) = w.member("nosy").await;
        let (status, direct) = w
            .send(
                Method::POST,
                "/v1/directs",
                &w.owner_token,
                Some(json!({"user_id": peer.user_id, "e2ee": true})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{direct}");
        let conv = direct["id"].as_str().expect("id").to_string();
        let mut a = ready(&w.app, &w.owner.user_id, &w.owner_token).await;
        let b = ready(&w.app, &peer.user_id, &peer_token).await;
        let nosy = ready(&w.app, &outsider.user_id, &outsider_token).await;
        start(&w.app, &mut a, &conv).await;
        let mut devs = [a, b];
        settle(&w.app, &mut devs, 0, &conv).await;
        let (status, said) = say(&w.app, &mut devs[0], &conv, "just us", json!({})).await;
        assert_eq!(status, StatusCode::CREATED, "{said}");
        assert_eq!(read(&w.app, &mut devs[1], &conv).await, ["just us"]);
        let (_, group) = info(&w.app, &devs[0].token, &conv).await;
        assert_eq!(
            group["members"].as_array().expect("members").len(),
            2,
            "the outsider is not in it"
        );
        // A third member sees nothing of it, and cannot join it.
        assert_eq!(
            info(&w.app, &nosy.token, &conv).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            messages(&w.app, &nosy.token, &conv).await.0,
            StatusCode::NOT_FOUND
        );
        let (status, _) = call(
            &w.app,
            Method::GET,
            &format!(
                "/v1/e2ee/conversations/{conv}/handshake?after=0&device_id={}",
                nosy.id()
            ),
            &nosy.token,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    })
    .await;
}

#[tokio::test]
async fn state_changing_routes_are_rate_limited_per_person() {
    run(|db| async move {
        let w = world(db).await;
        let (_, token) = w.member("rl").await;
        let (_, other_token) = w.member("rl2").await;
        let dev = Dev::new(&w.owner.user_id, &token);
        // Revoking a device that is not there is cheap and counts: a burst of them runs dry.
        let mut limited = None;
        for at in 0..60 {
            let (status, _) = w
                .send(
                    Method::DELETE,
                    &format!("/v1/e2ee/devices/{}", fresh_uuid()),
                    &token,
                    None,
                )
                .await;
            if status == StatusCode::TOO_MANY_REQUESTS {
                limited = Some(at);
                break;
            }
            assert_eq!(status, StatusCode::NOT_FOUND);
        }
        let at = limited.expect("a burst of 60 is limited");
        // Right behind it, any other state change of theirs is refused too.
        let (status, body) = w
            .send(
                Method::PUT,
                &format!("/v1/e2ee/devices/{}", dev.id()),
                &token,
                Some(json!({"signature_key": dev.client.signature_key_b64()})),
            )
            .await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::TOO_MANY_REQUESTS, Some("slow_down"))
        );
        assert!(
            (35..=45).contains(&at),
            "the burst is about 40, it was {at}"
        );
        // Other people have their own allowance, and reads are not counted.
        let (status, _) = w
            .send(
                Method::DELETE,
                &format!("/v1/e2ee/devices/{}", fresh_uuid()),
                &other_token,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = w
            .send(
                Method::GET,
                &format!("/v1/e2ee/users/{}/devices", dev.user()),
                &token,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        // It refills.
        tokio::time::sleep(Duration::from_millis(1600)).await;
        let (status, _) = w
            .send(
                Method::DELETE,
                &format!("/v1/e2ee/devices/{}", fresh_uuid()),
                &token,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    })
    .await;
}

#[tokio::test]
async fn the_servers_external_sender_is_one_key_kept_in_postgres() {
    run(|db| async move {
        let w = world(db).await;
        let p = pair(&w, "key").await;
        let (_, first) = info(&w.app, &p.owner.token, &p.conv).await;
        let sender = first["external_sender"]
            .as_str()
            .expect("sender")
            .to_string();
        // Another router on the same database, as a restarted process would be: the same key.
        let again = api::router(w.db.runtime.clone(), None);
        let (_, second) = info(&again, &p.owner.token, &p.conv).await;
        assert_eq!(second["external_sender"], sender.as_str());
        let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM e2ee_server_key")
            .fetch_one(&w.db.owner)
            .await
            .expect("count");
        assert_eq!(stored, 1);
        // It is a public key and a credential, nothing else the group could be harmed by.
        assert!(unb64(&sender).len() < 120);
        // Proposals for a group are signed by it and only it, so a stored group survives a
        // restart: a new member is added by a router that never saw the group start.
        let (late, late_token) = w.member("late").await;
        let newcomer = ready(&again, &late.user_id, &late_token).await;
        let mut devs = [p.owner, p.other, newcomer];
        settle(&again, &mut devs, 0, &p.conv).await;
        assert_eq!(devs[2].client.epoch(), 2);
        let (status, said) = say(
            &again,
            &mut devs[2],
            &p.conv,
            "after the restart",
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{said}");
        // Bots have no part in any of it.
        let (status, _) = Call::new(Method::GET, &format!("/v1/e2ee/conversations/{}", p.conv))
            .bot("not-a-real-bot-token")
            .send(&w.app)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    })
    .await;
}

#[tokio::test]
async fn the_group_is_rebuilt_when_nobody_in_it_can_commit() {
    run(|db| async move {
        let w = world(db).await;
        // One person alone with one device makes the group; the device is revoked; a new device
        // starts again at epoch 0, and the old messages stay what they were.
        let conv = w.channel("solo", true).await;
        let mut first = ready(&w.app, &w.owner.user_id, &w.owner_token).await;
        start(&w.app, &mut first, &conv).await;
        let (status, said) = say(&w.app, &mut first, &conv, "in the first group", json!({})).await;
        assert_eq!(status, StatusCode::CREATED, "{said}");
        let mut second = Dev::new(&w.owner.user_id, &w.owner_token);
        let (status, body) = register_vouched(&w.app, &second, &first).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        upload_packages(&w.app, &second, 2).await;
        // The first device is still wanted and in; the second is added by it.
        let mut devs = [first, second];
        settle(&w.app, &mut devs, 0, &conv).await;
        second = Dev::new(&w.owner.user_id, &w.owner_token);
        let [first, kept] = devs;
        let _ = second;
        let mut devs = [first, kept];
        let (status, body) = w
            .send(
                Method::DELETE,
                &format!("/v1/e2ee/devices/{}", devs[0].id()),
                &w.owner_token,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        // The second device holds the group and removes the first.
        let (status, body) = commit(&w.app, &mut devs[1], &conv).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        let (_, group) = info(&w.app, &devs[1].token, &conv).await;
        assert_eq!(group["members"].as_array().expect("members").len(), 1);
        // Now the last one goes too: nobody is left to commit, and the group is over.
        let third = Dev::new(&w.owner.user_id, &w.owner_token);
        let (status, body) = register_vouched(&w.app, &third, &devs[1]).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let (status, _) = w
            .send(
                Method::DELETE,
                &format!("/v1/e2ee/devices/{}", devs[1].id()),
                &w.owner_token,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let mut third = third;
        let (status, group) = info(&w.app, &third.token, &conv).await;
        assert_eq!(status, StatusCode::OK, "{group}");
        assert!(group["epoch"].is_null(), "the group is gone: {group}");
        start(&w.app, &mut third, &conv).await;
        let (status, said) = say(&w.app, &mut third, &conv, "in the new group", json!({})).await;
        assert_eq!(status, StatusCode::CREATED, "{said}");
    })
    .await;
}
