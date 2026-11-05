//! Device linking through the real HTTP routes: the relay of sealed messages between two sessions
//! of one person, the history archive, and what the server keeps and forgets of either. The
//! protocol is `docs/e2ee-text.md` section 5.
//!
//! Alone in its own test binary, so it can hold the one global log subscriber and read every
//! line the server writes: no link id, message or archive byte may be in it.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use common::{first_owner, join, run, session, Call, TestDb};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

/// Inside every message and archive the tests send. It must never reach a log.
const MARKER: &str = "LINK-OPAQUE-MARKER-5c1e7b";

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

/// Everything the server writes, at every level.
fn logs() -> &'static Logs {
    static LOGS: OnceLock<Logs> = OnceLock::new();
    LOGS.get_or_init(|| {
        let logs = Logs::default();
        let writer = logs.clone();
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("trace"))
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .init();
        logs
    })
}

/// No log line holds a link id, the marker, or the marker as base64.
fn assert_logs_clean(ids: &[&str]) {
    let text = logs().text();
    assert!(!text.contains(MARKER), "marker in the logs");
    assert!(
        !text.contains(&STANDARD.encode(MARKER)),
        "marker in the logs"
    );
    for id in ids {
        assert!(!text.contains(id), "link id in the logs");
    }
}

// ---- small helpers --------------------------------------------------------------------------

fn app(db: &TestDb) -> Router {
    api::router(db.runtime.clone(), None)
}

/// A scratch upload directory for this test.
fn upload_dir() -> PathBuf {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).expect("random");
    let tag: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    let dir = std::env::temp_dir().join(format!("tinyserver-e2ee-link-{tag}"));
    std::fs::create_dir_all(&dir).expect("upload dir");
    std::env::set_var("TINYSERVER_UPLOAD_DIR", &dir);
    dir
}

/// The archive files on disk, by name.
fn archive_files(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir.join("links")) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
        .collect();
    names.sort();
    names
}

/// Bytes that hold the marker, `len` long.
fn opaque(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    getrandom::fill(&mut bytes).expect("random");
    let marker = MARKER.as_bytes();
    let at = len.saturating_sub(marker.len()) / 2;
    bytes[at..at + marker.len().min(len)].copy_from_slice(&marker[..marker.len().min(len)]);
    bytes
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

/// A request with raw bytes and headers of the test's choosing.
async fn raw(
    app: &Router,
    method: Method,
    path: &str,
    token: &str,
    headers: &[(header::HeaderName, String)],
    body: Vec<u8>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("cf-connecting-ip", common::fresh_address())
        .header("authorization", format!("Bearer {token}"));
    for (name, value) in headers {
        request = request.header(name, value);
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
        .to_bytes();
    (status, headers, bytes.to_vec())
}

/// A PUT of the archive with a correct Content-Length.
async fn put_archive(app: &Router, token: &str, id: &str, bytes: &[u8]) -> (StatusCode, Vec<u8>) {
    let (status, _, body) = raw(
        app,
        Method::PUT,
        &format!("/v1/e2ee/links/{id}/archive"),
        token,
        &[
            (header::CONTENT_TYPE, "application/octet-stream".into()),
            (header::CONTENT_LENGTH, bytes.len().to_string()),
        ],
        bytes.to_vec(),
    )
    .await;
    (status, body)
}

async fn get_archive(
    app: &Router,
    token: &str,
    id: &str,
    range: Option<&str>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let headers: Vec<(header::HeaderName, String)> = range
        .map(|range| vec![(header::RANGE, range.to_string())])
        .unwrap_or_default();
    raw(
        app,
        Method::GET,
        &format!("/v1/e2ee/links/{id}/archive"),
        token,
        &headers,
        Vec::new(),
    )
    .await
}

async fn new_link(app: &Router, token: &str) -> String {
    let (status, body) = call(app, Method::POST, "/v1/e2ee/links", token, None).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id = body["link_id"].as_str().expect("link_id").to_string();
    assert_eq!(URL_SAFE_NO_PAD.decode(&id).expect("base64url").len(), 16);
    assert!(body["expires_at"]
        .as_str()
        .is_some_and(|at| at.ends_with('Z')));
    id
}

async fn post(app: &Router, token: &str, id: &str, from: &str, data: &[u8]) -> (StatusCode, Value) {
    call(
        app,
        Method::POST,
        &format!("/v1/e2ee/links/{id}/messages"),
        token,
        Some(json!({ "from": from, "data": STANDARD.encode(data) })),
    )
    .await
}

async fn read(app: &Router, token: &str, id: &str, query: &str) -> (StatusCode, Value) {
    call(
        app,
        Method::GET,
        &format!("/v1/e2ee/links/{id}/messages{query}"),
        token,
        None,
    )
    .await
}

async fn expire(db: &TestDb, id: &str, ago: &str) {
    sqlx::query("UPDATE e2ee_links SET expires_at = now() - $2::interval WHERE id = $1")
        .bind(URL_SAFE_NO_PAD.decode(id).expect("id"))
        .bind(ago)
        .execute(&db.owner)
        .await
        .expect("expire");
}

async fn rows(db: &TestDb) -> (i64, i64) {
    sqlx::query_as(
        "SELECT (SELECT count(*) FROM e2ee_links), (SELECT count(*) FROM e2ee_link_messages)",
    )
    .fetch_one(&db.owner)
    .await
    .expect("counts")
}

// ---- the relay ------------------------------------------------------------------------------

#[tokio::test]
async fn two_sessions_of_one_person_relay_messages() {
    logs();
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = app(&db);
        let (ada, new_device) = join(&db, &owner, "ada@tinyserver.test", "member").await;
        let old_device = session(&db, &ada.user_id).await;

        let id = new_link(&app, &new_device).await;
        let first = opaque(65);
        let second = opaque(8 * 1024);
        let (status, body) = post(&app, &old_device, &id, "old", &first).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body, json!({ "seq": 1 }));
        let (status, body) = post(&app, &new_device, &id, "new", &second).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body, json!({ "seq": 2 }));

        let (status, body) = read(&app, &new_device, &id, "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            json!([
                { "seq": 1, "from": "old", "data": STANDARD.encode(&first) },
                { "seq": 2, "from": "new", "data": STANDARD.encode(&second) },
            ])
        );
        let (_, body) = read(&app, &old_device, &id, "?after=1").await;
        assert_eq!(
            body,
            json!([{ "seq": 2, "from": "new", "data": STANDARD.encode(&second) }])
        );
        let (_, body) = read(&app, &old_device, &id, "?after=2").await;
        assert_eq!(body, json!([]));

        // What the server stores is what was sent, and nothing that says which device is which
        // beyond the label.
        let stored: Vec<(String, Vec<u8>)> =
            sqlx::query_as("SELECT sender, data FROM e2ee_link_messages ORDER BY seq")
                .fetch_all(&db.owner)
                .await
                .expect("stored");
        assert_eq!(stored, vec![("old".into(), first), ("new".into(), second)]);

        let (status, _) = call(
            &app,
            Method::DELETE,
            &format!("/v1/e2ee/links/{id}"),
            &old_device,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(rows(&db).await, (0, 0));
        let (status, _) = read(&app, &new_device, &id, "").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        // Again, and by the other device: the same answer.
        let (status, _) = call(
            &app,
            Method::DELETE,
            &format!("/v1/e2ee/links/{id}"),
            &new_device,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_logs_clean(&[&id]);
    })
    .await;
}

#[tokio::test]
async fn someone_else_cannot_touch_a_link() {
    logs();
    run(|db| async move {
        let dir = upload_dir();
        let owner = first_owner(&db).await;
        let app = app(&db);
        let (_ada, ada_token) = join(&db, &owner, "ada@tinyserver.test", "member").await;
        let (_bea, bea_token) = join(&db, &owner, "bea@tinyserver.test", "member").await;
        let owner_token = session(&db, &owner.user_id).await;

        let id = new_link(&app, &ada_token).await;
        let (status, _) = post(&app, &ada_token, &id, "new", &opaque(65)).await;
        assert_eq!(status, StatusCode::CREATED);
        let archive = opaque(4096);
        let (status, _) = put_archive(&app, &ada_token, &id, &archive).await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Another member, and the owner of the community, get what a link that does not exist
        // gets.
        for token in [&bea_token, &owner_token] {
            let (status, _) = post(&app, token, &id, "old", &opaque(65)).await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            let (status, body) = read(&app, token, &id, "?wait=1").await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
            let (status, _) = put_archive(&app, token, &id, &opaque(10)).await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            let (status, _, body) = get_archive(&app, token, &id, None).await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert!(!body.windows(MARKER.len()).any(|w| w == MARKER.as_bytes()));
            // Deleting is idempotent, so it says 204; it deletes nothing of Ada's.
            let (status, _) = call(
                &app,
                Method::DELETE,
                &format!("/v1/e2ee/links/{id}"),
                token,
                None,
            )
            .await;
            assert_eq!(status, StatusCode::NO_CONTENT);
        }
        let (status, body) = read(&app, &ada_token, &id, "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_array().map(Vec::len), Some(1));
        let (status, _, body) = get_archive(&app, &ada_token, &id, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, archive);

        // No session at all.
        let (status, _) = Call::new(Method::POST, "/v1/e2ee/links").send(&app).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = Call::new(Method::GET, &format!("/v1/e2ee/links/{id}/messages"))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let _ = std::fs::remove_dir_all(dir);
        assert_logs_clean(&[&id]);
    })
    .await;
}

#[tokio::test]
async fn links_and_messages_are_capped() {
    logs();
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = app(&db);
        let (_ada, token) = join(&db, &owner, "ada@tinyserver.test", "member").await;

        let mut ids = Vec::new();
        for _ in 0..5 {
            ids.push(new_link(&app, &token).await);
        }
        let (status, body) = call(&app, Method::POST, "/v1/e2ee/links", &token, None).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
        assert_eq!(body["error"], "slow_down");
        // An expired link does not count against the five.
        expire(&db, &ids[0], "1 second").await;
        new_link(&app, &token).await;

        let id = &ids[1];
        let (status, _) = post(&app, &token, id, "new", &opaque(8 * 1024 + 1)).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        let (status, _) = post(&app, &token, id, "new", &[]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = post(&app, &token, id, "middle", &opaque(10)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = call(
            &app,
            Method::POST,
            &format!("/v1/e2ee/links/{id}/messages"),
            &token,
            Some(json!({ "from": "new", "data": "not base64!" })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        for seq in 1..=16 {
            let (status, body) = post(&app, &token, id, "old", &opaque(32)).await;
            assert_eq!(status, StatusCode::CREATED, "{body}");
            assert_eq!(body["seq"], seq);
        }
        let (status, _) = post(&app, &token, id, "old", &opaque(32)).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

        // Ids that are not 16 bytes of base64url are links that do not exist.
        for bad in [
            "nope",
            "AAAAAAAAAAAAAAAAAAAAAA==",
            "00000000-0000-4000-8000-000000000001",
        ] {
            let (status, _) = read(&app, &token, bad, "").await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{bad}");
            let (status, _) = post(&app, &token, bad, "new", &opaque(8)).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{bad}");
            let (status, _) = call(
                &app,
                Method::DELETE,
                &format!("/v1/e2ee/links/{bad}"),
                &token,
                None,
            )
            .await;
            assert_eq!(status, StatusCode::NO_CONTENT, "{bad}");
        }
        let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        assert_logs_clean(&refs);
        // The canary is not empty: the refusals above were logged, by reason.
        let text = logs().text();
        assert!(text.contains("e2ee link failed"), "no link failure logged");
        assert!(text.contains("links.post"), "no route logged");
        assert!(text.contains("too_large"), "no reason logged");
    })
    .await;
}

#[tokio::test]
async fn link_creation_is_rate_limited() {
    logs();
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = app(&db);
        let (_ada, token) = join(&db, &owner, "ada@tinyserver.test", "member").await;
        // Ten at once, each deleted so the open-link cap is not what refuses the eleventh.
        for _ in 0..10 {
            let id = new_link(&app, &token).await;
            let (status, _) = call(
                &app,
                Method::DELETE,
                &format!("/v1/e2ee/links/{id}"),
                &token,
                None,
            )
            .await;
            assert_eq!(status, StatusCode::NO_CONTENT);
        }
        let (status, body) = call(&app, Method::POST, "/v1/e2ee/links", &token, None).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
        assert_eq!(rows(&db).await, (0, 0));
    })
    .await;
}

// ---- expiry ---------------------------------------------------------------------------------

#[tokio::test]
async fn an_expired_link_is_gone_and_its_archive_an_hour_later() {
    logs();
    run(|db| async move {
        let dir = upload_dir();
        let owner = first_owner(&db).await;
        let app = app(&db);
        let (_ada, token) = join(&db, &owner, "ada@tinyserver.test", "member").await;

        let quiet = new_link(&app, &token).await;
        let (status, _) = post(&app, &token, &quiet, "new", &opaque(65)).await;
        assert_eq!(status, StatusCode::CREATED);
        let carrying = new_link(&app, &token).await;
        let (status, _) = post(&app, &token, &carrying, "old", &opaque(65)).await;
        assert_eq!(status, StatusCode::CREATED);
        let archive = opaque(70_000);
        let (status, _) = put_archive(&app, &token, &carrying, &archive).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(archive_files(&dir).len(), 1);

        expire(&db, &quiet, "1 second").await;
        expire(&db, &carrying, "1 second").await;
        for id in [&quiet, &carrying] {
            let (status, _) = read(&app, &token, id, "").await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            let (status, _) = post(&app, &token, id, "new", &opaque(65)).await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            let (status, _) = put_archive(&app, &token, id, &opaque(10)).await;
            assert_eq!(status, StatusCode::NOT_FOUND);
        }
        // A download that started in time may still finish within the hour.
        let (status, _, body) = get_archive(&app, &token, &carrying, Some("bytes=100-")).await;
        assert_eq!(status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(body, archive[100..]);

        // The sweep takes every message and the link with no archive at once.
        db::sweep(&db.runtime).await.expect("sweep");
        assert_eq!(rows(&db).await, (1, 0));
        assert_eq!(archive_files(&dir).len(), 1);

        // An hour on, the archive and its row go too.
        expire(&db, &carrying, "1 hour 1 second").await;
        let (status, _, _) = get_archive(&app, &token, &carrying, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let swept = db::sweep(&db.runtime).await.expect("sweep");
        assert_eq!(swept.link_archives, 1);
        assert_eq!(rows(&db).await, (0, 0));
        assert!(archive_files(&dir).is_empty(), "{:?}", archive_files(&dir));
        let _ = std::fs::remove_dir_all(dir);
        assert_logs_clean(&[&quiet, &carrying]);
    })
    .await;
}

#[tokio::test]
async fn the_sweep_deletes_archive_files_no_row_names() {
    logs();
    run(|db| async move {
        let dir = upload_dir();
        let owner = first_owner(&db).await;
        let app = app(&db);
        let (ada, token) = join(&db, &owner, "ada@tinyserver.test", "member").await;
        let id = new_link(&app, &token).await;
        let (status, _) = put_archive(&app, &token, &id, &opaque(5000)).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        // Left by a crash: a partial upload, and an archive whose row is gone.
        let links = dir.join("links");
        std::fs::write(links.join(format!("{}.part", "a".repeat(64))), b"partial").expect("part");
        std::fs::write(links.join("b".repeat(64)), b"stray").expect("stray");
        assert_eq!(archive_files(&dir).len(), 3);

        let swept = db::sweep(&db.runtime).await.expect("sweep");
        assert_eq!(swept.link_archives, 2);
        assert_eq!(archive_files(&dir).len(), 1, "the live archive stays");

        // A deleted account takes its links with it; the next sweep takes the file.
        db::delete_account(&db.runtime, &ada)
            .await
            .expect("delete account");
        assert_eq!(rows(&db).await, (0, 0));
        db::sweep(&db.runtime).await.expect("sweep");
        assert!(archive_files(&dir).is_empty());
        let _ = std::fs::remove_dir_all(dir);
    })
    .await;
}

// ---- the archive ----------------------------------------------------------------------------

#[tokio::test]
async fn the_archive_round_trips_with_ranges_and_is_deleted_with_the_link() {
    logs();
    run(|db| async move {
        let dir = upload_dir();
        let owner = first_owner(&db).await;
        let app = app(&db);
        let (ada, old_device) = join(&db, &owner, "ada@tinyserver.test", "member").await;
        let new_device = session(&db, &ada.user_id).await;
        let id = new_link(&app, &new_device).await;

        let (status, _, _) = get_archive(&app, &new_device, &id, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "no archive yet");

        // 200 KiB and a bit, so the download comes in several pieces.
        let archive = opaque(200 * 1024 + 7);
        let (status, body) = put_archive(&app, &old_device, &id, &archive).await;
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "{}",
            String::from_utf8_lossy(&body)
        );

        // One file, named by neither the link id nor anything derived from it, and no partial.
        let files = archive_files(&dir);
        assert_eq!(files.len(), 1, "{files:?}");
        let name = &files[0];
        assert_eq!(name.len(), 64);
        assert!(name.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let raw_id = URL_SAFE_NO_PAD.decode(&id).expect("id");
        let hex_id: String = raw_id.iter().map(|byte| format!("{byte:02x}")).collect();
        assert!(!name.contains(&hex_id));
        assert_eq!(
            std::fs::read(dir.join("links").join(name)).expect("file"),
            archive
        );

        let (status, headers, body) = get_archive(&app, &new_device, &id, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, archive);
        assert_eq!(headers[header::CONTENT_TYPE], "application/octet-stream");
        assert_eq!(headers[header::ACCEPT_RANGES], "bytes");
        assert_eq!(headers[header::CONTENT_LENGTH], archive.len().to_string());

        let total = archive.len();
        let (status, headers, body) =
            get_archive(&app, &new_device, &id, Some("bytes=10-19")).await;
        assert_eq!(status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(body, archive[10..20]);
        assert_eq!(
            headers[header::CONTENT_RANGE],
            format!("bytes 10-19/{total}")
        );
        assert_eq!(headers[header::CONTENT_LENGTH], "10");
        let (status, _, body) = get_archive(&app, &new_device, &id, Some("bytes=70000-")).await;
        assert_eq!(status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(body, archive[70000..]);
        let (status, headers, body) = get_archive(&app, &new_device, &id, Some("bytes=-5")).await;
        assert_eq!(status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(body, archive[total - 5..]);
        assert_eq!(
            headers[header::CONTENT_RANGE],
            format!("bytes {}-{}/{total}", total - 5, total - 1)
        );
        let (status, headers, _) =
            get_archive(&app, &new_device, &id, Some(&format!("bytes={total}-"))).await;
        assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(headers[header::CONTENT_RANGE], format!("bytes */{total}"));

        // Once per link.
        let (status, body) = put_archive(&app, &old_device, &id, &opaque(100)).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            serde_json::from_slice::<Value>(&body).expect("json")["error"],
            "archive_exists"
        );

        // Never through the media routes: their ids are uuids, and the file is not one.
        for path in [
            format!("/v1/media/{name}"),
            format!("/v1/media/links%2F{name}"),
            format!("/v1/media/..%2Flinks%2F{name}"),
        ] {
            let (status, _, body) =
                raw(&app, Method::GET, &path, &new_device, &[], Vec::new()).await;
            assert_ne!(status, StatusCode::OK, "{path}");
            assert!(!body.windows(MARKER.len()).any(|w| w == MARKER.as_bytes()));
        }

        let (status, _) = call(
            &app,
            Method::DELETE,
            &format!("/v1/e2ee/links/{id}"),
            &new_device,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(
            archive_files(&dir).is_empty(),
            "the file goes with the link"
        );
        let (status, _, _) = get_archive(&app, &new_device, &id, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let _ = std::fs::remove_dir_all(dir);
        assert_logs_clean(&[&id, name]);
    })
    .await;
}

#[tokio::test]
async fn the_archive_is_capped_and_a_bad_upload_leaves_nothing() {
    logs();
    run(|db| async move {
        let dir = upload_dir();
        let owner = first_owner(&db).await;
        let app = app(&db);
        let (_ada, token) = join(&db, &owner, "ada@tinyserver.test", "member").await;
        let id = new_link(&app, &token).await;
        let path = format!("/v1/e2ee/links/{id}/archive");
        let octets = (header::CONTENT_TYPE, "application/octet-stream".to_string());

        // No Content-Length.
        let (status, _, body) = raw(
            &app,
            Method::PUT,
            &path,
            &token,
            std::slice::from_ref(&octets),
            opaque(10),
        )
        .await;
        assert_eq!(status, StatusCode::LENGTH_REQUIRED);
        assert_eq!(
            serde_json::from_slice::<Value>(&body).expect("json")["error"],
            "length_required"
        );
        // Not octets.
        let (status, _, _) = raw(
            &app,
            Method::PUT,
            &path,
            &token,
            &[
                (header::CONTENT_TYPE, "image/png".into()),
                (header::CONTENT_LENGTH, "10".into()),
            ],
            opaque(10),
        )
        .await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        // Empty.
        let (status, _) = put_archive(&app, &token, &id, &[]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Past the server's cap: refused on the declared length, before a byte is read.
        sqlx::query("UPDATE server_settings SET e2ee_link_archive_max = 1048576")
            .execute(&db.owner)
            .await
            .expect("cap");
        let (status, _, _) = raw(
            &app,
            Method::PUT,
            &path,
            &token,
            &[octets.clone(), (header::CONTENT_LENGTH, "1048577".into())],
            Vec::new(),
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        let (_, caps) = call(&app, Method::GET, "/v1/capabilities", &token, None).await;
        assert_eq!(caps["e2ee_link_archive_max"], 1_048_576);

        // A body longer than it said, and one shorter: refused, and nothing is kept.
        let (status, _, _) = raw(
            &app,
            Method::PUT,
            &path,
            &token,
            &[octets.clone(), (header::CONTENT_LENGTH, "100".into())],
            opaque(101),
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(archive_files(&dir).is_empty());
        let (status, _, _) = raw(
            &app,
            Method::PUT,
            &path,
            &token,
            &[octets.clone(), (header::CONTENT_LENGTH, "100".into())],
            opaque(99),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(archive_files(&dir).is_empty());
        let (status, _, _) = get_archive(&app, &token, &id, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // The link may still take its archive, at the cap exactly.
        let archive = opaque(1_048_576);
        let (status, _) = put_archive(&app, &token, &id, &archive).await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // One archive per person at a time.
        let other = new_link(&app, &token).await;
        let (status, _) = put_archive(&app, &token, &other, &opaque(10)).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        let (status, _) = call(
            &app,
            Method::DELETE,
            &format!("/v1/e2ee/links/{id}"),
            &token,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = put_archive(&app, &token, &other, &opaque(10)).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(archive_files(&dir).len(), 1);
        let _ = std::fs::remove_dir_all(dir);
        assert_logs_clean(&[&id, &other]);
    })
    .await;
}

// ---- the long poll --------------------------------------------------------------------------

#[tokio::test]
async fn a_read_waits_for_the_next_message() {
    logs();
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = app(&db);
        let (ada, new_device) = join(&db, &owner, "ada@tinyserver.test", "member").await;
        let old_device = session(&db, &ada.user_id).await;
        let id = new_link(&app, &new_device).await;

        // Nothing comes: an empty answer after about the wait asked for.
        let started = Instant::now();
        let (status, body) = read(&app, &new_device, &id, "?wait=1").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, json!([]));
        assert!(started.elapsed() >= Duration::from_millis(900));
        assert!(started.elapsed() < Duration::from_secs(5));

        // A message posted while the read waits ends the wait at once.
        let data = opaque(65);
        let poster = {
            let (app, token, id, data) =
                (app.clone(), old_device.clone(), id.clone(), data.clone());
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(300)).await;
                post(&app, &token, &id, "old", &data).await
            })
        };
        let started = Instant::now();
        let (status, body) = read(&app, &new_device, &id, "?wait=20").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            json!([{ "seq": 1, "from": "old", "data": STANDARD.encode(&data) }])
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(poster.await.expect("poster").0, StatusCode::CREATED);

        // A message already there answers at once.
        let started = Instant::now();
        let (_, body) = read(&app, &new_device, &id, "?after=0&wait=20").await;
        assert_eq!(body.as_array().map(Vec::len), Some(1));
        assert!(started.elapsed() < Duration::from_secs(2));

        // Deleting the link ends a wait with 404.
        let deleter = {
            let (app, token, id) = (app.clone(), old_device.clone(), id.clone());
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(300)).await;
                call(
                    &app,
                    Method::DELETE,
                    &format!("/v1/e2ee/links/{id}"),
                    &token,
                    None,
                )
                .await
            })
        };
        let started = Instant::now();
        let (status, _) = read(&app, &new_device, &id, "?after=1&wait=20").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(deleter.await.expect("deleter").0, StatusCode::NO_CONTENT);

        // The wait is capped at 25 seconds whatever is asked; a fifth concurrent wait answers
        // at once instead of holding a request open.
        let id = new_link(&app, &new_device).await;
        let mut waiting = Vec::new();
        for _ in 0..4 {
            let (app, token, id) = (app.clone(), new_device.clone(), id.clone());
            waiting.push(tokio::spawn(async move {
                read(&app, &token, &id, "?wait=3").await
            }));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        let started = Instant::now();
        let (status, body) = read(&app, &new_device, &id, "?wait=3").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, json!([]));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
        for wait in waiting {
            assert_eq!(wait.await.expect("wait").0, StatusCode::OK);
        }
        assert_logs_clean(&[&id]);
    })
    .await;
}

#[tokio::test]
async fn capabilities_advertise_device_links() {
    logs();
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = app(&db);
        let (_ada, token) = join(&db, &owner, "ada@tinyserver.test", "member").await;
        let (status, caps) = call(&app, Method::GET, "/v1/capabilities", &token, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(caps["e2ee_device_link"], true);
        assert!(caps["features"]
            .as_array()
            .expect("features")
            .contains(&json!("e2ee_device_link")));
        assert_eq!(caps["e2ee_link_archive_max"], 512 * 1024 * 1024);
    })
    .await;
}
