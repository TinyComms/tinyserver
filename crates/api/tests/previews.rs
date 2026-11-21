//! Sender-supplied link previews on plaintext messages (issue #67).

mod common;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use common::{first_owner, join, run, session, Call};
use db::perm;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

async fn send_message(
    app: &axum::Router,
    token: &str,
    conversation_id: &str,
    body: Value,
) -> (StatusCode, Value) {
    Call::new(
        Method::POST,
        &format!("/v1/conversations/{conversation_id}/messages"),
    )
    .token(token)
    .json(body)
    .send(app)
    .await
}

async fn get_json(app: &axum::Router, token: &str, path: &str) -> Value {
    let (status, body) = Call::new(Method::GET, path).token(token).send(app).await;
    assert_eq!(status, StatusCode::OK, "{path}: {body}");
    body
}

/// A valid 1x1 red PNG.
const TINY_PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
    0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, 0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00,
    0x00, 0x03, 0x01, 0x01, 0x00, 0x18, 0xDD, 0x8D, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E,
    0x44, 0xAE, 0x42, 0x60, 0x82,
];

async fn upload_png(app: &axum::Router, token: &str, name: &str) -> (StatusCode, Value) {
    let boundary = "----tinyserverpreviewboundary";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: image/png\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(TINY_PNG);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/media")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .expect("request");
    let res = app.clone().oneshot(req).await.expect("response");
    let status = res.status();
    let bytes = res.into_body().collect().await.expect("body").to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

#[tokio::test]
async fn previews_validate_store_bind_images_and_clear_on_edit_and_delete() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let (alice, alice_token) = join(&db, &owner, "alice@tinyserver.test", "member").await;
        let (_bob, bob_token) = join(&db, &owner, "bob@tinyserver.test", "member").await;
        let app = api::router(db.runtime.clone(), None);

        // Capability advertises `link_previews`.
        let caps = get_json(&app, &owner_token, "/v1/capabilities").await;
        let features = caps["features"].as_array().expect("features");
        assert!(features.iter().any(|f| f == "link_previews"), "{caps}");

        let (status, chan) = Call::new(Method::POST, "/v1/channels")
            .token(&owner_token)
            .json(json!({"name": "links"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED);
        let chan_id = chan["id"].as_str().expect("id").to_string();

        // Upload a clean preview image as Alice, and another as Bob.
        let (status, alice_img) = upload_png(&app, &alice_token, "thumb.png").await;
        assert_eq!(status, StatusCode::CREATED, "{alice_img}");
        let alice_img_id = alice_img["id"].as_str().expect("id").to_string();

        let (status, bob_img) = upload_png(&app, &bob_token, "bob.png").await;
        assert_eq!(status, StatusCode::CREATED, "{bob_img}");
        let bob_img_id = bob_img["id"].as_str().expect("id").to_string();

        // Refused: URL not in body.
        let (status, err) = send_message(
            &app,
            &alice_token,
            &chan_id,
            json!({
                "body": "check this out",
                "previews": [{"url": "https://example.com/page", "title": "Example"}]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
        assert_eq!(err["error"], "invalid");

        // Refused: over-long title (> 200 chars).
        let (status, err) = send_message(
            &app,
            &alice_token,
            &chan_id,
            json!({
                "body": "https://example.com/a",
                "previews": [{"url": "https://example.com/a", "title": "x".repeat(201)}]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
        assert_eq!(err["error"], "invalid");

        // Refused: someone else's upload as image_attachment_id.
        let (status, err) = send_message(
            &app,
            &alice_token,
            &chan_id,
            json!({
                "body": "https://example.com/a",
                "previews": [{
                    "url": "https://example.com/a",
                    "image_attachment_id": bob_img_id
                }]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
        assert_eq!(err["error"], "invalid");

        // Accepted: valid preview with Alice's clean image. Image is NOT in `attachments`.
        let (status, msg) = send_message(
            &app,
            &alice_token,
            &chan_id,
            json!({
                "body": "Read https://example.com/post",
                "previews": [{
                    "url": "https://example.com/post",
                    "site": "Example",
                    "title": "A Post",
                    "description": "Short summary",
                    "image_attachment_id": alice_img_id
                }]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{msg}");
        let msg_id = msg["id"].as_str().expect("id").to_string();
        assert_eq!(msg["attachments"].as_array().map(Vec::len), Some(0));
        let previews = msg["previews"].as_array().expect("previews");
        assert_eq!(previews.len(), 1);
        assert_eq!(previews[0]["url"], "https://example.com/post");
        assert_eq!(previews[0]["site"], "Example");
        assert_eq!(previews[0]["title"], "A Post");
        assert_eq!(previews[0]["image_attachment_id"], alice_img_id);

        // Bob can download the preview image via /v1/media/{id} because he can view the channel.
        let (status, _) = Call::new(Method::GET, &format!("/v1/media/{alice_img_id}"))
            .token(&bob_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK);

        // Editing the message to remove the URL clears the preview automatically.
        let (status, edited) = Call::new(Method::PATCH, &format!("/v1/messages/{msg_id}"))
            .token(&alice_token)
            .json(json!({"body": "link removed"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{edited}");
        assert_eq!(edited["previews"].as_array().map(Vec::len), Some(0));

        // Author or moderator with manage_messages can clear previews with `previews: []`.
        let (status, m2) = send_message(
            &app,
            &alice_token,
            &chan_id,
            json!({
                "body": "https://example.com/keep",
                "previews": [{"url": "https://example.com/keep", "title": "Keep"}]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let m2_id = m2["id"].as_str().expect("id").to_string();

        // Bob (not author, not moderator) cannot strip Alice's preview.
        let (status, _) = Call::new(Method::PATCH, &format!("/v1/messages/{m2_id}"))
            .token(&bob_token)
            .json(json!({"previews": []}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Owner (has manage_messages) can strip Alice's preview with `previews: []`.
        let _ = (alice.user_id, perm::MANAGE_MESSAGES);
        let (status, stripped) = Call::new(Method::PATCH, &format!("/v1/messages/{m2_id}"))
            .token(&owner_token)
            .json(json!({"previews": []}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{stripped}");
        assert_eq!(stripped["previews"].as_array().map(Vec::len), Some(0));
        assert_eq!(stripped["body"], "https://example.com/keep");

        // Deleting a message clears its previews.
        let (status, m3) = send_message(
            &app,
            &alice_token,
            &chan_id,
            json!({
                "body": "https://example.com/del",
                "previews": [{"url": "https://example.com/del", "title": "Del"}]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let m3_id = m3["id"].as_str().expect("id").to_string();
        let (status, _) = Call::new(Method::DELETE, &format!("/v1/messages/{m3_id}"))
            .token(&alice_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Encrypted channel refuses plaintext previews on a ciphertext post.
        let (status, e2ee_chan) = Call::new(Method::POST, "/v1/channels")
            .token(&owner_token)
            .json(json!({"name": "sealed", "e2ee": true}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED);
        let e2ee_id = e2ee_chan["id"].as_str().expect("id").to_string();
        let (status, err) = send_message(
            &app,
            &owner_token,
            &e2ee_id,
            json!({
                "ciphertext": "AAAA",
                "epoch": 0,
                "device_id": "00000000-0000-4000-8000-000000000001",
                "kind": "message",
                "previews": [{"url": "https://example.com/x"}]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
        assert_eq!(err["error"], "e2ee_required");
    })
    .await;
}
