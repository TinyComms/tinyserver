//! Custom community emoji and stickers (`0053_custom_emoji.sql`, issue #66).

mod common;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use common::{first_owner, join, run, session, Call};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

/// Minimal valid 1×1 RGBA PNG.
const TINY_PNG: &[u8] = &[
    0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, b'I', b'H', b'D', b'R',
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
    0x89, 0x00, 0x00, 0x00, 0x0A, b'I', b'D', b'A', b'T', 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, b'I', b'E', b'N', b'D', 0xAE,
    0x42, 0x60, 0x82,
];

fn png_bytes() -> Vec<u8> {
    TINY_PNG.to_vec()
}

fn multipart_emoji(kind: Option<&str>, name: &str, file: &[u8]) -> (String, Vec<u8>) {
    let boundary = "tiny-emoji-boundary-1";
    let mut body = Vec::new();
    if let Some(kind) = kind {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"kind\"\r\n\r\n{kind}\r\n"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\n{name}\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"e.png\"\r\nContent-Type: image/png\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(file);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), body)
}

async fn upload_emoji(
    app: &axum::Router,
    token: &str,
    kind: Option<&str>,
    name: &str,
    file: &[u8],
) -> (StatusCode, Value) {
    let (ct, body) = multipart_emoji(kind, name, file);
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/emoji")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, ct)
        .body(Body::from(body))
        .expect("request");
    let res = app.clone().oneshot(req).await.expect("response");
    let status = res.status();
    let bytes = res.into_body().collect().await.expect("body").to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

#[tokio::test]
async fn emoji_and_sticker_crud_spans_reactions_and_caching() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let (_member, member_token) = join(&db, &owner, "member@tinyserver.test", "member").await;
        let app = api::router(db.runtime.clone(), None);

        // Capabilities advertise custom_emoji and stickers.
        let (status, caps) = Call::new(Method::GET, "/v1/capabilities")
            .token(&member_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{caps}");
        let features = caps["features"].as_array().expect("features");
        assert!(features.iter().any(|f| f == "custom_emoji"));
        assert!(features.iter().any(|f| f == "stickers"));

        // Non-admin member cannot upload.
        let png = png_bytes();
        let (status, _) = upload_emoji(&app, &member_token, None, "party", &png).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Non-image and oversized payload are refused.
        let (status, _) = upload_emoji(&app, &owner_token, None, "bad_img", b"hello world").await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let huge = vec![0u8; db::STICKER_MAX_BYTES + 100 * 1024];
        let (status, _) = upload_emoji(&app, &owner_token, Some("sticker"), "too_big", &huge).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

        // Owner uploads an emoji and a sticker.
        let (status, created) = upload_emoji(&app, &owner_token, None, "party_parrot", &png).await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let emoji_id = created["id"].as_str().expect("id").to_string();
        assert_eq!(created["name"], "party_parrot");
        assert_eq!(created["kind"], "emoji");

        let (status, sticker) =
            upload_emoji(&app, &owner_token, Some("sticker"), "big_wave", &png).await;
        assert_eq!(status, StatusCode::CREATED, "{sticker}");
        let sticker_id = sticker["id"].as_str().expect("sticker id").to_string();

        // List all and filtered by kind.
        let (status, list) = Call::new(Method::GET, "/v1/emoji")
            .token(&member_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(list.as_array().expect("array").len(), 2);

        let (status, stickers_only) = Call::new(Method::GET, "/v1/emoji?kind=sticker")
            .token(&member_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(stickers_only.as_array().expect("array").len(), 1);

        // Fetch image with ETag and If-None-Match -> 304.
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("/v1/emoji/{emoji_id}"))
            .header(header::AUTHORIZATION, format!("Bearer {member_token}"))
            .body(Body::empty())
            .expect("req");
        let res = app.clone().oneshot(req).await.expect("res");
        assert_eq!(res.status(), StatusCode::OK);
        let etag = res
            .headers()
            .get(header::ETAG)
            .expect("etag")
            .to_str()
            .expect("str")
            .to_string();
        assert!(res
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("private") && v.contains("max-age")));

        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("/v1/emoji/{emoji_id}"))
            .header(header::AUTHORIZATION, format!("Bearer {member_token}"))
            .header(header::IF_NONE_MATCH, &etag)
            .body(Body::empty())
            .expect("req");
        let res = app.clone().oneshot(req).await.expect("res");
        assert_eq!(res.status(), StatusCode::NOT_MODIFIED);

        // Rename emoji.
        let (status, renamed) = Call::new(Method::PATCH, &format!("/v1/emoji/{emoji_id}"))
            .token(&owner_token)
            .json(json!({"name": "dance_parrot"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{renamed}");
        assert_eq!(renamed["name"], "dance_parrot");

        // Post a message with an emoji span and a sticker message.
        let (status, channel) = Call::new(Method::POST, "/v1/channels")
            .token(&owner_token)
            .json(json!({"name": "emoji-test"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED);
        let channel_id = channel["id"].as_str().expect("channel id").to_string();

        let (status, msg) = Call::new(
            Method::POST,
            &format!("/v1/conversations/{channel_id}/messages"),
        )
        .token(&member_token)
        .json(json!({
            "body": "hi :dance_parrot:!",
            "emoji": [{"id": emoji_id, "start": 3, "end": 17}]
        }))
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::CREATED, "{msg}");
        let msg_id = msg["id"].as_str().expect("msg id").to_string();
        assert_eq!(msg["emoji"][0]["id"], emoji_id);

        let (status, sticker_msg) = Call::new(
            Method::POST,
            &format!("/v1/conversations/{channel_id}/messages"),
        )
        .token(&member_token)
        .json(json!({"sticker_id": sticker_id}))
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::CREATED, "{sticker_msg}");
        assert_eq!(sticker_msg["sticker_id"], sticker_id);
        assert_eq!(sticker_msg["body"], "");

        // Custom reaction toggles and counts.
        let (status, rx) = Call::new(Method::PUT, &format!("/v1/messages/{msg_id}/reactions"))
            .token(&member_token)
            .json(json!({"emoji_id": emoji_id}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{rx}");
        assert_eq!(rx["emoji"], ":dance_parrot:");
        assert_eq!(rx["emoji_id"], emoji_id);
        assert_eq!(rx["count"], 1);
        assert_eq!(rx["me"], true);

        // Delete emoji: reactions disappear, message text stays intact.
        let (status, _) = Call::new(Method::DELETE, &format!("/v1/emoji/{emoji_id}"))
            .token(&owner_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let (status, history) = Call::new(
            Method::GET,
            &format!("/v1/conversations/{channel_id}/messages"),
        )
        .token(&member_token)
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::OK);
        let first = &history.as_array().expect("history")[0];
        assert_eq!(first["body"], "hi :dance_parrot:!");
        assert_eq!(first["reactions"].as_array().expect("reactions").len(), 0);
    })
    .await;
}
