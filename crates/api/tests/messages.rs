//! Text channels, direct messages, reactions, reads, and uploads.
//!
//! `0008_messages.sql` applies after `0007_e2ee.sql`. On a database whose newest migration is
//! `0004`, migrate fails in `run` before these assertions.

mod common;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use common::live::{connect, durable, ping, serve, Ws};
use common::{first_owner, join, run, session, Call};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

#[tokio::test]
async fn a_member_can_post_edit_react_and_read_but_not_create_a_channel() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let (member, member_token) = join(&db, &owner, "member@tinyserver.test", "member").await;
        let app = api::router(db.runtime.clone(), None);

        let (status, denied) = Call::new(Method::POST, "/v1/channels")
            .token(&member_token)
            .json(json!({"name": "secret"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
        assert_eq!(denied["error"], "forbidden");

        let (status, channel) = Call::new(Method::POST, "/v1/channels")
            .token(&owner_token)
            .json(json!({"name": "general", "topic": "hello"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{channel}");
        let channel_id = channel["id"].as_str().expect("channel id").to_string();
        assert_eq!(channel["name"], "general");
        assert_eq!(channel["unread"], 0);

        let (status, first) =
            send_message(&app, &member_token, &channel_id, json!({"body": "one"})).await;
        assert_eq!(status, StatusCode::CREATED, "{first}");
        assert_eq!(first["author_id"], member.user_id);
        assert_eq!(first["body"], "one");
        let first_id = first["id"].as_str().expect("message id").to_string();

        let (status, second) =
            send_message(&app, &member_token, &channel_id, json!({"body": "two"})).await;
        assert_eq!(status, StatusCode::CREATED, "{second}");
        let second_id = second["id"].as_str().expect("message id").to_string();

        let listed = get_json(&app, &owner_token, "/v1/channels").await;
        assert_eq!(listed[0]["unread"].as_i64(), Some(2));
        assert_eq!(listed[0]["last_message"]["body"], "two");

        let page = get_json(
            &app,
            &owner_token,
            &format!("/v1/conversations/{channel_id}/messages?limit=1"),
        )
        .await;
        assert_eq!(page.as_array().map(Vec::len), Some(1));
        assert_eq!(page[0]["id"], second_id);

        let older = get_json(
            &app,
            &owner_token,
            &format!("/v1/conversations/{channel_id}/messages?limit=1&before={second_id}"),
        )
        .await;
        assert_eq!(older[0]["id"], first_id);

        mark_read(&app, &owner_token, &channel_id, &first_id).await;
        let listed = get_json(&app, &owner_token, "/v1/channels").await;
        assert_eq!(listed[0]["unread"].as_i64(), Some(1));
        mark_read(&app, &owner_token, &channel_id, &first_id).await;
        let listed = get_json(&app, &owner_token, "/v1/channels").await;
        assert_eq!(listed[0]["unread"].as_i64(), Some(1));
        mark_read(&app, &owner_token, &channel_id, &second_id).await;
        let listed = get_json(&app, &owner_token, "/v1/channels").await;
        assert_eq!(listed[0]["unread"].as_i64(), Some(0));

        let (status, edited) = Call::new(Method::PATCH, &format!("/v1/messages/{first_id}"))
            .token(&member_token)
            .json(json!({"body": "one more"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{edited}");
        assert_eq!(edited["body"], "one more");
        assert!(edited["edited_at"].is_string());

        let (status, reaction) =
            Call::new(Method::PUT, &format!("/v1/messages/{first_id}/reactions"))
                .token(&member_token)
                .json(json!({"emoji": "👍"}))
                .send(&app)
                .await;
        assert_eq!(status, StatusCode::OK, "{reaction}");
        assert_eq!(reaction["count"].as_i64(), Some(1));
        assert_eq!(reaction["me"], true);

        let (status, reaction) =
            Call::new(Method::PUT, &format!("/v1/messages/{first_id}/reactions"))
                .token(&member_token)
                .json(json!({"emoji": "👍"}))
                .send(&app)
                .await;
        assert_eq!(status, StatusCode::OK, "{reaction}");
        assert_eq!(reaction["count"].as_i64(), Some(0));
        assert_eq!(reaction["me"], false);

        let (status, rejected) =
            Call::new(Method::PUT, &format!("/v1/messages/{first_id}/reactions"))
                .token(&member_token)
                .json(json!({"emoji": "👍👍"}))
                .send(&app)
                .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");

        let (status, again) = Call::new(Method::PUT, &format!("/v1/messages/{first_id}/reactions"))
            .token(&member_token)
            .json(json!({"emoji": "👍"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{again}");
        let (status, cleared) = Call::new(
            Method::DELETE,
            &format!("/v1/messages/{first_id}/reactions"),
        )
        .token(&member_token)
        .json(json!({"emoji": "👍"}))
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{cleared}");

        let (status, gone) = Call::new(Method::DELETE, &format!("/v1/messages/{second_id}"))
            .token(&member_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{gone}");
        let page = get_json(
            &app,
            &owner_token,
            &format!("/v1/conversations/{channel_id}/messages"),
        )
        .await;
        let deleted = page
            .as_array()
            .expect("page")
            .iter()
            .find(|message| message["id"] == second_id)
            .expect("deleted message");
        assert_eq!(deleted["body"], "");
        assert!(deleted["deleted_at"].is_string());

        let (status, rejected) = Call::new(Method::PATCH, &format!("/v1/messages/{second_id}"))
            .token(&member_token)
            .json(json!({"body": "nope"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");
        let (status, missing) =
            Call::new(Method::PUT, &format!("/v1/messages/{second_id}/reactions"))
                .token(&member_token)
                .json(json!({"emoji": "👍"}))
                .send(&app)
                .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{missing}");

        let (status, retry) = send_message(
            &app,
            &member_token,
            &channel_id,
            json!({"body": "hello", "client_id": "c-1"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{retry}");
        let (status, same) = send_message(
            &app,
            &member_token,
            &channel_id,
            json!({"body": "different", "client_id": "c-1"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{same}");
        assert_eq!(same["id"], retry["id"]);
        assert_eq!(same["body"], "hello");
    })
    .await;
}

#[tokio::test]
async fn a_timeout_or_a_ban_cannot_post() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let (timed, timed_token) = join(&db, &owner, "timed@tinyserver.test", "member").await;
        let (banned, banned_token) = join(&db, &owner, "banned@tinyserver.test", "member").await;
        let app = api::router(db.runtime.clone(), None);
        let (status, channel) = Call::new(Method::POST, "/v1/channels")
            .token(&owner_token)
            .json(json!({"name": "general"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{channel}");
        let channel_id = channel["id"].as_str().expect("channel id").to_string();

        sqlx::query(
            "UPDATE memberships SET timeout_until = now() + interval '1 day' WHERE user_id = $1::uuid",
        )
        .bind(&timed.user_id)
        .execute(&db.owner)
        .await
        .expect("timeout");
        let (status, denied) = send_message(&app, &timed_token, &channel_id, json!({"body": "no"})).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
        assert_eq!(denied["error"], "forbidden");

        sqlx::query("INSERT INTO bans (user_id) VALUES ($1::uuid)")
            .bind(&banned.user_id)
            .execute(&db.owner)
            .await
            .expect("ban");
        let (status, denied) = send_message(&app, &banned_token, &channel_id, json!({"body": "no"})).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
        assert_eq!(denied["error"], "banned");
    })
    .await;
}

#[tokio::test]
async fn a_gif_and_a_video_can_be_uploaded_and_downloaded() {
    run(|db| async move {
        let dir = std::env::temp_dir().join(format!("tinyserver-uploads-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("upload dir");
        std::env::set_var("TINYSERVER_UPLOAD_DIR", &dir);

        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let (_member, member_token) = join(&db, &owner, "member@tinyserver.test", "member").await;
        let app = api::router(db.runtime.clone(), None);
        let (status, channel) = Call::new(Method::POST, "/v1/channels")
            .token(&owner_token)
            .json(json!({"name": "media"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{channel}");
        let channel_id = channel["id"].as_str().expect("channel id").to_string();

        let gif = include_bytes!("fixtures/tiny.gif").as_slice();
        let (status, saved) = upload(&app, &owner_token, "wave.gif", "image/gif", gif, &[]).await;
        assert_eq!(status, StatusCode::CREATED, "{saved}");
        assert_eq!(saved["kind"], "gif");
        assert_eq!(saved["width"], 1);
        assert_eq!(saved["height"], 1);
        let gif_id = saved["id"].as_str().expect("gif id").to_string();
        let (status, bytes) = download(&app, &owner_token, &gif_id).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a"),
            "downloaded gif must still be a GIF after rewrite"
        );
        let (status, _) = download(&app, &member_token, &gif_id).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, message) = send_message(
            &app,
            &owner_token,
            &channel_id,
            json!({"body": "", "attachment_ids": [gif_id]}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{message}");
        assert_eq!(message["attachments"][0]["kind"], "gif");
        assert_eq!(message["attachments"][0]["name"], "wave.gif");
        let (status, bytes) = download(&app, &member_token, &gif_id).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a"),
            "linked gif must still be a GIF after rewrite"
        );

        let mut video = vec![0_u8; 16];
        video[4..8].copy_from_slice(b"ftyp");
        let (status, saved) = upload(
            &app,
            &owner_token,
            "clip.mp4",
            "video/mp4",
            &video,
            &[("duration", "3")],
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{saved}");
        assert_eq!(saved["kind"], "video");
        assert_eq!(saved["duration"].as_i64(), Some(3));
        let video_id = saved["id"].as_str().expect("video id").to_string();
        let (status, bytes) = download(&app, &owner_token, &video_id).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bytes, video);

        let _ = std::fs::remove_dir_all(&dir);
    })
    .await;
}

#[tokio::test]
async fn an_html_upload_is_unsupported_media() {
    run(|db| async move {
        let dir =
            std::env::temp_dir().join(format!("tinyserver-uploads-html-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("upload dir");
        std::env::set_var("TINYSERVER_UPLOAD_DIR", &dir);

        let owner = first_owner(&db).await;
        let token = session(&db, &owner.user_id).await;
        let app = api::router(db.runtime.clone(), None);
        let (status, denied) = upload(
            &app,
            &token,
            "page.html",
            "text/html",
            b"<html>hi</html>",
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{denied}");
        assert_eq!(denied["error"], "unsupported_media");
        let _ = std::fs::remove_dir_all(&dir);
    })
    .await;
}

#[tokio::test]
async fn a_pe_named_as_png_is_unsupported_media() {
    run(|db| async move {
        let dir =
            std::env::temp_dir().join(format!("tinyserver-uploads-pe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("upload dir");
        std::env::set_var("TINYSERVER_UPLOAD_DIR", &dir);

        let owner = first_owner(&db).await;
        let token = session(&db, &owner.user_id).await;
        let app = api::router(db.runtime.clone(), None);
        let mut bytes = b"MZ".to_vec();
        bytes.extend_from_slice(&[0; 64]);
        let (status, denied) = upload(&app, &token, "photo.png", "image/png", &bytes, &[]).await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{denied}");
        assert_eq!(denied["error"], "unsupported_media");
        let _ = std::fs::remove_dir_all(&dir);
    })
    .await;
}

#[tokio::test]
async fn a_direct_message_is_not_delivered_to_a_third_member() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let (peer, peer_token) = join(&db, &owner, "peer@tinyserver.test", "member").await;
        let (_other, other_token) = join(&db, &owner, "other@tinyserver.test", "member").await;
        let server = serve(&db, api::Limits::default()).await;
        let (_owner_ws, _) = connect(&server, &owner_token, None).await;
        let (mut peer_ws, _) = connect(&server, &peer_token, None).await;
        let (mut other_ws, _) = connect(&server, &other_token, None).await;
        let app = api::router(db.runtime.clone(), None);

        let (status, rejected) = Call::new(Method::POST, "/v1/directs")
            .token(&owner_token)
            .json(json!({"user_id": owner.user_id}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");

        let (status, missing) = Call::new(Method::POST, "/v1/directs")
            .token(&owner_token)
            .json(json!({"user_id": "00000000-0000-0000-0000-000000000000"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{missing}");

        let (status, direct) = Call::new(Method::POST, "/v1/directs")
            .token(&owner_token)
            .json(json!({"user_id": peer.user_id}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{direct}");
        let direct_id = direct["id"].as_str().expect("direct id").to_string();
        assert_eq!(direct["peer"]["user_id"], peer.user_id);

        let (status, again) = Call::new(Method::POST, "/v1/directs")
            .token(&owner_token)
            .json(json!({"user_id": peer.user_id}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{again}");
        assert_eq!(again["id"], direct_id);

        let (status, message) =
            send_message(&app, &owner_token, &direct_id, json!({"body": "psst"})).await;
        assert_eq!(status, StatusCode::CREATED, "{message}");

        let created = next_type(&mut peer_ws, "direct.created").await;
        assert_eq!(created["direct"]["id"], direct_id);
        let posted = next_type(&mut peer_ws, "message.created").await;
        assert_eq!(posted["message"]["body"], "psst");
        assert_eq!(posted["conversation_id"], direct_id);

        let (status, hidden) = get_messages(&app, &other_token, &direct_id).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{hidden}");
        ping(&mut other_ws).await;
    })
    .await;
}

#[tokio::test]
async fn a_private_channels_events_reach_only_members_who_can_view_it() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let (viewer, viewer_token) = join(&db, &owner, "viewer@tinyserver.test", "member").await;
        let (barred, barred_token) = join(&db, &owner, "barred@tinyserver.test", "member").await;
        let server = serve(&db, api::Limits::default()).await;
        let app = api::router(db.runtime.clone(), None);

        let (_, roles) = Call::new(Method::GET, "/v1/roles")
            .token(&owner_token)
            .send(&app)
            .await;
        let everyone = roles
            .as_array()
            .expect("roles")
            .iter()
            .find(|role| role["name"] == "@everyone")
            .and_then(|role| role["id"].as_str())
            .expect("everyone")
            .to_string();
        let (status, crew) = Call::new(Method::POST, "/v1/roles")
            .token(&owner_token)
            .json(json!({"name": "Crew", "permissions": 0, "color": "#22c55e"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{crew}");
        let crew = crew["id"].as_str().expect("crew id").to_string();
        let (status, given) = Call::new(
            Method::PUT,
            &format!("/v1/members/{}/roles", viewer.user_id),
        )
        .token(&owner_token)
        .json(json!({ "role_ids": [crew] }))
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::OK, "{given}");

        let mut channels = Vec::new();
        for name in ["open", "staff"] {
            let (status, channel) = Call::new(Method::POST, "/v1/channels")
                .token(&owner_token)
                .json(json!({ "name": name }))
                .send(&app)
                .await;
            assert_eq!(status, StatusCode::CREATED, "{channel}");
            channels.push(channel["id"].as_str().expect("channel id").to_string());
        }
        let (open, staff) = (channels[0].clone(), channels[1].clone());
        // @everyone cannot view staff; Crew can.
        for (role, allow, deny) in [(&everyone, 0, 1), (&crew, 1, 0)] {
            let (status, put) = Call::new(
                Method::PUT,
                &format!("/v1/channels/{staff}/overrides/{role}"),
            )
            .token(&owner_token)
            .json(json!({"allow": allow, "deny": deny}))
            .send(&app)
            .await;
            assert_eq!(status, StatusCode::OK, "{put}");
        }

        let (mut owner_ws, _) = connect(&server, &owner_token, None).await;
        let (mut viewer_ws, _) = connect(&server, &viewer_token, None).await;
        let (mut barred_ws, ready) = connect(&server, &barred_token, None).await;
        let since = ready["seq"].as_i64().expect("seq");

        // The control: a channel everyone can view still reaches everyone.
        let (status, hello) =
            send_message(&app, &owner_token, &open, json!({"body": "public hello"})).await;
        assert_eq!(status, StatusCode::CREATED, "{hello}");
        assert_eq!(
            next_type(&mut barred_ws, "message.created").await["message"]["body"],
            "public hello"
        );
        next_type(&mut viewer_ws, "message.created").await;
        next_type(&mut owner_ws, "message.created").await;

        // The private channel: its body, its edit and its reaction reach the member who can
        // view it and no one else.
        let (status, secret) = send_message(
            &app,
            &owner_token,
            &staff,
            json!({"body": "layoffs friday"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{secret}");
        let secret_id = secret["id"].as_str().expect("message id").to_string();
        let (status, edited) = Call::new(Method::PATCH, &format!("/v1/messages/{secret_id}"))
            .token(&owner_token)
            .json(json!({"body": "layoffs monday"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{edited}");
        let created = next_type(&mut viewer_ws, "message.created").await;
        assert_eq!(created["message"]["body"], "layoffs friday");
        let edit = next_type(&mut viewer_ws, "message.edited").await;
        assert_eq!(edit["message"]["body"], "layoffs monday");

        // Nothing about the staff channel reached the barred socket: its next durable frame
        // is the pong.
        ping(&mut barred_ws).await;

        // A socket that reconnects and replays does not see it either.
        let (mut replay_ws, _) = connect(&server, &barred_token, Some(since)).await;
        let replayed = next_type(&mut replay_ws, "message.created").await;
        assert_eq!(replayed["message"]["body"], "public hello");
        ping(&mut replay_ws).await;

        // The stored rows say the same: every event that carries the private text is
        // addressed to named viewers. None is addressed to NULL, which is every socket.
        let rows: Vec<(String, Option<Vec<String>>)> = sqlx::query_as(
            "SELECT topic, audience::text[] FROM outbox WHERE payload::text LIKE '%layoffs%' ORDER BY id",
        )
        .fetch_all(&db.owner)
        .await
        .expect("outbox");
        assert!(rows.len() >= 2, "{rows:?}");
        for (topic, audience) in rows {
            let audience = audience.unwrap_or_else(|| panic!("{topic} has no audience"));
            assert!(!audience.is_empty(), "{topic} has an empty audience");
            assert!(
                audience.iter().all(|id| id != &barred.user_id),
                "{topic} names the barred member"
            );
        }
    })
    .await;
}

#[tokio::test]
async fn an_admin_can_lower_the_image_cap() {
    run(|db| async move {
        let dir =
            std::env::temp_dir().join(format!("tinyserver-uploads-cap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("upload dir");
        std::env::set_var("TINYSERVER_UPLOAD_DIR", &dir);

        let owner = first_owner(&db).await;
        let token = session(&db, &owner.user_id).await;
        let app = api::router(db.runtime.clone(), None);
        let gif = include_bytes!("fixtures/tiny.gif").as_slice();

        let (status, server) = Call::new(Method::PATCH, "/v1/server")
            .token(&token)
            .json(json!({"image_max_bytes": 8}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{server}");
        assert_eq!(server["image_max_bytes"], 8);

        let (status, denied) = upload(&app, &token, "wave.gif", "image/gif", gif, &[]).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{denied}");
        assert_eq!(denied["error"], "too_large");

        let (status, server) = Call::new(Method::PATCH, "/v1/server")
            .token(&token)
            .json(json!({"image_max_bytes": 8 * 1024 * 1024}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{server}");
        let (status, saved) = upload(&app, &token, "wave.gif", "image/gif", gif, &[]).await;
        assert_eq!(status, StatusCode::CREATED, "{saved}");
        assert_eq!(saved["kind"], "gif");
    })
    .await;
}

#[tokio::test]
async fn a_zip_is_unsupported_until_the_server_allows_archives() {
    run(|db| async move {
        let dir =
            std::env::temp_dir().join(format!("tinyserver-uploads-zip-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("upload dir");
        std::env::set_var("TINYSERVER_UPLOAD_DIR", &dir);

        let owner = first_owner(&db).await;
        let token = session(&db, &owner.user_id).await;
        let app = api::router(db.runtime.clone(), None);
        let zip = stored_text_zip("hello.txt", b"hello");

        let (status, denied) =
            upload(&app, &token, "notes.zip", "application/zip", &zip, &[]).await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{denied}");
        assert_eq!(denied["error"], "unsupported_media");

        let (status, server) = Call::new(Method::GET, "/v1/server")
            .token(&token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{server}");
        assert_eq!(server["allow_archives"], false);

        let (status, server) = Call::new(Method::PATCH, "/v1/server")
            .token(&token)
            .json(json!({"allow_archives": true}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{server}");
        assert_eq!(server["allow_archives"], true);

        let (status, saved) = upload(&app, &token, "notes.zip", "application/zip", &zip, &[]).await;
        assert_eq!(status, StatusCode::CREATED, "{saved}");
        assert_eq!(saved["kind"], "file");

        let _ = std::fs::remove_dir_all(&dir);
    })
    .await;
}

#[tokio::test]
async fn an_eicar_upload_is_blocked() {
    run(|db| async move {
        let dir =
            std::env::temp_dir().join(format!("tinyserver-uploads-eicar-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("upload dir");
        std::env::set_var("TINYSERVER_UPLOAD_DIR", &dir);

        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let (_member, member_token) = join(&db, &owner, "member@tinyserver.test", "member").await;
        let app = api::router(db.runtime.clone(), None);

        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let (status, denied) =
            upload(&app, &owner_token, "eicar.txt", "text/plain", eicar, &[]).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
        assert_eq!(denied["error"], "blocked");

        let ids: Vec<String> = sqlx::query_scalar("SELECT id::text FROM attachments")
            .fetch_all(&db.owner)
            .await
            .expect("attachment ids");
        assert!(
            ids.is_empty(),
            "blocked upload must not commit a row: {ids:?}"
        );
        if let Some(id) = denied["id"].as_str() {
            let (status, _) = download(&app, &member_token, id).await;
            assert_ne!(
                status,
                StatusCode::OK,
                "member GET of blocked id must never be 200"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    })
    .await;
}

#[tokio::test]
async fn a_message_cannot_name_an_unscanned_attachment() {
    run(|db| async move {
        let dir = std::env::temp_dir().join(format!(
            "tinyserver-uploads-unscanned-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("upload dir");
        std::env::set_var("TINYSERVER_UPLOAD_DIR", &dir);

        let owner = first_owner(&db).await;
        let token = session(&db, &owner.user_id).await;
        let app = api::router(db.runtime.clone(), None);
        let (status, channel) = Call::new(Method::POST, "/v1/channels")
            .token(&token)
            .json(json!({"name": "files"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{channel}");
        let channel_id = channel["id"].as_str().expect("channel id").to_string();

        let (status, saved) =
            upload(&app, &token, "notes.txt", "text/plain", b"hello notes", &[]).await;
        assert_eq!(status, StatusCode::CREATED, "{saved}");
        let id = saved["id"].as_str().expect("attachment id").to_string();

        sqlx::query("UPDATE attachments SET scan_status = 'scanning' WHERE id = $1::uuid")
            .bind(&id)
            .execute(&db.owner)
            .await
            .expect("mark scanning");

        let (status, denied) = send_message(
            &app,
            &token,
            &channel_id,
            json!({"body": "", "attachment_ids": [id]}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{denied}");
        assert_eq!(denied["error"], "invalid");

        let _ = std::fs::remove_dir_all(&dir);
    })
    .await;
}

#[tokio::test]
async fn a_scanning_attachment_download_is_locked() {
    run(|db| async move {
        let dir = std::env::temp_dir().join(format!(
            "tinyserver-uploads-scanning-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("upload dir");
        std::env::set_var("TINYSERVER_UPLOAD_DIR", &dir);

        let owner = first_owner(&db).await;
        let token = session(&db, &owner.user_id).await;
        let app = api::router(db.runtime.clone(), None);

        let (status, saved) =
            upload(&app, &token, "notes.txt", "text/plain", b"hello notes", &[]).await;
        assert_eq!(status, StatusCode::CREATED, "{saved}");
        let id = saved["id"].as_str().expect("attachment id").to_string();

        sqlx::query("UPDATE attachments SET scan_status = 'scanning' WHERE id = $1::uuid")
            .bind(&id)
            .execute(&db.owner)
            .await
            .expect("mark scanning");

        let (status, bytes) = download(&app, &token, &id).await;
        assert_eq!(
            status,
            StatusCode::LOCKED,
            "{}",
            String::from_utf8_lossy(&bytes)
        );
        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        assert_eq!(body["error"], "scanning");

        let _ = std::fs::remove_dir_all(&dir);
    })
    .await;
}

#[tokio::test]
async fn download_sends_attachment_disposition_for_files() {
    run(|db| async move {
        let dir = std::env::temp_dir().join(format!(
            "tinyserver-uploads-disposition-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("upload dir");
        std::env::set_var("TINYSERVER_UPLOAD_DIR", &dir);

        let owner = first_owner(&db).await;
        let token = session(&db, &owner.user_id).await;
        let app = api::router(db.runtime.clone(), None);

        let pdf = b"%PDF-1.4\n";
        let (status, saved) = upload(&app, &token, "doc.pdf", "application/pdf", pdf, &[]).await;
        assert_eq!(status, StatusCode::CREATED, "{saved}");
        assert_eq!(saved["kind"], "file");
        assert_eq!(saved["mime"], "application/pdf");
        let pdf_id = saved["id"].as_str().expect("pdf id").to_string();

        let (status, headers, _) = download_at(&app, &token, &format!("/v1/media/{pdf_id}")).await;
        assert_eq!(status, StatusCode::OK);
        let disposition = header_str(&headers, header::CONTENT_DISPOSITION);
        assert!(
            disposition.starts_with("attachment"),
            "pdf disposition: {disposition}"
        );
        assert_eq!(
            header_str(&headers, header::CONTENT_TYPE),
            "application/pdf"
        );

        let pdf_url = saved["url"].as_str().expect("signed url");
        assert!(
            pdf_url.starts_with(&format!("/v1/media/{pdf_id}?")),
            "{pdf_url}"
        );
        assert!(pdf_url.contains("ex="), "{pdf_url}");
        assert!(pdf_url.contains("is="), "{pdf_url}");
        assert!(pdf_url.contains("hm="), "{pdf_url}");

        let notes = b"hello notes";
        let (status, saved) = upload(&app, &token, "notes.txt", "text/plain", notes, &[]).await;
        assert_eq!(status, StatusCode::CREATED, "{saved}");
        let notes_id = saved["id"].as_str().expect("notes id");
        let (status, headers, _) =
            download_at(&app, &token, &format!("/v1/media/{notes_id}")).await;
        assert_eq!(status, StatusCode::OK);
        let disposition = header_str(&headers, header::CONTENT_DISPOSITION);
        assert!(
            disposition.starts_with("attachment"),
            "file disposition: {disposition}"
        );

        let gif = include_bytes!("fixtures/tiny.gif").as_slice();
        let (status, saved) = upload(&app, &token, "wave.gif", "image/gif", gif, &[]).await;
        assert_eq!(status, StatusCode::CREATED, "{saved}");
        assert_eq!(saved["kind"], "gif");
        let gif_id = saved["id"].as_str().expect("gif id");
        let (status, headers, _) = download_at(&app, &token, &format!("/v1/media/{gif_id}")).await;
        assert_eq!(status, StatusCode::OK);
        let disposition = header_str(&headers, header::CONTENT_DISPOSITION);
        assert!(
            disposition.starts_with("inline"),
            "gif disposition: {disposition}"
        );
        assert_eq!(header_str(&headers, header::CONTENT_TYPE), "image/gif");

        let png = include_bytes!("fixtures/tiny.png").as_slice();
        let (status, saved) = upload(&app, &token, "dot.png", "image/png", png, &[]).await;
        assert_eq!(status, StatusCode::CREATED, "{saved}");
        assert_eq!(saved["kind"], "image");
        let png_id = saved["id"].as_str().expect("png id");
        let (status, headers, _) = download_at(&app, &token, &format!("/v1/media/{png_id}")).await;
        assert_eq!(status, StatusCode::OK);
        let disposition = header_str(&headers, header::CONTENT_DISPOSITION);
        assert!(
            disposition.starts_with("inline"),
            "png disposition: {disposition}"
        );
        assert_eq!(header_str(&headers, header::CONTENT_TYPE), "image/png");

        let _ = std::fs::remove_dir_all(&dir);
    })
    .await;
}

#[tokio::test]
async fn download_keeps_nosniff_and_no_store() {
    run(|db| async move {
        let dir =
            std::env::temp_dir().join(format!("tinyserver-uploads-nosniff-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("upload dir");
        std::env::set_var("TINYSERVER_UPLOAD_DIR", &dir);

        let owner = first_owner(&db).await;
        let token = session(&db, &owner.user_id).await;
        let app = api::router(db.runtime.clone(), None);

        let (status, saved) =
            upload(&app, &token, "notes.txt", "text/plain", b"hello notes", &[]).await;
        assert_eq!(status, StatusCode::CREATED, "{saved}");
        let id = saved["id"].as_str().expect("id");
        let (status, headers, _) = download_at(&app, &token, &format!("/v1/media/{id}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            header_str(&headers, header::X_CONTENT_TYPE_OPTIONS),
            "nosniff"
        );
        assert_eq!(header_str(&headers, header::CACHE_CONTROL), "no-store");

        let _ = std::fs::remove_dir_all(&dir);
    })
    .await;
}

#[tokio::test]
async fn a_bad_hmac_is_refused() {
    run(|db| async move {
        let dir =
            std::env::temp_dir().join(format!("tinyserver-uploads-hmac-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("upload dir");
        std::env::set_var("TINYSERVER_UPLOAD_DIR", &dir);

        let owner = first_owner(&db).await;
        let token = session(&db, &owner.user_id).await;
        let app = api::router(db.runtime.clone(), None);

        let (status, saved) =
            upload(&app, &token, "notes.txt", "text/plain", b"hello notes", &[]).await;
        assert_eq!(status, StatusCode::CREATED, "{saved}");
        let id = saved["id"].as_str().expect("id").to_string();

        let (status, _, bytes) = download_at(
            &app,
            &token,
            &format!("/v1/media/{id}?ex=2000000000&is=1&hm=00"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "invalid hm must 401: {}",
            String::from_utf8_lossy(&bytes)
        );

        let (status, _, bytes) = download_at(&app, &token, &format!("/v1/media/{id}?ex=1")).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "partial hmac params must 401: {}",
            String::from_utf8_lossy(&bytes)
        );

        let (status, _) = download(&app, &token, &id).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "missing hmac params stay Bearer-compat"
        );

        let url = saved["url"].as_str().expect("signed url");
        let (status, _, _) = download_at(&app, &token, url).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a minted url still downloads with Bearer"
        );

        let _ = std::fs::remove_dir_all(&dir);
    })
    .await;
}

async fn send_message(
    app: &Router,
    token: &str,
    conversation: &str,
    body: Value,
) -> (StatusCode, Value) {
    let path = format!("/v1/conversations/{conversation}/messages");
    Call::new(Method::POST, &path)
        .token(token)
        .json(body)
        .send(app)
        .await
}

async fn get_json(app: &Router, token: &str, path: &str) -> Value {
    let (status, value) = Call::new(Method::GET, path).token(token).send(app).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    value
}

async fn get_messages(app: &Router, token: &str, conversation: &str) -> (StatusCode, Value) {
    let path = format!("/v1/conversations/{conversation}/messages");
    Call::new(Method::GET, &path).token(token).send(app).await
}

async fn mark_read(app: &Router, token: &str, conversation: &str, message_id: &str) {
    let path = format!("/v1/conversations/{conversation}/read");
    let (status, value) = Call::new(Method::POST, &path)
        .token(token)
        .json(json!({"message_id": message_id}))
        .send(app)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{value}");
}

async fn next_type(ws: &mut Ws, kind: &str) -> Value {
    loop {
        let value = durable(ws).await;
        if value["type"] == kind {
            return value;
        }
    }
}

/// One stored text file, built in memory. CRC-32 matches the ZIP spec.
fn stored_text_zip(name: &str, data: &[u8]) -> Vec<u8> {
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &byte in data {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                if crc & 1 == 1 {
                    crc = (crc >> 1) ^ 0xEDB8_8320;
                } else {
                    crc >>= 1;
                }
            }
        }
        !crc
    }

    let name_bytes = name.as_bytes();
    let crc = crc32(data);
    let size = u32::try_from(data.len()).expect("zip size");
    let name_len = u16::try_from(name_bytes.len()).expect("zip name");
    let mut out = Vec::new();
    out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&name_len.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(data);
    let cd_offset = u32::try_from(out.len()).expect("cd offset");
    out.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&name_len.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(name_bytes);
    let cd_size = u32::try_from(out.len()).expect("cd size") - cd_offset;
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn multipart(filename: &str, mime: &str, bytes: &[u8], fields: &[(&str, &str)]) -> Vec<u8> {
    let boundary = "TinyBoundary";
    let mut body = Vec::new();
    body.extend(format!("--{boundary}\r\n").as_bytes());
    body.extend(
        format!(
            "Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: {mime}\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend(bytes);
    for (name, value) in fields {
        body.extend(
            format!("\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}")
                .as_bytes(),
        );
    }
    body.extend(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

async fn upload(
    app: &Router,
    token: &str,
    filename: &str,
    mime: &str,
    bytes: &[u8],
    fields: &[(&str, &str)],
) -> (StatusCode, Value) {
    let body = multipart(filename, mime, bytes, fields);
    let (status, _headers, bytes) = exchange(
        app,
        Method::POST,
        "/v1/media",
        token,
        "multipart/form-data; boundary=TinyBoundary",
        body,
    )
    .await;
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

async fn download(app: &Router, token: &str, id: &str) -> (StatusCode, Vec<u8>) {
    let path = format!("/v1/media/{id}");
    let (status, headers, bytes) = download_at(app, token, &path).await;
    if status == StatusCode::OK {
        let mime = headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        assert!(!mime.is_empty(), "download content type");
    }
    (status, bytes)
}

async fn download_at(
    app: &Router,
    token: &str,
    path: &str,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    exchange(app, Method::GET, path, token, "", Vec::new()).await
}

fn header_str(headers: &axum::http::HeaderMap, name: axum::http::HeaderName) -> &str {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
}

async fn exchange(
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
