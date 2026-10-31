//! Bots: a token and the scopes an owner granted.

mod common;

use axum::http::{Method, StatusCode};
use common::{first_owner, run, session, Call};
use serde_json::json;

#[tokio::test]
async fn a_bot_can_do_only_what_it_was_granted() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = api::router(db.runtime.clone(), None);
        let owner_token = session(&db, &owner.user_id).await;

        let (_member, member_token) =
            common::join(&db, &owner, "member@tinyserver.test", "member").await;
        let (status, body) = Call::new(Method::POST, "/v1/bots")
            .token(&member_token)
            .json(json!({"name": "Nope", "scopes": ["rooms.read"]}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, json!({"error": "forbidden"}));

        let (status, body) = Call::new(Method::POST, "/v1/bots")
            .token(&owner_token)
            .json(json!({"name": "  Herald ", "scopes": ["voice.connect"]}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

        let (status, issued) = Call::new(Method::POST, "/v1/bots")
            .token(&owner_token)
            .json(json!({"name": "  Herald ", "scopes": ["rooms.read"]}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{issued}");
        assert_eq!(issued["name"], "Herald");
        assert_eq!(issued["scopes"], json!(["rooms.read"]));
        let token = issued["token"].as_str().expect("token");
        let bot_id = issued["id"].as_str().expect("id");

        let (status, me) = Call::new(Method::GET, "/v1/me").bot(token).send(&app).await;
        assert_eq!(status, StatusCode::OK, "{me}");
        assert_eq!(me["role"], "bot");
        assert_eq!(me["display_name"], "Herald");
        assert_eq!(me["user_id"], bot_id);
        assert_eq!(me["scopes"], json!(["rooms.read"]));
        assert!(me.get("email").expect("email field").is_null());

        let (status, _) = Call::new(Method::GET, "/v1/me")
            .token(token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, rooms) = Call::new(Method::GET, "/v1/rooms")
            .bot(token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{rooms}");
        assert_eq!(rooms, json!([]));

        let (status, body) = Call::new(Method::GET, "/v1/members")
            .bot(token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, json!({"error": "forbidden"}));

        let (status, _) = Call::new(Method::POST, "/v1/rooms")
            .bot(token)
            .json(json!({"name": "Secret"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, listed) = Call::new(Method::GET, "/v1/bots")
            .token(&owner_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert_eq!(listed.as_array().expect("list").len(), 1);
        assert!(listed[0].get("token").is_none());

        let (status, _) = Call::new(Method::GET, "/v1/bots")
            .token(&member_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let path = format!("/v1/bots/{bot_id}");
        let (status, _) = Call::new(Method::DELETE, &path)
            .token(&owner_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = Call::new(Method::GET, "/v1/me").bot(token).send(&app).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    })
    .await;
}

#[tokio::test]
async fn a_bot_granted_manage_channels_can_create_a_room() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = api::router(db.runtime.clone(), None);
        let owner_token = session(&db, &owner.user_id).await;

        let (status, issued) = Call::new(Method::POST, "/v1/bots")
            .token(&owner_token)
            .json(json!({
                "name": "Mason",
                "permissions": 512,
                "scopes": ["members.read"]
            }))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{issued}");
        assert_eq!(issued["permissions"], json!(512));
        assert_eq!(issued["scopes"], json!(["rooms.write"]));
        let token = issued["token"].as_str().expect("token");

        let (status, room) = Call::new(Method::POST, "/v1/rooms")
            .bot(token)
            .json(json!({"name": "Workshop"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{room}");
        assert_eq!(room["name"], "Workshop");

        let (status, reader) = Call::new(Method::POST, "/v1/bots")
            .token(&owner_token)
            .json(json!({"name": "Reader", "scopes": ["rooms.read"]}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{reader}");
        let reader_token = reader["token"].as_str().expect("token");
        let (status, _) = Call::new(Method::POST, "/v1/rooms")
            .bot(reader_token)
            .json(json!({"name": "Secret"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    })
    .await;
}
