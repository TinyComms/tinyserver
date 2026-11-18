//! A new community starts with a #general text channel: the transaction that makes the first
//! owner membership makes the community's first channel. See
//! `0042_seed_general_channel.sql`. It applies after `0022_e2ee_text_messages.sql`; on a
//! database whose newest migration is older, migrate fails in `run` before these assertions.

mod common;

use axum::http::{Method, StatusCode};
use common::{first_owner, invite_hash, profile, run, session, Call};

#[tokio::test]
async fn a_new_community_starts_with_exactly_one_general_channel() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let token = session(&db, &owner.user_id).await;
        let app = api::router(db.runtime.clone(), None);

        let (_, channels) = Call::new(Method::GET, "/v1/channels")
            .token(&token)
            .send(&app)
            .await;
        let channels = channels.as_array().expect("channels");
        assert_eq!(channels.len(), 1, "{channels:?}");
        let general = &channels[0];
        assert_eq!(general["name"], "general");
        assert_eq!(general["topic"], "");
        assert_eq!(general["position"], 0);
        assert!(general["category_id"].is_null());
        assert_eq!(general["created_by"].as_str(), Some(owner.user_id.as_str()));
        assert_eq!(general["e2ee"], false);
        assert_eq!(general["overrides"], serde_json::json!([]));
        assert_eq!(general["unread"], 0);
        assert!(general["last_message"].is_null());

        // The same wiring a created channel gets: an audit row with no actor, as bootstrap
        // writes its own, and the channel.created event a client already listens for.
        let (actor, name, seeded): (Option<String>, String, bool) = sqlx::query_as(
            "SELECT actor_id::text, detail->>'name', (detail->>'seeded')::boolean
             FROM audit_log WHERE action = 'channel.create'",
        )
        .fetch_one(&db.owner)
        .await
        .expect("seed audit");
        assert_eq!((actor.as_deref(), name.as_str(), seeded), (None, "general", true));
        let announced: String = sqlx::query_scalar(
            "SELECT payload->'channel'->>'id' FROM outbox WHERE topic = 'channel.created'
             ORDER BY id DESC LIMIT 1",
        )
        .fetch_one(&db.owner)
        .await
        .expect("channel.created event");
        assert_eq!(Some(announced.as_str()), general["id"].as_str());
    })
    .await;
}

#[tokio::test]
async fn the_seeded_channel_follows_the_e2ee_text_setting() {
    run(|db| async move {
        // Setup runs later, so the setting is changed as the database's own state here.
        sqlx::query("UPDATE server_settings SET e2ee_text = 'new_required'")
            .execute(&db.owner)
            .await
            .expect("new_required");
        let owner = first_owner(&db).await;
        let token = session(&db, &owner.user_id).await;
        let app = api::router(db.runtime.clone(), None);

        let (_, channels) = Call::new(Method::GET, "/v1/channels")
            .token(&token)
            .send(&app)
            .await;
        let channels = channels.as_array().expect("channels");
        assert_eq!(channels.len(), 1, "{channels:?}");
        assert_eq!(channels[0]["name"], "general");
        assert_eq!(channels[0]["e2ee"], true);
    })
    .await;
}

#[tokio::test]
async fn the_seed_happens_with_no_device_enrolled_yet() {
    run(|db| async move {
        // At the first sign-in no device can be enrolled yet, so an encrypted seed starts over
        // an empty audience even at the smallest cap: nothing about the device state stops it.
        sqlx::query("UPDATE server_settings SET e2ee_text = 'new_required', e2ee_group_devices_max = 2")
            .execute(&db.owner)
            .await
            .expect("cap");
        let owner = first_owner(&db).await;
        assert_eq!(owner.role, "owner");
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM channels")
            .fetch_one(&db.owner)
            .await
            .expect("channels");
        assert_eq!(count, 1, "the seed happens whatever the device state");
    })
    .await;
}

#[tokio::test]
async fn a_deleted_general_is_not_brought_back_by_the_next_owner() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let token = session(&db, &owner.user_id).await;
        let app = api::router(db.runtime.clone(), None);
        let (_, channels) = Call::new(Method::GET, "/v1/channels")
            .token(&token)
            .send(&app)
            .await;
        let id = channels.as_array().expect("channels")[0]["id"]
            .as_str()
            .expect("channel id")
            .to_string();
        let (status, _) = Call::new(Method::DELETE, &format!("/v1/channels/{id}"))
            .token(&token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // A recovery owner forced past the one that exists joins a community that already has
        // people: its first membership was made long ago, so nothing is seeded again.
        let issued = db::owner_invite(&db.owner, true)
            .await
            .expect("owner invite")
            .expect("forced");
        let keeper = db::sign_in(
            &db.runtime,
            &profile("keeper@tinyserver.test"),
            Some(&invite_hash(&issued.token)),
            db::Groups::default(),
        )
        .await
        .expect("recovery owner signs in");
        assert_eq!(keeper.role, "owner");
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM channels")
            .fetch_one(&db.owner)
            .await
            .expect("channels");
        assert_eq!(count, 0, "a deleted general is not seeded again");
    })
    .await;
}
