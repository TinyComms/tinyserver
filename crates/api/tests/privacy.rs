//! What one member can learn about another, and what the server keeps. Each test names a
//! privacy property and fails when it stops holding.

mod common;

use axum::http::{Method, StatusCode};
use common::{first_owner, join, run, session, Call};
use serde_json::{json, Value};

fn emails(members: &Value) -> Vec<(String, Option<String>)> {
    members
        .as_array()
        .expect("members")
        .iter()
        .map(|member| {
            (
                member["user_id"].as_str().expect("user_id").to_string(),
                member["email"].as_str().map(str::to_string),
            )
        })
        .collect()
}

#[tokio::test]
async fn a_member_sees_their_own_email_and_not_another_members() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let (ada, ada_token) = join(&db, &owner, "ada@tinyserver.test", "member").await;
        let (bea, _) = join(&db, &owner, "bea@tinyserver.test", "member").await;
        let app = api::router(db.runtime.clone(), None);

        let (status, seen_by_ada) = Call::new(Method::GET, "/v1/members")
            .token(&ada_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{seen_by_ada}");
        let seen_by_ada = emails(&seen_by_ada);
        assert_eq!(seen_by_ada.len(), 3);
        for (user_id, email) in &seen_by_ada {
            if user_id == &ada.user_id {
                assert_eq!(email.as_deref(), Some("ada@tinyserver.test"));
            } else {
                assert_eq!(email, &None, "{user_id}'s email reached another member");
            }
        }

        // Whoever manages the server can still tell people apart by email.
        let (_, seen_by_owner) = Call::new(Method::GET, "/v1/members")
            .token(&owner_token)
            .send(&app)
            .await;
        let seen_by_owner = emails(&seen_by_owner);
        let bea_row = seen_by_owner
            .iter()
            .find(|(user_id, _)| user_id == &bea.user_id)
            .expect("bea");
        assert_eq!(bea_row.1.as_deref(), Some("bea@tinyserver.test"));
    })
    .await;
}

#[tokio::test]
async fn deleting_an_account_removes_the_person_and_what_they_said() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let (ada, ada_token) = join(&db, &owner, "ada@tinyserver.test", "member").await;
        let (_bea, bea_token) = join(&db, &owner, "bea@tinyserver.test", "member").await;
        let app = api::router(db.runtime.clone(), None);

        let (status, channel) = Call::new(Method::POST, "/v1/channels")
            .token(&owner_token)
            .json(json!({"name": "general"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{channel}");
        let channel = channel["id"].as_str().expect("channel").to_string();

        let (status, renamed) = Call::new(Method::PATCH, "/v1/me")
            .token(&ada_token)
            .json(json!({"display_name": "Ada Lovelace"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{renamed}");

        let (status, posted) = Call::new(
            Method::POST,
            &format!("/v1/conversations/{channel}/messages"),
        )
        .token(&ada_token)
        .json(json!({"body": "first draft of the secret"}))
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::CREATED, "{posted}");
        let message = posted["id"].as_str().expect("message").to_string();
        let (status, edited) = Call::new(Method::PATCH, &format!("/v1/messages/{message}"))
            .token(&ada_token)
            .json(json!({"body": "final text of the secret"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{edited}");

        // An edit rewrites the live history that still holds the first version, so a socket
        // that reconnects is not replayed text its author took back.
        let first: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM outbox WHERE payload::text LIKE '%first draft%'",
        )
        .fetch_one(&db.owner)
        .await
        .expect("outbox");
        assert_eq!(
            first, 0,
            "an edited message's first version is in the outbox"
        );

        // A one-time sign-in code she has not traded yet, as if she were mid sign-in on
        // another device when she deleted her account.
        sqlx::query(
            "INSERT INTO auth_codes (code_hash, user_id, client_challenge, issuer, expires_at)
             VALUES (sha256('unredeemed'::bytea), $1::uuid, 'challenge', 'https://auth.test',
                     now() + interval '1 minute')",
        )
        .bind(&ada.user_id)
        .execute(&db.owner)
        .await
        .expect("auth code");

        // The typed phrase is required.
        let (status, _) = Call::new(Method::DELETE, "/v1/me")
            .token(&ada_token)
            .json(json!({"confirm": "yes"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // A sole owner cannot leave the community without one.
        let (status, refused) = Call::new(Method::DELETE, "/v1/me")
            .token(&owner_token)
            .json(json!({"confirm": "delete my account"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{refused}");
        assert_eq!(refused["error"], "last_owner");

        let (status, _) = Call::new(Method::DELETE, "/v1/me")
            .token(&ada_token)
            .json(json!({"confirm": "delete my account"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // The session is gone.
        let (status, _) = Call::new(Method::GET, "/v1/me")
            .token(&ada_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Nothing that says who she was remains in the user row.
        let row: (Option<String>, String, bool, bool) = sqlx::query_as(
            "SELECT email, display_name, deleted_at IS NOT NULL, avatar IS NULL
             FROM users WHERE id = $1::uuid",
        )
        .bind(&ada.user_id)
        .fetch_one(&db.owner)
        .await
        .expect("tombstone");
        assert_eq!(row, (None, "Deleted user".to_string(), true, true));
        for (table, filter) in [
            ("user_identities", "user_id"),
            ("memberships", "user_id"),
            ("sessions", "user_id"),
            ("auth_codes", "user_id"),
        ] {
            let left: i64 = sqlx::query_scalar(&format!(
                "SELECT count(*) FROM {table} WHERE {filter} = $1::uuid"
            ))
            .bind(&ada.user_id)
            .fetch_one(&db.owner)
            .await
            .expect("count");
            assert_eq!(left, 0, "{table} still has a row for the deleted account");
        }

        // Her message is emptied for the people who remain, not left saying what it said.
        let (status, history) = Call::new(
            Method::GET,
            &format!("/v1/conversations/{channel}/messages"),
        )
        .token(&bea_token)
        .send(&app)
        .await;
        assert_eq!(status, StatusCode::OK, "{history}");
        assert_eq!(history[0]["body"], "");
        assert!(history[0]["deleted_at"].is_string(), "{history}");

        // No stored copy of the text, the name, or the email is left in the live history or
        // the audit log.
        for needle in ["final text", "Ada Lovelace", "ada@tinyserver.test"] {
            let outbox: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM outbox WHERE payload::text LIKE '%' || $1 || '%'",
            )
            .bind(needle)
            .fetch_one(&db.owner)
            .await
            .expect("outbox");
            assert_eq!(outbox, 0, "{needle:?} is still in the outbox");
            let audit: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM audit_log WHERE detail::text LIKE '%' || $1 || '%'",
            )
            .bind(needle)
            .fetch_one(&db.owner)
            .await
            .expect("audit");
            assert_eq!(audit, 0, "{needle:?} is still in the audit log");
        }

        // The record that it happened stays, without who she was.
        let deleted: i64 =
            sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = 'account.delete'")
                .fetch_one(&db.owner)
                .await
                .expect("audit");
        assert_eq!(deleted, 1);
    })
    .await;
}
