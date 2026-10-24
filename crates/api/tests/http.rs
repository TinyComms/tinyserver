//! The HTTP surface against a real Postgres. See `common` for the environment.

mod common;

use axum::http::{Method, StatusCode};
use common::{first_owner, run, sign_in, sqlstate, Call, OWNER_EMAIL, OWNER_PASSWORD, PASSWORD};
use serde_json::json;

#[tokio::test]
async fn an_owner_signs_in_reads_me_and_signs_out() {
    run(|db| async move {
        first_owner(&db).await;
        let app = api::router(db.runtime.clone());

        let (status, body) = Call::new(Method::POST, "/v1/session")
            .json(json!({"email": OWNER_EMAIL, "password": "wrong-password-here"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, json!({"error": "invalid_credentials"}));

        let token = sign_in(&app, OWNER_EMAIL, OWNER_PASSWORD).await;
        let (status, body) = Call::new(Method::GET, "/v1/me")
            .token(&token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["email"], OWNER_EMAIL);
        assert_eq!(body["role"], "owner");

        let (status, _) = Call::new(Method::DELETE, "/v1/session")
            .token(&token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, body) = Call::new(Method::GET, "/v1/me")
            .token(&token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, json!({"error": "unauthorized"}));
    })
    .await;
}

#[tokio::test]
async fn a_member_cannot_make_rooms_or_invites_or_read_the_audit() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = api::router(db.runtime.clone());
        let owner_token = sign_in(&app, OWNER_EMAIL, OWNER_PASSWORD).await;

        let (status, issued) = Call::new(Method::POST, "/v1/invites")
            .token(&owner_token)
            .json(json!({"role": "member"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, accepted) = Call::new(Method::POST, "/v1/invites/accept")
            .json(json!({
                "token": issued["token"],
                "email": "member@tinyserver.test",
                "password": PASSWORD,
                "display_name": "Member",
            }))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK);
        let member_token = accepted["token"].as_str().expect("token");
        let member_id = accepted["user_id"].as_str().expect("user id");

        let forbidden = json!({"error": "forbidden"});
        let calls = [
            Call::new(Method::POST, "/v1/rooms").json(json!({"name": "Nope"})),
            Call::new(Method::POST, "/v1/invites").json(json!({"role": "member"})),
            Call::new(Method::GET, "/v1/invites"),
            Call::new(Method::GET, "/v1/audit"),
            Call::new(Method::PATCH, "/v1/members/00000000-0000-0000-0000-000000000000")
                .json(json!({"role": "admin"})),
        ];
        for call in calls {
            let path = call.path;
            let (status, body) = call.token(member_token).send(&app).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
            assert_eq!(body, forbidden, "{path}");
        }
        let (status, _) = Call::new(Method::GET, "/v1/rooms")
            .token(member_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK);

        // RLS holds even when the API check is skipped.
        for statement in [
            "INSERT INTO rooms (name, created_by) VALUES ('Nope', $1::uuid)",
            "INSERT INTO invites (role, token_hash, created_by, expires_at)
             VALUES ('member', sha256('x'::bytea), $1::uuid, now() + interval '1 day')",
        ] {
            let mut tx = db.runtime.begin().await.expect("begin");
            sqlx::query("SELECT set_config('app.user_id', $1, true), set_config('app.role', 'member', true)")
                .bind(member_id)
                .execute(&mut *tx)
                .await
                .expect("scope");
            let error = sqlx::query(statement)
                .bind(member_id)
                .execute(&mut *tx)
                .await
                .expect_err("RLS denies the insert");
            assert_eq!(sqlstate(&error), "42501", "{statement}");
        }
        let mut tx = db.runtime.begin().await.expect("begin");
        sqlx::query("SELECT set_config('app.user_id', $1, true), set_config('app.role', 'member', true)")
            .bind(member_id)
            .execute(&mut *tx)
            .await
            .expect("scope");
        let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log")
            .fetch_one(&mut *tx)
            .await
            .expect("audit count");
        assert_eq!(visible, 0);
        let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM invites")
            .fetch_one(&mut *tx)
            .await
            .expect("invite count");
        assert_eq!(visible, 0);
        drop(tx);

        let audit = db::list_audit(&db.runtime, &owner, 50).await.expect("audit");
        assert!(audit.iter().any(|row| row.action == "invite.accept"));
    })
    .await;
}

#[tokio::test]
async fn an_admin_cannot_change_or_remove_an_owner() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let (admin, admin_token) =
            common::join(&db, &owner, "admin@tinyserver.test", "admin").await;
        let app = api::router(db.runtime.clone());
        let owner_path = format!("/v1/members/{}", owner.user_id);
        let admin_path = format!("/v1/members/{}", admin.user_id);

        let (status, body) = Call::new(Method::PATCH, &owner_path)
            .token(&admin_token)
            .json(json!({"role": "member"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, json!({"error": "forbidden"}));

        let (status, _) = Call::new(Method::DELETE, &owner_path)
            .token(&admin_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _) = Call::new(Method::PATCH, &admin_path)
            .token(&admin_token)
            .json(json!({"role": "owner"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let roles: Vec<String> =
            sqlx::query_scalar("SELECT role FROM memberships ORDER BY created_at")
                .fetch_all(&db.owner)
                .await
                .expect("roles");
        assert_eq!(roles, ["owner", "admin"]);
    })
    .await;
}

#[tokio::test]
async fn the_last_owner_cannot_be_demoted_or_removed() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = api::router(db.runtime.clone());
        let token = sign_in(&app, OWNER_EMAIL, OWNER_PASSWORD).await;
        let path = format!("/v1/members/{}", owner.user_id);

        let (status, body) = Call::new(Method::PATCH, &path)
            .token(&token)
            .json(json!({"role": "admin"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, json!({"error": "last_owner"}));

        let (status, body) = Call::new(Method::DELETE, &path)
            .token(&token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, json!({"error": "last_owner"}));

        let (second, _) = common::join(&db, &owner, "second@tinyserver.test", "member").await;
        let (status, _) = Call::new(Method::PATCH, &format!("/v1/members/{}", second.user_id))
            .token(&token)
            .json(json!({"role": "owner"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = Call::new(Method::PATCH, &path)
            .token(&token)
            .json(json!({"role": "admin"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, json!({"role": "admin"}));
        assert_eq!(common::owner_count(&db).await, 1);
    })
    .await;
}

#[tokio::test]
async fn an_invite_signs_a_person_in_once_and_not_after_it_expires() {
    run(|db| async move {
        first_owner(&db).await;
        let app = api::router(db.runtime.clone());
        let owner_token = sign_in(&app, OWNER_EMAIL, OWNER_PASSWORD).await;

        let issued = invite(&app, &owner_token, Some("first-invite")).await;
        let replayed = invite(&app, &owner_token, Some("first-invite")).await;
        assert_eq!(replayed, issued);

        let accept = |token: serde_json::Value, email: &'static str| {
            let app = app.clone();
            async move {
                Call::new(Method::POST, "/v1/invites/accept")
                    .json(json!({
                        "token": token,
                        "email": email,
                        "password": PASSWORD,
                        "display_name": "Guest",
                    }))
                    .send(&app)
                    .await
            }
        };

        let (status, accepted) = accept(issued["token"].clone(), "guest@tinyserver.test").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(accepted["role"], "member");
        let (status, me) = Call::new(Method::GET, "/v1/me")
            .token(accepted["token"].as_str().expect("token"))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(me["email"], "guest@tinyserver.test");
        assert_eq!(me["role"], "member");

        let (status, body) = accept(issued["token"].clone(), "other@tinyserver.test").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, json!({"error": "not_found"}));

        let stale = invite(&app, &owner_token, None).await;
        sqlx::query(
            "UPDATE invites SET expires_at = now() - interval '1 minute' WHERE id = $1::uuid",
        )
        .bind(stale["id"].as_str().expect("id"))
        .execute(&db.owner)
        .await
        .expect("expire invite");
        let (status, body) = accept(stale["token"].clone(), "late@tinyserver.test").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, json!({"error": "not_found"}));

        let late: i64 =
            sqlx::query_scalar("SELECT count(*) FROM users WHERE email = 'late@tinyserver.test'")
                .fetch_one(&db.owner)
                .await
                .expect("user count");
        assert_eq!(late, 0);
    })
    .await;
}

async fn invite(app: &axum::Router, owner_token: &str, key: Option<&str>) -> serde_json::Value {
    let mut call = Call::new(Method::POST, "/v1/invites")
        .token(owner_token)
        .json(json!({"role": "member"}));
    if let Some(key) = key {
        call = call.idempotency_key(key);
    }
    let (status, body) = call.send(app).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body
}
