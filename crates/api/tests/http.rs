//! The HTTP surface against a real Postgres. See `common` for the environment.

mod common;

use axum::http::{Method, StatusCode};
use common::{first_owner, invite_hash, profile, run, session, sqlstate, Call, OWNER_EMAIL};
use serde_json::json;

#[tokio::test]
async fn an_owner_reads_me_and_signs_out() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = api::router(db.runtime.clone(), None);

        // Password sign-in, invite acceptance, and password change are gone.
        for (method, path) in [
            (Method::POST, "/v1/session"),
            (Method::POST, "/v1/invites/accept"),
            (Method::POST, "/v1/me/password"),
        ] {
            let (status, _) = Call::new(method, path)
                .json(json!({"email": OWNER_EMAIL, "password": "an-old-password"}))
                .send(&app)
                .await;
            assert!(
                status == StatusCode::NOT_FOUND || status == StatusCode::METHOD_NOT_ALLOWED,
                "{path}: {status}"
            );
        }

        let token = session(&db, &owner.user_id).await;
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
        let app = api::router(db.runtime.clone(), None);
        let (member, member_token) =
            common::join(&db, &owner, "member@tinyserver.test", "member").await;
        let member_token = member_token.as_str();
        let member_id = member.user_id.as_str();

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

        // An admin cannot make an owner invite even past the API. Only bootstrap can.
        let mut tx = db.runtime.begin().await.expect("begin");
        sqlx::query("SELECT set_config('app.user_id', $1, true), set_config('app.role', 'admin', true)")
            .bind(member_id)
            .execute(&mut *tx)
            .await
            .expect("scope");
        let error = sqlx::query(
            "INSERT INTO invites (role, token_hash, created_by, expires_at)
             VALUES ('owner', sha256('y'::bytea), $1::uuid, now() + interval '1 day')",
        )
        .bind(member_id)
        .execute(&mut *tx)
        .await
        .expect_err("RLS denies an owner invite");
        assert_eq!(sqlstate(&error), "42501");
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
        let app = api::router(db.runtime.clone(), None);
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
        let app = api::router(db.runtime.clone(), None);
        let token = session(&db, &owner.user_id).await;
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
async fn an_invite_lets_a_person_in_once_and_not_after_it_expires() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = api::router(db.runtime.clone(), None);
        let owner_token = session(&db, &owner.user_id).await;

        let issued = invite(&app, &owner_token, Some("first-invite")).await;
        let replayed = invite(&app, &owner_token, Some("first-invite")).await;
        assert_eq!(replayed, issued);
        let token = issued["token"].as_str().expect("token");

        let guest = db::sign_in(
            &db.runtime,
            &profile("guest@tinyserver.test"),
            Some(&invite_hash(token)),
            db::Groups::default(),
        )
        .await
        .expect("join");
        assert_eq!(guest.role, "member");
        assert!(guest.joined);
        let (status, me) = Call::new(Method::GET, "/v1/me")
            .token(&session(&db, &guest.user_id).await)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(me["email"], "guest@tinyserver.test");
        assert_eq!(me["role"], "member");

        let again = db::sign_in(
            &db.runtime,
            &profile("other@tinyserver.test"),
            Some(&invite_hash(token)),
            db::Groups::default(),
        )
        .await;
        assert!(matches!(again, Err(db::AuthError::NotMember)));

        let stale = invite(&app, &owner_token, None).await;
        sqlx::query(
            "UPDATE invites SET expires_at = now() - interval '1 minute' WHERE id = $1::uuid",
        )
        .bind(stale["id"].as_str().expect("id"))
        .execute(&db.owner)
        .await
        .expect("expire invite");
        let late = db::sign_in(
            &db.runtime,
            &profile("late@tinyserver.test"),
            Some(&invite_hash(stale["token"].as_str().expect("token"))),
            db::Groups::default(),
        )
        .await;
        assert!(matches!(late, Err(db::AuthError::NotMember)));

        // Turned away means nothing written.
        let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
            .fetch_one(&db.owner)
            .await
            .expect("user count");
        assert_eq!(users, 2);
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
