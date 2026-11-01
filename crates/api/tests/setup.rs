//! First-run setup: the owner chooses what the community keeps about its members. Each test
//! names a property and fails when it stops holding.

mod common;

use axum::http::{Method, StatusCode};
use common::{first_owner, invite_hash, join, run, session, Call, TestDb, ISSUER, OWNER_EMAIL};
use serde_json::{json, Value};

fn app(db: &TestDb) -> axum::Router {
    api::router(db.runtime.clone(), None)
}

async fn get_setup(app: &axum::Router, token: &str) -> (StatusCode, Value) {
    Call::new(Method::GET, "/v1/setup")
        .token(token)
        .send(app)
        .await
}

async fn put_setup(app: &axum::Router, token: &str, body: Value) -> (StatusCode, Value) {
    Call::new(Method::PUT, "/v1/setup")
        .token(token)
        .json(body)
        .send(app)
        .await
}

/// A person's account as the owner's roster sees it: `(email, display_name)`.
async fn account(db: &TestDb, user_id: &str) -> (Option<String>, String) {
    sqlx::query_as("SELECT email, display_name FROM users WHERE id = $1::uuid")
        .bind(user_id)
        .fetch_one(&db.owner)
        .await
        .expect("account")
}

/// Signs a new person in through an identity provider with an invite, the way the callback does.
async fn join_with(
    db: &TestDb,
    owner: &db::Caller,
    subject: &str,
    email: Option<&str>,
    name: Option<&str>,
) -> String {
    let issued = match db::create_invite(&db.runtime, owner, "member", None).await {
        Ok(db::Wrote::Fresh(issued)) => issued,
        _ => panic!("invite"),
    };
    let profile = db::Profile {
        issuer: ISSUER.to_string(),
        subject: subject.to_string(),
        email: email.map(str::to_string),
        name: name.map(str::to_string),
        sid: None,
    };
    db::sign_in(
        &db.runtime,
        &profile,
        Some(&invite_hash(&issued.token)),
        db::Groups::default(),
    )
    .await
    .expect("signs in")
    .user_id
}

#[tokio::test]
async fn a_server_that_has_not_been_set_up_says_so_and_offers_what_it_would_do() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let token = session(&db, &owner.user_id).await;
        let app = app(&db);

        let (status, setup) = get_setup(&app, &token).await;
        assert_eq!(status, StatusCode::OK, "{setup}");
        assert_eq!(setup["needed"], true);
        assert_eq!(setup["completed_at"], Value::Null);
        // The defaults are what the server did before there was a setup.
        assert_eq!(
            setup["current"],
            json!({
                "provider_profile": "full",
                "activity_visibility": "everyone",
                "sign_in_methods": "any",
            })
        );
        // No sign-in is configured in this app: no passkeys and no provider.
        assert_eq!(
            setup["deployment"],
            json!({"passkeys": false, "sso": false})
        );
        assert_eq!(setup["counts"]["members"], 1);

        let presets = setup["presets"].as_array().expect("presets");
        let ids: Vec<&str> = presets
            .iter()
            .map(|p| p["id"].as_str().expect("id"))
            .collect();
        assert_eq!(ids, ["convenience", "privacy"]);
        // Privacy asks for passkey sign-in, which this server does not run.
        assert_eq!(presets[0]["available"], true);
        assert_eq!(presets[1]["available"], false);
        assert!(presets[1]["unavailable"].is_string());

        let choices = setup["choices"].as_array().expect("choices");
        let ids: Vec<&str> = choices
            .iter()
            .map(|c| c["id"].as_str().expect("id"))
            .collect();
        assert_eq!(
            ids,
            ["provider_profile", "activity_visibility", "sign_in_methods"]
        );
        for choice in choices {
            assert!(choice["question"]
                .as_str()
                .is_some_and(|text| !text.is_empty()));
            for option in choice["options"].as_array().expect("options") {
                // Every option says what it does, in a sentence.
                assert!(
                    option["effect"]
                        .as_str()
                        .is_some_and(|text| text.len() > 20),
                    "{option}"
                );
            }
        }
        assert!(setup["always"]
            .as_array()
            .expect("always")
            .iter()
            .any(|line| line
                .as_str()
                .is_some_and(|line| line.contains("no usernames"))));

        let (_, capabilities) = Call::new(Method::GET, "/v1/capabilities")
            .token(&token)
            .send(&app)
            .await;
        assert!(capabilities["features"]
            .as_array()
            .expect("features")
            .contains(&json!("first_run_setup")));
    })
    .await;
}

#[tokio::test]
async fn only_an_owner_may_see_or_change_the_choices() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let (_ada, ada_token) = join(&db, &owner, "ada@tinyserver.test", "member").await;
        // An admin holds every permission, and still is not an owner.
        let (_bea, bea_token) = join(&db, &owner, "bea@tinyserver.test", "admin").await;
        let app = app(&db);

        for token in [&ada_token, &bea_token] {
            let (status, body) = get_setup(&app, token).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
            let (status, body) = put_setup(&app, token, json!({"preset": "convenience"})).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        }
        let (status, _) = Call::new(Method::GET, "/v1/setup").send(&app).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = Call::new(Method::PUT, "/v1/setup")
            .json(json!({}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Nothing changed, and nothing was audited.
        let left: i64 =
            sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = 'setup.apply'")
                .fetch_one(&db.owner)
                .await
                .expect("audit");
        assert_eq!(left, 0);
        let done: Option<String> =
            sqlx::query_scalar("SELECT setup_completed_at::text FROM server_settings")
                .fetch_one(&db.owner)
                .await
                .expect("settings");
        assert_eq!(done, None);
    })
    .await;
}

#[tokio::test]
async fn keeping_what_you_have_finishes_setup_and_changes_nothing() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let (_ada, ada_token) = join(&db, &owner, "ada@tinyserver.test", "member").await;
        let app = app(&db);

        let (status, applied) = put_setup(&app, &owner_token, json!({})).await;
        assert_eq!(status, StatusCode::OK, "{applied}");
        assert_eq!(applied["emails_erased"], 0);
        assert_eq!(applied["last_seen_cleared"], 0);
        assert_eq!(applied["settings"]["provider_profile"], "full");
        assert_eq!(applied["settings"]["activity_visibility"], "everyone");
        assert_eq!(applied["settings"]["sign_in_methods"], "any");
        assert!(applied["settings"]["setup_completed_at"].is_string());

        let (_, setup) = get_setup(&app, &owner_token).await;
        assert_eq!(setup["needed"], false);
        assert!(setup["completed_at"].is_string());

        // Every member can read what the community keeps about them, and that it was chosen.
        let (status, server) = Call::new(Method::GET, "/v1/server")
            .token(&ada_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{server}");
        assert_eq!(server["provider_profile"], "full");
        assert_eq!(server["activity_visibility"], "everyone");
        assert_eq!(server["sign_in_methods"], "any");
        assert!(server["setup_completed_at"].is_string());

        // Emails were not touched.
        let (email, _) = account(&db, &owner.user_id).await;
        assert_eq!(email.as_deref(), Some(OWNER_EMAIL));

        // The first completion stays the first one.
        let first = applied["settings"]["setup_completed_at"].clone();
        let (_, again) =
            put_setup(&app, &owner_token, json!({"activity_visibility": "admins"})).await;
        assert_eq!(again["settings"]["setup_completed_at"], first);
        assert_eq!(again["settings"]["activity_visibility"], "admins");
    })
    .await;
}

#[tokio::test]
async fn a_choice_that_is_not_one_of_the_options_is_refused() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let token = session(&db, &owner.user_id).await;
        let app = app(&db);
        for body in [
            json!({"provider_profile": "everything"}),
            json!({"preset": "maximum"}),
            json!({"activity_visibility": 3}),
            json!({"unknown": true}),
        ] {
            let (status, response) = put_setup(&app, &token, body.clone()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {response}");
        }
        let (_, setup) = get_setup(&app, &token).await;
        assert_eq!(setup["needed"], true, "a refused request finished setup");
    })
    .await;
}

#[tokio::test]
async fn the_privacy_preset_is_refused_where_there_are_no_passkeys_unless_that_one_choice_is_left_out(
) {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let token = session(&db, &owner.user_id).await;
        let app = app(&db);

        let (status, body) = put_setup(&app, &token, json!({"preset": "privacy"})).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["error"], "passkeys_unavailable");
        // All or nothing: the refusal left the other two choices as they were.
        let (_, setup) = get_setup(&app, &token).await;
        assert_eq!(setup["current"]["provider_profile"], "full");
        assert_eq!(setup["current"]["activity_visibility"], "everyone");
        assert_eq!(setup["needed"], true);

        let (status, body) = put_setup(
            &app,
            &token,
            json!({"preset": "privacy", "sign_in_methods": "any"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["settings"]["provider_profile"], "none");
        assert_eq!(body["settings"]["activity_visibility"], "nobody");
        assert_eq!(body["settings"]["sign_in_methods"], "any");
    })
    .await;
}

#[tokio::test]
async fn what_a_provider_may_leave_in_a_new_account_is_what_the_owner_chose() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let token = session(&db, &owner.user_id).await;
        let app = app(&db);

        // Full: the name and the email, and the start of the email when there is no name.
        let kept = join_with(
            &db,
            &owner,
            "u1",
            Some("kept@provider.test"),
            Some("Kept Name"),
        )
        .await;
        assert_eq!(
            account(&db, &kept).await,
            (
                Some("kept@provider.test".to_string()),
                "Kept Name".to_string()
            )
        );
        let from_email = join_with(&db, &owner, "u2", Some("moss@provider.test"), None).await;
        assert_eq!(
            account(&db, &from_email).await,
            (Some("moss@provider.test".to_string()), "moss".to_string())
        );

        // Name only: no email, and never the start of one.
        let (status, body) = put_setup(&app, &token, json!({"provider_profile": "name"})).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let named = join_with(&db, &owner, "u3", Some("ada@provider.test"), Some("Ada")).await;
        assert_eq!(account(&db, &named).await, (None, "Ada".to_string()));
        let unnamed = join_with(&db, &owner, "u4", Some("bea@provider.test"), None).await;
        assert_eq!(
            account(&db, &unnamed).await,
            (None, "Member".to_string()),
            "the start of an email address became a name"
        );

        // Nothing: neither.
        let (status, body) = put_setup(&app, &token, json!({"provider_profile": "none"})).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let nothing = join_with(&db, &owner, "u5", Some("cy@provider.test"), Some("Cy")).await;
        assert_eq!(account(&db, &nothing).await, (None, "Member".to_string()));

        // The choice is about new accounts. People already in keep what they have.
        assert_eq!(
            account(&db, &kept).await,
            (
                Some("kept@provider.test".to_string()),
                "Kept Name".to_string()
            )
        );
        // And a person who signs in again is not changed by it.
        let issued = match db::create_invite(&db.runtime, &owner, "member", None).await {
            Ok(db::Wrote::Fresh(issued)) => issued,
            _ => panic!("invite"),
        };
        let again = db::Profile {
            issuer: ISSUER.to_string(),
            subject: "u1".to_string(),
            email: Some("changed@provider.test".to_string()),
            name: Some("Changed".to_string()),
            sid: None,
        };
        db::sign_in(
            &db.runtime,
            &again,
            Some(&invite_hash(&issued.token)),
            db::Groups::default(),
        )
        .await
        .expect("signs in again");
        assert_eq!(
            account(&db, &kept).await,
            (
                Some("kept@provider.test".to_string()),
                "Kept Name".to_string()
            )
        );
    })
    .await;
}

#[tokio::test]
async fn erasing_emails_removes_every_members_address_and_says_how_many() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let token = session(&db, &owner.user_id).await;
        let (ada, _) = join(&db, &owner, "ada@tinyserver.test", "member").await;
        let (bea, _) = join(&db, &owner, "bea@tinyserver.test", "member").await;
        let app = app(&db);

        let (_, setup) = get_setup(&app, &token).await;
        assert_eq!(setup["counts"]["emails_stored"], 3);

        // Choosing to keep no email does not remove the ones already held.
        let (_, body) = put_setup(&app, &token, json!({"provider_profile": "none"})).await;
        assert_eq!(body["emails_erased"], 0);
        assert_eq!(
            account(&db, &ada.user_id).await.0.as_deref(),
            Some("ada@tinyserver.test")
        );

        // Asking does, once.
        let (status, body) = put_setup(&app, &token, json!({"erase_emails": true})).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["emails_erased"], 3);
        for user in [&owner.user_id, &ada.user_id, &bea.user_id] {
            assert_eq!(account(&db, user).await.0, None);
        }
        // The people are still there, with their names and roles.
        let (_, members) = Call::new(Method::GET, "/v1/members")
            .token(&token)
            .send(&app)
            .await;
        assert_eq!(members.as_array().expect("members").len(), 3);
        let (_, again) = put_setup(&app, &token, json!({"erase_emails": true})).await;
        assert_eq!(again["emails_erased"], 0);

        // The audit row records the choices and the count, and no address or name.
        let detail: Value = sqlx::query_scalar(
            "SELECT detail FROM audit_log WHERE action = 'setup.apply'
             ORDER BY created_at, id LIMIT 1 OFFSET 1",
        )
        .fetch_one(&db.owner)
        .await
        .expect("audit");
        assert_eq!(detail["emails_erased"], 3);
        let text = detail.to_string();
        assert!(
            !text.contains("tinyserver.test") && !text.contains("Owner"),
            "{text}"
        );
    })
    .await;
}

async fn members(app: &axum::Router, token: &str) -> Vec<Value> {
    let (status, members) = Call::new(Method::GET, "/v1/members")
        .token(token)
        .send(app)
        .await;
    assert_eq!(status, StatusCode::OK, "{members}");
    members.as_array().expect("members").clone()
}

fn row<'a>(members: &'a [Value], user_id: &str) -> &'a Value {
    members
        .iter()
        .find(|member| member["user_id"] == user_id)
        .expect("member")
}

#[tokio::test]
async fn who_sees_when_a_member_was_last_online_is_the_owners_choice_and_nobody_stops_recording() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let (ada, ada_token) = join(&db, &owner, "ada@tinyserver.test", "member").await;
        let app = app(&db);
        let both = [owner.user_id.clone(), ada.user_id.clone()];
        db::touch_seen(&db.runtime, &both).await.expect("seen");

        // Everyone, as before.
        let seen = members(&app, &ada_token).await;
        assert!(row(&seen, &owner.user_id)["last_seen_at"].is_string());
        assert_eq!(row(&seen, &owner.user_id)["joined_via"], "invite");

        // Admins: a member sees neither, the owner does.
        let (status, body) =
            put_setup(&app, &owner_token, json!({"activity_visibility": "admins"})).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["last_seen_cleared"], 0,
            "admins can still see it, so it is kept"
        );
        let seen = members(&app, &ada_token).await;
        for member in &seen {
            assert_eq!(member["last_seen_at"], Value::Null, "{member}");
            assert_eq!(member["joined_via"], Value::Null, "{member}");
        }
        let seen = members(&app, &owner_token).await;
        assert!(row(&seen, &ada.user_id)["last_seen_at"].is_string());
        assert_eq!(row(&seen, &ada.user_id)["joined_via"], "invite");

        // Nobody: what was recorded is cleared, nothing new is, and no one sees how they joined.
        let (_, body) =
            put_setup(&app, &owner_token, json!({"activity_visibility": "nobody"})).await;
        assert_eq!(body["last_seen_cleared"], 2);
        db::touch_seen(&db.runtime, &both).await.expect("seen");
        let recorded: i64 =
            sqlx::query_scalar("SELECT count(*) FROM memberships WHERE last_seen_at IS NOT NULL")
                .fetch_one(&db.owner)
                .await
                .expect("count");
        assert_eq!(
            recorded, 0,
            "last-seen was recorded after the owner chose nobody"
        );
        for token in [&ada_token, &owner_token] {
            for member in members(&app, token).await {
                assert_eq!(member["last_seen_at"], Value::Null);
                assert_eq!(member["joined_via"], Value::Null);
            }
        }

        // Choosing everyone again starts recording again.
        put_setup(
            &app,
            &owner_token,
            json!({"activity_visibility": "everyone"}),
        )
        .await;
        db::touch_seen(&db.runtime, &both).await.expect("seen");
        let seen = members(&app, &ada_token).await;
        assert!(row(&seen, &ada.user_id)["last_seen_at"].is_string());
    })
    .await;
}

#[tokio::test]
async fn applying_setup_is_audited_and_reaches_every_connected_client() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let token = session(&db, &owner.user_id).await;
        let app = app(&db);
        let (status, _) = put_setup(&app, &token, json!({"activity_visibility": "admins"})).await;
        assert_eq!(status, StatusCode::OK);

        let (_, audit) = Call::new(Method::GET, "/v1/audit")
            .token(&token)
            .send(&app)
            .await;
        let rows = audit.as_array().cloned().expect("audit rows");
        let applied = rows
            .iter()
            .find(|row| row["action"] == "setup.apply")
            .expect("setup.apply in the audit log");
        assert_eq!(applied["detail"]["activity_visibility"], "admins");
        assert_eq!(applied["actor_id"], owner.user_id.as_str());

        let event: Value = sqlx::query_scalar(
            "SELECT payload FROM outbox WHERE topic = 'server.updated' ORDER BY id DESC LIMIT 1",
        )
        .fetch_one(&db.owner)
        .await
        .expect("event");
        assert_eq!(event["server"]["activity_visibility"], "admins");
    })
    .await;
}
