//! Sign-in through OpenID Connect, against a real Postgres and the fake provider in
//! `common/oidc.rs`. See `common` for the environment.

mod common;

use std::collections::HashMap;

use axum::body::Body;
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use axum::Router;
use common::oidc::{self, ClientAuth, Person, Provider, Tamper, CLIENT_ID, CLIENT_KEY};
use common::{first_owner, run, Call, TestDb};
use http_body_util::BodyExt;
use openidconnect::{CsrfToken, PkceCodeChallenge};
use serde_json::{json, Value};
use tower::ServiceExt;

const REDIRECT: &str = "http://127.0.0.1:53121/callback";

/// tinyclient's side: its PKCE pair and state, made fresh for each sign-in.
struct Client {
    verifier: String,
    challenge: String,
    state: String,
}

impl Client {
    fn new() -> Self {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        Self {
            verifier: verifier.secret().clone(),
            challenge: challenge.as_str().to_string(),
            state: CsrfToken::new_random_len(24).secret().clone(),
        }
    }

    fn body(&self, extra: Value) -> Value {
        let mut body = json!({
            "redirect_uri": REDIRECT,
            "code_challenge": self.challenge,
            "code_challenge_method": "S256",
            "state": self.state,
        });
        if let (Some(body), Some(extra)) = (body.as_object_mut(), extra.as_object()) {
            for (name, value) in extra {
                body.insert(name.clone(), value.clone());
            }
        }
        body
    }
}

async fn start(app: &Router, client: &Client, extra: Value) -> String {
    let (status, body) = Call::new(Method::POST, "/v1/auth/start")
        .json(client.body(extra))
        .send(app)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["authorize_url"]
        .as_str()
        .expect("authorize_url")
        .to_string()
}

async fn get(app: &Router, uri: &str) -> (StatusCode, HeaderMap, String) {
    let response = app
        .clone()
        .oneshot(Request::get(uri).body(Body::empty()).expect("request"))
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
    (
        status,
        headers,
        String::from_utf8(bytes.to_vec()).expect("utf-8"),
    )
}

async fn callback(app: &Router, code: &str, state: &str) -> (StatusCode, HeaderMap, String) {
    get(app, &format!("/v1/auth/callback?code={code}&state={state}")).await
}

/// The query tinyserver sent the browser back to tinyclient with.
fn back_at_client(status: StatusCode, headers: &HeaderMap) -> HashMap<String, String> {
    assert_eq!(status, StatusCode::FOUND);
    let location = headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("location");
    let url = url::Url::parse(location).expect("location url");
    assert_eq!(
        format!("{}://{}{}", url.scheme(), url.authority(), url.path()),
        REDIRECT
    );
    url.query_pairs().into_owned().collect()
}

/// Start, the provider's page, and the callback. Returns what tinyclient's listener got.
async fn through_provider(
    app: &Router,
    provider: &Provider,
    client: &Client,
    extra: Value,
    person: Person,
    tamper: Tamper,
) -> HashMap<String, String> {
    let authorize_url = start(app, client, extra).await;
    let (code, state) = provider.authorize(&authorize_url, person, tamper);
    let (status, headers, _) = callback(app, &code, &state).await;
    let back = back_at_client(status, &headers);
    assert_eq!(back["state"], client.state);
    back
}

async fn token(app: &Router, code: &str, verifier: &str) -> (StatusCode, Value) {
    Call::new(Method::POST, "/v1/auth/token")
        .json(json!({"code": code, "code_verifier": verifier}))
        .send(app)
        .await
}

/// The whole sign-in, expecting a session. Returns the token response.
async fn sign_in(app: &Router, provider: &Provider, extra: Value, person: Person) -> Value {
    let client = Client::new();
    let back = through_provider(app, provider, &client, extra, person, Tamper::default()).await;
    let code = back
        .get("code")
        .unwrap_or_else(|| panic!("no code: {back:?}"));
    let (status, body) = token(app, code, &client.verifier).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

async fn invite(db: &TestDb, owner: &db::Caller, role: &str) -> String {
    let Ok(db::Wrote::Fresh(issued)) = db::create_invite(&db.runtime, owner, role, None).await
    else {
        panic!("invite");
    };
    issued.token
}

async fn users(db: &TestDb) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&db.owner)
        .await
        .expect("users")
}

async fn me(app: &Router, token: &str) -> (StatusCode, Value) {
    Call::new(Method::GET, "/v1/me")
        .token(token)
        .send(app)
        .await
}

#[tokio::test]
async fn the_config_names_the_providers() {
    run(|db| async move {
        let first = Provider::start().await;
        let second = Provider::start().await;
        let mut other = second.provider_config("work");
        other.name = Some("Work".to_string());
        let sign_in =
            api::SignIn::discover(oidc::config(vec![first.provider_config("default"), other]))
                .await
                .expect("discover");
        let app = api::router(db.runtime.clone(), Some(sign_in));
        let (status, body) = Call::new(Method::GET, "/v1/auth/config").send(&app).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            json!({
                "methods": ["oidc"],
                "provider_name": oidc::PROVIDER_NAME,
                "providers": [
                    {"id": "default", "name": oidc::PROVIDER_NAME},
                    {"id": "work", "name": "Work"},
                ],
            })
        );

        // Without sign-in configured there is no /v1/auth.
        let bare = api::router(db.runtime.clone(), None);
        let (status, _) = Call::new(Method::GET, "/v1/auth/config").send(&bare).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    })
    .await;
}

#[tokio::test]
async fn an_invite_lets_a_person_in_and_they_come_back_without_it() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let provider = Provider::start().await;
        let app = api::router(db.runtime.clone(), Some(provider.sign_in().await));
        let invite = invite(&db, &owner, "member").await;

        let client = Client::new();
        let back = through_provider(
            &app,
            &provider,
            &client,
            json!({"invite": invite}),
            Person::new("moss"),
            Tamper::default(),
        )
        .await;
        assert_eq!(back.len(), 2, "{back:?}");
        assert_eq!(provider.client_auth(), Some(ClientAuth::Basic));
        let (status, body) = token(&app, &back["code"], &client.verifier).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let keys: Vec<&String> = body.as_object().expect("object").keys().collect();
        assert_eq!(keys, ["display_name", "email", "role", "token", "user_id"]);
        assert_eq!(body["role"], "member");
        assert_eq!(body["email"], "moss@provider.test");
        assert_eq!(body["display_name"], "Person moss");
        let user_id = body["user_id"].as_str().expect("user id").to_string();
        let (status, me_body) = me(&app, body["token"].as_str().expect("token")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(me_body["user_id"], user_id);

        let identity: (String, String) =
            sqlx::query_as("SELECT issuer, subject FROM user_identities WHERE user_id = $1::uuid")
                .bind(&user_id)
                .fetch_one(&db.owner)
                .await
                .expect("identity");
        assert_eq!(identity, (provider.issuer.clone(), "moss".to_string()));
        let audit = db::list_audit(&db.runtime, &owner, &db::AuditQuery::latest(20))
            .await
            .expect("audit");
        assert!(audit.iter().any(|row| row.action == "invite.accept"
            && row.actor_id.as_deref() == Some(user_id.as_str())));

        // Again, with no invite: a member signs in. A spent invite changes nothing.
        let again = sign_in(
            &app,
            &provider,
            json!({"invite": invite}),
            Person::new("moss"),
        )
        .await;
        assert_eq!(again["user_id"], user_id);
        assert_eq!(users(&db).await, 2);

        // A person with no email has none.
        let invite = self::invite(&db, &owner, "admin").await;
        let mut quiet = Person::new("quiet");
        quiet.email = None;
        quiet.name = None;
        let body = sign_in(&app, &provider, json!({"invite": invite}), quiet).await;
        assert_eq!(body["email"], Value::Null);
        assert_eq!(body["display_name"], "Member");
        assert_eq!(body["role"], "admin");
        let members = db::list_members(&db.runtime, &owner)
            .await
            .expect("members");
        assert!(members
            .iter()
            .any(|member| member.email.is_none() && member.role == "admin"));
    })
    .await;
}

#[tokio::test]
async fn the_owner_invite_from_bootstrap_makes_the_first_owner() {
    run(|db| async move {
        let provider = Provider::start().await;
        let app = api::router(db.runtime.clone(), Some(provider.sign_in().await));
        let first = db::owner_invite(&db.owner, false)
            .await
            .expect("owner invite")
            .expect("no owner yet");
        // A second run before anyone used it replaces it.
        let issued = db::owner_invite(&db.owner, false)
            .await
            .expect("owner invite")
            .expect("still no owner");
        assert_eq!(issued.role, "owner");

        let client = Client::new();
        let back = through_provider(
            &app,
            &provider,
            &client,
            json!({"invite": first.token}),
            Person::new("first"),
            Tamper::default(),
        )
        .await;
        assert_eq!(back["error"], "not_member", "the replaced invite is gone");

        let body = sign_in(
            &app,
            &provider,
            json!({"invite": issued.token}),
            Person::new("first"),
        )
        .await;
        assert_eq!(body["role"], "owner");
        assert!(db::owner_invite(&db.owner, false)
            .await
            .expect("owner invite")
            .is_none());
        let forced = db::owner_invite(&db.owner, true)
            .await
            .expect("owner invite")
            .expect("forced");
        assert_eq!(forced.role, "owner");
        let actions: Vec<String> =
            sqlx::query_scalar("SELECT action FROM audit_log WHERE actor_id IS NULL ORDER BY id")
                .fetch_all(&db.owner)
                .await
                .expect("audit");
        assert_eq!(
            actions,
            ["bootstrap", "invite.revoke", "bootstrap", "bootstrap"]
        );
    })
    .await;
}

#[tokio::test]
async fn someone_without_an_invite_is_not_a_member_and_nothing_is_kept() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let provider = Provider::start().await;
        let app = api::router(db.runtime.clone(), Some(provider.sign_in().await));
        let before = users(&db).await;

        for extra in [json!({}), json!({"invite": "not-an-invite"})] {
            let client = Client::new();
            let back = through_provider(
                &app,
                &provider,
                &client,
                extra,
                Person::new("stranger"),
                Tamper::default(),
            )
            .await;
            assert_eq!(back.get("error").map(String::as_str), Some("not_member"));
            assert!(!back.contains_key("code"));
        }

        // The owner's email at this provider is someone else. Email never links.
        let mut lookalike = Person::new("lookalike");
        lookalike.email = Some(common::OWNER_EMAIL.to_string());
        let back = through_provider(
            &app,
            &provider,
            &Client::new(),
            json!({}),
            lookalike,
            Tamper::default(),
        )
        .await;
        assert_eq!(back["error"], "not_member");
        assert_eq!(users(&db).await, before);
        let _ = owner;
    })
    .await;
}

#[tokio::test]
async fn an_expired_spent_or_unknown_state_gets_a_page_and_no_redirect() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let provider = Provider::start().await;
        let app = api::router(db.runtime.clone(), Some(provider.sign_in().await));
        let invite = invite(&db, &owner, "member").await;

        let expired = |status: StatusCode, headers: &HeaderMap, body: &str| {
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(headers.get(header::LOCATION).is_none());
            assert_eq!(headers[header::CONTENT_TYPE], "text/html; charset=utf-8");
            assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
            assert_eq!(headers[header::CACHE_CONTROL], "no-store");
            assert_eq!(headers["referrer-policy"], "no-referrer");
            assert!(headers[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .expect("csp")
                .starts_with("default-src 'none'"));
            assert!(body.contains("This sign-in expired. Start again from tinyclient."));
        };

        let client = Client::new();
        let authorize_url = start(&app, &client, json!({"invite": invite})).await;
        let (code, state) =
            provider.authorize(&authorize_url, Person::new("late"), Tamper::default());
        sqlx::query("UPDATE auth_pending SET expires_at = now() - interval '1 second'")
            .execute(&db.owner)
            .await
            .expect("expire");
        let (status, headers, body) = callback(&app, &code, &state).await;
        expired(status, &headers, &body);
        assert_eq!(
            provider.token_requests(),
            0,
            "no exchange for an expired state"
        );

        let client = Client::new();
        let authorize_url = start(&app, &client, json!({"invite": invite})).await;
        let (code, state) =
            provider.authorize(&authorize_url, Person::new("twice"), Tamper::default());
        let (status, headers, _) = callback(&app, &code, &state).await;
        assert!(back_at_client(status, &headers).contains_key("code"));
        let (status, headers, body) = callback(&app, &code, &state).await;
        expired(status, &headers, &body);

        let (status, headers, body) = callback(&app, "x", "never-issued-state").await;
        expired(status, &headers, &body);
        let (status, headers, body) = get(&app, "/v1/auth/callback").await;
        expired(status, &headers, &body);
    })
    .await;
}

#[tokio::test]
async fn a_one_time_code_works_once_with_the_right_verifier_inside_a_minute() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let provider = Provider::start().await;
        let app = api::router(db.runtime.clone(), Some(provider.sign_in().await));
        let invite = invite(&db, &owner, "member").await;
        let invalid = json!({"error": "invalid_grant"});

        let client = Client::new();
        let back = through_provider(
            &app,
            &provider,
            &client,
            json!({"invite": invite}),
            Person::new("once"),
            Tamper::default(),
        )
        .await;
        let wrong = Client::new();
        let (status, body) = token(&app, &back["code"], &wrong.verifier).await;
        assert_eq!((status, body), (StatusCode::BAD_REQUEST, invalid.clone()));
        // The wrong verifier spent it.
        let (status, body) = token(&app, &back["code"], &client.verifier).await;
        assert_eq!((status, body), (StatusCode::BAD_REQUEST, invalid.clone()));

        let client = Client::new();
        let back = through_provider(
            &app,
            &provider,
            &client,
            json!({}),
            Person::new("once"),
            Tamper::default(),
        )
        .await;
        let (status, _) = token(&app, &back["code"], &client.verifier).await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = token(&app, &back["code"], &client.verifier).await;
        assert_eq!(
            (status, body),
            (StatusCode::BAD_REQUEST, invalid.clone()),
            "replayed"
        );

        let client = Client::new();
        let back = through_provider(
            &app,
            &provider,
            &client,
            json!({}),
            Person::new("once"),
            Tamper::default(),
        )
        .await;
        sqlx::query("UPDATE auth_codes SET expires_at = now() - interval '1 second'")
            .execute(&db.owner)
            .await
            .expect("expire");
        let (status, body) = token(&app, &back["code"], &client.verifier).await;
        assert_eq!(
            (status, body),
            (StatusCode::BAD_REQUEST, invalid.clone()),
            "expired"
        );

        for body in [
            json!({}),
            json!({"code": "x"}),
            json!({"code": "x", "code_verifier": "short"}),
        ] {
            let (status, reply) = Call::new(Method::POST, "/v1/auth/token")
                .json(body)
                .send(&app)
                .await;
            assert_eq!((status, reply), (StatusCode::BAD_REQUEST, invalid.clone()));
        }
        let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions")
            .fetch_one(&db.owner)
            .await
            .expect("sessions");
        assert_eq!(sessions, 1);
    })
    .await;
}

#[tokio::test]
async fn a_bad_id_token_or_provider_error_fails_the_sign_in() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let provider = Provider::start().await;
        let app = api::router(db.runtime.clone(), Some(provider.sign_in().await));
        let invite = invite(&db, &owner, "member").await;
        let before = users(&db).await;

        let tampers = [
            (
                "wrong nonce",
                Tamper {
                    nonce: Some("another-nonce".into()),
                    ..Tamper::default()
                },
            ),
            (
                "wrong issuer",
                Tamper {
                    issuer: Some("http://127.0.0.1:1".into()),
                    ..Tamper::default()
                },
            ),
            (
                "wrong audience",
                Tamper {
                    audiences: Some(vec!["someone-else".into()]),
                    ..Tamper::default()
                },
            ),
            (
                "untrusted extra audience",
                Tamper {
                    audiences: Some(vec![CLIENT_ID.into(), "someone-else".into()]),
                    ..Tamper::default()
                },
            ),
            (
                "azp of another client",
                Tamper {
                    authorized_party: Some("someone-else".into()),
                    ..Tamper::default()
                },
            ),
            (
                "alg none",
                Tamper {
                    unsigned: true,
                    ..Tamper::default()
                },
            ),
            (
                "expired",
                Tamper {
                    expired: true,
                    ..Tamper::default()
                },
            ),
            (
                "a key not in the set",
                Tamper {
                    unpublished_key: true,
                    ..Tamper::default()
                },
            ),
        ];
        for (what, tamper) in tampers {
            let back = through_provider(
                &app,
                &provider,
                &Client::new(),
                json!({"invite": invite}),
                Person::new("victim"),
                tamper,
            )
            .await;
            assert_eq!(
                back.get("error").map(String::as_str),
                Some("failed"),
                "{what}"
            );
            assert!(!back.contains_key("code"), "{what}");
        }
        assert_eq!(
            users(&db).await,
            before,
            "nothing kept, and the invite is unused"
        );

        // The person said no at the provider.
        let client = Client::new();
        let authorize_url = start(&app, &client, json!({})).await;
        let (_, state) = provider.authorize(&authorize_url, Person::new("no"), Tamper::default());
        let (status, headers, _) = get(
            &app,
            &format!("/v1/auth/callback?error=access_denied&state={state}"),
        )
        .await;
        let back = back_at_client(status, &headers);
        assert_eq!(back["error"], "denied");
        assert_eq!(back["state"], client.state);

        // RFC 9207: a callback naming another issuer is a mix-up.
        let client = Client::new();
        let authorize_url = start(&app, &client, json!({"invite": invite})).await;
        let (code, state) =
            provider.authorize(&authorize_url, Person::new("mixed"), Tamper::default());
        let (status, headers, _) = get(
            &app,
            &format!("/v1/auth/callback?code={code}&state={state}&iss=https%3A%2F%2Fevil.test"),
        )
        .await;
        assert_eq!(back_at_client(status, &headers)["error"], "failed");

        // The invite still works for the right person.
        let body = sign_in(
            &app,
            &provider,
            json!({"invite": invite}),
            Person::new("victim"),
        )
        .await;
        assert_eq!(body["role"], "member");
    })
    .await;
}

#[tokio::test]
async fn a_new_signing_key_is_read_once_when_a_token_names_it() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let provider = Provider::start().await;
        let app = api::router(db.runtime.clone(), Some(provider.sign_in().await));
        assert_eq!(provider.jwks_reads(), 1);
        let invite = invite(&db, &owner, "member").await;

        provider.rotate();
        sign_in(
            &app,
            &provider,
            json!({"invite": invite}),
            Person::new("rotated"),
        )
        .await;
        assert_eq!(provider.jwks_reads(), 2);
        sign_in(&app, &provider, json!({}), Person::new("rotated")).await;
        assert_eq!(provider.jwks_reads(), 2, "the new key is kept");
    })
    .await;
}

#[tokio::test]
async fn start_takes_only_a_loopback_callback_and_s256() {
    run(|db| async move {
        let provider = Provider::start().await;
        let app = api::router(db.runtime.clone(), Some(provider.sign_in().await));
        let client = Client::new();
        let bad = json!({"error": "bad_request"});
        for extra in [
            json!({"redirect_uri": "http://example.org:53121/callback"}),
            json!({"redirect_uri": "http://localhost:53121/callback"}),
            json!({"redirect_uri": "https://127.0.0.1:53121/callback"}),
            json!({"redirect_uri": "http://127.0.0.1:53121/other"}),
            json!({"redirect_uri": "http://127.0.0.1/callback"}),
            json!({"redirect_uri": "tinyclient://callback"}),
            json!({"code_challenge_method": "plain"}),
            json!({"code_challenge": "too-short"}),
            json!({"state": "short"}),
            json!({"state": "has spaces in it, which is no good"}),
            json!({"invite": "bad invite!"}),
            json!({"provider": "nobody"}),
        ] {
            let (status, body) = Call::new(Method::POST, "/v1/auth/start")
                .json(client.body(extra.clone()))
                .send(&app)
                .await;
            assert_eq!(
                (status, body),
                (StatusCode::BAD_REQUEST, bad.clone()),
                "{extra}"
            );
        }
        let (status, body) = Call::new(Method::POST, "/v1/auth/start")
            .json(json!({"redirect_uri": REDIRECT}))
            .send(&app)
            .await;
        assert_eq!((status, body), (StatusCode::BAD_REQUEST, bad));

        let ipv6 = start(
            &app,
            &client,
            json!({"redirect_uri": "http://[::1]:40000/callback"}),
        )
        .await;
        assert!(ipv6.starts_with(&provider.issuer));
        let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_pending")
            .fetch_one(&db.owner)
            .await
            .expect("pending");
        assert_eq!(pending, 1);
    })
    .await;
}

#[tokio::test]
async fn two_providers_make_two_identities_for_one_subject() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let home = Provider::start().await;
        let work = Provider::start().await;
        let sign_in = api::SignIn::discover(oidc::config(vec![
            home.provider_config("home"),
            work.provider_config("work"),
        ]))
        .await
        .expect("discover");
        let app = api::router(db.runtime.clone(), Some(sign_in));

        let at_home = sign_in_with(
            &app,
            &home,
            json!({"invite": invite(&db, &owner, "member").await}),
        )
        .await;
        let at_work = sign_in_with(
            &app,
            &work,
            json!({"provider": "work", "invite": invite(&db, &owner, "member").await}),
        )
        .await;
        assert_ne!(at_home["user_id"], at_work["user_id"]);
        let again = sign_in_with(&app, &home, json!({"provider": "home"})).await;
        assert_eq!(again["user_id"], at_home["user_id"]);

        // A provider's code is never taken by the other: the state says where it went.
        let client = Client::new();
        let authorize_url = start(&app, &client, json!({"provider": "work"})).await;
        assert!(authorize_url.starts_with(&work.issuer));
    })
    .await;
}

async fn sign_in_with(app: &Router, provider: &Provider, extra: Value) -> Value {
    sign_in(app, provider, extra, Person::new("same-subject")).await
}

#[tokio::test]
async fn groups_let_people_join_and_make_admins_but_never_owners() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let provider = Provider::start().await;
        let mut config = provider.provider_config("default");
        config.member_groups = vec!["chat".into()];
        config.admin_groups = vec!["staff".into()];
        let sign_in = api::SignIn::discover(oidc::config(vec![config]))
            .await
            .expect("discover");
        let app = api::router(db.runtime.clone(), Some(sign_in));

        let member = sign_in_as(&app, &provider, Person::new("chatter").groups(&["chat"])).await;
        assert_eq!(member["role"], "member");
        let admin = sign_in_as(&app, &provider, Person::new("boss").groups(&["staff"])).await;
        assert_eq!(admin["role"], "admin");
        let back = through_provider(
            &app,
            &provider,
            &Client::new(),
            json!({}),
            Person::new("outsider").groups(&["other"]),
            Tamper::default(),
        )
        .await;
        assert_eq!(back["error"], "not_member");

        // A member who joins the admin group is lifted when they next sign in.
        let lifted = sign_in_as(&app, &provider, Person::new("chatter").groups(&["chat", "staff"])).await;
        assert_eq!(lifted["user_id"], member["user_id"]);
        assert_eq!(lifted["role"], "admin");

        let joins: Vec<Value> = sqlx::query_scalar(
            "SELECT detail FROM audit_log WHERE action = 'member.join' ORDER BY id",
        )
        .fetch_all(&db.owner)
        .await
        .expect("audit");
        assert_eq!(joins.len(), 2);
        assert!(joins.iter().all(|detail| detail["via"] == "groups"));
        let lifts: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_log WHERE action = 'member.role' AND detail->>'via' = 'groups'",
        )
        .fetch_one(&db.owner)
        .await
        .expect("audit");
        assert_eq!(lifts, 1);

        // The owner in the admin group stays owner; no claim makes or unmakes one.
        let kept = db::sign_in(
            &db.runtime,
            &common::profile(common::OWNER_EMAIL),
            None,
            db::Groups { join: Some("admin"), admin: true },
        )
        .await
        .expect("owner signs in");
        assert_eq!(kept.role, "owner");
        assert_eq!(kept.user_id, owner.user_id);
        let owners: i64 =
            sqlx::query_scalar("SELECT count(*) FROM memberships WHERE owner")
                .fetch_one(&db.owner)
                .await
                .expect("owners");
        assert_eq!(owners, 1);
        let error = sqlx::query("SELECT app_join_by_groups(gen_random_uuid(), 'owner', 'x')")
            .execute(&db.runtime)
            .await
            .expect_err("owner is not a groups role");
        assert_eq!(common::sqlstate(&error), "22023");
    })
    .await;
}

async fn sign_in_as(app: &Router, provider: &Provider, person: Person) -> Value {
    sign_in(app, provider, json!({}), person).await
}

#[tokio::test]
async fn admin_groups_alone_do_not_open_the_door() {
    run(|db| async move {
        first_owner(&db).await;
        let provider = Provider::start().await;
        let mut config = provider.provider_config("default");
        config.admin_groups = vec!["staff".into()];
        let sign_in = api::SignIn::discover(oidc::config(vec![config]))
            .await
            .expect("discover");
        let app = api::router(db.runtime.clone(), Some(sign_in));
        let back = through_provider(
            &app,
            &provider,
            &Client::new(),
            json!({}),
            Person::new("boss").groups(&["staff"]),
            Tamper::default(),
        )
        .await;
        assert_eq!(back["error"], "not_member");
    })
    .await;
}

#[tokio::test]
async fn back_channel_logout_ends_the_sessions_the_provider_names() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let provider = Provider::start().await;
        let app = api::router(db.runtime.clone(), Some(provider.sign_in().await));
        let invite = invite(&db, &owner, "member").await;

        let first = sign_in(&app, &provider, json!({"invite": invite}), Person::new("moss").sid("sid-1")).await;
        let second = sign_in(&app, &provider, json!({}), Person::new("moss").sid("sid-2")).await;
        let first_token = first["token"].as_str().expect("token").to_string();
        let second_token = second["token"].as_str().expect("token").to_string();
        let owner_token = common::session(&db, &owner.user_id).await;

        let logout = |token: String| {
            let app = app.clone();
            async move {
                let body = format!("logout_token={token}");
                let response = app
                    .oneshot(
                        Request::post("/v1/auth/backchannel-logout")
                            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                            .body(Body::from(body))
                            .expect("request"),
                    )
                    .await
                    .expect("response");
                let status = response.status();
                let cache = response.headers().get(header::CACHE_CONTROL).cloned();
                let bytes = response.into_body().collect().await.expect("body").to_bytes();
                assert_eq!(cache.as_ref().map(|value| value.as_bytes()), Some(&b"no-store"[..]));
                (status, String::from_utf8(bytes.to_vec()).expect("utf-8"))
            }
        };

        let refused = r#"{"error":"invalid_request"}"#.to_string();
        let bad_tokens = [
            ("no event", provider.logout_token(json!({"sid": "sid-1", "events": null}))),
            ("wrong event", provider.logout_token(json!({"sid": "sid-1", "events": {"x": {}}}))),
            ("a nonce", provider.logout_token(json!({"sid": "sid-1", "nonce": "n"}))),
            ("another audience", provider.logout_token(json!({"sid": "sid-1", "aud": "else"}))),
            ("another issuer", provider.logout_token(json!({"sid": "sid-1", "iss": "https://evil.test"}))),
            ("old", provider.logout_token(json!({"sid": "sid-1", "iat": 1_000_000}))),
            ("expired", provider.logout_token(json!({"sid": "sid-1", "exp": 1_000_000}))),
            ("no jti", provider.logout_token(json!({"sid": "sid-1", "jti": null}))),
            ("no sub or sid", provider.logout_token(json!({}))),
            (
                "unsigned",
                {
                    let token = provider.logout_token(json!({"sid": "sid-1"}));
                    let mut parts: Vec<&str> = token.split('.').collect();
                    parts[2] = "";
                    parts.join(".")
                },
            ),
            (
                "alg none",
                {
                    use base64::Engine;
                    let token = provider.logout_token(json!({"sid": "sid-1"}));
                    let payload = token.split('.').nth(1).expect("payload").to_string();
                    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(br#"{"alg":"none"}"#);
                    format!("{header}.{payload}.")
                },
            ),
            (
                "a forged signature",
                oidc::sign_jwt(
                    &json!({"alg": "RS256", "kid": "a"}),
                    &json!({
                        "iss": provider.issuer, "aud": CLIENT_ID, "iat": chrono::Utc::now().timestamp(),
                        "jti": "j", "sid": "sid-1",
                        "events": {oidc::LOGOUT_EVENT: {}},
                    }),
                    "b",
                ),
            ),
            ("not a JWT", "garbage".to_string()),
        ];
        for (what, token) in bad_tokens {
            let (status, body) = logout(token).await;
            assert_eq!((status, body), (StatusCode::BAD_REQUEST, refused.clone()), "{what}");
        }
        assert_eq!(me(&app, &first_token).await.0, StatusCode::OK);

        let (status, body) = logout(provider.logout_token(json!({"sid": "sid-1"}))).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, ""));
        assert_eq!(me(&app, &first_token).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(me(&app, &second_token).await.0, StatusCode::OK, "another provider session");

        let (status, _) = logout(provider.logout_token(json!({"sub": "moss"}))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(me(&app, &second_token).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(me(&app, &owner_token).await.0, StatusCode::OK, "sessions from elsewhere stay");

        // Someone the server never saw: nothing to end, still 200.
        let (status, _) = logout(provider.logout_token(json!({"sub": "nobody", "sid": "s"}))).await;
        assert_eq!(status, StatusCode::OK);
        let logouts: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_log WHERE action = 'session.logout' AND detail->>'via' = 'backchannel'",
        )
        .fetch_one(&db.owner)
        .await
        .expect("audit");
        assert_eq!(logouts, 2);
    })
    .await;
}

#[tokio::test]
async fn the_client_authenticates_the_way_the_provider_offers() {
    run(|db| async move {
        let owner = first_owner(&db).await;

        let post_only = Provider::start_with_methods(&["client_secret_post"]).await;
        let app = api::router(db.runtime.clone(), Some(post_only.sign_in().await));
        sign_in(
            &app,
            &post_only,
            json!({"invite": invite(&db, &owner, "member").await}),
            Person::new("p"),
        )
        .await;
        assert_eq!(post_only.client_auth(), Some(ClientAuth::Post));

        let jwt_only = Provider::start_with_methods(&["private_key_jwt"]).await;
        let mut config = jwt_only.provider_config("default");
        // A secret alone is no use to it.
        assert!(api::SignIn::discover(oidc::config(vec![config.clone()]))
            .await
            .is_err());
        config.client_secret = None;
        config.private_key_pem = Some(CLIENT_KEY.to_string());
        config.private_key_id = Some("tinyserver-1".to_string());
        let sign_in_config = api::SignIn::discover(oidc::config(vec![config]))
            .await
            .expect("discover");
        let app = api::router(db.runtime.clone(), Some(sign_in_config));
        sign_in(
            &app,
            &jwt_only,
            json!({"invite": invite(&db, &owner, "member").await}),
            Person::new("k"),
        )
        .await;
        let Some(ClientAuth::PrivateKeyJwt(claims)) = jwt_only.client_auth() else {
            panic!("expected private_key_jwt, got {:?}", jwt_only.client_auth());
        };
        assert_eq!(claims["iss"], CLIENT_ID);
        assert_eq!(claims["sub"], CLIENT_ID);
        assert_eq!(claims["aud"], format!("{}/token", jwt_only.issuer));
        let lifetime = claims["exp"].as_i64().expect("exp") - claims["iat"].as_i64().expect("iat");
        assert!((1..=300).contains(&lifetime), "{lifetime}");
    })
    .await;
}

#[tokio::test]
async fn an_internal_url_carries_server_calls_while_the_issuer_stays_public() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let public = "https://auth.tinyserver.test";
        let provider = Provider::start_public(public).await;
        let config = provider.provider_config("default");
        assert_eq!(
            config.internal_url.as_deref(),
            Some(provider.address.as_str())
        );
        let inside = api::SignIn::discover(oidc::config(vec![config.clone()]))
            .await
            .expect("discover through the internal URL");
        assert_eq!(provider.discovery_reads(), 1);
        let app = api::router(db.runtime.clone(), Some(inside));

        // The browser goes to the public issuer; the exchange and keys go inside.
        let body = sign_in(
            &app,
            &provider,
            json!({"invite": invite(&db, &owner, "member").await}),
            Person::new("inside"),
        )
        .await;
        assert_eq!(body["role"], "member");
        assert_eq!(provider.token_requests(), 1);
        let issuer: String =
            sqlx::query_scalar("SELECT issuer FROM user_identities WHERE user_id = $1::uuid")
                .bind(body["user_id"].as_str().expect("user id"))
                .fetch_one(&db.owner)
                .await
                .expect("identity");
        assert_eq!(issuer, public);

        // A token with the internal address as issuer is not the provider.
        let back = through_provider(
            &app,
            &provider,
            &Client::new(),
            json!({}),
            Person::new("inside"),
            Tamper {
                issuer: Some(provider.address.clone()),
                ..Tamper::default()
            },
        )
        .await;
        assert_eq!(back["error"], "failed");

        // The configured issuer must be what discovery says, exactly.
        let mut wrong = config;
        wrong.issuer = format!("{public}/");
        let error = api::SignIn::discover(oidc::config(vec![wrong]))
            .await
            .err()
            .expect("issuer mismatch");
        assert!(!error.transient);
    })
    .await;
}

#[tokio::test]
async fn discovery_needs_the_exact_issuer_and_a_reachable_provider() {
    run(|_db| async move {
        let provider = Provider::start().await;
        let mut config = provider.provider_config("default");
        config.issuer = format!("{}/", provider.issuer);
        let error = api::SignIn::discover(oidc::config(vec![config]))
            .await
            .err()
            .expect("trailing slash is another issuer");
        assert!(!error.transient, "{error}");

        let mut config = provider.provider_config("default");
        config.issuer = "http://127.0.0.1:1".to_string();
        let error = api::SignIn::discover(oidc::config(vec![config]))
            .await
            .err()
            .expect("unreachable");
        assert!(error.transient, "{error}");

        let error = api::SignIn::discover(oidc::config(vec![
            provider.provider_config("same"),
            provider.provider_config("same"),
        ]))
        .await
        .err()
        .expect("duplicate");
        assert!(!error.transient);
    })
    .await;
}

#[tokio::test]
async fn a_session_from_sign_in_ends_after_the_configured_days() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let provider = Provider::start().await;
        let mut config = provider.config();
        config.session_days = 2;
        let sign_in = api::SignIn::discover(config).await.expect("discover");
        let app = api::router(db.runtime.clone(), Some(sign_in));
        let body = self::sign_in(
            &app,
            &provider,
            json!({"invite": invite(&db, &owner, "member").await}),
            Person::new("short").sid("sid-short"),
        )
        .await;
        let (days, issuer, sid): (f64, Option<String>, Option<String>) = sqlx::query_as(
            "SELECT extract(epoch FROM expires_at - now())::float8 / 86400, issuer, sid
             FROM sessions WHERE user_id = $1::uuid",
        )
        .bind(body["user_id"].as_str().expect("user id"))
        .fetch_one(&db.owner)
        .await
        .expect("session");
        assert!((1.99..=2.0).contains(&days), "{days}");
        assert_eq!(issuer.as_deref(), Some(provider.issuer.as_str()));
        assert_eq!(sid.as_deref(), Some("sid-short"));
    })
    .await;
}
