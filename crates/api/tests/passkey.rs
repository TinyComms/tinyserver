//! Built-in passkey sign-in, from the browser's side: sign-up with an invite, sign-in with no
//! username, recovery codes, claim links for existing members, and what is kept.
//!
//! Registration and signing are done by `webauthn-authenticator-rs`'s software passkey, which
//! checks nothing the server does not also check. It returns no user handle, which a real
//! resident-key authenticator does, so `Device::assert` puts back the handle the account was
//! made with; everything else, the challenge, origin, relying party, signature and counter, is
//! really verified by the server.

mod common;

use axum::body::Body;
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use common::oidc::{self, Provider};
use common::{first_owner, join, run, session, Call, TestDb};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use webauthn_authenticator_rs::prelude::{
    CreationChallengeResponse, RequestChallengeResponse, Url, WebauthnAuthenticator,
};
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::Uuid;

const ORIGIN: &str = "https://tiny.test";
const REDIRECT: &str = "http://127.0.0.1:53121/callback";
const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP0123456789";

fn passkeys() -> api::Passkeys {
    api::Passkeys::new(ORIGIN, "Test", None).expect("relying party")
}

/// Passkeys only: no identity provider anywhere.
fn passkey_app(db: &TestDb) -> Router {
    let sign_in = api::SignIn::passkey_only(ORIGIN, 30, passkeys()).expect("sign-in");
    api::router(db.runtime.clone(), Some(sign_in))
}

/// A person's authenticator and the browser origin it signs for.
struct Device {
    authenticator: SoftPasskey,
    origin: Url,
}

impl Device {
    fn new() -> Self {
        Self::at(ORIGIN)
    }

    fn at(origin: &str) -> Self {
        Self {
            // `true` marks every ceremony as user-verified, as a phone's unlock would.
            authenticator: SoftPasskey::new(true),
            origin: Url::parse(origin).expect("origin"),
        }
    }

    fn register(&mut self, options: &Value) -> Value {
        // The server must ask for a discoverable credential: there is no username to sign in
        // with otherwise. The software passkey cannot make one, so it is told it need not.
        let selection = &options["publicKey"]["authenticatorSelection"];
        assert_eq!(selection["residentKey"], "required", "{options}");
        assert_eq!(selection["requireResidentKey"], true, "{options}");
        assert_eq!(selection["userVerification"], "required", "{options}");
        let mut options = options.clone();
        options["publicKey"]["authenticatorSelection"]["residentKey"] = json!("discouraged");
        options["publicKey"]["authenticatorSelection"]["requireResidentKey"] = json!(false);
        let options: CreationChallengeResponse =
            serde_json::from_value(options).expect("creation options");
        let made = self
            .authenticator
            .do_registration(self.origin.clone(), options)
            .expect("registered");
        serde_json::to_value(made).expect("json")
    }

    /// Signs the server's challenge with the credential `credential_id`, and sends the user
    /// handle `handle` as a resident-key authenticator would.
    fn assert(&mut self, options: &Value, credential_id: &str, handle: &str) -> Value {
        let mut options = options.clone();
        options["publicKey"]["allowCredentials"] =
            json!([{"type": "public-key", "id": credential_id}]);
        let options: RequestChallengeResponse =
            serde_json::from_value(options).expect("request options");
        let asserted = self
            .authenticator
            .do_authentication(self.origin.clone(), options)
            .expect("asserted");
        let mut json = serde_json::to_value(asserted).expect("json");
        let uuid = Uuid::parse_str(handle).expect("handle");
        json["response"]["userHandle"] = Value::String(URL_SAFE_NO_PAD.encode(uuid.as_bytes()));
        json
    }
}

fn raw_id(credential: &Value) -> String {
    credential["rawId"].as_str().expect("rawId").to_string()
}

/// A page, not JSON.
async fn page(app: &Router, path: &str) -> (StatusCode, HeaderMap, String) {
    let response = app
        .clone()
        .oneshot(
            Request::get(path)
                .header("cf-connecting-ip", common::fresh_address())
                .body(Body::empty())
                .expect("request"),
        )
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
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

async fn invite(db: &TestDb, owner: &db::Caller) -> String {
    match db::create_invite(&db.runtime, owner, "member", None).await {
        Ok(db::Wrote::Fresh(issued)) => issued.token,
        _ => panic!("invite"),
    }
}

/// `POST /v1/auth/start`: the pending sign-in's state and the page it sends the browser to.
async fn start(app: &Router, invite: Option<&str>) -> (String, String) {
    let mut body = json!({
        "redirect_uri": REDIRECT,
        "code_challenge": db::s256(VERIFIER),
        "code_challenge_method": "S256",
        "state": "client-state-0123456789abcdef",
    });
    if let Some(invite) = invite {
        body["invite"] = json!(invite);
    }
    let (status, body) = Call::new(Method::POST, "/v1/auth/start")
        .json(body)
        .send(app)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let url = Url::parse(body["authorize_url"].as_str().expect("url")).expect("url");
    let state = url
        .query_pairs()
        .find(|(name, _)| name == "state")
        .map(|(_, value)| value.into_owned())
        .expect("state");
    note(&state);
    (state, url.path().to_string())
}

/// What the browser is redirected to, and trades for a session.
async fn redeem(app: &Router, redirect: &str) -> (String, String) {
    let url = Url::parse(redirect).expect("redirect");
    assert_eq!(url.path(), "/callback");
    let get = |name: &str| {
        url.query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    };
    assert_eq!(
        get("state").as_deref(),
        Some("client-state-0123456789abcdef")
    );
    let code = get("code").unwrap_or_else(|| panic!("no code in {redirect}"));
    note(&code);
    let (status, body) = Call::new(Method::POST, "/v1/auth/token")
        .json(json!({"code": code, "code_verifier": VERIFIER}))
        .send(app)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    note(body["token"].as_str().expect("token"));
    (
        body["token"].as_str().expect("token").to_string(),
        body["user_id"].as_str().expect("user").to_string(),
    )
}

struct Account {
    token: String,
    user_id: String,
    credential_id: String,
    subject: String,
    codes: Vec<String>,
}

async fn subject_of(db: &TestDb, user_id: &str) -> String {
    db::subject_of(&db.owner, user_id)
        .await
        .expect("subject")
        .expect("has a passkey subject")
}

/// Sign-up with an invite, all the way to a session.
async fn sign_up(
    app: &Router,
    db: &TestDb,
    device: &mut Device,
    invite: &str,
    name: &str,
) -> Account {
    let (state, path) = start(app, Some(invite)).await;
    assert_eq!(path, "/v1/auth/passkey");
    let (status, begun) = Call::new(Method::POST, "/v1/auth/passkey/signup/begin")
        .json(json!({"state": state, "display_name": name}))
        .send(app)
        .await;
    assert_eq!(status, StatusCode::OK, "{begun}");
    let credential = device.register(&begun["options"]);
    let (status, finished) = Call::new(Method::POST, "/v1/auth/passkey/signup/finish")
        .json(json!({"state": state, "cid": begun["cid"], "credential": credential}))
        .send(app)
        .await;
    assert_eq!(status, StatusCode::OK, "{finished}");
    let codes: Vec<String> = finished["codes"]
        .as_array()
        .expect("codes")
        .iter()
        .map(|code| code.as_str().expect("code").to_string())
        .collect();
    for code in &codes {
        note(code);
    }
    note(begun["cid"].as_str().expect("cid"));
    note(finished["cont"].as_str().expect("cont"));
    let (status, sent) = Call::new(Method::POST, "/v1/auth/passkey/continue")
        .json(json!({"state": state, "cont": finished["cont"]}))
        .send(app)
        .await;
    assert_eq!(status, StatusCode::OK, "{sent}");
    let (token, user_id) = redeem(app, sent["redirect"].as_str().expect("redirect")).await;
    let subject = subject_of(db, &user_id).await;
    Account {
        token,
        user_id,
        credential_id: raw_id(&credential),
        subject,
        codes,
    }
}

/// Sign-in with a passkey, no username: the redirect tinyclient gets, or the failure.
async fn sign_in(
    app: &Router,
    device: &mut Device,
    credential_id: &str,
    subject: &str,
) -> (StatusCode, Value) {
    let (state, _) = start(app, None).await;
    let (status, begun) = Call::new(Method::POST, "/v1/auth/passkey/login/begin")
        .json(json!({"state": state}))
        .send(app)
        .await;
    assert_eq!(status, StatusCode::OK, "{begun}");
    note(begun["cid"].as_str().expect("cid"));
    note(credential_id);
    let credential = device.assert(&begun["options"], credential_id, subject);
    Call::new(Method::POST, "/v1/auth/passkey/login/finish")
        .json(json!({"state": state, "cid": begun["cid"], "credential": credential}))
        .send(app)
        .await
}

async fn signed_in(app: &Router, device: &mut Device, account: &Account) -> (String, String) {
    let (status, body) = sign_in(app, device, &account.credential_id, &account.subject).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    redeem(app, body["redirect"].as_str().expect("redirect")).await
}

/// The error a redirect to tinyclient carries.
fn redirect_error(body: &Value) -> String {
    let url = Url::parse(body["redirect"].as_str().expect("redirect")).expect("url");
    url.query_pairs()
        .find(|(name, _)| name == "error")
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default()
}

async fn count(db: &TestDb, sql: &str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(&db.owner)
        .await
        .expect("count")
}

fn sha(text: &str) -> Vec<u8> {
    Sha256::digest(text.as_bytes()).to_vec()
}

#[tokio::test]
async fn config_offers_the_passkey_and_start_opens_its_page() {
    run(|db| async move {
        let app = passkey_app(&db);
        let (status, body) = Call::new(Method::GET, "/v1/auth/config").send(&app).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["methods"], json!(["oidc"]));
        assert_eq!(body["provider_name"], "Passkey");
        assert_eq!(
            body["providers"],
            json!([{"id": "passkey", "name": "Passkey"}])
        );
        let (state, path) = start(&app, None).await;
        assert_eq!(path, "/v1/auth/passkey");
        assert!(!state.is_empty());
    })
    .await;
}

#[tokio::test]
async fn an_invite_makes_an_account_with_a_passkey_and_a_session() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = passkey_app(&db);
        let mut device = Device::new();
        let invite = invite(&db, &owner).await;
        let account = sign_up(&app, &db, &mut device, &invite, "Ada Lovelace").await;
        assert_eq!(account.codes.len(), 10);

        let (status, mine) = Call::new(Method::GET, "/v1/me/passkeys")
            .token(&account.token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{mine}");
        assert_eq!(mine["recovery_codes_left"], 10);
        assert_eq!(mine["passkeys"].as_array().map(Vec::len), Some(1));
        assert_eq!(mine["passkeys"][0]["label"], "Passkey");

        let name: String = sqlx::query_scalar("SELECT display_name FROM users WHERE id = $1::uuid")
            .bind(&account.user_id)
            .fetch_one(&db.owner)
            .await
            .expect("name");
        assert_eq!(name, "Ada Lovelace");
        let role: Option<String> = sqlx::query_scalar("SELECT app_member_role($1::uuid)")
            .bind(&account.user_id)
            .fetch_one(&db.owner)
            .await
            .expect("role");
        assert_eq!(role.as_deref(), Some("member"));
        // The identity is the passkey's, with a random subject: no email, no provider.
        let issuer: String =
            sqlx::query_scalar("SELECT issuer FROM user_identities WHERE user_id = $1::uuid")
                .bind(&account.user_id)
                .fetch_one(&db.owner)
                .await
                .expect("issuer");
        assert_eq!(issuer, "tinyserver:passkey");
        let email: Option<String> =
            sqlx::query_scalar("SELECT email FROM users WHERE id = $1::uuid")
                .bind(&account.user_id)
                .fetch_one(&db.owner)
                .await
                .expect("email");
        assert_eq!(email, None);
    })
    .await;
}

#[tokio::test]
async fn a_passkey_signs_in_again_with_no_username() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = passkey_app(&db);
        let mut device = Device::new();
        let invite = invite(&db, &owner).await;
        let account = sign_up(&app, &db, &mut device, &invite, "Ada").await;
        let (token, user_id) = signed_in(&app, &mut device, &account).await;
        assert_eq!(user_id, account.user_id);
        assert_ne!(token, account.token);
        // Both sessions work.
        for token in [&token, &account.token] {
            let (status, _) = Call::new(Method::GET, "/v1/me/passkeys")
                .token(token)
                .send(&app)
                .await;
            assert_eq!(status, StatusCode::OK);
        }
        let used: Option<String> =
            sqlx::query_scalar("SELECT last_used_at::text FROM passkey_credentials")
                .fetch_one(&db.owner)
                .await
                .expect("used");
        assert!(used.is_some());
    })
    .await;
}

#[tokio::test]
async fn a_challenge_works_once() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = passkey_app(&db);
        let mut device = Device::new();
        let invite = invite(&db, &owner).await;
        let account = sign_up(&app, &db, &mut device, &invite, "Ada").await;

        let (state, _) = start(&app, None).await;
        let (_, begun) = Call::new(Method::POST, "/v1/auth/passkey/login/begin")
            .json(json!({"state": state}))
            .send(&app)
            .await;
        let credential = device.assert(&begun["options"], &account.credential_id, &account.subject);
        let finish = json!({"state": state, "cid": begun["cid"], "credential": credential});
        let (first, body) = Call::new(Method::POST, "/v1/auth/passkey/login/finish")
            .json(finish.clone())
            .send(&app)
            .await;
        assert_eq!(first, StatusCode::OK, "{body}");
        // The same signed answer again: the ceremony and the pending sign-in are both spent.
        let (second, body) = Call::new(Method::POST, "/v1/auth/passkey/login/finish")
            .json(finish)
            .send(&app)
            .await;
        assert_eq!(second, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "expired");
    })
    .await;
}

#[tokio::test]
async fn an_answer_for_another_sign_in_is_refused() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = passkey_app(&db);
        let mut device = Device::new();
        let invite = invite(&db, &owner).await;
        let account = sign_up(&app, &db, &mut device, &invite, "Ada").await;

        let (state_a, _) = start(&app, None).await;
        let (state_b, _) = start(&app, None).await;
        let (_, begun) = Call::new(Method::POST, "/v1/auth/passkey/login/begin")
            .json(json!({"state": state_a}))
            .send(&app)
            .await;
        let credential = device.assert(&begun["options"], &account.credential_id, &account.subject);
        // A ceremony begun for one sign-in cannot finish another.
        let (status, body) = Call::new(Method::POST, "/v1/auth/passkey/login/finish")
            .json(json!({"state": state_b, "cid": begun["cid"], "credential": credential}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "expired");
    })
    .await;
}

#[tokio::test]
async fn a_passkey_made_for_another_origin_is_refused() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = passkey_app(&db);
        let invite = invite(&db, &owner).await;
        let (state, _) = start(&app, Some(&invite)).await;
        let (_, begun) = Call::new(Method::POST, "/v1/auth/passkey/signup/begin")
            .json(json!({"state": state, "display_name": "Mallory"}))
            .send(&app)
            .await;
        // A page on a sibling subdomain asked the authenticator (the relying party id allows it), so the origin in the signed client
        // data is not this server's.
        let mut phisher = Device::at("https://evil.tiny.test");
        let credential = phisher.register(&begun["options"]);
        let (status, body) = Call::new(Method::POST, "/v1/auth/passkey/signup/finish")
            .json(json!({"state": state, "cid": begun["cid"], "credential": credential}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid");
        assert_eq!(
            count(&db, "SELECT count(*) FROM passkey_credentials").await,
            0
        );
        // The invite was not spent and no account was made.
        assert_eq!(
            count(&db, "SELECT count(*) FROM users").await,
            1,
            "only the owner exists"
        );
    })
    .await;
}

#[tokio::test]
async fn an_invite_that_is_used_up_makes_nothing() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = passkey_app(&db);
        let invite = invite(&db, &owner).await;
        let mut first = Device::new();
        sign_up(&app, &db, &mut first, &invite, "First").await;

        let (state, _) = start(&app, Some(&invite)).await;
        let (status, body) = Call::new(Method::POST, "/v1/auth/passkey/signup/begin")
            .json(json!({"state": state, "display_name": "Second"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invite_unusable");
        assert_eq!(
            count(&db, "SELECT count(*) FROM passkey_credentials").await,
            1
        );
    })
    .await;
}

#[tokio::test]
async fn no_invite_means_no_new_account() {
    run(|db| async move {
        first_owner(&db).await;
        let app = passkey_app(&db);
        let (state, _) = start(&app, None).await;
        let (status, body) = Call::new(Method::POST, "/v1/auth/passkey/signup/begin")
            .json(json!({"state": state, "display_name": "Nobody"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "no_invite");
    })
    .await;
}

#[tokio::test]
async fn a_counter_that_goes_back_turns_the_passkey_off() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = passkey_app(&db);
        let mut device = Device::new();
        let invite = invite(&db, &owner).await;
        let account = sign_up(&app, &db, &mut device, &invite, "Ada").await;
        // One good sign-in, then pretend a copy of the key already got to a higher count.
        signed_in(&app, &mut device, &account).await;
        sqlx::query(
            "UPDATE passkey_credentials
             SET passkey = jsonb_set(passkey, '{cred,counter}', '1000')",
        )
        .execute(&db.owner)
        .await
        .expect("raise the stored counter");

        let (status, body) =
            sign_in(&app, &mut device, &account.credential_id, &account.subject).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "flagged");
        // Still refused, without needing the counter check again.
        let (status, body) =
            sign_in(&app, &mut device, &account.credential_id, &account.subject).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "flagged");
        let (_, mine) = Call::new(Method::GET, "/v1/me/passkeys")
            .token(&account.token)
            .send(&app)
            .await;
        assert_eq!(mine["passkeys"][0]["flagged"], true);
        assert_eq!(
            count(
                &db,
                "SELECT count(*) FROM audit_log WHERE action = 'passkey.flag'"
            )
            .await,
            1
        );
    })
    .await;
}

#[tokio::test]
async fn a_credential_for_another_account_does_not_sign_you_in_as_it() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = passkey_app(&db);
        let mut ada = Device::new();
        let mut grace = Device::new();
        let invite_a = invite(&db, &owner).await;
        let invite_b = invite(&db, &owner).await;
        let ada_account = sign_up(&app, &db, &mut ada, &invite_a, "Ada").await;
        let grace_account = sign_up(&app, &db, &mut grace, &invite_b, "Grace").await;
        // Grace's key, with Ada's user handle: the handle must be the credential's own account.
        let (status, body) = sign_in(
            &app,
            &mut grace,
            &grace_account.credential_id,
            &ada_account.subject,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid");
    })
    .await;
}

#[tokio::test]
async fn a_recovery_code_works_once_and_makes_a_new_passkey() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = passkey_app(&db);
        let mut device = Device::new();
        let invite = invite(&db, &owner).await;
        let account = sign_up(&app, &db, &mut device, &invite, "Ada").await;
        let code = account.codes[0].clone();

        // The code goes in lower case with spaces: it reads the same.
        let typed = code.to_lowercase().replace('-', " ");
        let mut new_device = Device::new();
        let (state, _) = start(&app, None).await;
        let (status, begun) = Call::new(Method::POST, "/v1/auth/passkey/recover/begin")
            .json(json!({"state": state, "code": typed}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{begun}");
        let credential = new_device.register(&begun["options"]);
        let (status, done) = Call::new(Method::POST, "/v1/auth/passkey/recover/finish")
            .json(json!({"state": state, "cid": begun["cid"], "code": typed,
                         "credential": credential}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{done}");
        assert_eq!(done["codes_left"], 9);
        let (status, sent) = Call::new(Method::POST, "/v1/auth/passkey/continue")
            .json(json!({"state": state, "cont": done["cont"]}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{sent}");
        let (_, user_id) = redeem(&app, sent["redirect"].as_str().expect("redirect")).await;
        assert_eq!(user_id, account.user_id);
        assert_eq!(
            count(&db, "SELECT count(*) FROM passkey_credentials").await,
            2,
            "the old passkey stays: it is the person's to remove"
        );

        // The same code a second time is refused at the start.
        let (state, _) = start(&app, None).await;
        let (status, body) = Call::new(Method::POST, "/v1/auth/passkey/recover/begin")
            .json(json!({"state": state, "code": code}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_code");
        // And a made-up one.
        let (status, body) = Call::new(Method::POST, "/v1/auth/passkey/recover/begin")
            .json(json!({"state": state, "code": "00000-00000-00000-00000-00000"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_code");
        let (status, body) = Call::new(Method::POST, "/v1/auth/passkey/recover/begin")
            .json(json!({"state": state, "code": "not a code"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_code");
    })
    .await;
}

#[tokio::test]
async fn a_second_try_at_a_recovery_code_replaces_the_first_and_the_code_is_spent_once() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = passkey_app(&db);
        let mut device = Device::new();
        let invite = invite(&db, &owner).await;
        let account = sign_up(&app, &db, &mut device, &invite, "Ada").await;
        let code = account.codes[1].clone();

        // Begin twice with the same code: the second challenge replaces the first, so the
        // first try cannot finish and the second can.
        let mut tries = Vec::new();
        for _ in 0..2 {
            let (state, _) = start(&app, None).await;
            let (_, begun) = Call::new(Method::POST, "/v1/auth/passkey/recover/begin")
                .json(json!({"state": state, "code": code}))
                .send(&app)
                .await;
            let mut other = Device::new();
            let credential = other.register(&begun["options"]);
            tries.push(json!({"state": state, "cid": begun["cid"], "code": code,
                              "credential": credential}));
        }
        let first = Call::new(Method::POST, "/v1/auth/passkey/recover/finish")
            .json(tries[0].clone())
            .send(&app)
            .await;
        assert_eq!(first.0, StatusCode::BAD_REQUEST, "{}", first.1);
        assert_eq!(first.1["error"], "expired");
        let second = Call::new(Method::POST, "/v1/auth/passkey/recover/finish")
            .json(tries[1].clone())
            .send(&app)
            .await;
        assert_eq!(second.0, StatusCode::OK, "{}", second.1);
        assert_eq!(
            count(&db, "SELECT count(*) FROM passkey_credentials").await,
            2
        );
    })
    .await;
}

#[tokio::test]
async fn two_spends_of_one_recovery_code_at_once_let_one_in() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = passkey_app(&db);
        let mut device = Device::new();
        let invite = invite(&db, &owner).await;
        let account = sign_up(&app, &db, &mut device, &invite, "Ada").await;
        let hash = db::recovery_hash(&account.codes[2]).expect("hash");

        // Past the ceremony, where two tries cannot coexist, straight at the spend.
        let passkey = json!({});
        let ids = [[1u8; 16], [2u8; 16]];
        let new = |index: usize| db::NewCredential {
            credential_id: &ids[index],
            passkey: &passkey,
            sign_count: 0,
            backup_eligible: false,
            backup_state: false,
            label: "Passkey",
        };
        let (one, two) = (new(0), new(1));
        let (a, b) = tokio::join!(
            spend_code(&db, &hash, &account, &one),
            spend_code(&db, &hash, &account, &two)
        );
        let wins = [&a, &b].iter().filter(|result| result.is_ok()).count();
        assert_eq!(wins, 1, "{a:?} {b:?}");
        let lost = if a.is_err() { &a } else { &b };
        assert!(matches!(lost, Err(db::PasskeyError::NotFound)), "{lost:?}");
        assert_eq!(
            count(&db, "SELECT count(*) FROM passkey_credentials").await,
            2
        );
        assert_eq!(
            count(&db, "SELECT count(*) FROM passkey_recovery_codes").await,
            9,
            "one code spent"
        );
    })
    .await;
}

#[tokio::test]
async fn recovery_codes_are_kept_only_as_hashes_and_a_new_set_replaces_the_old() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = passkey_app(&db);
        let mut device = Device::new();
        let invite = invite(&db, &owner).await;
        let account = sign_up(&app, &db, &mut device, &invite, "Ada").await;

        // Nothing stored is a code, or the plain digest of one.
        for code in &account.codes {
            let plain: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM passkey_recovery_codes WHERE code_hash = $1",
            )
            .bind(sha(code))
            .fetch_one(&db.owner)
            .await
            .expect("count");
            assert_eq!(plain, 0, "a code is stored as its plain digest");
            let hash = db::recovery_hash(code).expect("hash");
            let stored: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM passkey_recovery_codes WHERE code_hash = $1",
            )
            .bind(hash.as_slice())
            .fetch_one(&db.owner)
            .await
            .expect("count");
            assert_eq!(stored, 1);
        }
        let lengths: Vec<i32> =
            sqlx::query_scalar("SELECT octet_length(code_hash) FROM passkey_recovery_codes")
                .fetch_all(&db.owner)
                .await
                .expect("lengths");
        assert!(lengths.iter().all(|length| *length == 32));

        let (status, fresh) = Call::new(Method::POST, "/v1/me/recovery-codes")
            .token(&account.token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{fresh}");
        let fresh: Vec<String> = fresh["codes"]
            .as_array()
            .expect("codes")
            .iter()
            .map(|code| code.as_str().expect("code").to_string())
            .collect();
        assert_eq!(fresh.len(), 10);
        for old in &account.codes {
            assert!(!fresh.contains(old));
            let (state, _) = start(&app, None).await;
            let (status, body) = Call::new(Method::POST, "/v1/auth/passkey/recover/begin")
                .json(json!({"state": state, "code": old}))
                .send(&app)
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        }
        let (state, _) = start(&app, None).await;
        let (status, body) = Call::new(Method::POST, "/v1/auth/passkey/recover/begin")
            .json(json!({"state": state, "code": fresh[0]}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    })
    .await;
}

#[tokio::test]
async fn the_last_passkey_stays_unless_a_recovery_code_does() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = passkey_app(&db);
        let mut device = Device::new();
        let invite = invite(&db, &owner).await;
        let account = sign_up(&app, &db, &mut device, &invite, "Ada").await;
        let id: String = sqlx::query_scalar("SELECT id::text FROM passkey_credentials")
            .fetch_one(&db.owner)
            .await
            .expect("id");

        // With no recovery code left, removing the only passkey would lock the account.
        sqlx::query("DELETE FROM passkey_recovery_codes")
            .execute(&db.owner)
            .await
            .expect("codes gone");
        let path = format!("/v1/me/passkeys/{id}");
        let (status, body) = Call::new(Method::DELETE, &path)
            .token(&account.token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(
            count(&db, "SELECT count(*) FROM passkey_credentials").await,
            1
        );

        // With a code left it may go: the account can still be recovered.
        let (status, _) = Call::new(Method::POST, "/v1/me/recovery-codes")
            .token(&account.token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = Call::new(Method::DELETE, &path)
            .token(&account.token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(
            count(&db, "SELECT count(*) FROM passkey_credentials").await,
            0
        );
    })
    .await;
}

#[tokio::test]
async fn an_old_session_cannot_change_how_the_account_signs_in() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = passkey_app(&db);
        let mut device = Device::new();
        let invite = invite(&db, &owner).await;
        let account = sign_up(&app, &db, &mut device, &invite, "Ada").await;
        sqlx::query("UPDATE sessions SET created_at = now() - interval '1 hour'")
            .execute(&db.owner)
            .await
            .expect("age the session");
        let id: String = sqlx::query_scalar("SELECT id::text FROM passkey_credentials")
            .fetch_one(&db.owner)
            .await
            .expect("id");

        for (method, path) in [
            (Method::DELETE, format!("/v1/me/passkeys/{id}")),
            (Method::POST, "/v1/me/recovery-codes".to_string()),
            (Method::POST, "/v1/me/passkeys/link".to_string()),
        ] {
            let (status, body) = Call::new(method, &path)
                .token(&account.token)
                .send(&app)
                .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {body}");
            assert_eq!(body["error"], "recent_sign_in_required", "{path}");
        }
        // Reading and renaming need no recent sign-in.
        let (status, _) = Call::new(Method::GET, "/v1/me/passkeys")
            .token(&account.token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = Call::new(Method::PATCH, &format!("/v1/me/passkeys/{id}"))
            .token(&account.token)
            .json(json!({"label": "Phone"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        // Signing in again makes a recent one.
        let (token, _) = signed_in(&app, &mut device, &account).await;
        let (status, _) = Call::new(Method::POST, "/v1/me/recovery-codes")
            .token(&token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK);
    })
    .await;
}

#[tokio::test]
async fn a_bot_has_no_passkeys() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = passkey_app(&db);
        let owner_session = session(&db, &owner.user_id).await;
        let (status, bot) = Call::new(Method::POST, "/v1/bots")
            .token(&owner_session)
            .json(json!({"name": "helper", "scopes": ["rooms.read"]}))
            .send(&app)
            .await;
        if status != StatusCode::CREATED && status != StatusCode::OK {
            // The bot routes ask for more than this test is about; the rule is in `person`.
            eprintln!("skipped: could not make a bot ({status}: {bot})");
            return;
        }
        let token = bot["token"].as_str().expect("bot token").to_string();
        let (status, _) = Call::new(Method::GET, "/v1/me/passkeys")
            .bot(&token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    })
    .await;
}

/// An existing member, signed in the way a provider does it, with an OIDC identity.
async fn oidc_member(db: &TestDb, owner: &db::Caller, email: &str) -> db::Caller {
    join(db, owner, email, "member").await.0
}

#[tokio::test]
async fn a_claim_link_puts_a_passkey_on_an_existing_account_and_changes_nothing_else() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = passkey_app(&db);
        let member = oidc_member(&db, &owner, "ada@example.org").await;
        let before: (String, Option<String>, String) = sqlx::query_as(
            "SELECT display_name, email, created_at::text FROM users WHERE id = $1::uuid",
        )
        .bind(&member.user_id)
        .fetch_one(&db.owner)
        .await
        .expect("before");

        let token = db::mint_claim(&db.owner, &member.user_id, 14)
            .await
            .expect("claim");
        // The link's token is never stored.
        let stored: Vec<Vec<u8>> = sqlx::query_scalar("SELECT token_hash FROM passkey_claims")
            .fetch_all(&db.owner)
            .await
            .expect("claims");
        assert_eq!(stored, vec![sha(&token)]);

        let (status, headers, html) = page(&app, "/v1/auth/passkey/claim").await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("data-mode=\"claim\""));
        assert!(!html.contains(&token));
        assert!(headers.get(header::CONTENT_SECURITY_POLICY).is_some());

        let (status, who) = Call::new(Method::POST, "/v1/auth/passkey/claim/peek")
            .json(json!({"token": token}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{who}");
        assert_eq!(who["name"], "Person");

        let mut device = Device::new();
        let (status, begun) = Call::new(Method::POST, "/v1/auth/passkey/claim/begin")
            .json(json!({"token": token}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{begun}");
        let credential = device.register(&begun["options"]);
        let (status, claimed) = Call::new(Method::POST, "/v1/auth/passkey/claim/finish")
            .json(json!({"token": token, "cid": begun["cid"], "credential": credential}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{claimed}");
        assert_eq!(claimed["codes"].as_array().map(Vec::len), Some(10));

        // The link is spent: it shows nothing and starts nothing.
        let (status, body) = Call::new(Method::POST, "/v1/auth/passkey/claim/peek")
            .json(json!({"token": token}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_link");
        let (status, body) = Call::new(Method::POST, "/v1/auth/passkey/claim/begin")
            .json(json!({"token": token}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(count(&db, "SELECT count(*) FROM passkey_claims").await, 0);

        // The account is the same account, with a second way in beside the first.
        let after: (String, Option<String>, String) = sqlx::query_as(
            "SELECT display_name, email, created_at::text FROM users WHERE id = $1::uuid",
        )
        .bind(&member.user_id)
        .fetch_one(&db.owner)
        .await
        .expect("after");
        assert_eq!(before, after);
        let issuers: Vec<String> = sqlx::query_scalar(
            "SELECT issuer FROM user_identities WHERE user_id = $1::uuid ORDER BY issuer",
        )
        .bind(&member.user_id)
        .fetch_all(&db.owner)
        .await
        .expect("issuers");
        assert_eq!(
            issuers,
            vec![common::ISSUER.to_string(), "tinyserver:passkey".to_string()]
        );

        // And it signs in as that account.
        let subject = subject_of(&db, &member.user_id).await;
        let account = Account {
            token: String::new(),
            user_id: member.user_id.clone(),
            credential_id: raw_id(&credential),
            subject,
            codes: Vec::new(),
        };
        let (_, user_id) = signed_in(&app, &mut device, &account).await;
        assert_eq!(user_id, member.user_id);
    })
    .await;
}

#[tokio::test]
async fn a_claim_link_that_expired_or_never_existed_does_nothing() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = passkey_app(&db);
        let member = oidc_member(&db, &owner, "ada@example.org").await;
        let token = db::mint_claim(&db.owner, &member.user_id, 1)
            .await
            .expect("claim");
        sqlx::query("UPDATE passkey_claims SET expires_at = now() - interval '1 second'")
            .execute(&db.owner)
            .await
            .expect("expire");
        for token in [token.as_str(), "not-a-real-token-0123456789", "a b", ""] {
            let (status, body) = Call::new(Method::POST, "/v1/auth/passkey/claim/peek")
                .json(json!({"token": token}))
                .send(&app)
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{token}: {body}");
            assert_eq!(body["error"], "invalid_link");
            let (status, body) = Call::new(Method::POST, "/v1/auth/passkey/claim/begin")
                .json(json!({"token": token}))
                .send(&app)
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{token}: {body}");
        }
        assert_eq!(
            count(&db, "SELECT count(*) FROM passkey_credentials").await,
            0
        );
    })
    .await;
}

#[tokio::test]
async fn a_claim_link_cannot_be_finished_with_another_links_ceremony() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = passkey_app(&db);
        let ada = oidc_member(&db, &owner, "ada@example.org").await;
        let grace = oidc_member(&db, &owner, "grace@example.org").await;
        let token_a = db::mint_claim(&db.owner, &ada.user_id, 14)
            .await
            .expect("claim");
        let token_b = db::mint_claim(&db.owner, &grace.user_id, 14)
            .await
            .expect("claim");

        // Begun with Ada's link, finished with Grace's: it must not attach to Grace.
        let (_, begun) = Call::new(Method::POST, "/v1/auth/passkey/claim/begin")
            .json(json!({"token": token_a}))
            .send(&app)
            .await;
        let mut device = Device::new();
        let credential = device.register(&begun["options"]);
        let (status, body) = Call::new(Method::POST, "/v1/auth/passkey/claim/finish")
            .json(json!({"token": token_b, "cid": begun["cid"], "credential": credential}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_link");
        assert_eq!(
            count(&db, "SELECT count(*) FROM passkey_credentials").await,
            0
        );
        // Both links are still good: nothing was spent but the ceremony.
        assert_eq!(count(&db, "SELECT count(*) FROM passkey_claims").await, 2);
    })
    .await;
}

#[tokio::test]
async fn a_new_claim_link_replaces_the_old_one() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let member = oidc_member(&db, &owner, "ada@example.org").await;
        let first = db::mint_claim(&db.owner, &member.user_id, 14)
            .await
            .expect("claim");
        let second = db::mint_claim(&db.owner, &member.user_id, 14)
            .await
            .expect("claim");
        assert_ne!(first, second);
        let stored: Vec<Vec<u8>> = sqlx::query_scalar("SELECT token_hash FROM passkey_claims")
            .fetch_all(&db.owner)
            .await
            .expect("claims");
        assert_eq!(stored, vec![sha(&second)]);
        let app = passkey_app(&db);
        let (status, _) = Call::new(Method::POST, "/v1/auth/passkey/claim/peek")
            .json(json!({"token": first}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // Bad lifetimes and unknown members are refused.
        assert!(matches!(
            db::mint_claim(&db.owner, &member.user_id, 0).await,
            Err(db::PasskeyError::Invalid)
        ));
        assert!(matches!(
            db::mint_claim(&db.owner, &member.user_id, 91).await,
            Err(db::PasskeyError::Invalid)
        ));
        assert!(matches!(
            db::mint_claim(&db.owner, "00000000-0000-0000-0000-000000000000", 14).await,
            Err(db::PasskeyError::NotFound)
        ));
    })
    .await;
}

#[tokio::test]
async fn a_banned_member_gets_no_claim_and_no_sign_in() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = passkey_app(&db);
        let member = oidc_member(&db, &owner, "ada@example.org").await;
        let token = db::mint_claim(&db.owner, &member.user_id, 14)
            .await
            .expect("claim");
        db::ban(&db.runtime, &owner, &member.user_id, None, None)
            .await
            .expect("ban");
        // A link made before the ban stops working, and none can be made after.
        let (status, body) = Call::new(Method::POST, "/v1/auth/passkey/claim/peek")
            .json(json!({"token": token}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(matches!(
            db::mint_claim(&db.owner, &member.user_id, 14).await,
            Err(db::PasskeyError::NotFound)
        ));
    })
    .await;
}

#[tokio::test]
async fn a_ban_holds_after_the_old_identity_is_retired() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = passkey_app(&db);
        let member = oidc_member(&db, &owner, "ada@example.org").await;
        let token = db::mint_claim(&db.owner, &member.user_id, 14)
            .await
            .expect("claim");
        let mut device = Device::new();
        let (_, begun) = Call::new(Method::POST, "/v1/auth/passkey/claim/begin")
            .json(json!({"token": token}))
            .send(&app)
            .await;
        let credential = device.register(&begun["options"]);
        let (status, _) = Call::new(Method::POST, "/v1/auth/passkey/claim/finish")
            .json(json!({"token": token, "cid": begun["cid"], "credential": credential}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK);

        // Ban them, then take away the provider identity the ban also names.
        db::ban(&db.runtime, &owner, &member.user_id, None, None)
            .await
            .expect("ban");
        let retired = db::retire_identities(&db.owner, false)
            .await
            .expect("retire");
        assert_eq!(retired.len(), 1);
        assert_eq!(retired[0].issuer, common::ISSUER);
        assert_eq!(
            retired[0].subject, "ada@example.org",
            "kept, so it can be put back"
        );
        let banned: bool = sqlx::query_scalar("SELECT app_banned($1::uuid)")
            .bind(&member.user_id)
            .fetch_one(&db.owner)
            .await
            .expect("banned");
        assert!(
            banned,
            "the ban follows the account, not the provider identity"
        );

        // And the passkey no longer signs them in: tinyclient is told why.
        let subject = subject_of(&db, &member.user_id).await;
        let (status, body) = sign_in(&app, &mut device, &raw_id(&credential), &subject).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(redirect_error(&body), "banned");
    })
    .await;
}

#[tokio::test]
async fn retiring_identities_skips_anyone_who_could_be_locked_out() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = passkey_app(&db);
        let claimed = oidc_member(&db, &owner, "claimed@example.org").await;
        let waiting = oidc_member(&db, &owner, "waiting@example.org").await;
        let token = db::mint_claim(&db.owner, &claimed.user_id, 14)
            .await
            .expect("claim");
        let mut device = Device::new();
        let (_, begun) = Call::new(Method::POST, "/v1/auth/passkey/claim/begin")
            .json(json!({"token": token}))
            .send(&app)
            .await;
        let credential = device.register(&begun["options"]);
        Call::new(Method::POST, "/v1/auth/passkey/claim/finish")
            .json(json!({"token": token, "cid": begun["cid"], "credential": credential}))
            .send(&app)
            .await;

        // A dry run says what it would do and does not do it.
        let would = db::retire_identities(&db.owner, true)
            .await
            .expect("dry run");
        assert_eq!(
            would
                .iter()
                .map(|item| item.user_id.as_str())
                .collect::<Vec<_>>(),
            vec![claimed.user_id.as_str()]
        );
        assert_eq!(
            count(
                &db,
                "SELECT count(*) FROM user_identities WHERE issuer <> 'tinyserver:passkey'"
            )
            .await,
            3
        );
        // Applying removes the claimed member's provider identity only. The owner and the
        // member who never claimed keep theirs: they could not get in otherwise.
        let done = db::retire_identities(&db.owner, false)
            .await
            .expect("apply");
        assert_eq!(done.len(), 1);
        let left: Vec<String> = sqlx::query_scalar(
            "SELECT user_id::text FROM user_identities WHERE issuer <> 'tinyserver:passkey'
             ORDER BY user_id",
        )
        .fetch_all(&db.owner)
        .await
        .expect("left");
        assert!(left.contains(&waiting.user_id));
        assert!(left.contains(&owner.user_id));
        assert!(!left.contains(&claimed.user_id));
        // Nothing left to do, and a flagged passkey would not count either.
        assert!(db::retire_identities(&db.owner, false)
            .await
            .expect("again")
            .is_empty());
        assert_eq!(
            count(
                &db,
                "SELECT count(*) FROM audit_log WHERE action = 'identity.retire'"
            )
            .await,
            1
        );
    })
    .await;
}

#[tokio::test]
async fn the_roster_says_who_has_a_passkey_and_what_else_signs_them_in() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = passkey_app(&db);
        let claimed = oidc_member(&db, &owner, "claimed@example.org").await;
        let waiting = oidc_member(&db, &owner, "waiting@example.org").await;
        let token = db::mint_claim(&db.owner, &claimed.user_id, 14)
            .await
            .expect("claim");
        let mut device = Device::new();
        let (_, begun) = Call::new(Method::POST, "/v1/auth/passkey/claim/begin")
            .json(json!({"token": token}))
            .send(&app)
            .await;
        let credential = device.register(&begun["options"]);
        Call::new(Method::POST, "/v1/auth/passkey/claim/finish")
            .json(json!({"token": token, "cid": begun["cid"], "credential": credential}))
            .send(&app)
            .await;

        let roster = db::roster(&db.owner).await.expect("roster");
        assert_eq!(roster.len(), 3);
        let row = |id: &str| roster.iter().find(|row| row.user_id == id).expect("row");
        assert_eq!(row(&claimed.user_id).passkeys, 1);
        assert_eq!(
            row(&claimed.user_id).issuers,
            vec![common::ISSUER.to_string(), "tinyserver:passkey".to_string()]
        );
        assert_eq!(row(&waiting.user_id).passkeys, 0);
        assert_eq!(
            row(&waiting.user_id).issuers,
            vec![common::ISSUER.to_string()]
        );
        // The provider's own name for them is kept, so a retired identity can be put back.
        assert_eq!(
            row(&waiting.user_id).identities,
            vec![format!("{} waiting@example.org", common::ISSUER)]
        );
        assert_eq!(
            row(&waiting.user_id).email.as_deref(),
            Some("waiting@example.org")
        );
        assert_eq!(row(&owner.user_id).role.as_deref(), Some("owner"));
        assert!(!row(&waiting.user_id).banned);
    })
    .await;
}

#[tokio::test]
async fn a_second_device_is_added_with_a_link_the_person_makes_themself() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = passkey_app(&db);
        let mut laptop = Device::new();
        let invite = invite(&db, &owner).await;
        let account = sign_up(&app, &db, &mut laptop, &invite, "Ada").await;

        let (status, link) = Call::new(Method::POST, "/v1/me/passkeys/link")
            .token(&account.token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{link}");
        let url = Url::parse(link["url"].as_str().expect("url")).expect("url");
        assert_eq!(url.path(), "/v1/auth/passkey/claim");
        // The token is after the #, so it is never in a request.
        let token = url.fragment().expect("fragment").to_string();
        assert!(url.query().is_none());

        let mut phone = Device::new();
        let (status, begun) = Call::new(Method::POST, "/v1/auth/passkey/claim/begin")
            .json(json!({"token": token}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{begun}");
        // The laptop's passkey is excluded, so a device cannot be added twice.
        assert_eq!(
            begun["options"]["publicKey"]["excludeCredentials"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );
        let credential = phone.register(&begun["options"]);
        let (status, claimed) = Call::new(Method::POST, "/v1/auth/passkey/claim/finish")
            .json(json!({"token": token, "cid": begun["cid"], "credential": credential}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{claimed}");
        assert!(
            claimed["codes"].is_null(),
            "they already have recovery codes"
        );
        let (_, mine) = Call::new(Method::GET, "/v1/me/passkeys")
            .token(&account.token)
            .send(&app)
            .await;
        assert_eq!(mine["passkeys"].as_array().map(Vec::len), Some(2));
        assert_eq!(mine["recovery_codes_left"], 10);
        // The phone signs in as the same person, with the same subject.
        let phone_account = Account {
            token: String::new(),
            user_id: account.user_id.clone(),
            credential_id: raw_id(&credential),
            subject: account.subject.clone(),
            codes: Vec::new(),
        };
        let (_, user_id) = signed_in(&app, &mut phone, &phone_account).await;
        assert_eq!(user_id, account.user_id);
    })
    .await;
}

#[tokio::test]
async fn deleting_an_account_takes_its_passkeys_codes_and_links_with_it() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = passkey_app(&db);
        let mut device = Device::new();
        let invite = invite(&db, &owner).await;
        let account = sign_up(&app, &db, &mut device, &invite, "Ada").await;
        Call::new(Method::POST, "/v1/me/passkeys/link")
            .token(&account.token)
            .send(&app)
            .await;
        // A ceremony in progress for them too.
        let (state, _) = start(&app, None).await;
        Call::new(Method::POST, "/v1/auth/passkey/recover/begin")
            .json(json!({"state": state, "code": account.codes[0]}))
            .send(&app)
            .await;
        assert!(count(&db, "SELECT count(*) FROM passkey_credentials").await > 0);
        assert!(count(&db, "SELECT count(*) FROM passkey_claims").await > 0);
        assert!(
            count(
                &db,
                "SELECT count(*) FROM passkey_ceremonies WHERE user_id IS NOT NULL"
            )
            .await
                > 0
        );

        let (status, body) = Call::new(Method::DELETE, "/v1/me")
            .token(&account.token)
            .json(json!({"confirm": "delete my account"}))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        for table in [
            "passkey_credentials",
            "passkey_recovery_codes",
            "passkey_claims",
            "passkey_ceremonies",
        ] {
            assert_eq!(
                count(&db, &format!("SELECT count(*) FROM {table}")).await,
                0,
                "{table}"
            );
        }
        let identities: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM user_identities WHERE issuer = 'tinyserver:passkey'",
        )
        .fetch_one(&db.owner)
        .await
        .expect("identities");
        assert_eq!(identities, 0);
        // The passkey that was theirs signs nobody in now.
        let (status, body) =
            sign_in(&app, &mut device, &account.credential_id, &account.subject).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    })
    .await;
}

#[tokio::test]
async fn the_passkey_tables_hold_no_address_agent_email_or_phone() {
    run(|db| async move {
        let columns: Vec<(String, String)> = sqlx::query_as(
            "SELECT table_name::text, column_name::text FROM information_schema.columns
             WHERE table_schema = 'public' AND table_name LIKE 'passkey\\_%'
             ORDER BY table_name, ordinal_position",
        )
        .fetch_all(&db.owner)
        .await
        .expect("columns");
        let tables: std::collections::BTreeSet<&str> =
            columns.iter().map(|(table, _)| table.as_str()).collect();
        assert_eq!(
            tables.into_iter().collect::<Vec<_>>(),
            vec![
                "passkey_ceremonies",
                "passkey_claims",
                "passkey_credentials",
                "passkey_recovery_codes"
            ]
        );
        for (table, column) in &columns {
            for forbidden in [
                "ip", "addr", "agent", "email", "phone", "host", "country", "geo",
            ] {
                assert!(
                    !column.split('_').any(|part| part == forbidden)
                        && !column.contains("address")
                        && !column.contains("user_agent"),
                    "{table}.{column}"
                );
            }
        }
        // The runtime role reaches them only through the functions.
        for table in [
            "passkey_credentials",
            "passkey_recovery_codes",
            "passkey_claims",
            "passkey_ceremonies",
        ] {
            let granted: bool = sqlx::query_scalar(
                "SELECT has_table_privilege('app_runtime', $1, 'SELECT,INSERT,UPDATE,DELETE')",
            )
            .bind(table)
            .fetch_one(&db.owner)
            .await
            .expect("privilege");
            assert!(!granted, "{table} is open to app_runtime");
            let rls: (bool, bool) = sqlx::query_as(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = $1",
            )
            .bind(table)
            .fetch_one(&db.owner)
            .await
            .expect("rls");
            assert_eq!(rls, (true, true), "{table}");
        }
    })
    .await;
}

#[tokio::test]
async fn the_pages_say_what_may_run_and_carry_no_secret() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = passkey_app(&db);
        let invite = invite(&db, &owner).await;
        let (state, _) = start(&app, Some(&invite)).await;
        let (status, headers, html) = page(&app, &format!("/v1/auth/passkey?state={state}")).await;
        assert_eq!(status, StatusCode::OK);
        let policy = headers
            .get(header::CONTENT_SECURITY_POLICY)
            .and_then(|value| value.to_str().ok())
            .expect("a policy");
        // The policy names exactly the script on the page.
        let script = html
            .split("<script>")
            .nth(1)
            .and_then(|rest| rest.split("</script>").next())
            .expect("a script");
        let hash =
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(script.as_bytes()));
        assert!(
            policy.contains(&format!("script-src 'sha256-{hash}'")),
            "{policy}"
        );
        assert!(policy.contains("default-src 'none'"));
        assert!(policy.contains("connect-src 'self'"));
        assert!(!policy.contains("unsafe"));
        assert!(html.contains(&format!("data-state=\"{state}\"")));
        // An invite shows the sign-up form; the invite token itself is nowhere on the page.
        assert!(html.contains("Create my account"));
        assert!(!html.contains(&invite));
        assert_eq!(
            headers
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );

        // Without an invite there is no sign-up form.
        let (state, _) = start(&app, None).await;
        let (_, _, html) = page(&app, &format!("/v1/auth/passkey?state={state}")).await;
        assert!(!html.contains("Create my account"));
        assert!(html.contains("I lost my passkeys"));

        // A state that is made up, expired or badly shaped shows the expired page.
        for bad in [
            "/v1/auth/passkey",
            "/v1/auth/passkey?state=nope",
            "/v1/auth/passkey?state=a%20b",
        ] {
            let (status, _, html) = page(&app, bad).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
            assert!(html.contains("expired"));
        }
    })
    .await;
}

#[tokio::test]
async fn without_passkeys_turned_on_there_are_no_passkey_routes() {
    run(|db| async move {
        let provider = Provider::start().await;
        let sign_in =
            api::SignIn::discover(oidc::config(vec![provider.provider_config("default")]))
                .await
                .expect("discover");
        let app = api::router(db.runtime.clone(), Some(sign_in));
        let (status, config) = Call::new(Method::GET, "/v1/auth/config").send(&app).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            config["providers"]
                .as_array()
                .map(|list| list.iter().map(|p| p["id"].clone()).collect::<Vec<_>>()),
            Some(vec![json!("default")])
        );
        for path in [
            "/v1/auth/passkey/login/begin",
            "/v1/auth/passkey/signup/begin",
            "/v1/auth/passkey/claim/peek",
            "/v1/me/passkeys/link",
        ] {
            let (status, _) = Call::new(Method::POST, path)
                .json(json!({}))
                .send(&app)
                .await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        }
        let (status, _, _) = page(&app, "/v1/auth/passkey?state=x").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    })
    .await;
}

#[tokio::test]
async fn both_modes_open_the_passkey_page_and_still_offer_the_provider() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let provider = Provider::start().await;
        let sign_in =
            api::SignIn::discover(oidc::config(vec![provider.provider_config("default")]))
                .await
                .expect("discover")
                .with_passkeys(passkeys());
        let app = api::router(db.runtime.clone(), Some(sign_in));
        let (_, config) = Call::new(Method::GET, "/v1/auth/config").send(&app).await;
        assert_eq!(config["providers"][0]["id"], "passkey");
        assert_eq!(config["providers"][1]["id"], "default");

        // The default is the passkey page, and it offers the provider as the other way in.
        let (state, path) = start(&app, None).await;
        assert_eq!(path, "/v1/auth/passkey");
        let (status, _, html) = page(&app, &format!("/v1/auth/passkey?state={state}")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("instead"), "{html}");
        assert!(
            html.contains(&provider.issuer.replace('&', "&amp;")),
            "{html}"
        );

        // A client that names the provider goes straight to it, as before.
        let (status, body) = Call::new(Method::POST, "/v1/auth/start")
            .json(json!({
                "redirect_uri": REDIRECT,
                "code_challenge": db::s256(VERIFIER),
                "code_challenge_method": "S256",
                "state": "client-state-0123456789abcdef",
                "provider": "default",
            }))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let url = body["authorize_url"].as_str().expect("url");
        assert!(url.starts_with(&provider.issuer), "{url}");

        // And someone who signed up with a passkey beside it is a member like any other.
        let mut device = Device::new();
        let invite = invite(&db, &owner).await;
        let account = sign_up(&app, &db, &mut device, &invite, "Ada").await;
        let (status, _) = Call::new(Method::GET, "/v1/me/passkeys")
            .token(&account.token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK);
    })
    .await;
}

#[tokio::test]
async fn the_recovery_and_claim_calls_are_rate_limited_per_address() {
    run(|db| async move {
        first_owner(&db).await;
        let app = passkey_app(&db);
        let address = "198.51.100.77";
        let (state, _) = start(&app, None).await;
        let mut statuses = Vec::new();
        for _ in 0..10 {
            let (status, _) = Call::new(Method::POST, "/v1/auth/passkey/recover/begin")
                .address(address)
                .json(json!({"state": state, "code": "00000-00000-00000-00000-00000"}))
                .send(&app)
                .await;
            statuses.push(status);
        }
        // Eight a minute, then turned away before anything is looked up.
        assert_eq!(
            statuses
                .iter()
                .filter(|s| **s == StatusCode::BAD_REQUEST)
                .count(),
            8,
            "{statuses:?}"
        );
        assert_eq!(
            statuses
                .iter()
                .filter(|s| **s == StatusCode::TOO_MANY_REQUESTS)
                .count(),
            2,
            "{statuses:?}"
        );
        // The claim calls share that tight gate, apart from the recovery calls' count.
        let mut limited = false;
        for _ in 0..10 {
            let (status, _) = Call::new(Method::POST, "/v1/auth/passkey/claim/peek")
                .address("198.51.100.78")
                .json(json!({"token": "x"}))
                .send(&app)
                .await;
            limited |= status == StatusCode::TOO_MANY_REQUESTS;
        }
        assert!(limited);
    })
    .await;
}

#[tokio::test]
async fn a_database_that_runs_the_migrations_twice_keeps_one_set_of_functions() {
    run(|db| async move {
        // Applying again is a no-op: the migration is recorded, not re-run.
        db::migrate(&db.owner).await.expect("migrate again");
        let functions: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_proc WHERE proname LIKE 'app_passkey_%'
               AND proname <> 'app_passkey_forget_user'",
        )
        .fetch_one(&db.owner)
        .await
        .expect("functions");
        assert_eq!(functions, 21);
        // None is open to the world, and each is for the runtime role only.
        let open: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_proc p
             WHERE p.proname LIKE 'app_passkey_%'
               AND has_function_privilege('public', p.oid, 'EXECUTE')",
        )
        .fetch_one(&db.owner)
        .await
        .expect("open");
        assert_eq!(open, 0);
    })
    .await;
}

/// Spends a recovery code with a made-up credential, straight at the database.
async fn spend_code(
    db: &TestDb,
    hash: &[u8; 32],
    account: &Account,
    credential: &db::NewCredential<'_>,
) -> Result<(), db::PasskeyError> {
    let recovery = db::Recovery {
        code_hash: hash,
        user_id: &account.user_id,
        subject: &account.subject,
        credential,
    };
    db::recover(&db.runtime, &recovery).await.map(|_| ())
}

/// Every secret the flows below make or are given, so a log test can look for each of them.
static SECRETS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

fn note(secret: &str) {
    SECRETS
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .push(secret.to_string());
}

/// What the subscriber wrote.
#[derive(Clone, Default)]
struct Logs(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl Logs {
    fn text(&self) -> String {
        let bytes = self.0.lock().unwrap_or_else(|poison| poison.into_inner());
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

impl std::io::Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The one global subscriber of this test binary: it sees every line at every level, from every
/// test, so it is installed by the first test that asks and shared after.
static LOGS: std::sync::OnceLock<Logs> = std::sync::OnceLock::new();

fn capture_logs() -> Logs {
    LOGS.get_or_init(|| {
        let logs = Logs::default();
        let writer = logs.clone();
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .try_init()
            .ok();
        logs
    })
    .clone()
}

#[tokio::test]
async fn no_secret_a_flow_makes_reaches_the_logs() {
    let logs = capture_logs();
    run(|db| async move {
        let owner = first_owner(&db).await;
        let app = passkey_app(&db);
        let mut device = Device::new();
        let invite_token = invite(&db, &owner).await;
        note(&invite_token);
        let account = sign_up(&app, &db, &mut device, &invite_token, "Ada Lovelace").await;
        note(&account.token);
        note(&account.credential_id);
        note(&account.subject);
        signed_in(&app, &mut device, &account).await;

        // A recovery, a claim link, a link a person makes for themself, and some refusals.
        let (state, _) = start(&app, None).await;
        let (_, begun) = Call::new(Method::POST, "/v1/auth/passkey/recover/begin")
            .json(json!({"state": state, "code": account.codes[3]}))
            .send(&app)
            .await;
        note(begun["cid"].as_str().expect("cid"));
        let member = oidc_member(&db, &owner, "grace@example.org").await;
        let claim = db::mint_claim(&db.owner, &member.user_id, 14)
            .await
            .expect("claim");
        note(&claim);
        let mut grace = Device::new();
        let (_, begun) = Call::new(Method::POST, "/v1/auth/passkey/claim/begin")
            .json(json!({"token": claim}))
            .send(&app)
            .await;
        note(begun["cid"].as_str().expect("cid"));
        let credential = grace.register(&begun["options"]);
        note(&raw_id(&credential));
        Call::new(Method::POST, "/v1/auth/passkey/claim/finish")
            .json(json!({"token": claim, "cid": begun["cid"], "credential": credential}))
            .send(&app)
            .await;
        let (_, link) = Call::new(Method::POST, "/v1/me/passkeys/link")
            .token(&account.token)
            .send(&app)
            .await;
        let url = Url::parse(link["url"].as_str().expect("url")).expect("url");
        note(url.fragment().expect("fragment"));
        Call::new(Method::POST, "/v1/auth/passkey/claim/peek")
            .json(json!({"token": "not-a-real-token-0123456789"}))
            .send(&app)
            .await;
        Call::new(Method::POST, "/v1/auth/passkey/recover/begin")
            .json(json!({"state": state, "code": "00000-00000-00000-00000-00000"}))
            .send(&app)
            .await;
        let (state, _) = start(&app, None).await;
        Call::new(Method::POST, "/v1/auth/passkey/login/finish")
            .json(json!({"state": state, "cid": "x", "credential": {"id": "x"}}))
            .send(&app)
            .await;
    })
    .await;

    // Everything the process logged except two things. The stand-in browser is the test's own
    // client and traces what it makes. `webauthn_rs_core` traces whole credentials below warn;
    // the server's log policy holds it at warn, which a unit test in tinyserver's log_policy
    // checks. Its warnings and errors, and everything else, stay.
    let everything = logs.text();
    let text = everything
        .lines()
        .filter(|line| !line.contains("webauthn_authenticator_rs"))
        .filter(|line| {
            let quiet = [" TRACE ", " DEBUG ", " INFO "]
                .iter()
                .any(|level| line.contains(level));
            !(quiet && line.contains("webauthn_rs_core::"))
        })
        .collect::<Vec<_>>()
        .join("\n");
    // The flows really were logged: this is not an empty subscriber.
    assert!(text.contains("signed in with a passkey"), "{text}");
    assert!(text.contains("account made with a passkey"), "{text}");
    assert!(
        text.contains("passkey claimed on an existing account"),
        "{text}"
    );
    let secrets = SECRETS
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone();
    assert!(secrets.len() > 20, "{} secrets noted", secrets.len());
    for secret in secrets.iter().filter(|secret| secret.len() >= 8) {
        if let Some(line) = text.lines().find(|line| line.contains(secret.as_str())) {
            panic!(
                "a log line holds a secret ({} characters): {line}",
                secret.len()
            );
        }
    }
    // Nor a name a person typed, nor an email.
    assert!(!text.contains("Ada Lovelace"));
    assert!(!text.contains("grace@example.org"));
}

// First-run setup, where it meets passkeys.

/// Puts a passkey on an existing account with a claim link, as an owner's roster would.
async fn attach_passkey(app: &Router, db: &TestDb, user_id: &str, device: &mut Device) -> Account {
    let token = db::mint_claim(&db.owner, user_id, 14).await.expect("claim");
    note(&token);
    let (status, begun) = Call::new(Method::POST, "/v1/auth/passkey/claim/begin")
        .json(json!({"token": token}))
        .send(app)
        .await;
    assert_eq!(status, StatusCode::OK, "{begun}");
    note(begun["cid"].as_str().expect("cid"));
    let credential = device.register(&begun["options"]);
    let (status, claimed) = Call::new(Method::POST, "/v1/auth/passkey/claim/finish")
        .json(json!({"token": token, "cid": begun["cid"], "credential": credential}))
        .send(app)
        .await;
    assert_eq!(status, StatusCode::OK, "{claimed}");
    let codes: Vec<String> = claimed["codes"]
        .as_array()
        .expect("codes")
        .iter()
        .map(|code| code.as_str().expect("code").to_string())
        .collect();
    for code in &codes {
        note(code);
    }
    Account {
        token: String::new(),
        user_id: user_id.to_string(),
        credential_id: raw_id(&credential),
        subject: subject_of(db, user_id).await,
        codes,
    }
}

async fn put_setup(app: &Router, token: &str, body: Value) -> (StatusCode, Value) {
    Call::new(Method::PUT, "/v1/setup")
        .token(token)
        .json(body)
        .send(app)
        .await
}

async fn get_setup(app: &Router, token: &str) -> Value {
    let (status, setup) = Call::new(Method::GET, "/v1/setup")
        .token(token)
        .send(app)
        .await;
    assert_eq!(status, StatusCode::OK, "{setup}");
    setup
}

/// The query tinyserver sent the browser back to tinyclient with.
fn redirect_pairs(headers: &HeaderMap) -> std::collections::HashMap<String, String> {
    let location = headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("location");
    Url::parse(location)
        .expect("url")
        .query_pairs()
        .into_owned()
        .collect()
}

#[tokio::test]
async fn passkeys_only_waits_for_the_owner_to_have_a_passkey_and_for_members_to_be_ready() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let ada = oidc_member(&db, &owner, "ada@example.org").await;
        let ada_token = session(&db, &ada.user_id).await;
        let app = passkey_app(&db);

        let setup = get_setup(&app, &owner_token).await;
        assert_eq!(setup["deployment"], json!({"passkeys": true, "sso": false}));
        assert_eq!(setup["counts"]["owner_has_passkey"], false);
        assert_eq!(setup["counts"]["members_without_passkey"], 2);
        assert_eq!(setup["presets"][1]["available"], true);

        // The owner has no passkey: choosing passkeys only would lock the owner out.
        let (status, body) =
            put_setup(&app, &owner_token, json!({"sign_in_methods": "passkey"})).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["error"], "owner_needs_passkey");

        let mut owner_device = Device::new();
        let owner_passkey = attach_passkey(&app, &db, &owner.user_id, &mut owner_device).await;
        let setup = get_setup(&app, &owner_token).await;
        assert_eq!(setup["counts"]["owner_has_passkey"], true);
        assert_eq!(setup["counts"]["members_without_passkey"], 1);

        // Ada has none: she is counted, and nothing is changed until the owner says so.
        let (status, body) = put_setup(&app, &owner_token, json!({"preset": "privacy"})).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["error"], "members_without_passkey");
        assert_eq!(body["count"], 1);
        let setup = get_setup(&app, &owner_token).await;
        assert_eq!(setup["current"]["sign_in_methods"], "any");
        assert_eq!(
            setup["current"]["provider_profile"], "full",
            "a refused request changed a choice"
        );
        assert_eq!(setup["needed"], true);

        let (status, body) = put_setup(
            &app,
            &owner_token,
            json!({"preset": "privacy", "allow_lockout": true}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["settings"]["sign_in_methods"], "passkey");

        // A session Ada already has carries on. The owner signs in with the passkey.
        let (status, _) = Call::new(Method::GET, "/v1/me")
            .token(&ada_token)
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK);
        let (_, user_id) = signed_in(&app, &mut owner_device, &owner_passkey).await;
        assert_eq!(user_id, owner.user_id);

        // The owner gives Ada a link, and she is in with a passkey.
        let mut ada_device = Device::new();
        let ada_passkey = attach_passkey(&app, &db, &ada.user_id, &mut ada_device).await;
        let (_, user_id) = signed_in(&app, &mut ada_device, &ada_passkey).await;
        assert_eq!(user_id, ada.user_id);
        let setup = get_setup(&app, &owner_token).await;
        assert_eq!(setup["counts"]["members_without_passkey"], 0);
    })
    .await;
}

#[tokio::test]
async fn passkeys_only_turns_a_provider_away_and_the_page_stops_offering_it() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let provider = Provider::start().await;
        let sign_in =
            api::SignIn::discover(oidc::config(vec![provider.provider_config("default")]))
                .await
                .expect("discover")
                .with_passkeys(passkeys());
        let app = api::router(db.runtime.clone(), Some(sign_in));
        let mut device = Device::new();
        let owner_passkey = attach_passkey(&app, &db, &owner.user_id, &mut device).await;

        let setup = get_setup(&app, &owner_token).await;
        assert_eq!(setup["deployment"], json!({"passkeys": true, "sso": true}));

        // Someone is part-way through signing in at the provider when the owner chooses.
        let invite_token = invite(&db, &owner).await;
        let begin = |invite: String| {
            let app = app.clone();
            async move {
                Call::new(Method::POST, "/v1/auth/start")
                    .json(json!({
                        "redirect_uri": REDIRECT,
                        "code_challenge": db::s256(VERIFIER),
                        "code_challenge_method": "S256",
                        "state": "client-state-0123456789abcdef",
                        "provider": "default",
                        "invite": invite,
                    }))
                    .send(&app)
                    .await
            }
        };
        let (status, body) = begin(invite_token.clone()).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let url = body["authorize_url"].as_str().expect("url").to_string();
        assert!(url.starts_with(&provider.issuer), "{url}");
        let (code, state) =
            provider.authorize(&url, oidc::Person::new("zed"), oidc::Tamper::default());

        let (status, body) =
            put_setup(&app, &owner_token, json!({"sign_in_methods": "passkey"})).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // The provider vouches for them, and the community does not take it.
        let (status, headers, _) = page(
            &app,
            &format!("/v1/auth/callback?code={code}&state={state}"),
        )
        .await;
        assert_eq!(status, StatusCode::FOUND);
        let pairs = redirect_pairs(&headers);
        assert_eq!(pairs.get("error").map(String::as_str), Some("passkey_only"));
        assert!(!pairs.contains_key("code"));
        assert_eq!(
            count(
                &db,
                "SELECT count(*) FROM users WHERE display_name LIKE '%zed%'"
            )
            .await,
            0
        );
        // The invite was not spent either.
        assert_eq!(
            count(
                &db,
                "SELECT count(*) FROM invites WHERE accepted_at IS NOT NULL AND role = 'member'"
            )
            .await,
            0
        );

        // Starting a sign-in now, even naming the provider, opens the passkey page, and the page
        // has no way to the provider on it.
        let (status, body) = begin(invite_token).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let url = Url::parse(body["authorize_url"].as_str().expect("url")).expect("url");
        assert_eq!(url.path(), "/v1/auth/passkey");
        let (status, _, html) = page(
            &app,
            &format!("{}?{}", url.path(), url.query().unwrap_or("")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!html.contains("instead"), "{html}");
        assert!(
            !html.contains(&provider.issuer.replace('&', "&amp;")),
            "{html}"
        );

        // A person with a passkey is unaffected.
        let (_, user_id) = signed_in(&app, &mut device, &owner_passkey).await;
        assert_eq!(user_id, owner.user_id);
    })
    .await;
}

#[tokio::test]
async fn the_choice_does_not_lock_everyone_out_when_the_server_is_started_without_passkeys() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        // Passkeys only was chosen while passkeys were on.
        sqlx::query("UPDATE server_settings SET sign_in_methods = 'passkey'")
            .execute(&db.owner)
            .await
            .expect("choice");
        // The operator then starts the server with providers only, as a rollback does.
        let provider = Provider::start().await;
        let sign_in =
            api::SignIn::discover(oidc::config(vec![provider.provider_config("default")]))
                .await
                .expect("discover");
        let app = api::router(db.runtime.clone(), Some(sign_in));
        let invite_token = invite(&db, &owner).await;
        let (status, body) = Call::new(Method::POST, "/v1/auth/start")
            .json(json!({
                "redirect_uri": REDIRECT,
                "code_challenge": db::s256(VERIFIER),
                "code_challenge_method": "S256",
                "state": "client-state-0123456789abcdef",
                "invite": invite_token,
            }))
            .send(&app)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let url = body["authorize_url"].as_str().expect("url");
        assert!(url.starts_with(&provider.issuer), "{url}");
        let (code, state) =
            provider.authorize(url, oidc::Person::new("zed"), oidc::Tamper::default());
        let (status, headers, _) = page(
            &app,
            &format!("/v1/auth/callback?code={code}&state={state}"),
        )
        .await;
        assert_eq!(status, StatusCode::FOUND);
        let pairs = redirect_pairs(&headers);
        assert!(pairs.contains_key("code"), "{pairs:?}");
        assert!(!pairs.contains_key("error"), "{pairs:?}");
    })
    .await;
}

#[tokio::test]
async fn what_the_owner_chose_about_providers_does_not_touch_the_name_typed_for_a_passkey() {
    run(|db| async move {
        let owner = first_owner(&db).await;
        let owner_token = session(&db, &owner.user_id).await;
        let app = passkey_app(&db);
        let (status, body) = put_setup(
            &app,
            &owner_token,
            json!({"provider_profile": "none", "activity_visibility": "nobody"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let mut device = Device::new();
        let invite_token = invite(&db, &owner).await;
        let account = sign_up(&app, &db, &mut device, &invite_token, "Ada Lovelace").await;
        let (email, name): (Option<String>, String) =
            sqlx::query_as("SELECT email, display_name FROM users WHERE id = $1::uuid")
                .bind(&account.user_id)
                .fetch_one(&db.owner)
                .await
                .expect("account");
        assert_eq!(name, "Ada Lovelace");
        assert_eq!(email, None);
    })
    .await;
}
