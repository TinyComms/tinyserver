//! A software passkey and the calls that put one on an account, shared by the suites that need
//! a member with a passkey.

use axum::http::{Method, StatusCode};
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use webauthn_authenticator_rs::prelude::{
    CreationChallengeResponse, RequestChallengeResponse, Url, WebauthnAuthenticator,
};
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::Uuid;

use super::{Call, TestDb};

pub const ORIGIN: &str = "https://tiny.test";

/// A person's authenticator and the browser origin it signs for.
pub struct Device {
    pub authenticator: SoftPasskey,
    pub origin: Url,
}

impl Device {
    pub fn new() -> Self {
        Self::at(ORIGIN)
    }

    pub fn at(origin: &str) -> Self {
        Self {
            // `true` marks every ceremony as user-verified, as a phone's unlock would.
            authenticator: SoftPasskey::new(true),
            origin: Url::parse(origin).expect("origin"),
        }
    }

    pub fn register(&mut self, options: &Value) -> Value {
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
    pub fn assert(&mut self, options: &Value, credential_id: &str, handle: &str) -> Value {
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

pub fn raw_id(credential: &Value) -> String {
    credential["rawId"].as_str().expect("rawId").to_string()
}

pub struct Account {
    pub token: String,
    pub user_id: String,
    pub credential_id: String,
    pub subject: String,
    pub codes: Vec<String>,
}

pub async fn subject_of(db: &TestDb, user_id: &str) -> String {
    db::subject_of(&db.owner, user_id)
        .await
        .expect("subject")
        .expect("has a passkey subject")
}

/// Puts a passkey on an existing account with a claim link, as an owner's roster would.
pub async fn attach_passkey(
    app: &Router,
    db: &TestDb,
    user_id: &str,
    device: &mut Device,
) -> Account {
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

/// Every secret the flows below make or are given, so a log test can look for each of them.
pub static SECRETS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

pub fn note(secret: &str) {
    SECRETS
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .push(secret.to_string());
}

pub const REDIRECT: &str = "http://127.0.0.1:53121/callback";
pub const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP0123456789";

pub async fn invite(db: &TestDb, owner: &db::Caller) -> String {
    match db::create_invite(&db.runtime, owner, "member", None).await {
        Ok(db::Wrote::Fresh(issued)) => issued.token,
        _ => panic!("invite"),
    }
}

/// `POST /v1/auth/start`: the pending sign-in's state and the page it sends the browser to.
pub async fn start(app: &Router, invite: Option<&str>) -> (String, String) {
    start_as(app, invite, None).await
}

/// [`start`] naming the sign-in method. Where it goes depends on what the owner chose: with
/// `provider` stored, `"provider": "passkey"` is refused; with `any`, it opens the passkey page.
pub async fn start_as(
    app: &Router,
    invite: Option<&str>,
    provider: Option<&str>,
) -> (String, String) {
    let mut body = json!({
        "redirect_uri": REDIRECT,
        "code_challenge": db::s256(VERIFIER),
        "code_challenge_method": "S256",
        "state": "client-state-0123456789abcdef",
    });
    if let Some(invite) = invite {
        body["invite"] = json!(invite);
    }
    if let Some(provider) = provider {
        body["provider"] = json!(provider);
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
pub async fn redeem(app: &Router, redirect: &str) -> (String, String) {
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

/// Sign-up with an invite, all the way to a session.
pub async fn sign_up(
    app: &Router,
    db: &TestDb,
    device: &mut Device,
    invite: &str,
    name: &str,
) -> Account {
    // Always names the passkey page: the same on a passkey-only deployment, and the only way
    // onto it when a provider is configured too.
    let (state, path) = start_as(app, Some(invite), Some("passkey")).await;
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
