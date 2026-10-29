//! A tiny OpenID Connect provider on a real port: discovery, keys, and a token endpoint that
//! checks the client's credentials and PKCE and signs an ID token. It also mints back-channel
//! logout tokens. The test plays the browser: it reads the authorization URL tinyserver built
//! and hands the provider a code for it.
//!
//! The RSA keys in `tests/fixtures` exist only for these tests.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use axum::extract::{Form, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use openidconnect::core::{CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey};
use openidconnect::{JsonWebKey, JsonWebKeyId, PrivateSigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::task::JoinHandle;

pub const CLIENT_ID: &str = "tinyserver";
pub const CLIENT_SECRET: &str = "test-client-secret";
pub const PUBLIC_URL: &str = "https://chat.tinyserver.test";
pub const PROVIDER_NAME: &str = "Test provider";
pub const LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

const KEY_A: &str = include_str!("../fixtures/oidc-key-a.pem");
const KEY_B: &str = include_str!("../fixtures/oidc-key-b.pem");
/// tinyserver's own key for `private_key_jwt`.
pub const CLIENT_KEY: &str = include_str!("../fixtures/oidc-client-key.pem");

/// Who signs in at the provider.
#[derive(Clone)]
pub struct Person {
    pub subject: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub groups: Option<Value>,
    pub sid: Option<String>,
}

impl Person {
    pub fn new(subject: &str) -> Self {
        Self {
            subject: subject.to_string(),
            email: Some(format!("{subject}@provider.test")),
            name: Some(format!("Person {subject}")),
            groups: None,
            sid: None,
        }
    }

    pub fn groups(mut self, groups: &[&str]) -> Self {
        self.groups = Some(json!(groups));
        self
    }

    pub fn sid(mut self, sid: &str) -> Self {
        self.sid = Some(sid.to_string());
        self
    }
}

/// What the provider gets wrong in the ID token it signs.
#[derive(Clone, Default)]
pub struct Tamper {
    pub issuer: Option<String>,
    pub audiences: Option<Vec<String>>,
    pub authorized_party: Option<String>,
    pub nonce: Option<String>,
    /// `alg: none`, no signature.
    pub unsigned: bool,
    /// Signed with key `b` while the key set has only `a`.
    pub unpublished_key: bool,
    pub expired: bool,
}

/// How the client authenticated at the token endpoint, as the provider saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientAuth {
    Basic,
    Post,
    /// `private_key_jwt`, with the assertion's claims.
    PrivateKeyJwt(Value),
}

struct Grant {
    nonce: String,
    challenge: String,
    redirect_uri: String,
    person: Person,
    tamper: Tamper,
}

struct Inner {
    issuer: String,
    /// Key ids in the key set, `a` and maybe `b`.
    published: Vec<&'static str>,
    /// The key id new tokens are signed with.
    signing: &'static str,
    grants: HashMap<String, Grant>,
    jwks_reads: usize,
    discovery_reads: usize,
    token_requests: usize,
    next_code: u64,
    methods: Vec<&'static str>,
    client_auth: Option<ClientAuth>,
}

pub struct Provider {
    /// What the provider calls itself and puts in `iss`.
    pub issuer: String,
    /// Where it actually listens. The same as `issuer` unless started with a public issuer.
    pub address: String,
    inner: Arc<Mutex<Inner>>,
    task: JoinHandle<()>,
}

impl Drop for Provider {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Provider {
    /// Listens on `127.0.0.1` and is its own issuer.
    pub async fn start() -> Self {
        Self::launch(None, &["client_secret_basic", "client_secret_post"]).await
    }

    /// Listens on `127.0.0.1` but says its issuer is `issuer`, with every endpoint there, as
    /// Tinyauth does behind a tunnel. Reach it through an internal URL.
    pub async fn start_public(issuer: &str) -> Self {
        Self::launch(
            Some(issuer.to_string()),
            &["client_secret_basic", "client_secret_post"],
        )
        .await
    }

    /// Offers only these client authentication methods in discovery.
    pub async fn start_with_methods(methods: &[&'static str]) -> Self {
        Self::launch(None, methods).await
    }

    async fn launch(issuer: Option<String>, methods: &[&'static str]) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind provider");
        let address = format!("http://{}", listener.local_addr().expect("address"));
        let issuer = issuer.unwrap_or_else(|| address.clone());
        let inner = Arc::new(Mutex::new(Inner {
            issuer: issuer.clone(),
            published: vec!["a"],
            signing: "a",
            grants: HashMap::new(),
            jwks_reads: 0,
            discovery_reads: 0,
            token_requests: 0,
            next_code: 0,
            methods: methods.to_vec(),
            client_auth: None,
        }));
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/token", post(token))
            .with_state(inner.clone());
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            issuer,
            address,
            inner,
            task,
        }
    }

    /// This provider as `id`, with a client secret.
    pub fn provider_config(&self, id: &str) -> api::ProviderConfig {
        api::ProviderConfig {
            id: id.to_string(),
            issuer: self.issuer.clone(),
            client_id: CLIENT_ID.to_string(),
            client_secret: Some(CLIENT_SECRET.to_string()),
            private_key_pem: None,
            private_key_id: None,
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            name: Some(PROVIDER_NAME.to_string()),
            internal_url: (self.address != self.issuer).then(|| self.address.clone()),
            groups_claim: None,
            admin_groups: Vec::new(),
            member_groups: Vec::new(),
            signup: None,
        }
    }

    pub fn config(&self) -> api::SignInConfig {
        config(vec![self.provider_config("default")])
    }

    pub async fn sign_in(&self) -> api::SignIn {
        api::SignIn::discover(self.config())
            .await
            .expect("discover the test provider")
    }

    /// Publishes key `b` next to `a` and signs with `b` from now on.
    pub fn rotate(&self) {
        let mut inner = lock(&self.inner);
        inner.published = vec!["a", "b"];
        inner.signing = "b";
    }

    pub fn jwks_reads(&self) -> usize {
        lock(&self.inner).jwks_reads
    }

    pub fn discovery_reads(&self) -> usize {
        lock(&self.inner).discovery_reads
    }

    pub fn token_requests(&self) -> usize {
        lock(&self.inner).token_requests
    }

    pub fn client_auth(&self) -> Option<ClientAuth> {
        lock(&self.inner).client_auth.clone()
    }

    /// Plays the provider's authorization page: checks the request tinyserver built and returns
    /// the code and state the browser would bring to the callback.
    pub fn authorize(
        &self,
        authorize_url: &str,
        person: Person,
        tamper: Tamper,
    ) -> (String, String) {
        let url = url::Url::parse(authorize_url).expect("authorize url");
        assert_eq!(
            format!("{}://{}", url.scheme(), url.authority()),
            self.issuer,
            "the browser goes to the provider's public address"
        );
        assert_eq!(url.path(), "/authorize");
        let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
        assert_eq!(query["response_type"], "code");
        assert_eq!(query["client_id"], CLIENT_ID);
        assert_eq!(query["code_challenge_method"], "S256");
        assert_eq!(
            query["redirect_uri"],
            format!("{PUBLIC_URL}/v1/auth/callback")
        );
        let scopes: Vec<&str> = query["scope"].split(' ').collect();
        for scope in ["openid", "profile", "email"] {
            assert!(scopes.contains(&scope), "{scopes:?}");
        }
        assert!(query["state"].len() >= 32);
        assert!(query["nonce"].len() >= 32);

        let mut inner = lock(&self.inner);
        inner.next_code += 1;
        let code = format!("provider-code-{}", inner.next_code);
        inner.grants.insert(
            code.clone(),
            Grant {
                nonce: query["nonce"].clone(),
                challenge: query["code_challenge"].clone(),
                redirect_uri: query["redirect_uri"].clone(),
                person,
                tamper,
            },
        );
        (code, query["state"].clone())
    }

    /// A logout token signed with the current key: `iss`, `aud`, `iat`, `jti`, the logout
    /// event, then `changes` laid over it. A `null` in `changes` removes the claim.
    pub fn logout_token(&self, changes: Value) -> String {
        let (issuer, signing) = {
            let inner = lock(&self.inner);
            (inner.issuer.clone(), inner.signing)
        };
        let mut claims = json!({
            "iss": issuer,
            "aud": CLIENT_ID,
            "iat": chrono::Utc::now().timestamp(),
            "jti": format!("jti-{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()),
            "events": { LOGOUT_EVENT: {} },
        });
        if let (Some(claims), Some(changes)) = (claims.as_object_mut(), changes.as_object()) {
            for (name, value) in changes {
                if value.is_null() {
                    claims.remove(name);
                } else {
                    claims.insert(name.clone(), value.clone());
                }
            }
        }
        sign_jwt(
            &json!({"alg": "RS256", "typ": "logout+jwt", "kid": signing}),
            &claims,
            signing,
        )
    }
}

/// Sign-in with these providers, the first the default.
pub fn config(providers: Vec<api::ProviderConfig>) -> api::SignInConfig {
    api::SignInConfig {
        public_url: PUBLIC_URL.to_string(),
        session_days: 30,
        providers,
    }
}

fn lock(inner: &Mutex<Inner>) -> MutexGuard<'_, Inner> {
    inner.lock().unwrap_or_else(|poison| poison.into_inner())
}

fn key(kid: &'static str) -> CoreRsaPrivateSigningKey {
    let pem = match kid {
        "a" => KEY_A,
        "b" => KEY_B,
        _ => CLIENT_KEY,
    };
    CoreRsaPrivateSigningKey::from_pem(pem, Some(JsonWebKeyId::new(kid.to_string())))
        .expect("test key")
}

/// A compact JWS over `header` and `claims`, signed RS256 with test key `kid`.
pub fn sign_jwt(header: &Value, claims: &Value, kid: &'static str) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature = key(kid)
        .sign(
            &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            input.as_bytes(),
        )
        .expect("sign");
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

async fn discovery(State(inner): State<Arc<Mutex<Inner>>>) -> Json<Value> {
    let mut inner = lock(&inner);
    inner.discovery_reads += 1;
    let issuer = inner.issuer.clone();
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": inner.methods,
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true,
    }))
}

async fn jwks(State(inner): State<Arc<Mutex<Inner>>>) -> Json<Value> {
    let mut inner = lock(&inner);
    inner.jwks_reads += 1;
    let keys: Vec<Value> = inner
        .published
        .iter()
        .map(|kid| serde_json::to_value(key(kid).as_verification_key()).expect("jwk"))
        .collect();
    Json(json!({ "keys": keys }))
}

fn refuse(error: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": error }))).into_response()
}

/// The client's credentials, checked the way the discovery document says it may send them.
fn client_auth(
    issuer: &str,
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> Option<ClientAuth> {
    let basic = format!(
        "Basic {}",
        STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"))
    );
    if headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        == Some(basic.as_str())
    {
        return Some(ClientAuth::Basic);
    }
    if form.get("client_id").map(String::as_str) == Some(CLIENT_ID)
        && form.get("client_secret").map(String::as_str) == Some(CLIENT_SECRET)
    {
        return Some(ClientAuth::Post);
    }
    let assertion_type = form.get("client_assertion_type").map(String::as_str);
    let assertion = form.get("client_assertion")?;
    if assertion_type != Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer") {
        return None;
    }
    let mut parts = assertion.split('.');
    let (Some(head), Some(body), Some(signature)) = (parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(head).ok()?).ok()?;
    if header["alg"] != "RS256" {
        return None;
    }
    let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
    key("client")
        .as_verification_key()
        .verify_signature(
            &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            format!("{head}.{body}").as_bytes(),
            &signature,
        )
        .ok()?;
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(body).ok()?).ok()?;
    let now = chrono::Utc::now().timestamp();
    let fits = claims["iss"] == CLIENT_ID
        && claims["sub"] == CLIENT_ID
        && claims["aud"] == format!("{issuer}/token")
        && claims["jti"].is_string()
        && claims["exp"].as_i64().is_some_and(|exp| exp > now)
        && form.get("client_id").map(String::as_str) == Some(CLIENT_ID)
        && !form.contains_key("client_secret");
    fits.then_some(ClientAuth::PrivateKeyJwt(claims))
}

async fn token(
    State(inner): State<Arc<Mutex<Inner>>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let issuer = {
        let mut inner = lock(&inner);
        inner.token_requests += 1;
        inner.issuer.clone()
    };
    let Some(auth) = client_auth(&issuer, &headers, &form) else {
        return refuse("invalid_client");
    };
    lock(&inner).client_auth = Some(auth);
    if form.get("grant_type").map(String::as_str) != Some("authorization_code") {
        return refuse("unsupported_grant_type");
    }
    let (signing, grant) = {
        let mut inner = lock(&inner);
        let Some(grant) = form.get("code").and_then(|code| inner.grants.remove(code)) else {
            return refuse("invalid_grant");
        };
        (inner.signing, grant)
    };
    if form.get("redirect_uri") != Some(&grant.redirect_uri) {
        return refuse("invalid_grant");
    }
    // The server's leg of PKCE.
    let verifier = form.get("code_verifier").cloned().unwrap_or_default();
    if URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) != grant.challenge {
        return refuse("invalid_grant");
    }

    let tamper = &grant.tamper;
    let now = chrono::Utc::now().timestamp();
    let (issued, expires) = if tamper.expired {
        (now - 120, now - 60)
    } else {
        (now, now + 300)
    };
    let mut claims = json!({
        "iss": tamper.issuer.clone().unwrap_or(issuer),
        "aud": tamper.audiences.clone().unwrap_or_else(|| vec![CLIENT_ID.to_string()]),
        "sub": grant.person.subject,
        "iat": issued,
        "exp": expires,
        "nonce": tamper.nonce.clone().unwrap_or(grant.nonce.clone()),
    });
    let extra = [
        ("email", grant.person.email.clone().map(Value::String)),
        ("name", grant.person.name.clone().map(Value::String)),
        ("groups", grant.person.groups.clone()),
        ("sid", grant.person.sid.clone().map(Value::String)),
        ("azp", tamper.authorized_party.clone().map(Value::String)),
    ];
    for (name, value) in extra {
        if let (Some(value), Some(claims)) = (value, claims.as_object_mut()) {
            claims.insert(name.to_string(), value);
        }
    }

    let id_token = if tamper.unsigned {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
        format!("{header}.{payload}.")
    } else {
        let kid = if tamper.unpublished_key { "b" } else { signing };
        sign_jwt(
            &json!({"alg": "RS256", "typ": "JWT", "kid": kid}),
            &claims,
            kid,
        )
    };
    Json(json!({
        "access_token": "provider-access-token",
        "token_type": "Bearer",
        "expires_in": 300,
        "id_token": id_token,
    }))
    .into_response()
}
