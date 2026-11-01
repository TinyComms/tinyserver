//! Built-in passkey sign-in (WebAuthn), for a community that has no identity provider of its own.
//!
//! A passkey is one more source of `(issuer, subject)`, beside OpenID Connect. Invites, bans,
//! roles, sessions and account deletion are the machinery `auth.rs` already runs; this module
//! only proves who is signing in and then hands the browser back to tinyclient exactly as the
//! OIDC callback does, so tinyclient needs no change.
//!
//! `POST /v1/auth/start` opens a pending sign-in as before and returns this page's address.
//! The page runs a ceremony: `begin` makes a challenge and keeps its state in Postgres under a
//! random id the page holds, `finish` spends that state (a challenge works once) and checks the
//! browser's answer with `webauthn-rs`. Nothing here implements WebAuthn or any cryptography.
//!
//! Stored about a person: the credential's public half, its counter and flags, and a label.
//! Never an address, a user agent, an email or a phone number. Recovery codes and claim links
//! are kept only as hashes, and no secret, challenge or credential id is ever logged.
//!
//! The pages are the only place that run script: one fixed inline script, named in the policy by
//! its hash, which loads nothing and talks only to this server.

use std::sync::{Arc, LazyLock};

use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{Extension, Json, Router};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use db::{
    AuthError, Ceremony, Claim, NewCeremony, NewCredential, PasskeyError, PendingPeek, PgPool,
    Recovery, Signup, CEREMONY_SECS, PASSKEY_ISSUER, RECOVERY_CODES,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;
use webauthn_rs::prelude::{
    CredentialID, DiscoverableAuthentication, Passkey, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Uuid, Webauthn, WebauthnBuilder, WebauthnError,
};

use crate::auth::{client_url, escape, expired, server_trouble, Outcome, STYLE};
use crate::community::{caller, lift, ApiError};
use crate::oidc::{ConfigError, SignIn};

/// The provider id passkeys go by in `GET /v1/auth/config` and `POST /v1/auth/start`.
pub const PROVIDER_ID: &str = "passkey";

/// How recently someone must have signed in to add or remove a way of signing in.
const RECENT_SECS: i32 = 600;

/// A claim link made by the person themself, for another device of theirs.
const SELF_LINK_SECS: i32 = 3600;

/// The label a passkey gets when the person gave none.
const DEFAULT_LABEL: &str = "Passkey";

#[derive(Clone)]
pub struct Passkeys {
    webauthn: Arc<Webauthn>,
}

impl Passkeys {
    /// The relying party is the host of `public_url` unless `rp_id` names a domain above it. A
    /// passkey works only for the relying party it was made for, so changing either one later
    /// stops every passkey working: pick `rp_id` before anyone enrols.
    pub fn new(public_url: &str, rp_name: &str, rp_id: Option<&str>) -> Result<Self, ConfigError> {
        let origin = Url::parse(public_url)
            .map_err(|_| ConfigError::fatal("TINYSERVER_PUBLIC_URL is not a URL"))?;
        let host = origin
            .host_str()
            .ok_or_else(|| ConfigError::fatal("TINYSERVER_PUBLIC_URL has no host"))?
            .to_ascii_lowercase();
        let rp_id = match rp_id.map(|id| id.trim().trim_end_matches('.').to_ascii_lowercase()) {
            None => host,
            Some(id) if id.is_empty() => host,
            Some(id) => {
                // The WebAuthn rule: the host itself, or a registrable domain above it.
                let above = host.ends_with(&format!(".{id}")) && id.contains('.');
                if id != host && !above {
                    return Err(ConfigError::fatal(
                        "TINYSERVER_PASSKEY_RP_ID must be the host of TINYSERVER_PUBLIC_URL \
                         or a domain above it, such as example.org",
                    ));
                }
                id
            }
        };
        let webauthn = WebauthnBuilder::new(&rp_id, &origin)
            .map_err(|error| ConfigError::fatal(format!("passkey relying party: {error}")))?
            .rp_name(rp_name)
            .build()
            .map_err(|error| ConfigError::fatal(format!("passkey relying party: {error}")))?;
        Ok(Self {
            webauthn: Arc::new(webauthn),
        })
    }
}

/// The address of the sign-in page for the pending sign-in `state`.
pub(crate) fn page_url(public_url: &str, state: &str) -> String {
    let mut url = format!("{public_url}/v1/auth/passkey");
    if let Ok(mut parsed) = Url::parse(&url) {
        parsed.query_pairs_mut().append_pair("state", state);
        url = parsed.to_string();
    }
    url
}

pub(crate) fn routes() -> Router<PgPool> {
    let flow = Router::new()
        .route("/v1/auth/passkey", get(signin_page))
        .route("/v1/auth/passkey/claim", get(claim_page))
        .route("/v1/auth/passkey/login/begin", post(login_begin))
        .route("/v1/auth/passkey/login/finish", post(login_finish))
        .route("/v1/auth/passkey/signup/begin", post(signup_begin))
        .route("/v1/auth/passkey/signup/finish", post(signup_finish))
        .route("/v1/auth/passkey/recover/begin", post(recover_begin))
        .route("/v1/auth/passkey/recover/finish", post(recover_finish))
        .route("/v1/auth/passkey/claim/peek", post(claim_peek))
        .route("/v1/auth/passkey/claim/begin", post(claim_begin))
        .route("/v1/auth/passkey/claim/finish", post(claim_finish))
        .route("/v1/auth/passkey/continue", post(continue_sign_in))
        // An attestation is a few KiB; the router's default is 8.
        .layer(DefaultBodyLimit::max(16 * 1024));
    let mine = Router::new()
        .route("/v1/me/passkeys", get(list_mine))
        .route(
            "/v1/me/passkeys/{id}",
            patch(rename_mine).delete(remove_mine),
        )
        .route("/v1/me/passkeys/link", post(link_mine))
        .route("/v1/me/recovery-codes", post(new_codes));
    flow.merge(mine)
}

// What the browser is sent and sends back.

#[derive(Serialize)]
struct Options {
    /// The id of the ceremony the browser holds until it calls `finish`.
    cid: String,
    options: Value,
}

#[derive(Serialize)]
struct Redirect {
    redirect: String,
}

#[derive(Serialize)]
struct Recorded {
    codes: Vec<String>,
    cont: String,
}

#[derive(Deserialize)]
struct StateBody {
    state: String,
}

#[derive(Deserialize)]
struct SignupBegin {
    state: String,
    display_name: String,
}

#[derive(Deserialize)]
struct LoginFinish {
    state: String,
    cid: String,
    credential: PublicKeyCredential,
}

#[derive(Deserialize)]
struct SignupFinish {
    state: String,
    cid: String,
    credential: RegisterPublicKeyCredential,
    label: Option<String>,
}

#[derive(Deserialize)]
struct RecoverBegin {
    state: String,
    code: String,
}

#[derive(Deserialize)]
struct RecoverFinish {
    state: String,
    cid: String,
    code: String,
    credential: RegisterPublicKeyCredential,
    label: Option<String>,
}

#[derive(Deserialize)]
struct TokenBody {
    token: String,
}

#[derive(Deserialize)]
struct ClaimFinish {
    token: String,
    cid: String,
    credential: RegisterPublicKeyCredential,
    label: Option<String>,
}

#[derive(Deserialize)]
struct ContinueBody {
    state: String,
    cont: String,
}

/// Why a call was refused, as the page reads it.
struct Failure {
    status: StatusCode,
    error: &'static str,
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        (self.status, Json(ErrorBody { error: self.error })).into_response()
    }
}

fn bad(error: &'static str) -> Failure {
    Failure {
        status: StatusCode::BAD_REQUEST,
        error,
    }
}

fn unavailable() -> Failure {
    Failure {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        error: "unavailable",
    }
}

/// A database failure, as the page reads it. The cause is logged, never the data.
fn failed(error: PasskeyError) -> Failure {
    match error {
        PasskeyError::NotFound => bad("expired"),
        PasskeyError::Taken => bad("credential_taken"),
        PasskeyError::Busy => Failure {
            status: StatusCode::SERVICE_UNAVAILABLE,
            error: "busy",
        },
        PasskeyError::Refused | PasskeyError::Invalid => bad("invalid"),
        PasskeyError::Auth(AuthError::NotMember) => bad("invite_unusable"),
        PasskeyError::Auth(AuthError::Banned) => bad("banned"),
        PasskeyError::Auth(_) | PasskeyError::Database(_) => {
            tracing::warn!(%error, "passkey call failed");
            unavailable()
        }
    }
}

fn logged(error: impl std::fmt::Display, what: &'static str) -> Failure {
    tracing::warn!(%error, "{what}");
    unavailable()
}

fn enabled(sign_in: &SignIn) -> Result<&Passkeys, Failure> {
    sign_in.passkeys().ok_or_else(|| bad("invalid"))
}

/// 1 to `max` characters from the URL-safe base64 alphabet: what this server makes for a
/// sign-in state, a ceremony id and a claim token.
fn shaped(text: &str, max: usize) -> bool {
    (1..=max).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn display_name(text: &str) -> Option<String> {
    let name: String = text.trim().chars().filter(|c| !c.is_control()).collect();
    let name = name.trim().to_string();
    (1..=80).contains(&name.chars().count()).then_some(name)
}

fn label(text: Option<&str>) -> String {
    text.map(str::trim)
        .filter(|text| {
            !text.is_empty() && text.chars().count() <= 60 && !text.chars().any(char::is_control)
        })
        .unwrap_or(DEFAULT_LABEL)
        .to_string()
}

/// A random account id. Passkeys carry it as the user handle, so a sign-in can start with no
/// username: the browser offers the passkeys it has for this site and names the account.
fn new_subject() -> Uuid {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("the OS random number generator failed");
    Uuid::from_bytes(bytes)
}

// The options the browser needs, with the two things the library leaves to the caller.

/// Registration options. The library asks for a resident key as "not required", and a hardware
/// key then makes a credential that cannot sign in without a username. This server has no
/// username to ask for, so the credential must be discoverable.
fn creation_options(options: &impl Serialize) -> Value {
    let mut value = serde_json::to_value(options).unwrap_or(Value::Null);
    if let Some(selection) = value
        .pointer_mut("/publicKey/authenticatorSelection")
        .and_then(Value::as_object_mut)
    {
        selection.insert("residentKey".to_string(), Value::from("required"));
        selection.insert("requireResidentKey".to_string(), Value::from(true));
    }
    value
}

/// Sign-in options. The library marks them for the browser's autofill (conditional mediation),
/// which only works behind an input field; this page asks with a button.
fn request_options(options: &impl Serialize) -> Value {
    let mut value = serde_json::to_value(options).unwrap_or(Value::Null);
    if let Some(object) = value.as_object_mut() {
        object.remove("mediation");
    }
    value
}

// Ceremony helpers.

async fn pending(pool: &PgPool, state: &str) -> Result<PendingPeek, Failure> {
    if !shaped(state, 256) {
        return Err(bad("expired"));
    }
    match db::peek_pending(pool, state).await {
        Ok(Some(pending)) => Ok(pending),
        Ok(None) => Err(bad("expired")),
        Err(error) => Err(logged(error, "pending sign-in not read")),
    }
}

async fn spend(
    pool: &PgPool,
    kind: &'static str,
    cid: &str,
    state: Option<&str>,
) -> Result<Ceremony, Failure> {
    if !shaped(cid, 128) {
        return Err(bad("expired"));
    }
    let ceremony = db::take_ceremony(pool, kind, cid)
        .await
        .map_err(failed)?
        .ok_or_else(|| bad("expired"))?;
    if state.is_some_and(|state| !ceremony.belongs_to(state)) {
        return Err(bad("expired"));
    }
    Ok(ceremony)
}

fn registration_state(ceremony: &Ceremony) -> Result<PasskeyRegistration, Failure> {
    ceremony
        .state
        .clone()
        .and_then(|state| serde_json::from_value(state).ok())
        .ok_or_else(|| bad("expired"))
}

/// What the library says about a registration, as the page reads it.
fn registration_failure(error: &WebauthnError) -> Failure {
    tracing::info!(%error, "passkey registration refused");
    bad("invalid")
}

/// The parts of a new credential the database keeps. The library's own serialisation is what
/// the next sign-in is checked against; the counter and flags are read back out of it.
struct Made {
    passkey: Passkey,
    json: Value,
}

impl Made {
    fn new(passkey: Passkey) -> Result<Self, Failure> {
        let json = serde_json::to_value(&passkey).map_err(|error| logged(error, "passkey"))?;
        Ok(Self { passkey, json })
    }

    fn flag(&self, name: &str) -> bool {
        self.json
            .pointer(&format!("/cred/{name}"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }

    fn credential<'a>(&'a self, label: &'a str) -> NewCredential<'a> {
        NewCredential {
            credential_id: self.passkey.cred_id().as_ref(),
            passkey: &self.json,
            sign_count: self
                .json
                .pointer("/cred/counter")
                .and_then(Value::as_i64)
                .unwrap_or(0),
            backup_eligible: self.flag("backup_eligible"),
            backup_state: self.flag("backup_state"),
            label,
        }
    }
}

fn exclusions(ids: Vec<Vec<u8>>) -> Option<Vec<CredentialID>> {
    (!ids.is_empty()).then_some(ids)
}

/// Ends a sign-in: spends the pending state and sends tinyclient its one-time code, or the
/// reason it was refused, as the OIDC callback does.
async fn hand_back(pool: &PgPool, state: &str, subject: &str) -> Result<Json<Redirect>, Failure> {
    let pending = db::take_pending(pool, state)
        .await
        .map_err(|error| logged(error, "pending sign-in not read"))?
        .ok_or_else(|| bad("expired"))?;
    let profile = db::Profile {
        issuer: PASSKEY_ISSUER.to_string(),
        subject: subject.to_string(),
        email: None,
        name: None,
        sid: None,
    };
    let to_client = |outcome: Outcome| {
        client_url(&pending.client_redirect, &pending.client_state, &outcome)
            .map(|redirect| Json(Redirect { redirect }))
            .ok_or_else(unavailable)
    };
    let signed_in = match db::sign_in(
        pool,
        &profile,
        pending.invite_hash.as_deref(),
        db::Groups::default(),
    )
    .await
    {
        Ok(signed_in) => signed_in,
        Err(AuthError::NotMember) => {
            tracing::info!("sign-in refused: not a member");
            return to_client(Outcome::Error("not_member"));
        }
        Err(AuthError::Banned) => {
            tracing::info!("sign-in refused: banned");
            return to_client(Outcome::Error("banned"));
        }
        Err(error) => {
            tracing::warn!(%error, "sign-in not recorded");
            return to_client(Outcome::Error("failed"));
        }
    };
    let code = db::issue_code(
        pool,
        &signed_in.user_id,
        &pending.client_challenge,
        PASSKEY_ISSUER,
        None,
    )
    .await
    .map_err(|error| logged(error, "one-time code not saved"))?;
    tracing::info!(
        user_id = %signed_in.user_id,
        role = %signed_in.role,
        joined = signed_in.joined,
        "signed in with a passkey"
    );
    to_client(Outcome::Code(code))
}

// Sign-in.

async fn login_begin(
    State(pool): State<PgPool>,
    Extension(sign_in): Extension<SignIn>,
    body: Result<Json<StateBody>, JsonRejection>,
) -> Result<Json<Options>, Failure> {
    let passkeys = enabled(&sign_in)?;
    let Json(body) = body.map_err(|_| bad("invalid"))?;
    pending(&pool, &body.state).await?;
    let (challenge, state) = passkeys
        .webauthn
        .start_discoverable_authentication()
        .map_err(|error| logged(error, "passkey challenge"))?;
    let state_json =
        serde_json::to_value(&state).map_err(|error| logged(error, "passkey state"))?;
    let cid = db::random_id();
    db::begin_ceremony(
        &pool,
        &NewCeremony {
            kind: "login",
            id: &cid,
            state: Some(&state_json),
            user: None,
            subject: None,
            pending: Some(&body.state),
            display_name: None,
            secret: None,
            ttl_secs: CEREMONY_SECS,
        },
    )
    .await
    .map_err(failed)?;
    Ok(Json(Options {
        cid,
        options: request_options(&challenge),
    }))
}

async fn login_finish(
    State(pool): State<PgPool>,
    Extension(sign_in): Extension<SignIn>,
    body: Result<Json<LoginFinish>, JsonRejection>,
) -> Result<Json<Redirect>, Failure> {
    let passkeys = enabled(&sign_in)?;
    let Json(body) = body.map_err(|_| bad("invalid"))?;
    let ceremony = spend(&pool, "login", &body.cid, Some(&body.state)).await?;
    let state: DiscoverableAuthentication = ceremony
        .state
        .and_then(|state| serde_json::from_value(state).ok())
        .ok_or_else(|| bad("expired"))?;
    let (handle, credential_id) = passkeys
        .webauthn
        .identify_discoverable_authentication(&body.credential)
        .map_err(|_| bad("invalid"))?;
    let found = db::find_credential(&pool, credential_id)
        .await
        .map_err(failed)?
        .ok_or_else(|| bad("invalid"))?;
    // The user handle the authenticator holds must be the account this credential belongs to.
    if found.subject != handle.to_string() {
        tracing::warn!("passkey refused: user handle does not match its account");
        return Err(bad("invalid"));
    }
    if found.flagged {
        return Err(bad("flagged"));
    }
    let mut passkey: Passkey =
        serde_json::from_value(found.passkey.clone()).map_err(|error| logged(error, "passkey"))?;
    let result = match passkeys.webauthn.finish_discoverable_authentication_v2(
        &body.credential,
        state,
        &passkey,
    ) {
        Ok(result) => result,
        Err(WebauthnError::CredentialPossibleCompromise) => {
            // A valid signature, with a counter that did not go up: possibly a cloned
            // authenticator. It is turned off until its owner removes it.
            tracing::warn!(user_id = %found.user_id, "passkey flagged: its counter went back");
            db::flag_credential(&pool, &found.id)
                .await
                .map_err(failed)?;
            return Err(bad("flagged"));
        }
        Err(error) => {
            tracing::info!(%error, "passkey assertion refused");
            return Err(bad("invalid"));
        }
    };
    passkey.update_credential(&result);
    let json = serde_json::to_value(&passkey).map_err(|error| logged(error, "passkey"))?;
    db::record_use(
        &pool,
        &found.id,
        &json,
        i64::from(result.counter()),
        result.backup_eligible(),
        result.backup_state(),
    )
    .await
    .map_err(failed)?;
    hand_back(&pool, &body.state, &found.subject).await
}

// Sign-up with an invite.

async fn signup_begin(
    State(pool): State<PgPool>,
    Extension(sign_in): Extension<SignIn>,
    body: Result<Json<SignupBegin>, JsonRejection>,
) -> Result<Json<Options>, Failure> {
    let passkeys = enabled(&sign_in)?;
    let Json(body) = body.map_err(|_| bad("invalid"))?;
    let pending = pending(&pool, &body.state).await?;
    let Some(invite_hash) = pending.invite_hash else {
        return Err(bad("no_invite"));
    };
    if !db::invite_usable(&pool, &invite_hash)
        .await
        .map_err(|error| logged(error, "invite not read"))?
    {
        return Err(bad("invite_unusable"));
    }
    let name = display_name(&body.display_name).ok_or_else(|| bad("invalid"))?;
    let subject = new_subject();
    let (challenge, registration) = passkeys
        .webauthn
        .start_passkey_registration(subject, &name, &name, None)
        .map_err(|error| logged(error, "passkey challenge"))?;
    let state_json =
        serde_json::to_value(&registration).map_err(|error| logged(error, "passkey state"))?;
    let cid = db::random_id();
    db::begin_ceremony(
        &pool,
        &NewCeremony {
            kind: "signup",
            id: &cid,
            state: Some(&state_json),
            user: None,
            subject: Some(&subject.to_string()),
            pending: Some(&body.state),
            display_name: Some(&name),
            secret: None,
            ttl_secs: CEREMONY_SECS,
        },
    )
    .await
    .map_err(failed)?;
    Ok(Json(Options {
        cid,
        options: creation_options(&challenge),
    }))
}

async fn signup_finish(
    State(pool): State<PgPool>,
    Extension(sign_in): Extension<SignIn>,
    body: Result<Json<SignupFinish>, JsonRejection>,
) -> Result<Json<Recorded>, Failure> {
    let passkeys = enabled(&sign_in)?;
    let Json(body) = body.map_err(|_| bad("invalid"))?;
    let ceremony = spend(&pool, "signup", &body.cid, Some(&body.state)).await?;
    let (Some(subject), Some(name)) = (ceremony.subject.clone(), ceremony.display_name.clone())
    else {
        return Err(bad("expired"));
    };
    let registration = registration_state(&ceremony)?;
    let made = Made::new(
        passkeys
            .webauthn
            .finish_passkey_registration(&body.credential, &registration)
            .map_err(|error| registration_failure(&error))?,
    )?;
    let pending = pending(&pool, &body.state).await?;
    let invite_hash = pending.invite_hash.ok_or_else(|| bad("no_invite"))?;
    let codes = db::new_recovery_codes(RECOVERY_CODES);
    let label = label(body.label.as_deref());
    let signed_in = db::signup(
        &pool,
        &Signup {
            subject: &subject,
            display_name: &name,
            invite_hash: &invite_hash,
            credential: &made.credential(&label),
            codes: &codes,
        },
    )
    .await
    .map_err(failed)?;
    tracing::info!(user_id = %signed_in.user_id, "account made with a passkey");
    let cont = db::random_id();
    db::begin_continue(&pool, &cont, &signed_in.user_id, &subject, &body.state)
        .await
        .map_err(failed)?;
    Ok(Json(Recorded { codes, cont }))
}

/// The step after a passkey is made and its recovery codes are shown: tinyclient gets its code.
async fn continue_sign_in(
    State(pool): State<PgPool>,
    Extension(sign_in): Extension<SignIn>,
    body: Result<Json<ContinueBody>, JsonRejection>,
) -> Result<Json<Redirect>, Failure> {
    enabled(&sign_in)?;
    let Json(body) = body.map_err(|_| bad("invalid"))?;
    let ceremony = spend(&pool, "continue", &body.cont, Some(&body.state)).await?;
    let subject = ceremony.subject.ok_or_else(|| bad("expired"))?;
    hand_back(&pool, &body.state, &subject).await
}

// A recovery code, when every passkey is lost.

async fn recover_begin(
    State(pool): State<PgPool>,
    Extension(sign_in): Extension<SignIn>,
    body: Result<Json<RecoverBegin>, JsonRejection>,
) -> Result<Json<Options>, Failure> {
    let passkeys = enabled(&sign_in)?;
    let Json(body) = body.map_err(|_| bad("invalid"))?;
    pending(&pool, &body.state).await?;
    let hash = db::recovery_hash(&body.code).ok_or_else(|| bad("invalid_code"))?;
    let user = db::recovery_owner(&pool, &hash)
        .await
        .map_err(failed)?
        .ok_or_else(|| bad("invalid_code"))?;
    let subject = db::subject_of(&pool, &user)
        .await
        .map_err(failed)?
        .ok_or_else(|| bad("invalid_code"))?;
    let handle = Uuid::parse_str(&subject).map_err(|error| logged(error, "passkey subject"))?;
    let name = db::display_name_of(&pool, &user)
        .await
        .map_err(failed)?
        .ok_or_else(|| bad("invalid_code"))?;
    let existing = db::credential_ids_of(&pool, &user).await.map_err(failed)?;
    let (challenge, registration) = passkeys
        .webauthn
        .start_passkey_registration(handle, &name, &name, exclusions(existing))
        .map_err(|error| logged(error, "passkey challenge"))?;
    let state_json =
        serde_json::to_value(&registration).map_err(|error| logged(error, "passkey state"))?;
    let cid = db::random_id();
    db::begin_ceremony(
        &pool,
        &NewCeremony {
            kind: "recover",
            id: &cid,
            state: Some(&state_json),
            user: Some(&user),
            subject: Some(&subject),
            pending: Some(&body.state),
            display_name: None,
            secret: Some(&hash),
            ttl_secs: CEREMONY_SECS,
        },
    )
    .await
    .map_err(failed)?;
    Ok(Json(Options {
        cid,
        options: creation_options(&challenge),
    }))
}

#[derive(Serialize)]
struct Recovered {
    codes_left: i32,
    cont: String,
}

async fn recover_finish(
    State(pool): State<PgPool>,
    Extension(sign_in): Extension<SignIn>,
    body: Result<Json<RecoverFinish>, JsonRejection>,
) -> Result<Json<Recovered>, Failure> {
    let passkeys = enabled(&sign_in)?;
    let Json(body) = body.map_err(|_| bad("invalid"))?;
    let ceremony = spend(&pool, "recover", &body.cid, Some(&body.state)).await?;
    let hash = db::recovery_hash(&body.code).ok_or_else(|| bad("invalid_code"))?;
    // The finishing call must carry the code the beginning one did.
    if !ceremony.has_secret(&hash) {
        return Err(bad("invalid_code"));
    }
    let (Some(user), Some(subject)) = (ceremony.user_id.clone(), ceremony.subject.clone()) else {
        return Err(bad("expired"));
    };
    let registration = registration_state(&ceremony)?;
    let made = Made::new(
        passkeys
            .webauthn
            .finish_passkey_registration(&body.credential, &registration)
            .map_err(|error| registration_failure(&error))?,
    )?;
    let label = label(body.label.as_deref());
    let codes_left = db::recover(
        &pool,
        &Recovery {
            code_hash: &hash,
            user_id: &user,
            subject: &subject,
            credential: &made.credential(&label),
        },
    )
    .await
    .map_err(|error| match error {
        // Spent by another try while this one was at the authenticator.
        PasskeyError::NotFound => bad("invalid_code"),
        other => failed(other),
    })?;
    tracing::info!(user_id = %user, codes_left, "recovery code used");
    let cont = db::random_id();
    db::begin_continue(&pool, &cont, &user, &subject, &body.state)
        .await
        .map_err(failed)?;
    Ok(Json(Recovered { codes_left, cont }))
}

// A claim link: an existing member's passkey, on their existing account.

#[derive(Serialize)]
struct Who {
    name: String,
    /// The server's own name and icon, so the page can say which community this is for.
    server: String,
    icon: Option<String>,
}

async fn claim_peek(
    State(pool): State<PgPool>,
    Extension(sign_in): Extension<SignIn>,
    body: Result<Json<TokenBody>, JsonRejection>,
) -> Result<Json<Who>, Failure> {
    enabled(&sign_in)?;
    let Json(body) = body.map_err(|_| bad("invalid_link"))?;
    if !shaped(&body.token, 128) {
        return Err(bad("invalid_link"));
    }
    let (_, name) = db::peek_claim(&pool, &body.token)
        .await
        .map_err(failed)?
        .ok_or_else(|| bad("invalid_link"))?;
    let face = db::server_face(&pool)
        .await
        .map_err(|error| failed(error.into()))?;
    let icon = face.icon.map(|(content_type, bytes)| {
        format!("data:{content_type};base64,{}", STANDARD.encode(bytes))
    });
    Ok(Json(Who {
        name,
        server: face.name,
        icon,
    }))
}

async fn claim_begin(
    State(pool): State<PgPool>,
    Extension(sign_in): Extension<SignIn>,
    body: Result<Json<TokenBody>, JsonRejection>,
) -> Result<Json<Options>, Failure> {
    let passkeys = enabled(&sign_in)?;
    let Json(body) = body.map_err(|_| bad("invalid_link"))?;
    if !shaped(&body.token, 128) {
        return Err(bad("invalid_link"));
    }
    let (user, name) = db::peek_claim(&pool, &body.token)
        .await
        .map_err(failed)?
        .ok_or_else(|| bad("invalid_link"))?;
    // A member who already has a passkey identity keeps it: a second passkey, same account.
    let subject = match db::subject_of(&pool, &user).await.map_err(failed)? {
        Some(subject) => subject,
        None => new_subject().to_string(),
    };
    let handle = Uuid::parse_str(&subject).map_err(|error| logged(error, "passkey subject"))?;
    let existing = db::credential_ids_of(&pool, &user).await.map_err(failed)?;
    let (challenge, registration) = passkeys
        .webauthn
        .start_passkey_registration(handle, &name, &name, exclusions(existing))
        .map_err(|error| logged(error, "passkey challenge"))?;
    let state_json =
        serde_json::to_value(&registration).map_err(|error| logged(error, "passkey state"))?;
    let cid = db::random_id();
    let secret = db::claim_hash(&body.token);
    db::begin_ceremony(
        &pool,
        &NewCeremony {
            kind: "claim",
            id: &cid,
            state: Some(&state_json),
            user: Some(&user),
            subject: Some(&subject),
            pending: None,
            display_name: None,
            secret: Some(&secret),
            ttl_secs: CEREMONY_SECS,
        },
    )
    .await
    .map_err(failed)?;
    Ok(Json(Options {
        cid,
        options: creation_options(&challenge),
    }))
}

#[derive(Serialize)]
struct Claimed {
    /// Recovery codes, when this was the member's first passkey. Shown once.
    codes: Option<Vec<String>>,
}

async fn claim_finish(
    State(pool): State<PgPool>,
    Extension(sign_in): Extension<SignIn>,
    body: Result<Json<ClaimFinish>, JsonRejection>,
) -> Result<Json<Claimed>, Failure> {
    let passkeys = enabled(&sign_in)?;
    let Json(body) = body.map_err(|_| bad("invalid"))?;
    let ceremony = spend(&pool, "claim", &body.cid, None).await?;
    if !shaped(&body.token, 128) || !ceremony.has_secret(&db::claim_hash(&body.token)) {
        return Err(bad("invalid_link"));
    }
    let (Some(user), Some(subject)) = (ceremony.user_id.clone(), ceremony.subject.clone()) else {
        return Err(bad("expired"));
    };
    let registration = registration_state(&ceremony)?;
    let made = Made::new(
        passkeys
            .webauthn
            .finish_passkey_registration(&body.credential, &registration)
            .map_err(|error| registration_failure(&error))?,
    )?;
    let codes = db::new_recovery_codes(RECOVERY_CODES);
    let label = label(body.label.as_deref());
    let seeded = db::claim(
        &pool,
        &Claim {
            token: &body.token,
            user_id: &user,
            subject: &subject,
            credential: &made.credential(&label),
            codes: &codes,
        },
    )
    .await
    .map_err(|error| match error {
        PasskeyError::NotFound => bad("invalid_link"),
        other => failed(other),
    })?;
    tracing::info!(user_id = %user, "passkey claimed on an existing account");
    Ok(Json(Claimed {
        codes: seeded.then_some(codes),
    }))
}

// A signed-in person's own passkeys.

/// What `/v1/me/passkeys` and the recovery-code calls refuse besides the usual.
enum Refusal {
    Api(ApiError),
    /// Adding or removing a way of signing in asks for a recent sign-in.
    NotRecent,
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        match self {
            Self::Api(error) => error.into_response(),
            Self::NotRecent => Failure {
                status: StatusCode::FORBIDDEN,
                error: "recent_sign_in_required",
            }
            .into_response(),
        }
    }
}

impl From<ApiError> for Refusal {
    fn from(error: ApiError) -> Self {
        Self::Api(error)
    }
}

async fn person(pool: &PgPool, headers: &HeaderMap) -> Result<db::Caller, Refusal> {
    let caller = caller(pool, headers).await?;
    // A bot has no passkeys.
    if caller.scopes.is_empty() {
        Ok(caller)
    } else {
        Err(Refusal::Api(ApiError::Forbidden))
    }
}

async fn recent(pool: &PgPool, caller: &db::Caller) -> Result<(), Refusal> {
    match db::session_is_recent(pool, &caller.user_id, RECENT_SECS).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(Refusal::NotRecent),
        Err(error) => {
            tracing::warn!(%error, "session age not read");
            Err(Refusal::Api(ApiError::Unavailable))
        }
    }
}

#[derive(Serialize)]
struct PasskeyView {
    id: String,
    label: String,
    created_at: String,
    last_used_at: Option<String>,
    /// Whether the platform may sync this passkey to the person's other devices.
    synced: bool,
    /// Turned off because its counter went back. Remove it.
    flagged: bool,
}

#[derive(Serialize)]
struct Mine {
    passkeys: Vec<PasskeyView>,
    recovery_codes_left: i32,
}

async fn list_mine(State(pool): State<PgPool>, headers: HeaderMap) -> Result<Json<Mine>, Refusal> {
    let caller = person(&pool, &headers).await?;
    let rows = db::list_mine(&pool, &caller).await.map_err(lift)?;
    let recovery_codes_left = db::codes_left(&pool, &caller).await.map_err(lift)?;
    Ok(Json(Mine {
        passkeys: rows
            .into_iter()
            .map(|row| PasskeyView {
                id: row.id,
                label: row.label,
                created_at: row.created_at,
                last_used_at: row.last_used_at,
                synced: row.backup_state,
                flagged: row.flagged,
            })
            .collect(),
        recovery_codes_left,
    }))
}

#[derive(Deserialize)]
struct RenameBody {
    label: String,
}

async fn rename_mine(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Result<Json<RenameBody>, JsonRejection>,
) -> Result<StatusCode, Refusal> {
    let caller = person(&pool, &headers).await?;
    let Json(body) = body.map_err(|_| Refusal::Api(ApiError::Invalid))?;
    db::rename_mine(&pool, &caller, &id, &body.label)
        .await
        .map_err(lift)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_mine(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, Refusal> {
    let caller = person(&pool, &headers).await?;
    recent(&pool, &caller).await?;
    db::remove_mine(&pool, &caller, &id).await.map_err(lift)?;
    tracing::info!(user_id = %caller.user_id, "passkey removed");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct NewCodes {
    codes: Vec<String>,
}

/// A new set of recovery codes. Every code of the old set stops working.
async fn new_codes(
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<NewCodes>, Refusal> {
    let caller = person(&pool, &headers).await?;
    recent(&pool, &caller).await?;
    let codes = db::new_recovery_codes(RECOVERY_CODES);
    db::regenerate_codes(&pool, &caller, &codes)
        .await
        .map_err(lift)?;
    tracing::info!(user_id = %caller.user_id, "recovery codes replaced");
    Ok(Json(NewCodes { codes }))
}

#[derive(Serialize)]
struct Link {
    url: String,
}

/// A link for adding a passkey on another device: the claim page, for this account, good for an
/// hour. Opening it needs nothing else, so it is only made for a recent sign-in.
async fn link_mine(
    State(pool): State<PgPool>,
    Extension(sign_in): Extension<SignIn>,
    headers: HeaderMap,
) -> Result<Json<Link>, Refusal> {
    let caller = person(&pool, &headers).await?;
    recent(&pool, &caller).await?;
    let token = db::random_id();
    db::claim_link_for_me(&pool, &caller, &token, SELF_LINK_SECS)
        .await
        .map_err(lift)?;
    Ok(Json(Link {
        url: claim_url(sign_in.public_url(), &token),
    }))
}

/// The claim link. The token is in the fragment, which a browser never sends, so it reaches no
/// access log, proxy log or `Referer`: only the page's script reads it.
pub fn claim_url(public_url: &str, token: &str) -> String {
    format!("{public_url}/v1/auth/passkey/claim#{token}")
}

// The pages.

#[derive(Deserialize)]
struct PageQuery {
    state: Option<String>,
}

/// The one script every page carries. Fixed text, named in the policy by its hash.
///
/// A browser turns every CRLF in an inline script into LF before it hashes it for the policy. A
/// checkout that converts line endings (Windows) would give the file CRLFs, the hash here would
/// not be the browser's, and the page's script would be blocked. So the text is made LF-only
/// before it is hashed and before it is sent.
static SCRIPT: LazyLock<String> =
    LazyLock::new(|| include_str!("passkey.js").replace("\r\n", "\n"));

/// The pages' stylesheet: the shared one and what these pages add.
static PAGE_STYLE: LazyLock<String> = LazyLock::new(|| {
    format!(
        "{STYLE}\
         main{{max-width:25rem;padding:2rem 2rem 1.25rem}}\
         .brand{{display:flex;align-items:center;gap:.9rem;margin:0 0 1.5rem}}\
         .mark{{flex:none;width:3.25rem;height:3.25rem;border-radius:14px;overflow:hidden;\
         display:flex;align-items:center;justify-content:center;background:#2f6feb;color:#fff;\
         font-size:1.5rem;font-weight:700;object-fit:cover}}\
         .brand h1{{font-size:1.35rem;line-height:1.2;margin:0;overflow-wrap:anywhere}}\
         .kind{{margin:.15rem 0 0;color:#a8abb3;font-size:.9rem}}\
         label{{display:block;font-weight:600;margin:0 0 .35rem}}\
         input[type=text]{{box-sizing:border-box;width:100%;padding:.7rem .8rem;border-radius:8px;\
         border:1px solid rgba(255,255,255,.18);font:inherit;background:#18191c;color:inherit}}\
         input[type=text]:focus{{outline:2px solid #2f6feb;outline-offset:1px}}\
         .button[disabled]{{opacity:.5;cursor:default}}\
         .stack{{display:flex;flex-direction:column;gap:.75rem}}\
         .stack p{{margin:0}}\
         .more{{margin-top:1.25rem;font-size:.9rem;color:#a8abb3}}\
         .more summary{{cursor:pointer;width:max-content}}\
         .more .stack{{margin-top:.9rem}}\
         pre{{font:15px/1.7 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;\
         background:#18191c;padding:.75rem 1rem;border-radius:8px;overflow-x:auto;\
         border:1px solid rgba(255,255,255,.12);user-select:all}}\
         .by{{display:flex;align-items:center;justify-content:center;gap:.4rem;margin-top:1.5rem;\
         padding-top:1rem;border-top:1px solid rgba(255,255,255,.08);color:#858993;font-size:.8rem}}\
         .by svg{{width:1.1rem;height:1.1rem}}\
         [hidden]{{display:none !important}}"
    )
});

fn digest(text: &str) -> String {
    STANDARD.encode(Sha256::digest(text.as_bytes()))
}

/// Only the stylesheet and the script above run; the page talks to this server and no one else,
/// cannot be framed, and cannot submit a form anywhere.
static POLICY: LazyLock<HeaderValue> = LazyLock::new(|| {
    HeaderValue::from_str(&format!(
        "default-src 'none'; style-src 'sha256-{style}'; script-src 'sha256-{script}'; \
         img-src data:; connect-src 'self'; form-action 'none'; base-uri 'none'; \
         frame-ancestors 'none'",
        style = digest(&PAGE_STYLE),
        script = digest(&SCRIPT),
    ))
    .unwrap_or_else(|_| HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"))
});

/// The Tiny mark, small, under every page.
const LOGO: &str = "<svg viewBox=\"0 0 1024 1024\" aria-hidden=\"true\"><rect x=\"100\" y=\"100\" \
    width=\"824\" height=\"824\" rx=\"186\" fill=\"#2f6feb\"/><g transform=\"translate(512 512) \
    scale(1.24) translate(-512 -512)\"><path fill=\"#fff\" d=\"M422 282 H602 A160 160 0 0 1 762 \
    442 V562 A160 160 0 0 1 602 722 H280 A18 18 0 0 1 262 704 V442 A160 160 0 0 1 422 282 \
    Z\"/><path transform=\"translate(-22 -2)\" fill=\"none\" stroke=\"#2f6feb\" \
    stroke-width=\"74\" stroke-linecap=\"round\" stroke-linejoin=\"round\" d=\"M430 384 V578 \
    Q430 624 476 624 H470 M386 488 H476 M661.5 505.5 A68 68 0 1 0 661.5 606.5\"/></g></svg>";

/// The name and mark at the top of a page: the server's own icon, or its first letter.
fn brand(face: Option<&db::Face>, kind: &str) -> String {
    let (name, mark) = match face {
        Some(face) => {
            let mark = match &face.icon {
                Some((content_type, bytes)) => format!(
                    "<img class=\"mark\" id=\"server-icon\" alt=\"\" src=\"data:{};base64,{}\">",
                    escape(content_type),
                    STANDARD.encode(bytes)
                ),
                None => initial(&face.name),
            };
            (face.name.as_str(), mark)
        }
        // The claim page does not know yet: its script fills this in once the link is checked.
        None => ("", initial("T")),
    };
    format!(
        "<header class=\"brand\">\n{mark}\n<div>\n<h1 id=\"server-name\">{name}</h1>\n\
         <p class=\"kind\">{kind}</p>\n</div>\n</header>",
        name = escape(name),
        kind = escape(kind),
    )
}

/// A tile with the first letter, for a server with no icon.
fn initial(name: &str) -> String {
    let letter: String = name
        .chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().collect())
        .unwrap_or_else(|| "T".to_string());
    format!(
        "<span class=\"mark\" id=\"server-icon\">{}</span>",
        escape(&letter)
    )
}

fn render(
    title: &str,
    mode: &str,
    state: &str,
    face: Option<&db::Face>,
    kind: &str,
    body: &str,
) -> Response {
    let title = escape(title);
    let brand = brand(face, kind);
    let page = format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta name=\"referrer\" content=\"no-referrer\">\n<meta name=\"color-scheme\" \
         content=\"dark\">\n<meta name=\"theme-color\" content=\"#18191c\">\n\
         <title>{title}</title>\n<style>{style}</style>\n</head>\n<body>\n\
         <main data-mode=\"{mode}\" data-state=\"{state}\">\n{brand}\n{body}\n\
         <p id=\"status\" class=\"note\" role=\"status\" aria-live=\"polite\"></p>\n\
         <noscript><p class=\"alert\">Passkeys need JavaScript. Turn it on for this page.</p>\
         </noscript>\n<footer class=\"by\">{LOGO}<span>TinyServer</span></footer>\n\
         </main>\n<script>{script}</script>\n</body>\n</html>\n",
        style = *PAGE_STYLE,
        mode = escape(mode),
        state = escape(state),
        script = *SCRIPT,
    );
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            ),
            (header::CONTENT_SECURITY_POLICY, POLICY.clone()),
        ],
        page,
    )
        .into_response()
}

/// The text shown after a passkey is made: its recovery codes, and the way on.
const CODES: &str = "<section id=\"codes\" class=\"stack\" hidden>\n\
    <p id=\"codes-intro\"></p>\n\
    <pre id=\"codelist\"></pre>\n\
    <div id=\"codes-ack\" class=\"stack\">\n\
    <label><input type=\"checkbox\" id=\"saved\"> I saved these codes</label>\n\
    <p class=\"note\">Each code works once, and it is the only way back in if you lose your \
    passkeys. Nobody can reset your account for you.</p>\n\
    </div>\n\
    <button class=\"button\" id=\"go\" type=\"button\" disabled>Continue</button>\n\
    </section>";

async fn signin_page(
    State(pool): State<PgPool>,
    Extension(sign_in): Extension<SignIn>,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    let Some(state) = query
        .ok()
        .and_then(|Query(query)| query.state)
        .filter(|state| shaped(state, 256))
    else {
        return expired();
    };
    let leg = match db::peek_pending(&pool, &state).await {
        Ok(Some(leg)) => leg,
        Ok(None) => return expired(),
        Err(error) => {
            tracing::warn!(%error, "pending sign-in not read");
            return server_trouble();
        }
    };
    // Someone who started a sign-in from Tiny may see which server it is. Anyone else is shown
    // nothing: the check above is what stands between this page and a stranger.
    let face = db::server_face(&pool).await.ok();
    let invited = leg.invite_hash.is_some();
    let provider = sign_in
        .provider(Some(&leg.provider))
        .map(|provider| (provider.name().to_string(), provider));
    let other = provider
        .map(|(name, provider)| {
            let url = provider.authorize_url(&state, &leg.nonce, &leg.verifier);
            format!(
                "<a class=\"button quiet\" href=\"{url}\">Sign in with {name} instead</a>\n",
                url = escape(&url),
                name = escape(&name),
            )
        })
        .unwrap_or_default();
    // An invited person is here to make an account, so that comes first. Anyone else is here to
    // sign in.
    let lead = if invited {
        "<div class=\"stack\" id=\"new\">\n\
         <div><label for=\"name\">Your name</label>\n\
         <input type=\"text\" id=\"name\" maxlength=\"80\" autocomplete=\"nickname\" \
         placeholder=\"What people will call you\"></div>\n\
         <button class=\"button\" id=\"signup\" type=\"button\">Create my account</button>\n\
         <p class=\"note\">Your passkey stays on your device. This server keeps only its public \
         half: no email, no phone number.</p>\n\
         <button class=\"button quiet\" id=\"login\" type=\"button\">I already have a passkey\
         </button>\n\
         </div>"
    } else {
        "<div class=\"stack\">\n\
         <button class=\"button\" id=\"login\" type=\"button\">Sign in with a passkey</button>\n\
         <p class=\"note\">Use the passkey on this device, or a security key.</p>\n\
         </div>"
    };
    let body = format!(
        "<div id=\"form\">\n{lead}\n{other}\
         <details class=\"more\">\n<summary>Lost your passkeys?</summary>\n\
         <div class=\"stack\">\n\
         <div><label for=\"code\">A recovery code</label>\n\
         <input type=\"text\" id=\"code\" autocomplete=\"off\" autocapitalize=\"characters\" \
         spellcheck=\"false\"></div>\n\
         <button class=\"button quiet\" id=\"recover\" type=\"button\">Use a recovery code\
         </button>\n\
         </div>\n</details>\n</div>\n{CODES}"
    );
    let kind = if invited { "You're invited" } else { "Sign in" };
    render(
        if invited { "Join" } else { "Sign in" },
        "signin",
        &state,
        face.as_ref(),
        kind,
        &body,
    )
}

async fn claim_page() -> Response {
    let body = format!(
        "<div id=\"form\" class=\"stack\">\n\
         <p id=\"who\">Checking your link…</p>\n\
         <button class=\"button\" id=\"claim\" type=\"button\" hidden>Make my passkey</button>\n\
         <p class=\"note\">Your passkey stays on your device. This server keeps only its public \
         half. Your account, roles and messages stay as they are.</p>\n\
         </div>\n{CODES}\n\
         <section id=\"done\" class=\"stack\" hidden>\n\
         <p>All set. Open Tiny and sign in with your passkey.</p>\n\
         </section>"
    );
    // The server's name is filled in by the script once the link is checked: until then this
    // page does not know whether the link is real.
    render(
        "Set up your passkey",
        "claim",
        "",
        None,
        "Set up your passkey",
        &body,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        claim_url, creation_options, digest, display_name, label, page_url, request_options,
        shaped, POLICY, SCRIPT,
    };
    use serde_json::json;

    #[test]
    fn a_claim_token_travels_in_the_fragment() {
        let url = claim_url("https://chat.example.org", "abc_DEF-123");
        assert_eq!(
            url,
            "https://chat.example.org/v1/auth/passkey/claim#abc_DEF-123"
        );
        assert!(!url.split('#').next().unwrap_or("").contains("abc_DEF"));
    }

    #[test]
    fn the_sign_in_page_address_carries_only_the_state() {
        assert_eq!(
            page_url("https://chat.example.org", "s-1_x"),
            "https://chat.example.org/v1/auth/passkey?state=s-1_x"
        );
    }

    #[test]
    fn ids_are_url_safe_and_bounded() {
        assert!(shaped("aZ09-_", 8));
        assert!(!shaped("", 8));
        assert!(!shaped("a b", 8));
        assert!(!shaped("a=b", 8));
        assert!(!shaped("a/b", 8));
        assert!(!shaped(&"a".repeat(9), 8));
    }

    #[test]
    fn a_display_name_is_trimmed_without_control_characters_and_80_long() {
        assert_eq!(
            display_name("  Ada \u{7} Lovelace  ").as_deref(),
            Some("Ada  Lovelace")
        );
        assert_eq!(display_name("   "), None);
        assert_eq!(display_name(&"x".repeat(81)), None);
        assert_eq!(
            display_name(&"x".repeat(80)).map(|name| name.len()),
            Some(80)
        );
    }

    #[test]
    fn a_label_falls_back_when_it_is_empty_long_or_has_control_characters() {
        assert_eq!(label(Some(" Laptop ")), "Laptop");
        assert_eq!(label(None), "Passkey");
        assert_eq!(label(Some("  ")), "Passkey");
        assert_eq!(label(Some(&"x".repeat(61))), "Passkey");
        assert_eq!(label(Some("a\nb")), "Passkey");
    }

    #[test]
    fn registration_asks_for_a_discoverable_credential() {
        let library = json!({"publicKey": {"authenticatorSelection": {
            "residentKey": "discouraged", "requireResidentKey": false,
            "userVerification": "required"}}});
        let adjusted = creation_options(&library);
        let selection = &adjusted["publicKey"]["authenticatorSelection"];
        assert_eq!(selection["residentKey"], "required");
        assert_eq!(selection["requireResidentKey"], true);
        assert_eq!(selection["userVerification"], "required");
    }

    #[test]
    fn sign_in_options_do_not_ask_for_conditional_mediation() {
        let library = json!({"publicKey": {"challenge": "x"}, "mediation": "conditional"});
        let adjusted = request_options(&library);
        assert!(adjusted.get("mediation").is_none());
        assert_eq!(adjusted["publicKey"]["challenge"], "x");
    }

    #[test]
    fn the_script_the_policy_names_is_the_text_a_browser_hashes() {
        // A browser reads every CRLF in an inline script as LF before it hashes it, so a script
        // with CRLFs (a checkout that converts line endings) would be blocked by its own policy.
        assert!(!SCRIPT.contains('\r'));
        let policy = POLICY.to_str().unwrap_or("");
        assert!(policy.contains(&format!("script-src 'sha256-{}'", digest(&SCRIPT))));
    }

    #[test]
    fn the_policy_names_the_script_and_allows_nothing_else_to_run_or_load() {
        let policy = POLICY.to_str().unwrap_or("");
        assert!(policy.contains("default-src 'none'"));
        assert!(policy.contains("script-src 'sha256-"));
        assert!(policy.contains("connect-src 'self'"));
        assert!(policy.contains("form-action 'none'"));
        assert!(policy.contains("frame-ancestors 'none'"));
        assert!(!policy.contains("unsafe-inline"));
        assert!(!policy.contains("unsafe-eval"));
    }

    #[test]
    fn the_script_loads_nothing_and_reads_no_secret_from_the_server_text() {
        // The only fetches go to this server's own paths.
        for line in SCRIPT.lines().filter(|line| line.contains("fetch(")) {
            assert!(!line.contains("http"), "{line}");
        }
        assert!(!SCRIPT.contains("innerHTML"));
        assert!(!SCRIPT.contains("document.write"));
        assert!(!SCRIPT.contains("eval("));
        assert!(!SCRIPT.contains("localStorage"));
        assert!(!SCRIPT.contains("sessionStorage"));
    }

    #[test]
    fn the_relying_party_is_the_host_unless_a_domain_above_it_is_named() {
        use super::Passkeys;
        let url = "https://chat.example.org";
        assert!(Passkeys::new(url, "T", None).is_ok());
        assert!(Passkeys::new(url, "T", Some("")).is_ok());
        assert!(Passkeys::new(url, "T", Some("chat.example.org")).is_ok());
        assert!(Passkeys::new(url, "T", Some("Example.ORG.")).is_ok());
        for bad in [
            "org",
            "other.org",
            "example.com",
            "hat.example.org",
            "evil-example.org",
            "a.chat.example.org",
        ] {
            assert!(Passkeys::new(url, "T", Some(bad)).is_err(), "{bad}");
        }
    }
}
