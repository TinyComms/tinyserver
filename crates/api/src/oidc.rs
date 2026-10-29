//! OpenID Connect providers. tinyserver is a confidential client of each: it holds the client
//! secret or private key, makes the code exchange with its own PKCE verifier (S256, whether or
//! not discovery says so), and checks the ID token. Nothing a provider issues reaches tinyclient.
//!
//! Each provider's keys are read at start and kept. A token signed with a key id they do not
//! have makes one fresh read, at most every 10 seconds, so a key rotation needs no restart.
//!
//! A provider may have an internal URL, such as `http://pocket-id:1411` on the compose network.
//! Discovery, keys, and the code exchange then go there, with the discovered endpoints moved to
//! the internal origin, while the issuer in discovery and in every token must still be exactly
//! the public issuer. The browser always goes to the public authorization endpoint.
//!
//! A provider may also make accounts: with Pocket ID's sign-up configured, tinyserver can ask it
//! for a single-use sign-up link for someone who arrives with an invite. The API key for that is
//! never logged, and neither is a link it returns.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreClientAuthMethod,
    CoreErrorResponseType, CoreGenderClaim, CoreIdTokenVerifier, CoreJsonWebKey, CoreJsonWebKeySet,
    CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreProviderMetadata,
    CoreRevocableToken, CoreRevocationErrorResponse, CoreRsaPrivateSigningKey,
    CoreTokenIntrospectionResponse, CoreTokenType,
};
use openidconnect::{
    AdditionalClaims, AuthType, AuthorizationCode, ClaimsVerificationError, ClientId, ClientSecret,
    CsrfToken, EmptyExtraTokenFields, EndpointNotSet, EndpointSet, IdToken, IdTokenFields,
    IssuerUrl, JsonWebKey, JsonWebKeyId, JsonWebKeySet, JsonWebKeySetUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, PrivateSigningKey, RedirectUrl, RequestTokenError, Scope,
    SignatureVerificationError, StandardErrorResponse, StandardTokenResponse, TokenResponse,
    TokenUrl,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

/// Every claim the library does not model, such as `groups` and `sid`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct Extra {
    #[serde(flatten)]
    claims: HashMap<String, Value>,
}

impl AdditionalClaims for Extra {}

type Fields = IdTokenFields<
    Extra,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;
type ProviderIdToken =
    IdToken<Extra, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm>;
type Client = openidconnect::Client<
    Extra,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    StandardTokenResponse<Fields, CoreTokenType>,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
    EndpointNotSet,
>;

/// Signature algorithms a provider's token may use. Never `none`, never a shared-secret MAC.
const ALGS: [CoreJwsSigningAlgorithm; 3] = [
    CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
    CoreJwsSigningAlgorithm::EcdsaP256Sha256,
    CoreJwsSigningAlgorithm::EdDsa,
];

/// How far ahead of this server's clock a token's `iat` may be, in seconds.
const IAT_AHEAD: i64 = 60;
/// How old a token's `iat` may be, in seconds. As long as a pending sign-in lives.
const IAT_BEHIND: i64 = 10 * 60;
/// The least time between two key reads for an unknown key id.
const REFETCH_EVERY: Duration = Duration::from_secs(10);
/// Every request to a provider: discovery, keys, and the code exchange.
const PROVIDER_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a `private_key_jwt` client assertion is good for, in seconds.
const ASSERTION_SECONDS: i64 = 60;
/// The event a back-channel logout token carries.
const LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";
/// How long a sign-up link works: a little past the pending sign-in it was made for.
const SIGNUP_TTL: &str = "15m";

/// Sign-in settings, from the environment in `tinyserver serve`.
#[derive(Clone, Debug)]
pub struct SignInConfig {
    /// `https://chat.example.org`. The callback is this plus `/v1/auth/callback`.
    pub public_url: String,
    /// A session from sign-in lasts this many days, then the person signs in again.
    pub session_days: u32,
    /// The first is the default for `POST /v1/auth/start`.
    pub providers: Vec<ProviderConfig>,
}

/// One provider.
#[derive(Clone)]
pub struct ProviderConfig {
    /// `[a-z0-9_-]`, 1 to 32 characters. Sent by tinyclient to pick a provider.
    pub id: String,
    pub issuer: String,
    pub client_id: String,
    /// `client_secret_basic` or `client_secret_post`, whichever discovery offers.
    pub client_secret: Option<String>,
    /// A PKCS#1 RSA key in PEM. When set, the client authenticates with `private_key_jwt`.
    pub private_key_pem: Option<String>,
    /// The `kid` put on client assertions, if the provider wants one.
    pub private_key_id: Option<String>,
    /// Asked for at the provider. `openid` is always sent.
    pub scopes: Vec<String>,
    /// Shown in tinyclient. The issuer's host when unset.
    pub name: Option<String>,
    /// Where this server reaches the provider, when not at the issuer.
    pub internal_url: Option<String>,
    /// The claim with the person's groups. `groups` when unset.
    pub groups_claim: Option<String>,
    /// In one of these, a member becomes admin at sign-in.
    pub admin_groups: Vec<String>,
    /// In one of these, or an admin group, a person may join without an invite. Empty means
    /// invite only.
    pub member_groups: Vec<String>,
    /// The provider makes accounts for people who arrive with an invite. Unset is a provider
    /// that only signs people in.
    pub signup: Option<SignupConfig>,
}

/// Pocket ID sign-up links (`POST /api/signup-tokens`), for people who arrive with an invite.
#[derive(Clone)]
pub struct SignupConfig {
    /// Where this server reaches Pocket ID's API. The provider's internal URL, else its issuer,
    /// when unset.
    pub api_url: Option<String>,
    /// Sent as `X-API-Key`. An admin key: it may create users, so it lives in a secret file.
    pub api_key: String,
    /// Pocket ID groups a new account joins.
    pub group_ids: Vec<String>,
}

impl fmt::Debug for SignupConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignupConfig")
            .field("api_url", &self.api_url)
            .field("api_key", &"[redacted]")
            .field("group_ids", &self.group_ids)
            .finish()
    }
}

impl fmt::Debug for ProviderConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderConfig")
            .field("id", &self.id)
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "private_key_pem",
                &self.private_key_pem.as_ref().map(|_| "[redacted]"),
            )
            .field("private_key_id", &self.private_key_id)
            .field("scopes", &self.scopes)
            .field("name", &self.name)
            .field("internal_url", &self.internal_url)
            .field("groups_claim", &self.groups_claim)
            .field("admin_groups", &self.admin_groups)
            .field("member_groups", &self.member_groups)
            .field("signup", &self.signup)
            .finish()
    }
}

/// Why sign-in could not be set up. The message never carries a secret or key.
#[derive(Debug)]
pub struct ConfigError {
    message: String,
    /// Worth another try: a provider could not be reached or answered badly. A wrong issuer
    /// or a bad setting is not.
    pub transient: bool,
}

impl ConfigError {
    fn fatal(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            transient: false,
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ConfigError {}

/// The providers, discovered. Cheap to clone.
#[derive(Clone)]
pub struct SignIn {
    inner: Arc<Shared>,
}

struct Shared {
    providers: Vec<Provider>,
    session_days: u32,
    /// `TINYSERVER_PUBLIC_URL`, without a trailing slash.
    public_url: String,
}

pub(crate) struct Provider {
    id: String,
    name: String,
    client: Client,
    client_id: ClientId,
    issuer: IssuerUrl,
    jwks_uri: JsonWebKeySetUrl,
    keys: RwLock<CoreJsonWebKeySet>,
    /// When the keys were last read for an unknown key id. Held across the read, so two
    /// callbacks with a new key make one request.
    refetched: tokio::sync::Mutex<Option<Instant>>,
    http: reqwest::Client,
    scopes: Vec<String>,
    assertion: Option<Assertion>,
    groups_claim: String,
    admin_groups: Vec<String>,
    member_groups: Vec<String>,
    signup: Option<Signup>,
}

/// Where and how to ask Pocket ID for a sign-up link.
struct Signup {
    /// `.../api/signup-tokens`, inside when there is an internal URL.
    tokens_url: Url,
    api_key: String,
    group_ids: Vec<String>,
    /// The public issuer: the browser goes to its sign-up page.
    page_base: Url,
}

/// A single-use sign-up page at the provider. The token in it is a secret: never logged.
pub(crate) struct SignupLink(pub String);

/// Why no sign-up link was made. Logged; no token or key in it.
#[derive(Debug)]
pub(crate) enum SignupFailure {
    /// This provider makes no accounts.
    NotConfigured,
    /// The API could not be reached.
    Unreachable,
    /// The API answered with this status.
    Status(u16),
    /// The answer had no usable token.
    Unreadable,
}

impl fmt::Display for SignupFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConfigured => f.write_str("the provider makes no accounts"),
            Self::Unreachable => f.write_str("sign-up API not reached"),
            Self::Status(status) => write!(f, "sign-up API answered HTTP {status}"),
            Self::Unreadable => f.write_str("sign-up API answer had no token"),
        }
    }
}

/// `private_key_jwt` (RFC 7523): a JWT signed with the client's key replaces the secret.
struct Assertion {
    key: CoreRsaPrivateSigningKey,
    key_id: Option<String>,
    /// The token endpoint as discovered, before any move to the internal URL.
    audience: String,
}

/// A new authorization request: the URL for the browser and what to keep for the callback.
pub(crate) struct Begun {
    pub authorize_url: String,
    pub state: String,
    pub verifier: String,
    pub nonce: String,
}

/// A person the provider vouched for, and what their groups allow.
pub(crate) struct Verified {
    pub profile: db::Profile,
    pub groups: db::Groups,
}

/// What a back-channel logout token names.
pub(crate) struct Logout {
    pub issuer: String,
    pub subject: Option<String>,
    pub sid: Option<String>,
}

/// Why a callback or logout did not go through. Logged by kind; none of it goes to the browser.
#[derive(Debug)]
pub(crate) enum Failure {
    /// The token endpoint refused the code, with its OAuth error code.
    Refused(String),
    /// The token endpoint could not be reached, or its answer could not be read.
    Exchange(&'static str),
    NoIdToken,
    Claims(ClaimsVerificationError),
    /// `azp` names another client.
    AuthorizedParty,
    /// No key in the provider's set has the token's key id.
    NoKey,
    /// A logout token that is not one, with what is wrong.
    Logout(&'static str),
    /// A client assertion could not be signed.
    Assertion,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(code) => write!(f, "token endpoint refused the code: {code}"),
            Self::Exchange(why) => write!(f, "code exchange failed: {why}"),
            Self::NoIdToken => f.write_str("token response has no ID token"),
            Self::Claims(error) => write!(f, "ID token rejected: {}", claims_kind(error)),
            Self::AuthorizedParty => f.write_str("ID token rejected: azp is another client"),
            Self::NoKey => f.write_str("token rejected: no key for the key id"),
            Self::Logout(why) => write!(f, "logout token rejected: {why}"),
            Self::Assertion => f.write_str("client assertion could not be signed"),
        }
    }
}

impl Failure {
    fn no_key(&self) -> bool {
        matches!(
            self,
            Self::NoKey
                | Self::Claims(ClaimsVerificationError::SignatureVerification(
                    SignatureVerificationError::NoMatchingKey
                ))
        )
    }
}

impl SignIn {
    /// Reads every provider's discovery document and keys. Fails when an issuer in a document
    /// is not exactly the configured one.
    pub async fn discover(config: SignInConfig) -> Result<Self, ConfigError> {
        let public_url = secure_url("TINYSERVER_PUBLIC_URL", &config.public_url)?;
        let callback = format!(
            "{}/v1/auth/callback",
            public_url.as_str().trim_end_matches('/')
        );
        let redirect = RedirectUrl::new(callback)
            .map_err(|_| ConfigError::fatal("TINYSERVER_PUBLIC_URL is not a URL"))?;
        if config.providers.is_empty() {
            return Err(ConfigError::fatal("no sign-in provider is configured"));
        }
        if !(1..=365).contains(&config.session_days) {
            return Err(ConfigError::fatal(
                "TINYSERVER_SESSION_MAX_DAYS must be 1 to 365",
            ));
        }
        let mut providers: Vec<Provider> = Vec::new();
        for provider in config.providers {
            let provider = Provider::discover(provider, redirect.clone()).await?;
            if providers.iter().any(|seen| seen.id == provider.id) {
                return Err(ConfigError::fatal(format!(
                    "provider id {} is configured twice",
                    provider.id
                )));
            }
            // Back-channel logout and identities are keyed by issuer.
            if providers.iter().any(|seen| seen.issuer == provider.issuer) {
                return Err(ConfigError::fatal(format!(
                    "issuer {} is configured twice",
                    provider.issuer.as_str()
                )));
            }
            providers.push(provider);
        }
        Ok(Self {
            inner: Arc::new(Shared {
                providers,
                session_days: config.session_days,
                public_url: public_url.as_str().trim_end_matches('/').to_string(),
            }),
        })
    }

    /// In configured order. The first is the default.
    pub(crate) fn providers(&self) -> &[Provider] {
        &self.inner.providers
    }

    /// The default provider's name.
    pub fn provider_name(&self) -> &str {
        self.inner
            .providers
            .first()
            .map_or("", |provider| provider.name.as_str())
    }

    /// The provider with `id`, or the first when `id` is `None`.
    pub(crate) fn provider(&self, id: Option<&str>) -> Option<&Provider> {
        match id {
            None => self.inner.providers.first(),
            Some(id) => self
                .inner
                .providers
                .iter()
                .find(|provider| provider.id == id),
        }
    }

    pub(crate) fn session_days(&self) -> u32 {
        self.inner.session_days
    }

    /// `TINYSERVER_PUBLIC_URL`, without a trailing slash.
    pub(crate) fn public_url(&self) -> &str {
        &self.inner.public_url
    }

    /// Checks a back-channel logout token from whichever provider its `iss` names.
    pub(crate) async fn logout(&self, token: &str) -> Result<Logout, Failure> {
        let claims = unverified_payload(token)?;
        let issuer = claims
            .get("iss")
            .and_then(Value::as_str)
            .ok_or(Failure::Logout("no issuer"))?;
        let provider = self
            .inner
            .providers
            .iter()
            .find(|provider| provider.issuer.as_str() == issuer)
            .ok_or(Failure::Logout("unknown issuer"))?;
        provider.logout(token).await
    }
}

impl Provider {
    async fn discover(config: ProviderConfig, redirect: RedirectUrl) -> Result<Self, ConfigError> {
        let id = config.id.clone();
        let fatal = |message: String| ConfigError::fatal(format!("provider {id}: {message}"));
        let transient = |message: String| ConfigError {
            message: format!("provider {id}: {message}"),
            transient: true,
        };
        let id_ok = (1..=32).contains(&config.id.len())
            && config
                .id
                .bytes()
                .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'));
        if !id_ok {
            return Err(fatal("the id must be 1 to 32 of a-z, 0-9, _ and -".into()));
        }
        let issuer_url =
            secure_url("the issuer", &config.issuer).map_err(|error| fatal(error.message))?;
        // Compared as the string it is, with no normalizing.
        let issuer = IssuerUrl::new(config.issuer.clone())
            .map_err(|_| fatal("the issuer is not a URL".into()))?;
        if config.client_id.is_empty() {
            return Err(fatal("the client id is empty".into()));
        }
        let internal = match &config.internal_url {
            None => None,
            Some(internal) => {
                let url = Url::parse(internal)
                    .map_err(|_| fatal("the internal URL is not a URL".into()))?;
                if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                    return Err(fatal("the internal URL must be http or https".into()));
                }
                Some(url)
            }
        };

        let http = reqwest::Client::builder()
            // A redirect from a provider is never followed: a token request could carry the
            // client credentials to wherever it points.
            .redirect(reqwest::redirect::Policy::none())
            .timeout(PROVIDER_TIMEOUT)
            .build()
            .map_err(|error| fatal(format!("HTTP client: {error}")))?;

        let base = internal.as_ref().unwrap_or(&issuer_url);
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            base.as_str().trim_end_matches('/')
        );
        let response = http
            .get(&discovery_url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|error| transient(format!("discovery at {discovery_url}: {error}")))?;
        if !response.status().is_success() {
            return Err(transient(format!(
                "discovery at {discovery_url}: HTTP {}",
                response.status()
            )));
        }
        let body = response
            .bytes()
            .await
            .map_err(|error| transient(format!("discovery at {discovery_url}: {error}")))?;
        let metadata: CoreProviderMetadata = serde_json::from_slice(&body)
            .map_err(|error| fatal(format!("discovery at {discovery_url}: {error}")))?;
        if metadata.issuer().as_str() != config.issuer {
            return Err(fatal(format!(
                "discovery says the issuer is {}, not {}",
                metadata.issuer().as_str(),
                config.issuer
            )));
        }
        let Some(public_token_url) = metadata.token_endpoint().cloned() else {
            return Err(fatal("the provider has no token endpoint".into()));
        };
        let token_url = TokenUrl::from_url(moved(
            public_token_url.url(),
            &issuer_url,
            internal.as_ref(),
        ));
        let jwks_uri = JsonWebKeySetUrl::from_url(moved(
            metadata.jwks_uri().url(),
            &issuer_url,
            internal.as_ref(),
        ));
        let keys = JsonWebKeySet::fetch_async(&jwks_uri, &http)
            .await
            .map_err(|error| transient(format!("keys at {}: {error}", jwks_uri.as_str())))?;

        // No list means the provider takes client_secret_basic, by the discovery spec.
        let methods = metadata.token_endpoint_auth_methods_supported();
        let offers = |method: &CoreClientAuthMethod| match methods {
            Some(methods) => methods.contains(method),
            None => *method == CoreClientAuthMethod::ClientSecretBasic,
        };
        let client_id = ClientId::new(config.client_id.clone());
        let base_client: Client = openidconnect::Client::new(
            client_id.clone(),
            issuer.clone(),
            JsonWebKeySet::new(Vec::new()),
        )
        .set_auth_uri(metadata.authorization_endpoint().clone())
        .set_token_uri(token_url)
        .set_redirect_uri(redirect);
        let (client, assertion) = match (config.client_secret, config.private_key_pem) {
            (Some(_), Some(_)) => {
                return Err(fatal(
                    "set a client secret or a private key, not both".into(),
                ))
            }
            (None, None) => return Err(fatal("no client secret or private key".into())),
            (None, Some(pem)) => {
                // Asked for on purpose, so a provider that lists no methods gets it anyway.
                if methods.is_some() && !offers(&CoreClientAuthMethod::PrivateKeyJwt) {
                    return Err(fatal("the provider does not offer private_key_jwt".into()));
                }
                let key = CoreRsaPrivateSigningKey::from_pem(&pem, None)
                    .map_err(|_| fatal("the private key is not a PKCS#1 RSA key in PEM".into()))?;
                // No secret: client_id goes in the body next to the assertion.
                let client = base_client.set_auth_type(AuthType::RequestBody);
                let assertion = Assertion {
                    key,
                    key_id: config.private_key_id,
                    audience: public_token_url.as_str().to_string(),
                };
                (client, Some(assertion))
            }
            (Some(secret), None) => {
                if secret.is_empty() {
                    return Err(fatal("the client secret is empty".into()));
                }
                let auth_type = if offers(&CoreClientAuthMethod::ClientSecretBasic) {
                    AuthType::BasicAuth
                } else if offers(&CoreClientAuthMethod::ClientSecretPost) {
                    AuthType::RequestBody
                } else {
                    return Err(fatal(
                        "the provider offers neither client_secret_basic nor client_secret_post"
                            .into(),
                    ));
                };
                let client = base_client
                    .set_client_secret(ClientSecret::new(secret))
                    .set_auth_type(auth_type);
                (client, None)
            }
        };

        let name = config
            .name
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| issuer_url.host_str().unwrap_or("your provider").to_string());
        let signup = match config.signup {
            None => None,
            Some(signup) => {
                let api_key = signup.api_key.trim().to_string();
                if api_key.len() < 16 {
                    return Err(fatal(
                        "the sign-up API key is shorter than 16 characters".into(),
                    ));
                }
                let api_base = match &signup.api_url {
                    Some(api_url) => {
                        let url = Url::parse(api_url)
                            .map_err(|_| fatal("the sign-up API URL is not a URL".into()))?;
                        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                            return Err(fatal("the sign-up API URL must be http or https".into()));
                        }
                        url
                    }
                    None => internal.clone().unwrap_or_else(|| issuer_url.clone()),
                };
                let tokens_url = Url::parse(&format!(
                    "{}/api/signup-tokens",
                    api_base.as_str().trim_end_matches('/')
                ))
                .map_err(|_| fatal("the sign-up API URL is not a URL".into()))?;
                let group_ids = signup
                    .group_ids
                    .into_iter()
                    .map(|id| id.trim().to_string())
                    .filter(|id| !id.is_empty())
                    .collect();
                Some(Signup {
                    tokens_url,
                    api_key,
                    group_ids,
                    page_base: issuer_url.clone(),
                })
            }
        };
        let scopes = config
            .scopes
            .into_iter()
            .map(|scope| scope.trim().to_string())
            .filter(|scope| !scope.is_empty() && scope != "openid")
            .collect();
        Ok(Self {
            id: config.id,
            name,
            client,
            client_id,
            issuer,
            jwks_uri,
            keys: RwLock::new(keys),
            refetched: tokio::sync::Mutex::new(None),
            http,
            scopes,
            assertion,
            groups_claim: config
                .groups_claim
                .filter(|claim| !claim.is_empty())
                .unwrap_or_else(|| "groups".to_string()),
            admin_groups: config.admin_groups,
            member_groups: config.member_groups,
            signup,
        })
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn issuer(&self) -> &str {
        self.issuer.as_str()
    }

    /// A fresh state, nonce, and PKCE pair (S256), and the authorization URL that carries them.
    pub(crate) fn begin(&self) -> Begun {
        let state = CsrfToken::new_random_len(32).secret().clone();
        let nonce = Nonce::new_random_len(32).secret().clone();
        let (_, verifier) = PkceCodeChallenge::new_random_sha256();
        let verifier = verifier.secret().clone();
        Begun {
            authorize_url: self.authorize_url(&state, &nonce, &verifier),
            state,
            verifier,
            nonce,
        }
    }

    /// The authorization URL for a pending sign-in's state, nonce, and verifier. The same each
    /// time for the same three.
    pub(crate) fn authorize_url(&self, state: &str, nonce: &str, verifier: &str) -> String {
        let state = CsrfToken::new(state.to_string());
        let nonce = Nonce::new(nonce.to_string());
        let challenge = PkceCodeChallenge::from_code_verifier_sha256(&PkceCodeVerifier::new(
            verifier.to_string(),
        ));
        let mut request = self
            .client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                move || state,
                move || nonce,
            )
            .set_pkce_challenge(challenge);
        for scope in &self.scopes {
            request = request.add_scope(Scope::new(scope.clone()));
        }
        request.url().0.to_string()
    }

    /// Whether this provider makes accounts for people who arrive with an invite.
    pub(crate) fn makes_accounts(&self) -> bool {
        self.signup.is_some()
    }

    /// Asks Pocket ID for one sign-up token, good once and for a short while, and returns the
    /// page the browser opens to use it. Neither the key nor the token is logged.
    pub(crate) async fn signup_link(&self) -> Result<SignupLink, SignupFailure> {
        let signup = self.signup.as_ref().ok_or(SignupFailure::NotConfigured)?;
        let mut body = serde_json::json!({ "ttl": SIGNUP_TTL, "usageLimit": 1 });
        if !signup.group_ids.is_empty() {
            body["userGroupIds"] = Value::from(signup.group_ids.clone());
        }
        let response = self
            .http
            .post(signup.tokens_url.clone())
            .header("X-API-Key", &signup.api_key)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|_| SignupFailure::Unreachable)?;
        let status = response.status();
        if !status.is_success() {
            return Err(SignupFailure::Status(status.as_u16()));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| SignupFailure::Unreadable)?;
        let answer: Value =
            serde_json::from_slice(&bytes).map_err(|_| SignupFailure::Unreadable)?;
        let token = answer
            .get("token")
            .and_then(Value::as_str)
            .filter(|token| {
                (1..=128).contains(&token.len())
                    && token
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            })
            .ok_or(SignupFailure::Unreadable)?;
        let mut page = signup.page_base.clone();
        page.set_path("/signup");
        page.set_query(None);
        page.query_pairs_mut().append_pair("token", token);
        Ok(SignupLink(page.to_string()))
    }

    /// Exchanges the code with the client's credentials and `verifier`, then checks the ID
    /// token.
    pub(crate) async fn finish(
        &self,
        code: &str,
        verifier: &str,
        nonce: &str,
    ) -> Result<Verified, Failure> {
        let mut request = self
            .client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .set_pkce_verifier(PkceCodeVerifier::new(verifier.to_string()));
        if let Some(assertion) = &self.assertion {
            request = request
                .add_extra_param(
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                )
                .add_extra_param("client_assertion", self.client_assertion(assertion)?);
        }
        let response = request
            .request_async(&self.http)
            .await
            .map_err(|error| match error {
                RequestTokenError::ServerResponse(response) => {
                    Failure::Refused(response.error().as_ref().to_string())
                }
                RequestTokenError::Request(_) => Failure::Exchange("request"),
                RequestTokenError::Parse(_, _) => Failure::Exchange("unreadable response"),
                RequestTokenError::Other(_) => Failure::Exchange("other"),
            })?;
        let id_token = response.id_token().ok_or(Failure::NoIdToken)?;
        let nonce = Nonce::new(nonce.to_string());
        match self.verify(id_token, &nonce, self.keys()) {
            Err(failure) if failure.no_key() => {
                let keys = self.refetch().await.ok_or(Failure::NoKey)?;
                self.verify(id_token, &nonce, keys)
            }
            verified => verified,
        }
    }

    /// Checks a back-channel logout token: signature, `iss`, `aud`, `iat`, `exp` when present,
    /// `jti`, the logout event, no `nonce`, and a `sub` or `sid`.
    async fn logout(&self, token: &str) -> Result<Logout, Failure> {
        match self.verify_logout(token, &self.keys()) {
            Err(failure) if failure.no_key() => {
                let keys = self.refetch().await.ok_or(Failure::NoKey)?;
                self.verify_logout(token, &keys)
            }
            checked => checked,
        }
    }

    fn keys(&self) -> CoreJsonWebKeySet {
        self.keys
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }

    /// `iss` exact, `aud` has this client and no one untrusted, `azp` this client when present,
    /// `exp`, `iat` near now, `nonce`, and a signature by one of `keys` in an allowed algorithm.
    fn verify(
        &self,
        id_token: &ProviderIdToken,
        nonce: &Nonce,
        keys: CoreJsonWebKeySet,
    ) -> Result<Verified, Failure> {
        let verifier = CoreIdTokenVerifier::new_public_client(
            self.client_id.clone(),
            self.issuer.clone(),
            keys,
        )
        .set_allowed_algs(ALGS)
        .set_issue_time_verifier_fn(|issued| issued_near_now(issued.timestamp()));
        let claims = id_token.claims(&verifier, nonce).map_err(Failure::Claims)?;
        // Extra audiences are already refused above. A present azp must still be this client.
        if let Some(party) = claims.authorized_party() {
            if party.as_str() != self.client_id.as_str() {
                return Err(Failure::AuthorizedParty);
            }
        }
        let name = claims
            .name()
            .and_then(|name| name.get(None))
            .map(|name| name.as_str().trim().to_string())
            // Pocket ID sends an empty name when someone left first and last name blank.
            .filter(|name| !name.is_empty())
            .or_else(|| {
                claims
                    .preferred_username()
                    .map(|name| name.as_str().trim().to_string())
                    .filter(|name| !name.is_empty())
            });
        let extra = &claims.additional_claims().claims;
        let sid = extra
            .get("sid")
            .and_then(Value::as_str)
            .filter(|sid| (1..=255).contains(&sid.len()))
            .map(str::to_string);
        let groups = self.groups(&claimed_groups(extra.get(&self.groups_claim)));
        Ok(Verified {
            profile: db::Profile {
                issuer: claims.issuer().as_str().to_string(),
                subject: claims.subject().as_str().to_string(),
                email: claims.email().map(|email| email.as_str().to_string()),
                name,
                sid,
            },
            groups,
        })
    }

    /// What the person's groups allow. Joining needs member groups to be configured; someone
    /// in an admin group then joins as admin. The owner role never comes from a claim.
    fn groups(&self, claimed: &[String]) -> db::Groups {
        let in_any = |configured: &[String]| claimed.iter().any(|group| configured.contains(group));
        let admin = in_any(&self.admin_groups);
        let join = if self.member_groups.is_empty() {
            None
        } else if admin {
            Some("admin")
        } else if in_any(&self.member_groups) {
            Some("member")
        } else {
            None
        };
        db::Groups { join, admin }
    }

    fn verify_logout(&self, token: &str, keys: &CoreJsonWebKeySet) -> Result<Logout, Failure> {
        let claims = verify_jws(token, keys)?;
        if claims.get("iss").and_then(Value::as_str) != Some(self.issuer.as_str()) {
            return Err(Failure::Logout("issuer"));
        }
        let audiences: Vec<&str> = match claims.get("aud") {
            Some(Value::String(aud)) => vec![aud.as_str()],
            Some(Value::Array(auds)) => auds.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        if audiences.is_empty() || audiences.iter().any(|aud| *aud != self.client_id.as_str()) {
            return Err(Failure::Logout("audience"));
        }
        let issued = claims
            .get("iat")
            .and_then(Value::as_i64)
            .ok_or(Failure::Logout("no iat"))?;
        issued_near_now(issued).map_err(|_| Failure::Logout("iat"))?;
        if let Some(expires) = claims.get("exp") {
            let expires = expires.as_i64().ok_or(Failure::Logout("exp"))?;
            if expires <= now() {
                return Err(Failure::Logout("expired"));
            }
        }
        if !claims.get("jti").is_some_and(Value::is_string) {
            return Err(Failure::Logout("no jti"));
        }
        let event = claims
            .get("events")
            .and_then(Value::as_object)
            .and_then(|events| events.get(LOGOUT_EVENT));
        if !event.is_some_and(Value::is_object) {
            return Err(Failure::Logout("no logout event"));
        }
        // A nonce would mean an ID token offered as a logout token.
        if claims.contains_key("nonce") {
            return Err(Failure::Logout("nonce"));
        }
        let text = |name: &str| {
            claims
                .get(name)
                .and_then(Value::as_str)
                .filter(|value| (1..=255).contains(&value.len()))
                .map(str::to_string)
        };
        let subject = text("sub");
        let sid = text("sid");
        if subject.is_none() && sid.is_none() {
            return Err(Failure::Logout("neither sub nor sid"));
        }
        Ok(Logout {
            issuer: self.issuer.as_str().to_string(),
            subject,
            sid,
        })
    }

    /// RFC 7523 client assertion: `iss` and `sub` the client id, `aud` the token endpoint.
    fn client_assertion(&self, assertion: &Assertion) -> Result<String, Failure> {
        let mut header = serde_json::json!({"alg": "RS256", "typ": "JWT"});
        if let Some(key_id) = &assertion.key_id {
            header["kid"] = Value::String(key_id.clone());
        }
        let issued = now();
        let claims = serde_json::json!({
            "iss": self.client_id.as_str(),
            "sub": self.client_id.as_str(),
            "aud": assertion.audience,
            "jti": CsrfToken::new_random_len(32).secret(),
            "iat": issued,
            "exp": issued + ASSERTION_SECONDS,
        });
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature = assertion
            .key
            .sign(
                &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
                input.as_bytes(),
            )
            .map_err(|_| Failure::Assertion)?;
        Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }

    /// Reads the provider's keys again. Another caller's fresh read counts: within
    /// `REFETCH_EVERY` the keys on hand are returned without a request.
    async fn refetch(&self) -> Option<CoreJsonWebKeySet> {
        let mut last = self.refetched.lock().await;
        if last.is_some_and(|at| at.elapsed() < REFETCH_EVERY) {
            return Some(self.keys());
        }
        *last = Some(Instant::now());
        match JsonWebKeySet::fetch_async(&self.jwks_uri, &self.http).await {
            Ok(keys) => {
                tracing::info!(provider = %self.id, "provider keys read again for an unknown key id");
                *self
                    .keys
                    .write()
                    .unwrap_or_else(|poison| poison.into_inner()) = keys.clone();
                Some(keys)
            }
            Err(error) => {
                tracing::warn!(provider = %self.id, %error, "provider keys could not be read");
                None
            }
        }
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs() as i64)
}

fn issued_near_now(issued: i64) -> Result<(), String> {
    let now = now();
    if issued > now + IAT_AHEAD {
        Err("issued in the future".to_string())
    } else if issued < now - IAT_BEHIND {
        Err("issued too long ago".to_string())
    } else {
        Ok(())
    }
}

/// A groups claim: an array of strings, or one string of comma-separated names.
fn claimed_groups(claim: Option<&Value>) -> Vec<String> {
    match claim {
        Some(Value::Array(groups)) => groups
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        Some(Value::String(groups)) => groups
            .split(',')
            .map(str::trim)
            .filter(|group| !group.is_empty())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

/// `url` at the internal origin when it is at the public issuer's origin. Path and query stay.
fn moved(url: &Url, public: &Url, internal: Option<&Url>) -> Url {
    let Some(internal) = internal else {
        return url.clone();
    };
    if url.origin() != public.origin() {
        return url.clone();
    }
    let mut moved = internal.clone();
    moved.set_path(url.path());
    moved.set_query(url.query());
    moved
}

#[derive(Deserialize)]
struct JoseHeader {
    alg: String,
    kid: Option<String>,
    typ: Option<String>,
    crit: Option<Value>,
}

fn parts(token: &str) -> Result<[&str; 3], Failure> {
    let mut split = token.split('.');
    match (split.next(), split.next(), split.next(), split.next()) {
        (Some(header), Some(payload), Some(signature), None)
            if !header.is_empty() && !payload.is_empty() =>
        {
            Ok([header, payload, signature])
        }
        _ => Err(Failure::Logout("not a signed JWT")),
    }
}

fn unverified_payload(token: &str) -> Result<serde_json::Map<String, Value>, Failure> {
    let [_, payload, _] = parts(token)?;
    let payload = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| Failure::Logout("payload encoding"))?;
    serde_json::from_slice(&payload).map_err(|_| Failure::Logout("payload json"))
}

/// A compact JWS signed by one of `keys` in an allowed algorithm. Returns the claims.
fn verify_jws(
    token: &str,
    keys: &CoreJsonWebKeySet,
) -> Result<serde_json::Map<String, Value>, Failure> {
    let [header_part, payload_part, signature_part] = parts(token)?;
    let header: JoseHeader = URL_SAFE_NO_PAD
        .decode(header_part)
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
        .ok_or(Failure::Logout("header"))?;
    if header.crit.is_some() {
        return Err(Failure::Logout("crit"));
    }
    if let Some(typ) = &header.typ {
        let typ = typ.to_ascii_lowercase();
        if !matches!(
            typ.as_str(),
            "jwt" | "logout+jwt" | "application/logout+jwt"
        ) {
            return Err(Failure::Logout("typ"));
        }
    }
    let alg: CoreJwsSigningAlgorithm = serde_json::from_value(Value::String(header.alg))
        .map_err(|_| Failure::Logout("algorithm"))?;
    if !ALGS.contains(&alg) {
        return Err(Failure::Logout("algorithm"));
    }
    let signature = URL_SAFE_NO_PAD
        .decode(signature_part)
        .map_err(|_| Failure::Logout("signature encoding"))?;
    if signature.is_empty() {
        return Err(Failure::Logout("unsigned"));
    }
    let candidates: Vec<&CoreJsonWebKey> = keys
        .keys()
        .iter()
        .filter(|key| match &header.kid {
            Some(kid) => key.key_id() == Some(&JsonWebKeyId::new(kid.clone())),
            None => true,
        })
        .collect();
    if candidates.is_empty() {
        return Err(Failure::NoKey);
    }
    let input = format!("{header_part}.{payload_part}");
    let verified = candidates.iter().any(|key| {
        key.verify_signature(&alg, input.as_bytes(), &signature)
            .is_ok()
    });
    if !verified {
        return Err(Failure::Logout("signature"));
    }
    unverified_payload(token)
}

/// `https`, or `http` to this machine for development and tests. No query, fragment, or user.
fn secure_url(name: &str, value: &str) -> Result<Url, ConfigError> {
    let url = Url::parse(value).map_err(|_| ConfigError::fatal(format!("{name} is not a URL")))?;
    let local = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    let scheme_ok = url.scheme() == "https" || (url.scheme() == "http" && local);
    if !scheme_ok {
        return Err(ConfigError::fatal(format!(
            "{name} must be https (http only for 127.0.0.1, localhost, or [::1])"
        )));
    }
    if url.query().is_some() || url.fragment().is_some() || !url.username().is_empty() {
        return Err(ConfigError::fatal(format!(
            "{name} must not have a query, fragment, or user"
        )));
    }
    Ok(url)
}

/// The kind of a claims failure, without the claim values.
fn claims_kind(error: &ClaimsVerificationError) -> &'static str {
    match error {
        ClaimsVerificationError::Expired(_) => "expired or bad iat",
        ClaimsVerificationError::InvalidAudience(_) => "audience",
        ClaimsVerificationError::InvalidAuthContext(_) => "acr",
        ClaimsVerificationError::InvalidAuthTime(_) => "auth_time",
        ClaimsVerificationError::InvalidIssuer(_) => "issuer",
        ClaimsVerificationError::InvalidNonce(_) => "nonce",
        ClaimsVerificationError::InvalidSubject(_) => "subject",
        ClaimsVerificationError::SignatureVerification(
            SignatureVerificationError::NoMatchingKey,
        ) => "no key for the key id",
        ClaimsVerificationError::SignatureVerification(
            SignatureVerificationError::DisallowedAlg(_)
            | SignatureVerificationError::UnsupportedAlg(_),
        ) => "algorithm",
        ClaimsVerificationError::SignatureVerification(SignatureVerificationError::NoSignature) => {
            "unsigned"
        }
        ClaimsVerificationError::SignatureVerification(_) => "signature",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::{claimed_groups, moved, secure_url};
    use serde_json::json;
    use url::Url;

    #[test]
    fn a_provider_or_public_url_is_https_or_local() {
        assert!(secure_url("X", "https://auth.example.org").is_ok());
        assert!(secure_url("X", "http://127.0.0.1:9000").is_ok());
        assert!(secure_url("X", "http://[::1]:9000").is_ok());
        assert!(secure_url("X", "http://auth.example.org").is_err());
        assert!(secure_url("X", "https://auth.example.org/?a=b").is_err());
        assert!(secure_url("X", "https://user@auth.example.org").is_err());
        assert!(secure_url("X", "not a url").is_err());
    }

    #[test]
    fn only_endpoints_at_the_public_issuer_move_inside() {
        let public = Url::parse("https://auth.example.org").expect("url");
        let internal = Url::parse("http://tinyauth:3000").expect("url");
        let token = Url::parse("https://auth.example.org/api/oidc/token?x=1").expect("url");
        assert_eq!(
            moved(&token, &public, Some(&internal)).as_str(),
            "http://tinyauth:3000/api/oidc/token?x=1"
        );
        let elsewhere = Url::parse("https://keys.example.net/jwks").expect("url");
        assert_eq!(moved(&elsewhere, &public, Some(&internal)), elsewhere);
        assert_eq!(moved(&token, &public, None), token);
    }

    #[test]
    fn groups_are_an_array_or_a_comma_list() {
        assert_eq!(claimed_groups(Some(&json!(["a", "b", 3]))), ["a", "b"]);
        assert_eq!(claimed_groups(Some(&json!("a, b,,"))), ["a", "b"]);
        assert!(claimed_groups(Some(&json!({"a": 1}))).is_empty());
        assert!(claimed_groups(None).is_empty());
    }
}
