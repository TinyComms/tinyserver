//! First-run setup. After the owner signs in for the first time, a client asks `GET /v1/setup`
//! and offers the choices it describes; `PUT /v1/setup` applies them. The same two routes change
//! the choices later.
//!
//! The server writes the outline itself, so a client shows what the server will really do and
//! has no copy of its own to keep in step. Owners only: these choices say what the community
//! keeps about everyone in it.

use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use db::{
    ActivityVisibility, PgPool, Preset, ProviderProfile, SetupChange, SetupError, SignInMethods,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::community::{caller, lift, ApiError};
use crate::oidc::SignIn;

/// What the owner reads where a provider would be named and none is configured.
pub(crate) const NO_PROVIDER_NAME: &str = "your sign-in provider";

/// What this deployment offers, from how the server was started. Fixed for the life of the
/// process.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct Deployment {
    /// Built-in passkey sign-in is on.
    pub passkeys: bool,
    /// At least one identity provider is configured.
    pub sso: bool,
    /// What the first provider is called, for the words the owner reads.
    #[serde(skip)]
    pub provider_name: String,
}

impl Deployment {
    pub(crate) fn of(sign_in: Option<&SignIn>) -> Self {
        Self {
            passkeys: true,
            sso: sign_in.is_some_and(SignIn::has_providers),
            provider_name: sign_in
                .filter(|sign_in| sign_in.has_providers())
                .map_or_else(
                    || NO_PROVIDER_NAME.to_string(),
                    |sign_in| sign_in.provider_name().to_string(),
                ),
        }
    }
}

pub fn routes(deployment: Deployment, public_url: String) -> Router<PgPool> {
    Router::new()
        .route("/v1/setup", get(show).put(apply))
        .route("/v1/setup/claim-links", post(claim_links))
        .layer(Extension(deployment))
        .layer(Extension(PublicUrl(public_url)))
}

/// What the owner is told about one choice, option by option.
fn choices(deployment: &Deployment) -> Value {
    let name = deployment.provider_name.as_str();
    json!([
        {
            "id": "provider_profile",
            "title": "What to keep from a sign-in provider",
            "question": "When someone first joins through single sign-on, what should the \
                         server keep from their account there?",
            // Passkey accounts have no provider, so this only reaches single sign-on.
            "relevant": deployment.sso,
            "options": [
                {
                    "id": "full",
                    "title": "Name and email address",
                    "effect": "Keeps the name and email address the provider gives. People who \
                               manage the server can see members' email addresses."
                },
                {
                    "id": "name",
                    "title": "Name only",
                    "effect": "Keeps the name and never an email address."
                },
                {
                    "id": "none",
                    "title": "Nothing",
                    "effect": "Keeps neither. New members start as \u{201c}Member\u{201d} and \
                               choose their own name."
                }
            ]
        },
        {
            "id": "activity_visibility",
            "title": "Who sees when members were last online",
            "question": "Should members, or only admins, see when someone was last online and \
                         how they joined (by invite or through a group)?",
            "relevant": true,
            "options": [
                {
                    "id": "everyone",
                    "title": "Every member",
                    "effect": "Everyone sees when others were last online and how they \n                               joined."
                },
                {
                    "id": "admins",
                    "title": "Admins only",
                    "effect": "Only people who manage the server see it."
                },
                {
                    "id": "nobody",
                    "title": "Nobody",
                    "effect": "The server stops recording when anyone was last online and clears \
                               what it has. No one sees how a member joined."
                }
            ]
        },
        {
            "id": "sign_in_methods",
            "title": "How members sign in",
            "question": "Which sign-in methods should the server accept?",
            "relevant": deployment.sso,
            "options": [
                {
                    "id": "provider",
                    "title": format!("Through {name} only"),
                    "effect": format!(
                        "Members sign in through {name} and nothing else. Passkeys already \
                         made keep working but aren't offered."
                    ),
                    "needs": ["owner_has_provider"]
                },
                {
                    "id": "any",
                    "title": format!("Passkeys, or through {name}"),
                    "effect": format!(
                        "Members may sign in with a passkey or through {name}. The sign-in \
                         page offers both."
                    ),
                    "needs": []
                },
                {
                    "id": "passkey",
                    "title": "Passkeys only",
                    "effect": format!(
                        "Members sign in with a passkey and nothing else. People who only \
                         have a {name} account cannot sign in until you give them a link to \
                         add a passkey. Sessions already open carry on."
                    ),
                    "needs": ["owner_has_passkey"]
                }
            ]
        }
    ])
}

fn presets() -> Value {
    json!([
        {
            "id": "convenience",
            "title": "Convenience",
            "summary": "Easiest to run, and how the server worked before this setup. Names and \
                        email addresses from sign-in are kept, everyone sees when others were \
                        last online, and members sign in through your sign-in provider.",
            "choices": Preset::Convenience.posture(),
            "available": true
        },
        {
            "id": "privacy",
            "title": "Privacy",
            "summary": "Keeps the least about members. Nothing is kept from a sign-in provider, \
                        nobody's last-online time is recorded, and members sign in with passkeys \
                        only.",
            "choices": Preset::Privacy.posture(),
            "available": true
        }
    ])
}

/// Facts that hold whatever is chosen, so the owner is not left to guess.
fn always() -> Value {
    json!([
        "There are no usernames. A member has a display name, which is not unique, and signs in \
         with a passkey or through a sign-in provider.",
        "The server sends no analytics or crash reports anywhere."
    ])
}

async fn show(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Extension(deployment): Extension<Deployment>,
) -> Result<Json<Value>, SetupFailure> {
    let caller = caller(&pool, &headers).await?;
    let state = db::setup_state(&pool, &caller).await?;
    let members = db::setup_members(&pool, &caller).await?;
    Ok(Json(json!({
        "needed": state.completed_at.is_none(),
        "completed_at": state.completed_at,
        "current": state.posture,
        "deployment": &deployment,
        "counts": {
            "members": state.members,
            "members_without_passkey": state.members_without_passkey,
            "emails_stored": state.emails_stored,
            "members_without_provider": state.members_without_provider,
            "owner_has_passkey": state.owner_has_passkey,
            "owner_has_provider": state.owner_has_provider,
        },
        "members": members,
        "presets": presets(),
        "choices": choices(&deployment),
        "always": always(),
    })))
}

/// Every field is optional. A preset sets all three choices; a named choice then overrides it.
/// `{}` keeps everything as it is and marks setup done.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ApplyBody {
    #[serde(default)]
    preset: Option<Preset>,
    #[serde(default)]
    provider_profile: Option<ProviderProfile>,
    #[serde(default)]
    activity_visibility: Option<ActivityVisibility>,
    #[serde(default)]
    sign_in_methods: Option<SignInMethods>,
    /// Remove the email address of every member. One way.
    #[serde(default)]
    erase_emails: bool,
    /// Choose passkeys only although some members have no passkey yet.
    #[serde(default)]
    allow_lockout: bool,
}

impl ApplyBody {
    fn change(&self) -> SetupChange {
        let mut change = self.preset.map(SetupChange::preset).unwrap_or_default();
        change.provider_profile = self.provider_profile.or(change.provider_profile);
        change.activity_visibility = self.activity_visibility.or(change.activity_visibility);
        change.sign_in_methods = self.sign_in_methods.or(change.sign_in_methods);
        change.erase_emails = self.erase_emails;
        change.allow_lockout = self.allow_lockout;
        change
    }
}

async fn apply(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Extension(deployment): Extension<Deployment>,
    body: Result<Json<ApplyBody>, JsonRejection>,
) -> Result<Json<db::Applied>, SetupFailure> {
    let caller = caller(&pool, &headers).await?;
    let Json(body) = body.map_err(|_| SetupFailure::Api(ApiError::Invalid))?;
    let applied = db::apply_setup(&pool, &caller, &body.change(), deployment.sso).await?;
    tracing::info!(
        user_id = %caller.user_id,
        provider_profile = applied.settings.provider_profile.as_str(),
        activity_visibility = applied.settings.activity_visibility.as_str(),
        sign_in_methods = applied.settings.sign_in_methods.as_str(),
        emails_erased = applied.emails_erased,
        last_seen_cleared = applied.last_seen_cleared,
        "setup applied"
    );
    Ok(Json(applied))
}

#[derive(Clone)]
struct PublicUrl(String);

const MOST_LINKS: usize = 200;
const DEFAULT_DAYS: i32 = 14;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimLinksBody {
    user_ids: Vec<String>,
    #[serde(default)]
    days: Option<i32>,
}

/// Passkey claim links for the members named, so the owner can hand each person theirs. The
/// token is in the URL's fragment and the server keeps only its hash, so the links are shown
/// once here and never listed. Any id that is not a current member refuses the whole request.
async fn claim_links(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Extension(PublicUrl(public_url)): Extension<PublicUrl>,
    body: Result<Json<ClaimLinksBody>, JsonRejection>,
) -> Result<Json<Value>, SetupFailure> {
    let caller = caller(&pool, &headers).await?;
    // Owners only, before anything about the request is judged.
    let members = db::setup_members(&pool, &caller).await?;
    let Json(body) = body.map_err(|_| SetupFailure::BadRequest)?;
    let days = body.days.unwrap_or(DEFAULT_DAYS);
    if body.user_ids.len() > MOST_LINKS || !(1..=90).contains(&days) {
        return Err(SetupFailure::BadRequest);
    }
    // One link per member, in the order first named.
    let mut ids: Vec<String> = Vec::with_capacity(body.user_ids.len());
    for id in &body.user_ids {
        let id = id.to_lowercase();
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    // Minted in one transaction: any id that is not a current member refuses the lot.
    let made = db::claim_links_for(&pool, &caller, &ids, days).await?;
    let links: Vec<Value> = made
        .into_iter()
        .map(|(user_id, token)| {
            let name = members
                .iter()
                .find(|member| member.user_id == user_id)
                .map(|member| member.display_name.as_str());
            json!({
                "user_id": user_id,
                "display_name": name,
                "url": crate::passkey::claim_url(&public_url, &token),
            })
        })
        .collect();
    tracing::info!(user_id = %caller.user_id, links = links.len(), days, "claim links made");
    Ok(Json(json!({ "links": links })))
}

/// A refusal, with the reason the owner can act on.
enum SetupFailure {
    Api(ApiError),
    /// A claim-links request that names someone who is not a member, or asks for a bad lifetime.
    BadRequest,
    OwnerNeedsPasskey,
    MembersWithoutPasskey(i32),
    OwnerNeedsProvider,
    MembersWithoutProvider(i32),
}

impl From<ApiError> for SetupFailure {
    fn from(error: ApiError) -> Self {
        Self::Api(error)
    }
}

impl From<SetupError> for SetupFailure {
    fn from(error: SetupError) -> Self {
        match error {
            SetupError::Forbidden => Self::Api(ApiError::Forbidden),
            SetupError::OwnerNeedsPasskey => Self::OwnerNeedsPasskey,
            SetupError::MembersWithoutPasskey(count) => Self::MembersWithoutPasskey(count),
            SetupError::OwnerNeedsProvider => Self::OwnerNeedsProvider,
            SetupError::MembersWithoutProvider(count) => Self::MembersWithoutProvider(count),
            SetupError::NoSuchMember => Self::BadRequest,
            SetupError::Community(error) => Self::Api(lift(error)),
        }
    }
}

impl IntoResponse for SetupFailure {
    fn into_response(self) -> Response {
        match self {
            Self::Api(error) => error.into_response(),
            Self::BadRequest => (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "bad_request"})),
            )
                .into_response(),
            Self::OwnerNeedsPasskey => conflict(json!({"error": "owner_needs_passkey"})),
            Self::MembersWithoutPasskey(count) => {
                conflict(json!({"error": "members_without_passkey", "count": count}))
            }
            Self::OwnerNeedsProvider => conflict(json!({"error": "owner_needs_provider"})),
            Self::MembersWithoutProvider(count) => {
                conflict(json!({"error": "members_without_provider", "count": count}))
            }
        }
    }
}

fn conflict(body: Value) -> Response {
    (StatusCode::CONFLICT, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use db::Posture;

    #[test]
    fn a_named_choice_overrides_the_preset_and_the_rest_stand() {
        let body = ApplyBody {
            preset: Some(Preset::Privacy),
            sign_in_methods: Some(SignInMethods::Any),
            ..ApplyBody::default()
        };
        let change = body.change();
        assert_eq!(change.provider_profile, Some(ProviderProfile::None));
        assert_eq!(change.activity_visibility, Some(ActivityVisibility::Nobody));
        assert_eq!(change.sign_in_methods, Some(SignInMethods::Any));
    }

    #[test]
    fn an_empty_body_changes_no_choice() {
        let change = ApplyBody::default().change();
        assert_eq!(change, SetupChange::default());
    }

    #[test]
    fn every_option_the_outline_offers_is_one_the_server_accepts() {
        let deployment = Deployment {
            passkeys: true,
            sso: true,
            provider_name: "Acme".to_string(),
        };
        for choice in choices(&deployment).as_array().expect("choices") {
            let id = choice["id"].as_str().expect("id");
            for option in choice["options"].as_array().expect("options") {
                let option = option["id"].as_str().expect("option");
                let known = match id {
                    "provider_profile" => ProviderProfile::parse(option).is_some(),
                    "activity_visibility" => ActivityVisibility::parse(option).is_some(),
                    "sign_in_methods" => SignInMethods::parse(option).is_some(),
                    other => panic!("unknown choice {other}"),
                };
                assert!(known, "{id}: {option}");
            }
        }
    }

    #[test]
    fn a_preset_in_the_outline_is_the_posture_it_applies() {
        for preset in presets().as_array().expect("presets") {
            let posture: Posture = match preset["id"].as_str().expect("id") {
                "convenience" => Preset::Convenience.posture(),
                "privacy" => Preset::Privacy.posture(),
                other => panic!("unknown preset {other}"),
            };
            assert_eq!(preset["choices"], json!(posture));
        }
    }

    #[test]
    fn both_presets_are_always_offered() {
        for preset in presets().as_array().expect("presets") {
            assert_eq!(preset["available"], true);
            assert!(preset.get("unavailable").is_none());
        }
    }
}
