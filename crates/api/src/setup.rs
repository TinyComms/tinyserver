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
use axum::routing::get;
use axum::{Extension, Json, Router};
use db::{
    ActivityVisibility, PgPool, Preset, ProviderProfile, SetupChange, SetupError, SignInMethods,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::community::{caller, lift, ApiError};
use crate::oidc::SignIn;

/// What this deployment offers, from how the server was started. Fixed for the life of the
/// process.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct Deployment {
    /// Built-in passkey sign-in is on.
    pub passkeys: bool,
    /// At least one identity provider is configured.
    pub sso: bool,
}

impl Deployment {
    pub(crate) fn of(sign_in: Option<&SignIn>) -> Self {
        Self {
            passkeys: sign_in.is_some_and(|sign_in| sign_in.passkeys().is_some()),
            sso: sign_in.is_some_and(|sign_in| !sign_in.providers().is_empty()),
        }
    }
}

pub fn routes(deployment: Deployment) -> Router<PgPool> {
    Router::new()
        .route("/v1/setup", get(show).put(apply))
        .layer(Extension(deployment))
}

/// What the owner is told about one choice, option by option.
fn choices(deployment: Deployment) -> Value {
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
            "relevant": deployment.passkeys,
            "options": [
                {
                    "id": "any",
                    "title": "Whatever this server offers",
                    "effect": if deployment.sso {
                        "Members sign in with a passkey or with single sign-on."
                    } else {
                        "Members sign in with a passkey."
                    }
                },
                {
                    "id": "passkey",
                    "title": "Passkeys only",
                    "effect": "Members sign in with a passkey and nothing else. People who \
                               only have a single sign-on account cannot sign in until you give \
                               them a link to add a passkey. Sessions already open carry on.",
                    "needs": ["passkeys", "owner_has_passkey"]
                }
            ]
        }
    ])
}

fn presets(deployment: Deployment) -> Value {
    let privacy_available = deployment.passkeys;
    json!([
        {
            "id": "convenience",
            "title": "Convenience",
            "summary": "Easiest to run, and how the server worked before this setup. Names and \
                        email addresses from sign-in are kept, everyone sees when others were \
                        last online, and any sign-in method works.",
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
            "available": privacy_available,
            "unavailable": if privacy_available {
                Value::Null
            } else {
                json!("This server was started without passkey sign-in. Choose privacy with \
                       \"sign_in_methods\": \"any\" to take the rest.")
            }
        }
    ])
}

/// Facts that hold whatever is chosen, so the owner is not left to guess.
fn always() -> Value {
    json!([
        "There are no usernames. A member has a display name, which is not unique, and signs in \
         with a passkey or a single sign-on account.",
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
    Ok(Json(json!({
        "needed": state.completed_at.is_none(),
        "completed_at": state.completed_at,
        "current": state.posture,
        "deployment": deployment,
        "counts": {
            "members": state.members,
            "members_without_passkey": state.members_without_passkey,
            "emails_stored": state.emails_stored,
            "owner_has_passkey": state.owner_has_passkey,
        },
        "presets": presets(deployment),
        "choices": choices(deployment),
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
    let applied = db::apply_setup(&pool, &caller, &body.change(), deployment.passkeys).await?;
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

/// A refusal, with the reason the owner can act on.
enum SetupFailure {
    Api(ApiError),
    PasskeysUnavailable,
    OwnerNeedsPasskey,
    MembersWithoutPasskey(i32),
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
            SetupError::PasskeysUnavailable => Self::PasskeysUnavailable,
            SetupError::OwnerNeedsPasskey => Self::OwnerNeedsPasskey,
            SetupError::MembersWithoutPasskey(count) => Self::MembersWithoutPasskey(count),
            SetupError::Community(error) => Self::Api(lift(error)),
        }
    }
}

impl IntoResponse for SetupFailure {
    fn into_response(self) -> Response {
        match self {
            Self::Api(error) => error.into_response(),
            Self::PasskeysUnavailable => conflict(json!({"error": "passkeys_unavailable"})),
            Self::OwnerNeedsPasskey => conflict(json!({"error": "owner_needs_passkey"})),
            Self::MembersWithoutPasskey(count) => {
                conflict(json!({"error": "members_without_passkey", "count": count}))
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
        };
        for choice in choices(deployment).as_array().expect("choices") {
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
        let deployment = Deployment {
            passkeys: true,
            sso: false,
        };
        for preset in presets(deployment).as_array().expect("presets") {
            let posture: Posture = match preset["id"].as_str().expect("id") {
                "convenience" => Preset::Convenience.posture(),
                "privacy" => Preset::Privacy.posture(),
                other => panic!("unknown preset {other}"),
            };
            assert_eq!(preset["choices"], json!(posture));
        }
    }

    #[test]
    fn privacy_is_not_offered_where_passkeys_are_not() {
        let without = Deployment {
            passkeys: false,
            sso: true,
        };
        let privacy = &presets(without)[1];
        assert_eq!(privacy["available"], false);
        assert!(privacy["unavailable"].is_string());
    }
}
