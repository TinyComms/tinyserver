//! First-run setup: what this community collects about its members, chosen by the owner.
//!
//! Three choices, each enforced where the data is made or read, not only recorded:
//!
//! * [`ProviderProfile`]: what is kept from an identity provider when someone first signs in
//!   with it (`api::auth`).
//! * [`ActivityVisibility`]: who sees last-seen and how a member joined
//!   (`community::member_select`), and whether last-seen is recorded at all (`app_seen`).
//! * [`SignInMethods`]: which kind of sign-in is accepted from someone who is not yet a member
//!   (`api::auth`).
//!
//! The defaults are what the server did before there was a setup, so an upgrade changes nothing
//! until the owner chooses. Setup is owner-only; there is no permission bit for it.

use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use thiserror::Error;

use crate::community::{audit, from_sql, scope, STAMP};
use crate::error::DbError;
use crate::outbox::emit;
use crate::server::{settings_in, ServerSettings};
use crate::session::{new_token, token_digest};
use crate::{Caller, CommunityError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderProfile {
    /// The name and the email address the provider gives. What the server did before.
    Full,
    /// The name, never an email address.
    Name,
    /// Neither: the account starts as "Member" and the person picks a name.
    None,
}

impl ProviderProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Name => "name",
            Self::None => "none",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "full" => Some(Self::Full),
            "name" => Some(Self::Name),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    /// Whether an email address from the provider is kept.
    pub fn keeps_email(self) -> bool {
        self == Self::Full
    }

    /// Whether the name from the provider, or the start of its email, seeds the display name.
    pub fn keeps_name(self) -> bool {
        self != Self::None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActivityVisibility {
    Everyone,
    /// Holders of manage_server.
    Admins,
    /// Not recorded.
    Nobody,
}

impl ActivityVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Everyone => "everyone",
            Self::Admins => "admins",
            Self::Nobody => "nobody",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "everyone" => Some(Self::Everyone),
            "admins" => Some(Self::Admins),
            "nobody" => Some(Self::Nobody),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignInMethods {
    /// An identity provider. What the server did before passkeys.
    Provider,
    /// A provider or a passkey.
    Any,
    /// Passkeys only: a new sign-in through an identity provider is refused.
    Passkey,
}

impl SignInMethods {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::Any => "any",
            Self::Passkey => "passkey",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "provider" => Some(Self::Provider),
            "any" => Some(Self::Any),
            "passkey" => Some(Self::Passkey),
            _ => None,
        }
    }
}

/// The three choices as they stand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Posture {
    pub provider_profile: ProviderProfile,
    pub activity_visibility: ActivityVisibility,
    pub sign_in_methods: SignInMethods,
}

impl Posture {
    /// What the server did before it had a setup.
    pub const CONVENIENCE: Posture = Posture {
        provider_profile: ProviderProfile::Full,
        activity_visibility: ActivityVisibility::Everyone,
        sign_in_methods: SignInMethods::Provider,
    };

    /// The least the server can keep and still work.
    pub const PRIVACY: Posture = Posture {
        provider_profile: ProviderProfile::None,
        activity_visibility: ActivityVisibility::Nobody,
        sign_in_methods: SignInMethods::Passkey,
    };
}

/// A starting point. The owner may still change any one choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Preset {
    Convenience,
    Privacy,
}

impl Preset {
    pub fn posture(self) -> Posture {
        match self {
            Self::Convenience => Posture::CONVENIENCE,
            Self::Privacy => Posture::PRIVACY,
        }
    }
}

/// The choices as sign-in reads them. A `None` row cannot happen: there is always one
/// `server_settings` row.
pub async fn posture(pool: &PgPool) -> Result<Posture, DbError> {
    let mut conn = pool.acquire().await?;
    posture_in(&mut conn).await
}

pub(crate) async fn posture_in(conn: &mut sqlx::PgConnection) -> Result<Posture, DbError> {
    // A database that has not had the setup migration yet behaves as the server always did,
    // instead of failing every sign-in until it is migrated.
    let migrated: bool = sqlx::query_scalar("SELECT to_regprocedure('app_posture()') IS NOT NULL")
        .fetch_one(&mut *conn)
        .await?;
    if !migrated {
        return Ok(Posture::CONVENIENCE);
    }
    let row: (String, String, String) = sqlx::query_as(
        "SELECT provider_profile, activity_visibility, sign_in_methods FROM app_posture()",
    )
    .fetch_one(conn)
    .await?;
    posture_from(&row.0, &row.1, &row.2)
}

fn posture_from(profile: &str, activity: &str, methods: &str) -> Result<Posture, DbError> {
    // The columns carry check constraints, so this is only a corrupt row.
    let corrupt = || DbError::Sql(sqlx::Error::Protocol("unknown posture value".into()));
    Ok(Posture {
        provider_profile: ProviderProfile::parse(profile).ok_or_else(corrupt)?,
        activity_visibility: ActivityVisibility::parse(activity).ok_or_else(corrupt)?,
        sign_in_methods: SignInMethods::parse(methods).ok_or_else(corrupt)?,
    })
}

/// What the owner is shown: whether setup has been done, the choices as they stand, and what
/// changing them would reach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SetupState {
    /// When an owner first applied setup, `None` until then.
    pub completed_at: Option<String>,
    pub posture: Posture,
    pub members: i32,
    /// Members who could not sign in under passkeys only until they add one.
    pub members_without_passkey: i32,
    /// Members who could not sign in under a provider only until they add one.
    pub members_without_provider: i32,
    /// Members with an email address on file, which 'erase emails' would remove.
    pub emails_stored: i32,
    /// Whether the owner has a passkey, which passkeys only needs before it can be chosen.
    pub owner_has_passkey: bool,
    /// Whether the owner has a provider sign-in, which provider only needs before it can be
    /// chosen again.
    pub owner_has_provider: bool,
}

/// The owner's choices to apply. `None` leaves a choice as it is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SetupChange {
    pub provider_profile: Option<ProviderProfile>,
    pub activity_visibility: Option<ActivityVisibility>,
    pub sign_in_methods: Option<SignInMethods>,
    /// Remove every member's stored email address. One way.
    pub erase_emails: bool,
    /// Choose passkeys only (or a provider only) although some members have no such sign-in
    /// yet: they cannot sign in until the owner gives them a claim link.
    pub allow_lockout: bool,
}

impl SetupChange {
    pub fn preset(preset: Preset) -> Self {
        let posture = preset.posture();
        Self {
            provider_profile: Some(posture.provider_profile),
            activity_visibility: Some(posture.activity_visibility),
            sign_in_methods: Some(posture.sign_in_methods),
            ..Self::default()
        }
    }
}

/// What applying did, beyond the choices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Applied {
    pub settings: ServerSettings,
    pub emails_erased: i32,
    pub last_seen_cleared: i32,
}

#[derive(Debug, Error)]
pub enum SetupError {
    /// Not an owner.
    #[error("forbidden")]
    Forbidden,
    /// Passkeys only, while the owner has no passkey: the owner could not sign in again.
    #[error("owner needs a passkey")]
    OwnerNeedsPasskey,
    /// Passkeys only, while this many members have no passkey.
    #[error("{0} members have no passkey")]
    MembersWithoutPasskey(i32),
    /// Provider only, while the owner has no provider sign-in.
    #[error("owner needs a provider sign-in")]
    OwnerNeedsProvider,
    /// Provider only, while this many members have no provider sign-in.
    #[error("{0} members have no provider sign-in")]
    MembersWithoutProvider(i32),
    /// A claim link for someone who is not a current member (unknown, deleted or banned).
    #[error("no such member")]
    NoSuchMember,
    #[error(transparent)]
    Community(#[from] CommunityError),
}

fn classify(error: sqlx::Error) -> SetupError {
    if let Some(db) = error.as_database_error() {
        let message = db.message();
        match db.code().as_deref() {
            Some("42501") => return SetupError::Forbidden,
            // P0002: not a current member. 22P02: not even a uuid.
            Some("P0002" | "22P02") => return SetupError::NoSuchMember,
            Some("22023") if message == "owner_needs_passkey" => {
                return SetupError::OwnerNeedsPasskey
            }
            Some("22023") if message == "owner_needs_provider" => {
                return SetupError::OwnerNeedsProvider
            }
            Some("22023") => {
                if let Some(count) = message
                    .strip_prefix("members_without_passkey:")
                    .and_then(|count| count.parse().ok())
                {
                    return SetupError::MembersWithoutPasskey(count);
                }
                if let Some(count) = message
                    .strip_prefix("members_without_provider:")
                    .and_then(|count| count.parse().ok())
                {
                    return SetupError::MembersWithoutProvider(count);
                }
            }
            _ => {}
        }
    }
    SetupError::Community(from_sql(error))
}

/// Owners only.
pub async fn setup_state(pool: &PgPool, caller: &Caller) -> Result<SetupState, SetupError> {
    let mut tx = scope(pool, caller).await?;
    let row: (
        Option<String>,
        String,
        String,
        String,
        i32,
        i32,
        i32,
        i32,
        bool,
        bool,
    ) = sqlx::query_as(&format!(
        "SELECT to_char(completed_at AT TIME ZONE 'UTC', '{STAMP}'),
                    provider_profile, activity_visibility, sign_in_methods,
                    members, members_without_passkey, members_without_provider,
                    emails_stored, owner_has_passkey, owner_has_provider
             FROM app_setup_state()"
    ))
    .fetch_one(&mut *tx)
    .await
    .map_err(classify)?;
    tx.commit().await.map_err(from_sql)?;
    let posture = posture_from(&row.1, &row.2, &row.3).map_err(CommunityError::Database)?;
    Ok(SetupState {
        completed_at: row.0,
        posture,
        members: row.4,
        members_without_passkey: row.5,
        members_without_provider: row.6,
        emails_stored: row.7,
        owner_has_passkey: row.8,
        owner_has_provider: row.9,
    })
}

/// A member as the owner's checklist shows them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SetupMember {
    pub user_id: String,
    pub display_name: String,
    /// Has a passkey.
    pub passkey: bool,
    /// Has a sign-in through an identity provider.
    pub provider: bool,
}

/// Owners only. Every member who is not banned, the owner included, by name.
pub async fn setup_members(pool: &PgPool, caller: &Caller) -> Result<Vec<SetupMember>, SetupError> {
    let mut tx = scope(pool, caller).await?;
    let rows: Vec<(String, String, bool, bool)> = sqlx::query_as(
        "SELECT user_id::text, display_name, passkey, provider FROM app_setup_members()",
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(classify)?;
    tx.commit().await.map_err(from_sql)?;
    Ok(rows
        .into_iter()
        .map(|(user_id, display_name, passkey, provider)| SetupMember {
            user_id,
            display_name,
            passkey,
            provider,
        })
        .collect())
}

/// Owners only. A claim link for each member named, good for `days` (1 to 90), audited with the
/// owner as the actor. Returns `(user_id, token)` in the order given. A token is shown once and
/// kept only as a hash. An older link for the same member stops working. All in one
/// transaction: `NoSuchMember` for anyone banned, deleted or not a member refuses the lot and
/// replaces nothing.
pub async fn claim_links_for(
    pool: &PgPool,
    caller: &Caller,
    user_ids: &[String],
    days: i32,
) -> Result<Vec<(String, String)>, SetupError> {
    let mut tx = scope(pool, caller).await?;
    let mut made = Vec::with_capacity(user_ids.len());
    for user_id in user_ids {
        let token = new_token();
        sqlx::query("SELECT app_setup_claim_link($1, $2::uuid, $3)")
            .bind(token_digest(&token).as_slice())
            .bind(user_id)
            .bind(days)
            .execute(&mut *tx)
            .await
            .map_err(classify)?;
        made.push((user_id.clone(), token));
    }
    tx.commit().await.map_err(from_sql)?;
    Ok(made)
}

/// Owners only. Applies the choices and marks setup done, in one transaction, audited as
/// `setup.apply` with the choices and the counts, never a name or an address. Applying again
/// later changes the choices the same way.
pub async fn apply_setup(
    pool: &PgPool,
    caller: &Caller,
    change: &SetupChange,
    providers: bool,
) -> Result<Applied, SetupError> {
    let mut tx = scope(pool, caller).await?;
    let (emails_erased, last_seen_cleared): (i32, i32) = sqlx::query_as(
        "SELECT emails_erased, last_seen_cleared
         FROM app_setup_apply($1, $2, $3, $4, $5, $6)",
    )
    .bind(change.provider_profile.map(ProviderProfile::as_str))
    .bind(change.activity_visibility.map(ActivityVisibility::as_str))
    .bind(change.sign_in_methods.map(SignInMethods::as_str))
    .bind(change.erase_emails)
    .bind(change.allow_lockout)
    .bind(providers)
    .fetch_one(&mut *tx)
    .await
    .map_err(classify)?;
    let settings = settings_in(&mut tx).await?;
    audit(
        &mut tx,
        "setup.apply",
        "server",
        json!({
            "provider_profile": settings.provider_profile,
            "activity_visibility": settings.activity_visibility,
            "sign_in_methods": settings.sign_in_methods,
            "emails_erased": emails_erased,
            "last_seen_cleared": last_seen_cleared,
            "allow_lockout": change.allow_lockout,
        }),
    )
    .await?;
    emit(&mut tx, "server.updated", json!({ "server": settings })).await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(Applied {
        settings,
        emails_erased,
        last_seen_cleared,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_convenience_preset_is_what_the_server_did_before() {
        assert_eq!(Preset::Convenience.posture(), Posture::CONVENIENCE);
        assert_eq!(Posture::CONVENIENCE.provider_profile, ProviderProfile::Full);
        assert_eq!(
            Posture::CONVENIENCE.activity_visibility,
            ActivityVisibility::Everyone
        );
        assert_eq!(
            Posture::CONVENIENCE.sign_in_methods,
            SignInMethods::Provider
        );
    }

    #[test]
    fn the_privacy_preset_keeps_the_least() {
        let privacy = Preset::Privacy.posture();
        assert!(!privacy.provider_profile.keeps_email());
        assert!(!privacy.provider_profile.keeps_name());
        assert_eq!(privacy.activity_visibility, ActivityVisibility::Nobody);
        assert_eq!(privacy.sign_in_methods, SignInMethods::Passkey);
    }

    #[test]
    fn a_choice_is_read_back_as_it_was_written() {
        for profile in [
            ProviderProfile::Full,
            ProviderProfile::Name,
            ProviderProfile::None,
        ] {
            assert_eq!(ProviderProfile::parse(profile.as_str()), Some(profile));
        }
        for activity in [
            ActivityVisibility::Everyone,
            ActivityVisibility::Admins,
            ActivityVisibility::Nobody,
        ] {
            assert_eq!(ActivityVisibility::parse(activity.as_str()), Some(activity));
        }
        for methods in [
            SignInMethods::Provider,
            SignInMethods::Any,
            SignInMethods::Passkey,
        ] {
            assert_eq!(SignInMethods::parse(methods.as_str()), Some(methods));
        }
        assert_eq!(SignInMethods::Provider.as_str(), "provider");
        assert_eq!(SignInMethods::Any.as_str(), "any");
        assert_eq!(SignInMethods::Passkey.as_str(), "passkey");
        assert_eq!(ProviderProfile::parse("everything"), None);
        assert_eq!(ActivityVisibility::parse(""), None);
        assert_eq!(SignInMethods::parse("Passkey"), None);
    }

    #[test]
    fn a_preset_is_a_change_of_all_three_choices_and_nothing_else() {
        let change = SetupChange::preset(Preset::Privacy);
        assert_eq!(change.provider_profile, Some(ProviderProfile::None));
        assert_eq!(change.activity_visibility, Some(ActivityVisibility::Nobody));
        assert_eq!(change.sign_in_methods, Some(SignInMethods::Passkey));
        assert!(!change.erase_emails && !change.allow_lockout);
    }
}
