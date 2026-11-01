//! Sign-in through an OpenID Connect provider, the rows between the steps.
//!
//! A pending sign-in lives 10 minutes and a one-time code 60 seconds. Both are found by the
//! SHA-256 of a 32-byte random value and deleted on first use, whether or not that use succeeds.
//! A person is `(issuer, subject)`; email never links accounts, and the same person at two
//! providers is two accounts.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::session::{new_token, open_session_in, token_digest, Origin};
use crate::{DbError, OpenedSession, SessionError};

#[derive(Debug, Error)]
pub enum AuthError {
    /// Signed in at the provider, but not a member, and neither a usable invite nor a joining
    /// group came with it.
    #[error("not a member")]
    NotMember,
    /// Banned: no invite, joining group, or membership lets them in.
    #[error("banned")]
    Banned,
    /// A one-time code that is unknown, used, expired, or presented with the wrong verifier.
    #[error("invalid grant")]
    InvalidGrant(GrantReason),
    #[error(transparent)]
    Database(#[from] DbError),
}

/// Why a one-time code was refused. A missing row is `Used`: the row is deleted on the first
/// try, so a replay and a code that never existed look the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantReason {
    Unknown,
    Used,
    Expired,
    Verifier,
}

impl From<sqlx::Error> for AuthError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(DbError::from(error))
    }
}

/// What `POST /v1/auth/start` keeps until the provider sends the browser back.
pub struct PendingLogin<'a> {
    /// The state sent to the provider. Stored as its SHA-256.
    pub state: &'a str,
    /// The configured provider id the sign-in went to.
    pub provider: &'a str,
    /// The server's PKCE verifier for the provider leg.
    pub verifier: &'a str,
    pub nonce: &'a str,
    pub client_redirect: &'a str,
    pub client_challenge: &'a str,
    pub client_state: &'a str,
    /// An invite token from tinyclient. Stored as its SHA-256.
    pub invite: Option<&'a str>,
}

pub struct Pending {
    pub provider: String,
    pub verifier: String,
    pub nonce: String,
    pub client_redirect: String,
    pub client_challenge: String,
    pub client_state: String,
    pub invite_hash: Option<Vec<u8>>,
}

/// The verified ID token, reduced to what tinyserver keeps.
pub struct Profile {
    pub issuer: String,
    pub subject: String,
    /// Seeds a new account. Never used to find one.
    pub email: Option<String>,
    /// `name`, else `preferred_username`. Seeds a new account's display name.
    pub name: Option<String>,
    /// The provider's session id, for back-channel logout.
    pub sid: Option<String>,
}

/// What the provider's groups claim allows, as the owner configured it. The default allows
/// nothing, which is invite-only sign-in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Groups {
    /// Join without an invite, with this role: `member` or `admin`. Never `owner`.
    pub join: Option<&'static str>,
    /// A member signing in becomes admin.
    pub admin: bool,
}

pub struct SignedIn {
    pub user_id: String,
    pub role: String,
    /// True when this sign-in made the membership, through the invite or the groups.
    pub joined: bool,
}

pub async fn save_pending(pool: &PgPool, login: &PendingLogin<'_>) -> Result<(), DbError> {
    let state_hash = token_digest(login.state);
    let invite_hash = login.invite.map(token_digest);
    sqlx::query(
        "INSERT INTO auth_pending
             (state_hash, provider, verifier, nonce, client_redirect, client_challenge,
              client_state, invite_hash, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now() + interval '10 minutes')",
    )
    .bind(state_hash.as_slice())
    .bind(login.provider)
    .bind(login.verifier)
    .bind(login.nonce)
    .bind(login.client_redirect)
    .bind(login.client_challenge)
    .bind(login.client_state)
    .bind(invite_hash.as_ref().map(|hash| hash.as_slice()))
    .execute(pool)
    .await?;
    Ok(())
}

type PendingRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    Option<Vec<u8>>,
    bool,
);

/// Deletes the pending sign-in for `state` and returns it, or `None` when there is none or it
/// expired. A state works once.
pub async fn take_pending(pool: &PgPool, state: &str) -> Result<Option<Pending>, DbError> {
    let state_hash = token_digest(state);
    let row: Option<PendingRow> = sqlx::query_as(
        "DELETE FROM auth_pending
         WHERE state_hash = $1
         RETURNING provider, verifier, nonce, client_redirect, client_challenge, client_state,
                   invite_hash, expires_at > now()",
    )
    .bind(state_hash.as_slice())
    .fetch_optional(pool)
    .await?;
    let Some((
        provider,
        verifier,
        nonce,
        client_redirect,
        client_challenge,
        client_state,
        invite_hash,
        fresh,
    )) = row
    else {
        return Ok(None);
    };
    Ok(fresh.then_some(Pending {
        provider,
        verifier,
        nonce,
        client_redirect,
        client_challenge,
        client_state,
        invite_hash,
    }))
}

/// The provider leg of a pending sign-in, enough to build its authorization URL again.
pub struct ProviderLeg {
    pub provider: String,
    pub verifier: String,
    pub nonce: String,
}

/// What a pending sign-in with an invite may do about a sign-up link at the provider.
pub enum SignupClaim {
    /// Claimed now. Ask the provider for one link, and only one.
    Claimed(ProviderLeg),
    /// A link was already asked for on this sign-in. No second one.
    AlreadyMade(ProviderLeg),
    /// The invite is unknown, expired, used up, or revoked.
    InviteUnusable,
    /// No such pending sign-in, it expired, or it carries no invite.
    Gone,
}

/// The provider leg of a fresh pending sign-in that carries an invite, without spending it.
pub async fn invited_pending(pool: &PgPool, state: &str) -> Result<Option<ProviderLeg>, DbError> {
    let state_hash = token_digest(state);
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT provider, verifier, nonce FROM auth_pending
         WHERE state_hash = $1 AND expires_at > now() AND invite_hash IS NOT NULL",
    )
    .bind(state_hash.as_slice())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(provider, verifier, nonce)| ProviderLeg {
        provider,
        verifier,
        nonce,
    }))
}

/// Marks the pending sign-in for `state` as having asked for a sign-up link, when it is fresh,
/// carries an invite that could still be accepted, and has not asked before. Two tries at once
/// claim it once.
pub async fn claim_signup(pool: &PgPool, state: &str) -> Result<SignupClaim, DbError> {
    let state_hash = token_digest(state);
    let claimed: Option<(String, String, String)> = sqlx::query_as(
        "UPDATE auth_pending SET signup_at = now()
         WHERE state_hash = $1 AND expires_at > now() AND invite_hash IS NOT NULL
           AND signup_at IS NULL AND app_invite_usable(invite_hash)
         RETURNING provider, verifier, nonce",
    )
    .bind(state_hash.as_slice())
    .fetch_optional(pool)
    .await?;
    if let Some((provider, verifier, nonce)) = claimed {
        return Ok(SignupClaim::Claimed(ProviderLeg {
            provider,
            verifier,
            nonce,
        }));
    }
    let row: Option<(String, String, String, bool)> = sqlx::query_as(
        "SELECT provider, verifier, nonce, signup_at IS NOT NULL FROM auth_pending
         WHERE state_hash = $1 AND expires_at > now() AND invite_hash IS NOT NULL",
    )
    .bind(state_hash.as_slice())
    .fetch_optional(pool)
    .await?;
    Ok(match row {
        None => SignupClaim::Gone,
        Some((provider, verifier, nonce, true)) => SignupClaim::AlreadyMade(ProviderLeg {
            provider,
            verifier,
            nonce,
        }),
        Some((_, _, _, false)) => SignupClaim::InviteUnusable,
    })
}

/// Gives the claim back when the provider made no link, so the person can try again.
pub async fn release_signup(pool: &PgPool, state: &str) -> Result<(), DbError> {
    let state_hash = token_digest(state);
    sqlx::query("UPDATE auth_pending SET signup_at = NULL WHERE state_hash = $1")
        .bind(state_hash.as_slice())
        .execute(pool)
        .await?;
    Ok(())
}

/// Points the identity `user_id` has at `issuer` to `subject`, or gives them one there. For a
/// provider whose subjects changed, such as a move from Tinyauth to Pocket ID at the same
/// issuer. Runs as `app_owner`. Returns false when that user does not exist.
pub async fn relink_identity(
    pool: &PgPool,
    user_id: &str,
    issuer: &str,
    subject: &str,
) -> Result<Relinked, DbError> {
    let mut tx = pool.begin().await?;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE id = $1::uuid)")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
    if !exists {
        return Ok(Relinked::NoSuchUser);
    }
    let taken: Option<String> = sqlx::query_scalar(
        "SELECT user_id::text FROM user_identities WHERE issuer = $1 AND subject = $2",
    )
    .bind(issuer)
    .bind(subject)
    .fetch_optional(&mut *tx)
    .await?;
    match taken {
        Some(owner) if owner == user_id => return Ok(Relinked::Unchanged),
        Some(owner) => return Ok(Relinked::Taken { user_id: owner }),
        None => {}
    }
    let previous: Option<String> = sqlx::query_scalar(
        "DELETE FROM user_identities WHERE user_id = $1::uuid AND issuer = $2 RETURNING subject",
    )
    .bind(user_id)
    .bind(issuer)
    .fetch_optional(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO user_identities (user_id, issuer, subject) VALUES ($1::uuid, $2, $3)")
        .bind(user_id)
        .bind(issuer)
        .bind(subject)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO audit_log (actor_id, action, subject, detail, subject_user_id)
         VALUES (NULL, 'identity.relink', 'user',
                 jsonb_build_object('issuer', $2::text, 'subject', $3::text,
                                    'previous_subject', $4::text),
                 $1::uuid)",
    )
    .bind(user_id)
    .bind(issuer)
    .bind(subject)
    .bind(previous.as_deref())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Relinked::Moved { previous })
}

/// What `relink_identity` did.
#[derive(Debug, PartialEq, Eq)]
pub enum Relinked {
    /// The identity now names the new subject. `previous` is the subject it had, if any.
    Moved {
        previous: Option<String>,
    },
    /// It already did.
    Unchanged,
    /// Another account has that identity: someone signed in with it already.
    Taken {
        user_id: String,
    },
    NoSuchUser,
}

/// Every identity, for the operator: user id, display name, issuer, subject.
pub async fn list_identities(
    pool: &PgPool,
) -> Result<Vec<(String, String, String, String)>, DbError> {
    let rows = sqlx::query_as(
        "SELECT u.id::text, u.display_name, i.issuer, i.subject
         FROM user_identities i JOIN users u ON u.id = i.user_id
         ORDER BY u.created_at, i.issuer",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Finds the person by `(issuer, subject)`. A member signs in. Anyone else needs the invite
/// whose hash came with the pending sign-in, audited as `invite.accept`, or a joining group,
/// audited as `member.join`. Either makes the account if there is none. An admin group then
/// lifts a member to admin. Nothing is written for someone turned away.
pub async fn sign_in(
    pool: &PgPool,
    profile: &Profile,
    invite_hash: Option<&[u8]>,
    groups: Groups,
) -> Result<SignedIn, AuthError> {
    let mut tx = pool.begin().await?;
    let signed_in = sign_in_in(&mut tx, profile, invite_hash, groups).await?;
    tx.commit().await?;
    Ok(signed_in)
}

/// [`sign_in`] inside a transaction the caller owns and commits. On `Err` the caller must roll
/// back: a refusal writes nothing, but an error may leave the transaction mid-way. The passkey
/// sign-up uses this to make the account, accept the invite, and store the first credential as
/// one unit.
pub(crate) async fn sign_in_in(
    tx: &mut Transaction<'_, Postgres>,
    profile: &Profile,
    invite_hash: Option<&[u8]>,
    groups: Groups,
) -> Result<SignedIn, AuthError> {
    // Two first sign-ins for one person at once would otherwise both make an account.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1 || chr(10) || $2, 0))")
        .bind(&profile.issuer)
        .bind(&profile.subject)
        .execute(&mut **tx)
        .await?;
    let found: Option<String> = sqlx::query_scalar(
        "SELECT user_id::text FROM user_identities WHERE issuer = $1 AND subject = $2",
    )
    .bind(&profile.issuer)
    .bind(&profile.subject)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(user_id) = &found {
        let banned: bool = sqlx::query_scalar("SELECT app_banned($1::uuid)")
            .bind(user_id)
            .fetch_one(&mut **tx)
            .await?;
        if banned {
            return Err(AuthError::Banned);
        }
        let role: Option<String> = sqlx::query_scalar("SELECT app_member_role($1::uuid)")
            .bind(user_id)
            .fetch_one(&mut **tx)
            .await?;
        if let Some(role) = role {
            let role = promote(tx, user_id, &role, &profile.issuer, groups).await?;
            return Ok(SignedIn {
                user_id: user_id.clone(),
                role,
                joined: false,
            });
        }
    }
    if invite_hash.is_none() && groups.join.is_none() {
        return Err(AuthError::NotMember);
    }

    let user_id = match found {
        Some(user_id) => user_id,
        None => {
            let user_id: String = sqlx::query_scalar(
                "INSERT INTO users (email, display_name) VALUES ($1, $2) RETURNING id::text",
            )
            .bind(profile_email(profile.email.as_deref()))
            .bind(profile_name(profile))
            .fetch_one(&mut **tx)
            .await?;
            sqlx::query(
                "INSERT INTO user_identities (user_id, issuer, subject) VALUES ($1::uuid, $2, $3)",
            )
            .bind(&user_id)
            .bind(&profile.issuer)
            .bind(&profile.subject)
            .execute(&mut **tx)
            .await?;
            user_id
        }
    };

    let mut role = None;
    if let Some(invite_hash) = invite_hash {
        // A savepoint, so a bad invite can still fall through to the groups.
        let mut attempt = sqlx::Acquire::begin(&mut **tx).await?;
        let accepted: Result<String, sqlx::Error> =
            sqlx::query_scalar("SELECT app_accept_invite($1, $2::uuid)")
                .bind(invite_hash)
                .bind(&user_id)
                .fetch_one(&mut *attempt)
                .await;
        match accepted {
            Ok(accepted) => {
                attempt.commit().await?;
                role = Some(accepted);
            }
            // Unknown, used, or expired.
            Err(error) if sqlstate(&error) == "P0002" => attempt.rollback().await?,
            Err(error) if banned(&error) => return Err(AuthError::Banned),
            Err(error) => return Err(error.into()),
        }
    }
    let role = match (role, groups.join) {
        (Some(role), _) => role,
        (None, Some(join)) => {
            let joined: Result<String, sqlx::Error> =
                sqlx::query_scalar("SELECT app_join_by_groups($1::uuid, $2, $3)")
                    .bind(&user_id)
                    .bind(join)
                    .bind(&profile.issuer)
                    .fetch_one(&mut **tx)
                    .await;
            match joined {
                Ok(role) => role,
                Err(error) if banned(&error) => return Err(AuthError::Banned),
                Err(error) => return Err(error.into()),
            }
        }
        // The account made above rolls back with the transaction.
        (None, None) => return Err(AuthError::NotMember),
    };
    let role = promote(tx, &user_id, &role, &profile.issuer, groups).await?;
    Ok(SignedIn {
        user_id,
        role,
        joined: true,
    })
}

/// Lifts a member in an admin group to admin. Every other role stays as it is.
async fn promote(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
    role: &str,
    issuer: &str,
    groups: Groups,
) -> Result<String, AuthError> {
    if !groups.admin || role != "member" {
        return Ok(role.to_string());
    }
    let role: String = sqlx::query_scalar("SELECT app_promote_by_groups($1::uuid, $2)")
        .bind(user_id)
        .bind(issuer)
        .fetch_one(&mut **tx)
        .await?;
    Ok(role)
}

/// A one-time code for tinyclient, bound to its PKCE challenge, the issuer, and the provider's
/// session id. Good for 60 seconds.
pub async fn issue_code(
    pool: &PgPool,
    user_id: &str,
    client_challenge: &str,
    issuer: &str,
    sid: Option<&str>,
) -> Result<String, DbError> {
    let code = new_token();
    let digest = token_digest(&code);
    sqlx::query(
        "INSERT INTO auth_codes (code_hash, user_id, client_challenge, issuer, sid, expires_at)
         VALUES ($1, $2::uuid, $3, $4, $5, now() + interval '60 seconds')",
    )
    .bind(digest.as_slice())
    .bind(user_id)
    .bind(client_challenge)
    .bind(issuer)
    .bind(sid)
    .execute(pool)
    .await?;
    Ok(code)
}

/// Trades a one-time code and the client's PKCE verifier for a session that lasts
/// `session_days`. The code is spent by the first try, right or wrong.
pub async fn redeem_code(
    pool: &PgPool,
    code: &str,
    verifier: &str,
    session_days: u32,
) -> Result<OpenedSession, AuthError> {
    if code.is_empty() || code.len() > 128 {
        return Err(AuthError::InvalidGrant(GrantReason::Unknown));
    }
    if !pkce_verifier_shaped(verifier) {
        return Err(AuthError::InvalidGrant(GrantReason::Verifier));
    }
    let digest = token_digest(code);
    let mut tx = pool.begin().await?;
    let row: Option<(String, String, String, Option<String>, bool)> = sqlx::query_as(
        "DELETE FROM auth_codes
         WHERE code_hash = $1
         RETURNING user_id::text, client_challenge, issuer, sid, expires_at > now()",
    )
    .bind(digest.as_slice())
    .fetch_optional(&mut *tx)
    .await?;
    let Some((user_id, challenge, issuer, sid, fresh)) = row else {
        return Err(AuthError::InvalidGrant(GrantReason::Used));
    };
    if !fresh {
        tx.commit().await?;
        return Err(AuthError::InvalidGrant(GrantReason::Expired));
    }
    if !challenge_matches(verifier, &challenge) {
        tx.commit().await?;
        return Err(AuthError::InvalidGrant(GrantReason::Verifier));
    }
    let origin = Origin {
        issuer: Some(&issuer),
        sid: sid.as_deref(),
        days: session_days,
    };
    let opened = match open_session_in(&mut tx, &user_id, origin).await {
        Ok(opened) => opened,
        // Removed between the callback and now.
        Err(SessionError::Unauthorized) => {
            tx.commit().await?;
            return Err(AuthError::InvalidGrant(GrantReason::Unknown));
        }
        Err(SessionError::Database(error)) => return Err(AuthError::Database(error)),
    };
    tx.commit().await?;
    Ok(opened)
}

/// Back-channel logout: ends the sessions that came from `issuer` for the provider session
/// `sid`, or for the person `subject` there, or for both together. Each person's live sockets
/// close through `session.ended`, and the end is audited as `session.logout`. Returns how many
/// sessions ended.
pub async fn end_provider_sessions(
    pool: &PgPool,
    issuer: &str,
    subject: Option<&str>,
    sid: Option<&str>,
) -> Result<u64, DbError> {
    if subject.is_none() && sid.is_none() {
        return Ok(0);
    }
    let mut tx = pool.begin().await?;
    let user_id: Option<String> = match subject {
        Some(subject) => {
            let found: Option<String> = sqlx::query_scalar(
                "SELECT user_id::text FROM user_identities WHERE issuer = $1 AND subject = $2",
            )
            .bind(issuer)
            .bind(subject)
            .fetch_optional(&mut *tx)
            .await?;
            let Some(found) = found else {
                return Ok(0);
            };
            Some(found)
        }
        None => None,
    };
    let ended: Vec<String> = sqlx::query_scalar(
        "DELETE FROM sessions
         WHERE issuer = $1
           AND ($2::text IS NULL OR sid = $2)
           AND ($3::uuid IS NULL OR user_id = $3::uuid)
         RETURNING user_id::text",
    )
    .bind(issuer)
    .bind(sid)
    .bind(user_id.as_deref())
    .fetch_all(&mut *tx)
    .await?;
    let mut users: Vec<&String> = ended.iter().collect();
    users.sort();
    users.dedup();
    for user in users {
        let count = ended.iter().filter(|ended| *ended == user).count() as i64;
        // The provider has no account here, so the row names the person whose sessions ended.
        sqlx::query("SELECT set_config('app.user_id', $1, true)")
            .bind(user)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO audit_log (actor_id, action, subject, detail)
             VALUES ($1::uuid, 'session.logout', 'session',
                     jsonb_build_object('user_id', $1::text, 'via', 'backchannel',
                                        'issuer', $2::text, 'sessions_ended', $3::bigint))",
        )
        .bind(user)
        .bind(issuer)
        .bind(count)
        .execute(&mut *tx)
        .await?;
        sqlx::query("SELECT app_emit('session.ended', jsonb_build_object('user_id', $1::text))")
            .bind(user)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(ended.len() as u64)
}

/// `BASE64URL(SHA-256(verifier))`, RFC 7636 S256.
pub fn s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// RFC 7636: 43 to 128 characters from the unreserved set.
pub fn pkce_verifier_shaped(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len()) && verifier.bytes().all(unreserved)
}

/// An S256 challenge: 32 bytes in URL-safe base64 without padding.
pub fn pkce_challenge_shaped(challenge: &str) -> bool {
    challenge.len() == 43
        && challenge
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        && URL_SAFE_NO_PAD
            .decode(challenge)
            .is_ok_and(|raw| raw.len() == 32)
}

fn unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn challenge_matches(verifier: &str, challenge: &str) -> bool {
    let computed = s256(verifier);
    computed.len() == challenge.len() && bool::from(computed.as_bytes().ct_eq(challenge.as_bytes()))
}

/// The provider's email if it looks like one and fits, else none.
fn profile_email(email: Option<&str>) -> Option<String> {
    let email = email?.trim();
    let shaped = !email.is_empty()
        && email.chars().count() <= 254
        && email.contains('@')
        && !email.chars().any(|c| c.is_whitespace() || c.is_control());
    shaped.then(|| email.to_string())
}

/// `name`, else the email's local part, else "Member", without control characters and cut to
/// 80 characters. The person can change it afterwards.
fn profile_name(profile: &Profile) -> String {
    let local = profile
        .email
        .as_deref()
        .and_then(|email| email.split_once('@'))
        .map(|(local, _)| local);
    [profile.name.as_deref(), local]
        .into_iter()
        .flatten()
        .map(|name| {
            let cleaned: String = name.chars().filter(|c| !c.is_control()).collect();
            cleaned.trim().chars().take(80).collect::<String>()
        })
        .map(|name| name.trim().to_string())
        .find(|name| !name.is_empty())
        .unwrap_or_else(|| "Member".to_string())
}

fn banned(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|error| error.message() == "banned")
}

fn sqlstate(error: &sqlx::Error) -> String {
    error
        .as_database_error()
        .and_then(|error| error.code())
        .map(|code| code.to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{
        challenge_matches, pkce_challenge_shaped, pkce_verifier_shaped, profile_email,
        profile_name, s256, Profile,
    };

    fn profile(email: Option<&str>, name: Option<&str>) -> Profile {
        Profile {
            issuer: "https://auth.example".to_string(),
            subject: "s".to_string(),
            email: email.map(str::to_string),
            name: name.map(str::to_string),
            sid: None,
        }
    }

    #[test]
    fn s256_matches_the_rfc_7636_example() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            s256(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert!(challenge_matches(
            verifier,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
        assert!(!challenge_matches(
            verifier,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cN"
        ));
        assert!(!challenge_matches(verifier, ""));
    }

    #[test]
    fn verifier_and_challenge_shapes() {
        assert!(pkce_verifier_shaped(&"a".repeat(43)));
        assert!(pkce_verifier_shaped(&"a~._-".repeat(25)));
        assert!(!pkce_verifier_shaped(&"a".repeat(42)));
        assert!(!pkce_verifier_shaped(&"a".repeat(129)));
        assert!(!pkce_verifier_shaped(&format!("{}+", "a".repeat(43))));
        assert!(pkce_challenge_shaped(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
        assert!(!pkce_challenge_shaped(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c="
        ));
        assert!(!pkce_challenge_shaped("short"));
    }

    #[test]
    fn a_profile_seeds_a_name_and_maybe_an_email() {
        assert_eq!(
            profile_name(&profile(Some("moss@example.org"), Some("  Moss  "))),
            "Moss"
        );
        assert_eq!(
            profile_name(&profile(Some("moss@example.org"), Some(" \u{7} "))),
            "moss"
        );
        assert_eq!(profile_name(&profile(None, None)), "Member");
        assert_eq!(
            profile_name(&profile(None, Some(&"n".repeat(200))))
                .chars()
                .count(),
            80
        );
        assert_eq!(
            profile_email(Some(" moss@example.org ")).as_deref(),
            Some("moss@example.org")
        );
        assert_eq!(profile_email(Some("not an email")), None);
        assert_eq!(profile_email(Some(&format!("{}@x", "a".repeat(260)))), None);
        assert_eq!(profile_email(None), None);
    }
}
