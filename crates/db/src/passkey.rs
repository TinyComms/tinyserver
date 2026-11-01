//! Passkey sign-in, the rows behind it.
//!
//! A passkey is a source of `(issuer, subject)` like an OpenID Connect provider: the issuer is
//! [`PASSKEY_ISSUER`] and the subject is a random 128-bit account id. Invites, bans, roles,
//! sessions and account deletion are the machinery `auth.rs` already runs. The tables here are
//! reached only through the `app_passkey_*` functions of migration 0030; the owner-side calls
//! at the bottom (roster, claim links, retiring OIDC identities) run as `app_owner`.
//!
//! Nothing here stores an address, a user agent, an email or a name beyond what a person typed
//! at sign-up. Recovery codes and claim links are kept only as hashes.

use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::auth::{sign_in_in, AuthError, Groups, Profile, SignedIn};
use crate::community::{from_sql, scope};
use crate::session::{new_token, token_digest};
use crate::{Caller, CommunityError, DbError};

/// The issuer every passkey identity carries.
pub const PASSKEY_ISSUER: &str = "tinyserver:passkey";

/// Recovery codes in a set.
pub const RECOVERY_CODES: usize = 10;

/// A ceremony lives this long, whatever the kind.
pub const CEREMONY_SECS: i32 = 300;

/// After a passkey is made, the person has this long to save their recovery codes.
pub const CONTINUE_SECS: i32 = 900;

#[derive(Debug, Error)]
pub enum PasskeyError {
    /// Unknown, expired, spent, or not this person's.
    #[error("not found")]
    NotFound,
    /// A rule refused it: banned, or the account already has another passkey identity.
    #[error("refused")]
    Refused,
    /// The credential id is already registered.
    #[error("already registered")]
    Taken,
    #[error("invalid")]
    Invalid,
    /// Too many ceremonies are open at once.
    #[error("busy")]
    Busy,
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Database(#[from] DbError),
}

fn from_pg(error: sqlx::Error) -> PasskeyError {
    let code = error
        .as_database_error()
        .and_then(|db| db.code().map(|code| code.to_string()));
    match code.as_deref() {
        Some("P0002") => PasskeyError::NotFound,
        Some("42501") => PasskeyError::Refused,
        Some("23505") => PasskeyError::Taken,
        Some("22023" | "23514" | "23503") => PasskeyError::Invalid,
        Some("53400") => PasskeyError::Busy,
        _ => PasskeyError::Database(DbError::from(error)),
    }
}

/// 32 random bytes, URL-safe base64: a ceremony id, a claim link token, a sign-in state.
pub fn random_id() -> String {
    new_token()
}

// Recovery codes.

/// Crockford's base32: no I, L, O or U, so a code read aloud or copied by hand survives.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A set of recovery codes, each 25 characters in five groups: 125 bits.
pub fn new_recovery_codes(count: usize) -> Vec<String> {
    (0..count)
        .map(|_| {
            let mut raw = [0u8; 25];
            getrandom::fill(&mut raw).expect("the OS random number generator failed");
            let mut code = String::with_capacity(29);
            for (index, byte) in raw.iter().enumerate() {
                if index > 0 && index % 5 == 0 {
                    code.push('-');
                }
                // 256 is a multiple of 32, so masking leaves no bias.
                code.push(char::from(ALPHABET[usize::from(byte & 31)]));
            }
            code
        })
        .collect()
}

/// The hash a code is stored under, or `None` for something that is not shaped like a code.
/// Case, dashes and spaces do not matter, and `I`, `L` and `O` read as `1`, `1` and `0`.
pub fn recovery_hash(code: &str) -> Option<[u8; 32]> {
    let mut normal = String::with_capacity(25);
    for character in code.chars() {
        match character.to_ascii_uppercase() {
            '-' | ' ' => {}
            'I' | 'L' => normal.push('1'),
            'O' => normal.push('0'),
            other if other.is_ascii() && ALPHABET.contains(&(other as u8)) => normal.push(other),
            _ => return None,
        }
    }
    if normal.len() != 25 {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(b"tinyserver recovery v1\n");
    hasher.update(normal.as_bytes());
    Some(hasher.finalize().into())
}

fn code_hashes(codes: &[String]) -> Result<Vec<Vec<u8>>, PasskeyError> {
    codes
        .iter()
        .map(|code| {
            recovery_hash(code)
                .map(|hash| hash.to_vec())
                .ok_or(PasskeyError::Invalid)
        })
        .collect()
}

// Ceremonies.

/// A ceremony to begin. `id` is the random value the page holds; only its hash is stored.
pub struct NewCeremony<'a> {
    /// `signup`, `login`, `recover`, `claim` or `continue`.
    pub kind: &'a str,
    pub id: &'a str,
    /// The library's state for this challenge.
    pub state: Option<&'a Value>,
    pub user: Option<&'a str>,
    pub subject: Option<&'a str>,
    /// The sign-in state this ceremony belongs to.
    pub pending: Option<&'a str>,
    pub display_name: Option<&'a str>,
    /// A claim link token or recovery code, kept as its hash, so the finishing call can prove it
    /// is the same one that began.
    pub secret: Option<&'a [u8]>,
    pub ttl_secs: i32,
}

pub async fn begin_ceremony(pool: &PgPool, ceremony: &NewCeremony<'_>) -> Result<(), PasskeyError> {
    sqlx::query("SELECT app_passkey_ceremony_begin($1, $2, $3, $4::uuid, $5, $6, $7, $8, $9)")
        .bind(ceremony.kind)
        .bind(token_digest(ceremony.id).as_slice())
        .bind(ceremony.state)
        .bind(ceremony.user)
        .bind(ceremony.subject)
        .bind(ceremony.pending.map(|state| token_digest(state).to_vec()))
        .bind(ceremony.display_name)
        .bind(ceremony.secret)
        .bind(ceremony.ttl_secs)
        .execute(pool)
        .await
        .map_err(from_pg)?;
    Ok(())
}

/// A ceremony that was spent.
pub struct Ceremony {
    pub state: Option<Value>,
    pub user_id: Option<String>,
    pub subject: Option<String>,
    pub pending_hash: Option<Vec<u8>>,
    pub display_name: Option<String>,
    pub secret_hash: Option<Vec<u8>>,
}

impl Ceremony {
    /// True when this ceremony was begun for the sign-in `state`.
    pub fn belongs_to(&self, state: &str) -> bool {
        self.pending_hash
            .as_deref()
            .is_some_and(|hash| bool::from(hash.ct_eq(&token_digest(state))))
    }

    /// True when this ceremony was begun with exactly this secret hash.
    pub fn has_secret(&self, secret: &[u8]) -> bool {
        self.secret_hash
            .as_deref()
            .is_some_and(|hash| bool::from(hash.ct_eq(secret)))
    }
}

type CeremonyRow = (
    Option<Value>,
    Option<String>,
    Option<String>,
    Option<Vec<u8>>,
    Option<String>,
    Option<Vec<u8>>,
);

/// Spends the ceremony. It is gone whether or not what follows works, so a challenge is good
/// for one try. `None` for an unknown id, the wrong kind, or one that expired.
pub async fn take_ceremony(
    pool: &PgPool,
    kind: &str,
    id: &str,
) -> Result<Option<Ceremony>, PasskeyError> {
    let row: Option<CeremonyRow> = sqlx::query_as(
        "SELECT state, user_id::text, subject, pending_hash, display_name, secret_hash
         FROM app_passkey_ceremony_take($1, $2)",
    )
    .bind(kind)
    .bind(token_digest(id).as_slice())
    .fetch_optional(pool)
    .await
    .map_err(from_pg)?;
    Ok(row.map(
        |(state, user_id, subject, pending_hash, display_name, secret_hash)| Ceremony {
            state,
            user_id,
            subject,
            pending_hash,
            display_name,
            secret_hash,
        },
    ))
}

/// After the passkey is made: the step that lets the person read their recovery codes before
/// tinyclient gets its code. The pending sign-in is kept alive for it.
pub async fn begin_continue(
    pool: &PgPool,
    id: &str,
    user_id: &str,
    subject: &str,
    pending: &str,
) -> Result<(), PasskeyError> {
    sqlx::query("SELECT app_passkey_continue($1::uuid, $2, $3, $4, $5)")
        .bind(user_id)
        .bind(subject)
        .bind(token_digest(pending).as_slice())
        .bind(token_digest(id).as_slice())
        .bind(CONTINUE_SECS)
        .execute(pool)
        .await
        .map_err(from_pg)?;
    Ok(())
}

/// A fresh pending sign-in, read without spending it.
pub struct PendingPeek {
    pub provider: String,
    pub verifier: String,
    pub nonce: String,
    pub invite_hash: Option<Vec<u8>>,
}

pub async fn peek_pending(pool: &PgPool, state: &str) -> Result<Option<PendingPeek>, DbError> {
    let row: Option<(String, String, String, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT provider, verifier, nonce, invite_hash FROM auth_pending
         WHERE state_hash = $1 AND expires_at > now()",
    )
    .bind(token_digest(state).as_slice())
    .fetch_optional(pool)
    .await?;
    Ok(
        row.map(|(provider, verifier, nonce, invite_hash)| PendingPeek {
            provider,
            verifier,
            nonce,
            invite_hash,
        }),
    )
}

/// An invite that could still be accepted.
pub async fn invite_usable(pool: &PgPool, invite_hash: &[u8]) -> Result<bool, DbError> {
    let usable: bool = sqlx::query_scalar("SELECT app_invite_usable($1)")
        .bind(invite_hash)
        .fetch_one(pool)
        .await?;
    Ok(usable)
}

// Credentials.

/// A verified credential to keep.
pub struct NewCredential<'a> {
    pub credential_id: &'a [u8],
    /// The library's serialisation of the credential.
    pub passkey: &'a Value,
    pub sign_count: i64,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub label: &'a str,
}

async fn insert_in(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
    subject: &str,
    credential: &NewCredential<'_>,
) -> Result<(), PasskeyError> {
    sqlx::query("SELECT app_passkey_insert($1::uuid, $2, $3, $4, $5, $6, $7, $8)")
        .bind(user_id)
        .bind(subject)
        .bind(credential.credential_id)
        .bind(credential.passkey)
        .bind(credential.sign_count)
        .bind(credential.backup_eligible)
        .bind(credential.backup_state)
        .bind(credential.label)
        .execute(&mut **tx)
        .await
        .map_err(from_pg)?;
    Ok(())
}

async fn seed_in(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
    hashes: &[Vec<u8>],
) -> Result<bool, PasskeyError> {
    let seeded: bool = sqlx::query_scalar("SELECT app_passkey_seed_recovery($1::uuid, $2)")
        .bind(user_id)
        .bind(hashes)
        .fetch_one(&mut **tx)
        .await
        .map_err(from_pg)?;
    Ok(seeded)
}

async fn attach_in(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
    subject: &str,
) -> Result<(), PasskeyError> {
    let attached: bool = sqlx::query_scalar("SELECT app_passkey_attach($1::uuid, $2)")
        .bind(user_id)
        .bind(subject)
        .fetch_one(&mut **tx)
        .await
        .map_err(from_pg)?;
    if attached {
        Ok(())
    } else {
        // The account already signs in as another passkey subject.
        Err(PasskeyError::Refused)
    }
}

/// The passkey subject an account already has.
pub async fn subject_of(pool: &PgPool, user_id: &str) -> Result<Option<String>, PasskeyError> {
    sqlx::query_scalar("SELECT app_passkey_subject_of($1::uuid)")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .map_err(from_pg)
}

/// A credential found by its id, with the subject its account signs in as.
pub struct Found {
    pub id: String,
    pub user_id: String,
    pub subject: String,
    pub passkey: Value,
    pub flagged: bool,
}

pub async fn find_credential(
    pool: &PgPool,
    credential_id: &[u8],
) -> Result<Option<Found>, PasskeyError> {
    let row: Option<(String, String, String, Value, bool)> = sqlx::query_as(
        "SELECT id::text, user_id::text, subject, passkey, flagged FROM app_passkey_find($1)",
    )
    .bind(credential_id)
    .fetch_optional(pool)
    .await
    .map_err(from_pg)?;
    Ok(row.map(|(id, user_id, subject, passkey, flagged)| Found {
        id,
        user_id,
        subject,
        passkey,
        flagged,
    }))
}

/// The credential ids an account has, so a new registration cannot repeat one.
pub async fn credential_ids_of(pool: &PgPool, user_id: &str) -> Result<Vec<Vec<u8>>, PasskeyError> {
    let rows: Vec<(Vec<u8>,)> =
        sqlx::query_as("SELECT credential_id FROM app_passkey_credentials_of($1::uuid)")
            .bind(user_id)
            .fetch_all(pool)
            .await
            .map_err(from_pg)?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// After a good assertion: the counter and flags the credential now has, and when it was used.
pub async fn record_use(
    pool: &PgPool,
    id: &str,
    passkey: &Value,
    sign_count: i64,
    backup_eligible: bool,
    backup_state: bool,
) -> Result<(), PasskeyError> {
    sqlx::query("SELECT app_passkey_record_use($1::uuid, $2, $3, $4, $5)")
        .bind(id)
        .bind(passkey)
        .bind(sign_count)
        .bind(backup_eligible)
        .bind(backup_state)
        .execute(pool)
        .await
        .map_err(from_pg)?;
    Ok(())
}

/// A valid signature with a counter that did not go up: refuse this credential from now on.
pub async fn flag_credential(pool: &PgPool, id: &str) -> Result<(), PasskeyError> {
    sqlx::query("SELECT app_passkey_flag($1::uuid)")
        .bind(id)
        .execute(pool)
        .await
        .map_err(from_pg)?;
    Ok(())
}

// Sign-up, claim and recovery: each makes the credential and what goes with it as one unit.

pub struct Signup<'a> {
    pub subject: &'a str,
    pub display_name: &'a str,
    pub invite_hash: &'a [u8],
    pub credential: &'a NewCredential<'a>,
    pub codes: &'a [String],
}

/// A new member: the account, the invite, the passkey and the first recovery codes, or none of
/// them. A refused invite spends nothing.
pub async fn signup(pool: &PgPool, signup: &Signup<'_>) -> Result<SignedIn, PasskeyError> {
    let hashes = code_hashes(signup.codes)?;
    let mut tx = pool.begin().await.map_err(from_pg)?;
    let profile = Profile {
        issuer: PASSKEY_ISSUER.to_string(),
        subject: signup.subject.to_string(),
        email: None,
        name: Some(signup.display_name.to_string()),
        sid: None,
    };
    let signed_in = sign_in_in(
        &mut tx,
        &profile,
        Some(signup.invite_hash),
        Groups::default(),
    )
    .await?;
    insert_in(
        &mut tx,
        &signed_in.user_id,
        signup.subject,
        signup.credential,
    )
    .await?;
    seed_in(&mut tx, &signed_in.user_id, &hashes).await?;
    tx.commit().await.map_err(from_pg)?;
    Ok(signed_in)
}

/// The member a live claim link is for, with the name they go by.
pub async fn peek_claim(
    pool: &PgPool,
    token: &str,
) -> Result<Option<(String, String)>, PasskeyError> {
    let user: Option<String> = sqlx::query_scalar("SELECT app_passkey_claim_peek($1)::text")
        .bind(token_digest(token).as_slice())
        .fetch_one(pool)
        .await
        .map_err(from_pg)?;
    let Some(user) = user else {
        return Ok(None);
    };
    let name: Option<String> =
        sqlx::query_scalar("SELECT display_name FROM users WHERE id = $1::uuid")
            .bind(&user)
            .fetch_optional(pool)
            .await
            .map_err(from_pg)?;
    Ok(name.map(|name| (user, name)))
}

/// The hash a claim link token is kept under.
pub fn claim_hash(token: &str) -> [u8; 32] {
    token_digest(token)
}

pub struct Claim<'a> {
    pub token: &'a str,
    pub user_id: &'a str,
    pub subject: &'a str,
    pub credential: &'a NewCredential<'a>,
    pub codes: &'a [String],
}

/// A member's passkey on their existing account: the link is spent, the passkey attached, and a
/// first set of recovery codes made if they had none. Returns whether codes were made. The
/// member keeps their id, roles, messages and device keys: nothing about the account changes.
pub async fn claim(pool: &PgPool, claim: &Claim<'_>) -> Result<bool, PasskeyError> {
    let hashes = code_hashes(claim.codes)?;
    let mut tx = pool.begin().await.map_err(from_pg)?;
    sqlx::query("SELECT app_passkey_claim_consume($1, $2::uuid)")
        .bind(token_digest(claim.token).as_slice())
        .bind(claim.user_id)
        .execute(&mut *tx)
        .await
        .map_err(from_pg)?;
    attach_in(&mut tx, claim.user_id, claim.subject).await?;
    insert_in(&mut tx, claim.user_id, claim.subject, claim.credential).await?;
    let seeded = seed_in(&mut tx, claim.user_id, &hashes).await?;
    tx.commit().await.map_err(from_pg)?;
    Ok(seeded)
}

/// The account an unused recovery code belongs to.
pub async fn recovery_owner(pool: &PgPool, hash: &[u8]) -> Result<Option<String>, PasskeyError> {
    sqlx::query_scalar("SELECT app_passkey_recovery_lookup($1)::text")
        .bind(hash)
        .fetch_one(pool)
        .await
        .map_err(from_pg)
}

pub struct Recovery<'a> {
    pub code_hash: &'a [u8],
    pub user_id: &'a str,
    pub subject: &'a str,
    pub credential: &'a NewCredential<'a>,
}

/// Spends a recovery code and keeps a new passkey for its account, together. Returns the codes
/// left. A code that two tries use at once works for one.
pub async fn recover(pool: &PgPool, recovery: &Recovery<'_>) -> Result<i32, PasskeyError> {
    let mut tx = pool.begin().await.map_err(from_pg)?;
    let left: i32 = sqlx::query_scalar("SELECT app_passkey_recovery_consume($1, $2::uuid)")
        .bind(recovery.code_hash)
        .bind(recovery.user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(from_pg)?;
    attach_in(&mut tx, recovery.user_id, recovery.subject).await?;
    insert_in(
        &mut tx,
        recovery.user_id,
        recovery.subject,
        recovery.credential,
    )
    .await?;
    tx.commit().await.map_err(from_pg)?;
    Ok(left)
}

/// The name an account goes by.
pub async fn display_name_of(pool: &PgPool, user_id: &str) -> Result<Option<String>, PasskeyError> {
    sqlx::query_scalar("SELECT display_name FROM users WHERE id = $1::uuid AND deleted_at IS NULL")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .map_err(from_pg)
}

/// A claim link the caller makes for themself, good for `secs`. Only its hash is kept.
pub async fn claim_link_for_me(
    pool: &PgPool,
    caller: &Caller,
    token: &str,
    secs: i32,
) -> Result<(), CommunityError> {
    let mut tx = scope(pool, caller).await?;
    sqlx::query("SELECT app_passkey_claim_self($1, $2)")
        .bind(token_digest(token).as_slice())
        .bind(secs)
        .execute(&mut *tx)
        .await
        .map_err(from_sql)?;
    tx.commit().await.map_err(from_sql)
}

// A signed-in person's own passkeys.

pub struct PasskeyRow {
    pub id: String,
    pub label: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub flagged: bool,
}

type MineRow = (String, String, String, Option<String>, bool, bool, bool);

pub async fn list_mine(pool: &PgPool, caller: &Caller) -> Result<Vec<PasskeyRow>, CommunityError> {
    let mut tx = scope(pool, caller).await?;
    let rows: Vec<MineRow> = sqlx::query_as(
        "SELECT id::text, label, created_at::text, last_used_at::text, backup_eligible,
                backup_state, flagged
         FROM app_passkey_list()",
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(from_sql)?;
    tx.commit().await.map_err(from_sql)?;
    Ok(rows
        .into_iter()
        .map(
            |(id, label, created_at, last_used_at, backup_eligible, backup_state, flagged)| {
                PasskeyRow {
                    id,
                    label,
                    created_at,
                    last_used_at,
                    backup_eligible,
                    backup_state,
                    flagged,
                }
            },
        )
        .collect())
}

pub async fn rename_mine(
    pool: &PgPool,
    caller: &Caller,
    id: &str,
    label: &str,
) -> Result<(), CommunityError> {
    let label = label.trim();
    if label.is_empty() || label.chars().count() > 60 || label.chars().any(char::is_control) {
        return Err(CommunityError::Invalid);
    }
    let mut tx = scope(pool, caller).await?;
    sqlx::query("SELECT app_passkey_rename($1::uuid, $2)")
        .bind(id)
        .bind(label)
        .execute(&mut *tx)
        .await
        .map_err(from_sql)?;
    tx.commit().await.map_err(from_sql)
}

/// Removes one of the caller's passkeys. The last goes only while an unused recovery code is
/// left, else `Forbidden`.
pub async fn remove_mine(pool: &PgPool, caller: &Caller, id: &str) -> Result<(), CommunityError> {
    let mut tx = scope(pool, caller).await?;
    sqlx::query("SELECT app_passkey_remove($1::uuid)")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(from_sql)?;
    tx.commit().await.map_err(from_sql)
}

/// Recovery codes the caller has left.
pub async fn codes_left(pool: &PgPool, caller: &Caller) -> Result<i32, CommunityError> {
    let mut tx = scope(pool, caller).await?;
    let left: i32 = sqlx::query_scalar("SELECT app_passkey_codes_left()")
        .fetch_one(&mut *tx)
        .await
        .map_err(from_sql)?;
    tx.commit().await.map_err(from_sql)?;
    Ok(left)
}

/// A new set of recovery codes for the caller. Every code of the old set stops working.
pub async fn regenerate_codes(
    pool: &PgPool,
    caller: &Caller,
    codes: &[String],
) -> Result<(), CommunityError> {
    let hashes = code_hashes(codes).map_err(|_| CommunityError::Invalid)?;
    let mut tx = scope(pool, caller).await?;
    sqlx::query("SELECT app_passkey_regenerate($1)")
        .bind(&hashes)
        .execute(&mut *tx)
        .await
        .map_err(from_sql)?;
    tx.commit().await.map_err(from_sql)
}

/// Whether this session opened less than `secs` ago. Adding and removing sign-in methods asks
/// for a recent sign-in, so a stolen old session cannot plant a passkey of its own.
pub async fn session_is_recent(pool: &PgPool, user_id: &str, secs: i32) -> Result<bool, DbError> {
    let recent: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM sessions
                        WHERE user_id = $1::uuid
                          AND created_at > now() - make_interval(secs => $2))",
    )
    .bind(user_id)
    .bind(secs)
    .fetch_one(pool)
    .await?;
    Ok(recent)
}

// The operator's side. These run as `app_owner`, through `DATABASE_URL_MIGRATE`.

/// One member, as the operator sees them while moving a community to passkeys.
pub struct RosterRow {
    pub user_id: String,
    pub display_name: String,
    /// The email an OpenID Connect provider gave when the account was made, if it gave one.
    pub email: Option<String>,
    pub role: Option<String>,
    pub joined_at: String,
    pub last_seen_at: Option<String>,
    pub passkeys: i64,
    pub banned: bool,
    /// The issuers this account can sign in through.
    pub issuers: Vec<String>,
    /// Each of those as `issuer subject`, so a provider identity that is retired later can be
    /// put back with `relink-identity`.
    pub identities: Vec<String>,
}

type RosterTuple = (
    String,
    String,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
    i64,
    bool,
    Vec<String>,
    Vec<String>,
);

/// Every member who has not deleted their account.
pub async fn roster(pool: &PgPool) -> Result<Vec<RosterRow>, DbError> {
    let rows: Vec<RosterTuple> = sqlx::query_as(
        "SELECT u.id::text, u.display_name, u.email, app_member_role(u.id), m.created_at::text,
                m.last_seen_at::text,
                (SELECT count(*) FROM passkey_credentials c WHERE c.user_id = u.id),
                app_banned(u.id),
                coalesce((SELECT array_agg(DISTINCT i.issuer ORDER BY i.issuer)
                          FROM user_identities i WHERE i.user_id = u.id), '{}'),
                coalesce((SELECT array_agg(i.issuer || ' ' || i.subject ORDER BY i.issuer)
                          FROM user_identities i WHERE i.user_id = u.id), '{}')
         FROM users u
         JOIN memberships m ON m.user_id = u.id
         WHERE u.deleted_at IS NULL
         ORDER BY m.created_at, u.id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(
                user_id,
                display_name,
                email,
                role,
                joined_at,
                last_seen_at,
                passkeys,
                banned,
                issuers,
                identities,
            )| RosterRow {
                user_id,
                display_name,
                email,
                role,
                joined_at,
                last_seen_at,
                passkeys,
                banned,
                issuers,
                identities,
            },
        )
        .collect())
}

/// A claim link for `user_id`, good for `days`. Returns the token, which is shown once and kept
/// only as a hash. An older link for the same member stops working.
pub async fn mint_claim(pool: &PgPool, user_id: &str, days: i32) -> Result<String, PasskeyError> {
    if !(1..=90).contains(&days) {
        return Err(PasskeyError::Invalid);
    }
    let token = new_token();
    let mut tx = pool.begin().await.map_err(from_pg)?;
    let made: Option<i32> = sqlx::query_scalar(
        "WITH gone AS (DELETE FROM passkey_claims WHERE user_id = $1::uuid)
         INSERT INTO passkey_claims (token_hash, user_id, expires_at)
         SELECT $2, u.id, now() + make_interval(days => $3)
         FROM users u
         WHERE u.id = $1::uuid AND u.deleted_at IS NULL AND NOT app_banned(u.id)
         RETURNING 1",
    )
    .bind(user_id)
    .bind(token_digest(&token).as_slice())
    .bind(days)
    .fetch_optional(&mut *tx)
    .await
    .map_err(from_pg)?;
    if made.is_none() {
        return Err(PasskeyError::NotFound);
    }
    sqlx::query(
        "INSERT INTO audit_log (actor_id, action, subject, detail, subject_user_id)
         VALUES (NULL, 'passkey.claim_link', 'user', jsonb_build_object('days', $2::int),
                 $1::uuid)",
    )
    .bind(user_id)
    .bind(days)
    .execute(&mut *tx)
    .await
    .map_err(from_pg)?;
    tx.commit().await.map_err(from_pg)?;
    Ok(token)
}

/// What `retire_identities` would do, or did.
pub struct Retired {
    pub user_id: String,
    pub issuer: String,
    /// What the provider called them, kept so the identity can be put back.
    pub subject: String,
}

/// Removes every sign-in identity that is not a passkey from accounts that have a passkey and
/// at least one recovery code, so Pocket ID or any other provider can no longer sign them in.
/// With `dry_run` it removes nothing and says what it would. An account without a passkey keeps
/// its identities: retiring never locks anyone out who could still get in. A ban stays, as it
/// is kept on the account.
pub async fn retire_identities(pool: &PgPool, dry_run: bool) -> Result<Vec<Retired>, DbError> {
    let mut tx = pool.begin().await?;
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT i.user_id::text, i.issuer, i.subject
         FROM user_identities i
         WHERE i.issuer <> $1
           AND EXISTS (SELECT 1 FROM passkey_credentials c WHERE c.user_id = i.user_id
                                                             AND c.flagged_at IS NULL)
           AND EXISTS (SELECT 1 FROM passkey_recovery_codes r WHERE r.user_id = i.user_id)
         ORDER BY i.user_id, i.issuer",
    )
    .bind(PASSKEY_ISSUER)
    .fetch_all(&mut *tx)
    .await?;
    if !dry_run {
        for (user_id, issuer, subject) in &rows {
            sqlx::query(
                "DELETE FROM user_identities
                 WHERE user_id = $1::uuid AND issuer = $2 AND subject = $3",
            )
            .bind(user_id)
            .bind(issuer)
            .bind(subject)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO audit_log (actor_id, action, subject, detail, subject_user_id)
                 VALUES (NULL, 'identity.retire', 'user', jsonb_build_object('issuer', $2::text),
                         $1::uuid)",
            )
            .bind(user_id)
            .bind(issuer)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
    }
    Ok(rows
        .into_iter()
        .map(|(user_id, issuer, subject)| Retired {
            user_id,
            issuer,
            subject,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::{new_recovery_codes, recovery_hash};

    #[test]
    fn a_recovery_code_is_25_characters_in_five_groups_of_five() {
        for code in new_recovery_codes(50) {
            let groups: Vec<&str> = code.split('-').collect();
            assert_eq!(groups.len(), 5, "{code}");
            assert!(groups.iter().all(|group| group.len() == 5), "{code}");
            assert!(recovery_hash(&code).is_some(), "{code}");
        }
    }

    #[test]
    fn two_sets_share_no_code() {
        let mut all: Vec<String> = new_recovery_codes(200);
        all.sort();
        all.dedup();
        assert_eq!(all.len(), 200);
    }

    #[test]
    fn a_code_reads_the_same_in_any_case_with_or_without_dashes() {
        let code = "0123456789ABCDEFGHJKMNPQR";
        let dashed = "01234-56789-ABCDE-FGHJK-MNPQR";
        let spaced = "01234 56789 abcde fghjk mnpqr";
        let hash = recovery_hash(code);
        assert!(hash.is_some());
        assert_eq!(hash, recovery_hash(dashed));
        assert_eq!(hash, recovery_hash(spaced));
    }

    #[test]
    fn look_alike_letters_read_as_the_digits_they_resemble() {
        assert_eq!(
            recovery_hash("OIL00-00000-00000-00000-00000"),
            recovery_hash("01100-00000-00000-00000-00000")
        );
    }

    #[test]
    fn things_that_are_not_codes_have_no_hash() {
        for bad in [
            "",
            "short",
            "0123456789ABCDEFGHJKMNPQ",
            "0123456789ABCDEFGHJKMNPQRS",
            "0123456789ABCDEFGHJKMNPQ!",
            "0123456789ABCDEFGHJKMNPQU",
            "ééééé-ééééé-ééééé-ééééé-ééééé",
        ] {
            assert!(recovery_hash(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn the_stored_hash_is_not_the_plain_digest_of_the_code() {
        use sha2::{Digest, Sha256};
        let code = "0123456789ABCDEFGHJKMNPQR";
        let plain: [u8; 32] = Sha256::digest(code.as_bytes()).into();
        assert_ne!(recovery_hash(code), Some(plain));
    }
}
