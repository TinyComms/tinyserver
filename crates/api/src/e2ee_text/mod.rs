//! End-to-end encrypted text and attachments: devices, key packages, the MLS group of each
//! encrypted conversation, and ciphertext posts. The protocol is `docs/e2ee-text.md`.
//!
//! The server is the delivery service and an external sender. It stores ciphertext, public MLS
//! handshake messages and public keys; it signs Add and Remove proposals with one key of its own;
//! it keeps no key that opens a message. What each route checks is here and in the SQL of
//! `migrations/0021` and `0022`, where the group state lives.

mod key_file;
pub(crate) mod mls;

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Extension, Json, Router};
use db::{Caller, Issued, PgPool, Unissued, WelcomeFor};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::OnceCell;

use crate::messages::{lift, member, signed, Error};
use mls::{Refused, Signer};

/// A request that changes state: how many a person may make at once, and how often they get
/// one more back.
const BURST: f64 = 40.0;
const REFILL_PER_SEC: f64 = 2.0;
/// Key packages in one request, and the most of them a commit may add at once.
const KEY_PACKAGES_PER_CALL: usize = 50;
/// The handshake rows one read returns.
const HANDSHAKE_PAGE: i32 = 100;
/// A body of key packages: 50 of 8 KiB as base64, and the fields around them.
const KEY_PACKAGES_BODY: usize = 640 * 1024;
/// A commit, its welcomes and the ratchet tree of the epoch it makes, as base64: 4 MiB of commit,
/// 4 MiB of welcomes and 8 MiB of tree, and the fields around them.
const COMMIT_BODY: usize = 22 * 1024 * 1024;
/// The header of a sealed blob: `"TNYA1"`, the log2 of its chunk size, a 7 byte nonce prefix.
const SEALED_HEADER: usize = 13;
/// What a sealed blob starts with.
const SEALED_MAGIC: &[u8; 5] = b"TNYA1";
/// The AES-GCM tag after each chunk.
const SEALED_TAG: usize = 16;

/// What the routes share. One per router, so a test with its own database has its own key and its
/// own limits.
pub(crate) struct Server {
    signer: OnceCell<Arc<Signer>>,
    limiter: Limiter,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            signer: OnceCell::new(),
            limiter: Limiter::default(),
        }
    }
}

impl Server {
    /// The external sender, made on first use. The public half is in Postgres and the private
    /// half is a file, so a restart keeps the key members pinned and a database dump cannot sign
    /// proposals.
    async fn signer(&self, pool: &PgPool) -> Result<Arc<Signer>, Error> {
        self.signer
            .get_or_try_init(|| async {
                match load_signer(pool).await {
                    Ok(signer) => Ok(Arc::new(signer)),
                    Err(reason) => {
                        tracing::warn!(reason, "e2ee server key unusable");
                        Err(Error::Unavailable)
                    }
                }
            })
            .await
            .cloned()
    }

    fn allow(&self, user_id: &str) -> Result<(), Error> {
        if self.limiter.take(user_id, Instant::now()) {
            Ok(())
        } else {
            Err(Error::SlowDown)
        }
    }
}

/// Copies an old private half out of Postgres, or makes the key, before the process serves.
/// A missing secret is a hard error: this does not mint a new key over one clients already pin.
/// The reason names no key bytes.
pub async fn seal_external_sender(pool: &PgPool) -> Result<(), &'static str> {
    load_signer(pool).await.map(|_| ())
}

/// The file is the secret. Postgres keeps the public half. A public key with no file and no
/// private half is a lost key, and a file that does not match the public half is refused.
async fn load_signer(pool: &PgPool) -> Result<Signer, &'static str> {
    let state = db::server_key_state(pool)
        .await
        .map_err(|_| "e2ee server key could not be read")?;
    let path = key_file::path();
    match state {
        None => fresh_signer(pool, &path).await,
        Some(row) => stored_signer(pool, &path, &row).await,
    }
}

async fn fresh_signer(pool: &PgPool, path: &std::path::Path) -> Result<Signer, &'static str> {
    match key_file::read(path) {
        Ok(stored) => install_file(pool, &stored).await,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let (public, stored) = Signer::generate().ok_or("e2ee server key was not made")?;
            match key_file::create_new(path, &stored) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    let stored = key_file::read(path)
                        .map_err(|_| "e2ee server key file could not be read")?;
                    return install_file(pool, &stored).await;
                }
                Err(_) => return Err("e2ee server key file could not be written"),
            }
            let signer =
                Signer::from_parts(public.clone(), stored).ok_or("e2ee server key was not made")?;
            remember_public(pool, &public, signer.public_key()).await?;
            Ok(signer)
        }
        Err(_) => Err("e2ee server key file could not be read"),
    }
}

async fn stored_signer(
    pool: &PgPool,
    path: &std::path::Path,
    row: &db::ServerKeyRow,
) -> Result<Signer, &'static str> {
    match key_file::read(path) {
        Ok(stored) => {
            let signer =
                Signer::from_stored(&stored).ok_or("e2ee server key file is not usable")?;
            if signer.public_key() != row.public.as_slice() {
                return Err("e2ee server key file does not match the database");
            }
            if row.private.is_some() {
                clear_private(pool).await?;
            }
            Ok(signer)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            copy_private_out(pool, path, row).await
        }
        Err(_) => Err("e2ee server key file could not be read"),
    }
}

/// An upgrade: the private half is still in the row, and the file is not there yet.
async fn copy_private_out(
    pool: &PgPool,
    path: &std::path::Path,
    row: &db::ServerKeyRow,
) -> Result<Signer, &'static str> {
    let Some(stored) = row.private.as_deref() else {
        return Err("e2ee server key file is missing and the database has no copy");
    };
    let signer =
        Signer::from_stored(stored).ok_or("e2ee server key in the database is not usable")?;
    if signer.public_key() != row.public.as_slice() {
        return Err("e2ee server key in the database does not match its public half");
    }
    match key_file::create_new(path, stored) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let stored =
                key_file::read(path).map_err(|_| "e2ee server key file could not be read")?;
            let winner =
                Signer::from_stored(&stored).ok_or("e2ee server key file is not usable")?;
            if winner.public_key() != row.public.as_slice() {
                return Err("e2ee server key file does not match the database");
            }
            clear_private(pool).await?;
            return Ok(winner);
        }
        Err(_) => return Err("e2ee server key file could not be written"),
    }
    clear_private(pool).await?;
    Ok(signer)
}

async fn install_file(pool: &PgPool, stored: &[u8]) -> Result<Signer, &'static str> {
    let signer = Signer::from_stored(stored).ok_or("e2ee server key file is not usable")?;
    remember_public(pool, signer.public_key(), signer.public_key()).await?;
    clear_private(pool).await?;
    Ok(signer)
}

async fn remember_public(pool: &PgPool, public: &[u8], expect: &[u8]) -> Result<(), &'static str> {
    let kept = db::remember_server_public(pool, public)
        .await
        .map_err(|_| "e2ee server public key was not stored")?;
    if kept.as_slice() != expect {
        return Err("e2ee server key file does not match the database");
    }
    Ok(())
}

async fn clear_private(pool: &PgPool) -> Result<(), &'static str> {
    db::clear_server_private(pool)
        .await
        .map_err(|_| "e2ee server key could not be cleared from the database")
}

/// A token bucket per person. Memory only; a restart forgets it.
#[derive(Default)]
struct Limiter {
    buckets: Mutex<HashMap<String, (f64, Instant)>>,
}

impl Limiter {
    fn lock(&self) -> MutexGuard<'_, HashMap<String, (f64, Instant)>> {
        self.buckets
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn take(&self, user_id: &str, now: Instant) -> bool {
        let mut buckets = self.lock();
        if buckets.len() > 4096 {
            buckets.retain(|_, (_, at)| now.saturating_duration_since(*at).as_secs() < 600);
        }
        let entry = buckets.entry(user_id.to_string()).or_insert((BURST, now));
        let gained = now.saturating_duration_since(entry.1).as_secs_f64() * REFILL_PER_SEC;
        entry.0 = (entry.0 + gained).min(BURST);
        entry.1 = now;
        if entry.0 < 1.0 {
            return false;
        }
        entry.0 -= 1.0;
        true
    }
}

pub fn routes() -> Router<PgPool> {
    Router::new()
        .route(
            "/v1/e2ee/devices/{device_id}",
            put(put_device).delete(delete_device),
        )
        .route("/v1/e2ee/users/{user_id}/devices", get(user_devices))
        .route(
            "/v1/e2ee/key_packages",
            post(put_key_packages).layer(DefaultBodyLimit::max(KEY_PACKAGES_BODY)),
        )
        .route("/v1/e2ee/key_packages/count", get(key_package_count))
        .route("/v1/e2ee/conversations/{id}", get(conversation))
        .route("/v1/e2ee/conversations/{id}/group", post(create_group))
        .route(
            "/v1/e2ee/conversations/{id}/reactions",
            get(list_reactions).post(post_reaction),
        )
        .route("/v1/e2ee/conversations/{id}/handshake", get(handshake))
        .route("/v1/e2ee/conversations/{id}/tree", get(ratchet_tree))
        .route(
            "/v1/e2ee/invites/{id}/capability",
            put(set_invite_capability),
        )
        .route("/v1/e2ee/community", get(community).put(set_community))
        .route(
            "/v1/e2ee/conversations/{id}/commit",
            post(commit).layer(DefaultBodyLimit::max(COMMIT_BODY)),
        )
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

fn refused(refusal: Refused) -> Error {
    match refusal {
        Refused::Bad => Error::BadE2ee,
        Refused::TooLarge => Error::TooLarge,
    }
}

fn failed(user_id: &str, route: &'static str, error: &Error) {
    let reason = crate::messages::message_reason(error);
    tracing::warn!(user_id, route, reason, "e2ee failed");
}

#[derive(Deserialize)]
struct DeviceBody {
    signature_key: String,
    cross_signature: Option<String>,
    label: Option<String>,
    #[serde(default)]
    capability_signature: Option<String>,
}

async fn put_device(
    State(pool): State<PgPool>,
    Extension(server): Extension<Arc<Server>>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
    Json(body): Json<DeviceBody>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let caller = member(&pool, &headers).await?;
    register(&pool, &server, &caller, &device_id, &body)
        .await
        .map(|device| (StatusCode::CREATED, Json(device)))
        .inspect_err(|error| failed(&caller.user_id, "devices.put", error))
}

async fn register(
    pool: &PgPool,
    server: &Server,
    caller: &Caller,
    device_id: &str,
    body: &DeviceBody,
) -> Result<Value, Error> {
    server.allow(&caller.user_id)?;
    let key = mls::decode(&body.signature_key, 65).map_err(refused)?;
    // An uncompressed P-256 point. A key that is not a point cannot sign a key package, so a
    // device with one is inert; this only keeps the obvious garbage out.
    if key.len() != 65 || key[0] != 4 {
        return Err(Error::BadE2ee);
    }
    let cross = match &body.cross_signature {
        Some(text) => Some(mls::decode(text, 128).map_err(refused)?),
        None => None,
    };
    let capability = match &body.capability_signature {
        Some(text) => Some(mls::decode(text, 128).map_err(refused)?),
        None => None,
    };
    let active = db::active_keys(pool, caller).await.map_err(lift)?;
    let invite_key = db::invite_capability(pool, caller).await.map_err(lift)?;
    let stored = match cross.as_deref() {
        // The first device is trusted on first use, unless the invite it came through carries a
        // capability key. That key has to have signed this device.
        _ if active.is_empty() => None,
        Some(signature) => {
            if !mls::cross_signed(&caller.user_id, device_id, &key, signature, &active) {
                return Err(Error::BadE2ee);
            }
            Some(signature)
        }
        // None: the database refuses, with `device_exists` if this id is already a device and
        // `cross_signature_required` if not, so that a retry of a registration is told it landed.
        None => None,
    };
    let stored_capability = if active.is_empty() {
        if let Some(invite_key) = invite_key {
            let Some(signature) = capability.as_deref() else {
                return Err(Error::BadE2ee);
            };
            if !mls::device_capability_signed(
                &caller.user_id,
                device_id,
                &key,
                signature,
                &invite_key,
            ) {
                return Err(Error::BadE2ee);
            }
            Some(signature)
        } else {
            None
        }
    } else {
        None
    };
    db::put_device(
        pool,
        caller,
        device_id,
        &key,
        stored,
        body.label.as_deref(),
        stored_capability,
    )
    .await
    .map_err(lift)
}

async fn delete_device(
    State(pool): State<PgPool>,
    Extension(server): Extension<Arc<Server>>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> Result<StatusCode, Error> {
    let caller = member(&pool, &headers).await?;
    server.allow(&caller.user_id)?;
    db::revoke_device(&pool, &caller, &device_id)
        .await
        .map_err(lift)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn user_devices(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, Error> {
    let caller = member(&pool, &headers).await?;
    db::user_devices(&pool, &caller, &user_id)
        .await
        .map(Json)
        .map_err(lift)
}

#[derive(Deserialize)]
struct KeyPackagesBody {
    device_id: String,
    #[serde(default)]
    key_packages: Vec<String>,
    last_resort: Option<String>,
}

async fn put_key_packages(
    State(pool): State<PgPool>,
    Extension(server): Extension<Arc<Server>>,
    headers: HeaderMap,
    Json(body): Json<KeyPackagesBody>,
) -> Result<StatusCode, Error> {
    let caller = member(&pool, &headers).await?;
    server.allow(&caller.user_id)?;
    store_key_packages(&pool, &caller, &body)
        .await
        .inspect_err(|error| failed(&caller.user_id, "key_packages.put", error))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn store_key_packages(
    pool: &PgPool,
    caller: &Caller,
    body: &KeyPackagesBody,
) -> Result<(), Error> {
    if body.key_packages.len() > KEY_PACKAGES_PER_CALL {
        return Err(Error::TooManyKeys);
    }
    // Their own device: its key is what every package must carry.
    let key = db::device_key(pool, caller, &body.device_id)
        .await
        .map_err(lift)?;
    let now = now();
    let mut packages = Vec::with_capacity(body.key_packages.len());
    for text in &body.key_packages {
        let data = mls::decode(text, mls::KEY_PACKAGE_MAX).map_err(refused)?;
        let expires = mls::validate_key_package(&caller.user_id, &body.device_id, &key, &data, now)
            .map_err(refused)?;
        packages.push((data, expires));
    }
    let last = match &body.last_resort {
        Some(text) => {
            let data = mls::decode(text, mls::KEY_PACKAGE_MAX).map_err(refused)?;
            let expires =
                mls::validate_key_package(&caller.user_id, &body.device_id, &key, &data, now)
                    .map_err(refused)?;
            Some((data, expires))
        }
        None => None,
    };
    db::put_key_packages(
        pool,
        caller,
        &body.device_id,
        &packages,
        last.as_ref()
            .map(|(data, expires)| (data.as_slice(), *expires)),
    )
    .await
    .map_err(lift)?;
    Ok(())
}

#[derive(Deserialize)]
struct DeviceQuery {
    device_id: Option<String>,
}

async fn key_package_count(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Query(query): Query<DeviceQuery>,
) -> Result<Json<Value>, Error> {
    let caller = member(&pool, &headers).await?;
    let Some(device_id) = query.device_id else {
        return Err(Error::Invalid);
    };
    db::key_package_count(&pool, &caller, &device_id)
        .await
        .map(Json)
        .map_err(lift)
}

/// Signs every proposal of the group that is due. The members read them from the log.
/// The MLS group id the conversation uses, and whether a ciphertext must name the conversation.
async fn mls_of(
    pool: &PgPool,
    caller: &Caller,
    conversation: &str,
) -> Result<([u8; 16], bool), Error> {
    let target = db::mls_target(pool, caller, conversation)
        .await
        .map_err(lift)?;
    let group = mls::uuid_bytes(&target.group_id).ok_or(Error::Invalid)?;
    Ok((group, target.audience_groups))
}

async fn issue(
    pool: &PgPool,
    server: &Server,
    caller: &Caller,
    conversation: &str,
) -> Result<(), Error> {
    let (group, _) = mls_of(pool, caller, conversation).await?;
    let signer = server.signer(pool).await?;
    db::issue_proposals(pool, caller, conversation, |epoch, items| {
        sign(&signer, &group, epoch, items)
    })
    .await
    .map_err(lift)
}

/// One signed proposal per item, removes first as the database orders them, and the batch a
/// member reads. An Add whose key package no longer parses is dropped.
fn sign(signer: &Signer, group: &[u8; 16], epoch: u64, items: &[Unissued]) -> Option<Issued> {
    let proposals: Vec<Option<Vec<u8>>> = items
        .iter()
        .map(
            |item| match (item.op.as_str(), item.leaf_index, &item.key_package) {
                ("remove", Some(leaf), _) => signer.remove(leaf, group, epoch),
                ("add", _, Some(data)) => {
                    let package = mls::parse_key_package(data).ok()?;
                    signer.add(package, group, epoch)
                }
                _ => None,
            },
        )
        .collect();
    let made: Vec<&[u8]> = proposals.iter().flatten().map(Vec::as_slice).collect();
    let batch = mls::batch(&made)?;
    Some(Issued { proposals, batch })
}

async fn conversation(
    State(pool): State<PgPool>,
    Extension(server): Extension<Arc<Server>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, Error> {
    let caller = member(&pool, &headers).await?;
    let result = async {
        let info = db::group_info(&pool, &caller, &id).await.map_err(lift)?;
        if info.get("e2ee").and_then(Value::as_bool) != Some(true) {
            return Ok(info);
        }
        issue(&pool, &server, &caller, &id).await?;
        let mut info = db::group_info(&pool, &caller, &id).await.map_err(lift)?;
        let signer = server.signer(&pool).await?;
        if let Some(object) = info.as_object_mut() {
            object.insert("external_sender".into(), json!(signer.external_sender()));
        }
        Ok(info)
    }
    .await;
    result
        .map(Json)
        .inspect_err(|error| failed(&caller.user_id, "conversation", error))
}

#[derive(Deserialize)]
struct GroupBody {
    device_id: String,
    /// 32 bytes: the group id, then this conversation's id. Omitted when the client has no
    /// declared binding.
    #[serde(default)]
    context: Option<String>,
}

async fn create_group(
    State(pool): State<PgPool>,
    Extension(server): Extension<Arc<Server>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<GroupBody>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let caller = member(&pool, &headers).await?;
    server.allow(&caller.user_id)?;
    let result = async {
        let context = match body.context.as_deref() {
            Some(text) => {
                let bytes = mls::decode(text, 32).map_err(refused)?;
                if bytes.len() != 32 {
                    return Err(Error::BadE2ee);
                }
                Some(bytes)
            }
            None => None,
        };
        db::create_group(&pool, &caller, &id, &body.device_id, context.as_deref())
            .await
            .map_err(lift)?;
        let info = db::group_info(&pool, &caller, &id).await.map_err(lift)?;
        issue(&pool, &server, &caller, &id).await?;
        Ok(info.get("epoch").cloned().unwrap_or(json!(0)))
    }
    .await;
    let epoch = result.inspect_err(|error| failed(&caller.user_id, "group.create", error))?;
    Ok((StatusCode::CREATED, Json(json!({ "epoch": epoch }))))
}

#[derive(Deserialize)]
struct CapabilityBody {
    device_id: String,
    capability_key: String,
    signature: String,
}

async fn set_invite_capability(
    State(pool): State<PgPool>,
    Extension(server): Extension<Arc<Server>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<CapabilityBody>,
) -> Result<StatusCode, Error> {
    let caller = member(&pool, &headers).await?;
    server.allow(&caller.user_id)?;
    let result = async {
        let key = mls::decode(&body.capability_key, 65).map_err(refused)?;
        if key.len() != 65 || key[0] != 4 {
            return Err(Error::BadE2ee);
        }
        let signature = mls::decode(&body.signature, 128).map_err(refused)?;
        let device_key = db::device_key(&pool, &caller, &body.device_id)
            .await
            .map_err(lift)?;
        if !mls::invite_capability_signed(&id, &key, &signature, &device_key) {
            return Err(Error::BadE2ee);
        }
        db::set_invite_capability(&pool, &caller, &id, &key)
            .await
            .map_err(lift)?;
        Ok(())
    }
    .await;
    result.inspect_err(|error| failed(&caller.user_id, "invite.capability", error))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct ReactionBody {
    device_id: String,
    epoch: u64,
    ciphertext: String,
    client_id: String,
}

#[derive(Deserialize)]
struct ReactionQuery {
    after: Option<i64>,
    limit: Option<i32>,
}

async fn post_reaction(
    State(pool): State<PgPool>,
    Extension(server): Extension<Arc<Server>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ReactionBody>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let caller = member(&pool, &headers).await?;
    server.allow(&caller.user_id)?;
    let result = async {
        let (group, _) = mls_of(&pool, &caller, &id).await?;
        let data = mls::decode(&body.ciphertext, mls::CIPHERTEXT_MAX).map_err(refused)?;
        let conversation = canonical_uuid(&id).ok_or(Error::Invalid)?;
        let aad = mls::message_aad_for("reaction", None, Some(&conversation));
        mls::check_ciphertext(&group, body.epoch, &aad, &data).map_err(refused)?;
        let value = db::post_e2ee_reaction(
            &pool,
            &caller,
            &id,
            &data,
            body.epoch,
            &body.device_id,
            &body.client_id,
        )
        .await
        .map_err(lift)?;
        let created = value
            .get("created")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let status = if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        };
        Ok((status, Json(value)))
    }
    .await;
    result.inspect_err(|error| failed(&caller.user_id, "reaction.post", error))
}

async fn list_reactions(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<ReactionQuery>,
) -> Result<Json<Value>, Error> {
    let caller = member(&pool, &headers).await?;
    db::list_e2ee_reactions(&pool, &caller, &id, query.after, query.limit.unwrap_or(50))
        .await
        .map(Json)
        .map_err(lift)
        .inspect_err(|error| failed(&caller.user_id, "reaction.list", error))
}

#[derive(Deserialize)]
struct HandshakeQuery {
    after: Option<i64>,
    device_id: Option<String>,
}

async fn handshake(
    State(pool): State<PgPool>,
    Extension(server): Extension<Arc<Server>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<HandshakeQuery>,
) -> Result<Json<Value>, Error> {
    let caller = member(&pool, &headers).await?;
    let Some(device_id) = query.device_id else {
        return Err(Error::Invalid);
    };
    let result = async {
        issue(&pool, &server, &caller, &id).await?;
        let rows = db::handshake_after(
            &pool,
            &caller,
            &id,
            &device_id,
            query.after.unwrap_or(0),
            HANDSHAKE_PAGE,
        )
        .await
        .map_err(lift)?;
        let rows: Vec<Value> = rows
            .iter()
            .map(|row| {
                json!({
                    "seq": row.seq,
                    "kind": row.kind,
                    "epoch": row.epoch,
                    "data": mls::encode(&row.data),
                })
            })
            .collect();
        Ok(Json(Value::Array(rows)))
    }
    .await;
    result.inspect_err(|error| failed(&caller.user_id, "handshake", error))
}

/// The community's root key and the policy it signed. Clients pin the key on first sight.
async fn community(State(pool): State<PgPool>, headers: HeaderMap) -> Result<Json<Value>, Error> {
    let caller = member(&pool, &headers).await?;
    db::community_root(&pool, &caller)
        .await
        .map(Json)
        .map_err(lift)
        .inspect_err(|error| failed(&caller.user_id, "community", error))
}

#[derive(Deserialize)]
struct CommunityBody {
    root_key: String,
    policy: String,
    policy_signature: String,
    #[serde(default)]
    replace: bool,
}

/// Sets the community's root key and the policy it signs. The signature must hold; a different
/// root than the one set needs `replace: true`, and every member hears of it.
async fn set_community(
    State(pool): State<PgPool>,
    Extension(server): Extension<Arc<Server>>,
    headers: HeaderMap,
    Json(body): Json<CommunityBody>,
) -> Result<Json<Value>, Error> {
    let caller = member(&pool, &headers).await?;
    server.allow(&caller.user_id)?;
    let result = async {
        let root_key = mls::decode(&body.root_key, 65).map_err(refused)?;
        let policy = mls::decode(&body.policy, 4096).map_err(refused)?;
        let signature = mls::decode(&body.policy_signature, 128).map_err(refused)?;
        if root_key.len() != 65 || !mls::policy_signed(&root_key, &policy, &signature) {
            return Err(Error::BadE2ee);
        }
        db::set_community_root(&pool, &caller, &root_key, &policy, &signature, body.replace)
            .await
            .map_err(lift)
    }
    .await;
    result
        .map(Json)
        .inspect_err(|error| failed(&caller.user_id, "community.set", error))
}

#[derive(Deserialize)]
struct TreeQuery {
    device_id: Option<String>,
    epoch: Option<u64>,
}

/// The public ratchet tree of an epoch as its committer uploaded it, as the bytes of a TLS
/// `RatchetTree`, for a device that joined by a Welcome with no tree inside. `404` when there is
/// none: the committer did not send it, or it is older than the 8 epochs kept.
async fn ratchet_tree(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<TreeQuery>,
) -> Result<Response, Error> {
    let caller = member(&pool, &headers).await?;
    let (Some(device_id), Some(epoch)) = (query.device_id, query.epoch) else {
        return Err(Error::Invalid);
    };
    let tree = db::ratchet_tree(&pool, &caller, &id, &device_id, epoch)
        .await
        .map_err(lift)
        .inspect_err(|error| failed(&caller.user_id, "tree", error))?
        .ok_or(Error::NotFound)?;
    let mut response = (StatusCode::OK, tree).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok(response)
}

#[derive(Deserialize)]
struct CommitBody {
    device_id: String,
    epoch: u64,
    commit: String,
    #[serde(default)]
    welcomes: Vec<WelcomeBody>,
    /// The public ratchet tree of the epoch the commit makes, for joiners whose Welcome does not
    /// carry it.
    #[serde(default)]
    ratchet_tree: Option<String>,
}

#[derive(Deserialize)]
struct WelcomeBody {
    device_id: String,
    data: String,
}

async fn commit(
    State(pool): State<PgPool>,
    Extension(server): Extension<Arc<Server>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<CommitBody>,
) -> Result<StatusCode, Error> {
    let caller = member(&pool, &headers).await?;
    server.allow(&caller.user_id)?;
    apply(&pool, &caller, &id, &body)
        .await
        .inspect_err(|error| failed(&caller.user_id, "commit", error))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Checks a commit against the proposals signed for its epoch, then applies it. Applying is a
/// compare-and-swap on the epoch: of two commits for one epoch, one wins.
async fn apply(pool: &PgPool, caller: &Caller, id: &str, body: &CommitBody) -> Result<(), Error> {
    let (group, _) = mls_of(pool, caller, id).await?;
    let commit = mls::decode(&body.commit, mls::COMMIT_MAX).map_err(refused)?;
    let mut total = 0usize;
    let mut sent: HashMap<&str, Vec<u8>> = HashMap::new();
    if body.welcomes.len() > 100 {
        return Err(Error::BadE2ee);
    }
    for welcome in &body.welcomes {
        let data = mls::decode(&welcome.data, mls::WELCOME_MAX).map_err(refused)?;
        total += data.len();
        if total > mls::WELCOMES_MAX || sent.insert(welcome.device_id.as_str(), data).is_some() {
            return Err(Error::BadE2ee);
        }
    }

    let tree = match body.ratchet_tree.as_deref() {
        Some(text) => {
            let tree = mls::decode(text, mls::TREE_MAX).map_err(refused)?;
            mls::check_ratchet_tree(&group, &tree).map_err(refused)?;
            tree.chunks(mls::TREE_PART).map(<[u8]>::to_vec).collect()
        }
        None => Vec::new(),
    };

    let snapshot = db::commit_snapshot(pool, caller, id, &body.device_id, body.epoch)
        .await
        .map_err(lift)?;
    // Nothing is signed for this epoch, so there is nothing to commit: read the log again.
    if snapshot.issued.is_empty() {
        return Err(Error::ProposalsChanged);
    }
    let meta = mls::parse_commit(&group, body.epoch, &commit).map_err(refused)?;
    if meta.sender_leaf != snapshot.leaf {
        return Err(Error::BadE2ee);
    }

    // The commit must name exactly the proposals that were signed, once each.
    let mut by_reference = HashMap::new();
    for (index, issued) in snapshot.issued.iter().enumerate() {
        let reference = mls::proposal_ref(&issued.proposal).ok_or(Error::Unavailable)?;
        by_reference.insert(reference, index);
    }
    let mut ids = Vec::with_capacity(meta.proposal_refs.len());
    let mut taken = vec![false; snapshot.issued.len()];
    for reference in &meta.proposal_refs {
        let Some(&index) = by_reference.get(reference) else {
            return Err(Error::ProposalsChanged);
        };
        if std::mem::replace(&mut taken[index], true) {
            return Err(Error::BadE2ee);
        }
        ids.push(index);
    }
    if taken.iter().any(|taken| !taken) {
        return Err(Error::ProposalsChanged);
    }

    // A Welcome for every device it adds, and for no one else, naming that device's key package.
    let mut welcomes = Vec::new();
    let mut added = 0usize;
    for &index in &ids {
        let issued = &snapshot.issued[index];
        if issued.op != "add" {
            continue;
        }
        added += 1;
        let Some(package) = issued.key_package.as_deref() else {
            return Err(Error::Unavailable);
        };
        let reference = mls::key_package_ref(package).ok_or(Error::Unavailable)?;
        let Some(data) = sent.get(issued.device_id.as_str()) else {
            return Err(Error::BadE2ee);
        };
        let recipients = mls::welcome_recipients(data).map_err(refused)?;
        if !recipients.contains(&reference) {
            return Err(Error::BadE2ee);
        }
        welcomes.push(WelcomeFor {
            device_id: issued.device_id.clone(),
            data: data.clone(),
        });
    }
    if sent.len() != added {
        return Err(Error::BadE2ee);
    }
    let ids: Vec<i64> = ids.iter().map(|&index| snapshot.issued[index].id).collect();
    db::apply_commit(
        pool,
        caller,
        id,
        &body.device_id,
        body.epoch,
        &commit,
        &ids,
        &welcomes,
        &tree,
        meta.has_path,
    )
    .await
    .map_err(lift)?;
    Ok(())
}

/// Whether bytes have the shape of a sealed blob: the header, a chunk size from 1 KiB to 1 MiB,
/// then chunks of exactly that size plus a tag, but the last, which is 0 bytes to a full chunk of
/// plaintext plus its tag. The server cannot tell a blob from random bytes of that shape, and
/// does not try: this only keeps the sealed route from storing any file of any shape.
pub(crate) fn sealed_framing_ok(bytes: &[u8]) -> bool {
    if bytes.len() <= SEALED_HEADER || &bytes[..SEALED_MAGIC.len()] != SEALED_MAGIC {
        return false;
    }
    let log2 = bytes[SEALED_MAGIC.len()];
    if !(10..=20).contains(&log2) {
        return false;
    }
    let chunk = (1usize << log2) + SEALED_TAG;
    let rest = (bytes.len() - SEALED_HEADER) % chunk;
    rest == 0 || rest >= SEALED_TAG
}

/// The fields of a post that make it ciphertext, as the message route reads them.
pub(crate) struct PostFields<'a> {
    pub ciphertext: Option<&'a str>,
    pub epoch: Option<u64>,
    pub device_id: Option<&'a str>,
    pub kind: Option<&'a str>,
    pub target_id: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub reply_to: Option<&'a str>,
    pub attachments: &'a [String],
    /// The request also carried a `body`.
    pub has_body: bool,
}

/// A ciphertext post to `conversation`. `201` when stored, `200` with the original when the same
/// client id from the same device had been stored already.
pub(crate) async fn post_ciphertext(
    pool: &PgPool,
    caller: &Caller,
    conversation: &str,
    fields: PostFields<'_>,
) -> Result<(StatusCode, Json<Value>), Error> {
    /// Stands in for a device the request did not name, when the database is going to refuse it
    /// for another reason before it reads the device.
    const NIL: &str = "00000000-0000-0000-0000-000000000000";
    if fields
        .reply_to
        .is_some_and(|reply| !reply.trim().is_empty())
    {
        // A reply is inside the ciphertext. The server is not told what it replies to.
        return Err(Error::Invalid);
    }
    let kind = fields.kind.unwrap_or("message");
    if !matches!(kind, "message" | "edit") {
        return Err(Error::Invalid);
    }
    if fields.has_body {
        // The database says which refusal it is, before it reads anything else: not_e2ee for a
        // plaintext conversation, e2ee_required for an encrypted one.
        let device_id = fields.device_id.unwrap_or(NIL);
        let epoch = fields.epoch.unwrap_or_default();
        return post_stored(
            pool,
            caller,
            conversation,
            &[],
            epoch,
            device_id,
            &fields,
            kind,
        )
        .await;
    }
    let (Some(text), Some(epoch), Some(device_id)) =
        (fields.ciphertext, fields.epoch, fields.device_id)
    else {
        return Err(Error::Invalid);
    };
    let data = match mls::decode(text, mls::CIPHERTEXT_MAX) {
        Ok(data) => data,
        Err(refusal) => return Err(refine(pool, caller, conversation, refused(refusal)).await),
    };
    // The kind and target the server stores must be the ones the sender authenticated, with the
    // target in the form the server gives it back in.
    let target = match fields.target_id {
        Some(target) => Some(canonical_uuid(target).ok_or(Error::Invalid)?),
        None => None,
    };
    let (group, audience) = mls_of(pool, caller, conversation).await?;
    let bound = if audience {
        Some(canonical_uuid(conversation).ok_or(Error::Invalid)?)
    } else {
        None
    };
    let aad = mls::message_aad_for(kind, target.as_deref(), bound.as_deref());
    if let Err(refusal) = mls::check_ciphertext(&group, epoch, &aad, &data) {
        return Err(refine(pool, caller, conversation, refused(refusal)).await);
    }
    post_stored(
        pool,
        caller,
        conversation,
        &data,
        epoch,
        device_id,
        &fields,
        kind,
    )
    .await
}

/// A uuid as Postgres writes it: lowercase, hyphenated.
fn canonical_uuid(id: &str) -> Option<String> {
    let bytes = mls::uuid_bytes(id)?;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Some(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

/// A ciphertext that is no good for an encrypted conversation is `not_e2ee` when the conversation
/// is not one, and whatever refused it otherwise.
async fn refine(pool: &PgPool, caller: &Caller, conversation: &str, error: Error) -> Error {
    match db::group_info(pool, caller, conversation).await {
        Ok(info) if info.get("e2ee").and_then(Value::as_bool) != Some(true) => Error::NotE2ee,
        Ok(_) => error,
        Err(other) => lift(other),
    }
}

#[allow(clippy::too_many_arguments)]
async fn post_stored(
    pool: &PgPool,
    caller: &Caller,
    conversation: &str,
    ciphertext: &[u8],
    epoch: u64,
    device_id: &str,
    fields: &PostFields<'_>,
    kind: &str,
) -> Result<(StatusCode, Json<Value>), Error> {
    let message = db::NewE2eeMessage {
        ciphertext,
        epoch,
        device_id,
        client_id: fields.client_id,
        kind,
        target_id: fields.target_id,
        attachments: fields.attachments,
        has_body: fields.has_body,
    };
    let (value, created) = db::post_e2ee_message(pool, caller, conversation, &message)
        .await
        .map_err(lift)?;
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, signed(value)))
}

/// Entry for the fuzz targets: every parser a member can reach with bytes, on any input.
#[cfg(feature = "fuzz")]
pub fn fuzz_handshake(data: &[u8]) {
    const GROUP: [u8; 16] = [7; 16];
    const USER: &str = "00000000-0000-4000-8000-000000000001";
    const DEVICE: &str = "00000000-0000-4000-8000-000000000002";
    let _ = mls::validate_key_package(USER, DEVICE, &[4; 65], data, 1_700_000_000);
    let _ = mls::key_package_ref(data);
    let _ = mls::parse_commit(&GROUP, 0, data);
    let _ = mls::check_ciphertext(&GROUP, 0, &mls::message_aad("message", None), data);
    let _ = mls::check_ratchet_tree(&GROUP, data);
    let _ = sealed_framing_ok(data);
    let _ = mls::policy_signed(&[4; 65], data, data);
    let _ = mls::welcome_recipients(data);
    let _ = mls::proposal_ref(data);
    let _ = mls::cross_signed(USER, DEVICE, &[4; 65], data, &[vec![4; 65]]);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = mls::decode(text, mls::COMMIT_MAX);
    }
}
