//! End-to-end encrypted text: devices, key packages, the MLS group of each encrypted
//! conversation, and ciphertext messages.
//!
//! Everything here is a call to a `SECURITY DEFINER` function from `migrations/0021` or
//! `0022`. Those functions check who the caller is and what they may do; the tables have no
//! grant for the runtime role. This crate holds no MLS: the API crate parses and signs, and
//! hands the bytes here. Nothing stored is a key that opens a message.

use serde_json::Value;
use sqlx::PgPool;

use crate::messages::{blank_to_none, commit, is_uuid, json_in, message_sql, scoped, MessageError};
use crate::{Caller, DbError};

/// A proposal the server has yet to sign.
#[derive(Debug, Clone)]
pub struct Unissued {
    pub id: i64,
    /// `add` or `remove`.
    pub op: String,
    pub device_id: String,
    /// For a remove: the leaf to remove.
    pub leaf_index: Option<u32>,
    /// For an add: the claimed key package, as the device uploaded it.
    pub key_package: Option<Vec<u8>>,
}

/// What signing produced. `proposals` has one entry per [`Unissued`], in order; `None` is one
/// that could not be made and is dropped. `batch` is what members read from the log.
pub struct Issued {
    pub proposals: Vec<Option<Vec<u8>>>,
    pub batch: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct HandshakeRow {
    pub seq: i64,
    /// `proposals`, `commit` or `welcome`.
    pub kind: String,
    pub epoch: i64,
    pub data: Vec<u8>,
}

/// A proposal signed for the current epoch, and what a commit is checked against.
#[derive(Debug, Clone)]
pub struct IssuedProposal {
    pub id: i64,
    pub op: String,
    pub device_id: String,
    pub proposal: Vec<u8>,
    pub key_package: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct CommitSnapshot {
    /// The leaf the committing device sits in.
    pub leaf: u32,
    pub issued: Vec<IssuedProposal>,
}

/// A Welcome made for one device a commit adds.
#[derive(Debug, Clone)]
pub struct WelcomeFor {
    pub device_id: String,
    pub data: Vec<u8>,
}

/// A ciphertext post.
pub struct NewE2eeMessage<'a> {
    pub ciphertext: &'a [u8],
    pub epoch: u64,
    pub device_id: &'a str,
    pub client_id: Option<&'a str>,
    /// `message` or `edit`.
    pub kind: &'a str,
    pub target_id: Option<&'a str>,
    pub attachments: &'a [String],
    /// The request also had a `body`, which an encrypted conversation refuses.
    pub has_body: bool,
}

fn uuid_arg(value: &str) -> Result<&str, MessageError> {
    if is_uuid(value) {
        Ok(value)
    } else {
        Err(MessageError::Invalid)
    }
}

fn epoch_arg(epoch: u64) -> Result<i64, MessageError> {
    i64::try_from(epoch).map_err(|_| MessageError::Invalid)
}

/// Registers a device. `cross_signature` is checked by the caller against the person's active
/// devices; the database insists one is there when the person has any.
pub async fn put_device(
    pool: &PgPool,
    caller: &Caller,
    device_id: &str,
    signature_key: &[u8],
    cross_signature: Option<&[u8]>,
    label: Option<&str>,
) -> Result<Value, MessageError> {
    uuid_arg(device_id)?;
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(
        &mut tx,
        "SELECT app_e2ee_put_device($1::uuid, $2, $3, $4)",
        |query| {
            query
                .bind(device_id)
                .bind(signature_key)
                .bind(cross_signature)
                .bind(label)
        },
    )
    .await?;
    commit(tx, value).await
}

/// The signature keys of the caller's active devices.
pub async fn active_keys(pool: &PgPool, caller: &Caller) -> Result<Vec<Vec<u8>>, MessageError> {
    let mut tx = scoped(pool, caller).await?;
    let keys: Vec<Vec<u8>> = sqlx::query_scalar("SELECT app_e2ee_active_keys()")
        .fetch_all(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(keys)
}

/// The signature key of one of the caller's active devices.
pub async fn device_key(
    pool: &PgPool,
    caller: &Caller,
    device_id: &str,
) -> Result<Vec<u8>, MessageError> {
    uuid_arg(device_id)?;
    let mut tx = scoped(pool, caller).await?;
    let key: Vec<u8> = sqlx::query_scalar("SELECT app_e2ee_my_device_key($1::uuid)")
        .bind(device_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(key)
}

pub async fn revoke_device(
    pool: &PgPool,
    caller: &Caller,
    device_id: &str,
) -> Result<(), MessageError> {
    uuid_arg(device_id)?;
    let mut tx = scoped(pool, caller).await?;
    sqlx::query("SELECT app_e2ee_revoke_device($1::uuid)")
        .bind(device_id)
        .execute(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(())
}

pub async fn user_devices(
    pool: &PgPool,
    caller: &Caller,
    user_id: &str,
) -> Result<Value, MessageError> {
    uuid_arg(user_id)?;
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(&mut tx, "SELECT app_e2ee_user_devices($1::uuid)", |query| {
        query.bind(user_id)
    })
    .await?;
    commit(tx, value).await
}

/// Stores key packages, each with the time it stops being valid (seconds since the epoch), and
/// optionally the device's last resort package. Returns how many one-time packages remain.
pub async fn put_key_packages(
    pool: &PgPool,
    caller: &Caller,
    device_id: &str,
    packages: &[(Vec<u8>, i64)],
    last_resort: Option<(&[u8], i64)>,
) -> Result<i64, MessageError> {
    uuid_arg(device_id)?;
    let data: Vec<Vec<u8>> = packages.iter().map(|(data, _)| data.clone()).collect();
    let expires: Vec<i64> = packages.iter().map(|(_, expires)| *expires).collect();
    let (last, last_expires) = match last_resort {
        Some((data, expires)) => (Some(data), Some(expires)),
        None => (None, None),
    };
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(
        &mut tx,
        "SELECT app_e2ee_put_key_packages($1::uuid, $2, $3, $4, $5)",
        |query| {
            query
                .bind(device_id)
                .bind(data)
                .bind(expires)
                .bind(last)
                .bind(last_expires)
        },
    )
    .await?;
    let value = commit(tx, value).await?;
    Ok(value
        .get("remaining")
        .and_then(Value::as_i64)
        .unwrap_or_default())
}

pub async fn key_package_count(
    pool: &PgPool,
    caller: &Caller,
    device_id: &str,
) -> Result<Value, MessageError> {
    uuid_arg(device_id)?;
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(
        &mut tx,
        "SELECT app_e2ee_key_package_count($1::uuid)",
        |query| query.bind(device_id),
    )
    .await?;
    commit(tx, value).await
}

/// The server's external sender key, as `(public, private)`. Made by the first caller; a caller
/// that raced it gets the stored one.
pub async fn server_key(
    pool: &PgPool,
    public: &[u8],
    private: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), DbError> {
    let row: (Vec<u8>, Vec<u8>) =
        sqlx::query_as("SELECT r_public, r_private FROM app_e2ee_server_key($1, $2)")
            .bind(public)
            .bind(private)
            .fetch_one(pool)
            .await?;
    Ok(row)
}

/// What the caller may know of a conversation's group: `{e2ee, epoch, members, pending}`.
pub async fn group_info(
    pool: &PgPool,
    caller: &Caller,
    conversation: &str,
) -> Result<Value, MessageError> {
    uuid_arg(conversation)?;
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(&mut tx, "SELECT app_e2ee_info($1::uuid)", |query| {
        query.bind(conversation)
    })
    .await?;
    commit(tx, value).await
}

/// The caller's device starts the group at epoch 0.
pub async fn create_group(
    pool: &PgPool,
    caller: &Caller,
    conversation: &str,
    device_id: &str,
) -> Result<(), MessageError> {
    uuid_arg(conversation)?;
    uuid_arg(device_id)?;
    let mut tx = scoped(pool, caller).await?;
    sqlx::query("SELECT app_e2ee_create_group($1::uuid, $2::uuid)")
        .bind(conversation)
        .bind(device_id)
        .execute(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(())
}

/// Signs, through `sign`, every proposal of the group that is due and not yet signed, and
/// stores them. `sign` gets the group's epoch and the proposals; it runs with the group locked,
/// so keep it short. A conversation that is not encrypted is an error, one without a group is
/// not.
pub async fn issue_proposals<F>(
    pool: &PgPool,
    caller: &Caller,
    conversation: &str,
    sign: F,
) -> Result<(), MessageError>
where
    F: FnOnce(u64, &[Unissued]) -> Option<Issued>,
{
    uuid_arg(conversation)?;
    let mut tx = scoped(pool, caller).await?;
    type Row = (i64, i64, String, String, Option<i32>, Option<Vec<u8>>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT r_epoch, r_id, r_op, r_device::text, r_leaf, r_package
         FROM app_e2ee_begin_issue($1::uuid)",
    )
    .bind(conversation)
    .fetch_all(&mut *tx)
    .await
    .map_err(message_sql)?;
    let Some(first) = rows.first() else {
        tx.commit().await.map_err(message_sql)?;
        return Ok(());
    };
    let epoch = first.0;
    let items: Vec<Unissued> = rows
        .into_iter()
        .map(|(_, id, op, device_id, leaf, key_package)| Unissued {
            id,
            op,
            device_id,
            leaf_index: leaf.and_then(|leaf| u32::try_from(leaf).ok()),
            key_package,
        })
        .collect();
    let Some(issued) = sign(u64::try_from(epoch).unwrap_or_default(), &items) else {
        tx.commit().await.map_err(message_sql)?;
        return Ok(());
    };
    if issued.proposals.len() != items.len() {
        return Err(MessageError::Invalid);
    }
    let ids: Vec<i64> = items.iter().map(|item| item.id).collect();
    sqlx::query("SELECT app_e2ee_issue($1::uuid, $2, $3, $4, $5)")
        .bind(conversation)
        .bind(epoch)
        .bind(ids)
        .bind(issued.proposals)
        .bind(issued.batch)
        .execute(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(())
}

/// The handshake log after `after` for one of the caller's devices, at most `limit` rows.
pub async fn handshake_after(
    pool: &PgPool,
    caller: &Caller,
    conversation: &str,
    device_id: &str,
    after: i64,
    limit: i32,
) -> Result<Vec<HandshakeRow>, MessageError> {
    uuid_arg(conversation)?;
    uuid_arg(device_id)?;
    let mut tx = scoped(pool, caller).await?;
    let rows: Vec<(i64, String, i64, Vec<u8>)> = sqlx::query_as(
        "SELECT r_seq, r_kind, r_epoch, r_data FROM app_e2ee_handshake($1::uuid, $2::uuid, $3, $4)",
    )
    .bind(conversation)
    .bind(device_id)
    .bind(after)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await
    .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(rows
        .into_iter()
        .map(|(seq, kind, epoch, data)| HandshakeRow {
            seq,
            kind,
            epoch,
            data,
        })
        .collect())
}

/// What a commit from `device_id` for `epoch` is checked against. A stale epoch, a device not in
/// the group, or one that is being removed is an error.
pub async fn commit_snapshot(
    pool: &PgPool,
    caller: &Caller,
    conversation: &str,
    device_id: &str,
    epoch: u64,
) -> Result<CommitSnapshot, MessageError> {
    uuid_arg(conversation)?;
    uuid_arg(device_id)?;
    let epoch = epoch_arg(epoch)?;
    let mut tx = scoped(pool, caller).await?;
    type Row = (i32, i64, String, String, Vec<u8>, Option<Vec<u8>>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT r_leaf, r_id, r_op, r_device::text, r_proposal, r_package
         FROM app_e2ee_commit_snapshot($1::uuid, $2::uuid, $3)",
    )
    .bind(conversation)
    .bind(device_id)
    .bind(epoch)
    .fetch_all(&mut *tx)
    .await
    .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    let leaf = rows
        .first()
        .and_then(|row| u32::try_from(row.0).ok())
        .unwrap_or_default();
    Ok(CommitSnapshot {
        leaf,
        issued: rows
            .into_iter()
            .map(
                |(_, id, op, device_id, proposal, key_package)| IssuedProposal {
                    id,
                    op,
                    device_id,
                    proposal,
                    key_package,
                },
            )
            .collect(),
    })
}

/// Applies a commit that has been checked: `ids` are the proposals it names, in its order.
/// `StaleEpoch` when another commit won, `ProposalsChanged` when proposals were signed that this
/// one does not apply. Returns the commit's place in the log.
#[allow(clippy::too_many_arguments)]
pub async fn apply_commit(
    pool: &PgPool,
    caller: &Caller,
    conversation: &str,
    device_id: &str,
    epoch: u64,
    commit_bytes: &[u8],
    ids: &[i64],
    welcomes: &[WelcomeFor],
) -> Result<i64, MessageError> {
    uuid_arg(conversation)?;
    uuid_arg(device_id)?;
    let epoch = epoch_arg(epoch)?;
    let devices: Vec<String> = welcomes
        .iter()
        .map(|welcome| welcome.device_id.clone())
        .collect();
    if devices.iter().any(|device| !is_uuid(device)) {
        return Err(MessageError::Invalid);
    }
    let data: Vec<Vec<u8>> = welcomes
        .iter()
        .map(|welcome| welcome.data.clone())
        .collect();
    let mut tx = scoped(pool, caller).await?;
    let seq: i64 = sqlx::query_scalar(
        "SELECT app_e2ee_apply_commit($1::uuid, $2::uuid, $3, $4, $5, $6::text[]::uuid[], $7)",
    )
    .bind(conversation)
    .bind(device_id)
    .bind(epoch)
    .bind(commit_bytes)
    .bind(ids)
    .bind(devices)
    .bind(data)
    .fetch_one(&mut *tx)
    .await
    .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(seq)
}

/// Posts a ciphertext message or edit. `true` when this call stored it, `false` when the same
/// client id from the same device had already been stored and the original is returned.
pub async fn post_e2ee_message(
    pool: &PgPool,
    caller: &Caller,
    conversation: &str,
    message: &NewE2eeMessage<'_>,
) -> Result<(Value, bool), MessageError> {
    uuid_arg(conversation)?;
    uuid_arg(message.device_id)?;
    let target = blank_to_none(message.target_id);
    if let Some(target) = target {
        uuid_arg(target)?;
    }
    let attachments = if message.attachments.is_empty() {
        None
    } else if message.attachments.iter().all(|id| is_uuid(id)) {
        Some(message.attachments.to_vec())
    } else {
        return Err(MessageError::Invalid);
    };
    let epoch = epoch_arg(message.epoch)?;
    let mut tx = scoped(pool, caller).await?;
    let row: (Value, bool) = sqlx::query_as(
        "SELECT r_message, r_created FROM app_post_e2ee_message(
            $1::uuid, $2, $3, $4::uuid, $5, $6, $7::uuid, $8::text[]::uuid[], $9)",
    )
    .bind(conversation)
    .bind(message.ciphertext)
    .bind(epoch)
    .bind(message.device_id)
    .bind(blank_to_none(message.client_id))
    .bind(message.kind)
    .bind(target)
    .bind(attachments)
    .bind(message.has_body)
    .fetch_one(&mut *tx)
    .await
    .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(row)
}

/// The server's `e2ee_text` setting: `off`, `optional` or `new_required`.
pub async fn e2ee_text_mode(pool: &PgPool) -> Result<String, DbError> {
    let mode: String = sqlx::query_scalar("SELECT app_e2ee_text_mode()")
        .fetch_one(pool)
        .await?;
    Ok(mode)
}
