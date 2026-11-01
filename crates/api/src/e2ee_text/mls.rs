//! The MLS the delivery service needs, and nothing more: the external sender that signs Add and
//! Remove proposals, and checks of what members send (key packages, commits, welcomes, and the
//! outer framing of an application message).
//!
//! Nothing here holds a group secret or can make one. The server's key signs proposals only.
//! `crates/api/src/live/e2ee.rs` is the same idea for calls; this keeps its approach (openmls for
//! parsing, the same external sender construction) and differs where text needs it: groups live
//! in Postgres and outlast a process, and a commit is checked against the exact proposals that
//! were signed, which it must name by reference.

use std::sync::LazyLock;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use openmls::prelude::tls_codec::{DeserializeBytes as _, Serialize as _, VLBytes};
use openmls::prelude::{
    BasicCredential, Ciphersuite, ContentType, CredentialType, ExternalProposal, ExternalSender,
    GroupEpoch, GroupId, KeyPackage, KeyPackageIn, LeafNodeIndex, MlsMessageBodyIn, MlsMessageIn,
    OpenMlsCrypto, OpenMlsProvider, ProtocolMessage, ProtocolVersion, Sender as MlsSender,
    SenderExtensionIndex, SignatureScheme,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use sha2::{Digest, Sha256};

/// The ciphersuite of calls and of text.
pub(crate) const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256;
/// The most a key package may be, as bytes.
pub(crate) const KEY_PACKAGE_MAX: usize = 8 * 1024;
/// The most a commit may be, as bytes.
pub(crate) const COMMIT_MAX: usize = 256 * 1024;
/// The most one welcome may be: a ratchet tree of a large group.
pub(crate) const WELCOME_MAX: usize = 1024 * 1024;
/// The most the welcomes of one commit may add up to.
pub(crate) const WELCOMES_MAX: usize = 4 * 1024 * 1024;
/// The most a ciphertext message may be. The plaintext inside is at most 16 KiB.
pub(crate) const CIPHERTEXT_MAX: usize = 20 * 1024;
/// A key package valid for longer than this from now is refused.
const LIFETIME_MAX_SECS: u64 = 400 * 24 * 60 * 60;
/// What a device signs to vouch for another of the same person.
const CROSS_LABEL: &[u8] = b"tiny-e2ee-v1 device-add";

static PROVIDER: LazyLock<OpenMlsRustCrypto> = LazyLock::new(OpenMlsRustCrypto::default);

/// Why an MLS object was refused. The API turns both into `bad_e2ee`, or `too_large`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    /// Not what it must be.
    Bad,
    /// Over its size limit.
    TooLarge,
}

/// A uuid as its 16 bytes. `None` for anything but the hyphenated form.
pub(crate) fn uuid_bytes(id: &str) -> Option<[u8; 16]> {
    let bytes = id.as_bytes();
    if bytes.len() != 36 {
        return None;
    }
    let mut out = [0u8; 16];
    let mut at = 0;
    let mut index = 0;
    while index < 36 {
        if matches!(index, 8 | 13 | 18 | 23) {
            if bytes[index] != b'-' {
                return None;
            }
            index += 1;
            continue;
        }
        let high = char::from(bytes[index]).to_digit(16)?;
        let low = char::from(*bytes.get(index + 1)?).to_digit(16)?;
        out[at] = u8::try_from(high * 16 + low).ok()?;
        at += 1;
        index += 2;
    }
    Some(out)
}

/// The content of the basic credential in every leaf: the 16 byte user id then the 16 byte
/// device id.
pub(crate) fn credential_content(user: &[u8; 16], device: &[u8; 16]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(user);
    out[16..].copy_from_slice(device);
    out
}

pub(crate) fn decode(field: &str, max: usize) -> Result<Vec<u8>, Refused> {
    if field.len() > max / 3 * 4 + 8 {
        return Err(Refused::TooLarge);
    }
    let bytes = STANDARD.decode(field).map_err(|_| Refused::Bad)?;
    if bytes.len() > max {
        return Err(Refused::TooLarge);
    }
    Ok(bytes)
}

pub(crate) fn encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// A key package that is this device's own: it decodes, its signatures hold, it is for the
/// ciphersuite, its credential is exactly the person and the device, its signature key is the
/// one the device registered, and it is valid now and not for more than 400 days. `now` is
/// seconds since the epoch. Returns when it stops being valid.
pub(crate) fn validate_key_package(
    user_id: &str,
    device_id: &str,
    registered_key: &[u8],
    data: &[u8],
    now: u64,
) -> Result<i64, Refused> {
    let package = parse_key_package(data)?;
    let (Some(user), Some(device)) = (uuid_bytes(user_id), uuid_bytes(device_id)) else {
        return Err(Refused::Bad);
    };
    let credential = package.leaf_node().credential();
    let ours = package.ciphersuite() == SUITE
        && credential.credential_type() == CredentialType::Basic
        && credential.serialized_content() == credential_content(&user, &device)
        && package.leaf_node().signature_key().as_slice() == registered_key;
    if !ours {
        return Err(Refused::Bad);
    }
    let life = package.life_time();
    if !life.is_valid()
        || life.not_before() > now
        || life.not_after() <= now
        || life.not_after() - now > LIFETIME_MAX_SECS
    {
        return Err(Refused::Bad);
    }
    i64::try_from(life.not_after()).map_err(|_| Refused::Bad)
}

/// A key package that decodes and whose signatures hold.
pub(crate) fn parse_key_package(data: &[u8]) -> Result<KeyPackage, Refused> {
    if data.len() > KEY_PACKAGE_MAX {
        return Err(Refused::TooLarge);
    }
    untrusted(|| {
        KeyPackageIn::tls_deserialize_exact_bytes(data)
            .ok()?
            .validate(PROVIDER.crypto(), ProtocolVersion::Mls10)
            .ok()
    })
    .ok_or(Refused::Bad)
}

/// Runs a parser of bytes a member sent. openmls and tls_codec have debug assertions that fire on
/// cut input, where a release build returns an error; a panic is caught so a debug build answers
/// the same, and so nothing a client sends can take down its request. A panic is a refusal.
fn untrusted<T>(parse: impl FnOnce() -> Option<T>) -> Option<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(parse))
        .ok()
        .flatten()
}

/// An MLSMessage, or `Bad`.
fn message_in(data: &[u8]) -> Result<MlsMessageIn, Refused> {
    untrusted(|| MlsMessageIn::tls_deserialize_exact_bytes(data).ok()).ok_or(Refused::Bad)
}

/// The reference a Welcome names a key package by.
pub(crate) fn key_package_ref(data: &[u8]) -> Option<Vec<u8>> {
    let package = parse_key_package(data).ok()?;
    let reference = package.hash_ref(PROVIDER.crypto()).ok()?;
    Some(reference.as_slice().to_vec())
}

/// Whether `signature` is `signer_keys`' one device vouching for `new_key` as `device_id` of
/// `user_id`: ECDSA P-256 (DER) over SHA-256 of the label, the two ids and the key.
pub(crate) fn cross_signed(
    user_id: &str,
    device_id: &str,
    new_key: &[u8],
    signature: &[u8],
    signer_keys: &[Vec<u8>],
) -> bool {
    let (Some(user), Some(device)) = (uuid_bytes(user_id), uuid_bytes(device_id)) else {
        return false;
    };
    let mut message = Vec::with_capacity(CROSS_LABEL.len() + 32 + new_key.len());
    message.extend_from_slice(CROSS_LABEL);
    message.extend_from_slice(&user);
    message.extend_from_slice(&device);
    message.extend_from_slice(new_key);
    signer_keys.iter().any(|key| {
        PROVIDER
            .crypto()
            .verify_signature(
                SignatureScheme::ECDSA_SECP256R1_SHA256,
                &message,
                key,
                signature,
            )
            .is_ok()
    })
}

/// The outer framing of an application message: an MLS PrivateMessage for this group at this
/// epoch. The server cannot see more, and does not try.
pub(crate) fn check_ciphertext(group: &[u8; 16], epoch: u64, data: &[u8]) -> Result<(), Refused> {
    if data.len() > CIPHERTEXT_MAX {
        return Err(Refused::TooLarge);
    }
    let message = message_in(data)?;
    let Ok(protocol) = message.try_into_protocol_message() else {
        return Err(Refused::Bad);
    };
    if !matches!(protocol, ProtocolMessage::PrivateMessage(_))
        || protocol.group_id().as_slice() != group
        || protocol.epoch().as_u64() != epoch
        || protocol.content_type() != ContentType::Application
    {
        return Err(Refused::Bad);
    }
    Ok(())
}

/// What a commit says on its face.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CommitMeta {
    /// The leaf the sender claims.
    pub sender_leaf: u32,
    /// The proposals it applies, by reference, in its order.
    pub proposal_refs: Vec<[u8; 32]>,
}

/// A commit in the clear (an MLS PublicMessage) for this group at this epoch, from a member leaf,
/// that applies proposals by reference and none by value. openmls decodes it, so everything that
/// has a shape is checked; the proposal references are then read from the bytes, because openmls
/// does not give them out.
pub(crate) fn parse_commit(
    group: &[u8; 16],
    epoch: u64,
    data: &[u8],
) -> Result<CommitMeta, Refused> {
    if data.len() > COMMIT_MAX {
        return Err(Refused::TooLarge);
    }
    let message = message_in(data)?;
    let Ok(ProtocolMessage::PublicMessage(public)) = message.try_into_protocol_message() else {
        return Err(Refused::Bad);
    };
    let MlsSender::Member(index) = public.sender() else {
        return Err(Refused::Bad);
    };
    if public.group_id().as_slice() != group
        || public.epoch().as_u64() != epoch
        || public.content_type() != ContentType::Commit
    {
        return Err(Refused::Bad);
    }
    Ok(CommitMeta {
        sender_leaf: index.u32(),
        proposal_refs: commit_references(data).ok_or(Refused::Bad)?,
    })
}

/// A cursor over TLS-encoded bytes.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let slice = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|byte| byte[0])
    }

    fn u16(&mut self) -> Option<u16> {
        let bytes = self.take(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        let bytes = self.take(4)?;
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// The variable-length integer of RFC 9420 section 2.1.2: two bits of length, then the
    /// value. A value that could have been shorter is not accepted.
    fn varint(&mut self) -> Option<usize> {
        let first = self.u8()?;
        let (length, value) = match first >> 6 {
            0 => (0, usize::from(first)),
            1 => (1, usize::from(first & 0x3f)),
            2 => (3, usize::from(first & 0x3f)),
            _ => return None,
        };
        let mut value = value;
        for _ in 0..length {
            value = (value << 8) | usize::from(self.u8()?);
        }
        let minimal = match first >> 6 {
            0 => true,
            1 => value >= 64,
            _ => value >= 16384,
        };
        minimal.then_some(value)
    }

    /// A vector with a variable-length header.
    fn vector(&mut self) -> Option<&'a [u8]> {
        let length = self.varint()?;
        self.take(length)
    }
}

/// The proposal references a commit applies, read from the bytes of the MLSMessage that holds it:
/// version, wire format, then the framed content (group id, epoch, sender, authenticated data,
/// content type) and the commit's list of proposals. `None` if any is by value or the bytes are
/// not that shape.
fn commit_references(data: &[u8]) -> Option<Vec<[u8; 32]>> {
    let mut reader = Reader { bytes: data, at: 0 };
    if reader.u16()? != 1 || reader.u16()? != 1 {
        return None;
    }
    reader.vector()?; // group id
    reader.take(8)?; // epoch
    match reader.u8()? {
        1 => {
            reader.u32()?;
        }
        _ => return None,
    }
    reader.vector()?; // authenticated data
    if reader.u8()? != 3 {
        return None;
    }
    let list = reader.vector()?;
    let mut list = Reader { bytes: list, at: 0 };
    let mut references = Vec::new();
    while list.at < list.bytes.len() {
        // 1 is a proposal by value; 2 is a reference.
        if list.u8()? != 2 {
            return None;
        }
        let hash = list.vector()?;
        references.push(<[u8; 32]>::try_from(hash).ok()?);
    }
    Some(references)
}

/// The reference of a proposal the server signed, as a commit names it: SHA-256 over
/// `RefHashInput { label, value }` where value is the proposal's AuthenticatedContent, which for
/// a message from an external sender is its MLSMessage without the two bytes of version.
pub(crate) fn proposal_ref(message: &[u8]) -> Option<[u8; 32]> {
    let value = message.get(2..)?;
    let mut input = Vec::with_capacity(value.len() + 40);
    push_vector(&mut input, b"MLS 1.0 Proposal Reference")?;
    push_vector(&mut input, value)?;
    Some(Sha256::digest(&input).into())
}

fn push_vector(out: &mut Vec<u8>, bytes: &[u8]) -> Option<()> {
    let length = bytes.len();
    if length < 64 {
        out.push(u8::try_from(length).ok()?);
    } else if length < 16384 {
        out.extend_from_slice(&(0x4000 | u16::try_from(length).ok()?).to_be_bytes());
    } else if length < (1 << 30) {
        out.extend_from_slice(&(0x8000_0000 | u32::try_from(length).ok()?).to_be_bytes());
    } else {
        return None;
    }
    out.extend_from_slice(bytes);
    Some(())
}

/// The key package references a Welcome carries secrets for.
pub(crate) fn welcome_recipients(data: &[u8]) -> Result<Vec<Vec<u8>>, Refused> {
    if data.len() > WELCOME_MAX {
        return Err(Refused::TooLarge);
    }
    let message = message_in(data)?;
    let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
        return Err(Refused::Bad);
    };
    Ok(welcome
        .secrets()
        .iter()
        .map(|secret| secret.new_member().as_slice().to_vec())
        .collect())
}

/// The server's external sender: its own signing key. It signs proposals and nothing else.
pub(crate) struct Signer {
    keys: SignatureKeyPair,
    /// The TLS ExternalSender, base64, as a client pins it.
    sender: String,
}

impl Signer {
    /// A new key, as `(public, stored)`. `stored` is the TLS encoding of the key pair, which is
    /// what `e2ee_server_key.private_key` holds: openmls gives out no raw private key.
    pub fn generate() -> Option<(Vec<u8>, Vec<u8>)> {
        let keys = SignatureKeyPair::new(SUITE.signature_algorithm()).ok()?;
        let stored = keys.tls_serialize_detached().ok()?;
        Some((keys.public().to_vec(), stored))
    }

    /// The key from what `generate` returned and the database kept.
    pub fn from_parts(public: Vec<u8>, stored: Vec<u8>) -> Option<Self> {
        let keys = SignatureKeyPair::tls_deserialize_exact_bytes(&stored).ok()?;
        if keys.public() != public.as_slice()
            || keys.signature_scheme() != SUITE.signature_algorithm()
        {
            return None;
        }
        let credential = BasicCredential::new(b"tinyserver".to_vec());
        let sender = ExternalSender::new(keys.public().into(), credential.into())
            .tls_serialize_detached()
            .ok()?;
        Some(Self {
            keys,
            sender: STANDARD.encode(sender),
        })
    }

    /// The ExternalSender a client puts in its group's `external_senders` extension at index 0.
    pub fn external_sender(&self) -> &str {
        &self.sender
    }

    pub fn add(&self, key_package: KeyPackage, group: &[u8; 16], epoch: u64) -> Option<Vec<u8>> {
        ExternalProposal::new_add::<OpenMlsRustCrypto>(
            key_package,
            GroupId::from_slice(group),
            GroupEpoch::from(epoch),
            &self.keys,
            SenderExtensionIndex::new(0),
        )
        .ok()?
        .tls_serialize_detached()
        .ok()
    }

    pub fn remove(&self, leaf: u32, group: &[u8; 16], epoch: u64) -> Option<Vec<u8>> {
        ExternalProposal::new_remove::<OpenMlsRustCrypto>(
            LeafNodeIndex::new(leaf),
            GroupId::from_slice(group),
            GroupEpoch::from(epoch),
            &self.keys,
            SenderExtensionIndex::new(0),
        )
        .ok()?
        .tls_serialize_detached()
        .ok()
    }
}

/// What a member reads from the log for a batch of proposals: the MLSMessages one after the
/// other, as one TLS vector.
pub(crate) fn batch(messages: &[&[u8]]) -> Option<Vec<u8>> {
    let all: Vec<u8> = messages
        .iter()
        .flat_map(|message| message.iter().copied())
        .collect();
    VLBytes::new(all).tls_serialize_detached().ok()
}

#[cfg(test)]
mod tests;
