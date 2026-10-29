//! End-to-end encrypted calls: the server as the MLS delivery service and external sender, as
//! Discord's voice gateway is for DAVE. Memory only; a restart ends every call and every group.
//!
//! The apps hold the group. This module holds what a delivery service needs and nothing more:
//! a signing key for external Add and Remove proposals (made at start, never written or logged),
//! the key packages waiting to be added, who sits in which leaf, the epoch, and the one batch
//! of proposals in flight. It orders commits (the first valid one for a batch wins) and hands
//! the commit to the members and the welcome to the people it adds. It never sees a group
//! secret, so it cannot read or make a frame. `docs/calls.md` has the frames and the reasons.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use openmls::prelude::tls_codec::{DeserializeBytes as _, Serialize as _, VLBytes};
use openmls::prelude::{
    BasicCredential, Ciphersuite, ContentType, CredentialType, ExternalProposal, ExternalSender,
    GroupEpoch, GroupId, KeyPackage, KeyPackageIn, LeafNodeIndex, MlsMessageIn, OpenMlsProvider,
    ProtocolMessage, ProtocolVersion, Sender as MlsSender, SenderExtensionIndex, Welcome,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// The E2EE protocol version this server speaks: DAVE's MLS profile, version 1.
pub(crate) const VERSION: u16 = 1;
/// DAVE protocol version 1's ciphersuite.
const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256;
/// The most a key package, commit, or welcome may be, decoded.
pub(crate) const DATA_MAX: usize = 32 * 1024;
/// A batch with no winning commit by then is given up, and the group built again.
pub(crate) const STUCK: Duration = Duration::from_secs(10);

/// The MLS identity of a user: the first 8 bytes of SHA-256 over a label and their id.
pub(crate) fn mls_user_id(user_id: &str) -> u64 {
    hashed(b"tiny-e2ee-v1 user ", user_id)
}

/// The MLS group of a room's call, the same way.
pub(crate) fn mls_group_id(room_id: &str) -> u64 {
    hashed(b"tiny-e2ee-v1 room ", room_id)
}

fn hashed(label: &[u8], id: &str) -> u64 {
    let digest = Sha256::new()
        .chain_update(label)
        .chain_update(id.as_bytes())
        .finalize();
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(first)
}

/// A frame for the socket that holds `user_id`'s seat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Outgoing {
    pub user_id: String,
    pub frame: String,
}

#[derive(Serialize)]
struct Frame<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    room_id: &'a str,
    op: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_sender: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_ids: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<&'a str>,
}

impl<'a> Frame<'a> {
    fn new(room_id: &'a str, op: &'static str) -> Self {
        Self {
            kind: "call.e2ee",
            room_id,
            op,
            version: None,
            external_sender: None,
            user_ids: None,
            epoch: None,
            data: None,
        }
    }

    fn text(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// Why a client's `call.e2ee` was refused. The `error` code is in `docs/calls.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    /// Not in a call that is end-to-end encrypted now.
    NotFound,
    /// Not base64, too big, or not what it claims to be.
    Bad,
    /// A field is missing, or an unknown `op`.
    BadFrame,
}

impl Refused {
    pub fn code(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::Bad => "bad_e2ee",
            Self::BadFrame => "bad_frame",
        }
    }
}

/// The external sender: the server's own signing key. It signs proposals and nothing else.
struct Signer {
    provider: OpenMlsRustCrypto,
    keys: SignatureKeyPair,
    /// The TLS ExternalSender, base64, as `start` carries it.
    package: String,
}

impl Signer {
    fn new() -> Self {
        let keys = SignatureKeyPair::new(SUITE.signature_algorithm())
            .expect("a P-256 key can always be made");
        let credential = BasicCredential::new(b"tinyserver".to_vec());
        let package = ExternalSender::new(keys.public().into(), credential.into())
            .tls_serialize_detached()
            .expect("an external sender always serialises");
        Self {
            provider: OpenMlsRustCrypto::default(),
            keys,
            package: STANDARD.encode(package),
        }
    }

    fn add(&self, key_package: KeyPackage, group: u64, epoch: u64) -> Option<Vec<u8>> {
        let message = ExternalProposal::new_add::<OpenMlsRustCrypto>(
            key_package,
            GroupId::from_slice(&group.to_be_bytes()),
            GroupEpoch::from(epoch),
            &self.keys,
            SenderExtensionIndex::new(0),
        )
        .ok()?;
        message.tls_serialize_detached().ok()
    }

    fn remove(&self, leaf: u32, group: u64, epoch: u64) -> Option<Vec<u8>> {
        let message = ExternalProposal::new_remove::<OpenMlsRustCrypto>(
            LeafNodeIndex::new(leaf),
            GroupId::from_slice(&group.to_be_bytes()),
            GroupEpoch::from(epoch),
            &self.keys,
            SenderExtensionIndex::new(0),
        )
        .ok()?;
        message.tls_serialize_detached().ok()
    }

    /// A key package that is `user_id`'s own: it decodes, its signatures hold, it is for this
    /// ciphersuite, and its credential is exactly their MLS identity.
    fn key_package(&self, user_id: &str, data: &[u8]) -> Option<KeyPackage> {
        let package = KeyPackageIn::tls_deserialize_exact_bytes(data)
            .ok()?
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .ok()?;
        let credential = package.leaf_node().credential();
        let ours = package.ciphersuite() == SUITE
            && credential.credential_type() == CredentialType::Basic
            && credential.serialized_content() == mls_user_id(user_id).to_be_bytes();
        ours.then_some(package)
    }
}

/// One leaf of the group's tree.
#[derive(Debug, Clone)]
struct Leaf {
    user_id: String,
    /// Left the call, or could not follow: a Remove is due.
    departing: bool,
}

/// Proposals sent and not yet committed.
struct Batch {
    epoch: u64,
    /// Who was asked to commit.
    to: Vec<String>,
    removes: Vec<u32>,
    adds: Vec<(String, KeyPackage)>,
    at: Instant,
}

/// One room's call.
struct Room {
    room_id: String,
    group: u64,
    /// In join order, and whether each joined able to encrypt end to end.
    people: Vec<(String, bool)>,
    /// Key packages not yet in a batch, in the order they came.
    waiting: Vec<(String, KeyPackage)>,
    /// The group's leaves. Empty while there is no group.
    leaves: Vec<Option<Leaf>>,
    epoch: u64,
    batch: Option<Batch>,
    /// Being added by the batch in flight, and gone or reset since: removed once added.
    leave_after: Vec<String>,
}

impl Room {
    fn new(room_id: &str) -> Self {
        Self {
            room_id: room_id.to_string(),
            group: mls_group_id(room_id),
            people: Vec::new(),
            waiting: Vec::new(),
            leaves: Vec::new(),
            epoch: 0,
            batch: None,
            leave_after: Vec::new(),
        }
    }

    /// End-to-end encrypted: everyone in the call can do it.
    fn encrypted(&self) -> bool {
        self.people.iter().all(|(_, supports)| *supports)
    }

    fn present(&self, user_id: &str) -> bool {
        self.people.iter().any(|(person, _)| person == user_id)
    }

    fn unsupported(&self) -> Vec<String> {
        self.people
            .iter()
            .filter(|(_, supports)| !*supports)
            .map(|(person, _)| person.clone())
            .collect()
    }

    fn supporters(&self) -> Vec<String> {
        self.people
            .iter()
            .filter(|(_, supports)| *supports)
            .map(|(person, _)| person.clone())
            .collect()
    }

    /// Members that stay: those a batch goes to and a commit is shown to.
    fn staying(&self) -> Vec<String> {
        self.leaves
            .iter()
            .flatten()
            .filter(|leaf| !leaf.departing)
            .map(|leaf| leaf.user_id.clone())
            .collect()
    }

    /// Forgets the group. Key packages of people a cancelled batch would have added wait again.
    fn reset_group(&mut self) {
        if let Some(batch) = self.batch.take() {
            for (user_id, package) in batch.adds {
                if self.present(&user_id) && !self.leave_after.contains(&user_id) {
                    self.waiting.push((user_id, package));
                }
            }
        }
        self.leaves.clear();
        self.epoch = 0;
        self.leave_after.clear();
    }

    /// Forgets everything, key packages included.
    fn reset_all(&mut self) {
        self.batch = None;
        self.reset_group();
        self.waiting.clear();
    }

    fn start(&self, signer: &Signer, user_id: &str, out: &mut Vec<Outgoing>) {
        let mut frame = Frame::new(&self.room_id, "start");
        frame.version = Some(VERSION);
        frame.external_sender = Some(&signer.package);
        out.push(Outgoing {
            user_id: user_id.to_string(),
            frame: frame.text(),
        });
    }

    fn off(&self, user_id: &str, out: &mut Vec<Outgoing>) {
        let unsupported = self.unsupported();
        let mut frame = Frame::new(&self.room_id, "off");
        frame.user_ids = Some(&unsupported);
        out.push(Outgoing {
            user_id: user_id.to_string(),
            frame: frame.text(),
        });
    }

    fn send(
        &self,
        user_id: &str,
        op: &'static str,
        epoch: u64,
        data: &str,
        out: &mut Vec<Outgoing>,
    ) {
        let mut frame = Frame::new(&self.room_id, op);
        frame.epoch = Some(epoch);
        frame.data = Some(data);
        out.push(Outgoing {
            user_id: user_id.to_string(),
            frame: frame.text(),
        });
    }

    /// Marks `user_id` for removal wherever they are in the group or about to be.
    fn depart(&mut self, user_id: &str) {
        self.waiting.retain(|(person, _)| person != user_id);
        for leaf in self.leaves.iter_mut().flatten() {
            if leaf.user_id == user_id {
                leaf.departing = true;
            }
        }
        let adding = self
            .batch
            .as_ref()
            .is_some_and(|batch| batch.adds.iter().any(|(person, _)| person == user_id));
        if adding && !self.leave_after.iter().any(|person| person == user_id) {
            self.leave_after.push(user_id.to_string());
        }
    }

    /// Sends the next batch if there is work and none in flight.
    fn pump(&mut self, signer: &Signer, now: Instant, out: &mut Vec<Outgoing>) {
        if !self.encrypted() || self.people.is_empty() {
            return;
        }
        // Nobody who holds the group is left: it is gone with them.
        if !self.leaves.is_empty() && self.staying().is_empty() {
            self.reset_group();
        }
        if self.batch.is_some() {
            return;
        }
        if self.leaves.is_empty() {
            if self.waiting.len() < 2 {
                return;
            }
            // The earliest to join holds the first group: its own pending group, at epoch 0.
            let creator = self
                .people
                .iter()
                .find(|(person, _)| self.waiting.iter().any(|(waiting, _)| waiting == person))
                .map(|(person, _)| person.clone());
            let Some(creator) = creator else {
                return;
            };
            self.waiting.retain(|(person, _)| *person != creator);
            self.leaves = vec![Some(Leaf {
                user_id: creator,
                departing: false,
            })];
            self.epoch = 0;
        }
        let removes: Vec<u32> = self
            .leaves
            .iter()
            .enumerate()
            .filter(|(_, leaf)| leaf.as_ref().is_some_and(|leaf| leaf.departing))
            .filter_map(|(index, _)| u32::try_from(index).ok())
            .collect();
        if removes.is_empty() && self.waiting.is_empty() {
            return;
        }
        let adds = std::mem::take(&mut self.waiting);
        let mut messages = Vec::new();
        for leaf in &removes {
            match signer.remove(*leaf, self.group, self.epoch) {
                Some(message) => messages.extend(message),
                None => tracing::warn!("e2ee remove proposal not made"),
            }
        }
        for (_, package) in &adds {
            match signer.add(package.clone(), self.group, self.epoch) {
                Some(message) => messages.extend(message),
                None => tracing::warn!("e2ee add proposal not made"),
            }
        }
        let Ok(list) = VLBytes::new(messages).tls_serialize_detached() else {
            return;
        };
        // Operation 0 appends proposals.
        let payload = STANDARD.encode([&[0u8][..], &list].concat());
        let to = self.staying();
        for user_id in &to {
            self.send(user_id, "proposals", self.epoch, &payload, out);
        }
        tracing::debug!(
            epoch = self.epoch,
            removes = removes.len(),
            adds = adds.len(),
            members = to.len(),
            "e2ee proposals sent"
        );
        self.batch = Some(Batch {
            epoch: self.epoch,
            to,
            removes,
            adds,
            at: now,
        });
    }

    /// A commit from `user_id`. `Ok` also when it lost or came late: those are dropped.
    #[allow(clippy::too_many_arguments)]
    fn commit(
        &mut self,
        signer: &Signer,
        user_id: &str,
        epoch: u64,
        data: &[u8],
        welcome: Option<&[u8]>,
        now: Instant,
        out: &mut Vec<Outgoing>,
    ) -> Result<(), Refused> {
        let Some(batch) = &self.batch else {
            return Ok(());
        };
        if batch.epoch != epoch || !batch.to.iter().any(|person| person == user_id) {
            return Ok(());
        }
        let message = MlsMessageIn::tls_deserialize_exact_bytes(data).map_err(|_| Refused::Bad)?;
        let Ok(ProtocolMessage::PublicMessage(public)) = message.try_into_protocol_message() else {
            return Err(Refused::Bad);
        };
        let from_leaf = match public.sender() {
            MlsSender::Member(index) => index.u32() as usize,
            _ => return Err(Refused::Bad),
        };
        let sender_holds = self
            .leaves
            .get(from_leaf)
            .and_then(Option::as_ref)
            .is_some_and(|leaf| leaf.user_id == user_id);
        if public.content_type() != ContentType::Commit
            || public.group_id().as_slice() != self.group.to_be_bytes()
            || public.epoch().as_u64() != epoch
            || !sender_holds
        {
            return Err(Refused::Bad);
        }
        let welcome = if batch.adds.is_empty() {
            None
        } else {
            let welcome = welcome.ok_or(Refused::Bad)?;
            Welcome::tls_deserialize_exact_bytes(welcome).map_err(|_| Refused::Bad)?;
            Some(STANDARD.encode(welcome))
        };
        let Some(batch) = self.batch.take() else {
            return Ok(());
        };
        let commit = STANDARD.encode(data);
        for member in self.staying() {
            self.send(&member, "commit", epoch, &commit, out);
        }
        for leaf in &batch.removes {
            if let Some(slot) = self.leaves.get_mut(*leaf as usize) {
                *slot = None;
            }
        }
        for (user_id, _) in &batch.adds {
            let leaf = Some(Leaf {
                user_id: user_id.clone(),
                departing: self.leave_after.contains(user_id),
            });
            match self.leaves.iter().position(Option::is_none) {
                Some(blank) => self.leaves[blank] = leaf,
                None => self.leaves.push(leaf),
            }
        }
        while self.leaves.last().is_some_and(Option::is_none) {
            self.leaves.pop();
        }
        self.leave_after.clear();
        self.epoch = epoch + 1;
        if let Some(welcome) = welcome {
            for (user_id, _) in &batch.adds {
                if self.present(user_id) {
                    self.send(user_id, "welcome", self.epoch, &welcome, out);
                }
            }
        }
        tracing::debug!(epoch = self.epoch, "e2ee commit accepted");
        self.pump(signer, now, out);
        Ok(())
    }
}

/// Every room's E2EE state, under the same lock as the call registry.
pub(crate) struct Rooms {
    signer: Signer,
    rooms: HashMap<String, Room>,
}

impl Default for Rooms {
    fn default() -> Self {
        Self::new()
    }
}

impl Rooms {
    pub fn new() -> Self {
        Self {
            signer: Signer::new(),
            rooms: HashMap::new(),
        }
    }

    /// `user_id` took a seat with media in `room_id`. They get `start` or `off`; a joiner
    /// who cannot encrypt turns the room's call to transport only for everyone.
    pub fn join(&mut self, room_id: &str, user_id: &str, supports: bool) -> Vec<Outgoing> {
        let mut out = Vec::new();
        let room = self
            .rooms
            .entry(room_id.to_string())
            .or_insert_with(|| Room::new(room_id));
        let was = room.encrypted() && !room.people.is_empty();
        room.people.retain(|(person, _)| person != user_id);
        room.people.push((user_id.to_string(), supports));
        if supports {
            if room.encrypted() {
                room.start(&self.signer, user_id, &mut out);
            } else {
                room.off(user_id, &mut out);
            }
            return out;
        }
        if was {
            tracing::debug!("e2ee off: a participant cannot encrypt");
            room.reset_all();
        }
        for person in room.supporters() {
            room.off(&person, &mut out);
        }
        out
    }

    /// `user_id` left `room_id`'s call, for any reason.
    pub fn leave(&mut self, room_id: &str, user_id: &str, now: Instant) -> Vec<Outgoing> {
        let mut out = Vec::new();
        let Some(room) = self.rooms.get_mut(room_id) else {
            return out;
        };
        let Some(at) = room.people.iter().position(|(person, _)| person == user_id) else {
            return out;
        };
        let (_, supported) = room.people.remove(at);
        if room.people.is_empty() {
            self.rooms.remove(room_id);
            return out;
        }
        if !supported {
            if room.encrypted() {
                tracing::debug!("e2ee on: everyone left can encrypt");
                room.reset_all();
                for person in room.supporters() {
                    room.start(&self.signer, &person, &mut out);
                }
            } else {
                for person in room.supporters() {
                    room.off(&person, &mut out);
                }
            }
            return out;
        }
        if room.encrypted() {
            room.depart(user_id);
            room.pump(&self.signer, now, &mut out);
        }
        out
    }

    pub fn key_package(
        &mut self,
        room_id: &str,
        user_id: &str,
        data: &[u8],
        now: Instant,
    ) -> Result<Vec<Outgoing>, Refused> {
        let mut out = Vec::new();
        let Self { signer, rooms } = self;
        let room = room_for(rooms, room_id, user_id)?;
        let package = signer.key_package(user_id, data).ok_or(Refused::Bad)?;
        // A member who sends one has started again: the old leaf goes.
        room.depart(user_id);
        room.waiting.push((user_id.to_string(), package));
        room.pump(signer, now, &mut out);
        Ok(out)
    }

    pub fn commit(
        &mut self,
        room_id: &str,
        user_id: &str,
        epoch: u64,
        data: &[u8],
        welcome: Option<&[u8]>,
        now: Instant,
    ) -> Result<Vec<Outgoing>, Refused> {
        let mut out = Vec::new();
        let Self { signer, rooms } = self;
        let room = room_for(rooms, room_id, user_id)?;
        room.commit(signer, user_id, epoch, data, welcome, now, &mut out)?;
        Ok(out)
    }

    /// `user_id` could not apply a commit or a welcome. It starts again with a key package.
    pub fn invalid(
        &mut self,
        room_id: &str,
        user_id: &str,
        now: Instant,
    ) -> Result<Vec<Outgoing>, Refused> {
        let mut out = Vec::new();
        let Self { signer, rooms } = self;
        let room = room_for(rooms, room_id, user_id)?;
        room.depart(user_id);
        room.pump(signer, now, &mut out);
        Ok(out)
    }

    /// Builds again every group whose batch has waited [`STUCK`] for a commit.
    pub fn tick(&mut self, now: Instant) -> Vec<Outgoing> {
        let mut out = Vec::new();
        for room in self.rooms.values_mut() {
            let stuck = room
                .batch
                .as_ref()
                .is_some_and(|batch| now.saturating_duration_since(batch.at) >= STUCK);
            if stuck {
                tracing::debug!(
                    epoch = room.epoch,
                    "e2ee batch stuck; building the group again"
                );
                room.reset_all();
                for person in room.supporters() {
                    room.start(&self.signer, &person, &mut out);
                }
            }
        }
        out
    }

    pub fn clear(&mut self) {
        self.rooms.clear();
    }

    #[cfg(test)]
    fn leaves(&self, room_id: &str) -> Vec<Option<String>> {
        self.rooms.get(room_id).map_or_else(Vec::new, |room| {
            room.leaves
                .iter()
                .map(|leaf| leaf.as_ref().map(|leaf| leaf.user_id.clone()))
                .collect()
        })
    }

    #[cfg(test)]
    fn epoch(&self, room_id: &str) -> u64 {
        self.rooms.get(room_id).map_or(0, |room| room.epoch)
    }
}

/// `room_id`'s call, if it is end-to-end encrypted with `user_id` in it.
fn room_for<'a>(
    rooms: &'a mut HashMap<String, Room>,
    room_id: &str,
    user_id: &str,
) -> Result<&'a mut Room, Refused> {
    match rooms.get_mut(room_id) {
        Some(room) if room.present(user_id) && room.encrypted() => Ok(room),
        _ => Err(Refused::NotFound),
    }
}

/// Decodes a `data` or `welcome` field: base64, at most [`DATA_MAX`] bytes.
pub(crate) fn decode(field: Option<&str>) -> Result<Vec<u8>, Refused> {
    let field = field.ok_or(Refused::BadFrame)?;
    if field.len() > DATA_MAX / 3 * 4 + 4 {
        return Err(Refused::BadFrame);
    }
    let bytes = STANDARD.decode(field).map_err(|_| Refused::Bad)?;
    if bytes.len() > DATA_MAX {
        return Err(Refused::BadFrame);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
