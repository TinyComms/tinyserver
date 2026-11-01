//! A device that speaks MLS, as tinyclient does: real openmls groups, with the server only
//! delivering. Shared by the unit tests of `e2ee_text::mls` (through `#[path]`) and by
//! `tests/e2ee_text.rs`, so both drive the same client.
//!
//! Nothing here is part of the server. It exists so a test can make real key packages, real
//! commits, real welcomes and real application messages, and show the server accepts exactly
//! the right ones.

#![allow(dead_code)]

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use openmls::prelude::tls_codec::{DeserializeBytes as _, Serialize as _, VLBytes};
use openmls::prelude::{
    BasicCredential, Capabilities, Ciphersuite, CredentialWithKey, Extension, ExtensionType,
    Extensions, ExternalSender, GroupId, KeyPackage, Lifetime, MlsGroup, MlsGroupCreateConfig,
    MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn, OpenMlsProvider, ProcessedMessageContent,
    ProtocolVersion, RatchetTreeIn, StagedWelcome, MIXED_PLAINTEXT_WIRE_FORMAT_POLICY,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
pub const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256;

/// Signs as the key pair does (ECDSA P-256, DER). openmls hands out no private key, so it is
/// read from the TLS encoding of the pair: a vector of the private key, then the public key.
pub fn sign_with(provider: &OpenMlsRustCrypto, keys: &SignatureKeyPair, message: &[u8]) -> Vec<u8> {
    use openmls::prelude::OpenMlsCrypto;
    let encoded = keys.tls_serialize_detached().expect("serialise");
    let length = usize::from(encoded[0]);
    assert!(length < 64, "a 32 byte private key has a one byte header");
    let private = &encoded[1..=length];
    provider
        .crypto()
        .sign(SUITE.signature_algorithm(), message, private)
        .expect("sign")
}

/// The 16 bytes of a hyphenated uuid.
pub fn uuid16(id: &str) -> [u8; 16] {
    let hex: String = id.chars().filter(|c| *c != '-').collect();
    assert_eq!(hex.len(), 32, "a uuid");
    let mut out = [0u8; 16];
    for (at, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[at * 2..at * 2 + 2], 16).expect("hex");
    }
    out
}

/// Seconds since the epoch.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn capabilities() -> Capabilities {
    Capabilities::builder()
        .ciphersuites(vec![SUITE])
        .extensions(vec![
            ExtensionType::ExternalSenders,
            ExtensionType::LastResort,
        ])
        .build()
}

/// The authenticated data of an application message, as tinyclient's `crates/e2ee` sets it:
/// `"tiny-e2ee-v1 msg" 0x00 kind 0x00 target_id`.
pub fn message_aad(kind: &str, target_id: Option<&str>) -> Vec<u8> {
    let mut aad = b"tiny-e2ee-v1 msg".to_vec();
    aad.push(0);
    aad.extend_from_slice(kind.as_bytes());
    aad.push(0);
    aad.extend_from_slice(target_id.unwrap_or("").as_bytes());
    aad
}

/// What a commit made: the commit, and the welcome if it added anyone, both as MLSMessages, and
/// the public ratchet tree of the epoch it makes (TLS `RatchetTree`).
pub struct Committed {
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
    pub tree: Vec<u8>,
}

/// One device holds a group for each encrypted conversation it is in. The methods that read or
/// change a group work on the one `use_group` named last.
pub struct Client {
    pub provider: OpenMlsRustCrypto,
    pub keys: SignatureKeyPair,
    pub user_id: String,
    pub device_id: String,
    groups: HashMap<[u8; 16], MlsGroup>,
    current: [u8; 16],
}

impl Client {
    pub fn new(user_id: &str, device_id: &str) -> Self {
        Self {
            provider: OpenMlsRustCrypto::default(),
            keys: SignatureKeyPair::new(SUITE.signature_algorithm()).expect("keys"),
            user_id: user_id.to_string(),
            device_id: device_id.to_string(),
            groups: HashMap::new(),
            current: [0; 16],
        }
    }

    /// Works on the group of this conversation from now on.
    pub fn use_group(&mut self, id: [u8; 16]) {
        self.current = id;
    }

    pub fn has_group(&self, id: &[u8; 16]) -> bool {
        self.groups.contains_key(id)
    }

    pub fn group_mut(&mut self) -> &mut MlsGroup {
        self.groups.get_mut(&self.current).expect("in a group")
    }

    /// The 32 byte credential content: the user id then the device id.
    pub fn credential_content(&self) -> Vec<u8> {
        let mut content = uuid16(&self.user_id).to_vec();
        content.extend_from_slice(&uuid16(&self.device_id));
        content
    }

    pub fn signature_key(&self) -> Vec<u8> {
        self.keys.public().to_vec()
    }

    pub fn signature_key_b64(&self) -> String {
        STANDARD.encode(self.keys.public())
    }

    fn credential_with_key(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(self.credential_content()).into(),
            signature_key: self.keys.public().into(),
        }
    }

    /// What this device signs to vouch for `new_device`, as the server checks it.
    pub fn vouch_for(&self, user_id: &str, device_id: &str, new_key: &[u8]) -> Vec<u8> {
        let mut message = b"tiny-e2ee-v1 device-add".to_vec();
        message.extend_from_slice(&uuid16(user_id));
        message.extend_from_slice(&uuid16(device_id));
        message.extend_from_slice(new_key);
        sign_with(&self.provider, &self.keys, &message)
    }

    /// A key package valid for 30 days, for this device.
    pub fn key_package(&self) -> Vec<u8> {
        self.key_package_with(
            &self.keys,
            &self.credential_content(),
            Lifetime::new(30 * 24 * 3600),
        )
    }

    /// A key package signed by `keys` with `content` as its credential, valid as `lifetime` says.
    pub fn key_package_with(
        &self,
        keys: &SignatureKeyPair,
        content: &[u8],
        lifetime: Lifetime,
    ) -> Vec<u8> {
        let credential = CredentialWithKey {
            credential: BasicCredential::new(content.to_vec()).into(),
            signature_key: keys.public().into(),
        };
        let bundle = KeyPackage::builder()
            .key_package_lifetime(lifetime)
            .leaf_node_capabilities(capabilities())
            .build(SUITE, &self.provider, keys, credential)
            .expect("key package");
        bundle
            .key_package()
            .tls_serialize_detached()
            .expect("serialise")
    }

    /// A key package that lasts a year, for a last resort.
    pub fn last_resort(&self) -> Vec<u8> {
        let bundle = KeyPackage::builder()
            .key_package_lifetime(Lifetime::new(300 * 24 * 3600))
            .leaf_node_capabilities(capabilities())
            .mark_as_last_resort()
            .build(
                SUITE,
                &self.provider,
                &self.keys,
                self.credential_with_key(),
            )
            .expect("key package");
        bundle
            .key_package()
            .tls_serialize_detached()
            .expect("serialise")
    }

    /// Starts the group of `group_id` at epoch 0 with the server's external sender.
    pub fn create_group(&mut self, group_id: [u8; 16], external_sender: &str) {
        let bytes = STANDARD.decode(external_sender).expect("base64");
        let sender = ExternalSender::tls_deserialize_exact_bytes(&bytes).expect("external sender");
        let extensions =
            Extensions::single(Extension::ExternalSenders(vec![sender])).expect("extensions");
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(SUITE)
            .use_ratchet_tree_extension(true)
            .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .with_group_context_extensions(extensions)
            .capabilities(capabilities())
            .build();
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.keys,
            &config,
            GroupId::from_slice(&group_id),
            self.credential_with_key(),
        )
        .expect("group");
        self.groups.insert(group_id, group);
        self.current = group_id;
    }

    pub fn epoch(&self) -> u64 {
        self.groups[&self.current].epoch().as_u64()
    }

    pub fn leaf_index(&self) -> u32 {
        self.groups[&self.current].own_leaf_index().u32()
    }

    /// Reads a batch from the log: a TLS vector of MLSMessages, each an external proposal.
    pub fn messages_of(batch: &[u8]) -> Vec<Vec<u8>> {
        let (all, rest) = VLBytes::tls_deserialize_bytes(batch).expect("a vector");
        assert!(rest.is_empty(), "nothing after the vector");
        let mut bytes = all.as_slice();
        let mut out = Vec::new();
        while !bytes.is_empty() {
            let (message, rest) =
                MlsMessageIn::tls_deserialize_bytes(bytes).expect("an MLS message");
            let used = bytes.len() - rest.len();
            out.push(bytes[..used].to_vec());
            drop(message);
            bytes = rest;
        }
        out
    }

    /// Whether the group accepts this message as it is: a proposal for the right epoch, say.
    pub fn accepts(&mut self, message: &[u8]) -> bool {
        let Ok(message) = MlsMessageIn::tls_deserialize_exact_bytes(message) else {
            return false;
        };
        let Ok(protocol) = message.try_into_protocol_message() else {
            return false;
        };
        let provider = &self.provider;
        let group = self.groups.get_mut(&self.current).expect("in a group");
        group.process_message(provider, protocol).is_ok()
    }

    /// Stores each proposal of a batch, as a member does when it reads the log.
    pub fn take_proposals(&mut self, batch: &[u8]) {
        for message in Self::messages_of(batch) {
            self.take_proposal(&message);
        }
    }

    pub fn take_proposal(&mut self, message: &[u8]) {
        let message = MlsMessageIn::tls_deserialize_exact_bytes(message).expect("message");
        let protocol = message
            .try_into_protocol_message()
            .expect("protocol message");
        let provider = &self.provider;
        let group = self.groups.get_mut(&self.current).expect("in a group");
        let processed = group
            .process_message(provider, protocol)
            .expect("process proposal");
        match processed.into_content() {
            ProcessedMessageContent::ProposalMessage(queued)
            | ProcessedMessageContent::ExternalJoinProposalMessage(queued) => group
                .store_pending_proposal(provider.storage(), *queued)
                .expect("store proposal"),
            other => panic!("not a proposal: {other:?}"),
        }
    }

    /// Commits the proposals it has stored. The group does not move until `merge`.
    pub fn commit(&mut self) -> Committed {
        let provider = &self.provider;
        let keys = &self.keys;
        let group = self.groups.get_mut(&self.current).expect("in a group");
        let (commit, welcome, _) = group
            .commit_to_pending_proposals(provider, keys)
            .expect("commit");
        let tree = group
            .pending_commit()
            .expect("staged")
            .export_ratchet_tree(provider.crypto(), group.export_ratchet_tree())
            .expect("tree")
            .expect("a member's commit");
        Committed {
            commit: commit.tls_serialize_detached().expect("serialise"),
            welcome: welcome.map(|welcome| welcome.tls_serialize_detached().expect("serialise")),
            tree: RatchetTreeIn::from(tree)
                .tls_serialize_detached()
                .expect("serialise"),
        }
    }

    /// The server refused or lost the commit: it is dropped, and the proposals stay stored.
    pub fn abandon(&mut self) {
        let provider = &self.provider;
        self.groups
            .get_mut(&self.current)
            .expect("in a group")
            .clear_pending_commit(provider.storage())
            .expect("clear");
    }

    /// A key package for another ciphersuite (X25519 and Ed25519) with this device's credential,
    /// and the signature key it carries.
    pub fn key_package_other_suite(&self) -> (Vec<u8>, Vec<u8>) {
        let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let keys = SignatureKeyPair::new(suite.signature_algorithm()).expect("keys");
        let credential = CredentialWithKey {
            credential: BasicCredential::new(self.credential_content()).into(),
            signature_key: keys.public().into(),
        };
        let capabilities = Capabilities::builder().ciphersuites(vec![suite]).build();
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(capabilities)
            .build(suite, &self.provider, &keys, credential)
            .expect("key package");
        let bytes = bundle
            .key_package()
            .tls_serialize_detached()
            .expect("serialise");
        (bytes, keys.public().to_vec())
    }

    /// The server accepted the commit: the group moves to the next epoch.
    pub fn merge(&mut self) {
        let provider = &self.provider;
        self.groups
            .get_mut(&self.current)
            .expect("in a group")
            .merge_pending_commit(provider)
            .expect("merge");
    }

    /// Reads a commit someone else made.
    pub fn take_commit(&mut self, commit: &[u8]) {
        let message = MlsMessageIn::tls_deserialize_exact_bytes(commit).expect("message");
        let protocol = message
            .try_into_protocol_message()
            .expect("protocol message");
        let provider = &self.provider;
        let group = self.groups.get_mut(&self.current).expect("in a group");
        let processed = group
            .process_message(provider, protocol)
            .expect("process commit");
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => group
                .merge_staged_commit(provider, *staged)
                .expect("merge commit"),
            other => panic!("not a commit: {other:?}"),
        }
    }

    /// Joins from a welcome (an MLSMessage).
    pub fn join(&mut self, welcome: &[u8]) {
        self.join_with_tree(welcome, None);
    }

    /// From now on the commits of the current group put the ratchet tree in their Welcome, or
    /// leave it out for the joiner to fetch.
    pub fn inline_tree(&mut self, inline: bool) {
        let config = MlsGroupJoinConfig::builder()
            .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(inline)
            .build();
        let provider = &self.provider;
        self.groups
            .get_mut(&self.current)
            .expect("in a group")
            .set_configuration(provider.storage(), &config)
            .expect("configure");
    }

    /// Joins from a welcome, with the ratchet tree given apart from it when it has none inside.
    pub fn join_with_tree(&mut self, welcome: &[u8], tree: Option<&[u8]>) {
        let tree = tree.map(|tree| RatchetTreeIn::tls_deserialize_exact_bytes(tree).expect("tree"));
        let message = MlsMessageIn::tls_deserialize_exact_bytes(welcome).expect("message");
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            panic!("not a welcome");
        };
        let config = MlsGroupJoinConfig::builder()
            .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .build();
        let staged = StagedWelcome::new_from_welcome(&self.provider, &config, welcome, tree)
            .expect("welcome");
        let group = staged.into_group(&self.provider).expect("group");
        let id: [u8; 16] = group
            .group_id()
            .as_slice()
            .try_into()
            .expect("a 16 byte group id");
        self.groups.insert(id, group);
        self.current = id;
    }

    /// Encrypts a message, as an MLS PrivateMessage with the authenticated data of a message.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.encrypt_as("message", None, plaintext)
    }

    /// Encrypts with the authenticated data of `kind` and `target_id`.
    pub fn encrypt_as(&mut self, kind: &str, target_id: Option<&str>, plaintext: &[u8]) -> Vec<u8> {
        self.encrypt_with_aad(message_aad(kind, target_id), plaintext)
    }

    /// Encrypts with any authenticated data.
    pub fn encrypt_with_aad(&mut self, aad: Vec<u8>, plaintext: &[u8]) -> Vec<u8> {
        let provider = &self.provider;
        let keys = &self.keys;
        let group = self.groups.get_mut(&self.current).expect("in a group");
        group.set_aad(aad);
        group
            .create_message(provider, keys, plaintext)
            .expect("encrypt")
            .tls_serialize_detached()
            .expect("serialise")
    }

    /// `None` when it cannot be decrypted here.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let message = MlsMessageIn::tls_deserialize_exact_bytes(ciphertext).ok()?;
        let protocol = message.try_into_protocol_message().ok()?;
        let provider = &self.provider;
        let group = self.groups.get_mut(&self.current)?;
        let processed = group.process_message(provider, protocol).ok()?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => Some(message.into_bytes()),
            _ => None,
        }
    }

    pub fn is_member(&self, user_id: &str, device_id: &str) -> bool {
        let mut content = uuid16(user_id).to_vec();
        content.extend_from_slice(&uuid16(device_id));
        self.groups.get(&self.current).is_some_and(|group| {
            group
                .members()
                .any(|member| member.credential.serialized_content() == content.as_slice())
        })
    }
}

/// Never used, but keeps the protocol version in view: MLS 1.0.
pub const VERSION: ProtocolVersion = ProtocolVersion::Mls10;
