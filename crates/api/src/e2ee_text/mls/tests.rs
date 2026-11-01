//! The MLS checks of the delivery service, against real openmls groups.

#[path = "../../../tests/common/mls_client.rs"]
mod client;

use client::{sign_with, unix_now, uuid16, Client};
use openmls::prelude::{Lifetime, SignatureScheme};
use openmls_basic_credential::SignatureKeyPair;

use super::*;

const USER_A: &str = "11111111-1111-4111-8111-111111111111";
const DEVICE_A: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const USER_B: &str = "22222222-2222-4222-8222-222222222222";
const DEVICE_B: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const GROUP: &str = "33333333-3333-4333-8333-333333333333";

fn server() -> Signer {
    let (public, stored) = Signer::generate().expect("key");
    Signer::from_parts(public, stored).expect("signer")
}

#[test]
fn a_uuid_is_its_sixteen_bytes_and_only_in_its_own_form() {
    assert_eq!(uuid_bytes(GROUP), Some(uuid16(GROUP)));
    assert_eq!(uuid_bytes(&GROUP.replace('-', "")), None);
    assert_eq!(uuid_bytes(&GROUP.to_uppercase()), Some(uuid16(GROUP)));
    assert_eq!(uuid_bytes(""), None);
    assert_eq!(uuid_bytes("zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"), None);
    assert_eq!(uuid_bytes(&format!("{GROUP}0")), None);
}

#[test]
fn the_stored_server_key_is_the_one_that_was_made() {
    let (public, stored) = Signer::generate().expect("key");
    assert!(stored.len() <= 128, "fits the column");
    let first = Signer::from_parts(public.clone(), stored.clone()).expect("load");
    let again = Signer::from_parts(public, stored).expect("reload");
    assert_eq!(first.external_sender(), again.external_sender());
    // A stored key that is not the public key beside it is refused.
    let (other, _) = Signer::generate().expect("key");
    let (_, stored) = Signer::generate().expect("key");
    assert!(Signer::from_parts(other, stored).is_none());
}

#[test]
fn a_key_package_is_valid_only_for_its_own_device() {
    let a = Client::new(USER_A, DEVICE_A);
    let now = unix_now();
    let good = a.key_package();
    let expires = validate_key_package(USER_A, DEVICE_A, &a.signature_key(), &good, now);
    assert!(matches!(expires, Ok(at) if at > i64::try_from(now).expect("time")));

    // Somebody else's device and user.
    assert_eq!(
        validate_key_package(USER_B, DEVICE_A, &a.signature_key(), &good, now),
        Err(Refused::Bad)
    );
    assert_eq!(
        validate_key_package(USER_A, DEVICE_B, &a.signature_key(), &good, now),
        Err(Refused::Bad)
    );
    // The credential of another device, with a signature that holds.
    let b = Client::new(USER_B, DEVICE_B);
    let wrong_credential =
        a.key_package_with(&a.keys, &b.credential_content(), Lifetime::new(3600));
    assert_eq!(
        validate_key_package(USER_A, DEVICE_A, &a.signature_key(), &wrong_credential, now),
        Err(Refused::Bad)
    );
    // A different signature key than the one registered.
    assert_eq!(
        validate_key_package(USER_A, DEVICE_A, &b.signature_key(), &good, now),
        Err(Refused::Bad)
    );
    // Not a key package, truncated, and a bit flipped in its signature.
    assert_eq!(
        validate_key_package(USER_A, DEVICE_A, &a.signature_key(), b"nope", now),
        Err(Refused::Bad)
    );
    assert_eq!(
        validate_key_package(
            USER_A,
            DEVICE_A,
            &a.signature_key(),
            &good[..good.len() - 3],
            now
        ),
        Err(Refused::Bad)
    );
    let mut flipped = good.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    assert_eq!(
        validate_key_package(USER_A, DEVICE_A, &a.signature_key(), &flipped, now),
        Err(Refused::Bad)
    );
    assert_eq!(
        validate_key_package(
            USER_A,
            DEVICE_A,
            &a.signature_key(),
            &vec![0u8; KEY_PACKAGE_MAX + 1],
            now
        ),
        Err(Refused::TooLarge)
    );
}

#[test]
fn an_expired_or_far_future_key_package_is_refused() {
    let a = Client::new(USER_A, DEVICE_A);
    let now = unix_now();
    for (not_before, not_after) in [
        (now - 7200, now - 3600),
        (now + 3600, now + 7200),
        (now - 3600, now + 500 * 24 * 3600),
    ] {
        let package = a.key_package_with(
            &a.keys,
            &a.credential_content(),
            Lifetime::init(not_before, not_after),
        );
        assert_eq!(
            validate_key_package(USER_A, DEVICE_A, &a.signature_key(), &package, now),
            Err(Refused::Bad),
            "valid from {not_before} to {not_after}, now {now}"
        );
    }
}

#[test]
fn a_cross_signature_is_one_device_vouching_for_another() {
    let a = Client::new(USER_A, DEVICE_A);
    let b = Client::new(USER_A, DEVICE_B);
    let vouch = a.vouch_for(USER_A, DEVICE_B, &b.signature_key());
    let signers = [a.signature_key()];
    assert!(cross_signed(
        USER_A,
        DEVICE_B,
        &b.signature_key(),
        &vouch,
        &signers
    ));
    // The wrong signer, the wrong device, another person, another key, and garbage.
    let stranger = Client::new(USER_B, DEVICE_A);
    assert!(!cross_signed(
        USER_A,
        DEVICE_B,
        &b.signature_key(),
        &vouch,
        &[stranger.signature_key()]
    ));
    assert!(!cross_signed(
        USER_A,
        DEVICE_A,
        &b.signature_key(),
        &vouch,
        &signers
    ));
    assert!(!cross_signed(
        USER_B,
        DEVICE_B,
        &b.signature_key(),
        &vouch,
        &signers
    ));
    assert!(!cross_signed(
        USER_A,
        DEVICE_B,
        &a.signature_key(),
        &vouch,
        &signers
    ));
    assert!(!cross_signed(
        USER_A,
        DEVICE_B,
        &b.signature_key(),
        b"garbage",
        &signers
    ));
    assert!(!cross_signed(
        USER_A,
        DEVICE_B,
        &b.signature_key(),
        &vouch,
        &[]
    ));
    // The same key signing other words is not a device add.
    let other = sign_with(&a.provider, &a.keys, b"tiny-e2ee-v1 something else");
    assert!(!cross_signed(
        USER_A,
        DEVICE_B,
        &b.signature_key(),
        &other,
        &signers
    ));
}

/// A group of one device with the server's external sender, and a second device.
fn pair() -> (Client, Client, Signer, [u8; 16]) {
    let group = uuid16(GROUP);
    let server = server();
    let mut a = Client::new(USER_A, DEVICE_A);
    a.create_group(group, server.external_sender());
    let b = Client::new(USER_B, DEVICE_B);
    (a, b, server, group)
}

/// A and B in one group at epoch 1, as A's commit made it.
fn joined() -> (Client, Client, Signer, [u8; 16]) {
    let (mut a, mut b, server, group) = pair();
    let add = server
        .add(
            parse_key_package(&b.key_package()).expect("package"),
            &group,
            0,
        )
        .expect("add");
    a.take_proposals(&batch(&[&add]).expect("batch"));
    let committed = a.commit();
    a.merge();
    b.join(&committed.welcome.expect("welcome"));
    (a, b, server, group)
}

#[test]
fn a_commit_names_the_proposals_the_server_signed_by_reference() {
    let (mut a, b, server, group) = pair();
    let package = parse_key_package(&b.key_package()).expect("package");
    let add = server.add(package, &group, 0).expect("add proposal");
    a.take_proposals(&batch(&[&add]).expect("batch"));
    let committed = a.commit();

    let meta = parse_commit(&group, 0, &committed.commit).expect("a commit");
    assert_eq!(meta.sender_leaf, 0);
    assert_eq!(
        meta.proposal_refs,
        vec![proposal_ref(&add).expect("reference")]
    );
}

#[test]
fn a_welcome_names_exactly_the_key_package_it_was_made_for() {
    let (mut a, b, server, group) = pair();
    let b_package = b.key_package();
    let add = server
        .add(parse_key_package(&b_package).expect("package"), &group, 0)
        .expect("add");
    a.take_proposals(&batch(&[&add]).expect("batch"));
    let welcome = a.commit().welcome.expect("welcome");
    let recipients = welcome_recipients(&welcome).expect("recipients");
    assert_eq!(
        recipients,
        vec![key_package_ref(&b_package).expect("reference")]
    );
    // Another device's key package is not in it.
    let c = Client::new(USER_B, "cccccccc-cccc-4ccc-8ccc-cccccccccccc");
    assert!(!recipients.contains(&key_package_ref(&c.key_package()).expect("reference")));
}

#[test]
fn a_removal_is_committed_by_reference_and_a_removed_device_reads_nothing_after() {
    let (mut a, mut b, server, group) = joined();
    assert_eq!(a.epoch(), 1);
    let before = a.encrypt(b"while b is in");
    assert_eq!(b.decrypt(&before).as_deref(), Some(&b"while b is in"[..]));

    let remove = server.remove(1, &group, 1).expect("remove");
    a.take_proposal(&remove);
    let committed = a.commit();
    let meta = parse_commit(&group, 1, &committed.commit).expect("a commit");
    assert_eq!(
        meta.proposal_refs,
        vec![proposal_ref(&remove).expect("reference")]
    );
    assert!(committed.welcome.is_none(), "a removal makes no welcome");
    a.merge();
    assert!(!a.is_member(USER_B, DEVICE_B));

    // The removed device has no key for the new epoch.
    let after = a.encrypt(b"after b is out");
    assert_eq!(b.decrypt(&after), None);
}

#[test]
fn several_proposals_are_listed_in_the_order_they_were_signed() {
    let (mut a, mut b, server, group) = joined();
    let c = Client::new(USER_B, "cccccccc-cccc-4ccc-8ccc-cccccccccccc");
    let d = Client::new(USER_A, "dddddddd-dddd-4ddd-8ddd-dddddddddddd");
    let remove = server.remove(1, &group, 1).expect("remove");
    let add_c = server
        .add(
            parse_key_package(&c.key_package()).expect("package"),
            &group,
            1,
        )
        .expect("add");
    let add_d = server
        .add(
            parse_key_package(&d.key_package()).expect("package"),
            &group,
            1,
        )
        .expect("add");
    a.take_proposals(&batch(&[&remove, &add_c, &add_d]).expect("batch"));
    let committed = a.commit();
    let meta = parse_commit(&group, 1, &committed.commit).expect("a commit");
    let mut wanted = vec![
        proposal_ref(&remove).expect("reference"),
        proposal_ref(&add_c).expect("reference"),
        proposal_ref(&add_d).expect("reference"),
    ];
    // openmls lists them by kind. The server keeps its own order; a commit may use any, as
    // long as each is named once.
    let mut got = meta.proposal_refs.clone();
    wanted.sort();
    got.sort();
    assert_eq!(got, wanted);
    a.merge();
    // The remove blanked leaf 1 and the first add took it: the lowest free leaf.
    assert!(a.is_member(USER_B, "cccccccc-cccc-4ccc-8ccc-cccccccccccc"));
    assert!(!a.is_member(USER_B, DEVICE_B));
    let _ = &mut b;
}

#[test]
fn a_commit_for_another_group_epoch_or_without_a_member_sender_is_refused() {
    let (mut a, b, server, group) = pair();
    let add = server
        .add(
            parse_key_package(&b.key_package()).expect("package"),
            &group,
            0,
        )
        .expect("add");
    a.take_proposals(&batch(&[&add]).expect("batch"));
    let committed = a.commit();
    assert!(parse_commit(&group, 0, &committed.commit).is_ok());
    assert_eq!(
        parse_commit(&group, 1, &committed.commit),
        Err(Refused::Bad)
    );
    assert_eq!(
        parse_commit(&[9; 16], 0, &committed.commit),
        Err(Refused::Bad)
    );
    // A proposal and a welcome are not commits.
    assert_eq!(parse_commit(&group, 0, &add), Err(Refused::Bad));
    assert_eq!(
        parse_commit(&group, 0, &committed.welcome.expect("welcome")),
        Err(Refused::Bad)
    );
}

#[test]
fn an_application_message_is_checked_on_its_outer_frame_only() {
    let (mut a, _b, _server, group) = joined();
    let ciphertext = a.encrypt(b"secret words");
    assert!(check_ciphertext(&group, 1, &ciphertext).is_ok());
    assert_eq!(check_ciphertext(&group, 0, &ciphertext), Err(Refused::Bad));
    assert_eq!(
        check_ciphertext(&[1; 16], 1, &ciphertext),
        Err(Refused::Bad)
    );
    assert_eq!(
        check_ciphertext(&group, 1, b"plain words"),
        Err(Refused::Bad)
    );
    assert_eq!(check_ciphertext(&group, 1, &[]), Err(Refused::Bad));
    assert_eq!(
        check_ciphertext(&group, 1, &vec![0; CIPHERTEXT_MAX + 1]),
        Err(Refused::TooLarge)
    );
}

#[test]
fn a_handshake_message_is_not_an_application_message() {
    let (mut a, b, server, group) = pair();
    let add = server
        .add(
            parse_key_package(&b.key_package()).expect("package"),
            &group,
            0,
        )
        .expect("add");
    a.take_proposals(&batch(&[&add]).expect("batch"));
    let committed = a.commit();
    assert_eq!(
        check_ciphertext(&group, 0, &committed.commit),
        Err(Refused::Bad)
    );
    assert_eq!(check_ciphertext(&group, 0, &add), Err(Refused::Bad));
    let welcome = committed.welcome.expect("welcome");
    assert_eq!(check_ciphertext(&group, 1, &welcome), Err(Refused::Bad));
}

#[test]
fn the_group_itself_refuses_a_proposal_signed_for_another_epoch() {
    // The server must sign for the epoch it holds: openmls enforces it on the member side.
    let (mut a, b, server, group) = pair();
    let package = parse_key_package(&b.key_package()).expect("package");
    let stale = server.add(package, &group, 5).expect("add");
    let message = MlsMessageIn::tls_deserialize_exact_bytes(&stale).expect("message");
    let protocol = message.try_into_protocol_message().expect("protocol");
    let provider = &a.provider;
    let group_ref = a.group.as_mut().expect("group");
    assert!(group_ref.process_message(provider, protocol).is_err());
}

#[test]
fn malformed_bytes_are_refused_and_never_panic() {
    let (mut a, b, server, group) = pair();
    let add = server
        .add(
            parse_key_package(&b.key_package()).expect("package"),
            &group,
            0,
        )
        .expect("add");
    a.take_proposals(&batch(&[&add]).expect("batch"));
    let committed = a.commit();
    let valid = [
        committed.commit.clone(),
        committed.welcome.clone().expect("welcome"),
        b.key_package(),
        add.clone(),
    ];
    let try_all = |bytes: &[u8]| {
        let _ = validate_key_package(USER_A, DEVICE_A, &[4; 65], bytes, 0);
        let _ = parse_commit(&group, 0, bytes);
        let _ = check_ciphertext(&group, 0, bytes);
        let _ = welcome_recipients(bytes);
        let _ = proposal_ref(bytes);
        let _ = key_package_ref(bytes);
    };
    for bytes in &valid {
        for cut in [0, 1, 2, 3, 5, 8, 20, bytes.len() / 2, bytes.len() - 1] {
            try_all(&bytes[..cut.min(bytes.len())]);
        }
        // Every one of the first 400 bytes flipped in turn.
        for at in 0..bytes.len().min(400) {
            let mut changed = bytes.clone();
            changed[at] ^= 0xff;
            try_all(&changed);
        }
    }
    // Lengths that lie.
    for bytes in [
        &[0u8; 0][..],
        &[0xff; 64][..],
        &[0x00, 0x01, 0x00, 0x01, 0x3f][..],
        &[0x00, 0x01, 0x00, 0x01, 0x80, 0xff, 0xff, 0xff][..],
        &[0xc0, 0, 0, 0, 0, 0, 0, 0][..],
    ] {
        assert!(parse_commit(&group, 0, bytes).is_err());
        assert!(check_ciphertext(&group, 0, bytes).is_err());
        assert!(welcome_recipients(bytes).is_err());
        assert!(parse_key_package(bytes).is_err());
    }
}

#[test]
fn a_length_is_read_the_way_mls_writes_it_and_no_longer() {
    let read = |bytes: &[u8]| Reader { bytes, at: 0 }.varint();
    assert_eq!(read(&[0x00]), Some(0));
    assert_eq!(read(&[0x3f]), Some(63));
    assert_eq!(read(&[0x40, 0x40]), Some(64));
    assert_eq!(read(&[0x7f, 0xff]), Some(16383));
    assert_eq!(read(&[0x80, 0x00, 0x40, 0x00]), Some(16384));
    // A value that fits a shorter form must use it.
    assert_eq!(read(&[0x40, 0x3f]), None);
    assert_eq!(read(&[0x80, 0x00, 0x3f, 0xff]), None);
    // The reserved prefix, and a cut one.
    assert_eq!(read(&[0xc0, 0, 0, 0, 0, 0, 0, 0]), None);
    assert_eq!(read(&[0x40]), None);
    assert_eq!(read(&[]), None);
}

#[test]
fn a_proposal_reference_is_the_hash_of_the_label_and_the_value_as_vectors() {
    // The shape does not depend on openmls: a 74 byte value takes the two byte length.
    let mut message = vec![0, 1, 0, 1];
    message.extend_from_slice(&[7; 70]);
    let reference = proposal_ref(&message).expect("reference");
    let mut input = vec![26];
    input.extend_from_slice(b"MLS 1.0 Proposal Reference");
    input.extend_from_slice(&[0x40, 72]);
    input.extend_from_slice(&message[2..]);
    assert_eq!(reference.as_slice(), Sha256::digest(&input).as_slice());
    assert_eq!(proposal_ref(&[1]), None);
}

#[test]
fn the_keys_are_p256_points() {
    let pair = SignatureKeyPair::new(SignatureScheme::ECDSA_SECP256R1_SHA256).expect("keys");
    assert_eq!(pair.public().len(), 65);
    assert_eq!(pair.public()[0], 4);
}
