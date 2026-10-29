//! The SFU on loopback with headless str0m clients. No database and no live socket: the
//! test plays the API's part.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::*;
use sfu::client::Client;
use sfu::{Event, Lost, Refused};
use tokio::time::Instant;

#[tokio::test]
async fn two_peers_hear_each_other_and_another_room_hears_neither() {
    let mut sfu = start(config());
    let a = join(&mut sfu, "r", "a", b'A').await;
    let b = join(&mut sfu, "r", "b", b'B').await;
    let c = join(&mut sfu, "s", "c", b'C').await;
    let a_slots = sfu.slots_for(&a.call_id, 1).await;
    let b_slots = sfu.slots_for(&b.call_id, 1).await;
    assert_eq!(a_slots[0].user_id, "b");
    assert_eq!(b_slots[0].user_id, "a");

    for person in [&a, &b, &c] {
        person.running.sending(true);
    }
    hears(&b, &mid_of(&b_slots, "a"), b'A').await;
    hears(&a, &mid_of(&a_slots, "b"), b'B').await;
    let at_c = heard_over(&c, Duration::from_millis(500)).await;
    assert!(at_c.is_empty(), "another room heard {at_c:?}");
    let at_b = heard_over(&b, Duration::from_millis(300)).await;
    assert!(at_b.iter().all(|frame| frame.marker == b'A'), "{at_b:?}");
}

#[tokio::test]
async fn leaving_stops_forwarding_and_frees_the_slot() {
    let mut sfu = start(config());
    let a = join(&mut sfu, "r", "a", b'A').await;
    let b = join(&mut sfu, "r", "b", b'B').await;
    let b_slots = sfu.slots_for(&b.call_id, 1).await;
    a.running.sending(true);
    hears(&b, &mid_of(&b_slots, "a"), b'A').await;

    sfu.media.leave(&a.call_id);
    sfu.slots_for(&b.call_id, 0).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let after = heard_over(&b, Duration::from_millis(400)).await;
    assert!(after.is_empty(), "still forwarded: {after:?}");
}

#[tokio::test]
async fn a_muted_publisher_is_not_forwarded() {
    let mut sfu = start(config());
    let a = join(&mut sfu, "r", "a", b'A').await;
    let b = join(&mut sfu, "r", "b", b'B').await;
    let b_slots = sfu.slots_for(&b.call_id, 1).await;
    a.running.sending(true);
    hears(&b, &mid_of(&b_slots, "a"), b'A').await;

    sfu.media.state(&a.call_id, true, false);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let muted = heard_over(&b, Duration::from_millis(400)).await;
    assert!(muted.is_empty(), "muted but forwarded: {muted:?}");
    sfu.media.state(&a.call_id, false, false);
    hears(&b, &mid_of(&b_slots, "a"), b'A').await;
}

#[tokio::test]
async fn a_server_muted_publisher_is_not_forwarded_and_a_server_deafened_listener_hears_nothing() {
    let mut sfu = start(config());
    let a = join(&mut sfu, "r", "a", b'A').await;
    let b = join(&mut sfu, "r", "b", b'B').await;
    let a_slots = sfu.slots_for(&a.call_id, 1).await;
    let b_slots = sfu.slots_for(&b.call_id, 1).await;
    a.running.sending(true);
    b.running.sending(true);
    hears(&b, &mid_of(&b_slots, "a"), b'A').await;

    // Server mute: the client still sends and thinks it is unmuted.
    sfu.media.moderate(&a.call_id, true, false);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let silenced = heard_over(&b, Duration::from_millis(400)).await;
    assert!(
        silenced.is_empty(),
        "server muted but forwarded: {silenced:?}"
    );
    // a still hears b.
    hears(&a, &mid_of(&a_slots, "b"), b'B').await;

    // Server deafen on a: b's audio stops reaching a, a's own (now unmuted) audio flows.
    sfu.media.moderate(&a.call_id, false, true);
    hears(&b, &mid_of(&b_slots, "a"), b'A').await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let hushed = heard_over(&a, Duration::from_millis(400)).await;
    assert!(
        hushed.is_empty(),
        "server deafened but sent audio: {hushed:?}"
    );

    sfu.media.moderate(&a.call_id, false, false);
    hears(&a, &mid_of(&a_slots, "b"), b'B').await;
}

#[tokio::test]
async fn a_killed_peer_is_dropped_after_the_consent_timeout() {
    let mut sfu = start(config());
    let a = join(&mut sfu, "r", "a", b'A').await;
    let b = join(&mut sfu, "r", "b", b'B').await;
    sfu.slots_for(&b.call_id, 1).await;

    let started = Instant::now();
    let call_id = a.call_id.clone();
    a.running.stop();
    let lost = sfu
        .wait_for(|event| match event {
            Event::Left { call_id: id, lost } if *id == call_id => Some(*lost),
            _ => None,
        })
        .await;
    assert_eq!(lost, Lost::Gone);
    // The last packet may predate `started` by a frame or two.
    assert!(started.elapsed() >= Duration::from_millis(4500));
    sfu.slots_for(&b.call_id, 0).await;
}

#[tokio::test]
async fn a_participant_that_never_connects_is_dropped() {
    let mut sfu = start(config());
    let client = Client::new(SocketAddr::from((LOOPBACK, 0)), SLOTS).expect("client");
    let answer = sfu
        .media
        .join("r", "a", client.offer())
        .await
        .expect("answer");
    let lost = sfu
        .wait_for(|event| match event {
            Event::Left { call_id, lost } if *call_id == answer.call_id => Some(*lost),
            _ => None,
        })
        .await;
    assert_eq!(lost, Lost::Timeout);
}

#[tokio::test]
async fn a_rejoin_replaces_the_first_participant_without_a_left() {
    let mut sfu = start(config());
    let first = join(&mut sfu, "r", "a", b'A').await;
    let b = join(&mut sfu, "r", "b", b'B').await;
    sfu.slots_for(&b.call_id, 1).await;
    let second = join(&mut sfu, "r", "a", b'Z').await;
    assert_ne!(first.call_id, second.call_id);
    let b_slots = sfu.slots_for(&b.call_id, 1).await;
    second.running.sending(true);
    hears(&b, &mid_of(&b_slots, "a"), b'Z').await;
    assert_eq!(
        sfu.media.offer(&first.call_id, "v=0").await,
        Err(Refused::NotFound)
    );
}

#[tokio::test]
async fn speaking_names_the_loud_publisher() {
    let mut sfu = start(config());
    let a = join(&mut sfu, "r", "a", b'A').await;
    let _b = join(&mut sfu, "r", "b", b'B').await;
    a.running.sending(true);
    sfu.wait_for(|event| match event {
        Event::Speaking { room_id, user_ids } if room_id == "r" && user_ids == &["a"] => Some(()),
        _ => None,
    })
    .await;
    a.running.sending(false);
    sfu.wait_for(|event| match event {
        Event::Speaking { room_id, user_ids } if room_id == "r" && user_ids.is_empty() => Some(()),
        _ => None,
    })
    .await;
}

#[tokio::test]
async fn an_offer_that_is_not_sdp_is_refused() {
    let sfu = start(config());
    assert_eq!(
        sfu.media.join("r", "a", "not sdp").await,
        Err(Refused::BadSdp)
    );
    assert!(sfu.media.addr().port() != 0);
    assert!(sfu.media.running());
}

/// An app that encrypts end to end sends a frame the SFU cannot read: AES-GCM ciphertext with a
/// truncated tag, a nonce, and DAVE's 0xFAFA marker, in place of Opus. The SFU forwards it byte
/// for byte, and still finds the speaker from the RFC 6464 level, which stays in the clear.
#[tokio::test]
async fn an_end_to_end_encrypted_frame_is_forwarded_byte_for_byte() {
    let mut sfu = start(config());
    let a = join(&mut sfu, "r", "a", b'A').await;
    let b = join(&mut sfu, "r", "b", b'B').await;
    let b_slots = sfu.slots_for(&b.call_id, 1).await;
    let mid = mid_of(&b_slots, "a");

    // What only the apps could read. It never leaves them.
    let plain: &[u8] = b"opus: the words only the people in the call hear";
    // What goes on the wire: bytes that look random, then the tag, nonce and marker.
    let mut sealed: Vec<u8> = (0..plain.len() as u32)
        .map(|n| (n.wrapping_mul(2_654_435_761) >> 13) as u8 ^ 0x5a)
        .collect();
    sealed.extend_from_slice(&[0x9c, 0x31, 0x7e, 0x02, 0xd4, 0x88, 0x1b, 0x6f]);
    sealed.extend_from_slice(&[0x07, 0x0b, 0xfa, 0xfa]);
    assert!(!sealed.windows(plain.len()).any(|window| window == plain));

    a.running.send_payload(Some(sealed.clone()));
    a.running.sending(true);
    sfu.wait_for(|event| match event {
        Event::Speaking { room_id, user_ids } if room_id == "r" && user_ids == &["a"] => Some(()),
        _ => None,
    })
    .await;
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut heard = Vec::new();
    while heard.len() < 10 {
        assert!(
            Instant::now() < deadline,
            "only {} frames came",
            heard.len()
        );
        heard.extend(
            b.running
                .take_payloads()
                .into_iter()
                .filter(|(on, _)| *on == mid)
                .map(|(_, payload)| payload),
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    for payload in &heard {
        assert_eq!(payload, &sealed, "forwarded as it was sent");
        assert!(!payload.windows(plain.len()).any(|window| window == plain));
    }
}
