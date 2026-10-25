//! The SFU on loopback with headless str0m clients. No database and no live socket: the
//! test plays the API's part.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use sfu::client::{Client, Frame, Running};
use sfu::{Config, Event, Lost, Media, Refused, Slot};
use tokio::sync::mpsc::Receiver;
use tokio::time::{timeout, Instant};

const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;
/// Longer than the consent timeout, so a drop is waited for in one go.
const WAIT: Duration = Duration::from_secs(10);
const SLOTS: usize = 11;

fn config() -> Config {
    let mut config = Config::new(SocketAddr::from((LOOPBACK, 0)), LOOPBACK.into());
    config.connect_timeout = Duration::from_secs(2);
    // A silent str0m client still sends a STUN check or RTCP about every 3 s.
    config.consent_timeout = Duration::from_secs(5);
    config
}

struct Sfu {
    media: Media,
    events: Receiver<Event>,
    /// The latest slot map for each call id, kept while waiting for other events.
    slots: HashMap<String, Vec<Slot>>,
}

impl Drop for Sfu {
    fn drop(&mut self) {
        self.media.shutdown();
    }
}

fn start(config: Config) -> Sfu {
    let (media, events) = sfu::start(config).expect("start the SFU");
    Sfu {
        media,
        events,
        slots: HashMap::new(),
    }
}

impl Sfu {
    /// The next event `pick` returns something for. Others are skipped.
    async fn wait_for<T>(&mut self, mut pick: impl FnMut(&Event) -> Option<T>) -> T {
        let deadline = Instant::now() + WAIT;
        loop {
            let event = timeout(
                deadline.saturating_duration_since(Instant::now()),
                self.events.recv(),
            )
            .await
            .expect("an event in time")
            .expect("SFU running");
            if let Event::Slots { call_id, audio } = &event {
                self.slots.insert(call_id.clone(), audio.clone());
            }
            if let Some(found) = pick(&event) {
                return found;
            }
        }
    }

    /// Waits until `call_id`'s slot map has `want` entries.
    async fn slots_for(&mut self, call_id: &str, want: usize) -> Vec<Slot> {
        if let Some(audio) = self.slots.get(call_id).filter(|audio| audio.len() == want) {
            return audio.clone();
        }
        self.wait_for(|event| match event {
            Event::Slots { call_id: id, audio } if id == call_id && audio.len() == want => {
                Some(audio.clone())
            }
            _ => None,
        })
        .await
    }
}

/// One person in a call: their client and the call id the SFU gave them.
struct Person {
    call_id: String,
    running: Running,
}

async fn join(sfu: &mut Sfu, room_id: &str, user_id: &str, marker: u8) -> Person {
    let mut client = Client::new(SocketAddr::from((LOOPBACK, 0)), SLOTS).expect("client");
    let answer = sfu
        .media
        .join(room_id, user_id, client.offer())
        .await
        .expect("answer");
    client.accept(&answer.sdp).expect("accept the answer");
    let running = client.start(marker).expect("client thread");
    let call_id = answer.call_id.clone();
    sfu.wait_for(|event| {
        matches!(event, Event::Connected { call_id: id } if *id == call_id).then_some(())
    })
    .await;
    Person {
        call_id: answer.call_id,
        running,
    }
}

fn mid_of(slots: &[Slot], user_id: &str) -> String {
    slots
        .iter()
        .find(|slot| slot.user_id == user_id)
        .map(|slot| slot.mid.clone())
        .expect("a slot for that person")
}

/// Waits until `person` has received a frame tagged `marker` on `mid`.
async fn hears(person: &Person, mid: &str, marker: u8) {
    let deadline = Instant::now() + Duration::from_secs(2);
    let want = Frame {
        mid: mid.to_string(),
        marker,
    };
    while Instant::now() < deadline {
        if person.running.take().contains(&want) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no frame from {marker} on mid {mid} within 2 s");
}

/// Frames `person` receives over `period`.
async fn heard_over(person: &Person, period: Duration) -> Vec<Frame> {
    person.running.take();
    tokio::time::sleep(period).await;
    person.running.take()
}

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
