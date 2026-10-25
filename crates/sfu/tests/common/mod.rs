//! The SFU on loopback with headless str0m clients, and the test playing the API's part.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use sfu::client::{Client, Frame, Running};
use sfu::{Config, Event, Media, Slot};
use tokio::sync::mpsc::Receiver;
use tokio::time::{timeout, Instant};

pub const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;
/// Longer than the consent timeout, so a drop is waited for in one go.
pub const WAIT: Duration = Duration::from_secs(10);
pub const SLOTS: usize = 11;

pub fn config() -> Config {
    let mut config = Config::new(SocketAddr::from((LOOPBACK, 0)), LOOPBACK.into());
    config.connect_timeout = Duration::from_secs(2);
    // A silent str0m client still sends a STUN check or RTCP about every 3 s.
    config.consent_timeout = Duration::from_secs(5);
    config
}

pub struct Sfu {
    pub media: Media,
    pub events: Receiver<Event>,
    /// The latest slot map for each call id, kept while waiting for other events.
    pub slots: HashMap<String, Vec<Slot>>,
}

impl Drop for Sfu {
    fn drop(&mut self) {
        self.media.shutdown();
    }
}

pub fn start(config: Config) -> Sfu {
    let (media, events) = sfu::start(config).expect("start the SFU");
    Sfu {
        media,
        events,
        slots: HashMap::new(),
    }
}

impl Sfu {
    /// The next event `pick` returns something for. Others are skipped.
    pub async fn wait_for<T>(&mut self, mut pick: impl FnMut(&Event) -> Option<T>) -> T {
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
    pub async fn slots_for(&mut self, call_id: &str, want: usize) -> Vec<Slot> {
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
pub struct Person {
    pub call_id: String,
    pub running: Running,
}

pub async fn join(sfu: &mut Sfu, room_id: &str, user_id: &str, marker: u8) -> Person {
    let client = Client::new(SocketAddr::from((LOOPBACK, 0)), SLOTS).expect("client");
    join_with(sfu, client, room_id, user_id, marker).await
}

/// Joins with `client`, which may be a TCP one.
pub async fn join_with(
    sfu: &mut Sfu,
    mut client: Client,
    room_id: &str,
    user_id: &str,
    marker: u8,
) -> Person {
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

pub fn mid_of(slots: &[Slot], user_id: &str) -> String {
    slots
        .iter()
        .find(|slot| slot.user_id == user_id)
        .map(|slot| slot.mid.clone())
        .expect("a slot for that person")
}

/// Waits until `person` has received a frame tagged `marker` on `mid`.
pub async fn hears(person: &Person, mid: &str, marker: u8) {
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
pub async fn heard_over(person: &Person, period: Duration) -> Vec<Frame> {
    person.running.take();
    tokio::time::sleep(period).await;
    person.running.take()
}
