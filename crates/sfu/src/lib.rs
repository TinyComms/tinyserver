//! Media plane. One OS thread owns one UDP socket and one `str0m::Rtc` per participant.
//!
//! The API sends [`Media`] commands and reads [`Event`]s. str0m types stay in this crate.
//! RTP stays in memory. Postgres never stores it.

mod engine;
mod limit;
mod room;

#[cfg(feature = "headless")]
pub mod client;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc as async_mpsc, oneshot};

/// Commands waiting for the media thread. A full queue refuses the next one.
const COMMANDS: usize = 1024;
/// Events waiting for the API. A full queue drops `Speaking` and `Load`.
const EVENTS: usize = 1024;

/// Where the media thread listens, what it advertises, and its limits.
#[derive(Debug, Clone)]
pub struct Config {
    /// The UDP socket. Port 0 picks one; tests do that.
    pub bind: SocketAddr,
    /// The address members reach. The advertised port is the one bound.
    pub public_ip: IpAddr,
    /// A participant whose ICE and DTLS are not up by then is dropped.
    pub connect_timeout: Duration,
    /// A connected participant silent for this long is dropped. No packet at all, not even
    /// a STUN consent check.
    pub consent_timeout: Duration,
    /// Audio a publisher may send, in kb/s of payload. Frames over it are not forwarded.
    pub audio_kbps: u32,
    /// Packets one source address may send a second, and the burst above that.
    pub packets_per_second: u32,
    pub packet_burst: u32,
}

impl Config {
    /// The defaults in `docs/calls.md`, on `bind`, advertising `public_ip`.
    pub fn new(bind: SocketAddr, public_ip: IpAddr) -> Self {
        Self {
            bind,
            public_ip,
            connect_timeout: Duration::from_secs(15),
            consent_timeout: Duration::from_secs(30),
            audio_kbps: 64,
            packets_per_second: 500,
            packet_burst: 1000,
        }
    }
}

/// The SFU's reply to a join or an offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// Names this participant until they leave. A rejoin gets a new one.
    pub call_id: String,
    pub sdp: String,
}

/// Why the SFU refused a join or an offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// Not an SDP offer str0m accepts.
    BadSdp,
    /// No such participant. For an offer only.
    NotFound,
    /// The media thread is gone or its queue is full.
    Unavailable,
}

/// Why the SFU dropped a participant on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lost {
    /// ICE and DTLS were not up within `connect_timeout`.
    Timeout,
    /// No packet for `consent_timeout`, a DTLS failure, or ICE gave up.
    Gone,
}

/// One receive slot: the m-line `mid` carries `user_id`'s audio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slot {
    pub mid: String,
    pub user_id: String,
}

/// What the media thread tells the API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// ICE and DTLS are up.
    Connected { call_id: String },
    /// The whole slot map for one listener. Sent on every change.
    Slots { call_id: String, audio: Vec<Slot> },
    /// Who is speaking in a room. Sent when it changes, at most 4 times a second.
    Speaking {
        room_id: String,
        user_ids: Vec<String>,
    },
    /// The SFU dropped a participant. A `leave` from the API sends nothing.
    Left { call_id: String, lost: Lost },
    /// Every 5 s.
    Load {
        egress_kbps: u64,
        participants: usize,
    },
}

pub(crate) type Reply = oneshot::Sender<Result<Answer, Refused>>;

pub(crate) enum Command {
    Join {
        room_id: String,
        user_id: String,
        offer: String,
        reply: Reply,
    },
    Offer {
        call_id: String,
        offer: String,
        reply: Reply,
    },
    State {
        call_id: String,
        muted: bool,
        deafened: bool,
    },
    Leave {
        call_id: String,
    },
    Shutdown,
}

/// A handle on the media thread. Cheap to clone.
#[derive(Clone)]
pub struct Media {
    commands: SyncSender<Command>,
    waker: Arc<mio::Waker>,
    alive: Arc<AtomicBool>,
    addr: SocketAddr,
}

/// Binds the socket and starts the media thread.
pub fn start(config: Config) -> io::Result<(Media, async_mpsc::Receiver<Event>)> {
    let (commands, inbox) = mpsc::sync_channel(COMMANDS);
    let (events, outbox) = async_mpsc::channel(EVENTS);
    let alive = Arc::new(AtomicBool::new(true));
    let (engine, waker) = engine::Engine::bind(config, inbox, events, alive.clone())?;
    let addr = engine.advertised();
    std::thread::Builder::new()
        .name("sfu".to_string())
        .spawn(move || engine.run())?;
    let media = Media {
        commands,
        waker: Arc::new(waker),
        alive,
        addr,
    };
    Ok((media, outbox))
}

impl Media {
    /// The address and port in every answer's candidate.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// False once the media thread has stopped.
    pub fn running(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    /// Adds `user_id` to `room_id` with `offer`, replacing any participant they already are.
    pub async fn join(&self, room_id: &str, user_id: &str, offer: &str) -> Result<Answer, Refused> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::Join {
            room_id: room_id.to_string(),
            user_id: user_id.to_string(),
            offer: offer.to_string(),
            reply,
        })?;
        answer.await.unwrap_or(Err(Refused::Unavailable))
    }

    /// Renegotiates with a new offer from the same participant.
    pub async fn offer(&self, call_id: &str, offer: &str) -> Result<Answer, Refused> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::Offer {
            call_id: call_id.to_string(),
            offer: offer.to_string(),
            reply,
        })?;
        answer.await.unwrap_or(Err(Refused::Unavailable))
    }

    /// A muted publisher is not forwarded. A deafened listener is not sent anything.
    pub fn state(&self, call_id: &str, muted: bool, deafened: bool) {
        let _ = self.send(Command::State {
            call_id: call_id.to_string(),
            muted,
            deafened,
        });
    }

    /// Drops a participant. No `Left` follows.
    pub fn leave(&self, call_id: &str) {
        let _ = self.send(Command::Leave {
            call_id: call_id.to_string(),
        });
    }

    /// Ends every call and stops the thread.
    pub fn shutdown(&self) {
        let _ = self.send(Command::Shutdown);
    }

    fn send(&self, command: Command) -> Result<(), Refused> {
        match self.commands.try_send(command) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                tracing::warn!("media command queue full");
                return Err(Refused::Unavailable);
            }
            Err(TrySendError::Disconnected(_)) => return Err(Refused::Unavailable),
        }
        if let Err(error) = self.waker.wake() {
            tracing::warn!(%error, "media thread wake failed");
        }
        Ok(())
    }
}
