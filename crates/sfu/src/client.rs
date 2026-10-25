//! A headless call client on str0m. Tests use it, and tinyclient's `mediad` follows it.
//!
//! 1. [`Client::new`] binds a UDP socket and builds the offer: one `sendonly` audio m-line for
//!    the microphone, then one `recvonly` audio m-line per receive slot.
//! 2. The offer goes out as `call.join` `sdp`. The `call.answer` `sdp` comes back to
//!    [`Client::accept`]. The client never trickles; the SFU learns its address from STUN.
//! 3. [`Client::start`] drives str0m on its own thread, with no async runtime: a 20 ms Opus
//!    frame out, and every frame in, tagged with the mid it arrived on.
//! 4. `call.slots` says which mid carries whom. The SFU rewrites sequence numbers, but a slot
//!    that changes hands carries a new speaker's timestamps, so reset that slot's jitter
//!    buffer and decoder when its `user_id` changes.
//!
//! The frames are not real Opus. Each one is a TOC byte, a marker byte that says who sent it,
//! and a counter. The SFU never decodes, so it cannot tell.

use std::io::{self, ErrorKind};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use str0m::change::{SdpAnswer, SdpPendingOffer};
use str0m::media::{Direction, Frequency, MediaKind, MediaTime, Mid};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, Input, Output, Rtc, RtcConfig};

/// One Opus frame: 20 ms at 48 kHz.
const FRAME: Duration = Duration::from_millis(20);
const SAMPLES_PER_FRAME: u64 = 960;
/// The RFC 6464 level sent with each frame, in -dBov. Loud enough to count as speaking.
const LEVEL: i8 = -20;

/// A frame the client received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The receive m-line it came in on. `call.slots` maps it to a person.
    pub mid: String,
    /// The sender's marker byte.
    pub marker: u8,
}

/// A client with an offer out and no answer yet.
pub struct Client {
    rtc: Rtc,
    socket: UdpSocket,
    local: SocketAddr,
    microphone: Mid,
    pending: Option<SdpPendingOffer>,
    offer: String,
}

impl Client {
    /// Binds `bind` and builds an offer with `slots` receive slots. Use the room cap less one.
    pub fn new(bind: SocketAddr, slots: usize) -> io::Result<Self> {
        let socket = UdpSocket::bind(bind)?;
        let local = socket.local_addr()?;
        let mut rtc = RtcConfig::new()
            .clear_codecs()
            .enable_opus(true, false)
            .build(Instant::now());
        let candidate = Candidate::host(local, "udp")
            .map_err(|error| io::Error::other(format!("candidate: {error:?}")))?;
        rtc.add_local_candidate(candidate);

        let mut change = rtc.sdp_api();
        let microphone = change.add_media(MediaKind::Audio, Direction::SendOnly, None, None, None);
        for _ in 0..slots {
            change.add_media(MediaKind::Audio, Direction::RecvOnly, None, None, None);
        }
        let (offer, pending) = change
            .apply()
            .ok_or_else(|| io::Error::other("nothing to offer"))?;
        Ok(Self {
            rtc,
            socket,
            local,
            microphone,
            pending: Some(pending),
            offer: offer.to_sdp_string(),
        })
    }

    /// The SDP for `call.join`.
    pub fn offer(&self) -> &str {
        &self.offer
    }

    /// Takes the SDP from `call.answer`.
    pub fn accept(&mut self, answer: &str) -> Result<(), String> {
        let answer = SdpAnswer::from_sdp_string(answer).map_err(|error| format!("{error:?}"))?;
        let pending = self.pending.take().ok_or("no offer pending")?;
        self.rtc
            .sdp_api()
            .accept_answer(pending, answer)
            .map_err(|error| format!("{error:?}"))
    }

    /// Runs the call on a thread, sending frames tagged `marker`.
    pub fn start(self, marker: u8) -> io::Result<Running> {
        let shared = Arc::new(Shared::default());
        let thread = {
            let shared = shared.clone();
            std::thread::Builder::new()
                .name("headless".to_string())
                .spawn(move || self.run(marker, &shared))?
        };
        Ok(Running {
            shared,
            thread: Some(thread),
        })
    }

    /// The `mediad` loop: drain str0m, send a frame when one is due, then wait for a packet,
    /// the next str0m timeout, or the next frame, whichever comes first.
    fn run(mut self, marker: u8, shared: &Shared) {
        let mut buf = vec![0; 2000];
        let mut next_frame = Instant::now();
        let mut sent: u64 = 0;
        while !shared.stop.load(Ordering::Acquire) {
            let Some(timeout) = self.drain(shared) else {
                return;
            };
            let now = Instant::now();
            if shared.connected.load(Ordering::Acquire)
                && shared.sending.load(Ordering::Acquire)
                && now >= next_frame
            {
                self.send_frame(marker, sent, now);
                sent += 1;
                next_frame += FRAME;
                continue;
            }
            let wake = timeout.min(next_frame.max(now + Duration::from_millis(1)));
            let wait = wake
                .saturating_duration_since(now)
                .max(Duration::from_millis(1));
            if self.socket.set_read_timeout(Some(wait)).is_err() {
                return;
            }
            let input = match self.socket.recv_from(&mut buf) {
                Ok((n, source)) => {
                    let Some(Ok(contents)) = buf.get(..n).map(TryInto::try_into) else {
                        continue;
                    };
                    Input::Receive(
                        Instant::now(),
                        Receive {
                            proto: Protocol::Udp,
                            source,
                            destination: self.local,
                            contents,
                        },
                    )
                }
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                {
                    Input::Timeout(Instant::now())
                }
                Err(_) => Input::Timeout(Instant::now()),
            };
            if self.rtc.handle_input(input).is_err() {
                return;
            }
        }
    }

    /// Polls str0m until it asks for a timeout. `None` once the connection is over.
    fn drain(&mut self, shared: &Shared) -> Option<Instant> {
        loop {
            if !self.rtc.is_alive() {
                return None;
            }
            match self.rtc.poll_output().ok()? {
                Output::Timeout(at) => return Some(at),
                Output::Transmit(transmit) => {
                    let _ = self
                        .socket
                        .send_to(&transmit.contents, transmit.destination);
                }
                Output::Event(Event::Connected) => shared.connected.store(true, Ordering::Release),
                Output::Event(Event::MediaData(data)) => {
                    let marker = data.data.get(1).copied().unwrap_or_default();
                    let frame = Frame {
                        mid: data.mid.to_string(),
                        marker,
                    };
                    lock(&shared.frames).push(frame);
                }
                Output::Event(_) => {}
            }
        }
    }

    fn send_frame(&mut self, marker: u8, sent: u64, now: Instant) {
        let Some(writer) = self.rtc.writer(self.microphone) else {
            return;
        };
        let Some(pt) = writer.payload_params().next().map(|params| params.pt()) else {
            return;
        };
        // TOC byte 0x78: SILK wideband, 20 ms, one frame.
        let mut payload = vec![0x78, marker];
        payload.extend_from_slice(&sent.to_be_bytes());
        let time = MediaTime::new(sent * SAMPLES_PER_FRAME, Frequency::FORTY_EIGHT_KHZ);
        let _ = writer
            .audio_level(LEVEL, true)
            .write(pt, now, time, payload);
    }
}

#[derive(Default)]
struct Shared {
    stop: AtomicBool,
    connected: AtomicBool,
    sending: AtomicBool,
    frames: Mutex<Vec<Frame>>,
}

/// A client in a call. Dropping it stops it.
pub struct Running {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

impl Running {
    /// ICE and DTLS are up.
    pub fn connected(&self) -> bool {
        self.shared.connected.load(Ordering::Acquire)
    }

    /// Starts or stops the microphone. It starts stopped.
    pub fn sending(&self, on: bool) {
        self.shared.sending.store(on, Ordering::Release);
    }

    /// Frames received since the last call.
    pub fn take(&self) -> Vec<Frame> {
        std::mem::take(&mut *lock(&self.shared.frames))
    }

    /// Stops the thread and closes the socket, as a killed process would. Nothing is sent.
    pub fn stop(mut self) {
        self.halt();
    }

    fn halt(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.halt();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
