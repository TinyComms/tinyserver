//! A headless call client on str0m. Tests use it, and tinyclient's `mediad` follows it.
//!
//! 1. [`Client::new`] binds a UDP socket and builds the offer: one `sendonly` audio m-line for
//!    the microphone, then one `recvonly` audio m-line per receive slot. [`Client::tcp`]
//!    offers one active TCP candidate instead, and no UDP at all, as on a network that blocks
//!    UDP. It connects to the SFU's passive TCP candidate when str0m first sends to it, and
//!    frames each packet with a 2-byte length (RFC 4571).
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

use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use mio::net::{TcpStream, UdpSocket};
use mio::{Events, Interest, Poll, Token};
use str0m::change::{SdpAnswer, SdpPendingOffer};
use str0m::media::{Direction, Frequency, MediaKind, MediaTime, Mid};
use str0m::net::{Protocol, Receive, TcpType};
use str0m::{Candidate, Event, Input, Output, Rtc, RtcConfig};

use crate::tcp::{Conn, Readout};

/// One Opus frame: 20 ms at 48 kHz.
const FRAME: Duration = Duration::from_millis(20);
const SAMPLES_PER_FRAME: u64 = 960;
/// The RFC 6464 level sent with each frame, in -dBov. Loud enough to count as speaking.
const LEVEL: i8 = -20;
const UDP: Token = Token(0);
/// The discard port, which active TCP candidates advertise (RFC 6544).
const ACTIVE_PORT: u16 = 9;

/// A frame the client received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The receive m-line it came in on. `call.slots` maps it to a person.
    pub mid: String,
    /// The sender's marker byte.
    pub marker: u8,
}

/// How the client reaches the SFU.
enum Link {
    Udp(UdpSocket),
    /// One stream per SFU TCP candidate str0m sends to, opened on first use.
    Tcp {
        streams: HashMap<SocketAddr, (Token, Conn)>,
        next: usize,
    },
}

/// A client with an offer out and no answer yet.
pub struct Client {
    rtc: Rtc,
    link: Link,
    /// The local candidate's address. Every packet in is handed to str0m with it.
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
        let candidate = Candidate::host(local, "udp");
        Self::build(Link::Udp(socket), local, candidate, slots)
    }

    /// Like [`Client::new`], with one active TCP candidate on `ip` and no UDP.
    pub fn tcp(ip: IpAddr, slots: usize) -> io::Result<Self> {
        let local = SocketAddr::new(ip, ACTIVE_PORT);
        let candidate = Candidate::builder()
            .tcp()
            .host(local)
            .tcptype(TcpType::Active)
            .build();
        let link = Link::Tcp {
            streams: HashMap::new(),
            next: 1,
        };
        Self::build(link, local, candidate, slots)
    }

    fn build(
        link: Link,
        local: SocketAddr,
        candidate: Result<Candidate, str0m::error::IceError>,
        slots: usize,
    ) -> io::Result<Self> {
        let mut rtc = RtcConfig::new()
            .clear_codecs()
            .enable_opus(true, false)
            .build(Instant::now());
        let candidate =
            candidate.map_err(|error| io::Error::other(format!("candidate: {error:?}")))?;
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
            link,
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
    /// the next str0m timeout, or the next frame, whichever comes first. Each packet in is
    /// one input, and str0m is drained after every one.
    fn run(mut self, marker: u8, shared: &Shared) {
        let Ok(poll) = Poll::new() else {
            return;
        };
        if let Link::Udp(socket) = &mut self.link {
            if poll
                .registry()
                .register(socket, UDP, Interest::READABLE)
                .is_err()
            {
                return;
            }
        }
        let mut poll = poll;
        let mut events = Events::with_capacity(64);
        let mut next_frame = Instant::now();
        let mut sent: u64 = 0;
        let mut packets: VecDeque<Packet> = VecDeque::new();
        while !shared.stop.load(Ordering::Acquire) {
            let Some(timeout) = self.drain(shared, &poll) else {
                return;
            };
            if let Some((proto, source, packet)) = packets.pop_front() {
                if let Some(input) = input(proto, source, self.local, packet.as_slice()) {
                    if self.rtc.handle_input(input).is_err() {
                        return;
                    }
                }
                continue;
            }
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
            if let Err(error) = poll.poll(&mut events, Some(wait)) {
                if error.kind() != ErrorKind::Interrupted {
                    return;
                }
            }
            for event in &events {
                self.receive(event.token(), event.is_writable(), &mut packets);
            }
            if packets.is_empty()
                && self
                    .rtc
                    .handle_input(Input::Timeout(Instant::now()))
                    .is_err()
            {
                return;
            }
        }
    }

    /// Reads what `token` has waiting into `packets`, and flushes a writable stream.
    fn receive(&mut self, token: Token, writable: bool, packets: &mut VecDeque<Packet>) {
        match &mut self.link {
            Link::Udp(socket) => {
                let mut buf = vec![0; 2000];
                while let Ok((n, source)) = socket.recv_from(&mut buf) {
                    if let Some(packet) = buf.get(..n) {
                        packets.push_back((Protocol::Udp, source, packet.to_vec()));
                    }
                }
            }
            Link::Tcp { streams, .. } => {
                let Some((&server, (_, conn))) =
                    streams.iter_mut().find(|(_, (held, _))| *held == token)
                else {
                    return;
                };
                if writable && conn.flush().is_err() {
                    streams.remove(&server);
                    return;
                }
                let end = conn.read(usize::MAX, |frame| {
                    packets.push_back((Protocol::Tcp, server, frame.to_vec()));
                    true
                });
                if end == Readout::Closed {
                    streams.remove(&server);
                }
            }
        }
    }

    /// Sends one packet. Over TCP, the first one to an address opens the stream.
    fn transmit(&mut self, poll: &Poll, proto: Protocol, to: SocketAddr, packet: &[u8]) {
        match &mut self.link {
            Link::Udp(socket) if proto == Protocol::Udp => {
                let _ = socket.send_to(packet, to);
            }
            Link::Tcp { streams, next } if proto == Protocol::Tcp => {
                let (_, conn) = match streams.entry(to) {
                    Entry::Occupied(held) => held.into_mut(),
                    Entry::Vacant(free) => {
                        let Ok(mut socket) = TcpStream::connect(to) else {
                            return;
                        };
                        let _ = socket.set_nodelay(true);
                        let token = Token(*next);
                        *next += 1;
                        let interest = Interest::READABLE | Interest::WRITABLE;
                        if poll
                            .registry()
                            .register(&mut socket, token, interest)
                            .is_err()
                        {
                            return;
                        }
                        free.insert((token, Conn::new(socket, to)))
                    }
                };
                if conn.queue(packet) && conn.flush().is_err() {
                    streams.remove(&to);
                }
            }
            _ => {}
        }
    }

    /// Polls str0m until it asks for a timeout. `None` once the connection is over.
    fn drain(&mut self, shared: &Shared, poll: &Poll) -> Option<Instant> {
        loop {
            if !self.rtc.is_alive() {
                return None;
            }
            match self.rtc.poll_output().ok()? {
                Output::Timeout(at) => return Some(at),
                Output::Transmit(transmit) => {
                    let (proto, to) = (transmit.proto, transmit.destination);
                    self.transmit(poll, proto, to, &transmit.contents);
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

/// A packet read and not yet handed to str0m.
type Packet = (Protocol, SocketAddr, Vec<u8>);

/// A packet as str0m input, with `local` as its destination.
fn input(
    proto: Protocol,
    source: SocketAddr,
    local: SocketAddr,
    packet: &[u8],
) -> Option<Input<'_>> {
    let contents = packet.try_into().ok()?;
    Some(Input::Receive(
        Instant::now(),
        Receive {
            proto,
            source,
            destination: local,
            contents,
        },
    ))
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
