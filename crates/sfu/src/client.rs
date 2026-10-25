//! A headless call client on str0m. Tests use it, and tinyclient's `mediad` follows it.
//!
//! 1. [`Client::new`] binds a UDP socket and builds the offer: one `sendonly` audio m-line for
//!    the microphone, one `recvonly` audio m-line per receive slot, one video m-line for the
//!    camera with simulcast rids `h` and `l`, `inactive` until the camera starts, and one
//!    `recvonly` video m-line for the one video slot. [`Client::tcp`] offers one active TCP
//!    candidate instead, and no UDP at all, as on a network that blocks UDP. It connects to
//!    the SFU's passive TCP candidate when str0m first sends to it, and frames each packet
//!    with a 2-byte length (RFC 4571).
//! 2. The offer goes out as `call.join` `sdp`. The `call.answer` `sdp` comes back to
//!    [`Client::accept`]. The client never trickles; the SFU learns its address from STUN.
//! 3. [`Client::start`] drives str0m on its own thread, with no async runtime: a 20 ms Opus
//!    frame out, a camera frame on each layer every 1/30 s while the camera is on, and every
//!    frame in, tagged with the mid it arrived on.
//! 4. `call.slots` says which mid carries whom. The SFU rewrites sequence numbers, but a slot
//!    that changes hands carries a new speaker's timestamps, so reset that slot's jitter
//!    buffer and decoder when its `user_id` changes. The video slot changes hands on a
//!    keyframe; reset the video decoder then.
//! 5. [`Running::camera`] flips the camera m-line and returns the offer for `call.offer`;
//!    [`Running::accept`] takes its answer. A keyframe request from the SFU restarts that
//!    layer at its keyframe.
//!
//! The audio frames are not real Opus. Each one is a TOC byte, a marker byte that says who
//! sent it, and a counter. The SFU never decodes, so it cannot tell. The camera frames are
//! real H.264 constrained baseline from `fixtures/` (see its README), each with an SEI
//! message that says who sent it and on which layer, padded to the layer's nominal bitrate.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use mio::net::{TcpStream, UdpSocket};
use mio::{Events, Interest, Poll, Token, Waker};
use str0m::bwe::Bitrate;
use str0m::change::{SdpAnswer, SdpPendingOffer};
use str0m::media::{Direction, Frequency, MediaKind, MediaTime, Mid, Rid};
use str0m::media::{Simulcast, SimulcastLayer};
use str0m::net::{Protocol, Receive, TcpType};
use str0m::{Candidate, Event, Input, Output, Rtc, RtcConfig};

use crate::tcp::{Conn, Readout};

/// One Opus frame: 20 ms at 48 kHz.
const FRAME: Duration = Duration::from_millis(20);
const SAMPLES_PER_FRAME: u64 = 960;
/// The RFC 6464 level sent with each frame, in -dBov. Loud enough to count as speaking.
const LEVEL: i8 = -20;
/// One camera frame: 30 fps on the 90 kHz video clock.
const VIDEO_FRAME: Duration = Duration::from_nanos(33_333_333);
const TICKS_PER_VIDEO_FRAME: u64 = 3000;
/// The two simulcast layers: a 320×180 and a 160×90 clip, each 10 s of one keyframe and then
/// P frames, padded to 1.2 Mb/s and 350 kb/s.
const LAYERS: [Layer; 2] = [
    Layer {
        rid: "h",
        clip: include_bytes!("../fixtures/camera-h.h264"),
        bytes: 5000,
    },
    Layer {
        rid: "l",
        clip: include_bytes!("../fixtures/camera-l.h264"),
        bytes: 1458,
    },
];
/// Names the SEI message that tags each camera frame. No zero bytes, so it needs no
/// emulation prevention.
const TAG: &[u8; 16] = b"tinyserver-video";
/// A REMB goes out this often while one is set, as browsers send them.
const REMB_EVERY: Duration = Duration::from_secs(1);
const UDP: Token = Token(0);
const WAKE: Token = Token(1);
/// TCP streams take tokens from here up.
const FIRST_STREAM: usize = 2;
/// The discard port, which active TCP candidates advertise (RFC 6544).
const ACTIVE_PORT: u16 = 9;

/// H.264 constrained baseline, level 3.1, packetization mode 1, as the SFU takes it.
const H264_PROFILE: u32 = 0x42e01f;
const H264_PT: u8 = 108;
const H264_RTX_PT: u8 = 109;

/// An audio frame the client received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The receive m-line it came in on. `call.slots` maps it to a person.
    pub mid: String,
    /// The sender's marker byte.
    pub marker: u8,
}

/// A camera frame the client received on its video slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoFrame {
    pub mid: String,
    /// The sender's marker byte, from the frame's SEI tag. 0 if it has none.
    pub marker: u8,
    /// The layer it was sent on, `b'h'` or `b'l'`, from the same tag.
    pub layer: u8,
    pub keyframe: bool,
}

struct Layer {
    rid: &'static str,
    clip: &'static [u8],
    /// Every frame is padded to this size.
    bytes: usize,
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

/// A request from [`Running`] to the client's thread.
enum Request {
    Camera(bool, SyncSender<Result<String, String>>),
    Answer(String, SyncSender<Result<(), String>>),
}

/// A client with an offer out and no answer yet.
pub struct Client {
    rtc: Rtc,
    link: Link,
    /// The local candidate's address. Every packet in is handed to str0m with it.
    local: SocketAddr,
    microphone: Mid,
    camera: Mid,
    screen: Mid,
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
            next: FIRST_STREAM,
        };
        Self::build(link, local, candidate, slots)
    }

    fn build(
        link: Link,
        local: SocketAddr,
        candidate: Result<Candidate, str0m::error::IceError>,
        slots: usize,
    ) -> io::Result<Self> {
        let mut config = RtcConfig::new().clear_codecs().enable_opus(true, false);
        config.codec_config().add_h264(
            H264_PT.into(),
            Some(H264_RTX_PT.into()),
            true,
            H264_PROFILE,
        );
        let mut rtc = config.build(Instant::now());
        let candidate =
            candidate.map_err(|error| io::Error::other(format!("candidate: {error:?}")))?;
        rtc.add_local_candidate(candidate);

        let mut change = rtc.sdp_api();
        let microphone = change.add_media(MediaKind::Audio, Direction::SendOnly, None, None, None);
        for _ in 0..slots {
            change.add_media(MediaKind::Audio, Direction::RecvOnly, None, None, None);
        }
        let mut layers = Simulcast::new();
        for layer in &LAYERS {
            layers.add_send_layer(SimulcastLayer::new(layer.rid));
        }
        let camera = change.add_media(
            MediaKind::Video,
            Direction::Inactive,
            None,
            None,
            Some(layers),
        );
        let screen = change.add_media(MediaKind::Video, Direction::RecvOnly, None, None, None);
        let (offer, pending) = change
            .apply()
            .ok_or_else(|| io::Error::other("nothing to offer"))?;
        Ok(Self {
            rtc,
            link,
            local,
            microphone,
            camera,
            screen,
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
        accept(&mut self.rtc, &mut self.pending, answer)
    }

    /// Runs the call on a thread, sending frames tagged `marker`.
    pub fn start(self, marker: u8) -> io::Result<Running> {
        let shared = Arc::new(Shared::default());
        let poll = Poll::new()?;
        let waker = Arc::new(Waker::new(poll.registry(), WAKE)?);
        let (requests, inbox) = mpsc::sync_channel(4);
        let thread = {
            let shared = shared.clone();
            std::thread::Builder::new()
                .name("headless".to_string())
                .spawn(move || self.run(poll, &inbox, marker, &shared))?
        };
        Ok(Running {
            shared,
            requests,
            waker,
            thread: Some(thread),
        })
    }

    /// The `mediad` loop: drain str0m, answer a request, send a frame when one is due, then
    /// wait for a packet, a request, the next str0m timeout, or the next frame, whichever
    /// comes first. Each packet in is one input, and str0m is drained after every one.
    fn run(mut self, mut poll: Poll, inbox: &Receiver<Request>, marker: u8, shared: &Shared) {
        if let Link::Udp(socket) = &mut self.link {
            if poll
                .registry()
                .register(socket, UDP, Interest::READABLE)
                .is_err()
            {
                return;
            }
        }
        let mut events = Events::with_capacity(64);
        let mut camera = Camera::default();
        let mut next_frame = Instant::now();
        let mut next_video = Instant::now();
        let mut next_remb = Instant::now();
        let mut sent: u64 = 0;
        let mut packets: VecDeque<Packet> = VecDeque::new();
        while !shared.stop.load(Ordering::Acquire) {
            let Some(timeout) = self.drain(shared, &poll, &mut camera) else {
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
            if let Ok(request) = inbox.try_recv() {
                self.answer(request);
                continue;
            }
            let now = Instant::now();
            let connected = shared.connected.load(Ordering::Acquire);
            if connected && shared.sending.load(Ordering::Acquire) && now >= next_frame {
                self.send_frame(marker, sent, now);
                sent += 1;
                next_frame += FRAME;
                continue;
            }
            let camera_on = connected && self.camera_sending();
            if !camera_on {
                camera.on = false;
                next_video = now;
            } else if now >= next_video {
                if !camera.on {
                    // A camera that starts begins each layer at its keyframe.
                    camera = Camera {
                        on: true,
                        ..Camera::default()
                    };
                }
                self.send_video(marker, &mut camera, now);
                next_video += VIDEO_FRAME;
                continue;
            }
            let remb = shared.remb.load(Ordering::Acquire);
            if connected && remb > 0 && now >= next_remb {
                if let Some(stream) = self.rtc.direct_api().stream_rx_by_mid(self.screen, None) {
                    stream.request_remb(Bitrate::kbps(remb));
                }
                next_remb = now + REMB_EVERY;
                continue;
            }
            let mut wake = timeout.min(next_frame.max(now + Duration::from_millis(1)));
            if camera_on {
                wake = wake.min(next_video);
            }
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

    /// Renegotiates for [`Running`]: a new offer with the camera on or off, or its answer.
    fn answer(&mut self, request: Request) {
        match request {
            Request::Camera(on, reply) => {
                let direction = if on {
                    Direction::SendOnly
                } else {
                    Direction::Inactive
                };
                let mut change = self.rtc.sdp_api();
                change.set_direction(self.camera, direction);
                let offer = match change.apply() {
                    Some((offer, pending)) => {
                        self.pending = Some(pending);
                        Ok(offer.to_sdp_string())
                    }
                    None => Err("nothing changed".to_string()),
                };
                let _ = reply.send(offer);
            }
            Request::Answer(answer, reply) => {
                let _ = reply.send(accept(&mut self.rtc, &mut self.pending, &answer));
            }
        }
    }

    fn camera_sending(&self) -> bool {
        self.rtc
            .media(self.camera)
            .is_some_and(|media| media.direction().is_sending())
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
    fn drain(&mut self, shared: &Shared, poll: &Poll, camera: &mut Camera) -> Option<Instant> {
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
                Output::Event(Event::MediaData(data)) if data.mid == self.screen => {
                    let (marker, layer) = tag(&data.data).unwrap_or_default();
                    let frame = VideoFrame {
                        mid: data.mid.to_string(),
                        marker,
                        layer,
                        keyframe: data.is_keyframe(),
                    };
                    lock(&shared.video).push(frame);
                }
                Output::Event(Event::MediaData(data)) => {
                    let marker = data.data.get(1).copied().unwrap_or_default();
                    let frame = Frame {
                        mid: data.mid.to_string(),
                        marker,
                    };
                    lock(&shared.frames).push(frame);
                }
                Output::Event(Event::KeyframeRequest(request)) if request.mid == self.camera => {
                    shared.keyframes_asked.fetch_add(1, Ordering::AcqRel);
                    let rid = request.rid.as_deref();
                    for (at, layer) in LAYERS.iter().enumerate() {
                        if rid.is_none() || rid == Some(layer.rid) {
                            camera.restart[at] = true;
                        }
                    }
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

    /// One frame on each layer, with the same RTP time, as a simulcast encoder sends them.
    fn send_video(&mut self, marker: u8, camera: &mut Camera, now: Instant) {
        let time = MediaTime::new(camera.sent * TICKS_PER_VIDEO_FRAME, Frequency::NINETY_KHZ);
        camera.sent += 1;
        for (at, layer) in LAYERS.iter().enumerate() {
            let frames = &camera.clips[at];
            if camera.restart[at] {
                camera.restart[at] = false;
                camera.next[at] = 0;
            }
            let Some(picture) = frames.get(camera.next[at]) else {
                continue;
            };
            camera.next[at] = (camera.next[at] + 1) % frames.len();
            let frame = tagged(picture, marker, layer);
            let Some(writer) = self.rtc.writer(self.camera) else {
                return;
            };
            let Some(pt) = writer.payload_params().next().map(|params| params.pt()) else {
                return;
            };
            let _ = writer.rid(Rid::from(layer.rid)).write(pt, now, time, frame);
        }
    }
}

/// Where each camera layer is in its clip.
struct Camera {
    on: bool,
    /// Each layer's clip, cut into frames.
    clips: [Vec<Vec<u8>>; 2],
    next: [usize; 2],
    /// Start the layer over at its keyframe before its next frame.
    restart: [bool; 2],
    sent: u64,
}

impl Default for Camera {
    fn default() -> Self {
        Self {
            on: false,
            clips: LAYERS.map(|layer| frames(layer.clip)),
            next: [0; 2],
            restart: [false; 2],
            sent: 0,
        }
    }
}

fn accept(
    rtc: &mut Rtc,
    pending: &mut Option<SdpPendingOffer>,
    answer: &str,
) -> Result<(), String> {
    let answer = SdpAnswer::from_sdp_string(answer).map_err(|error| format!("{error:?}"))?;
    let pending = pending.take().ok_or("no offer pending")?;
    rtc.sdp_api()
        .accept_answer(pending, answer)
        .map_err(|error| format!("{error:?}"))
}

/// Cuts an H.264 Annex B stream into frames: each slice, with the parameter sets before it.
fn frames(clip: &[u8]) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    let mut frame = Vec::new();
    for unit in units(clip) {
        frame.extend_from_slice(&[0, 0, 0, 1]);
        frame.extend_from_slice(unit);
        // NAL types 1 and 5 are slices: a P frame and a keyframe.
        if matches!(unit.first().map(|header| header & 0x1f), Some(1 | 5)) {
            frames.push(std::mem::take(&mut frame));
        }
    }
    frames
}

/// The NAL units of an Annex B stream, without their start codes.
fn units(stream: &[u8]) -> Vec<&[u8]> {
    let mut starts = Vec::new();
    let mut at = 0;
    while let Some(found) = stream
        .get(at..)
        .and_then(|rest| rest.windows(3).position(|window| window == [0, 0, 1]))
    {
        starts.push(at + found + 3);
        at += found + 3;
    }
    starts
        .iter()
        .enumerate()
        .filter_map(|(n, &start)| {
            let end = match starts.get(n + 1) {
                // The next start code, and a fourth zero before it if there is one.
                Some(&next) => {
                    let end = next - 3;
                    if end > start && stream.get(end - 1) == Some(&0) {
                        end - 1
                    } else {
                        end
                    }
                }
                None => stream.len(),
            };
            stream.get(start..end)
        })
        .collect()
}

/// `picture` with an SEI tag in front: user data unregistered (payload type 5) holding
/// [`TAG`], the marker, the layer's rid, and padding up to the layer's frame size.
fn tagged(picture: &[u8], marker: u8, layer: &Layer) -> Vec<u8> {
    // Start code, NAL header, payload type, and trailing bits around the payload and its size.
    let room = layer.bytes.saturating_sub(picture.len() + 4 + 1 + 1 + 1);
    // The size takes one byte, and one more for each 255 of it.
    let length = room.saturating_sub(room / 256 + 1).max(TAG.len() + 2);
    let mut payload = Vec::with_capacity(length);
    payload.extend_from_slice(TAG);
    payload.push(marker);
    payload.push(layer.rid.as_bytes().first().copied().unwrap_or(b'h'));
    // No zero bytes, so no emulation prevention.
    payload.resize(payload.capacity(), 0xaa);
    let mut frame = Vec::with_capacity(layer.bytes + 8);
    frame.extend_from_slice(&[0, 0, 0, 1, 0x06, 0x05]);
    let mut size = payload.len();
    while size >= 255 {
        frame.push(0xff);
        size -= 255;
    }
    frame.push(u8::try_from(size).unwrap_or(0));
    frame.extend_from_slice(&payload);
    frame.push(0x80);
    frame.extend_from_slice(picture);
    frame
}

/// The marker and layer from a frame's SEI tag.
fn tag(frame: &[u8]) -> Option<(u8, u8)> {
    let at = frame.windows(TAG.len()).position(|window| window == TAG)?;
    let marker = *frame.get(at + TAG.len())?;
    let layer = *frame.get(at + TAG.len() + 1)?;
    Some((marker, layer))
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
    /// The REMB to send on the video slot, in kb/s. 0 sends none.
    remb: AtomicU64,
    keyframes_asked: AtomicU64,
    frames: Mutex<Vec<Frame>>,
    video: Mutex<Vec<VideoFrame>>,
}

/// A client in a call. Dropping it stops it.
pub struct Running {
    shared: Arc<Shared>,
    requests: SyncSender<Request>,
    waker: Arc<Waker>,
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

    /// Audio frames received since the last call.
    pub fn take(&self) -> Vec<Frame> {
        std::mem::take(&mut *lock(&self.shared.frames))
    }

    /// Camera frames received since the last call, in order.
    pub fn take_video(&self) -> Vec<VideoFrame> {
        std::mem::take(&mut *lock(&self.shared.video))
    }

    /// Keyframe requests the SFU has sent for the camera.
    pub fn keyframes_asked(&self) -> u64 {
        self.shared.keyframes_asked.load(Ordering::Acquire)
    }

    /// The offer for `call.offer` that turns the camera on or off. The camera sends once
    /// its answer is accepted.
    pub fn camera(&self, on: bool) -> Result<String, String> {
        let (reply, answer) = mpsc::sync_channel(1);
        self.ask(Request::Camera(on, reply))?;
        answer.recv().map_err(|_| "client stopped".to_string())?
    }

    /// Takes the `call.answer` for the last [`Running::camera`] offer.
    pub fn accept(&self, answer: &str) -> Result<(), String> {
        let (reply, done) = mpsc::sync_channel(1);
        self.ask(Request::Answer(answer.to_string(), reply))?;
        done.recv().map_err(|_| "client stopped".to_string())?
    }

    /// Sends a REMB of `kbps` on the video slot every second, as a receiver on a slow link
    /// would. `None` stops.
    pub fn remb(&self, kbps: Option<u64>) {
        self.shared
            .remb
            .store(kbps.unwrap_or_default(), Ordering::Release);
    }

    /// Stops the thread and closes the socket, as a killed process would. Nothing is sent.
    pub fn stop(mut self) {
        self.halt();
    }

    fn ask(&self, request: Request) -> Result<(), String> {
        self.requests
            .send(request)
            .map_err(|_| "client stopped".to_string())?;
        self.waker.wake().map_err(|error| error.to_string())
    }

    fn halt(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        let _ = self.waker.wake();
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

#[cfg(test)]
mod tests {
    use super::{frames, tag, tagged, units, LAYERS};

    #[test]
    fn each_clip_is_one_keyframe_then_p_frames() {
        for layer in &LAYERS {
            let clip = frames(layer.clip);
            assert_eq!(clip.len(), 300, "{}", layer.rid);
            let types = |frame: &[u8]| -> Vec<u8> {
                units(frame)
                    .iter()
                    .filter_map(|unit| unit.first().map(|header| header & 0x1f))
                    .collect()
            };
            // Parameter sets, then the IDR slice.
            assert_eq!(types(&clip[0]), vec![7, 8, 5]);
            assert!(clip[1..].iter().all(|frame| types(frame) == vec![1]));
        }
    }

    #[test]
    fn a_tagged_frame_is_padded_and_says_who_sent_it() {
        let layer = &LAYERS[1];
        let clip = frames(layer.clip);
        let frame = tagged(&clip[3], b'A', layer);
        assert_eq!(frame.len(), layer.bytes);
        assert_eq!(tag(&frame), Some((b'A', b'l')));
        let types: Vec<u8> = units(&frame)
            .iter()
            .filter_map(|unit| unit.first().map(|header| header & 0x1f))
            .collect();
        assert_eq!(types, vec![6, 1]);
    }
}
