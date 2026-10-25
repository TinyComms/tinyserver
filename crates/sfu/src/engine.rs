//! The media thread: one `mio` loop over the UDP socket and a waker for commands.
//!
//! Every `Rtc` is driven the way str0m requires: one input, then `poll_output` until it
//! returns a timeout. Audio frames are copied from each publisher to everyone else in the
//! room, on the receive slot that listener keeps for them.

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasher, Hasher};
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Token, Waker};
use str0m::change::SdpOffer;
use str0m::config::{CryptoProvider, DtlsCert};
use str0m::media::{Direction, MediaData, MediaKind, Mid};
use str0m::net::{DatagramRecv, Protocol, Receive};
use str0m::{Candidate, Event as RtcEvent, Input, Output, Rtc, RtcConfig};
use tokio::sync::mpsc as async_mpsc;

use crate::limit::Bucket;
use crate::room::{Announced, Slots, Speech};
use crate::{Answer, Command, Config, Event, Lost, Refused, Reply, Slot};

const SOCKET: Token = Token(0);
const WAKE: Token = Token(1);
/// The loop wakes at least this often.
const TICK: Duration = Duration::from_millis(50);
/// Larger than any datagram str0m sends or accepts.
const DATAGRAM: usize = 2000;
/// Source addresses with a packet budget. A new source past this is dropped.
const SOURCES: usize = 4096;
/// A source silent this long loses its budget entry.
const SOURCE_IDLE: Duration = Duration::from_secs(10);
const LOAD_EVERY: Duration = Duration::from_secs(5);

type PeerId = u64;

struct Peer {
    call_id: String,
    room_id: String,
    user_id: String,
    rtc: Rtc,
    /// The client's microphone m-line.
    publish: Option<Mid>,
    slots: Slots<Mid, PeerId>,
    /// Receive m-lines were added since the slots were last filled.
    new_slots: bool,
    /// The last slot map sent for this listener.
    told: Vec<Slot>,
    connected: bool,
    joined_at: Instant,
    heard_at: Instant,
    muted: bool,
    deafened: bool,
    speech: Speech,
    audio: Bucket,
    timeout: Instant,
    lost: Option<Lost>,
}

#[derive(Default)]
struct Room {
    /// In join order.
    members: Vec<PeerId>,
    announced: Announced,
}

/// Where a drained `Rtc` puts what it produced.
struct Sink<'a> {
    socket: &'a UdpSocket,
    events: &'a async_mpsc::Sender<Event>,
    egress: &'a mut u64,
    forward: &'a mut VecDeque<(PeerId, MediaData)>,
}

pub(crate) struct Engine {
    config: Config,
    poll: Poll,
    socket: UdpSocket,
    public: SocketAddr,
    inbox: Receiver<Command>,
    events: async_mpsc::Sender<Event>,
    alive: Arc<AtomicBool>,
    crypto: Arc<CryptoProvider>,
    cert: DtlsCert,
    peers: HashMap<PeerId, Peer>,
    by_call: HashMap<String, PeerId>,
    by_addr: HashMap<SocketAddr, PeerId>,
    sources: HashMap<SocketAddr, Bucket>,
    rooms: HashMap<String, Room>,
    forward: VecDeque<(PeerId, MediaData)>,
    next_id: u64,
    ids: RandomState,
    egress: u64,
    load_at: Instant,
    swept_at: Instant,
}

/// Marks the thread stopped however it ends, a panic included.
struct Running(Arc<AtomicBool>);

impl Drop for Running {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl Engine {
    pub fn bind(
        config: Config,
        inbox: Receiver<Command>,
        events: async_mpsc::Sender<Event>,
        alive: Arc<AtomicBool>,
    ) -> io::Result<(Self, Waker)> {
        let std_socket = std::net::UdpSocket::bind(config.bind)?;
        std_socket.set_nonblocking(true)?;
        let port = std_socket.local_addr()?.port();
        let mut socket = UdpSocket::from_std(std_socket);
        let poll = Poll::new()?;
        poll.registry()
            .register(&mut socket, SOCKET, Interest::READABLE)?;
        let waker = Waker::new(poll.registry(), WAKE)?;
        let crypto = Arc::new(str0m::crypto::from_feature_flags());
        let cert = crypto
            .dtls_provider
            .generate_certificate()
            .ok_or_else(|| io::Error::other("no DTLS certificate"))?;
        let now = Instant::now();
        let engine = Self {
            public: SocketAddr::new(config.public_ip, port),
            config,
            poll,
            socket,
            inbox,
            events,
            alive,
            crypto,
            cert,
            peers: HashMap::new(),
            by_call: HashMap::new(),
            by_addr: HashMap::new(),
            sources: HashMap::new(),
            rooms: HashMap::new(),
            forward: VecDeque::new(),
            next_id: 0,
            ids: RandomState::new(),
            egress: 0,
            load_at: now,
            swept_at: now,
        };
        Ok((engine, waker))
    }

    pub fn advertised(&self) -> SocketAddr {
        self.public
    }

    pub fn run(mut self) {
        let _running = Running(self.alive.clone());
        tracing::info!(addr = %self.public, "media listening");
        let mut events = Events::with_capacity(64);
        let mut buf = vec![0; DATAGRAM];
        loop {
            let wait = self
                .deadline()
                .saturating_duration_since(Instant::now())
                .min(TICK);
            if let Err(error) = self.poll.poll(&mut events, Some(wait)) {
                if error.kind() != ErrorKind::Interrupted {
                    tracing::error!(%error, "media poll failed");
                    return;
                }
            }
            if !self.commands() {
                tracing::info!("media stopped");
                return;
            }
            self.read(&mut buf);
            self.tick(Instant::now());
        }
    }

    /// The earliest `Rtc` timeout.
    fn deadline(&self) -> Instant {
        let later = Instant::now() + TICK;
        self.peers
            .values()
            .map(|peer| peer.timeout)
            .min()
            .map_or(later, |soonest| soonest.min(later))
    }

    /// Runs every queued command. False on `Shutdown` or once every handle is gone.
    fn commands(&mut self) -> bool {
        loop {
            let command = match self.inbox.try_recv() {
                Ok(command) => command,
                Err(TryRecvError::Empty) => return true,
                Err(TryRecvError::Disconnected) => return false,
            };
            let now = Instant::now();
            match command {
                Command::Join {
                    room_id,
                    user_id,
                    offer,
                    reply,
                } => self.join(room_id, user_id, &offer, reply, now),
                Command::Offer {
                    call_id,
                    offer,
                    reply,
                } => self.renegotiate(&call_id, &offer, reply),
                Command::State {
                    call_id,
                    muted,
                    deafened,
                } => {
                    if let Some(peer) = self.peer_mut(&call_id) {
                        peer.muted = muted;
                        peer.deafened = deafened;
                        if muted {
                            peer.speech.hush();
                        }
                    }
                }
                Command::Leave { call_id } => {
                    if let Some(id) = self.by_call.get(&call_id).copied() {
                        self.remove(id, None);
                    }
                }
                Command::Shutdown => return false,
            }
        }
    }

    fn join(&mut self, room_id: String, user_id: String, offer: &str, reply: Reply, now: Instant) {
        let Ok(offer) = SdpOffer::from_sdp_string(offer) else {
            let _ = reply.send(Err(Refused::BadSdp));
            return;
        };
        let replaced: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.user_id == user_id)
            .map(|(id, _)| *id)
            .collect();
        for id in replaced {
            self.remove(id, None);
        }
        let mut rtc = RtcConfig::new()
            .set_ice_lite(true)
            .set_crypto_provider(self.crypto.clone())
            .set_dtls_cert(self.cert.clone())
            .clear_codecs()
            .enable_opus(true, false)
            .build(now);
        match Candidate::host(self.public, "udp") {
            Ok(candidate) => {
                rtc.add_local_candidate(candidate);
            }
            Err(error) => {
                tracing::error!(?error, "media candidate refused");
                let _ = reply.send(Err(Refused::Unavailable));
                return;
            }
        }
        let answer = match rtc.sdp_api().accept_offer(offer) {
            Ok(answer) => answer,
            Err(error) => {
                tracing::info!(?error, "offer refused");
                let _ = reply.send(Err(Refused::BadSdp));
                return;
            }
        };
        self.next_id += 1;
        let id = self.next_id;
        let call_id = self.call_id();
        let rate = self.config.audio_kbps.saturating_mul(1000) / 8;
        let peer = Peer {
            call_id: call_id.clone(),
            room_id: room_id.clone(),
            user_id,
            rtc,
            publish: None,
            slots: Slots::new(),
            new_slots: false,
            told: Vec::new(),
            connected: false,
            joined_at: now,
            heard_at: now,
            muted: false,
            deafened: false,
            speech: Speech::new(),
            audio: Bucket::new(rate, rate, now),
            timeout: now,
            lost: None,
        };
        self.peers.insert(id, peer);
        self.by_call.insert(call_id.clone(), id);
        self.rooms.entry(room_id).or_default().members.push(id);
        self.drain(id);
        self.seat(id);
        self.settle();
        tracing::info!(%call_id, "media joined");
        let _ = reply.send(Ok(Answer {
            call_id,
            sdp: answer.to_sdp_string(),
        }));
    }

    fn renegotiate(&mut self, call_id: &str, offer: &str, reply: Reply) {
        let Some(id) = self.by_call.get(call_id).copied() else {
            let _ = reply.send(Err(Refused::NotFound));
            return;
        };
        let Ok(offer) = SdpOffer::from_sdp_string(offer) else {
            let _ = reply.send(Err(Refused::BadSdp));
            return;
        };
        let Some(peer) = self.peers.get_mut(&id) else {
            let _ = reply.send(Err(Refused::NotFound));
            return;
        };
        let answer = match peer.rtc.sdp_api().accept_offer(offer) {
            Ok(answer) => answer,
            Err(error) => {
                tracing::info!(?error, "offer refused");
                let _ = reply.send(Err(Refused::BadSdp));
                return;
            }
        };
        self.drain(id);
        self.settle();
        let _ = reply.send(Ok(Answer {
            call_id: call_id.to_string(),
            sdp: answer.to_sdp_string(),
        }));
    }

    /// Gives `id` a slot with every other member of its room, and them one with it.
    fn seat(&mut self, id: PeerId) {
        let Some(room_id) = self.peers.get(&id).map(|peer| peer.room_id.clone()) else {
            return;
        };
        let members = self.members(&room_id);
        for other in members.iter().copied().filter(|other| *other != id) {
            if let Some(peer) = self.peers.get_mut(&other) {
                peer.slots.assign(id);
            }
            if let Some(peer) = self.peers.get_mut(&id) {
                peer.slots.assign(other);
            }
        }
        for member in members {
            self.tell_slots(member);
        }
    }

    /// Takes `id` out of its room and frees its slots. `lost` is told to the API; a leave
    /// the API asked for is not.
    fn remove(&mut self, id: PeerId, lost: Option<Lost>) {
        let Some(mut peer) = self.peers.remove(&id) else {
            return;
        };
        peer.rtc.disconnect();
        self.by_call.remove(&peer.call_id);
        self.by_addr.retain(|_, owner| *owner != id);
        self.forward.retain(|(origin, _)| *origin != id);
        if let Some(lost) = lost {
            tracing::info!(call_id = %peer.call_id, ?lost, "media lost");
            tell(
                &self.events,
                Event::Left {
                    call_id: peer.call_id.clone(),
                    lost,
                },
            );
        }
        let members = match self.rooms.get_mut(&peer.room_id) {
            Some(room) => {
                room.members.retain(|member| *member != id);
                room.members.clone()
            }
            None => Vec::new(),
        };
        if members.is_empty() {
            self.rooms.remove(&peer.room_id);
        }
        for member in members {
            let freed = self
                .peers
                .get_mut(&member)
                .is_some_and(|other| other.slots.release(&id));
            if freed {
                self.reseat(member);
                self.tell_slots(member);
            }
        }
    }

    /// Fills `id`'s free slots with members who have none, as after someone left a full room.
    fn reseat(&mut self, id: PeerId) {
        let Some(room_id) = self.peers.get(&id).map(|peer| peer.room_id.clone()) else {
            return;
        };
        for other in self.members(&room_id) {
            if other == id {
                continue;
            }
            if let Some(peer) = self.peers.get_mut(&id) {
                peer.slots.assign(other);
            }
        }
    }

    fn members(&self, room_id: &str) -> Vec<PeerId> {
        self.rooms
            .get(room_id)
            .map(|room| room.members.clone())
            .unwrap_or_default()
    }

    /// Sends `id`'s slot map if it changed.
    fn tell_slots(&mut self, id: PeerId) {
        let Some(peer) = self.peers.get(&id) else {
            return;
        };
        let audio: Vec<Slot> = peer
            .slots
            .held()
            .filter_map(|(mid, other)| {
                self.peers.get(other).map(|other| Slot {
                    mid: mid.to_string(),
                    user_id: other.user_id.clone(),
                })
            })
            .collect();
        if audio == peer.told {
            return;
        }
        let call_id = peer.call_id.clone();
        if let Some(peer) = self.peers.get_mut(&id) {
            peer.told.clone_from(&audio);
        }
        tell(&self.events, Event::Slots { call_id, audio });
    }

    fn peer_mut(&mut self, call_id: &str) -> Option<&mut Peer> {
        let id = self.by_call.get(call_id)?;
        self.peers.get_mut(id)
    }

    fn call_id(&mut self) -> String {
        loop {
            let mut hasher = self.ids.build_hasher();
            hasher.write_u64(self.next_id);
            let call_id = format!("c-{:016x}", hasher.finish());
            if !self.by_call.contains_key(&call_id) {
                return call_id;
            }
            self.next_id += 1;
        }
    }

    /// Reads every datagram waiting on the socket.
    fn read(&mut self, buf: &mut [u8]) {
        loop {
            match self.socket.recv_from(buf) {
                Ok((n, source)) => {
                    let now = Instant::now();
                    if let Some(packet) = buf.get(..n) {
                        self.receive(packet, source, now);
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => return,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                // An ICMP error from an earlier send. Not this read's problem.
                Err(error) if error.kind() == ErrorKind::ConnectionRefused => {}
                Err(error) => {
                    tracing::warn!(%error, "media read failed");
                    return;
                }
            }
        }
    }

    /// One datagram. Over its source's budget, or for nobody, it is dropped. An address no
    /// participant uses yet gets through only as STUN carrying a participant's ICE username.
    fn receive(&mut self, packet: &[u8], source: SocketAddr, now: Instant) {
        if !self.sources.contains_key(&source) && self.sources.len() >= SOURCES {
            return;
        }
        let (rate, burst) = (self.config.packets_per_second, self.config.packet_burst);
        let budget = self
            .sources
            .entry(source)
            .or_insert_with(|| Bucket::new(rate, burst, now));
        if !budget.take(1, now) {
            return;
        }
        let Ok(contents) = DatagramRecv::try_from(packet) else {
            return;
        };
        let input = Input::Receive(
            now,
            Receive {
                proto: Protocol::Udp,
                source,
                destination: self.public,
                contents,
            },
        );
        let known = self
            .by_addr
            .get(&source)
            .copied()
            .filter(|id| self.peers.get(id).is_some_and(|p| p.rtc.accepts(&input)));
        let Some(id) = known.or_else(|| {
            self.peers
                .iter()
                .find(|(_, peer)| peer.rtc.accepts(&input))
                .map(|(id, _)| *id)
        }) else {
            return;
        };
        self.by_addr.insert(source, id);
        let Some(peer) = self.peers.get_mut(&id) else {
            return;
        };
        peer.heard_at = now;
        if let Err(error) = peer.rtc.handle_input(input) {
            tracing::info!(call_id = %peer.call_id, ?error, "media input refused");
            peer.rtc.disconnect();
        }
        self.drain(id);
        self.forward_all(now);
        self.settle();
    }

    /// Fills the slots of everyone whose `Rtc` reported new receive m-lines.
    fn settle(&mut self) {
        let fresh: Vec<PeerId> = self
            .peers
            .iter_mut()
            .filter(|(_, peer)| peer.new_slots)
            .map(|(id, peer)| {
                peer.new_slots = false;
                *id
            })
            .collect();
        for id in fresh {
            self.reseat(id);
            self.tell_slots(id);
        }
    }

    /// Timeouts, deadlines, speaking, load, and the dead.
    fn tick(&mut self, now: Instant) {
        let due: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.timeout <= now)
            .map(|(id, _)| *id)
            .collect();
        for id in due {
            if let Some(peer) = self.peers.get_mut(&id) {
                if let Err(error) = peer.rtc.handle_input(Input::Timeout(now)) {
                    tracing::info!(call_id = %peer.call_id, ?error, "media timeout failed");
                    peer.rtc.disconnect();
                }
            }
            self.drain(id);
        }
        self.forward_all(now);
        self.settle();

        for peer in self.peers.values_mut() {
            if peer.lost.is_some() {
                continue;
            }
            if !peer.connected
                && now.saturating_duration_since(peer.joined_at) >= self.config.connect_timeout
            {
                peer.lost = Some(Lost::Timeout);
            } else if peer.connected
                && now.saturating_duration_since(peer.heard_at) >= self.config.consent_timeout
            {
                peer.lost = Some(Lost::Gone);
            }
        }
        let dead: Vec<(PeerId, Lost)> = self
            .peers
            .iter()
            .filter_map(|(id, peer)| peer.lost.map(|lost| (*id, lost)))
            .collect();
        for (id, lost) in dead {
            self.remove(id, Some(lost));
        }

        self.speaking(now);
        if now.saturating_duration_since(self.swept_at) >= Duration::from_secs(1) {
            self.swept_at = now;
            self.sources
                .retain(|_, bucket| now.saturating_duration_since(bucket.used()) < SOURCE_IDLE);
        }
        let since = now.saturating_duration_since(self.load_at);
        if since >= LOAD_EVERY {
            let egress_kbps = self.egress.saturating_mul(8) / since.as_millis().max(1) as u64;
            self.egress = 0;
            self.load_at = now;
            hint(
                &self.events,
                Event::Load {
                    egress_kbps,
                    participants: self.peers.len(),
                },
            );
        }
    }

    fn speaking(&mut self, now: Instant) {
        for (room_id, room) in &mut self.rooms {
            let user_ids: Vec<String> = room
                .members
                .iter()
                .filter_map(|id| self.peers.get(id))
                .filter(|peer| !peer.muted && peer.speech.speaking(now))
                .map(|peer| peer.user_id.clone())
                .collect();
            if let Some(user_ids) = room.announced.due(user_ids, now) {
                hint(
                    &self.events,
                    Event::Speaking {
                        room_id: room_id.clone(),
                        user_ids,
                    },
                );
            }
        }
    }

    /// Polls one `Rtc` until it returns its next timeout.
    fn drain(&mut self, id: PeerId) {
        let Some(peer) = self.peers.get_mut(&id) else {
            return;
        };
        let mut sink = Sink {
            socket: &self.socket,
            events: &self.events,
            egress: &mut self.egress,
            forward: &mut self.forward,
        };
        drain(id, peer, &mut sink);
    }

    /// Copies each queued audio frame to every listener in its room.
    fn forward_all(&mut self, now: Instant) {
        while let Some((origin, data)) = self.forward.pop_front() {
            let Some(publisher) = self.peers.get_mut(&origin) else {
                continue;
            };
            if publisher.muted {
                continue;
            }
            publisher.speech.hear(data.ext_vals.audio_level, now);
            let size = u32::try_from(data.data.len()).unwrap_or(u32::MAX);
            if !publisher.audio.take(size, now) {
                continue;
            }
            let room_id = publisher.room_id.clone();
            for listener in self.members(&room_id) {
                if listener == origin {
                    continue;
                }
                let Some(peer) = self.peers.get_mut(&listener) else {
                    continue;
                };
                if peer.deafened || !peer.connected {
                    continue;
                }
                let Some(mid) = peer.slots.mid_of(&origin).copied() else {
                    continue;
                };
                let Some(writer) = peer.rtc.writer(mid) else {
                    continue;
                };
                let Some(pt) = writer.match_params(data.params) else {
                    continue;
                };
                if let Err(error) =
                    writer.write(pt, data.network_time, data.time, data.data.clone())
                {
                    tracing::info!(call_id = %peer.call_id, ?error, "media write failed");
                    peer.rtc.disconnect();
                }
                let mut sink = Sink {
                    socket: &self.socket,
                    events: &self.events,
                    egress: &mut self.egress,
                    forward: &mut self.forward,
                };
                drain(listener, peer, &mut sink);
            }
        }
    }
}

fn drain(id: PeerId, peer: &mut Peer, sink: &mut Sink<'_>) {
    loop {
        if !peer.rtc.is_alive() {
            peer.lost.get_or_insert(Lost::Gone);
            return;
        }
        let output = match peer.rtc.poll_output() {
            Ok(output) => output,
            Err(error) => {
                tracing::info!(call_id = %peer.call_id, ?error, "media output failed");
                peer.rtc.disconnect();
                peer.lost.get_or_insert(Lost::Gone);
                return;
            }
        };
        match output {
            Output::Timeout(at) => {
                peer.timeout = at;
                return;
            }
            Output::Transmit(transmit) => {
                *sink.egress += transmit.contents.len() as u64;
                if let Err(error) = sink
                    .socket
                    .send_to(&transmit.contents, transmit.destination)
                {
                    if error.kind() != ErrorKind::WouldBlock {
                        tracing::debug!(%error, "media send failed");
                    }
                }
            }
            Output::Event(event) => match event {
                RtcEvent::Connected => {
                    peer.connected = true;
                    tracing::info!(call_id = %peer.call_id, "media connected");
                    tell(
                        sink.events,
                        Event::Connected {
                            call_id: peer.call_id.clone(),
                        },
                    );
                }
                RtcEvent::MediaAdded(added) if added.kind == MediaKind::Audio => {
                    match added.direction {
                        Direction::RecvOnly | Direction::SendRecv if peer.publish.is_none() => {
                            peer.publish = Some(added.mid);
                        }
                        Direction::SendOnly => {
                            peer.slots.add_mid(added.mid);
                            peer.new_slots = true;
                        }
                        _ => {}
                    }
                }
                RtcEvent::MediaData(data) if Some(data.mid) == peer.publish => {
                    sink.forward.push_back((id, data));
                }
                RtcEvent::Closed => {
                    peer.lost.get_or_insert(Lost::Gone);
                }
                _ => {}
            },
        }
    }
}

/// Events the API must see. The API drains its queue, so this waits rarely and briefly.
fn tell(events: &async_mpsc::Sender<Event>, event: Event) {
    let _ = events.blocking_send(event);
}

/// Events that may be dropped when the queue is full.
fn hint(events: &async_mpsc::Sender<Event>, event: Event) {
    let _ = events.try_send(event);
}
