//! A minimal TURN client (RFC 5766) for relay mode. The SFU is the TURN client: one
//! allocation per participant over UDP to the TURN server, the relayed address is what the
//! participant's SDP answer advertises, and the participant's server-reflexive address (from
//! its `call.candidate` frame) is what CreatePermission covers. The protocol is plain RFC
//! 5389 long-term credentials with the credentials `generate-ice-servers` handed out; there
//! is nothing Cloudflare-specific here.
//!
//! Sans IO like the rest of the crate: [`TurnSession`] builds the bytes to send and consumes
//! the bytes that came back, and the caller owns the socket and the timing. Everything runs
//! on the SFU thread; no sockets and no threads are owned here.

use std::collections::{HashMap, VecDeque};
use std::hash::Hasher;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use aws_lc_rs::hmac;
use md5::{Digest, Md5};

/// The TURN server, and the short-lived credentials `generate-ice-servers` made for this
/// participant.
#[derive(Debug, Clone)]
pub(crate) struct TurnServer {
    pub server: SocketAddr,
    pub username: String,
    pub credential: String,
}

/// What came out of a datagram the caller fed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TurnEvent {
    /// The allocation is up. The relayed address is what the SDP answer advertises.
    Allocated {
        relayed: SocketAddr,
        lifetime: Duration,
    },
    /// CreatePermission succeeded for this peer address.
    Permission(SocketAddr),
    /// ChannelBind succeeded. The channel carries this peer's media.
    ChannelBound(SocketAddr),
    /// Media from a peer, unwrapped from a data indication or a channel.
    Received(SocketAddr, Vec<u8>),
    /// A datagram to send: the re-request after a credentials challenge.
    Send(Vec<u8>),
    /// A request the server never answered within its retries, or refused outright; the
    /// text says which. For the allocation and its refresh this is the session's end; a
    /// permission or a bind only drops its own request, whose timer re-arms.
    TimedOut(&'static str),
}

// --- Message types. Our methods are all below 0x10, so the type field is the class in its
// high bits over the method in its low ones: request 0x0003, success 0x0103, error 0x0113,
// send indication 0x0016, data indication 0x0017. ------------------------------------------------

const ALLOCATE: u16 = 3;
const REFRESH: u16 = 4;
const CREATE_PERMISSION: u16 = 8;
const CHANNEL_BIND: u16 = 9;
const SEND_INDICATION: u16 = 0x0016;
const DATA_INDICATION: u16 = 0x0017;

const CLASS_REQUEST: u8 = 0;
const CLASS_INDICATION: u8 = 1;
const CLASS_SUCCESS: u8 = 2;
const CLASS_ERROR: u8 = 3;

const MAGIC: u32 = 0x2112_A444;
const HEADER: usize = 20;
/// MESSAGE-INTEGRITY carries a 20-byte SHA-1 HMAC behind its four-byte header; the
/// attribute's length field counts the tag alone (RFC 5389 §15.4).
const INTEGRITY_LEN: usize = 20;
const CHANNEL_MIN: u16 = 0x4000;
const UDP: u8 = 17;
/// Channels re-bind a minute before the server would drop the binding at ten minutes.
const REBIND_AFTER: Duration = Duration::from_secs(9 * 60);
/// Permissions re-create a minute before the server drops them at five minutes.
const REPERMISSION_AFTER: Duration = Duration::from_secs(4 * 60);
/// Seven requests go out for one transaction before it fails (RFC 5389 §7.2.1).
const RETRIES: u32 = 6;
const RTO: Duration = Duration::from_millis(500);
/// The wait after the last retransmit, Rm times the RTO (RFC 5389 §7.2.1): the final
/// request gets an ample chance to be answered before the transaction is called dead.
const FINAL_GRACE: Duration = Duration::from_millis(16 * 500);
/// The largest datagram wrapped for a peer.
const MAX_PAYLOAD: usize = 1_400;

fn msg_type(method: u16, class: u8) -> u16 {
    let class_base = match class {
        CLASS_INDICATION => 0x0010,
        CLASS_SUCCESS => 0x0100,
        CLASS_ERROR => 0x0110,
        _ => 0x0000,
    };
    class_base | (method & 0xF)
}

fn method_of(msg_type: u16) -> u16 {
    msg_type & 0xF
}

fn class_of(msg_type: u16) -> u8 {
    match msg_type & 0x0110 {
        0x0100 => CLASS_SUCCESS,
        0x0110 => CLASS_ERROR,
        0x0010 => CLASS_INDICATION,
        _ => CLASS_REQUEST,
    }
}

/// Twelve bytes no observer of the wire can guess (RFC 5389 §6 wants unguessable
/// transaction ids; a counter, the clock, and the fixed bytes "TURN" were all readable).
/// Everything std offers without a dependency goes into a `DefaultHasher`, whose keys the
/// process drew from the operating system: a counter, the clock to the nanosecond, and this
/// frame's own stack address. None of them is enough alone.
fn rand_transaction() -> [u8; 12] {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed).to_be_bytes();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
        .to_le_bytes();
    let stack = 0u8;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hasher.write(&counter);
    hasher.write(&nanos);
    hasher.write(&(&stack as *const u8 as usize).to_le_bytes());
    let mixed = hasher.finish();
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(&mixed.to_le_bytes());
    // The last four bytes from a second pass, so all twelve carry the mix.
    let mut spread = std::collections::hash_map::DefaultHasher::new();
    spread.write(&mixed.to_le_bytes());
    spread.write(&counter);
    out[8..].copy_from_slice(&(spread.finish() as u32).to_le_bytes());
    out
}

/// XOR-hides an IPv4 port and address with the magic cookie, the STUN way. The eight bytes
/// are `[reserved, family, xport(2), xaddr(4)]`.
fn xor_into(buf: &mut [u8], addr: SocketAddr) {
    let IpAddr::V4(ip) = addr.ip() else {
        return;
    };
    buf[0] = 0;
    buf[1] = 1;
    buf[2..4].copy_from_slice(&addr.port().to_be_bytes());
    buf[4..8].copy_from_slice(&ip.octets());
    let masks = MAGIC.to_be_bytes();
    buf[2] ^= masks[0];
    buf[3] ^= masks[1];
    for i in 0..4 {
        buf[4 + i] ^= masks[i];
    }
}

/// Un-hides an IPv4 address the same way.
fn xor_out(buf: &[u8]) -> Option<SocketAddr> {
    if buf.len() < 8 || buf[1] != 1 {
        return None;
    }
    let mut port_bytes = [0u8; 2];
    port_bytes.copy_from_slice(&buf[2..4]);
    for (byte, mask) in port_bytes.iter_mut().zip(MAGIC.to_be_bytes()) {
        *byte ^= mask;
    }
    let port = u16::from_be_bytes(port_bytes);
    let mut octets = [0u8; 4];
    octets.copy_from_slice(&buf[4..8]);
    for (byte, mask) in octets.iter_mut().zip(MAGIC.to_be_bytes()) {
        *byte ^= mask;
    }
    Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
}

fn put_address(buf: &mut Vec<u8>, attribute: u16, addr: SocketAddr) {
    buf.extend_from_slice(&attribute.to_be_bytes());
    buf.extend_from_slice(&8u16.to_be_bytes());
    let mut value = [0u8; 8];
    value[1] = 1;
    xor_into(&mut value, addr);
    buf.extend_from_slice(&value);
}

/// When the next refresh is due: the lifetime minus a minute of margin. A grant shorter
/// than two minutes halves instead, so a short lifetime refreshes at its halfway point
/// instead of leaving `poll` due on every call.
fn refresh_at(now: Instant, lifetime_secs: u64) -> Instant {
    let margin = 60.min(lifetime_secs / 2);
    now + Duration::from_secs((lifetime_secs - margin).max(1))
}

/// The long-term-credentials key (RFC 5389 §15.4): MD5 over `username:realm:password`,
/// the same derivation on both sides of the wire.
fn integrity_key(username: &str, realm: &str, credential: &str) -> hmac::Key {
    let material = format!("{}:{}:{}", username, realm, credential);
    let digest = Md5::digest(material.as_bytes());
    hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, digest.as_ref())
}

/// The wait before the next retransmit, after `retransmits` went out (RFC 5389 §7.2.1):
/// the interval doubles from the RTO each time, and after the last one the final grace
/// carries the transaction to its 39.5 seconds — not to the three a fixed interval spent.
fn retry_wait(retransmits: u32) -> Duration {
    if retransmits >= RETRIES {
        return FINAL_GRACE;
    }
    RTO.saturating_mul(1u32 << retransmits)
}

/// What a response carried.
#[derive(Debug, Default)]
struct Attributes {
    relayed: Option<SocketAddr>,
    /// The family byte of the relayed address even when it did not parse as IPv4: family 2
    /// is IPv6, which this client cannot relay.
    relayed_family: Option<u8>,
    peer: Option<SocketAddr>,
    lifetime: Option<u64>,
    nonce: Option<Vec<u8>>,
    realm: Option<String>,
    data: Option<Vec<u8>>,
    error: Option<(u16, String)>,
    /// The MESSAGE-INTEGRITY tag, and where the attribute sits in the slice: the HMAC's
    /// input ends there, with the header length shortened to match (RFC 5389 §15.4), so
    /// the position is part of the verification.
    integrity: Option<Vec<u8>>,
    integrity_at: Option<usize>,
}

fn parse_attributes(data: &[u8]) -> Option<Attributes> {
    let mut found = Attributes::default();
    let mut at = 0;
    while at + 4 <= data.len() {
        let kind = u16::from_be_bytes([data[at], data[at + 1]]);
        let len = u16::from_be_bytes([data[at + 2], data[at + 3]]) as usize;
        let value = data.get(at + 4..at + 4 + len)?;
        match kind {
            22 => {
                found.relayed = xor_out(value);
                found.relayed_family = value.get(1).copied();
            }
            18 => found.peer = xor_out(value),
            13 => found.lifetime = Some(u32::from_be_bytes(value.try_into().ok()?) as u64),
            21 => found.nonce = Some(value.to_vec()),
            20 => found.realm = Some(String::from_utf8_lossy(value).into_owned()),
            19 => found.data = Some(value.to_vec()),
            9 => {
                // The code rides as class and number in the two bytes after the two zeros
                // (RFC 5389 §15.6): 401 is bytes 04 01, 438 is 04 26. Reading the pair as
                // one masked number turns a real 401 into 1 and a 438 into 54, and lands
                // every real challenge in the wrong arm.
                let class = u16::from(*value.get(2).unwrap_or(&0));
                let number = u16::from(*value.get(3).unwrap_or(&0));
                found.error = Some((
                    class * 100 + number,
                    String::from_utf8_lossy(value.get(4..).unwrap_or(b"")).into_owned(),
                ));
            }
            8 => {
                found.integrity = Some(value.to_vec());
                found.integrity_at = Some(at);
            }
            _ => {}
        }
        at += 4 + len.div_ceil(4) * 4;
    }
    Some(found)
}

/// What a request is for, so its answer lands on the right timer and the right event: the
/// peer a CreatePermission covers, or the channel and peer a ChannelBind binds.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Subject {
    Permission(SocketAddr),
    Bind(u16, SocketAddr),
}

/// A request waiting for the wire.
struct Request {
    method: u16,
    attributes: Vec<(u16, Vec<u8>)>,
    subject: Option<Subject>,
}

/// One request in flight: its attributes (for the credentials round-trip), the bytes to
/// re-send, and when to send them again.
struct Pending {
    method: u16,
    attributes: Vec<(u16, Vec<u8>)>,
    bytes: Vec<u8>,
    transaction: [u8; 12],
    deadline: Instant,
    tries: u32,
    subject: Option<Subject>,
}

/// One allocation, the relayed address, and everything bound to it. The credentials are the
/// host's, the relayed address and the bindings are one participant's.
pub(crate) struct TurnSession {
    server: TurnServer,
    nonce: Option<Vec<u8>>,
    realm: Option<String>,
    relayed: Option<SocketAddr>,
    lifetime_until: Instant,
    permissions: HashMap<SocketAddr, Instant>,
    /// Channel number, the peer it carries, and when the binding was made.
    channels: HashMap<u16, (SocketAddr, Instant)>,
    peers: HashMap<SocketAddr, u16>,
    next_channel: u16,
    /// Requests waiting for the wire. One transaction is in flight at a time (RFC 5389
    /// §7.2.1 has the client wait for the response before the next transaction); the queue
    /// is how a `call.candidate` arriving during a refresh keeps its CreatePermission
    /// instead of overwriting the refresh. `poll` sends the oldest once the wire frees.
    queue: VecDeque<Request>,
    /// The request on the wire, waiting for its response or its next retransmit.
    pending: Option<Pending>,
    /// Set once the allocation failed its retries, so the caller can tear the seat down.
    failed: bool,
}

impl TurnSession {
    pub fn new(server: TurnServer) -> Self {
        Self {
            server,
            nonce: None,
            realm: None,
            relayed: None,
            lifetime_until: Instant::now(),
            permissions: HashMap::new(),
            channels: HashMap::new(),
            peers: HashMap::new(),
            next_channel: CHANNEL_MIN,
            queue: VecDeque::new(),
            pending: None,
            failed: false,
        }
    }

    pub fn relayed(&self) -> Option<SocketAddr> {
        self.relayed
    }

    pub fn failed(&self) -> bool {
        self.failed
    }

    /// Starts the allocation and returns its datagram. Re-sending until the server answers
    /// is `poll`'s job.
    pub fn allocate(&mut self, now: Instant) -> Vec<u8> {
        // REQUESTED-TRANSPORT is the protocol byte plus three reserved ones (RFC 5766
        // §14.7). A length of one is answered 400 by a server that follows the RFC.
        self.send_or_queue(ALLOCATE, vec![(23, vec![UDP, 0, 0, 0])], None, now)
    }

    /// CreatePermission for a peer address, as `call.candidate` asked, and its datagram.
    /// Refreshes are `poll`'s job.
    pub fn create_permission(&mut self, peer: SocketAddr, now: Instant) -> Vec<u8> {
        if !self.active() || !peer.is_ipv4() || self.permission_scheduled(&peer) {
            return Vec::new();
        }
        let mut address = Vec::new();
        put_address(&mut address, 18, peer);
        // The timer starts on the ask, not the answer, so a request queued behind another
        // still comes round for its re-create even if this one is never answered.
        self.permissions.entry(peer).or_insert(now);
        self.send_or_queue(
            CREATE_PERMISSION,
            vec![(18, address)],
            Some(Subject::Permission(peer)),
            now,
        )
    }

    /// Whether a CreatePermission for this peer is in flight or queued already: a fresh
    /// `call.candidate` for an address being permitted has nothing to add.
    fn permission_scheduled(&self, peer: &SocketAddr) -> bool {
        let subject = Some(Subject::Permission(*peer));
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.subject == subject)
        {
            return true;
        }
        self.queue.iter().any(|request| request.subject == subject)
    }

    /// ChannelBind for a peer address, so its media travels as channel data, and its
    /// datagram. Re-binds are `poll`'s job.
    pub fn channel_bind(&mut self, peer: SocketAddr, now: Instant) -> Vec<u8> {
        if !self.active() || !peer.is_ipv4() || self.peers.contains_key(&peer) {
            return Vec::new();
        }
        self.bind(peer, now)
    }

    fn bind(&mut self, peer: SocketAddr, now: Instant) -> Vec<u8> {
        let channel = self.peers.get(&peer).copied().unwrap_or_else(|| {
            let channel = self.next_channel;
            self.next_channel += 1;
            channel
        });
        let mut number = channel.to_be_bytes().to_vec();
        number.extend_from_slice(&2u16.to_be_bytes());
        let mut address = Vec::new();
        put_address(&mut address, 18, peer);
        self.send_or_queue(
            CHANNEL_BIND,
            vec![(12, number), (18, address)],
            Some(Subject::Bind(channel, peer)),
            now,
        )
    }

    /// Wraps `payload` for `peer`: channel data once the channel is bound, a send indication
    /// until then. Empty when the session cannot carry it yet.
    pub fn send_to(&self, peer: SocketAddr, payload: &[u8]) -> Vec<u8> {
        if !self.active() || !peer.is_ipv4() || payload.is_empty() || payload.len() > MAX_PAYLOAD {
            return Vec::new();
        }
        let mut buf = Vec::with_capacity(payload.len() + 32);
        match self.peers.get(&peer).copied() {
            Some(channel) => {
                buf.extend_from_slice(&channel.to_be_bytes());
                buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                buf.extend_from_slice(payload);
            }
            None => {
                buf.extend_from_slice(&(SEND_INDICATION).to_be_bytes());
                buf.extend_from_slice(&[0, 0]);
                buf.extend_from_slice(&rand_transaction());
                put_address(&mut buf, 18, peer);
                // The DATA value is padded to four bytes and the header length counts the
                // padding (RFC 5389 §6, §15): a length that is not a multiple of four is
                // a datagram a conforming server drops.
                let padded = payload.len().div_ceil(4) * 4;
                buf.extend_from_slice(&19u16.to_be_bytes());
                buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                buf.extend_from_slice(payload);
                buf.resize(buf.len() + padded - payload.len(), 0);
                let len = (buf.len() - HEADER) as u16;
                buf[2..4].copy_from_slice(&len.to_be_bytes());
            }
        }
        buf
    }

    /// Re-sends what is pending, sends the oldest queued request once the wire frees,
    /// refreshes the allocation, re-creates permissions and re-binds channels when they
    /// are due, and reports the bytes to send. One thing at a time; the next call picks up
    /// where this left off.
    pub fn poll(&mut self, now: Instant) -> Option<Vec<u8>> {
        if self.failed {
            return None;
        }
        if let Some(pending) = &mut self.pending {
            if now >= pending.deadline {
                pending.tries += 1;
                if pending.tries > RETRIES {
                    // The allocation and its refresh are the session: without them there
                    // is nothing to relay on, and the caller tears the seat down. A
                    // permission or a bind the server never answered drops alone, its
                    // timer re-armed from now, and the rest of the session carries.
                    let method = pending.method;
                    let subject = pending.subject.take();
                    self.pending = None;
                    match method {
                        ALLOCATE | REFRESH => self.failed = true,
                        CREATE_PERMISSION => {
                            if let Some(Subject::Permission(peer)) = subject {
                                self.permissions.insert(peer, now);
                            }
                        }
                        CHANNEL_BIND => {
                            if let Some(Subject::Bind(channel, _)) = subject {
                                if let Some((_, bound)) = self.channels.get_mut(&channel) {
                                    *bound = now;
                                }
                            }
                        }
                        _ => {}
                    }
                    return None;
                }
                pending.deadline = now + retry_wait(pending.tries);
                return Some(pending.bytes.clone());
            }
            return None;
        }
        if !self.active() {
            return None;
        }
        if let Some(request) = self.queue.pop_front() {
            self.send_request(request.method, request.attributes, request.subject, now);
            return Some(self.pending_bytes());
        }
        if now >= self.lifetime_until {
            let bytes = self.send_or_queue(
                REFRESH,
                vec![(13, 600u32.to_be_bytes().to_vec())],
                None,
                now,
            );
            // The next refresh is due a full lifetime from the ask. A refresh the server
            // refuses or never answers ends the session, so this cannot mask a dead
            // allocation for long.
            self.lifetime_until = now + Duration::from_secs(600);
            if bytes.is_empty() {
                return None;
            }
            return Some(bytes);
        }
        let mut due_permission: Option<SocketAddr> = None;
        for (peer, due) in &self.permissions {
            if now.saturating_duration_since(*due) >= REPERMISSION_AFTER {
                due_permission = Some(*peer);
            }
        }
        if let Some(peer) = due_permission {
            let bytes = self.create_permission(peer, now);
            if bytes.is_empty() {
                return None;
            }
            return Some(bytes);
        }
        let mut rebind: Option<SocketAddr> = None;
        for (peer, bound) in self.channels.values() {
            if now.saturating_duration_since(*bound) >= REBIND_AFTER {
                rebind = Some(*peer);
            }
        }
        if let Some(peer) = rebind {
            let bytes = self.bind(peer, now);
            if bytes.is_empty() {
                return None;
            }
            return Some(bytes);
        }
        None
    }

    fn pending_bytes(&self) -> Vec<u8> {
        self.pending
            .as_ref()
            .map(|pending| pending.bytes.clone())
            .unwrap_or_default()
    }

    /// Feeds one datagram from the TURN server in and reports what it said.
    pub fn handle(&mut self, data: &[u8], now: Instant) -> Option<TurnEvent> {
        // Channel data is smaller than a STUN header, so it is recognized first. A zero-byte
        // datagram is nothing at all.
        if data.is_empty() {
            return None;
        }
        if (0x40..0x80).contains(&data[0]) {
            return self.channel_data(data);
        }
        if data.len() < HEADER {
            return None;
        }
        // A STUN message carries the magic cookie, and its length field covers exactly the
        // attributes (RFC 5389 §5, §6). Anything else is not a message for this session —
        // a length that does not match would have the attribute walk below read past the
        // datagram.
        if data[4..8] != MAGIC.to_be_bytes() {
            return None;
        }
        if u16::from_be_bytes([data[2], data[3]]) as usize != data.len() - HEADER {
            return None;
        }
        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        if msg_type == DATA_INDICATION {
            let attributes = parse_attributes(&data[HEADER..])?;
            let peer = attributes.peer?;
            let payload = attributes.data?;
            return Some(TurnEvent::Received(peer, payload));
        }
        let class = class_of(msg_type);
        if class != CLASS_SUCCESS && class != CLASS_ERROR {
            return None;
        }
        let method = method_of(msg_type);
        let pending = self.pending.as_ref()?;
        if pending.transaction != data[8..20] {
            return None;
        }
        let attributes = parse_attributes(&data[HEADER..])?;
        // Once the session holds credentials, its request on the wire was signed, and the
        // answer to it is signed too (RFC 5389 §10.1, §15.4): the tag covers the message
        // with the header length ending at the integrity attribute. An answer without a
        // tag that verifies is not the server's, and is dropped as if it never came — the
        // request stays in flight and its retransmits continue.
        if let (Some(_), Some(realm)) = (&self.nonce, &self.realm) {
            let (Some(tag), Some(at)) = (&attributes.integrity, attributes.integrity_at) else {
                return None;
            };
            let mut signed = data[..HEADER + at].to_vec();
            signed[2..4].copy_from_slice(&(at as u16).to_be_bytes());
            let key = integrity_key(&self.server.username, realm, &self.server.credential);
            if hmac::sign(&key, &signed).as_ref() != tag.as_slice() {
                return None;
            }
        }
        if class == CLASS_ERROR {
            let (code, _) = attributes.error?;
            match code {
                401 | 438 => {
                    // The challenge names the nonce and realm; the same request goes out
                    // again, now with credentials and integrity. The retries stay counted
                    // across challenges: the RETRIES-th is still answered, the one after
                    // it fails the session, so a server that never accepts cannot keep
                    // this session asking forever.
                    let method = pending.method;
                    let retry_attributes = pending.attributes.clone();
                    let subject = pending.subject.clone();
                    let tries = pending.tries + 1;
                    if tries > RETRIES {
                        self.pending = None;
                        self.failed = true;
                        return Some(TurnEvent::TimedOut("challenged too often"));
                    }
                    self.nonce = attributes.nonce.clone().or(self.nonce.clone());
                    self.realm = attributes.realm.clone().or(self.realm.clone());
                    self.send_request(method, retry_attributes, subject, now);
                    if let Some(retried) = self.pending.as_mut() {
                        retried.tries = tries;
                    }
                    Some(TurnEvent::Send(self.pending_bytes()))
                }
                _ => {
                    // The server refused the request outright. The allocation and its
                    // refresh are the session: without them there is nothing to relay on.
                    // A refused permission or bind drops alone, its timer re-armed from
                    // now, and the rest of the session carries.
                    let pending = self.pending.take()?;
                    match pending.method {
                        ALLOCATE | REFRESH => self.failed = true,
                        CREATE_PERMISSION => {
                            if let Some(Subject::Permission(peer)) = pending.subject {
                                self.permissions.insert(peer, now);
                            }
                        }
                        CHANNEL_BIND => {
                            if let Some(Subject::Bind(channel, _)) = pending.subject {
                                if let Some((_, bound)) = self.channels.get_mut(&channel) {
                                    *bound = now;
                                }
                            }
                        }
                        _ => {}
                    }
                    Some(TurnEvent::TimedOut("rejected"))
                }
            }
        } else {
            let pending = self.pending.take()?;
            match method {
                ALLOCATE => {
                    let relayed = match attributes.relayed {
                        Some(relayed) => relayed,
                        // No relayed address this client can use: family 2 is IPv6, and
                        // this client relays IPv4 — its peers are the IPv4
                        // `call.candidate` addresses. An answer without a relay at all is
                        // no answer. Neither changes on a re-send, so the session fails
                        // here instead of spending its retries on the same request.
                        None => {
                            self.failed = true;
                            let reason = if attributes.relayed_family == Some(2) {
                                "the relayed address is IPv6"
                            } else {
                                "no relayed address in the answer"
                            };
                            return Some(TurnEvent::TimedOut(reason));
                        }
                    };
                    let lifetime = attributes.lifetime.unwrap_or(600);
                    self.relayed = Some(relayed);
                    self.lifetime_until = refresh_at(now, lifetime);
                    Some(TurnEvent::Allocated {
                        relayed,
                        lifetime: Duration::from_secs(lifetime),
                    })
                }
                REFRESH => {
                    let lifetime = attributes.lifetime.unwrap_or(600);
                    self.lifetime_until = refresh_at(now, lifetime);
                    None
                }
                CREATE_PERMISSION => match pending.subject {
                    // The server's five minutes start now, for this peer alone; the others
                    // keep the timers their own successes stamped.
                    Some(Subject::Permission(peer)) => {
                        self.permissions.insert(peer, now);
                        Some(TurnEvent::Permission(peer))
                    }
                    _ => None,
                },
                CHANNEL_BIND => match pending.subject {
                    Some(Subject::Bind(channel, peer)) => {
                        self.channels.insert(channel, (peer, now));
                        self.peers.insert(peer, channel);
                        Some(TurnEvent::ChannelBound(peer))
                    }
                    _ => None,
                },
                _ => None,
            }
        }
    }

    /// Channel data in: the channel names the peer. Data indications name it themselves.
    fn channel_data(&mut self, data: &[u8]) -> Option<TurnEvent> {
        if data.len() < 4 {
            return None;
        }
        let channel = u16::from_be_bytes([data[0], data[1]]);
        let len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let payload = data.get(4..4 + len)?;
        let (peer, _bound) = self.channels.get(&channel)?;
        Some(TurnEvent::Received(*peer, payload.to_vec()))
    }

    fn active(&self) -> bool {
        self.relayed.is_some()
    }

    /// Builds one request and puts it on the wire as the pending one. Everything goes
    /// through `send_or_queue`, which only calls this when the wire is free — except the
    /// credentials round-trip, which replaces its own challenged request. Attributes go in
    /// first, credentials and integrity behind them: the HMAC signs everything before the
    /// integrity attribute, over a header length that ends there, and the wire's length
    /// counts the attribute again (RFC 5389 §15.4). The key for long-term credentials is
    /// MD5 over `username ":" realm ":" password`, with the realm this session was
    /// challenged with.
    fn send_request(
        &mut self,
        method: u16,
        attributes: Vec<(u16, Vec<u8>)>,
        subject: Option<Subject>,
        now: Instant,
    ) {
        let mut buf = Vec::with_capacity(160);
        buf.extend_from_slice(&msg_type(method, CLASS_REQUEST).to_be_bytes());
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(&MAGIC.to_be_bytes());
        let transaction = rand_transaction();
        buf.extend_from_slice(&transaction);
        let mut put = |kind: u16, value: &[u8]| {
            buf.extend_from_slice(&kind.to_be_bytes());
            let padded = value.len().div_ceil(4) * 4;
            buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
            buf.extend_from_slice(value);
            buf.resize(buf.len() + padded - value.len(), 0);
        };
        for (kind, value) in &attributes {
            put(*kind, value);
        }
        if let (Some(nonce), Some(realm)) = (&self.nonce, &self.realm) {
            put(20, realm.as_bytes());
            put(21, nonce);
            put(6, self.server.username.as_bytes());
            // The HMAC covers the message with its header length ending before the
            // integrity attribute (RFC 5389 §15.4); on the wire the length counts the
            // attribute again, the way a receiver's own length check wants it. So the
            // length field is written twice: once for the sign, once for the datagram.
            let len = (buf.len() - HEADER) as u16;
            buf[2..4].copy_from_slice(&len.to_be_bytes());
            let key = integrity_key(&self.server.username, realm, &self.server.credential);
            let tag = hmac::sign(&key, &buf);
            buf.extend_from_slice(&8u16.to_be_bytes());
            buf.extend_from_slice(&(INTEGRITY_LEN as u16).to_be_bytes());
            buf.extend_from_slice(tag.as_ref());
            let len = (buf.len() - HEADER) as u16;
            buf[2..4].copy_from_slice(&len.to_be_bytes());
        }
        self.pending = Some(Pending {
            method,
            attributes,
            bytes: buf,
            transaction,
            deadline: now + RTO,
            tries: 0,
            subject,
        });
    }

    /// Puts a request on the wire when it is free, or queues it when one is in flight.
    /// One transaction at a time is the RFC's model; the queue is how a permission asked
    /// during a refresh is not lost to it. Returns the bytes to send now — empty when the
    /// request waits in the queue for `poll`.
    fn send_or_queue(
        &mut self,
        method: u16,
        attributes: Vec<(u16, Vec<u8>)>,
        subject: Option<Subject>,
        now: Instant,
    ) -> Vec<u8> {
        if self.pending.is_some() {
            self.queue.push_back(Request {
                method,
                attributes,
                subject,
            });
            return Vec::new();
        }
        self.send_request(method, attributes, subject, now);
        self.pending_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credentials() -> TurnServer {
        TurnServer {
            server: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)), 3478),
            username: "1735689600:turn-key".into(),
            credential: "hush-the-password".into(),
        }
    }

    /// A 401 challenge with nonce and realm, the way a TURN server opens the exchange.
    /// The code rides as class 4, number 1, behind the two zeros (RFC 5389 §15.6), not as
    /// a bare number: encoding 401 big-endian is a wire this module reads wrong. The tag
    /// is what a server puts on answers once the exchange is under way; the session
    /// cannot check the very first one — it holds no credentials yet — so a signed
    /// opening challenge reads the same as an unsigned one.
    fn challenge(transaction: [u8; 12]) -> Vec<u8> {
        error_answer(transaction, 401, b"Unauthorized", b"nonce-1")
    }

    /// A 438 stale-nonce error, the way a TURN server re-challenges when the nonce has
    /// aged out: class 4, number 38, with the fresh nonce and realm.
    fn stale_nonce(transaction: [u8; 12]) -> Vec<u8> {
        error_answer(transaction, 438, b"Stale Nonce", b"nonce-2")
    }

    fn error_answer(transaction: [u8; 12], code: u16, reason: &[u8], nonce: &[u8]) -> Vec<u8> {
        let mut error = vec![0, 0, (code / 100) as u8, (code % 100) as u8];
        error.extend_from_slice(reason);
        let parts = [
            (9u16, error),
            (20u16, b"turn.example.org".to_vec()),
            (21u16, nonce.to_vec()),
        ];
        answer(msg_type(ALLOCATE, CLASS_ERROR), transaction, &parts)
    }

    /// The value of the first attribute of this kind in a STUN message.
    fn attribute(message: &[u8], kind: u16) -> Option<Vec<u8>> {
        let mut at = HEADER;
        while at + 4 <= message.len() {
            let kind_at = u16::from_be_bytes([message[at], message[at + 1]]);
            let len = u16::from_be_bytes([message[at + 2], message[at + 3]]) as usize;
            if kind_at == kind {
                return Some(message[at + 4..at + 4 + len].to_vec());
            }
            at += 4 + len.div_ceil(4) * 4;
        }
        None
    }

    /// The relayed address and the lifetime an allocate success carries.
    fn allocated_parts(lifetime: u32) -> Vec<(u16, Vec<u8>)> {
        let mut relayed = [0u8; 8];
        relayed[1] = 1;
        xor_into(
            &mut relayed,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 61_924),
        );
        vec![
            (22u16, relayed.to_vec()),
            (13u16, lifetime.to_be_bytes().to_vec()),
        ]
    }

    /// An allocate success with the relayed address and a lifetime.
    fn allocated(transaction: [u8; 12], lifetime: u32) -> Vec<u8> {
        answer(
            msg_type(ALLOCATE, CLASS_SUCCESS),
            transaction,
            &allocated_parts(lifetime),
        )
    }

    /// A success response for `method`, empty attributes.
    fn success(method: u16, transaction: [u8; 12]) -> Vec<u8> {
        answer(msg_type(method, CLASS_SUCCESS), transaction, &[])
    }

    /// The answer the tests hand the session once it can be checked: signed, the way a
    /// server signs its answers to a signed request (RFC 5389 §15.4).
    fn answer(msg_type: u16, transaction: [u8; 12], parts: &[(u16, Vec<u8>)]) -> Vec<u8> {
        with_integrity(raw(msg_type, transaction, parts))
    }

    /// The same datagram without the tag — what no conforming server sends after the
    /// client authenticated, and what the session must drop.
    fn raw(msg_type: u16, transaction: [u8; 12], parts: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&msg_type.to_be_bytes());
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(&MAGIC.to_be_bytes());
        buf.extend_from_slice(&transaction);
        for (kind, value) in parts {
            buf.extend_from_slice(&kind.to_be_bytes());
            // The length field says how long the value is; the padding to four is extra
            // and unstated (RFC 5389 §15).
            let padded = value.len().div_ceil(4) * 4;
            buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
            buf.extend_from_slice(value);
            buf.resize(buf.len() + padded - value.len(), 0);
        }
        let len = (buf.len() - HEADER) as u16;
        buf[2..4].copy_from_slice(&len.to_be_bytes());
        buf
    }

    /// Appends the MESSAGE-INTEGRITY attribute a server's answer carries: HMAC-SHA1 over
    /// the message with its header length ending at the attribute, keyed with the MD5 of
    /// this test's `username:realm:password` (RFC 5389 §15.4). On the wire the header
    /// length counts the attribute again.
    fn with_integrity(mut message: Vec<u8>) -> Vec<u8> {
        let server = credentials();
        let key = integrity_key(&server.username, "turn.example.org", &server.credential);
        let len = (message.len() - HEADER) as u16;
        message[2..4].copy_from_slice(&len.to_be_bytes());
        let tag = hmac::sign(&key, &message);
        message.extend_from_slice(&8u16.to_be_bytes());
        message.extend_from_slice(&(INTEGRITY_LEN as u16).to_be_bytes());
        message.extend_from_slice(tag.as_ref());
        let len = (message.len() - HEADER) as u16;
        message[2..4].copy_from_slice(&len.to_be_bytes());
        message
    }

    fn request_type(session: &TurnSession, method: u16, class: u8) -> bool {
        let Some(pending) = &session.pending else {
            return false;
        };
        let type_ = u16::from_be_bytes([pending.bytes[0], pending.bytes[1]]);
        type_ == msg_type(method, class)
    }

    /// Drives the allocation through its challenge, so a test starts with the session up
    /// and nothing on the wire.
    fn handshake(session: &mut TurnSession, start: Instant, lifetime: u32) {
        let first = session.allocate(start);
        session.handle(
            &challenge(first[8..20].try_into().expect("a 12-byte transaction id")),
            start + RTO,
        );
        let second = session.pending_bytes();
        session.handle(
            &allocated(
                second[8..20].try_into().expect("a 12-byte transaction id"),
                lifetime,
            ),
            start + RTO * 2,
        );
    }

    /// An allocate success whose relayed address carries family 2, IPv6 — the value this
    /// client cannot relay.
    fn allocated_ipv6(transaction: [u8; 12], lifetime: u32) -> Vec<u8> {
        let mut relayed = vec![0u8, 2];
        relayed.resize(20, 0xAA);
        let parts = [(22u16, relayed), (13u16, lifetime.to_be_bytes().to_vec())];
        answer(msg_type(ALLOCATE, CLASS_SUCCESS), transaction, &parts)
    }

    #[test]
    fn challenges_exhaust_the_retries_and_fail_the_session() {
        let start = Instant::now();
        let mut session = TurnSession::new(credentials());
        let mut request = session.allocate(start);
        // A server that keeps challenging: each 401 or 438 gets the re-request the session
        // emits, until the retry cap trips and the session fails instead of asking forever.
        // The codes alternate, so both wire encodings — 04 01 and 04 26 — are decoded as
        // challenges, not as rejections.
        for round in 0..RETRIES {
            let transaction = request[8..20].try_into().expect("a 12-byte transaction id");
            let error = if round % 2 == 0 {
                challenge(transaction)
            } else {
                stale_nonce(transaction)
            };
            let event = session.handle(&error, start + RTO * (round + 1));
            let TurnEvent::Send(re_request) = event.expect("the re-request") else {
                panic!("not a send");
            };
            request = re_request;
        }
        let event = session.handle(
            &challenge(request[8..20].try_into().expect("a 12-byte transaction id")),
            start + Duration::from_secs(10),
        );
        assert!(matches!(event, Some(TurnEvent::TimedOut(_))));
        assert!(session.failed());
    }

    #[test]
    fn answers_carry_integrity_once_the_session_holds_credentials() {
        let start = Instant::now();
        let mut session = TurnSession::new(credentials());
        let first = session.allocate(start);
        // The opening challenge cannot be checked: the session holds no credentials yet,
        // so it goes through without a tag, and the re-request goes out signed.
        let transaction = first[8..20].try_into().expect("a 12-byte transaction id");
        let mut error = vec![0, 0, 4, 1];
        error.extend_from_slice(b"Unauthorized");
        let unsigned_challenge = raw(
            msg_type(ALLOCATE, CLASS_ERROR),
            transaction,
            &[
                (9u16, error),
                (20u16, b"turn.example.org".to_vec()),
                (21u16, b"nonce-1".to_vec()),
            ],
        );
        session.handle(&unsigned_challenge, start + RTO);
        assert!(
            request_type(&session, ALLOCATE, CLASS_REQUEST),
            "the unsigned opening challenge was read"
        );
        let second = session.pending_bytes();

        // Now the session holds credentials, and its request on the wire was signed: an
        // answer without a tag is dropped as if it never came.
        let unsigned = raw(
            msg_type(ALLOCATE, CLASS_SUCCESS),
            second[8..20].try_into().expect("a 12-byte transaction id"),
            &allocated_parts(600),
        );
        assert!(
            session.handle(&unsigned, start + RTO * 2).is_none(),
            "no tag, no answer"
        );
        assert!(session.pending.is_some(), "the request is still in flight");

        let TurnEvent::Allocated { relayed, lifetime } = session
            .handle(
                &allocated(
                    second[8..20].try_into().expect("a 12-byte transaction id"),
                    600,
                ),
                start + RTO * 2,
            )
            .expect("the signed answer")
        else {
            panic!("not an allocation");
        };
        assert_eq!(lifetime, Duration::from_secs(600));
        assert_eq!(session.relayed(), Some(relayed));

        // The same rule for what follows: a permission's success without a tag, and one
        // signed over other bytes, are both dropped — the request stays in flight for its
        // retransmits — and the properly signed one is read.
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 5004);
        let request = session.create_permission(peer, start + RTO * 3);
        let transaction = request[8..20].try_into().expect("a 12-byte transaction id");
        let ok = msg_type(CREATE_PERMISSION, CLASS_SUCCESS);
        let unsigned = raw(ok, transaction, &[]);
        assert!(
            session.handle(&unsigned, start + RTO * 4).is_none(),
            "no tag, no answer"
        );
        assert!(session.pending.is_some(), "the request is still in flight");

        let mut tampered = with_integrity(raw(
            ok,
            transaction,
            &[(13u16, 600u32.to_be_bytes().to_vec())],
        ));
        tampered[HEADER + 7] ^= 0xFF;
        assert!(
            session.handle(&tampered, start + RTO * 4).is_none(),
            "a tag over other bytes is not the server's"
        );
        assert!(session.pending.is_some(), "the request is still in flight");

        let event = session
            .handle(&success(CREATE_PERMISSION, transaction), start + RTO * 4)
            .expect("the signed answer");
        assert!(
            matches!(event, TurnEvent::Permission(named) if named == peer),
            "the signed answer went through: {event:?}"
        );
        assert_eq!(
            session.permissions[&peer],
            start + RTO * 4,
            "the timer runs from the answer that verified"
        );
    }

    #[test]
    fn allocate_runs_the_challenge_and_names_the_relayed_address() {
        let start = Instant::now();
        let mut session = TurnSession::new(credentials());
        let first = session.allocate(start);
        assert!(request_type(&session, ALLOCATE, CLASS_REQUEST));
        // REQUESTED-TRANSPORT is the protocol byte, 17 for UDP, plus three reserved ones
        // (RFC 5766 §14.7); a length of one is answered 400 by a server that follows it.
        assert_eq!(
            attribute(&first, 23).as_deref(),
            Some(&[UDP, 0, 0, 0][..]),
            "REQUESTED-TRANSPORT is protocol plus three reserved bytes"
        );
        session.handle(
            &challenge(first[8..20].try_into().expect("a 12-byte transaction id")),
            start + RTO,
        );
        let second = session.pending_bytes();
        let text = String::from_utf8_lossy(&second).into_owned();
        assert!(text.contains("nonce-1"), "the nonce is missing");
        assert!(text.contains("turn.example.org"), "the realm is missing");
        assert!(text.contains("turn-key"), "the username is missing");
        assert!(request_type(&session, ALLOCATE, CLASS_REQUEST));

        let TurnEvent::Allocated { relayed, lifetime } = session
            .handle(
                &allocated(
                    second[8..20].try_into().expect("a 12-byte transaction id"),
                    600,
                ),
                start + RTO * 2,
            )
            .expect("the allocation answered")
        else {
            panic!("not an allocation");
        };
        assert_eq!(
            relayed,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 61_924)
        );
        assert_eq!(lifetime, Duration::from_secs(600));
        assert_eq!(session.relayed(), Some(relayed));
    }

    #[test]
    fn send_wraps_as_an_indication_until_the_channel_is_bound() {
        let start = Instant::now();
        let mut session = TurnSession::new(credentials());
        let first = session.allocate(start);
        session.handle(
            &challenge(first[8..20].try_into().expect("a 12-byte transaction id")),
            start + RTO,
        );
        let second = session.pending_bytes();
        session.handle(
            &allocated(
                second[8..20].try_into().expect("a 12-byte transaction id"),
                600,
            ),
            start + RTO * 2,
        );

        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 5004);
        let wrapped = session.send_to(peer, b"media");
        assert_eq!(
            u16::from_be_bytes([wrapped[0], wrapped[1]]),
            0x0016,
            "the send indication"
        );
        // The DATA value is five bytes and the datagram is padded to four with it: the
        // header length is a multiple of four and covers the datagram exactly (RFC 5389
        // §6, §15), or a conforming server drops the indication.
        let len = u16::from_be_bytes([wrapped[2], wrapped[3]]) as usize;
        assert_eq!(
            wrapped.len(),
            HEADER + len,
            "the length covers the datagram"
        );
        assert_eq!(len % 4, 0, "the length is a multiple of four");
        assert_eq!(
            attribute(&wrapped, 19).as_deref(),
            Some(&b"media"[..]),
            "the data"
        );
        // The attribute walks the same datagram, so the pad sits behind the value.
        let data_at = HEADER + 12 + 4;
        assert_eq!(&wrapped[data_at + 5..data_at + 8], &[0, 0, 0], "the pad");
        // An aligned payload needs no pad and ends the datagram.
        let aligned = session.send_to(peer, b"abcd");
        assert_eq!(&aligned[data_at..], b"abcd");
        assert_eq!(u16::from_be_bytes([aligned[2], aligned[3]]) % 4, 0);

        let permission = session.create_permission(peer, start + RTO * 2);
        assert!(request_type(&session, CREATE_PERMISSION, CLASS_REQUEST));
        session.handle(
            &success(
                CREATE_PERMISSION,
                permission[8..20]
                    .try_into()
                    .expect("a 12-byte transaction id"),
            ),
            start + RTO * 3,
        );

        let bind = session.channel_bind(peer, start + RTO * 3);
        assert!(request_type(&session, CHANNEL_BIND, CLASS_REQUEST));
        session.handle(
            &success(
                CHANNEL_BIND,
                bind[8..20].try_into().expect("a 12-byte transaction id"),
            ),
            start + RTO * 4,
        );

        let channel_data = session.send_to(peer, b"media");
        assert_eq!(
            u16::from_be_bytes([channel_data[0], channel_data[1]]) & 0xC000,
            0x4000
        );
        assert_eq!(&channel_data[4..9], b"media");

        let inbound = {
            let channel = u16::from_be_bytes([channel_data[0], channel_data[1]]);
            let mut buf = channel.to_be_bytes().to_vec();
            buf.extend_from_slice(&5u16.to_be_bytes());
            buf.extend_from_slice(b"relay");
            buf
        };
        let TurnEvent::Received(from, payload) = session
            .handle(&inbound, start + RTO * 4)
            .expect("channel data in")
        else {
            panic!("not a receive");
        };
        assert_eq!(from, peer);
        assert_eq!(payload, b"relay");
    }

    #[test]
    fn the_allocation_retries_until_the_server_answers() {
        let start = Instant::now();
        let mut session = TurnSession::new(credentials());
        let first = session.allocate(start);
        let again = session.poll(start + RTO).expect("the retransmit");
        assert_eq!(first, again, "the same bytes go out again");
    }

    #[test]
    fn the_allocation_fails_after_its_retries() {
        let start = Instant::now();
        let mut session = TurnSession::new(credentials());
        let _first = session.allocate(start);
        // The waits double (RFC 5389 §7.2.1): half a second in, then 1, 2, 4, 8, and 16
        // seconds between the six retransmits — and after the last one the eight-second
        // grace, so the transaction dies at 39.5 seconds, not at three.
        let mut at = start;
        let mut wait = RTO;
        for _ in 0..RETRIES {
            at += wait;
            session.poll(at).expect("a retransmit");
            wait *= 2;
        }
        at += FINAL_GRACE;
        assert!(session.poll(at).is_none(), "nothing left to send");
        assert!(session.failed());
    }

    #[test]
    fn the_allocation_refreshes_before_its_lifetime_runs_out() {
        let start = Instant::now();
        let mut session = TurnSession::new(credentials());
        let first = session.allocate(start);
        session.handle(
            &challenge(first[8..20].try_into().expect("a 12-byte transaction id")),
            start + RTO,
        );
        let second = session.pending_bytes();
        session.handle(
            &allocated(
                second[8..20].try_into().expect("a 12-byte transaction id"),
                120,
            ),
            start + RTO * 2,
        );

        // The handle happened at start + 2·RTO; the lifetime runs out 120 s minus 60 s after
        // that.
        let at = start + RTO * 2 + Duration::from_secs(120).saturating_sub(Duration::from_secs(60));
        let refresh = session.poll(at).expect("the refresh goes out");
        assert!(request_type(&session, REFRESH, CLASS_REQUEST));
        session.handle(
            &success(
                REFRESH,
                refresh[8..20].try_into().expect("a 12-byte transaction id"),
            ),
            at + RTO,
        );
    }

    #[test]
    fn the_permissions_and_channels_refresh_on_their_own_timers() {
        let start = Instant::now();
        let mut session = TurnSession::new(credentials());
        let first = session.allocate(start);
        session.handle(
            &challenge(first[8..20].try_into().expect("a 12-byte transaction id")),
            start + RTO,
        );
        let second = session.pending_bytes();
        session.handle(
            &allocated(
                second[8..20].try_into().expect("a 12-byte transaction id"),
                3600,
            ),
            start + RTO * 2,
        );

        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 5004);
        let permission = session.create_permission(peer, start + RTO * 2);
        session.handle(
            &success(
                CREATE_PERMISSION,
                permission[8..20]
                    .try_into()
                    .expect("a 12-byte transaction id"),
            ),
            start + RTO * 3,
        );
        let bind = session.channel_bind(peer, start + RTO * 3);
        session.handle(
            &success(
                CHANNEL_BIND,
                bind[8..20].try_into().expect("a 12-byte transaction id"),
            ),
            start + RTO * 4,
        );

        // Nothing is due right after the bindings were made.
        let value = session.poll(start + RTO * 4 + Duration::from_secs(1));
        assert!(
            value.is_none(),
            "poll answered nothing was due, but it sent {value:?}"
        );
    }

    #[test]
    fn transaction_ids_carry_no_constant_bytes_and_repeat_never() {
        // The ids used to be a counter, the clock's subsecond nanos, and the fixed bytes
        // "TURN": readable on the wire, and guessable enough to poison a relay. Sixteen in
        // a row now differ, and none still says TURN anywhere in its twelve bytes.
        let ids: Vec<[u8; 12]> = (0..16).map(|_| rand_transaction()).collect();
        for first in 0..ids.len() {
            for second in first + 1..ids.len() {
                assert_ne!(ids[first], ids[second], "two transactions shared an id");
            }
        }
        for id in &ids {
            for window in id.windows(4) {
                assert_ne!(window, &b"TURN"[..], "the id still carries the fixed tail");
            }
        }
    }

    #[test]
    fn a_permission_success_stamps_only_the_peer_it_was_for() {
        let start = Instant::now();
        let mut session = TurnSession::new(credentials());
        handshake(&mut session, start, 3600);

        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 5004);
        let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 5004);

        let first = session.create_permission(a, start + RTO * 2);
        let event = session.handle(
            &success(
                CREATE_PERMISSION,
                first[8..20].try_into().expect("a 12-byte transaction id"),
            ),
            start + RTO * 3,
        );
        assert!(
            matches!(event, Some(TurnEvent::Permission(peer)) if peer == a),
            "the success names the peer it was for: {event:?}"
        );
        assert_eq!(
            session.permissions[&a],
            start + RTO * 3,
            "the timer runs from the success, not from four minutes after the ask"
        );

        // A second peer joins two round-trips later; its success names it, and a's timer
        // stays where a's own success put it.
        let second = session.create_permission(b, start + RTO * 4);
        let event = session.handle(
            &success(
                CREATE_PERMISSION,
                second[8..20].try_into().expect("a 12-byte transaction id"),
            ),
            start + RTO * 5,
        );
        assert!(
            matches!(event, Some(TurnEvent::Permission(peer)) if peer == b),
            "the success names the peer it was for: {event:?}"
        );
        assert_eq!(
            session.permissions[&a],
            start + RTO * 3,
            "a's timer is untouched"
        );
        assert_eq!(session.permissions[&b], start + RTO * 5);

        // Four minutes after a's success, a alone is due: b's window starts one round-trip
        // later, and poll re-creates a, not whichever peer the map lists first.
        let at = start + RTO * 3 + Duration::from_secs(4 * 60) + Duration::from_millis(100);
        session.poll(at).expect("a's re-permission goes out");
        assert_eq!(
            session.pending.as_ref().expect("in flight").subject,
            Some(Subject::Permission(a)),
            "the re-create is for a"
        );
    }

    #[test]
    fn a_permission_queued_behind_a_refresh_still_goes_out() {
        let start = Instant::now();
        let mut session = TurnSession::new(credentials());
        handshake(&mut session, start, 120);

        // The lifetime of 120 s is due sixty seconds after the answer.
        let at = start + RTO * 2 + Duration::from_secs(60);
        let refresh = session.poll(at).expect("the refresh goes out");
        assert!(request_type(&session, REFRESH, CLASS_REQUEST));

        // The candidate arrives while the refresh is on the wire: it queues instead of
        // overwriting the refresh, and nothing of it goes out now.
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 5004);
        let queued = session.create_permission(peer, at + RTO);
        assert!(
            queued.is_empty(),
            "nothing goes out behind a pending request"
        );
        assert!(
            request_type(&session, REFRESH, CLASS_REQUEST),
            "the refresh is still the one in flight"
        );

        // The refresh is answered; the next poll sends the queued permission, not a lost
        // one.
        session.handle(
            &success(
                REFRESH,
                refresh[8..20].try_into().expect("a 12-byte transaction id"),
            ),
            at + RTO * 2,
        );
        session
            .poll(at + RTO * 2)
            .expect("the queued permission goes out");
        assert!(request_type(&session, CREATE_PERMISSION, CLASS_REQUEST));
        assert_eq!(
            session.pending.as_ref().expect("in flight").subject,
            Some(Subject::Permission(peer)),
            "it is the queued permission, in queue order"
        );
    }

    #[test]
    fn a_permission_timeout_drops_the_request_and_keeps_the_session() {
        let start = Instant::now();
        let mut session = TurnSession::new(credentials());
        handshake(&mut session, start, 3600);

        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 5004);
        let _request = session.create_permission(peer, start + RTO * 2);
        // The waits double (RFC 5389 §7.2.1), and after the last retransmit the eight-
        // second grace closes the transaction at 39.5 seconds.
        let mut at = start + RTO * 2;
        let mut wait = RTO;
        for _ in 0..RETRIES {
            at += wait;
            session.poll(at).expect("a retransmit");
            wait *= 2;
        }
        at += FINAL_GRACE;
        assert!(session.poll(at).is_none(), "the permission gives up");
        assert!(
            !session.failed(),
            "the session carries without the permission"
        );
        // The permission's timer re-armed at the timeout: poll does not hammer a server
        // that is not answering, and comes back on its own schedule.
        assert!(
            session.poll(at + Duration::from_secs(1)).is_none(),
            "not immediately again"
        );
        session
            .poll(at + Duration::from_secs(4 * 60) + Duration::from_secs(1))
            .expect("the re-create comes round on its timer");
        assert!(request_type(&session, CREATE_PERMISSION, CLASS_REQUEST));
    }

    #[test]
    fn a_short_lifetime_refreshes_at_half_instead_of_every_poll() {
        let start = Instant::now();
        let mut session = TurnSession::new(credentials());
        handshake(&mut session, start, 30);

        // Thirty seconds granted: a minute of margin cannot fit, so the halfway mark is
        // when the refresh goes out — not now, on every call.
        let due = start + RTO * 2 + Duration::from_secs(15);
        assert!(
            session.poll(due - Duration::from_secs(1)).is_none(),
            "half the grant is not up yet"
        );
        session.poll(due).expect("the refresh at half the lifetime");
        assert!(request_type(&session, REFRESH, CLASS_REQUEST));
    }

    #[test]
    fn an_ipv6_relayed_address_fails_the_session_instead_of_retrying() {
        let start = Instant::now();
        let mut session = TurnSession::new(credentials());
        let first = session.allocate(start);
        session.handle(
            &challenge(first[8..20].try_into().expect("a 12-byte transaction id")),
            start + RTO,
        );
        let second = session.pending_bytes();
        let event = session.handle(
            &allocated_ipv6(
                second[8..20].try_into().expect("a 12-byte transaction id"),
                600,
            ),
            start + RTO * 2,
        );
        assert!(
            matches!(event, Some(TurnEvent::TimedOut(_))),
            "the answer is a failure, not silence: {event:?}"
        );
        assert!(session.failed(), "the session says so");
        assert!(
            session.poll(start + RTO * 3).is_none(),
            "the same request does not go out again"
        );
    }

    #[test]
    fn datagrams_without_the_magic_cookie_or_a_matching_length_are_dropped() {
        let start = Instant::now();
        let mut session = TurnSession::new(credentials());
        let first = session.allocate(start);
        let transaction = first[8..20].try_into().expect("a 12-byte transaction id");

        let mut wrong_cookie = challenge(transaction);
        wrong_cookie[5] ^= 0xFF;
        assert!(
            session.handle(&wrong_cookie, start + RTO).is_none(),
            "not our cookie"
        );
        assert!(session.pending.is_some(), "the request is still in flight");

        let mut wrong_length = challenge(transaction);
        wrong_length[3] += 1;
        assert!(
            session.handle(&wrong_length, start + RTO).is_none(),
            "the length does not match the datagram"
        );
        assert!(session.pending.is_some());

        // The untouched answer still gets through.
        session.handle(&challenge(transaction), start + RTO);
        assert!(
            request_type(&session, ALLOCATE, CLASS_REQUEST),
            "the challenge was read"
        );
    }
}
