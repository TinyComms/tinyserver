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

use std::collections::HashMap;
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
    /// The server never answered a request within its retries.
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
/// MESSAGE-INTEGRITY carries a 20-byte SHA-1 HMAC behind its four-byte header.
const INTEGRITY_LEN: usize = 24;
const CHANNEL_MIN: u16 = 0x4000;
const UDP: u8 = 17;
/// Channels re-bind a minute before the server would drop the binding at ten minutes.
const REBIND_AFTER: Duration = Duration::from_secs(9 * 60);
/// Permissions re-create a minute before the server drops them at five minutes.
const REPERMISSION_AFTER: Duration = Duration::from_secs(4 * 60);
const RETRIES: u32 = 5;
/// A fixed retransmit interval for now; RFC 5389 §7.2.1's exponential backoff is a later
/// refinement.
const RTO: Duration = Duration::from_millis(500);
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

fn rand_transaction() -> [u8; 12] {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let mut out = [0u8; 12];
    out[..4].copy_from_slice(&COUNTER.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    out[4..8].copy_from_slice(&nanos.to_be_bytes());
    out[8..].copy_from_slice(b"TURN");
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

/// What a response carried.
#[derive(Debug, Default)]
struct Attributes {
    relayed: Option<SocketAddr>,
    peer: Option<SocketAddr>,
    lifetime: Option<u64>,
    nonce: Option<Vec<u8>>,
    realm: Option<String>,
    data: Option<Vec<u8>>,
    error: Option<(u16, String)>,
}

fn parse_attributes(data: &[u8]) -> Option<Attributes> {
    let mut found = Attributes::default();
    let mut at = 0;
    while at + 4 <= data.len() {
        let kind = u16::from_be_bytes([data[at], data[at + 1]]);
        let len = u16::from_be_bytes([data[at + 2], data[at + 3]]) as usize;
        let value = data.get(at + 4..at + 4 + len)?;
        match kind {
            22 => found.relayed = xor_out(value),
            18 => found.peer = xor_out(value),
            13 => found.lifetime = Some(u32::from_be_bytes(value.try_into().ok()?) as u64),
            21 => found.nonce = Some(value.to_vec()),
            20 => found.realm = Some(String::from_utf8_lossy(value).into_owned()),
            19 => found.data = Some(value.to_vec()),
            9 => {
                let code = value
                    .get(2..4)
                    .and_then(|bytes| bytes.try_into().ok())
                    .map(|bytes| u16::from_be_bytes(bytes) & 0x3FF)
                    .unwrap_or(0);
                found.error = Some((
                    code,
                    String::from_utf8_lossy(value.get(4..).unwrap_or(b"")).into_owned(),
                ));
            }
            _ => {}
        }
        at += 4 + len.div_ceil(4) * 4;
    }
    Some(found)
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
    /// The channel this pending CHANNEL_BIND will bind, with its peer.
    pending_bind: Option<(u16, SocketAddr)>,
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
            pending_bind: None,
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
        self.send_request(ALLOCATE, vec![(23, vec![UDP])], now);
        self.pending_bytes()
    }

    /// CreatePermission for a peer address, as `call.candidate` asked, and its datagram.
    /// Refreshes are `poll`'s job.
    pub fn create_permission(&mut self, peer: SocketAddr, now: Instant) -> Vec<u8> {
        if !self.active() || !peer.is_ipv4() {
            return Vec::new();
        }
        let mut address = Vec::new();
        put_address(&mut address, 18, peer);
        self.send_request(CREATE_PERMISSION, vec![(18, address)], now);
        self.permissions.entry(peer).or_insert(now);
        self.pending_bytes()
    }

    /// ChannelBind for a peer address, so its media travels as channel data, and its
    /// datagram. Re-binds are `poll`'s job.
    pub fn channel_bind(&mut self, peer: SocketAddr, now: Instant) -> Vec<u8> {
        if !self.active() || !peer.is_ipv4() || self.peers.contains_key(&peer) {
            return Vec::new();
        }
        self.bind(peer, now);
        self.pending_bytes()
    }

    fn bind(&mut self, peer: SocketAddr, now: Instant) {
        let channel = self.peers.get(&peer).copied().unwrap_or_else(|| {
            let channel = self.next_channel;
            self.next_channel += 1;
            channel
        });
        let mut number = channel.to_be_bytes().to_vec();
        number.extend_from_slice(&2u16.to_be_bytes());
        let mut address = Vec::new();
        put_address(&mut address, 18, peer);
        self.send_request(CHANNEL_BIND, vec![(12, number), (18, address)], now);
        self.pending_bind = Some((channel, peer));
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
                buf.extend_from_slice(&19u16.to_be_bytes());
                buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                buf.extend_from_slice(payload);
                let len = (buf.len() - HEADER) as u16;
                buf[2..4].copy_from_slice(&len.to_be_bytes());
            }
        }
        buf
    }

    /// Re-sends what is pending, refreshes the allocation, re-creates permissions and re-binds
    /// channels when they are due, and reports the bytes to send. One thing at a time; the
    /// next call picks up where this left off.
    pub fn poll(&mut self, now: Instant) -> Option<Vec<u8>> {
        if self.failed {
            return None;
        }
        if let Some(pending) = &mut self.pending {
            if now >= pending.deadline {
                pending.tries += 1;
                if pending.tries > RETRIES {
                    self.pending = None;
                    self.failed = true;
                    return None;
                }
                pending.deadline = now + RTO;
                return Some(pending.bytes.clone());
            }
            return None;
        }
        if !self.active() {
            return None;
        }
        if now >= self.lifetime_until {
            self.send_request(REFRESH, vec![(13, 600u32.to_be_bytes().to_vec())], now);
            self.lifetime_until = now + Duration::from_secs(600);
            return Some(self.pending_bytes());
        }
        let mut due_permission: Option<SocketAddr> = None;
        for (peer, due) in &self.permissions {
            if now.saturating_duration_since(*due) >= REPERMISSION_AFTER {
                due_permission = Some(*peer);
            }
        }
        if let Some(peer) = due_permission {
            self.create_permission(peer, now);
            return Some(self.pending_bytes());
        }
        let mut rebind: Option<SocketAddr> = None;
        for (peer, bound) in self.channels.values() {
            if now.saturating_duration_since(*bound) >= REBIND_AFTER {
                rebind = Some(*peer);
            }
        }
        if let Some(peer) = rebind {
            self.bind(peer, now);
            return Some(self.pending_bytes());
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
                    let tries = pending.tries + 1;
                    if tries > RETRIES {
                        self.pending = None;
                        self.failed = true;
                        return Some(TurnEvent::TimedOut("challenged too often"));
                    }
                    self.nonce = attributes.nonce.clone().or(self.nonce.clone());
                    self.realm = attributes.realm.clone().or(self.realm.clone());
                    self.send_request(method, retry_attributes, now);
                    if let Some(retried) = self.pending.as_mut() {
                        retried.tries = tries;
                    }
                    Some(TurnEvent::Send(self.pending_bytes()))
                }
                _ => {
                    self.failed = true;
                    self.pending = None;
                    Some(TurnEvent::TimedOut("rejected"))
                }
            }
        } else {
            match method {
                ALLOCATE => {
                    let relayed = attributes.relayed?;
                    let lifetime = attributes.lifetime.unwrap_or(600);
                    self.relayed = Some(relayed);
                    self.lifetime_until = now + Duration::from_secs(lifetime.saturating_sub(60));
                    self.pending = None;
                    Some(TurnEvent::Allocated {
                        relayed,
                        lifetime: Duration::from_secs(lifetime),
                    })
                }
                REFRESH => {
                    let lifetime = attributes.lifetime.unwrap_or(600);
                    self.lifetime_until = now + Duration::from_secs(lifetime.saturating_sub(60));
                    self.pending = None;
                    None
                }
                CREATE_PERMISSION => {
                    self.pending = None;
                    self.permissions = self
                        .permissions
                        .keys()
                        .map(|peer| (*peer, now + REPERMISSION_AFTER))
                        .collect();
                    let peer = *self.permissions.keys().next()?;
                    Some(TurnEvent::Permission(peer))
                }
                CHANNEL_BIND => {
                    self.pending = None;
                    if let Some((channel, peer)) = self.pending_bind.take() {
                        self.channels.insert(channel, (peer, now));
                        self.peers.insert(peer, channel);
                        Some(TurnEvent::ChannelBound(peer))
                    } else {
                        None
                    }
                }
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

    /// Builds one request and makes it the pending one. Attributes go in first, credentials
    /// and integrity behind them, and the header length counts the integrity attribute as
    /// present, the RFC's way of signing everything before it. The integrity key for
    /// long-term credentials is MD5 over `username ":" realm ":" password` (RFC 5389
    /// §15.4), with the realm this session was challenged with.
    fn send_request(&mut self, method: u16, attributes: Vec<(u16, Vec<u8>)>, now: Instant) {
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
            let end = buf.len() + INTEGRITY_LEN;
            buf[2..4].copy_from_slice(&((end - HEADER) as u16).to_be_bytes());
            let material = format!(
                "{}:{}:{}",
                self.server.username, realm, self.server.credential
            );
            let digest = Md5::digest(material.as_bytes());
            let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, digest.as_ref());
            buf.extend_from_slice(&8u16.to_be_bytes());
            buf.extend_from_slice(&(INTEGRITY_LEN as u16).to_be_bytes());
            buf.extend_from_slice(hmac::sign(&key, &buf).as_ref());
        }
        self.pending = Some(Pending {
            method,
            attributes,
            bytes: buf,
            transaction,
            deadline: now + RTO,
            tries: 0,
        });
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
    fn challenge(transaction: [u8; 12]) -> Vec<u8> {
        let error = {
            let mut value = vec![0, 0];
            value.extend_from_slice(&401u16.to_be_bytes());
            value.extend_from_slice(b"Unauthorized");
            value
        };
        let parts = [
            (9u16, error),
            (20u16, b"turn.example.org".to_vec()),
            (21u16, b"nonce-1".to_vec()),
        ];
        answer(msg_type(ALLOCATE, CLASS_ERROR), transaction, &parts)
    }

    /// An allocate success with the relayed address and a lifetime.
    fn allocated(transaction: [u8; 12], lifetime: u32) -> Vec<u8> {
        let mut relayed = [0u8; 8];
        relayed[1] = 1;
        xor_into(
            &mut relayed,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 61_924),
        );
        let parts = [
            (22u16, relayed.to_vec()),
            (13u16, lifetime.to_be_bytes().to_vec()),
        ];
        answer(msg_type(ALLOCATE, CLASS_SUCCESS), transaction, &parts)
    }

    /// A success response for `method`, empty attributes.
    fn success(method: u16, transaction: [u8; 12]) -> Vec<u8> {
        answer(msg_type(method, CLASS_SUCCESS), transaction, &[])
    }

    fn answer(msg_type: u16, transaction: [u8; 12], parts: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&msg_type.to_be_bytes());
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(&MAGIC.to_be_bytes());
        buf.extend_from_slice(&transaction);
        for (kind, value) in parts {
            buf.extend_from_slice(&kind.to_be_bytes());
            let padded = value.len().div_ceil(4) * 4;
            buf.extend_from_slice(&(padded as u16).to_be_bytes());
            buf.extend_from_slice(value);
            buf.resize(buf.len() + padded - value.len(), 0);
        }
        let len = (buf.len() - HEADER) as u16;
        buf[2..4].copy_from_slice(&len.to_be_bytes());
        buf
    }

    fn request_type(session: &TurnSession, method: u16, class: u8) -> bool {
        let Some(pending) = &session.pending else {
            return false;
        };
        let type_ = u16::from_be_bytes([pending.bytes[0], pending.bytes[1]]);
        type_ == msg_type(method, class)
    }

    #[test]
    fn challenges_exhaust_the_retries_and_fail_the_session() {
        let start = Instant::now();
        let mut session = TurnSession::new(credentials());
        let mut request = session.allocate(start);
        // A server that keeps challenging: each 401 gets the re-request the session emits,
        // until the retry cap trips and the session fails instead of asking forever.
        for round in 0..RETRIES {
            let event = session.handle(
                &challenge(request[8..20].try_into().expect("a 12-byte transaction id")),
                start + RTO * (u32::from(round) + 1),
            );
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
    fn allocate_runs_the_challenge_and_names_the_relayed_address() {
        let start = Instant::now();
        let mut session = TurnSession::new(credentials());
        let first = session.allocate(start);
        assert!(request_type(&session, ALLOCATE, CLASS_REQUEST));
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
        assert!(
            wrapped.len() >= 30,
            "the indication lost its attributes: {}",
            wrapped.len()
        );
        assert!(wrapped.ends_with(b"media"));

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
        let mut at = start;
        for _ in 0..RETRIES {
            at += RTO;
            session.poll(at).expect("a retransmit");
        }
        at += RTO;
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
}
