//! Caps the sign-in posts one client can make: each `start` stores a pending sign-in, each
//! `token` tries a one-time code, and each `join` may ask the provider for a sign-up link.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{LazyLock, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{ConnectInfo, Request};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use sha2::{Digest, Sha256};

const PER_KEY: usize = 5;
/// No password hashing sits behind these any more, so the shared cap is looser than the
/// per-address one: a pending sign-in is one small row, and a code try is one indexed delete.
const GLOBAL: usize = 120;
const WINDOW: Duration = Duration::from_secs(60);

static START: LazyLock<Gate> = LazyLock::new(|| Gate::new(PER_KEY, GLOBAL, WINDOW));
static TOKEN: LazyLock<Gate> = LazyLock::new(|| Gate::new(PER_KEY, GLOBAL, WINDOW));
/// Tighter: each try that gets through may make a sign-up link at the provider.
static JOIN: LazyLock<Gate> = LazyLock::new(|| Gate::new(JOIN_PER_KEY, JOIN_GLOBAL, WINDOW));
const JOIN_PER_KEY: usize = 3;
const JOIN_GLOBAL: usize = 30;
/// The passkey ceremonies. A sign-in is two posts and a sign-up four, so a person who mistypes
/// a few times still gets through; each `begin` stores a row and each `finish` checks a
/// signature, so one address cannot make many.
static PASSKEY: LazyLock<Gate> = LazyLock::new(|| Gate::new(30, 600, WINDOW));
/// The calls that take something to guess or spend: a recovery code, a claim link. Tight.
static PASSKEY_SECRET: LazyLock<Gate> = LazyLock::new(|| Gate::new(8, 120, WINDOW));

/// The gate for a passkey path, and a name for the log.
fn passkey_gate(path: &str) -> Option<(&'static Gate, &'static str)> {
    match path {
        "/v1/auth/passkey/recover/begin" | "/v1/auth/passkey/recover/finish" => {
            Some((&PASSKEY_SECRET, "/v1/auth/passkey/recover"))
        }
        "/v1/auth/passkey/claim/peek"
        | "/v1/auth/passkey/claim/begin"
        | "/v1/auth/passkey/claim/finish" => Some((&PASSKEY_SECRET, "/v1/auth/passkey/claim")),
        path if path.starts_with("/v1/auth/passkey/") => Some((&PASSKEY, "/v1/auth/passkey")),
        _ => None,
    }
}

struct Gate {
    per_key: usize,
    global_limit: usize,
    window: Duration,
    keys: Mutex<HashMap<String, Vec<Instant>>>,
    global_hits: Mutex<Vec<Instant>>,
}

impl Gate {
    fn new(per_key: usize, global_limit: usize, window: Duration) -> Self {
        Self {
            per_key,
            global_limit,
            window,
            keys: Mutex::new(HashMap::new()),
            global_hits: Mutex::new(Vec::new()),
        }
    }

    fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut keys = lock(&self.keys);
        let mut global = lock(&self.global_hits);
        prune(&mut global, now, self.window);
        // Allowed hits are capped by the global limit, so this walk stays small.
        keys.retain(|_, hits| {
            prune(hits, now, self.window);
            !hits.is_empty()
        });
        let used = keys.get(key).map_or(0, Vec::len);
        if used >= self.per_key || global.len() >= self.global_limit {
            return false;
        }
        keys.entry(key.to_string()).or_default().push(now);
        global.push(now);
        true
    }
}

#[derive(Serialize)]
struct SlowDown {
    error: &'static str,
}

pub async fn guard(request: Request<Body>, next: Next) -> Response {
    let gate = match (request.method(), request.uri().path()) {
        (&Method::POST, "/v1/auth/start") => Some(&*START),
        (&Method::POST, "/v1/auth/token") => Some(&*TOKEN),
        (&Method::POST, "/v1/auth/join") => Some(&*JOIN),
        (&Method::POST, path) => passkey_gate(path).map(|(gate, _)| gate),
        _ => None,
    };
    if let Some(gate) = gate {
        let peer = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0.ip());
        if !gate.allow(&client_key(request.headers(), peer)) {
            let route = match request.uri().path() {
                "/v1/auth/start" => "/v1/auth/start",
                "/v1/auth/token" => "/v1/auth/token",
                "/v1/auth/join" => "/v1/auth/join",
                path => passkey_gate(path).map_or("unknown", |(_, route)| route),
            };
            tracing::warn!(route, "rate limited");
            if request.uri().path() == "/v1/auth/join" {
                return crate::auth::slow_down_page();
            }
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(SlowDown { error: "slow_down" }),
            )
                .into_response();
        }
    }
    next.run(request).await
}

fn client_key(headers: &HeaderMap, peer: Option<IpAddr>) -> String {
    let claimed = headers
        .get("cf-connecting-ip")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<IpAddr>().ok());
    // A header is only a claim. It counts when the connection it arrived on is from a proxy
    // we trust. A direct caller, however it fills the header in, is keyed by who it is.
    let address = match (peer, claimed) {
        (Some(peer), Some(claimed)) if trusted(peer) => Some(claimed),
        (Some(peer), _) => Some(peer),
        // No peer address at all: a test calling the router directly.
        (None, claimed) => claimed,
    };
    address.map_or_else(|| "direct".to_string(), keyed)
}

/// The key a client is counted under. The address itself is never stored: the map holds a
/// truncated SHA-256 of it under a secret made when the process starts and never written
/// anywhere, so a memory dump or a debugger shows buckets and not addresses. IPv6 counts by
/// its /64, which is what one subscriber holds, so one person cannot spend a whole prefix.
///
/// This is a privacy measure and not a secrecy one. There are only 2^32 IPv4 addresses, so
/// anyone who holds the secret can find which address made a bucket. The secret exists only
/// in this process's memory, and a bucket lasts one minute.
fn keyed(address: IpAddr) -> String {
    static SECRET: LazyLock<[u8; 32]> = LazyLock::new(|| {
        let mut secret = [0u8; 32];
        // Without randomness a fixed secret would make the key guessable, which is the one
        // outcome worse than a failed start. The process cannot sign anyone in either.
        getrandom::fill(&mut secret).expect("the operating system's random source");
        secret
    });
    let address = match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    };
    let mut hasher = Sha256::new();
    hasher.update(*SECRET);
    match address {
        IpAddr::V4(v4) => {
            hasher.update([4]);
            hasher.update(v4.octets());
        }
        IpAddr::V6(v6) => {
            hasher.update([6]);
            hasher.update(&v6.octets()[..8]);
        }
    }
    hasher
        .finalize()
        .iter()
        .take(8)
        .fold(String::with_capacity(16), |mut text, byte| {
            use std::fmt::Write;
            let _ = write!(text, "{byte:02x}");
            text
        })
}

/// Proxies whose `cf-connecting-ip` is believed. Unset means any private, loopback or
/// link-local peer: cloudflared on a Docker network, a reverse proxy on the same host. A
/// peer on the public internet is never believed.
static TRUSTED: OnceLock<Vec<Net>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Net {
    address: IpAddr,
    bits: u8,
}

impl Net {
    fn contains(self, candidate: IpAddr) -> bool {
        let (left, right) = match (self.address, candidate) {
            (IpAddr::V4(left), IpAddr::V4(right)) => {
                (u128::from(u32::from(left)), u128::from(u32::from(right)))
            }
            (IpAddr::V6(left), IpAddr::V6(right)) => (u128::from(left), u128::from(right)),
            _ => return false,
        };
        let width = if self.address.is_ipv4() { 32 } else { 128 };
        if self.bits == 0 {
            return true;
        }
        let shift = u32::from(width - self.bits);
        left >> shift == right >> shift
    }
}

/// `TINYSERVER_TRUSTED_PROXIES`: addresses or CIDR ranges, comma separated. `none` trusts no
/// proxy, so every client is keyed by its own connection.
pub fn trust_proxies(spec: &str) -> Result<(), String> {
    let mut nets = Vec::new();
    for part in spec
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        if part.eq_ignore_ascii_case("none") {
            continue;
        }
        let (address, bits) = part
            .split_once('/')
            .map_or((part, None), |(a, b)| (a, Some(b)));
        let address: IpAddr = address
            .parse()
            .map_err(|_| format!("{part} is not an address or range"))?;
        let width = if address.is_ipv4() { 32 } else { 128 };
        let bits = match bits {
            None => width,
            Some(bits) => bits
                .parse::<u8>()
                .ok()
                .filter(|bits| *bits <= width)
                .ok_or_else(|| format!("{part} has a bad prefix length"))?,
        };
        nets.push(Net { address, bits });
    }
    TRUSTED
        .set(nets)
        .map_err(|_| "trusted proxies were already set".to_string())
}

fn trusted(peer: IpAddr) -> bool {
    let peer = match peer {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    };
    match TRUSTED.get() {
        Some(nets) => nets.iter().any(|net| net.contains(peer)),
        None => is_local(peer),
    }
}

fn is_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                // Carrier-grade NAT space, which Tailscale uses.
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                // fc00::/7 unique local, fe80::/10 link local.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

fn prune(hits: &mut Vec<Instant>, now: Instant, window: Duration) {
    hits.retain(|hit| now.saturating_duration_since(*hit) < window);
}

#[cfg(test)]
mod tests {
    use super::{client_key, is_local, lock, Gate, Net};
    use axum::http::{HeaderMap, HeaderValue};
    use std::net::IpAddr;
    use std::time::Duration;

    #[test]
    fn one_address_stops_and_a_second_address_shares_the_global_cap() {
        let gate = Gate::new(2, 3, Duration::from_secs(60));
        assert!(gate.allow("a"));
        assert!(gate.allow("a"));
        assert!(!gate.allow("a"));
        assert!(gate.allow("b"));
        assert!(!gate.allow("b"));
    }

    #[test]
    fn an_address_whose_hits_aged_out_is_forgotten() {
        let gate = Gate::new(2, 30, Duration::from_millis(20));
        assert!(gate.allow("a"));
        assert!(gate.allow("b"));
        std::thread::sleep(Duration::from_millis(40));
        assert!(gate.allow("c"));
        assert_eq!(lock(&gate.keys).len(), 1);
    }

    #[test]
    fn a_denied_address_leaves_no_entry() {
        let gate = Gate::new(1, 1, Duration::from_secs(60));
        assert!(gate.allow("a"));
        assert!(!gate.allow("b"));
        assert_eq!(lock(&gate.keys).len(), 1);
    }

    fn claim(address: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", HeaderValue::from_static(address));
        headers
    }

    fn ip(address: &str) -> Option<IpAddr> {
        Some(address.parse().expect("address"))
    }

    #[test]
    fn no_address_at_all_is_one_shared_bucket() {
        assert_eq!(client_key(&HeaderMap::new(), None), "direct");
        assert_eq!(client_key(&claim("not an address"), None), "direct");
        assert_eq!(client_key(&claim("203.0.113.8; drop"), None), "direct");
    }

    #[test]
    fn a_direct_caller_cannot_choose_its_bucket_by_filling_in_the_header() {
        // Whoever connects from the public internet is counted as itself, so rotating the
        // header does not get a fresh allowance.
        let from = ip("198.51.100.7");
        let first = client_key(&claim("203.0.113.1"), from);
        let second = client_key(&claim("203.0.113.2"), from);
        assert_eq!(first, second);
        assert_eq!(first, client_key(&HeaderMap::new(), from));
        assert_ne!(first, client_key(&HeaderMap::new(), ip("198.51.100.8")));
    }

    #[test]
    fn a_private_proxy_is_believed_about_who_is_behind_it() {
        // cloudflared on the Docker network, a reverse proxy on the same host.
        for proxy in [
            "172.30.53.10",
            "10.0.0.5",
            "192.168.1.9",
            "127.0.0.1",
            "::1",
            "fd00::2",
        ] {
            let proxy = ip(proxy);
            assert_eq!(
                client_key(&claim("203.0.113.8"), proxy),
                client_key(&HeaderMap::new(), ip("203.0.113.8")),
                "{proxy:?}"
            );
            assert_ne!(
                client_key(&claim("203.0.113.8"), proxy),
                client_key(&claim("203.0.113.9"), proxy)
            );
        }
    }

    #[test]
    fn a_key_does_not_contain_the_address() {
        for address in ["203.0.113.8", "2001:db8:1:2:3:4:5:6"] {
            let key = client_key(&HeaderMap::new(), ip(address));
            assert_eq!(key.len(), 16, "{key}");
            assert!(key.chars().all(|c| c.is_ascii_hexdigit()), "{key}");
            for part in address.split(['.', ':']) {
                assert!(
                    part.len() < 4 || !key.contains(part),
                    "{key} holds a piece of {address}"
                );
            }
        }
    }

    #[test]
    fn one_subscriber_is_one_bucket_across_a_v6_prefix_and_a_v4_mapped_address() {
        assert_eq!(
            client_key(&HeaderMap::new(), ip("2001:db8:1:2:aaaa::1")),
            client_key(&HeaderMap::new(), ip("2001:db8:1:2:bbbb::9"))
        );
        assert_ne!(
            client_key(&HeaderMap::new(), ip("2001:db8:1:2::1")),
            client_key(&HeaderMap::new(), ip("2001:db8:1:3::1"))
        );
        assert_eq!(
            client_key(&HeaderMap::new(), ip("::ffff:203.0.113.8")),
            client_key(&HeaderMap::new(), ip("203.0.113.8"))
        );
    }

    #[test]
    fn a_proxy_range_matches_its_prefix_and_nothing_else() {
        let net = Net {
            address: "203.0.113.0".parse().expect("address"),
            bits: 24,
        };
        assert!(net.contains("203.0.113.200".parse().expect("address")));
        assert!(!net.contains("203.0.114.1".parse().expect("address")));
        assert!(!net.contains("::1".parse().expect("address")));
        let all = Net {
            address: "0.0.0.0".parse().expect("address"),
            bits: 0,
        };
        assert!(all.contains("8.8.8.8".parse().expect("address")));
        assert!(is_local("100.127.101.103".parse().expect("address")));
        assert!(!is_local("100.128.0.1".parse().expect("address")));
        assert!(!is_local("8.8.8.8".parse().expect("address")));
        assert!(!is_local("2606:4700::1".parse().expect("address")));
    }
}
