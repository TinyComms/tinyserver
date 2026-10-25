//! ICE-TCP, the LAN candidate, stream caps, offer caps, and a flood, on loopback. No database.

mod common;

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use common::*;
use sfu::client::Client;
use sfu::Refused;
use tokio::time::Instant;

/// How a raw TCP stream to the SFU ended up.
#[derive(Debug, PartialEq, Eq)]
enum Fate {
    /// Still open after the wait.
    Open,
    /// The SFU closed it.
    Closed,
}

/// Reads until the SFU closes `stream` or `wait` passes.
fn fate(stream: &mut TcpStream, wait: Duration) -> Fate {
    let deadline = std::time::Instant::now() + wait;
    let mut buf = [0; 64];
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Fate::Open;
        }
        stream
            .set_read_timeout(Some(left))
            .expect("set a read timeout");
        match stream.read(&mut buf) {
            Ok(0) => return Fate::Closed,
            Ok(_) => {}
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Fate::Open;
            }
            Err(_) => return Fate::Closed,
        }
    }
}

/// Fates, off the test's runtime thread.
async fn fate_of(mut stream: TcpStream, wait: Duration) -> Fate {
    tokio::task::spawn_blocking(move || fate(&mut stream, wait))
        .await
        .expect("fate")
}

fn dial(sfu: &Sfu) -> TcpStream {
    TcpStream::connect(sfu.media.addr()).expect("connect over TCP")
}

#[tokio::test]
async fn a_client_with_only_tcp_hears_and_is_heard() {
    let mut sfu = start(config());
    let client = Client::tcp(LOOPBACK.into(), SLOTS).expect("TCP client");
    let offer = client.offer().to_string();
    assert!(offer.contains("tcptype active"), "{offer}");
    assert!(
        !offer.contains(" udp "),
        "the TCP client offered UDP: {offer}"
    );
    let a = join_with(&mut sfu, client, "r", "a", b'A').await;
    let b = join(&mut sfu, "r", "b", b'B').await;
    let a_slots = sfu.slots_for(&a.call_id, 1).await;
    let b_slots = sfu.slots_for(&b.call_id, 1).await;
    a.running.sending(true);
    b.running.sending(true);
    hears(&b, &mid_of(&b_slots, "a"), b'A').await;
    hears(&a, &mid_of(&a_slots, "b"), b'B').await;
}

#[tokio::test]
async fn two_tcp_clients_hear_each_other() {
    let mut sfu = start(config());
    let client = Client::tcp(LOOPBACK.into(), SLOTS).expect("TCP client");
    let a = join_with(&mut sfu, client, "r", "a", b'A').await;
    let client = Client::tcp(LOOPBACK.into(), SLOTS).expect("TCP client");
    let b = join_with(&mut sfu, client, "r", "b", b'B').await;
    let b_slots = sfu.slots_for(&b.call_id, 1).await;
    a.running.sending(true);
    hears(&b, &mid_of(&b_slots, "a"), b'A').await;
}

#[tokio::test]
async fn the_answer_has_udp_and_tcp_candidates_and_the_lan_ones_when_set() {
    let sfu = start(config());
    let client = Client::new(SocketAddr::from((LOOPBACK, 0)), SLOTS).expect("client");
    let answer = sfu
        .media
        .join("r", "a", client.offer())
        .await
        .expect("answer");
    let candidates: Vec<&str> = answer
        .sdp
        .lines()
        .filter(|line| line.starts_with("a=candidate"))
        .collect();
    assert_eq!(candidates.len(), 2, "{candidates:?}");
    let port = sfu.media.addr().port().to_string();
    assert!(candidates
        .iter()
        .any(|c| c.contains(" udp ") && c.contains(&port)));
    assert!(
        candidates
            .iter()
            .any(|c| c.contains(" tcp ") && c.contains(&port) && c.contains("tcptype passive")),
        "{candidates:?}"
    );
    assert_eq!(sfu.media.transports(), ["udp", "tcp"]);

    let lan = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let mut with_lan = config();
    with_lan.lan_ip = Some(lan);
    let sfu = start(with_lan);
    let answer = sfu
        .media
        .join("r", "a", client.offer())
        .await
        .expect("answer");
    let on_lan: Vec<&str> = answer
        .sdp
        .lines()
        .filter(|line| line.starts_with("a=candidate") && line.contains("192.0.2.10"))
        .collect();
    assert_eq!(on_lan.len(), 2, "{}", answer.sdp);
    assert!(on_lan.iter().any(|c| c.contains(" udp ")));
    assert!(on_lan.iter().any(|c| c.contains(" tcp ")));
    assert_eq!(sfu.media.transports(), ["udp", "tcp", "lan"]);
}

#[tokio::test]
async fn tcp_streams_over_a_cap_are_closed() {
    let quiet = Duration::from_millis(500);
    for cap in ["per source", "in all", "unverified"] {
        let mut config = config();
        match cap {
            "per source" => config.tcp_per_source = 2,
            "in all" => config.tcp_streams = 2,
            _ => config.tcp_unverified = 2,
        }
        let sfu = start(config);
        let first = dial(&sfu);
        let second = dial(&sfu);
        let third = dial(&sfu);
        assert_eq!(
            fate_of(third, Duration::from_secs(2)).await,
            Fate::Closed,
            "{cap}"
        );
        assert_eq!(fate_of(first, quiet).await, Fate::Open, "{cap}");
        assert_eq!(fate_of(second, quiet).await, Fate::Open, "{cap}");
    }
}

#[tokio::test]
async fn a_tcp_stream_without_stun_is_closed() {
    let mut config = config();
    config.tcp_handshake = Duration::from_millis(500);
    let sfu = start(config);
    let started = Instant::now();
    let silent = dial(&sfu);
    assert_eq!(fate_of(silent, Duration::from_secs(3)).await, Fate::Closed);
    assert!(started.elapsed() >= Duration::from_millis(400), "too soon");

    // An RTP-looking frame first.
    let mut rtp = dial(&sfu);
    rtp.write_all(&[0, 4, 0x80, 0, 0, 1]).expect("write");
    assert_eq!(fate_of(rtp, Duration::from_millis(300)).await, Fate::Closed);
    // A length over the frame cap.
    let mut big = dial(&sfu);
    big.write_all(&[0xff, 0xff, 0, 1]).expect("write");
    assert_eq!(fate_of(big, Duration::from_millis(300)).await, Fate::Closed);
    // A zero length.
    let mut empty = dial(&sfu);
    empty.write_all(&[0, 0]).expect("write");
    assert_eq!(
        fate_of(empty, Duration::from_millis(300)).await,
        Fate::Closed
    );
}

#[tokio::test]
async fn an_idle_tcp_stream_is_closed() {
    let mut config = config();
    config.tcp_handshake = Duration::from_secs(30);
    config.tcp_idle = Duration::from_millis(500);
    let sfu = start(config);
    let started = Instant::now();
    let mut stream = dial(&sfu);
    // Half a frame is not traffic.
    stream.write_all(&[0, 20, 0]).expect("write");
    assert_eq!(fate_of(stream, Duration::from_secs(3)).await, Fate::Closed);
    assert!(started.elapsed() >= Duration::from_millis(400), "too soon");
}

#[tokio::test]
async fn a_left_tcp_client_loses_its_stream() {
    let mut sfu = start(config());
    let client = Client::tcp(LOOPBACK.into(), SLOTS).expect("TCP client");
    let a = join_with(&mut sfu, client, "r", "a", b'A').await;
    let b = join(&mut sfu, "r", "b", b'B').await;
    let b_slots = sfu.slots_for(&b.call_id, 1).await;
    a.running.sending(true);
    hears(&b, &mid_of(&b_slots, "a"), b'A').await;
    sfu.media.leave(&a.call_id);
    sfu.slots_for(&b.call_id, 0).await;
    let after = heard_over(&b, Duration::from_millis(400)).await;
    assert!(after.is_empty(), "still forwarded: {after:?}");
}

#[tokio::test]
async fn offers_over_the_caps_are_bad_sdp() {
    let sfu = start(config());
    let many = Client::new(SocketAddr::from((LOOPBACK, 0)), 12).expect("client");
    assert_eq!(
        sfu.media.join("r", "a", many.offer()).await,
        Err(Refused::BadSdp),
        "13 audio m-lines"
    );
    let client = Client::new(SocketAddr::from((LOOPBACK, 0)), SLOTS).expect("client");
    let padded = format!("{}a=x:{}\r\n", client.offer(), "y".repeat(32 * 1024));
    assert_eq!(
        sfu.media.join("r", "a", &padded).await,
        Err(Refused::BadSdp),
        "over 32 KiB"
    );
    let data = format!(
        "{}m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n",
        client.offer()
    );
    assert_eq!(sfu.media.join("r", "a", &data).await, Err(Refused::BadSdp));
    let answer = sfu
        .media
        .join("r", "a", client.offer())
        .await
        .expect("answer");
    assert_eq!(
        sfu.media.offer(&answer.call_id, many.offer()).await,
        Err(Refused::BadSdp),
        "a renegotiation is capped too"
    );
}

#[tokio::test]
async fn a_flood_from_strangers_does_not_stop_a_call() {
    let mut sfu = start(config());
    let a = join(&mut sfu, "r", "a", b'A').await;
    let b = join(&mut sfu, "r", "b", b'B').await;
    let b_slots = sfu.slots_for(&b.call_id, 1).await;
    a.running.sending(true);
    hears(&b, &mid_of(&b_slots, "a"), b'A').await;

    let target = sfu.media.addr();
    let flood = tokio::task::spawn_blocking(move || {
        let sockets: Vec<UdpSocket> = (0..8)
            .map(|_| UdpSocket::bind((LOOPBACK, 0)).expect("bind"))
            .collect();
        // STUN-looking binding requests for nobody, and RTP from nobody.
        let mut stun = vec![0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42];
        stun.extend_from_slice(&[7; 12]);
        let rtp = [0x80; 200];
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut sent = 0u64;
        while std::time::Instant::now() < deadline {
            for socket in &sockets {
                let _ = socket.send_to(&stun, target);
                let _ = socket.send_to(&rtp, target);
                sent += 2;
            }
        }
        sent
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    hears(&b, &mid_of(&b_slots, "a"), b'A').await;
    let sent = flood.await.expect("flood");
    assert!(sent > 10_000, "the flood was only {sent} packets");
    hears(&b, &mid_of(&b_slots, "a"), b'A').await;
}
