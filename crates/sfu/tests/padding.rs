//! A call with no video to show gets no padding and no probes, and the estimate still works
//! once there is video. TWCC on, as the server runs it, so alone in its own test binary like
//! `bwe.rs`.

mod common;

use std::time::Duration;

use common::*;
use tokio::time::Instant;

/// What a listener may get beyond voice over a few seconds, in bytes of RTP. str0m pads at
/// 50 kb/s, which is about 12 000 bytes a second on the wire.
const QUIET: u64 = 2000;

fn twcc() -> sfu::Config {
    let mut config = config();
    config.bwe_start_kbps = Some(1000);
    config
}

#[tokio::test]
async fn a_voice_call_gets_no_padding_and_every_frame() {
    let mut sfu = start(twcc());
    let a = join(&mut sfu, "r", "a", b'A').await;
    let b = join(&mut sfu, "r", "b", b'B').await;
    let b_slots = sfu.slots_for(&b.call_id, 1).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Nobody talks: nothing but RTCP and STUN.
    let (rtp, padding) = (b.running.rtp_received(), b.running.padding_received());
    tokio::time::sleep(Duration::from_secs(3)).await;
    let rtp = b.running.rtp_received() - rtp;
    let after = b.running.padding_received();
    let (packets, bytes) = (after.0 - padding.0, after.1 - padding.1);
    println!("silent, 3 s: {rtp} bytes of RTP, {packets} padding packets, {bytes} bytes");
    assert!(rtp < QUIET, "{rtp} bytes of RTP to a silent listener");

    // One talks, past a 5 s probe: every frame, evenly, and still no padding.
    a.running.sending(true);
    hears(&b, &mid_of(&b_slots, "a"), b'A').await;
    // The client first sends the frames it owes for the silence, all at once.
    tokio::time::sleep(Duration::from_millis(500)).await;
    b.running.take_heard_at();
    b.running.take_payloads();
    let padding = b.running.padding_received();
    tokio::time::sleep(Duration::from_secs(7)).await;
    let heard = b.running.take_heard_at();
    // Each frame carries its number after the TOC and marker bytes.
    let numbers: Vec<u64> = b
        .running
        .take_payloads()
        .iter()
        .filter_map(|(_, frame)| Some(u64::from_be_bytes(frame.get(2..10)?.try_into().ok()?)))
        .collect();
    let after = b.running.padding_received();
    let (packets, bytes) = (after.0 - padding.0, after.1 - padding.1);
    let gap = heard
        .windows(2)
        .map(|pair| pair[1].duration_since(pair[0]))
        .max()
        .unwrap_or(Duration::MAX);
    println!(
        "talking, 7 s: {} frames, longest gap {gap:?}, {packets} padding packets, {bytes} bytes",
        heard.len()
    );
    assert!(heard.len() >= 340, "{} frames in 7 s", heard.len());
    assert!(numbers.len() >= 340, "{} numbered frames", numbers.len());
    let missed = numbers.windows(2).filter(|pair| pair[1] != pair[0] + 1);
    assert_eq!(missed.count(), 0, "frames missing or out of order");
    assert!(gap < Duration::from_millis(60), "a gap of {gap:?}");
    assert!(bytes < QUIET, "{bytes} bytes of padding under voice");
}

/// After voice alone the estimate has had nothing to measure. A camera starts where a new
/// listener's does, on `l` and on a keyframe, and keeps coming.
#[tokio::test]
async fn a_camera_after_voice_alone_starts_on_l() {
    let mut sfu = start(twcc());
    let a = join(&mut sfu, "r", "a", b'A').await;
    let b = join(&mut sfu, "r", "b", b'B').await;
    a.running.sending(true);
    tokio::time::sleep(Duration::from_secs(3)).await;
    sfu.camera(&a, true).await;
    let first = sees(&b, b'A').await;
    assert_eq!(first[0].layer, b'l', "{first:?}");
    assert!(first[0].keyframe);
    let seen = seen_over(&b, Duration::from_millis(1500)).await;
    assert!(seen.len() >= 30, "{} frames", seen.len());
}

/// The estimate still climbs to `h` after voice alone. Not in the default run, as in `bwe.rs`:
/// `cargo test -p sfu --test padding -- --ignored`.
#[tokio::test]
#[ignore = "depends on how busy the machine is"]
async fn the_estimate_climbs_to_h_after_voice_alone() {
    let mut sfu = start(twcc());
    let a = join(&mut sfu, "r", "a", b'A').await;
    let b = join(&mut sfu, "r", "b", b'B').await;
    a.running.sending(true);
    tokio::time::sleep(Duration::from_secs(3)).await;
    sfu.camera(&a, true).await;
    let from = Instant::now();
    let deadline = from + Duration::from_secs(10);
    loop {
        let seen = seen_over(&b, Duration::from_millis(250)).await;
        if seen.iter().any(|frame| frame.layer == b'h') {
            println!("reached h {:?} after the camera", from.elapsed());
            return;
        }
        assert!(Instant::now() < deadline, "the estimate never reached h");
    }
}
