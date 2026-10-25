//! str0m's TWCC bandwidth estimate choosing the layer, on loopback. Alone in its own test
//! binary, because the estimate drops when the machine is busy with other tests.

mod common;

use std::time::Duration;

use common::*;
use tokio::time::Instant;

/// TWCC on, as the server runs it. The estimate starts below `h`, so a listener starts on
/// `l`, and one whose REMB says 500 kb/s stays there.
#[tokio::test]
async fn a_listener_starts_on_l_and_a_slow_remb_keeps_it_there() {
    let mut config = config();
    config.bwe_start_kbps = Some(1000);
    let mut sfu = start(config);
    let a = join(&mut sfu, "r", "a", b'A').await;
    let fast = join(&mut sfu, "r", "fast", b'F').await;
    let slow = join(&mut sfu, "r", "slow", b'S').await;
    slow.running.remb(Some(500));
    sfu.camera(&a, true).await;
    let first = sees(&fast, b'A').await;
    assert_eq!(first[0].layer, b'l', "{first:?}");
    assert!(first[0].keyframe);
    sees(&slow, b'A').await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let held = seen_over(&slow, Duration::from_millis(1500)).await;
    assert!(!held.is_empty());
    assert!(held.iter().all(|frame| frame.layer == b'l'), "{held:?}");
}

/// The estimate climbs to `h` by probing. About 250 ms on loopback on an idle laptop, and
/// not at all with every core busy, so it is not in the default run:
/// `cargo test -p sfu --test bwe -- --ignored`.
#[tokio::test]
#[ignore = "depends on how busy the machine is"]
async fn the_estimate_climbs_to_h() {
    let mut config = config();
    config.bwe_start_kbps = Some(1000);
    let mut sfu = start(config);
    let a = join(&mut sfu, "r", "a", b'A').await;
    let b = join(&mut sfu, "r", "b", b'B').await;
    sfu.camera(&a, true).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let seen = seen_over(&b, Duration::from_millis(250)).await;
        if seen.iter().any(|frame| frame.layer == b'h') {
            return;
        }
        assert!(Instant::now() < deadline, "the estimate never reached h");
    }
}
