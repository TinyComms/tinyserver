//! Multi-stream video receive through the SFU on loopback with headless str0m clients.
//! Proves Issue #50: a viewer offering up to `Config::video_slots` receive video lines can
//! subscribe to a share plus several camera tiles at once, keyframe requests route per mid to
//! the right publisher layer, congestion drops tiles last-first before slot 0, publisher
//! stop/leave clears only its slot, and single-slot clients without `call.watch` behave as before.

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use common::*;
use sfu::client::{Client, VideoFrame};
use sfu::{Layer, Quality, Refused, Subscription, VideoKind, WatchTarget};
use tokio::time::Instant;

async fn join_multi(
    sfu: &mut Sfu,
    room_id: &str,
    user_id: &str,
    marker: u8,
    video_slots: usize,
) -> (Person, Vec<String>) {
    let client = Client::with_video_slots(SocketAddr::from((LOOPBACK, 0)), SLOTS, video_slots)
        .expect("multi-video client");
    let mids = client.video_mids();
    assert_eq!(mids.len(), video_slots);
    let person = join_with(sfu, client, room_id, user_id, marker).await;
    (person, mids)
}

fn sub_source(mid: &str, user_id: &str, kind: VideoKind, max: Quality) -> Subscription {
    Subscription {
        mid: mid.to_string(),
        target: WatchTarget::Source {
            user_id: user_id.to_string(),
            kind,
        },
        max,
    }
}

/// Waits until `person` has received at least one matching `(marker, layer)` frame on each
/// expected `(mid, marker, layer)` triple.
async fn sees_all(
    person: &Person,
    expected: &[(&str, u8, u8)],
) -> HashMap<String, Vec<VideoFrame>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut by_mid: HashMap<String, Vec<VideoFrame>> = HashMap::new();
    while Instant::now() < deadline {
        for frame in person.running.take_video() {
            by_mid.entry(frame.mid.clone()).or_default().push(frame);
        }
        let all_seen = expected.iter().all(|(mid, marker, layer)| {
            by_mid.get(*mid).is_some_and(|frames| {
                frames
                    .iter()
                    .any(|f| f.marker == *marker && f.layer == *layer)
            })
        });
        if all_seen {
            return by_mid;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("did not receive all expected streams {expected:?}; got {by_mid:?}");
}

#[tokio::test]
async fn viewer_receives_share_and_four_camera_tiles_and_routes_tile_pli() {
    let mut sfu = start(config());
    let a = join(&mut sfu, "r", "a", b'A').await;
    let b = join(&mut sfu, "r", "b", b'B').await;
    let c = join(&mut sfu, "r", "c", b'C').await;
    let d = join(&mut sfu, "r", "d", b'D').await;
    let (viewer, mids) = join_multi(&mut sfu, "r", "v", b'V', 5).await;

    // A shares and turns on camera; B, C, D turn on cameras.
    sfu.camera(&a, true).await;
    sfu.camera(&b, true).await;
    sfu.camera(&c, true).await;
    sfu.camera(&d, true).await;
    assert_eq!(sfu.share(&a, true).await, Ok(true));

    // Viewer subscribes: slot 0 = A's share, slots 1..4 = A, B, C, D cameras.
    // Even if a tile asks for `High`, tile slots are capped at `Low` in the first step.
    let subs = vec![
        sub_source(&mids[0], "a", VideoKind::Share, Quality::High),
        sub_source(&mids[1], "a", VideoKind::Camera, Quality::High),
        sub_source(&mids[2], "b", VideoKind::Camera, Quality::Low),
        sub_source(&mids[3], "c", VideoKind::Camera, Quality::Low),
        sub_source(&mids[4], "d", VideoKind::Camera, Quality::Low),
    ];
    assert_eq!(sfu.media.watch(&viewer.call_id, subs).await, Ok(()));

    let videos = sfu.videos_matching(&viewer.call_id, |v| v.len() == 5).await;
    assert_eq!(videos[0].mid, mids[0]);
    assert_eq!(videos[0].user_id, "a");
    assert_eq!(videos[0].kind, VideoKind::Share);
    assert_eq!(videos[0].layer, Layer::Share);
    // `video` mirrors slot 0.
    assert_eq!(
        sfu.video.get(&viewer.call_id).cloned().flatten(),
        Some(videos[0].clone())
    );
    for (idx, uid) in [(1, "a"), (2, "b"), (3, "c"), (4, "d")] {
        assert_eq!(videos[idx].mid, mids[idx]);
        assert_eq!(videos[idx].user_id, uid);
        assert_eq!(videos[idx].kind, VideoKind::Camera);
        assert_eq!(videos[idx].layer, Layer::Low, "tile {idx} must be low");
    }

    let expected = [
        (mids[0].as_str(), b'A', b's'),
        (mids[1].as_str(), b'A', b'l'),
        (mids[2].as_str(), b'B', b'l'),
        (mids[3].as_str(), b'C', b'l'),
        (mids[4].as_str(), b'D', b'l'),
    ];
    let by_mid = sees_all(&viewer, &expected).await;
    for (mid, marker, layer) in expected {
        let frames = &by_mid[mid];
        let first = frames
            .iter()
            .find(|f| f.marker == marker && f.layer == layer)
            .expect("matching frame");
        assert!(
            first.keyframe,
            "mid {mid} did not start on a keyframe: {frames:?}"
        );
    }

    // Wait past the SFU's 300 ms keyframe cooldown, then send a PLI on tile mid 2 (B's camera).
    tokio::time::sleep(Duration::from_millis(400)).await;
    let b_low_before = b.running.keyframes_asked_low();
    let c_before = c.running.keyframes_asked();
    viewer
        .running
        .request_keyframe(&mids[2])
        .expect("send PLI on tile mid");
    let deadline = Instant::now() + Duration::from_secs(3);
    while b.running.keyframes_asked_low() <= b_low_before {
        assert!(
            Instant::now() < deadline,
            "PLI on tile mid did not reach publisher B's low layer"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        c.running.keyframes_asked(),
        c_before,
        "PLI on B's tile must not hit C"
    );

    // Stopping C's camera clears only C's slot; the other four stay active.
    sfu.camera(&c, false).await;
    let after_stop = sfu
        .videos_matching(&viewer.call_id, |v| {
            v.len() == 4 && v.iter().all(|s| s.user_id != "c")
        })
        .await;
    assert_eq!(after_stop[0].mid, mids[0]);

    // D leaving clears D's slot cleanly.
    sfu.media.leave(&d.call_id);
    let after_leave = sfu
        .videos_matching(&viewer.call_id, |v| {
            v.len() == 3 && v.iter().all(|s| s.user_id != "d")
        })
        .await;
    assert_eq!(after_leave.len(), 3);

    // Subscribing with an empty list clears every video slot.
    assert_eq!(sfu.media.watch(&viewer.call_id, vec![]).await, Ok(()));
    sfu.videos_matching(&viewer.call_id, |v| v.is_empty()).await;
    assert_eq!(sfu.video.get(&viewer.call_id).cloned().flatten(), None);
}

#[tokio::test]
async fn congestion_drops_tiles_last_first_and_keeps_slot_zero_last() {
    let mut sfu = start(config());
    let a = join(&mut sfu, "r", "a", b'A').await;
    let b = join(&mut sfu, "r", "b", b'B').await;
    let c = join(&mut sfu, "r", "c", b'C').await;
    let (viewer, mids) = join_multi(&mut sfu, "r", "v", b'V', 4).await;

    sfu.camera(&a, true).await;
    sfu.camera(&b, true).await;
    sfu.camera(&c, true).await;
    assert_eq!(sfu.share(&a, true).await, Ok(true));

    // Start with plenty of bandwidth so all 4 slots are active.
    viewer.running.remb(Some(5000));
    let subs = vec![
        sub_source(&mids[0], "a", VideoKind::Share, Quality::High),
        sub_source(&mids[1], "a", VideoKind::Camera, Quality::Low),
        sub_source(&mids[2], "b", VideoKind::Camera, Quality::Low),
        sub_source(&mids[3], "c", VideoKind::Camera, Quality::Low),
    ];
    assert_eq!(sfu.media.watch(&viewer.call_id, subs).await, Ok(()));
    sfu.videos_matching(&viewer.call_id, |v| v.len() == 4).await;

    // Drop link to 1,700 kb/s: share (1,000) + tile 1 (350) + tile 2 (keep 250) fit; tile 3 (C) drops first.
    viewer.running.remb(Some(1700));
    let three = sfu.videos_matching(&viewer.call_id, |v| v.len() == 3).await;
    let active_mids: Vec<&str> = three.iter().map(|s| s.mid.as_str()).collect();
    assert_eq!(active_mids, vec![&mids[0], &mids[1], &mids[2]]);

    // Drop link to 950 kb/s: share stays (keep >= 800), all tiles drop.
    viewer.running.remb(Some(950));
    let one = sfu.videos_matching(&viewer.call_id, |v| v.len() == 1).await;
    assert_eq!(one[0].mid, mids[0]);
    assert_eq!(one[0].kind, VideoKind::Share);

    // Drop link to 600 kb/s: share drops last (< 800).
    viewer.running.remb(Some(600));
    sfu.videos_matching(&viewer.call_id, |v| v.is_empty()).await;

    // Recover link to 5,000 kb/s: all four come back.
    viewer.running.remb(Some(5000));
    let back = sfu.videos_matching(&viewer.call_id, |v| v.len() == 4).await;
    assert_eq!(back[0].mid, mids[0]);
}

#[tokio::test]
async fn watch_validation_and_offer_video_cap_refuse_invalid_requests() {
    let mut sfu = start(config());
    let a = join(&mut sfu, "r", "a", b'A').await;
    let (viewer, mids) = join_multi(&mut sfu, "r", "v", b'V', 3).await;

    // Too many video m-lines (2 send + 6 recv = 8 > default offer_video 7) -> BadSdp.
    let too_many = Client::with_video_slots(SocketAddr::from((LOOPBACK, 0)), SLOTS, 6)
        .expect("client with 6 video slots");
    assert_eq!(
        sfu.media.join("r", "x", too_many.offer()).await,
        Err(Refused::BadSdp)
    );

    // Unknown mid -> BadFrame.
    assert_eq!(
        sfu.media
            .watch(
                &viewer.call_id,
                vec![sub_source(
                    "no-such-mid",
                    "a",
                    VideoKind::Camera,
                    Quality::Low
                )],
            )
            .await,
        Err(Refused::BadFrame)
    );
    // Listener's own user_id -> BadFrame.
    assert_eq!(
        sfu.media
            .watch(
                &viewer.call_id,
                vec![sub_source(&mids[0], "v", VideoKind::Camera, Quality::Low)],
            )
            .await,
        Err(Refused::BadFrame)
    );
    // User not in room -> BadFrame.
    assert_eq!(
        sfu.media
            .watch(
                &viewer.call_id,
                vec![sub_source(
                    &mids[0],
                    "stranger",
                    VideoKind::Camera,
                    Quality::Low
                )],
            )
            .await,
        Err(Refused::BadFrame)
    );
    // Duplicate source across two mids -> BadFrame.
    assert_eq!(
        sfu.media
            .watch(
                &viewer.call_id,
                vec![
                    sub_source(&mids[0], "a", VideoKind::Camera, Quality::High),
                    sub_source(&mids[1], "a", VideoKind::Camera, Quality::Low),
                ],
            )
            .await,
        Err(Refused::BadFrame)
    );
    // Duplicate mid -> BadFrame.
    assert_eq!(
        sfu.media
            .watch(
                &viewer.call_id,
                vec![
                    sub_source(&mids[0], "a", VideoKind::Camera, Quality::High),
                    sub_source(&mids[0], "a", VideoKind::Share, Quality::High),
                ],
            )
            .await,
        Err(Refused::BadFrame)
    );
    // `auto` on a tile slot (slot 1) -> BadFrame.
    assert_eq!(
        sfu.media
            .watch(
                &viewer.call_id,
                vec![Subscription {
                    mid: mids[1].clone(),
                    target: WatchTarget::Auto,
                    max: Quality::Low,
                }],
            )
            .await,
        Err(Refused::BadFrame)
    );
    // `auto` on slot 0 works and follows today's rule.
    sfu.camera(&a, true).await;
    assert_eq!(
        sfu.media
            .watch(
                &viewer.call_id,
                vec![Subscription {
                    mid: mids[0].clone(),
                    target: WatchTarget::Auto,
                    max: Quality::High,
                }],
            )
            .await,
        Ok(())
    );
    let slot = sfu
        .video_for(&viewer.call_id, Some("a"))
        .await
        .expect("slot 0");
    assert_eq!(slot.mid, mids[0]);
    assert_eq!(slot.kind, VideoKind::Camera);
}

#[tokio::test]
async fn server_upload_budget_keeps_share_and_drops_tile_streams() {
    let mut cfg = config();
    // 2 share streams (`b` auto + `viewer` slot 0 = 16,000) + up to 6 audio streams (300)
    // + `a`'s main camera on low (350) = 16,650 <= 16,700, while adding `viewer`'s 2 low tile
    // streams (+700) pushes it above 16,700 so tiles drop while the share stays.
    cfg.egress_kbps = Some(16_700);
    let mut sfu = start(cfg);
    let a = join(&mut sfu, "r", "a", b'A').await;
    let b = join(&mut sfu, "r", "b", b'B').await;
    let (viewer, mids) = join_multi(&mut sfu, "r", "v", b'V', 3).await;

    sfu.camera(&a, true).await;
    sfu.camera(&b, true).await;
    assert_eq!(sfu.share(&a, true).await, Ok(true));

    let subs = vec![
        sub_source(&mids[0], "a", VideoKind::Share, Quality::High),
        sub_source(&mids[1], "a", VideoKind::Camera, Quality::Low),
        sub_source(&mids[2], "b", VideoKind::Camera, Quality::Low),
    ];
    assert_eq!(sfu.media.watch(&viewer.call_id, subs).await, Ok(()));

    let videos = sfu
        .videos_matching(&viewer.call_id, |v| {
            v.len() == 1 && v[0].kind == VideoKind::Share
        })
        .await;
    assert_eq!(videos[0].mid, mids[0]);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let frames = seen_over(&viewer, Duration::from_millis(500)).await;
    assert!(!frames.is_empty());
    assert!(
        frames.iter().all(|f| f.mid == mids[0] && f.layer == b's'),
        "tiles should be withheld by server egress budget: {frames:?}"
    );
}
