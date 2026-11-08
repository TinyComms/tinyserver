//! A keyframe bigger than a layer's bucket still reaches the viewer. No database: the test
//! plays the API's part and turns a camera on with a renegotiation. The fixture frames are
//! 5,000 (`h`) and 1,458 (`l`) bytes; both layer budgets sit below that, so on the base this
//! fails: no layer ever admits a frame, and the viewer waits forever on an empty slot.

mod common;

use common::*;
use sfu::{Config, VideoKind};

fn buckets_below_the_fixture_frames() -> Config {
    let mut config = config();
    // 6 kb/s is a 750-byte burst: no fixture frame fits it, and twice the burst still fits
    // the `l` keyframe, which is what the debt rule lets through on half a bucket.
    config.camera_high_kbps = 6;
    config.camera_low_kbps = 6;
    config
}

#[tokio::test]
async fn a_keyframe_bigger_than_a_layers_bucket_still_reaches_the_viewer() {
    let mut sfu = start(buckets_below_the_fixture_frames());
    let a = join(&mut sfu, "r", "a", b'A').await;
    let b = join(&mut sfu, "r", "b", b'B').await;
    sfu.camera(&a, true).await;
    // No estimate and no REMB: the viewer starts on `l`, the layer whose bucket no frame
    // fits. Its keyframe still has to get through, or the tile stays on "Connecting".
    let slot = sfu.video_for(&b.call_id, Some("a")).await.expect("a slot");
    assert_eq!(slot.kind, VideoKind::Camera);
    let frames = sees(&b, b'A').await;
    assert!(frames[0].keyframe, "the first frame is not a keyframe");
    assert!(frames.iter().all(|frame| frame.mid == slot.mid));
}
