//! Info-level SFU video state-change logs. Alone in its own test binary so it can hold the one
//! global tracing subscriber and assert the exact lines emitted at `info`.

mod common;

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use common::*;
use sfu::{Refused, VideoKind};

#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl Logs {
    fn lock(&self) -> MutexGuard<'_, Vec<u8>> {
        self.0.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    fn lines(&self) -> Vec<String> {
        String::from_utf8_lossy(&self.lock())
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn clear(&self) {
        self.lock().clear();
    }
}

impl std::io::Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.lock().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn video_state_changes_are_logged_at_info() {
    let logs = Logs::default();
    let writer = logs.clone();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .init();

    let mut sfu = start(config());
    let a = join(&mut sfu, "r", "a", b'A').await;
    let b = join(&mut sfu, "r", "b", b'B').await;
    let c = join(&mut sfu, "r", "c", b'C').await;

    logs.clear();

    // 1. A starts a share mid-call; B receives it.
    assert_eq!(sfu.share(&a, true).await, Ok(true));
    sfu.video_is(&b.call_id, "a", VideoKind::Share).await;
    sfu.video_is(&c.call_id, "a", VideoKind::Share).await;

    // 2. B tries to start a share while A holds it -> refused.
    assert_eq!(sfu.share(&b, true).await, Err(Refused::ShareTaken));

    // 3. Steady video flowing for 1 s should not repeat state-change lines.
    let before_steady = logs.lines().len();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let steady_lines = logs.lines();
    let steady_slot_lines = steady_lines[before_steady..]
        .iter()
        .filter(|line| line.contains("video slot") || line.contains("video publish"))
        .count();
    assert_eq!(
        steady_slot_lines,
        0,
        "unexpected repeated state-change lines while video is steady: {:?}",
        &steady_lines[before_steady..]
    );

    let after_share = logs.lines();
    let publish_idx = after_share
        .iter()
        .position(|line| {
            line.contains("video publish")
                && line.contains(&a.call_id)
                && line.contains("source=\"share\"")
                && line.contains("on=true")
        })
        .unwrap_or_else(|| panic!("missing video publish line in:\n{}", after_share.join("\n")));

    let slot_idx = after_share
        .iter()
        .position(|line| {
            line.contains("video slot")
                && !line.contains("video slot empty")
                && line.contains(&b.call_id)
                && line.contains(&format!("from={}", a.call_id))
                && line.contains("layer=\"share\"")
                && line.contains("why=\"share_started\"")
        })
        .unwrap_or_else(|| panic!("missing video slot line in:\n{}", after_share.join("\n")));

    assert!(
        publish_idx < slot_idx,
        "expected video publish before video slot"
    );

    assert!(
        after_share.iter().any(|line| {
            line.contains("share refused")
                && line.contains(&b.call_id)
                && line.contains("reason=\"share_taken\"")
        }),
        "missing share refused line in:\n{}",
        after_share.join("\n")
    );

    // 4. Deafen B: slot goes empty immediately, and after >3 s logs `video slot empty why=deafened`.
    logs.clear();
    sfu.media.state(&b.call_id, false, true);
    sfu.video_for(&b.call_id, None).await;

    let after_deafen = logs.lines();
    assert!(
        after_deafen.iter().any(|line| {
            line.contains("video slot")
                && !line.contains("video slot empty")
                && line.contains(&b.call_id)
                && line.contains("layer=\"none\"")
        }),
        "missing video slot layer=none line in:\n{}",
        after_deafen.join("\n")
    );

    // Wait past the 3 s threshold for `video slot empty`.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let lines = logs.lines();
        if lines.iter().any(|line| {
            line.contains("video slot empty")
                && line.contains(&b.call_id)
                && line.contains("why=\"deafened\"")
        }) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "missing video slot empty why=deafened line in:\n{}",
            lines.join("\n")
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Confirm `video slot empty` is not logged a second time while still deafened.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let empty_count = logs
        .lines()
        .iter()
        .filter(|line| line.contains("video slot empty") && line.contains(&b.call_id))
        .count();
    assert_eq!(empty_count, 1, "video slot empty should log only once");

    // 5. Stop A's share -> video publish on=false.
    assert_eq!(sfu.share(&a, false).await, Ok(false));
    let final_lines = logs.lines();
    assert!(
        final_lines.iter().any(|line| {
            line.contains("video publish")
                && line.contains(&a.call_id)
                && line.contains("source=\"share\"")
                && line.contains("on=false")
        }),
        "missing video publish on=false line in:\n{}",
        final_lines.join("\n")
    );
}
