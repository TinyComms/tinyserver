//! Video routing without the network: the speaker who holds the floor, which simulcast layers
//! a listener's video slots get, what the upload budget allows, and the RTP time each video slot
//! carries across switches.

use std::time::{Duration, Instant};

use crate::VideoKind;

/// Nominal camera bitrates from `docs/calls.md`, in kb/s. The upload budget plans with them.
pub(crate) const HIGH_KBPS: u64 = 1200;
pub(crate) const LOW_KBPS: u64 = 350;
/// The nominal screen share bitrate, in kb/s: a desktop's share at its best, 1440p at 60 fps.
pub(crate) const SHARE_KBPS: u64 = 8000;
/// Cap on a listener's combined probe target across multiple subscribed video slots.
pub(crate) const MAX_PROBE_KBPS: u64 = 12_000;
/// One forwarded audio stream with its headers, in kb/s, for the upload budget.
pub(crate) const AUDIO_KBPS: u64 = 50;
/// A listener on `l` moves up to `h` at this much room for video, and back down below
/// `DOWN_KBPS`.
pub(crate) const UP_KBPS: u64 = 1600;
pub(crate) const DOWN_KBPS: u64 = 1300;
/// A share gives way to a camera below `SHARE_DOWN_KBPS`, and comes back at `SHARE_UP_KBPS`.
pub(crate) const SHARE_UP_KBPS: u64 = 1000;
pub(crate) const SHARE_DOWN_KBPS: u64 = 800;
/// Video pauses below `PAUSE_KBPS`, so it cannot starve the audio of a link that small, and
/// resumes on a keyframe at `RESUME_KBPS`.
pub(crate) const PAUSE_KBPS: u64 = 250;
pub(crate) const RESUME_KBPS: u64 = 450;
/// What a listener's bandwidth estimator probes for while it wants `h`.
pub(crate) const PROBE_KBPS: u64 = 2000;
/// How far past `RESUME_KBPS` it probes while paused, and the steps it moves in.
const RESUME_MARGIN_KBPS: u64 = 250;
const RESUME_STEP_KBPS: u64 = 50;
/// What the link was asked to carry, as a percentage of the estimate, before the estimate says
/// anything about the link. Below this the sender is what limits the estimate.
const BUSY_PERCENT: u64 = 80;
/// The loss that shows a link is full. Less is what a lossy link does at any rate.
const FULL_LOSS: f32 = 0.10;
/// The round trip above its lowest that shows a queue building. 30 ms of jitter each way reached
/// 184 ms in a real call, and a 250 ms queue 205 ms.
const FULL_QUEUE: Duration = Duration::from_millis(200);
/// The least video, in kb/s, worth blaming. Audio is never given up, so audio alone that fills a
/// lossy link's low estimate says nothing about what taking the video away would do.
const VIDEO_LEAST: u64 = 50;
/// How many holds the wait before trying again after a withdrawal can grow to.
const RETRY_MOST: u32 = 12;
/// A layer with no frame for this long is not chosen while the other one is sending.
pub(crate) const STALE: Duration = Duration::from_secs(1);
/// Keyframe requests to one layer of one publisher go out at most this often.
pub(crate) const KEYFRAME_EVERY: Duration = Duration::from_millis(300);
/// The same while the layer is over budget: asking faster than a keyframe can fit only makes
/// the encoder send more.
pub(crate) const KEYFRAME_BROKEN_EVERY: Duration = Duration::from_secs(1);
/// A challenger takes the floor after being the loudest speaker this long.
pub(crate) const TAKE_FLOOR: Duration = Duration::from_millis(800);
/// While the holder still speaks, a challenger must be this much louder, in dB.
pub(crate) const FLOOR_MARGIN: f32 = 6.0;
/// The 90 kHz RTP clock of every video codec.
const VIDEO_HZ: u64 = 90_000;

/// What a paused listener probes for, to find `RESUME_KBPS` above the `audio_kbps` it gets. The
/// estimate settles about here, so a fixed target would stop short of it in a talkative room.
pub(crate) fn resume_probe_kbps(audio_kbps: u64) -> u64 {
    let target = RESUME_KBPS + RESUME_MARGIN_KBPS + audio_kbps;
    target.div_ceil(RESUME_STEP_KBPS) * RESUME_STEP_KBPS
}

/// One simulcast layer of a camera, or a share's one layer. `h` is high, `l` is low; a
/// camera without rids is high.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    High,
    Low,
    Share,
}

impl Layer {
    pub(crate) fn of_rid(rid: Option<&str>) -> Self {
        match rid {
            Some("l") => Self::Low,
            _ => Self::High,
        }
    }

    pub(crate) fn index(self) -> usize {
        match self {
            Self::High => 0,
            Self::Low => 1,
            Self::Share => 2,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::High => "h",
            Self::Low => "l",
            Self::Share => "share",
        }
    }

    /// The camera's other layer. A share has only one.
    pub(crate) fn other(self) -> Self {
        match self {
            Self::High => Self::Low,
            Self::Low => Self::High,
            Self::Share => Self::Share,
        }
    }
}

/// What video a listener can use: theirs from `call.quality`, a subscription's `max`, or the
/// server's from its upload budget. `Off` is audio only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Quality {
    Off,
    Low,
    High,
}

/// One video slot's demand for [`allocate`]: stream kind and maximum layer allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Want {
    pub kind: VideoKind,
    pub max: Quality,
}

/// Allocates a listener's available video room (`room_kbps`, after audio) across subscribed slots
/// in priority order: slot 0 first, then tile slots in the order subscribed. Under congestion the
/// last tile is dropped first and slot 0 last. Uses per-step up/down hysteresis so streams do not
/// flap around a threshold.
pub(crate) fn allocate(
    room_kbps: u64,
    wants: &[Want],
    held: &[Option<Layer>],
) -> Vec<Option<Layer>> {
    let mut left = room_kbps;
    let mut starved = false;
    let mut out = Vec::with_capacity(wants.len());
    for (idx, want) in wants.iter().enumerate() {
        let prev = held.get(idx).copied().flatten();
        if want.max == Quality::Off {
            out.push(None);
            continue;
        }
        if starved {
            out.push(None);
            continue;
        }
        match want.kind {
            VideoKind::Share => {
                let need = if prev == Some(Layer::Share) {
                    SHARE_DOWN_KBPS
                } else {
                    SHARE_UP_KBPS
                };
                if left >= need {
                    left = left.saturating_sub(SHARE_UP_KBPS);
                    out.push(Some(Layer::Share));
                } else {
                    starved = true;
                    out.push(None);
                }
            }
            VideoKind::Camera => {
                if want.max == Quality::High {
                    let high_need = if prev == Some(Layer::High) {
                        DOWN_KBPS
                    } else {
                        UP_KBPS
                    };
                    if left >= high_need {
                        left = left.saturating_sub(HIGH_KBPS);
                        out.push(Some(Layer::High));
                        continue;
                    }
                }
                let low_need = if prev.is_some() {
                    PAUSE_KBPS
                } else {
                    RESUME_KBPS
                };
                if left >= low_need {
                    left = left.saturating_sub(LOW_KBPS);
                    out.push(Some(Layer::Low));
                } else {
                    starved = true;
                    out.push(None);
                }
            }
        }
    }
    out
}

/// Allocation before any estimate or REMB has arrived: shares are always tried, cameras start on
/// `l`, and `Quality::Off` gets nothing.
pub(crate) fn allocate_unproven(wants: &[Want]) -> Vec<Option<Layer>> {
    wants
        .iter()
        .map(|want| {
            if want.max == Quality::Off {
                None
            } else {
                match want.kind {
                    VideoKind::Share => Some(Layer::Share),
                    VideoKind::Camera => Some(Layer::Low),
                }
            }
        })
        .collect()
}

/// Whether a link is really full. An estimate alone cannot say: it follows what is sent, so a
/// still screen or a quiet call reads as a slow link. So the link must have been asked for about
/// what the estimate says it holds, and must show it: packets lost, or a queue building. str0m
/// has no way to read its own pacer's queue, so the queue is the one on the path. Rates are in
/// kb/s, `loss` the share lost, and `queue` the round trip above its lowest. One second's look:
/// a lossy, jittery link can show this for a second, so it counts only twice running.
pub(crate) fn congested(
    audio: u64,
    video: u64,
    estimate: Option<u64>,
    loss: Option<f32>,
    queue: Option<Duration>,
) -> bool {
    let sent = audio + video;
    let busy = estimate.is_some_and(|estimate| sent * 100 >= estimate * BUSY_PERCENT);
    let full = loss.is_some_and(|loss| loss >= FULL_LOSS)
        || queue.is_some_and(|queue| queue >= FULL_QUEUE);
    video >= VIDEO_LEAST && busy && full
}

/// One look at a listener's link, each in kb/s less the audio it gets.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Reading {
    /// What the receiver reported itself, which needs no evidence.
    pub told: Option<u64>,
    /// str0m's estimate.
    pub estimate: Option<u64>,
    /// See [`congested`].
    pub congested: bool,
}

/// What was taken from a listener, and when it is tried again.
#[derive(Debug, Clone, Copy)]
struct Withdrawn {
    from: Option<u64>,
    retry: Instant,
}

/// Follows how much video room, in kb/s beside audio, one listener's link can carry. Down at once
/// on evidence, because a full link is losing audio now, and never on an estimate alone. Up as
/// soon as an estimate has held for a hold, so video does not flap on a link that only looks
/// better for a moment. Whatever was taken comes back to be tried again after a wait that grows
/// while it keeps failing, so no listener is left without video because of how a link once looked.
#[derive(Debug, Clone, Default)]
pub(crate) struct Link {
    /// Proven room for video in kb/s. `None` until there is word of that: `l`, and any share.
    room: Option<u64>,
    rising: Option<Instant>,
    withdrawn: Option<Withdrawn>,
    /// The wait after the last withdrawal, and when what it took was last tried again.
    wait: Duration,
    tried: Option<Instant>,
}

impl Link {
    pub fn update(&mut self, reading: Reading, hold: Duration, now: Instant) -> Option<u64> {
        let room = match (reading.told, reading.estimate) {
            (Some(told), Some(estimate)) => Some(told.min(estimate)),
            (told, estimate) => told.or(estimate),
        };
        let Some(room) = room else {
            return self.retry(reading, now);
        };
        let limit = if reading.congested {
            Some(room)
        } else {
            reading.told
        };
        if let Some(limit) = limit {
            match self.room {
                Some(held) if limit < held => {
                    self.withdraw(limit, hold, now);
                    return self.room;
                }
                None if reading.congested => {
                    self.withdraw(limit, hold, now);
                    return self.room;
                }
                None => {
                    self.room = Some(limit);
                }
                _ => {}
            }
        }
        let Some(cur) = self.room else {
            // Good news needs no wait the first time. Anything less says nothing yet.
            if room >= SHARE_DOWN_KBPS {
                self.room = Some(room);
            }
            return self.room;
        };
        if room <= cur {
            self.rising = None;
            return self.retry(reading, now);
        }
        let since = *self.rising.get_or_insert(now);
        if now.saturating_duration_since(since) >= hold {
            self.room = Some(room);
            self.rising = None;
            if self
                .withdrawn
                .is_some_and(|gone| gone.from.is_none_or(|from| from <= room))
            {
                self.withdrawn = None;
            }
        }
        self.room
    }

    /// Takes the link down to `room`, to be tried again later, sooner if it held for a while.
    fn withdraw(&mut self, room: u64, hold: Duration, now: Instant) {
        let failing = self
            .tried
            .is_some_and(|at| now.saturating_duration_since(at) < self.wait * 2);
        self.wait = if failing {
            (self.wait * 2).min(hold * RETRY_MOST)
        } else {
            hold
        };
        let from = self.withdrawn.map_or(self.room, |gone| gone.from);
        self.withdrawn = Some(Withdrawn {
            from,
            retry: now + self.wait,
        });
        self.room = Some(room);
        self.rising = None;
    }

    /// Puts back what was taken, if its wait is over and the receiver has not said otherwise.
    fn retry(&mut self, reading: Reading, now: Instant) -> Option<u64> {
        if let Some(gone) = self.withdrawn {
            let forbidden = reading
                .told
                .is_some_and(|told| gone.from.is_none_or(|from| told < from));
            if now >= gone.retry && !forbidden && !reading.congested {
                self.room = gone.from;
                self.withdrawn = None;
                self.tried = Some(now);
            }
        }
        self.room
    }

    pub fn room(&self) -> Option<u64> {
        self.room
    }
}

/// What the server's upload budget lets streams have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ceiling {
    /// Share streams fit in the upload budget.
    pub share: bool,
    /// The most a main camera stream may get.
    pub camera: Quality,
    /// Tile (`l`-only) camera streams fit alongside main cameras.
    pub tiles: bool,
}

/// The plan under the server's upload budget, counted over streams rather than listeners.
/// Shares come first, because text on a screen matters more than a face: they fit after audio, or
/// nobody gets one. Then cameras, with what is left: main cameras (`high_streams` on `h`,
/// `main_low_streams` already capped to `l`) and tiles (`tile_streams`, `l`-only) at full rate if
/// they fit, else all cameras on `l` if that fits, else main only on `h`/`l` without tiles, else
/// main only on `l` without tiles, else audio only.
pub(crate) fn ceiling(
    budget_kbps: Option<u32>,
    audio_streams: u64,
    share_streams: u64,
    high_streams: u64,
    main_low_streams: u64,
    tile_streams: u64,
) -> Ceiling {
    let Some(budget) = budget_kbps else {
        return Ceiling {
            share: true,
            camera: Quality::High,
            tiles: true,
        };
    };
    let budget = u64::from(budget);
    let audio = audio_streams.saturating_mul(AUDIO_KBPS);
    let shares = audio.saturating_add(share_streams.saturating_mul(SHARE_KBPS));
    let share = shares <= budget;
    let planned = if share { shares } else { audio };
    let fits = |high_kbps: u64, main_low_kbps: u64, tile_kbps: u64| {
        planned
            .saturating_add(high_streams.saturating_mul(high_kbps))
            .saturating_add(main_low_streams.saturating_mul(main_low_kbps))
            .saturating_add(tile_streams.saturating_mul(tile_kbps))
            <= budget
    };
    let (camera, tiles) = if fits(HIGH_KBPS, LOW_KBPS, LOW_KBPS) {
        (Quality::High, true)
    } else if tile_streams > 0 && fits(LOW_KBPS, LOW_KBPS, LOW_KBPS) {
        (Quality::Low, true)
    } else if fits(HIGH_KBPS, LOW_KBPS, 0) {
        (Quality::High, false)
    } else if fits(LOW_KBPS, LOW_KBPS, 0) {
        (Quality::Low, false)
    } else {
        (Quality::Off, false)
    };
    Ceiling {
        share,
        camera,
        tiles,
    }
}

/// Maps each source's RTP time onto one continuous timeline for a listener's video slot.
/// A new source starts where the last frame left off, plus the wall time since.
#[derive(Debug, Clone)]
pub(crate) struct Rebase<S> {
    source: Option<S>,
    offset: u64,
    last: Option<(u64, Instant)>,
}

impl<S> Default for Rebase<S> {
    fn default() -> Self {
        Self {
            source: None,
            offset: 0,
            last: None,
        }
    }
}

impl<S: PartialEq + Copy> Rebase<S> {
    /// The output time, at 90 kHz, of a frame from `source` at `time`.
    pub fn map(&mut self, source: S, time: u64, now: Instant) -> u64 {
        self.map_hz(source, time, VIDEO_HZ, now)
    }

    /// The output time, at `hz`, of a frame from `source` at `time`.
    pub fn map_hz(&mut self, source: S, time: u64, hz: u64, now: Instant) -> u64 {
        if self.source != Some(source) {
            let start = match self.last {
                Some((at, then)) => {
                    let gap = now.saturating_duration_since(then).as_micros();
                    let ticks = u64::try_from(gap.saturating_mul(u128::from(hz)) / 1_000_000)
                        .unwrap_or(u64::MAX);
                    at.wrapping_add(ticks.max(1))
                }
                None => time,
            };
            self.offset = start.wrapping_sub(time);
            self.source = Some(source);
        }
        let out = time.wrapping_add(self.offset);
        self.last = Some((out, now));
        out
    }
}

/// Who holds the floor in a room, from audio levels, and who held it before. A challenger
/// takes it after `TAKE_FLOOR` as the loudest speaker, and must beat a holder who is still
/// speaking by `FLOOR_MARGIN`, so the video does not flap between two people talking.
#[derive(Debug, Clone)]
pub(crate) struct Floor<K> {
    /// Holders, newest first. The first is the active speaker.
    recent: Vec<K>,
    challenger: Option<(K, Instant)>,
}

impl<K: PartialEq + Copy> Floor<K> {
    pub fn new() -> Self {
        Self {
            recent: Vec::new(),
            challenger: None,
        }
    }

    /// Everyone who has held the floor, newest first.
    pub fn recent(&self) -> &[K] {
        &self.recent
    }

    /// `speakers` are the people speaking now, with their smoothed level in dBov. True if
    /// the floor changed hands.
    pub fn hear(&mut self, speakers: &[(K, f32)], now: Instant) -> bool {
        let Some(&(loudest, level)) = speakers.iter().max_by(|a, b| a.1.total_cmp(&b.1)) else {
            self.challenger = None;
            return false;
        };
        let Some(&holder) = self.recent.first() else {
            self.take(loudest);
            return true;
        };
        if loudest == holder {
            self.challenger = None;
            return false;
        }
        let holder_level = speakers
            .iter()
            .find(|(key, _)| *key == holder)
            .map(|(_, level)| *level);
        if holder_level.is_some_and(|held| level < held + FLOOR_MARGIN) {
            self.challenger = None;
            return false;
        }
        match self.challenger {
            Some((key, since)) if key == loudest => {
                if now.saturating_duration_since(since) >= TAKE_FLOOR {
                    self.take(loudest);
                    return true;
                }
                false
            }
            _ => {
                self.challenger = Some((loudest, now));
                false
            }
        }
    }

    /// Someone left.
    pub fn forget(&mut self, key: &K) {
        self.recent.retain(|held| held != key);
        if self.challenger.is_some_and(|(held, _)| held == *key) {
            self.challenger = None;
        }
    }

    fn take(&mut self, key: K) {
        self.recent.retain(|held| *held != key);
        self.recent.insert(0, key);
        self.challenger = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rids_name_layers() {
        assert_eq!(Layer::of_rid(Some("h")), Layer::High);
        assert_eq!(Layer::of_rid(Some("l")), Layer::Low);
        assert_eq!(Layer::of_rid(None), Layer::High);
        assert_eq!(Layer::High.other(), Layer::Low);
        assert_eq!(Layer::Share.other(), Layer::Share);
    }

    const HOLD: Duration = Duration::from_secs(5);

    fn cam(max: Quality) -> Want {
        Want {
            kind: VideoKind::Camera,
            max,
        }
    }

    fn share(max: Quality) -> Want {
        Want {
            kind: VideoKind::Share,
            max,
        }
    }

    #[test]
    fn allocate_single_stream_matches_hysteresis_thresholds() {
        let high = [cam(Quality::High)];
        assert_eq!(allocate(5000, &high, &[None]), vec![Some(Layer::High)]);
        assert_eq!(
            allocate(UP_KBPS - 1, &high, &[Some(Layer::Low)]),
            vec![Some(Layer::Low)]
        );
        assert_eq!(
            allocate(UP_KBPS - 1, &high, &[Some(Layer::High)]),
            vec![Some(Layer::High)]
        );
        assert_eq!(
            allocate(DOWN_KBPS, &high, &[Some(Layer::High)]),
            vec![Some(Layer::High)]
        );
        assert_eq!(
            allocate(DOWN_KBPS - 1, &high, &[Some(Layer::High)]),
            vec![Some(Layer::Low)]
        );
        assert_eq!(allocate(RESUME_KBPS - 1, &high, &[None]), vec![None]);
        assert_eq!(
            allocate(RESUME_KBPS, &high, &[None]),
            vec![Some(Layer::Low)]
        );
        assert_eq!(
            allocate(PAUSE_KBPS, &high, &[Some(Layer::Low)]),
            vec![Some(Layer::Low)]
        );
        assert_eq!(
            allocate(PAUSE_KBPS - 1, &high, &[Some(Layer::Low)]),
            vec![None]
        );

        let s = [share(Quality::High)];
        assert_eq!(allocate(SHARE_UP_KBPS - 1, &s, &[None]), vec![None]);
        assert_eq!(
            allocate(SHARE_UP_KBPS, &s, &[None]),
            vec![Some(Layer::Share)]
        );
        assert_eq!(
            allocate(SHARE_DOWN_KBPS, &s, &[Some(Layer::Share)]),
            vec![Some(Layer::Share)]
        );
        assert_eq!(
            allocate(SHARE_DOWN_KBPS - 1, &s, &[Some(Layer::Share)]),
            vec![None]
        );
    }

    #[test]
    fn allocate_fits_share_when_tiles_do_not_and_drops_tiles_last_first() {
        let wants = [
            share(Quality::High),
            cam(Quality::Low),
            cam(Quality::Low),
            cam(Quality::Low),
            cam(Quality::Low),
        ];
        // Share fits at 1,000 kb/s, tiles do not.
        assert_eq!(
            allocate(1000, &wants, &[None; 5]),
            vec![Some(Layer::Share), None, None, None, None]
        );
        // 2,500 kb/s brings up the share (1,000) and all four tiles (3*350 + 450 = 1,500).
        let full = allocate(2500, &wants, &[None; 5]);
        assert_eq!(
            full,
            vec![
                Some(Layer::Share),
                Some(Layer::Low),
                Some(Layer::Low),
                Some(Layer::Low),
                Some(Layer::Low),
            ]
        );
        // Congestion drops the last tile first, then earlier tiles, then the share last.
        assert_eq!(
            allocate(2100, &wants, &full),
            vec![
                Some(Layer::Share),
                Some(Layer::Low),
                Some(Layer::Low),
                Some(Layer::Low),
                None,
            ]
        );
        assert_eq!(
            allocate(1700, &wants, &full),
            vec![
                Some(Layer::Share),
                Some(Layer::Low),
                Some(Layer::Low),
                None,
                None,
            ]
        );
        assert_eq!(
            allocate(1300, &wants, &full),
            vec![Some(Layer::Share), Some(Layer::Low), None, None, None]
        );
        assert_eq!(
            allocate(900, &wants, &full),
            vec![Some(Layer::Share), None, None, None, None]
        );
        assert_eq!(allocate(700, &wants, &full), vec![None; 5]);
    }

    #[test]
    fn allocate_hysteresis_prevents_tile_flapping_and_respects_quality_caps() {
        let wants = [cam(Quality::Low), cam(Quality::Low)];
        // Needs 350 + 450 = 800 to add the second tile.
        assert_eq!(
            allocate(799, &wants, &[Some(Layer::Low), None]),
            vec![Some(Layer::Low), None]
        );
        assert_eq!(
            allocate(800, &wants, &[Some(Layer::Low), None]),
            vec![Some(Layer::Low), Some(Layer::Low)]
        );
        // Once held, 350 + 250 = 600 keeps both; 599 drops the second.
        assert_eq!(
            allocate(600, &wants, &[Some(Layer::Low), Some(Layer::Low)]),
            vec![Some(Layer::Low), Some(Layer::Low)]
        );
        assert_eq!(
            allocate(599, &wants, &[Some(Layer::Low), Some(Layer::Low)]),
            vec![Some(Layer::Low), None]
        );
        // Quality::Low caps camera to Low; Quality::Off empties everything.
        assert_eq!(
            allocate(5000, &[cam(Quality::Low), cam(Quality::Off)], &[None, None]),
            vec![Some(Layer::Low), None]
        );
        assert_eq!(
            allocate_unproven(&[share(Quality::High), cam(Quality::High), cam(Quality::Off)]),
            vec![Some(Layer::Share), Some(Layer::Low), None]
        );
    }

    fn told(kbps: u64) -> Reading {
        Reading {
            told: Some(kbps),
            ..Reading::default()
        }
    }

    /// The estimator's figure with nothing to back it, as on a still screen.
    fn idle(kbps: u64) -> Reading {
        Reading {
            estimate: Some(kbps),
            ..Reading::default()
        }
    }

    fn full(kbps: u64) -> Reading {
        Reading {
            estimate: Some(kbps),
            congested: true,
            ..Reading::default()
        }
    }

    #[test]
    fn a_link_drops_at_once_and_climbs_only_after_the_hold() {
        let start = Instant::now();
        let mut link = Link::default();
        let none = Reading::default();
        assert_eq!(link.update(none, HOLD, start), None);
        assert_eq!(link.update(told(5000), HOLD, start), Some(5000));
        assert_eq!(link.update(told(200), HOLD, start), Some(200));
        assert_eq!(link.update(told(5000), HOLD, start), Some(200));
        let almost = start + HOLD - Duration::from_millis(1);
        assert_eq!(link.update(told(5000), HOLD, almost), Some(200));
        assert_eq!(link.update(told(5000), HOLD, start + HOLD), Some(5000));
    }

    #[test]
    fn a_dip_starts_the_hold_over() {
        let start = Instant::now();
        let mut link = Link::default();
        link.update(told(500), HOLD, start);
        assert_eq!(link.update(told(5000), HOLD, start), Some(500));
        let dip = start + HOLD / 2;
        assert_eq!(link.update(told(500), HOLD, dip), Some(500));
        assert_eq!(link.update(told(5000), HOLD, dip), Some(500));
        assert_eq!(link.update(told(5000), HOLD, start + HOLD), Some(500));
        assert_eq!(link.update(told(5000), HOLD, dip + HOLD), Some(5000));
    }

    #[test]
    fn good_news_is_taken_at_once_and_a_low_first_estimate_means_nothing() {
        let start = Instant::now();
        // A little audio off the estimator's 1,000 kb/s start.
        assert_eq!(Link::default().update(idle(950), HOLD, start), Some(950));
        assert_eq!(Link::default().update(idle(150), HOLD, start), None);
        assert_eq!(Link::default().update(idle(500), HOLD, start), None);
    }

    /// The call that found this: a still screen, whose estimate sat under 300 kb/s.
    #[test]
    fn an_estimate_with_nothing_behind_it_takes_nothing_away() {
        let start = Instant::now();
        let mut link = Link::default();
        link.update(idle(5000), HOLD, start);
        for second in 1..120 {
            let at = start + Duration::from_secs(second);
            assert_eq!(link.update(idle(150), HOLD, at), Some(5000));
        }
    }

    #[test]
    fn what_was_withdrawn_is_always_tried_again_and_the_wait_grows() {
        let start = Instant::now();
        let mut link = Link::default();
        link.update(idle(5000), HOLD, start);
        let mut at = start;
        for wait in [1, 2, 4, 8, 12, 12] {
            assert_eq!(link.update(full(200), HOLD, at), Some(200));
            let due = at + HOLD * wait;
            let before = due - Duration::from_millis(1);
            assert_eq!(link.update(idle(200), HOLD, before), Some(200));
            assert_eq!(
                link.update(idle(200), HOLD, due),
                Some(5000),
                "after {wait} holds"
            );
            at = due + Duration::from_secs(1);
        }
        // One that holds starts the wait over.
        at += HOLD * RETRY_MOST * 3;
        link.update(full(200), HOLD, at);
        assert_eq!(link.update(idle(200), HOLD, at + HOLD), Some(5000));
    }

    #[test]
    fn no_retry_while_the_link_is_full_or_the_receiver_says_no() {
        let start = Instant::now();
        let later = start + HOLD * 2;
        let mut link = Link::default();
        link.update(told(5000), HOLD, start);
        link.update(told(200), HOLD, start);
        assert_eq!(link.update(told(200), HOLD, later), Some(200));
        let mut link = Link::default();
        link.update(idle(5000), HOLD, start);
        link.update(full(200), HOLD, start);
        assert_eq!(link.update(full(200), HOLD, later), Some(200));
        assert_eq!(link.update(idle(200), HOLD, later), Some(5000));
    }

    #[test]
    fn a_link_is_full_only_when_it_was_asked_to_carry_its_estimate_and_shows_it() {
        let lost = Some(0.2);
        let queue = Some(Duration::from_millis(300));
        // A still screen, however low the estimate, or lost packets on a lossy link.
        assert!(!congested(50, 50, Some(250), lost, queue));
        // Sent all it could, and nothing shows.
        assert!(!congested(100, 400, Some(250), Some(0.0), None));
        let jitter = Some(Duration::from_millis(184));
        assert!(!congested(100, 400, Some(250), Some(0.03), jitter));
        assert!(congested(100, 400, Some(250), lost, None));
        assert!(congested(100, 400, Some(250), None, queue));
        assert!(!congested(100, 400, None, lost, queue), "no estimate");
    }

    /// A lossy link pins the estimate near the audio. In a real call that read as a full link
    /// with nothing to take away, and kept a viewer's share off it.
    #[test]
    fn audio_alone_never_shows_a_link_is_full() {
        let queue = Some(Duration::from_millis(300));
        assert!(!congested(85, 0, Some(78), Some(0.2), queue));
        assert!(
            !congested(85, 8, Some(78), Some(0.2), queue),
            "a still screen"
        );
    }

    #[test]
    fn the_resume_probe_reaches_resume_above_the_audio() {
        assert_eq!(resume_probe_kbps(0), 700);
        for audio in [0, 49, 50, 128, 304, 1000] {
            let spare = resume_probe_kbps(audio) - audio;
            assert_eq!(
                allocate(spare, &[cam(Quality::Low)], &[None]),
                vec![Some(Layer::Low)],
                "{audio} kb/s of audio"
            );
        }
        // Audio wobbles from one second to the next. The target need not.
        assert_eq!(resume_probe_kbps(301), resume_probe_kbps(304));
    }

    fn camera(budget: Option<u32>, audio: u64, viewers: u64) -> Quality {
        ceiling(budget, audio, 0, viewers, 0, 0).camera
    }

    #[test]
    fn the_budget_drops_to_low_then_to_audio_only() {
        assert_eq!(camera(None, 100, 100), Quality::High);
        // Two listeners, one audio stream each.
        assert_eq!(camera(Some(2500), 2, 2), Quality::High);
        assert_eq!(camera(Some(2000), 2, 2), Quality::Low);
        assert_eq!(camera(Some(500), 2, 2), Quality::Off);
        assert_eq!(camera(Some(500), 2, 0), Quality::High);
    }

    #[test]
    fn shares_are_planned_before_cameras() {
        let all = ceiling(None, 100, 100, 100, 0, 100);
        assert!(all.share);
        assert_eq!(all.camera, Quality::High);
        assert!(all.tiles);
        // Two share streams (8,000 each) and one camera stream, with three audio
        // streams (150): the camera fits above 16,150.
        let roomy = ceiling(Some(17_400), 3, 2, 1, 0, 0);
        assert_eq!((roomy.share, roomy.camera), (true, Quality::High));
        let tight = ceiling(Some(16_600), 3, 2, 1, 0, 0);
        assert_eq!((tight.share, tight.camera), (true, Quality::Low));
        let shares_only = ceiling(Some(16_200), 3, 2, 1, 0, 0);
        assert_eq!(
            (shares_only.share, shares_only.camera),
            (true, Quality::Off)
        );
        // No room for the shares: cameras get the budget instead.
        let cameras = ceiling(Some(2000), 3, 2, 1, 0, 0);
        assert_eq!((cameras.share, cameras.camera), (false, Quality::High));
    }

    #[test]
    fn ceiling_counts_tile_streams_separately_from_main_and_shares() {
        // 2 audio (100) + 1 share (8,000) + 4 low tiles (1,400) = 9,500.
        let fits_all = ceiling(Some(9_500), 2, 1, 0, 0, 4);
        assert_eq!(
            fits_all,
            Ceiling {
                share: true,
                camera: Quality::High,
                tiles: true,
            }
        );
        // Below 9,500: share still fits, tiles drop.
        let share_no_tiles = ceiling(Some(8_500), 2, 1, 0, 0, 4);
        assert_eq!(
            share_no_tiles,
            Ceiling {
                share: true,
                camera: Quality::High,
                tiles: false,
            }
        );
        // 2 audio (100) + 1 main (1,200) + 4 tiles (1,400) = 2,700.
        assert_eq!(
            ceiling(Some(2_700), 2, 0, 1, 0, 4),
            Ceiling {
                share: true,
                camera: Quality::High,
                tiles: true,
            }
        );
        // 1,900 fits main on Low (350) + 4 tiles (1,400) + audio (100) = 1,850.
        assert_eq!(
            ceiling(Some(1_900), 2, 0, 1, 0, 4),
            Ceiling {
                share: true,
                camera: Quality::Low,
                tiles: true,
            }
        );
        // 1,400 fits main on High (1,200) + audio (100) = 1,300 without tiles.
        assert_eq!(
            ceiling(Some(1_400), 2, 0, 1, 0, 4),
            Ceiling {
                share: true,
                camera: Quality::High,
                tiles: false,
            }
        );
        // 500 fits main on Low (350) + audio (100) = 450 without tiles.
        assert_eq!(
            ceiling(Some(500), 2, 0, 1, 0, 4),
            Ceiling {
                share: true,
                camera: Quality::Low,
                tiles: false,
            }
        );
        // 300 fits audio only.
        assert_eq!(
            ceiling(Some(300), 2, 0, 1, 0, 4),
            Ceiling {
                share: true,
                camera: Quality::Off,
                tiles: false,
            }
        );
        // Slot-0 cameras capped at Low (e.g. `call.quality("low")`) still respect egress_kbps.
        assert_eq!(
            ceiling(Some(300), 2, 0, 0, 1, 0),
            Ceiling {
                share: true,
                camera: Quality::Off,
                tiles: false,
            }
        );
        assert_eq!(
            ceiling(Some(450), 2, 0, 0, 1, 0),
            Ceiling {
                share: true,
                camera: Quality::High,
                tiles: true,
            }
        );
    }

    #[test]
    fn a_new_source_continues_the_timeline() {
        let start = Instant::now();
        let mut rebase = Rebase::default();
        assert_eq!(rebase.map('a', 1000, start), 1000);
        assert_eq!(rebase.map('a', 4000, start), 4000);
        let later = start + Duration::from_millis(100);
        assert_eq!(rebase.map('b', 7_000_000, later), 4000 + 9000);
        assert_eq!(rebase.map('b', 7_003_000, later), 4000 + 12_000);
        // Back to the first source, which is now far behind.
        assert_eq!(rebase.map('a', 2000, later), 4000 + 12_001);
    }

    #[test]
    fn rtp_time_wraps() {
        let start = Instant::now();
        let mut rebase = Rebase::default();
        rebase.map('a', u64::MAX - 10, start);
        assert_eq!(rebase.map('b', 5, start), u64::MAX - 9);
        assert_eq!(rebase.map('b', 20, start), 5);
    }

    #[test]
    fn the_first_speaker_takes_the_floor_at_once() {
        let start = Instant::now();
        let mut floor = Floor::new();
        assert!(!floor.hear(&[], start));
        assert!(floor.hear(&[(1, -20.0)], start));
        assert_eq!(floor.recent(), &[1]);
    }

    #[test]
    fn a_challenger_needs_time_and_a_margin_while_the_holder_speaks() {
        let start = Instant::now();
        let mut floor = Floor::new();
        floor.hear(&[(1, -20.0)], start);
        let both = [(1, -20.0), (2, -17.0)];
        assert!(!floor.hear(&both, start));
        assert!(
            !floor.hear(&both, start + TAKE_FLOOR * 2),
            "not loud enough"
        );
        let louder = [(1, -20.0), (2, -10.0)];
        assert!(!floor.hear(&louder, start));
        assert!(!floor.hear(&louder, start + TAKE_FLOOR / 2));
        assert!(floor.hear(&louder, start + TAKE_FLOOR));
        assert_eq!(floor.recent(), &[2, 1]);
    }

    #[test]
    fn a_challenger_takes_a_silent_holders_floor_after_the_wait() {
        let start = Instant::now();
        let mut floor = Floor::new();
        floor.hear(&[(1, -20.0)], start);
        assert!(!floor.hear(&[(2, -40.0)], start));
        assert!(
            !floor.hear(&[], start + TAKE_FLOOR / 2),
            "a pause resets it"
        );
        assert!(!floor.hear(&[(2, -40.0)], start + TAKE_FLOOR));
        assert!(floor.hear(&[(2, -40.0)], start + TAKE_FLOOR * 2));
        assert_eq!(floor.recent(), &[2, 1]);
        floor.forget(&2);
        assert_eq!(floor.recent(), &[1]);
    }
}
