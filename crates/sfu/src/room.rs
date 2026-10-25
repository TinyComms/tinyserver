//! Routing without the network: which receive slot carries whom, and who is speaking.

use std::time::{Duration, Instant};

/// A listener's receive m-lines and who each one carries. `M` is a mid, `K` a participant.
#[derive(Debug, Clone)]
pub(crate) struct Slots<M, K> {
    mids: Vec<M>,
    held: Vec<Option<K>>,
}

impl<M: PartialEq, K: PartialEq> Slots<M, K> {
    pub fn new() -> Self {
        Self {
            mids: Vec::new(),
            held: Vec::new(),
        }
    }

    /// A new receive m-line, free until assigned. A mid already known is ignored.
    pub fn add_mid(&mut self, mid: M) {
        if !self.mids.contains(&mid) {
            self.mids.push(mid);
            self.held.push(None);
        }
    }

    /// Gives `key` the first free slot. False if it already had one or none is free.
    pub fn assign(&mut self, key: K) -> bool {
        if self.held.iter().any(|held| held.as_ref() == Some(&key)) {
            return false;
        }
        match self.held.iter_mut().find(|held| held.is_none()) {
            Some(free) => {
                *free = Some(key);
                true
            }
            None => false,
        }
    }

    /// Frees `key`'s slot. False if it had none.
    pub fn release(&mut self, key: &K) -> bool {
        match self.held.iter_mut().find(|held| held.as_ref() == Some(key)) {
            Some(held) => {
                *held = None;
                true
            }
            None => false,
        }
    }

    pub fn mid_of(&self, key: &K) -> Option<&M> {
        let at = self
            .held
            .iter()
            .position(|held| held.as_ref() == Some(key))?;
        self.mids.get(at)
    }

    /// Held slots in m-line order.
    pub fn held(&self) -> impl Iterator<Item = (&M, &K)> {
        self.mids
            .iter()
            .zip(&self.held)
            .filter_map(|(mid, held)| held.as_ref().map(|key| (mid, key)))
    }
}

/// Smoothed level, in dBov, above which a publisher counts as speaking.
const LOUD: f32 = -50.0;
/// Weight of each new level in the average.
const SMOOTHING: f32 = 0.4;
/// A speaker stays speaking this long after the last loud packet.
pub(crate) const HOLD: Duration = Duration::from_millis(1500);
/// `Speaking` goes out at most this often per room.
pub(crate) const SPEAKING_EVERY: Duration = Duration::from_millis(250);

/// One publisher's voice, from the RFC 6464 level on each packet. Nothing is decoded.
#[derive(Debug, Clone)]
pub(crate) struct Speech {
    level: f32,
    loud_at: Option<Instant>,
}

impl Speech {
    pub fn new() -> Self {
        Self {
            level: -127.0,
            loud_at: None,
        }
    }

    /// `level` is the header value: 0 is loudest, -127 is silence.
    pub fn hear(&mut self, level: Option<i8>, now: Instant) {
        let Some(level) = level else {
            return;
        };
        let level = -f32::from(level.unsigned_abs().min(127));
        self.level += SMOOTHING * (level - self.level);
        if self.level > LOUD {
            self.loud_at = Some(now);
        }
    }

    pub fn speaking(&self, now: Instant) -> bool {
        self.loud_at
            .is_some_and(|at| now.saturating_duration_since(at) < HOLD)
    }

    /// The smoothed level, in dBov.
    pub fn level(&self) -> f32 {
        self.level
    }

    /// Silence, for a muted publisher.
    pub fn hush(&mut self) {
        self.level = -127.0;
        self.loud_at = None;
    }
}

/// The last `Speaking` sent for one room.
#[derive(Debug, Clone, Default)]
pub(crate) struct Announced {
    sent: Vec<String>,
    at: Option<Instant>,
}

impl Announced {
    /// `now_speaking` if it differs from the last one sent and the last one is old enough.
    pub fn due(&mut self, now_speaking: Vec<String>, now: Instant) -> Option<Vec<String>> {
        if now_speaking == self.sent {
            return None;
        }
        if self
            .at
            .is_some_and(|at| now.saturating_duration_since(at) < SPEAKING_EVERY)
        {
            return None;
        }
        self.sent.clone_from(&now_speaking);
        self.at = Some(now);
        Some(now_speaking)
    }
}

#[cfg(test)]
mod tests {
    use super::{Announced, Slots, Speech, HOLD, SPEAKING_EVERY};
    use std::time::{Duration, Instant};

    fn slots(mids: &[&'static str]) -> Slots<&'static str, u32> {
        let mut slots = Slots::new();
        for mid in mids {
            slots.add_mid(*mid);
        }
        slots
    }

    #[test]
    fn people_take_the_first_free_slot_in_order() {
        let mut slots = slots(&["1", "2", "3"]);
        assert!(slots.assign(7));
        assert!(slots.assign(8));
        assert!(!slots.assign(7), "one slot per person");
        assert_eq!(slots.mid_of(&7), Some(&"1"));
        assert_eq!(slots.mid_of(&8), Some(&"2"));
        let held: Vec<_> = slots.held().collect();
        assert_eq!(held, vec![(&"1", &7), (&"2", &8)]);
    }

    #[test]
    fn a_freed_slot_goes_to_the_next_person() {
        let mut slots = slots(&["1", "2"]);
        assert!(slots.assign(7));
        assert!(slots.assign(8));
        assert!(!slots.assign(9), "no slot free");
        assert!(slots.release(&7));
        assert!(!slots.release(&7));
        assert_eq!(slots.mid_of(&7), None);
        assert!(slots.assign(9));
        assert_eq!(slots.mid_of(&9), Some(&"1"));
    }

    #[test]
    fn a_known_mid_is_not_added_twice() {
        let mut slots = slots(&["1", "1", "2"]);
        assert!(slots.assign(7));
        assert!(slots.assign(8));
        assert!(!slots.assign(9));
    }

    #[test]
    fn loud_packets_make_a_speaker_who_holds_then_stops() {
        let start = Instant::now();
        let mut speech = Speech::new();
        speech.hear(Some(-127), start);
        assert!(!speech.speaking(start));
        for n in 0..5 {
            speech.hear(Some(-20), start + Duration::from_millis(20 * n));
        }
        let last = start + Duration::from_millis(80);
        assert!(speech.speaking(last));
        assert!(speech.speaking(last + HOLD - Duration::from_millis(1)));
        assert!(!speech.speaking(last + HOLD));
    }

    #[test]
    fn one_loud_packet_in_silence_is_not_speech() {
        let start = Instant::now();
        let mut speech = Speech::new();
        speech.hear(Some(-30), start);
        assert!(!speech.speaking(start));
        speech.hear(None, start);
        assert!(!speech.speaking(start));
    }

    #[test]
    fn speaking_is_sent_on_change_and_at_most_four_times_a_second() {
        let start = Instant::now();
        let mut announced = Announced::default();
        assert_eq!(announced.due(Vec::new(), start), None);
        let a = vec!["a".to_string()];
        assert_eq!(announced.due(a.clone(), start), Some(a.clone()));
        assert_eq!(announced.due(a.clone(), start), None);
        let soon = start + SPEAKING_EVERY / 2;
        assert_eq!(announced.due(Vec::new(), soon), None);
        let later = start + SPEAKING_EVERY;
        assert_eq!(announced.due(Vec::new(), later), Some(Vec::new()));
    }
}
