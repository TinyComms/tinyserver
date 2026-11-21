//! Routing without the network: which receive slot carries whom, and who is speaking.

use std::time::{Duration, Instant};

/// How long a speaker keeps their audio slot before another speaker can evict them.
pub(crate) const SLOT_HOLD: Duration = Duration::from_millis(1500);
/// While all slots are held by active speakers, a challenger must beat the quietest one by
/// this much, in dB, to take their slot after `SLOT_HOLD`.
pub(crate) const SLOT_MARGIN: f32 = 6.0;

#[derive(Debug, Clone)]
struct Held<K> {
    key: K,
    assigned_at: Instant,
    last_spoke_at: Option<Instant>,
}

/// A listener's receive m-lines and who each one carries. `M` is a mid, `K` a participant.
#[derive(Debug, Clone)]
pub(crate) struct Slots<M, K> {
    mids: Vec<M>,
    held: Vec<Option<Held<K>>>,
}

impl<M: PartialEq, K: PartialEq + Copy> Slots<M, K> {
    pub fn new() -> Self {
        Self {
            mids: Vec::new(),
            held: Vec::new(),
        }
    }

    /// Number of receive slots this listener offered.
    pub fn capacity(&self) -> usize {
        self.mids.len()
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
        self.assign_at(key, Instant::now(), false)
    }

    fn assign_at(&mut self, key: K, now: Instant, speaking: bool) -> bool {
        if self
            .held
            .iter()
            .any(|held| held.as_ref().is_some_and(|h| h.key == key))
        {
            return false;
        }
        match self.held.iter_mut().find(|held| held.is_none()) {
            Some(free) => {
                *free = Some(Held {
                    key,
                    assigned_at: now,
                    last_spoke_at: speaking.then_some(now),
                });
                true
            }
            None => false,
        }
    }

    /// Frees `key`'s slot. False if it had none.
    pub fn release(&mut self, key: &K) -> bool {
        match self
            .held
            .iter_mut()
            .find(|held| held.as_ref().is_some_and(|h| &h.key == key))
        {
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
            .position(|held| held.as_ref().is_some_and(|h| &h.key == key))?;
        self.mids.get(at)
    }

    /// Held slots in m-line order.
    pub fn held(&self) -> impl Iterator<Item = (&M, &K)> {
        self.mids
            .iter()
            .zip(&self.held)
            .filter_map(|(mid, held)| held.as_ref().map(|h| (mid, &h.key)))
    }

    /// Reconciles this listener's slots against all room `members` (excluding `listener`).
    /// Each entry is `(member_id, is_speaking, smoothed_level_dbov)` in join order.
    ///
    /// - Small calls (members <= capacity): everyone other than `listener` gets a slot.
    /// - Large calls: active speakers take free slots or evict quiet/expired holders first,
    ///   then the quietest active speaker if louder by `SLOT_MARGIN` after `SLOT_HOLD`.
    ///   Quiet joiners never evict anyone. `listener` is never seated in their own slots.
    ///
    /// Returns `true` if any slot assignment changed.
    pub fn reconcile(&mut self, listener: K, members: &[(K, bool, f32)], now: Instant) -> bool {
        let mut changed = false;

        // 1. Update last_spoke_at for any currently seated member who is speaking.
        for slot in self.held.iter_mut().flatten() {
            if members
                .iter()
                .any(|&(key, speaking, _)| key == slot.key && speaking)
            {
                slot.last_spoke_at = Some(now);
            }
        }

        // 2. Collect unseated active speakers, loudest first.
        let mut unseated_speakers: Vec<(K, f32)> = members
            .iter()
            .copied()
            .filter(|&(key, speaking, _)| {
                key != listener
                    && speaking
                    && !self
                        .held
                        .iter()
                        .any(|slot| slot.as_ref().is_some_and(|h| h.key == key))
            })
            .map(|(key, _, level)| (key, level))
            .collect();
        unseated_speakers.sort_by(|a, b| b.1.total_cmp(&a.1));

        // 3. Fill any free slots with active speakers first, then remaining members in join order.
        let mut remaining_speakers = Vec::new();
        for (speaker, level) in unseated_speakers {
            if self.assign_at(speaker, now, true) {
                changed = true;
            } else {
                remaining_speakers.push((speaker, level));
            }
        }
        if self.held.iter().any(Option::is_none) {
            for &(key, speaking, _) in members {
                if key == listener {
                    continue;
                }
                if self.assign_at(key, now, speaking) {
                    changed = true;
                }
                if self.held.iter().all(Option::is_some) {
                    break;
                }
            }
        }

        // 4. If slots are full and active speakers are still unseated, evict the best victim.
        for (challenger, challenger_level) in remaining_speakers {
            let Some(victim_idx) = self.pick_victim(members, challenger_level, now) else {
                break;
            };
            self.held[victim_idx] = Some(Held {
                key: challenger,
                assigned_at: now,
                last_spoke_at: Some(now),
            });
            changed = true;
        }

        changed
    }

    fn pick_victim(
        &self,
        members: &[(K, bool, f32)],
        challenger_level: f32,
        now: Instant,
    ) -> Option<usize> {
        // Priority 1: Someone who has never spoken (quiet joiner).
        if let Some((idx, _)) = self
            .held
            .iter()
            .enumerate()
            .filter_map(|(i, slot)| slot.as_ref().map(|h| (i, h)))
            .filter(|(_, h)| h.last_spoke_at.is_none())
            .min_by_key(|(_, h)| h.assigned_at)
        {
            return Some(idx);
        }

        // Priority 2: Someone who is NOT currently speaking and whose hold time has expired.
        if let Some((idx, _)) = self
            .held
            .iter()
            .enumerate()
            .filter_map(|(i, slot)| slot.as_ref().map(|h| (i, h)))
            .filter(|(_, h)| {
                let speaking = members
                    .iter()
                    .any(|&(key, spk, _)| key == h.key && spk);
                let last = h.last_spoke_at.unwrap_or(h.assigned_at).max(h.assigned_at);
                !speaking && now.saturating_duration_since(last) >= SLOT_HOLD
            })
            .min_by_key(|(_, h)| h.last_spoke_at.unwrap_or(h.assigned_at))
        {
            return Some(idx);
        }

        // Priority 3: Quietest active speaker who has held their slot at least SLOT_HOLD
        // and is strictly quieter than the challenger by SLOT_MARGIN.
        self.held
            .iter()
            .enumerate()
            .filter_map(|(i, slot)| slot.as_ref().map(|h| (i, h)))
            .filter(|(_, h)| now.saturating_duration_since(h.assigned_at) >= SLOT_HOLD)
            .filter_map(|(i, h)| {
                let level = members
                    .iter()
                    .find(|&&(key, _, _)| key == h.key)
                    .map_or(-127.0, |&(_, _, lvl)| lvl);
                (challenger_level >= level + SLOT_MARGIN).then_some((i, level))
            })
            .min_by(|a, b| a.1.total_cmp(&b.1))
            .map(|(i, _)| i)
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

    #[test]
    fn quiet_joiners_never_evict_a_speaker() {
        let now = Instant::now();
        let mut s = slots(&["1", "2"]);
        let members = vec![(1, true, -20.0), (2, true, -25.0), (3, false, -127.0)];
        assert!(s.reconcile(0, &members, now));
        assert_eq!(s.mid_of(&1), Some(&"1"));
        assert_eq!(s.mid_of(&2), Some(&"2"));
        assert_eq!(s.mid_of(&3), None);
        // Even after hold time, quiet joiner 3 does not evict anyone.
        let later = now + super::SLOT_HOLD + Duration::from_secs(1);
        assert!(!s.reconcile(0, &members, later));
        assert_eq!(s.mid_of(&3), None);
    }

    #[test]
    fn new_speaker_evicts_quiet_slot_holder_and_listener_never_hears_self() {
        let now = Instant::now();
        let mut s = slots(&["1", "2"]);
        // Listener is 0; 1 and 2 are quiet joiners seated initially.
        let members = vec![(0, true, -10.0), (1, false, -127.0), (2, false, -127.0)];
        assert!(s.reconcile(0, &members, now));
        assert_eq!(s.mid_of(&0), None, "listener never gets a slot for self");
        assert_eq!(s.mid_of(&1), Some(&"1"));
        assert_eq!(s.mid_of(&2), Some(&"2"));

        // Speaker 3 starts talking and takes a quiet holder's slot immediately.
        let members = vec![
            (0, true, -10.0),
            (1, false, -127.0),
            (2, false, -127.0),
            (3, true, -18.0),
        ];
        assert!(s.reconcile(0, &members, now + Duration::from_millis(100)));
        assert_eq!(s.mid_of(&3), Some(&"1"));
        assert_eq!(s.mid_of(&0), None);
    }

    #[test]
    fn slots_do_not_flap_between_speakers_talking_over_each_other() {
        let now = Instant::now();
        let mut s = slots(&["1"]);
        // Speaker 1 gets the single slot at -25 dB.
        assert!(s.reconcile(0, &[(1, true, -25.0), (2, false, -127.0)], now));
        assert_eq!(s.mid_of(&1), Some(&"1"));

        // Speaker 2 starts at -22 dB (only 3 dB louder < SLOT_MARGIN 6 dB): must not flap.
        let soon = now + super::SLOT_HOLD + Duration::from_millis(50);
        assert!(!s.reconcile(0, &[(1, true, -25.0), (2, true, -22.0)], soon));
        assert_eq!(s.mid_of(&1), Some(&"1"));

        // Speaker 2 is now -15 dB (10 dB louder >= SLOT_MARGIN) after hold time: takes slot.
        assert!(s.reconcile(0, &[(1, true, -25.0), (2, true, -15.0)], soon));
        assert_eq!(s.mid_of(&2), Some(&"1"));

        // Immediately after, Speaker 1 shouts at -5 dB: cannot flap back before SLOT_HOLD.
        assert!(!s.reconcile(
            0,
            &[(1, true, -5.0), (2, true, -15.0)],
            soon + Duration::from_millis(500)
        ));
        assert_eq!(s.mid_of(&2), Some(&"1"));
    }

    #[test]
    fn large_room_100_and_500_peers_seats_loudest_within_slot_budget() {
        let now = Instant::now();
        for total in [100u32, 500u32] {
            let mut listener_slots = slots(&["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"]);
            let mut members: Vec<(u32, bool, f32)> = (0..total)
                .map(|id| (id, false, -127.0))
                .collect();
            // Initial join: 11 non-self members seated.
            listener_slots.reconcile(0, &members, now);
            assert_eq!(listener_slots.held().count(), 11);
            assert_eq!(listener_slots.mid_of(&0), None);

            // 5 scripted speakers near the end of the roster start talking.
            let active = [total - 5, total - 4, total - 3, total - 2, total - 1];
            for (i, &id) in active.iter().enumerate() {
                members[id as usize] = (id, true, -20.0 - i as f32);
            }
            assert!(listener_slots.reconcile(0, &members, now + Duration::from_millis(100)));
            assert_eq!(listener_slots.held().count(), 11);
            for &id in &active {
                assert!(
                    listener_slots.mid_of(&id).is_some(),
                    "speaker {id} should be seated in room of {total}"
                );
            }
            assert_eq!(listener_slots.mid_of(&0), None);
        }
    }
}
