//! Group calls: one live call per group conversation, per-member rings, and end rules.
//! Memory only; a restart drops every call and writes no row. The row in `group_call_log` is
//! written once when the call ends.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use super::call::Participant;
use super::ring::{new_id, RING_FOR, SEAT_FOR};

const PREFIX: &str = "g:";

/// How long a lone participant with no ring pending stays before leaving as `alone`.
pub(crate) const ALONE_FOR: Duration = Duration::from_secs(300);

pub(crate) fn room_key(call_id: &str) -> String {
    format!("{PREFIX}{call_id}")
}

pub(crate) fn call_of_room(room_id: &str) -> Option<&str> {
    room_id.strip_prefix(PREFIX)
}

/// Per-member ring state on a group call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RingStatus {
    Ringing,
    Answered,
    Declined,
    Missed,
    Busy,
    Unreachable,
    Cancelled,
}

impl RingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ringing => "ringing",
            Self::Answered => "answered",
            Self::Declined => "declined",
            Self::Missed => "missed",
            Self::Busy => "busy",
            Self::Unreachable => "unreachable",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Wire entry for `rings: [{user_id, state}]` on `call.group.started` and `ready.group_calls`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RingEntry {
    pub user_id: String,
    pub state: &'static str,
}

/// One live group call in `ready.group_calls`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ReadyGroupCall {
    pub group_id: String,
    pub call_id: String,
    pub started_by: String,
    pub started_at: String,
    pub participants: Vec<Participant>,
    pub rings: Vec<RingEntry>,
}

/// Payload for `call.group.started`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StartedCard {
    pub group_id: String,
    pub call_id: String,
    pub started_by: String,
    pub started_at: String,
    pub rings: Vec<RingEntry>,
    pub participants: Vec<Participant>,
}

/// Result of `GroupCalls::start`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StartOutcome {
    /// A new group call was created; broadcast `call.group.started` to every member.
    Created {
        card: StartedCard,
        recipients: Vec<String>,
    },
    /// The group already had a live call; send `call.group.started` to the asker only.
    Existing { card: StartedCard },
}

/// One `call.group.ring` frame to fan out to `recipients`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RingEvent {
    pub recipients: Vec<String>,
    pub group_id: String,
    pub call_id: String,
    pub user_id: String,
    pub state: &'static str,
    pub by: String,
}

/// One finished group call: any pending rings cancelled, `call.group.ended` to members, and the
/// durable log record to write after releasing the lock.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EndedEvent {
    pub recipients: Vec<String>,
    pub group_id: String,
    pub call_id: String,
    pub outcome: &'static str,
    pub cancelled_rings: Vec<RingEvent>,
    pub record: GroupCallRecord,
}

/// Mirrors `db::GroupCallRecord` inside the live module so unit tests stay independent of sqlx.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct GroupCallRecord {
    pub call_id: String,
    pub group_id: String,
    pub started_by: String,
    pub outcome: &'static str,
    pub started_at: f64,
    pub people: Vec<(String, &'static str)>,
}

/// What one sweep tick produces for group calls.
#[derive(Debug, Default)]
pub(crate) struct SweepActions {
    pub ring_events: Vec<RingEvent>,
    pub ended: Vec<EndedEvent>,
    /// `(room_id, lone_user_id)` pairs that exceeded `ALONE_FOR` with no pending ring.
    pub alone_leaves: Vec<(String, String)>,
}

struct RingSlot {
    status: RingStatus,
    until: Option<Instant>,
    /// Last time this person was actually rung (`RingStatus::Ringing`). Prevents ringing the same
    /// person twice within `RING_FOR` in one call, whoever asks.
    last_rung_at: Option<Instant>,
    by: String,
}

struct GroupCall {
    id: String,
    group_id: String,
    started_by: String,
    started_at: SystemTime,
    started_at_iso: String,
    /// Current members of the group conversation.
    members: Vec<String>,
    /// Per-callee ring state.
    rings: HashMap<String, RingSlot>,
    /// Distinct user ids who ever took a seat in this call.
    joined: Vec<String>,
    /// Deadline for the first seat (`started_at + SEAT_FOR`), cleared once anyone sits.
    first_seat_by: Option<Instant>,
    /// When the lone remaining participant became alone with no ringing rings.
    alone_since: Option<Instant>,
}

impl GroupCall {
    fn has_ringing(&self) -> bool {
        self.rings
            .values()
            .any(|slot| slot.status == RingStatus::Ringing)
    }

    fn ring_entries(&self) -> Vec<RingEntry> {
        let mut entries = Vec::with_capacity(self.rings.len());
        let mut seen = HashSet::with_capacity(self.rings.len());
        for member in &self.members {
            if let Some(slot) = self.rings.get(member) {
                entries.push(RingEntry {
                    user_id: member.clone(),
                    state: slot.status.as_str(),
                });
                seen.insert(member.as_str());
            }
        }
        // Include any ring entries for people who left the group mid-call in sorted order.
        let mut extras: Vec<(&String, &RingSlot)> = self
            .rings
            .iter()
            .filter(|(uid, _)| !seen.contains(uid.as_str()))
            .collect();
        extras.sort_by(|(a, _), (b, _)| a.cmp(b));
        for (uid, slot) in extras {
            entries.push(RingEntry {
                user_id: uid.clone(),
                state: slot.status.as_str(),
            });
        }
        entries
    }

    fn started_card(&self, participants: Vec<Participant>) -> StartedCard {
        StartedCard {
            group_id: self.group_id.clone(),
            call_id: self.id.clone(),
            started_by: self.started_by.clone(),
            started_at: self.started_at_iso.clone(),
            rings: self.ring_entries(),
            participants,
        }
    }

    fn update_alone(&mut self, seated_count: usize, now: Instant) {
        if self.first_seat_by.is_some() || seated_count != 1 || self.has_ringing() {
            self.alone_since = None;
        } else if self.alone_since.is_none() {
            self.alone_since = Some(now);
        }
    }

    fn record(&self, outcome: &'static str) -> GroupCallRecord {
        let mut ids: Vec<String> = Vec::new();
        let mut seen: HashSet<&str> = HashSet::new();
        for uid in &self.members {
            if seen.insert(uid.as_str()) {
                ids.push(uid.clone());
            }
        }
        for uid in &self.joined {
            if seen.insert(uid.as_str()) {
                ids.push(uid.clone());
            }
        }
        let mut ring_keys: Vec<&String> = self.rings.keys().collect();
        ring_keys.sort();
        for uid in ring_keys {
            if seen.insert(uid.as_str()) {
                ids.push(uid.clone());
            }
        }
        let people = ids
            .into_iter()
            .map(|uid| {
                let out = if self.joined.iter().any(|j| j == &uid) {
                    "joined"
                } else {
                    match self.rings.get(&uid).map(|slot| slot.status) {
                        Some(RingStatus::Declined) => "declined",
                        Some(RingStatus::Busy) => "busy",
                        Some(
                            RingStatus::Missed
                            | RingStatus::Ringing
                            | RingStatus::Cancelled
                            | RingStatus::Answered,
                        ) => "missed",
                        Some(RingStatus::Unreachable) | None => "not_rung",
                    }
                };
                (uid, out)
            })
            .collect();
        let started_at = self
            .started_at
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        GroupCallRecord {
            call_id: self.id.clone(),
            group_id: self.group_id.clone(),
            started_by: self.started_by.clone(),
            outcome,
            started_at,
            people,
        }
    }
}

#[derive(Default)]
pub(crate) struct GroupCalls {
    by_id: HashMap<String, GroupCall>,
    by_group: HashMap<String, String>,
}

impl GroupCalls {
    /// Starts a call in `group_id` and rings every reachable, non-busy member regardless of
    /// group size. If the group already has a live call, returns `StartOutcome::Existing` so the
    /// hub can send `call.group.started` to the asker alone.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        &mut self,
        group_id: &str,
        started_by: &str,
        members: Vec<String>,
        mut is_busy: impl FnMut(&str) -> bool,
        mut is_online: impl FnMut(&str) -> bool,
        participants_of: impl FnOnce(&str) -> Vec<Participant>,
        now: Instant,
    ) -> StartOutcome {
        if let Some(call_id) = self.by_group.get(group_id).cloned() {
            let room_id = room_key(&call_id);
            let participants = participants_of(&room_id);
            let call = self.by_id.get_mut(&call_id).expect("group call");
            call.members = members;
            return StartOutcome::Existing {
                card: call.started_card(participants),
            };
        }

        let ringing_elsewhere: HashSet<String> = self
            .by_id
            .values()
            .flat_map(|other| {
                other
                    .rings
                    .iter()
                    .filter(|(_, slot)| slot.status == RingStatus::Ringing)
                    .map(|(uid, _)| uid.clone())
            })
            .collect();

        let id = new_id();
        let started_at = SystemTime::now();
        let started_at_iso = format_utc(started_at);
        let mut rings = HashMap::new();
        for member in &members {
            if member == started_by {
                continue;
            }
            let slot = if ringing_elsewhere.contains(member) || is_busy(member) {
                RingSlot {
                    status: RingStatus::Busy,
                    until: None,
                    last_rung_at: None,
                    by: started_by.to_string(),
                }
            } else if !is_online(member) {
                RingSlot {
                    status: RingStatus::Unreachable,
                    until: None,
                    last_rung_at: None,
                    by: started_by.to_string(),
                }
            } else {
                RingSlot {
                    status: RingStatus::Ringing,
                    until: Some(now + RING_FOR),
                    last_rung_at: Some(now),
                    by: started_by.to_string(),
                }
            };
            rings.insert(member.clone(), slot);
        }
        let recipients = members.clone();
        let call = GroupCall {
            id: id.clone(),
            group_id: group_id.to_string(),
            started_by: started_by.to_string(),
            started_at,
            started_at_iso,
            members,
            rings,
            joined: Vec::new(),
            first_seat_by: Some(now + SEAT_FOR),
            alone_since: None,
        };
        let card = call.started_card(Vec::new());
        self.by_group.insert(group_id.to_string(), id.clone());
        self.by_id.insert(id, call);
        StartOutcome::Created { card, recipients }
    }

    /// Rings `user_ids` in the live call `(group_id, call_id)`. Caller must already be verified
    /// as seated in `g:{call_id}`. Skips the sender, non-members, anyone already seated, and
    /// anyone rung within `RING_FOR` in this call.
    #[allow(clippy::too_many_arguments)]
    pub fn ring(
        &mut self,
        group_id: &str,
        call_id: &str,
        by: &str,
        user_ids: &[String],
        seated: &[String],
        mut is_busy: impl FnMut(&str) -> bool,
        mut is_online: impl FnMut(&str) -> bool,
        now: Instant,
    ) -> Result<Vec<RingEvent>, &'static str> {
        let active_id = self.by_group.get(group_id).ok_or("not_found")?;
        if active_id != call_id {
            return Err("not_found");
        }
        // Check busyness across OTHER group calls before borrowing `self.by_id` mutably.
        let ringing_elsewhere: HashSet<String> = self
            .by_id
            .iter()
            .filter(|(id, _)| id.as_str() != call_id)
            .flat_map(|(_, other)| {
                other
                    .rings
                    .iter()
                    .filter(|(_, slot)| slot.status == RingStatus::Ringing)
                    .map(|(uid, _)| uid.clone())
            })
            .collect();

        let call = self.by_id.get_mut(call_id).ok_or("not_found")?;
        let mut events = Vec::new();
        let mut seen = HashSet::new();
        for uid in user_ids {
            if !seen.insert(uid.as_str()) {
                continue;
            }
            if uid == by
                || !call.members.iter().any(|m| m == uid)
                || seated.iter().any(|s| s == uid)
            {
                continue;
            }
            if let Some(existing) = call.rings.get(uid) {
                if existing
                    .last_rung_at
                    .is_some_and(|at| now.saturating_duration_since(at) < RING_FOR)
                {
                    continue;
                }
            }
            let status = if ringing_elsewhere.contains(uid) || is_busy(uid) {
                RingStatus::Busy
            } else if !is_online(uid) {
                RingStatus::Unreachable
            } else {
                RingStatus::Ringing
            };
            let last_rung_at = if status == RingStatus::Ringing {
                Some(now)
            } else {
                call.rings.get(uid).and_then(|s| s.last_rung_at)
            };
            call.rings.insert(
                uid.clone(),
                RingSlot {
                    status,
                    until: (status == RingStatus::Ringing).then_some(now + RING_FOR),
                    last_rung_at,
                    by: by.to_string(),
                },
            );
            events.push(RingEvent {
                recipients: call.members.clone(),
                group_id: call.group_id.clone(),
                call_id: call.id.clone(),
                user_id: uid.clone(),
                state: status.as_str(),
                by: by.to_string(),
            });
        }
        if call.has_ringing() {
            call.alone_since = None;
        }
        Ok(events)
    }

    /// Cancels any active `Ringing` rings for `user_ids` in `(group_id, call_id)` with `by` set
    /// to the sender. Naming someone not ringing is `Ok` and changes nothing.
    pub fn unring(
        &mut self,
        group_id: &str,
        call_id: &str,
        by: &str,
        user_ids: &[String],
        seated_count: usize,
        now: Instant,
    ) -> Result<Vec<RingEvent>, &'static str> {
        let active_id = self.by_group.get(group_id).ok_or("not_found")?;
        if active_id != call_id {
            return Err("not_found");
        }
        let call = self.by_id.get_mut(call_id).ok_or("not_found")?;
        let mut events = Vec::new();
        let mut seen = HashSet::new();
        for uid in user_ids {
            if !seen.insert(uid.as_str()) {
                continue;
            }
            if let Some(slot) = call.rings.get_mut(uid) {
                if slot.status == RingStatus::Ringing {
                    slot.status = RingStatus::Cancelled;
                    slot.until = None;
                    slot.by = by.to_string();
                    events.push(RingEvent {
                        recipients: call.members.clone(),
                        group_id: call.group_id.clone(),
                        call_id: call.id.clone(),
                        user_id: uid.clone(),
                        state: RingStatus::Cancelled.as_str(),
                        by: by.to_string(),
                    });
                }
            }
        }
        call.update_alone(seated_count, now);
        Ok(events)
    }

    /// The callee stops their own ring on all their devices. The call is unaffected.
    pub fn decline(
        &mut self,
        group_id: &str,
        call_id: &str,
        user_id: &str,
        seated_count: usize,
        now: Instant,
    ) -> Result<RingEvent, &'static str> {
        let active_id = self.by_group.get(group_id).ok_or("not_found")?;
        if active_id != call_id {
            return Err("not_found");
        }
        let call = self.by_id.get_mut(call_id).ok_or("not_found")?;
        let slot = call.rings.get_mut(user_id).ok_or("not_found")?;
        if slot.status != RingStatus::Ringing {
            return Err("not_found");
        }
        slot.status = RingStatus::Declined;
        slot.until = None;
        let by = slot.by.clone();
        let event = RingEvent {
            recipients: call.members.clone(),
            group_id: call.group_id.clone(),
            call_id: call.id.clone(),
            user_id: user_id.to_string(),
            state: RingStatus::Declined.as_str(),
            by,
        };
        call.update_alone(seated_count, now);
        Ok(event)
    }

    /// Looks up the media room `g:{call_id}` for `group_id`'s live call, updating the cached
    /// member list if supplied.
    pub fn join_key(&mut self, group_id: &str, members: Option<Vec<String>>) -> Option<String> {
        let call_id = self.by_group.get(group_id)?.clone();
        if let (Some(call), Some(members)) = (self.by_id.get_mut(&call_id), members) {
            call.members = members;
        }
        Some(room_key(&call_id))
    }

    /// Whether `room_id` is a live group call and `user_id` is a current member.
    pub fn can_seat(&self, room_id: &str, user_id: &str) -> bool {
        let Some(call_id) = call_of_room(room_id) else {
            return false;
        };
        self.by_id
            .get(call_id)
            .is_some_and(|call| call.members.iter().any(|m| m == user_id))
    }

    /// Marks `user_id`'s ring in `group_id`'s live call as `answered`, called after admission
    /// passes and before SFU media setup so their other devices stop ringing at once.
    pub fn mark_answered(
        &mut self,
        group_id: &str,
        user_id: &str,
        seated_count: usize,
        now: Instant,
    ) -> Option<RingEvent> {
        let call_id = self.by_group.get(group_id)?.clone();
        let call = self.by_id.get_mut(&call_id)?;
        let slot = call.rings.get_mut(user_id)?;
        if slot.status != RingStatus::Ringing {
            return None;
        }
        slot.status = RingStatus::Answered;
        slot.until = None;
        let by = slot.by.clone();
        let event = RingEvent {
            recipients: call.members.clone(),
            group_id: call.group_id.clone(),
            call_id: call.id.clone(),
            user_id: user_id.to_string(),
            state: RingStatus::Answered.as_str(),
            by,
        };
        call.update_alone(seated_count, now);
        Some(event)
    }

    /// Cancels `user_id`'s pending `Ringing` ring on `room_id` (e.g. when a join is refused by
    /// capacity or scoped `call.leave` arrives before seating).
    pub fn cancel_ring_for_room(
        &mut self,
        room_id: &str,
        user_id: &str,
        by: &str,
        seated_count: usize,
        now: Instant,
    ) -> Option<RingEvent> {
        let call_id = call_of_room(room_id)?;
        let call = self.by_id.get_mut(call_id)?;
        let slot = call.rings.get_mut(user_id)?;
        if slot.status != RingStatus::Ringing {
            return None;
        }
        slot.status = RingStatus::Cancelled;
        slot.until = None;
        slot.by = by.to_string();
        let event = RingEvent {
            recipients: call.members.clone(),
            group_id: call.group_id.clone(),
            call_id: call.id.clone(),
            user_id: user_id.to_string(),
            state: RingStatus::Cancelled.as_str(),
            by: by.to_string(),
        };
        call.update_alone(seated_count, now);
        Some(event)
    }

    /// Records that `user_id` took a seat in `room_id`. Clears `first_seat_by` and updates the
    /// alone timer.
    pub fn on_seated(&mut self, room_id: &str, user_id: &str, seated_count: usize, now: Instant) {
        let Some(call_id) = call_of_room(room_id) else {
            return;
        };
        let Some(call) = self.by_id.get_mut(call_id) else {
            return;
        };
        if !call.joined.iter().any(|u| u == user_id) {
            call.joined.push(user_id.to_string());
        }
        call.first_seat_by = None;
        call.update_alone(seated_count, now);
    }

    /// Records that someone left `room_id`. Once the first seat has been taken and the room is
    /// empty, ends the call (`ended` if >= 2 distinct people ever sat, else `missed`) and cancels
    /// any remaining rings.
    pub fn on_left(
        &mut self,
        room_id: &str,
        remaining_count: usize,
        now: Instant,
    ) -> Option<EndedEvent> {
        let call_id = call_of_room(room_id)?.to_string();
        let should_end = {
            let call = self.by_id.get_mut(&call_id)?;
            if remaining_count == 0 && call.first_seat_by.is_none() {
                true
            } else {
                call.update_alone(remaining_count, now);
                false
            }
        };
        if !should_end {
            return None;
        }
        let outcome = if self.by_id.get(&call_id)?.joined.len() >= 2 {
            "ended"
        } else {
            "missed"
        };
        self.finish(&call_id, outcome)
    }

    /// Forces a group's live call to end (e.g. `group.deleted`).
    pub fn end_group(&mut self, group_id: &str) -> Option<(String, EndedEvent)> {
        let call_id = self.by_group.get(group_id)?.clone();
        let room_id = room_key(&call_id);
        let outcome = {
            let call = self.by_id.get(&call_id)?;
            if call.first_seat_by.is_some() {
                "cancelled"
            } else if call.joined.len() >= 2 {
                "ended"
            } else {
                "missed"
            }
        };
        let ended = self.finish(&call_id, outcome)?;
        Some((room_id, ended))
    }

    /// A member left or was removed from `group_id`. Removes them from the live call's audience
    /// and cancels their pending ring (sending the cancel to remaining members + the removed user).
    pub fn on_member_removed(
        &mut self,
        group_id: &str,
        user_id: &str,
        seated_count: usize,
        now: Instant,
    ) -> (Option<String>, Option<RingEvent>) {
        let Some(call_id) = self.by_group.get(group_id).cloned() else {
            return (None, None);
        };
        let room_id = room_key(&call_id);
        let Some(call) = self.by_id.get_mut(&call_id) else {
            return (None, None);
        };
        let mut recipients = call.members.clone();
        if !recipients.iter().any(|m| m == user_id) {
            recipients.push(user_id.to_string());
        }
        call.members.retain(|m| m != user_id);
        let event = call.rings.get_mut(user_id).and_then(|slot| {
            if slot.status != RingStatus::Ringing {
                return None;
            }
            slot.status = RingStatus::Cancelled;
            slot.until = None;
            Some(RingEvent {
                recipients,
                group_id: call.group_id.clone(),
                call_id: call.id.clone(),
                user_id: user_id.to_string(),
                state: RingStatus::Cancelled.as_str(),
                by: slot.by.clone(),
            })
        });
        call.update_alone(seated_count, now);
        (Some(room_id), event)
    }

    /// A member was added to `group_id`. If the group has a live call, adds them to the member
    /// list and returns a `StartedCard` to send to the newly added member.
    pub fn on_member_added(
        &mut self,
        group_id: &str,
        user_id: &str,
        participants_of: impl FnOnce(&str) -> Vec<Participant>,
    ) -> Option<StartedCard> {
        let call_id = self.by_group.get(group_id)?.clone();
        let room_id = room_key(&call_id);
        let participants = participants_of(&room_id);
        let call = self.by_id.get_mut(&call_id)?;
        if !call.members.iter().any(|m| m == user_id) {
            call.members.push(user_id.to_string());
        }
        Some(call.started_card(participants))
    }

    /// Community removal, ban, or timeout: drops any pending group rings for `user_id` across all
    /// live group calls.
    pub fn drop_user_rings(
        &mut self,
        user_id: &str,
        seated_count_of: impl Fn(&str) -> usize,
        now: Instant,
    ) -> Vec<RingEvent> {
        let mut events = Vec::new();
        for call in self.by_id.values_mut() {
            if let Some(slot) = call.rings.get_mut(user_id) {
                if slot.status == RingStatus::Ringing {
                    slot.status = RingStatus::Cancelled;
                    slot.until = None;
                    let mut recipients = call.members.clone();
                    if !recipients.iter().any(|m| m == user_id) {
                        recipients.push(user_id.to_string());
                    }
                    events.push(RingEvent {
                        recipients,
                        group_id: call.group_id.clone(),
                        call_id: call.id.clone(),
                        user_id: user_id.to_string(),
                        state: RingStatus::Cancelled.as_str(),
                        by: slot.by.clone(),
                    });
                }
            }
            let room_id = room_key(&call.id);
            call.update_alone(seated_count_of(&room_id), now);
        }
        events
    }

    /// Sweeps expired rings (`RING_FOR`), expired first-seat windows (`SEAT_FOR`), and lone
    /// participants past `ALONE_FOR`.
    pub fn sweep(&mut self, now: Instant, seated_of: impl Fn(&str) -> Vec<String>) -> SweepActions {
        let mut actions = SweepActions::default();
        let mut cancel_ids = Vec::new();

        let call_ids: Vec<String> = self.by_id.keys().cloned().collect();
        for call_id in call_ids {
            let room_id = room_key(&call_id);
            let seated = seated_of(&room_id);
            let Some(call) = self.by_id.get_mut(&call_id) else {
                continue;
            };
            if call.first_seat_by.is_some_and(|deadline| deadline <= now) {
                cancel_ids.push(call_id);
                continue;
            }
            let mut expired_users: Vec<String> = call
                .rings
                .iter()
                .filter(|(_, slot)| {
                    slot.status == RingStatus::Ringing
                        && slot.until.is_some_and(|until| until <= now)
                })
                .map(|(uid, _)| uid.clone())
                .collect();
            expired_users.sort();
            for uid in expired_users {
                if let Some(slot) = call.rings.get_mut(&uid) {
                    slot.status = RingStatus::Missed;
                    slot.until = None;
                    actions.ring_events.push(RingEvent {
                        recipients: call.members.clone(),
                        group_id: call.group_id.clone(),
                        call_id: call.id.clone(),
                        user_id: uid,
                        state: RingStatus::Missed.as_str(),
                        by: slot.by.clone(),
                    });
                }
            }
            call.update_alone(seated.len(), now);
            if seated.len() == 1
                && call
                    .alone_since
                    .is_some_and(|since| now.saturating_duration_since(since) >= ALONE_FOR)
            {
                actions.alone_leaves.push((room_id, seated[0].clone()));
            }
        }

        for call_id in cancel_ids {
            if let Some(ended) = self.finish(&call_id, "cancelled") {
                actions.ended.push(ended);
            }
        }
        actions
    }

    /// `(group_id, call_id, members)` for a `g:{call_id}` room.
    pub fn meta_of_room(&self, room_id: &str) -> Option<(&str, &str, &[String])> {
        let call_id = call_of_room(room_id)?;
        let call = self.by_id.get(call_id)?;
        Some((&call.group_id, &call.id, &call.members))
    }

    /// The live call's room id for `group_id` if its id matches `call_id`.
    pub fn room_for(&self, group_id: &str, call_id: &str) -> Option<String> {
        let active = self.by_group.get(group_id)?;
        if active == call_id {
            Some(room_key(call_id))
        } else {
            None
        }
    }

    /// The live call's room id for `group_id`, if any.
    pub fn active_room(&self, group_id: &str) -> Option<String> {
        self.by_group.get(group_id).map(|id| room_key(id))
    }

    /// Every live group call for groups `user_id` belongs to, sorted by `group_id`.
    pub fn ready(
        &self,
        user_id: &str,
        participants_of: impl Fn(&str) -> Vec<Participant>,
    ) -> Vec<ReadyGroupCall> {
        let mut calls: Vec<ReadyGroupCall> = self
            .by_id
            .values()
            .filter(|call| call.members.iter().any(|m| m == user_id))
            .map(|call| ReadyGroupCall {
                group_id: call.group_id.clone(),
                call_id: call.id.clone(),
                started_by: call.started_by.clone(),
                started_at: call.started_at_iso.clone(),
                participants: participants_of(&room_key(&call.id)),
                rings: call.ring_entries(),
            })
            .collect();
        calls.sort_by(|a, b| a.group_id.cmp(&b.group_id));
        calls
    }

    pub fn clear(&mut self) {
        self.by_id.clear();
        self.by_group.clear();
    }

    fn finish(&mut self, call_id: &str, outcome: &'static str) -> Option<EndedEvent> {
        let mut call = self.by_id.remove(call_id)?;
        self.by_group.remove(&call.group_id);

        let mut ringing_uids: Vec<String> = call
            .rings
            .iter()
            .filter(|(_, slot)| slot.status == RingStatus::Ringing)
            .map(|(uid, _)| uid.clone())
            .collect();
        ringing_uids.sort();

        let mut cancelled_rings = Vec::with_capacity(ringing_uids.len());
        for uid in ringing_uids {
            if let Some(slot) = call.rings.get_mut(&uid) {
                slot.status = RingStatus::Cancelled;
                slot.until = None;
                cancelled_rings.push(RingEvent {
                    recipients: call.members.clone(),
                    group_id: call.group_id.clone(),
                    call_id: call.id.clone(),
                    user_id: uid,
                    state: RingStatus::Cancelled.as_str(),
                    by: slot.by.clone(),
                });
            }
        }

        let record = call.record(outcome);
        Some(EndedEvent {
            recipients: call.members,
            group_id: call.group_id,
            call_id: call.id,
            outcome,
            cancelled_rings,
            record,
        })
    }
}

/// Formats `at` as RFC 3339 UTC (`YYYY-MM-DDTHH:MM:SSZ`) without extra dependencies.
pub(crate) fn format_utc(at: SystemTime) -> String {
    let secs = at
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = rem / 3_600;
    let minute = (rem % 3_600) / 60;
    let second = rem % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Howard Hinnant's civil-from-days algorithm (days since 1970-01-01).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + i64::from(m <= 2);
    (year, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn members(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn utc_formatting_matches_rfc3339() {
        assert_eq!(format_utc(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        // 2026-11-16T10:00:00Z = 1794823200 seconds since epoch.
        let t = UNIX_EPOCH + Duration::from_secs(1_794_823_200);
        assert_eq!(format_utc(t), "2026-11-16T10:00:00Z");
    }

    #[test]
    fn start_rings_every_reachable_member_regardless_of_group_size() {
        let mut calls = GroupCalls::default();
        let now = Instant::now();

        // 4-person group: A starts, B, C, D are all rung.
        let StartOutcome::Created { card, recipients } = calls.start(
            "g4",
            "a",
            members(&["a", "b", "c", "d"]),
            |_| false,
            |_| true,
            |_| vec![],
            now,
        ) else {
            panic!("created");
        };
        assert_eq!(recipients, members(&["a", "b", "c", "d"]));
        assert_eq!(card.rings.len(), 3);
        assert!(card.rings.iter().all(|r| r.state == "ringing"));

        // 20-person group (larger than legacy call_room_max=12): all 19 other members are rung.
        let big: Vec<String> = (0..20).map(|i| format!("u{i}")).collect();
        let StartOutcome::Created { card, .. } = calls.start(
            "g20",
            "u0",
            big.clone(),
            |_| false,
            |_| true,
            |_| vec![],
            now,
        ) else {
            panic!("created");
        };
        assert_eq!(card.rings.len(), 19);
        assert!(card.rings.iter().all(|r| r.state == "ringing"));

        // Starting again on an existing live call returns Existing without starting a new one.
        let existing = calls.start(
            "g4",
            "b",
            members(&["a", "b", "c", "d"]),
            |_| false,
            |_| true,
            |_| vec![],
            now,
        );
        assert!(matches!(existing, StartOutcome::Existing { .. }));
    }

    #[test]
    fn busy_and_unreachable_members_are_marked_without_blocking_others() {
        let mut calls = GroupCalls::default();
        let now = Instant::now();
        // B is busy (e.g. in a 1:1 call), C is offline, D is online (e.g. in a voice room -> not busy).
        let StartOutcome::Created { card, recipients } = calls.start(
            "g1",
            "a",
            members(&["a", "b", "c", "d"]),
            |u| u == "b",
            |u| u != "c",
            |_| vec![],
            now,
        ) else {
            panic!("created");
        };
        assert_eq!(recipients, members(&["a", "b", "c", "d"]));
        let state_of = |u: &str| card.rings.iter().find(|r| r.user_id == u).map(|r| r.state);
        assert_eq!(state_of("b"), Some("busy"));
        assert_eq!(state_of("c"), Some("unreachable"));
        assert_eq!(state_of("d"), Some("ringing"));
    }

    #[test]
    fn unring_cancels_one_ring_with_by_and_decline_affects_only_decliner() {
        let mut calls = GroupCalls::default();
        let now = Instant::now();
        let StartOutcome::Created { card, .. } = calls.start(
            "g1",
            "a",
            members(&["a", "b", "c", "d"]),
            |_| false,
            |_| true,
            |_| vec![],
            now,
        ) else {
            panic!("created");
        };
        let room = room_key(&card.call_id);
        calls.on_seated(&room, "a", 1, now);

        // B declines: only B changes, C and D keep ringing.
        let declined = calls
            .decline("g1", &card.call_id, "b", 1, now)
            .expect("decline");
        assert_eq!(declined.user_id, "b");
        assert_eq!(declined.state, "declined");
        assert_eq!(declined.by, "a");
        // Declining twice is not_found.
        assert_eq!(
            calls.decline("g1", &card.call_id, "b", 1, now),
            Err("not_found")
        );

        // A unrings C and also names B (already declined -> no-op).
        let cancelled = calls
            .unring("g1", &card.call_id, "a", &members(&["c", "b"]), 1, now)
            .expect("unring");
        assert_eq!(cancelled.len(), 1);
        assert_eq!(cancelled[0].user_id, "c");
        assert_eq!(cancelled[0].state, "cancelled");
        assert_eq!(cancelled[0].by, "a");

        // C is still a member and can still join without being rung.
        assert!(calls.can_seat(&room, "c"));

        // D answers on join before media.
        let answered = calls.mark_answered("g1", "d", 1, now).expect("answered");
        assert_eq!(answered.user_id, "d");
        assert_eq!(answered.state, "answered");
    }

    #[test]
    fn starter_never_sits_cancels_after_seat_for() {
        let mut calls = GroupCalls::default();
        let now = Instant::now();
        let StartOutcome::Created { card, .. } = calls.start(
            "g1",
            "a",
            members(&["a", "b", "c"]),
            |_| false,
            |_| true,
            |_| vec![],
            now,
        ) else {
            panic!("created");
        };
        let swept = calls.sweep(now + SEAT_FOR, |_| vec![]);
        assert_eq!(swept.ended.len(), 1);
        assert_eq!(swept.ended[0].call_id, card.call_id);
        assert_eq!(swept.ended[0].outcome, "cancelled");
        assert_eq!(swept.ended[0].record.outcome, "cancelled");
        assert_eq!(swept.ended[0].cancelled_rings.len(), 2);
        assert!(calls.active_room("g1").is_none());
    }

    #[test]
    fn starter_sits_alone_then_leaves_is_missed_and_multi_party_is_ended() {
        let mut calls = GroupCalls::default();
        let now = Instant::now();

        // Starter sits, nobody else joins, starter leaves -> missed.
        let StartOutcome::Created { card, .. } = calls.start(
            "g1",
            "a",
            members(&["a", "b"]),
            |_| false,
            |_| true,
            |_| vec![],
            now,
        ) else {
            panic!("created");
        };
        let room = room_key(&card.call_id);
        calls.on_seated(&room, "a", 1, now);
        let ended = calls.on_left(&room, 0, now).expect("ended");
        assert_eq!(ended.outcome, "missed");
        assert_eq!(ended.record.outcome, "missed");
        assert_eq!(ended.cancelled_rings.len(), 1);

        // Three seated: A leaves -> continues; B leaves -> continues; C leaves -> ended.
        let StartOutcome::Created { card, .. } = calls.start(
            "g1",
            "a",
            members(&["a", "b", "c"]),
            |_| false,
            |_| true,
            |_| vec![],
            now,
        ) else {
            panic!("created");
        };
        let room = room_key(&card.call_id);
        calls.on_seated(&room, "a", 1, now);
        calls.on_seated(&room, "b", 2, now);
        calls.on_seated(&room, "c", 3, now);
        assert!(calls.on_left(&room, 2, now).is_none());
        assert!(calls.on_left(&room, 1, now).is_none());
        let ended = calls.on_left(&room, 0, now).expect("ended");
        assert_eq!(ended.outcome, "ended");
        assert_eq!(ended.record.outcome, "ended");
        assert!(calls.on_left(&room, 0, now).is_none());
    }

    #[test]
    fn rings_expire_as_missed_and_lone_participant_leaves_after_alone_for() {
        let mut calls = GroupCalls::default();
        let now = Instant::now();
        let StartOutcome::Created { card, .. } = calls.start(
            "g1",
            "a",
            members(&["a", "b"]),
            |_| false,
            |_| true,
            |_| vec![],
            now,
        ) else {
            panic!("created");
        };
        let room = room_key(&card.call_id);
        calls.on_seated(&room, "a", 1, now);

        // At RING_FOR, B's ring expires as missed and A's alone timer starts.
        let t1 = now + RING_FOR;
        let swept = calls.sweep(t1, |_| vec!["a".to_string()]);
        assert_eq!(swept.ring_events.len(), 1);
        assert_eq!(swept.ring_events[0].user_id, "b");
        assert_eq!(swept.ring_events[0].state, "missed");
        assert!(swept.alone_leaves.is_empty());

        // Before ALONE_FOR, still alone without leave.
        let swept = calls.sweep(t1 + ALONE_FOR - Duration::from_secs(1), |_| {
            vec!["a".to_string()]
        });
        assert!(swept.alone_leaves.is_empty());

        // At ALONE_FOR, A is scheduled to leave as alone.
        let swept = calls.sweep(t1 + ALONE_FOR, |_| vec!["a".to_string()]);
        assert_eq!(swept.alone_leaves, vec![(room.clone(), "a".to_string())]);
    }

    #[test]
    fn same_person_cannot_be_rung_twice_within_ring_for() {
        let mut calls = GroupCalls::default();
        let now = Instant::now();
        let StartOutcome::Created { card, .. } = calls.start(
            "g1",
            "a",
            members(&["a", "b", "c"]),
            |_| false,
            |u| u != "c",
            |_| vec![],
            now,
        ) else {
            panic!("created");
        };
        let room = room_key(&card.call_id);
        calls.on_seated(&room, "a", 1, now);
        calls
            .decline("g1", &card.call_id, "b", 1, now)
            .expect("decline");

        // Trying to ring B again 5s later is ignored; ringing C (who was unreachable, never rung) works.
        let t1 = now + Duration::from_secs(5);
        let events = calls
            .ring(
                "g1",
                &card.call_id,
                "a",
                &members(&["b", "c"]),
                &members(&["a"]),
                |_| false,
                |_| true,
                t1,
            )
            .expect("ring");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].user_id, "c");
        assert_eq!(events[0].state, "ringing");

        // After RING_FOR, B can be rung again.
        let events = calls
            .ring(
                "g1",
                &card.call_id,
                "a",
                &members(&["b"]),
                &members(&["a"]),
                |_| false,
                |_| true,
                now + RING_FOR,
            )
            .expect("ring");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].user_id, "b");
        assert_eq!(events[0].state, "ringing");
    }
}
