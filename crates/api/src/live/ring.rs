//! A direct call before it is a seat. Memory only. A restart drops a ring and writes nothing.
//! The row in `direct_call_log` is written when the ring reaches an end.

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use super::call::Participant;

/// How long a ring waits for an answer.
pub const RING_FOR: Duration = Duration::from_secs(30);
/// How long an accepted call waits for both people to take a media seat.
pub const SEAT_FOR: Duration = Duration::from_secs(15);
/// Ring, accept, decline, and cancel: a burst, then one more this often.
pub const RING_BURST: u32 = 3;
pub const RING_EVERY: Duration = Duration::from_secs(10);

const PREFIX: &str = "d:";

pub(crate) fn room_key(ring_id: &str) -> String {
    format!("{PREFIX}{ring_id}")
}

fn ring_of_room(room_id: &str) -> Option<&str> {
    room_id.strip_prefix(PREFIX)
}

/// A new ring id. Sixteen random bytes, shaped as a uuid so the log can store it.
pub(crate) fn new_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("the OS random number generator failed");
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
        bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Ringing,
    Accepted,
    Live,
}

struct Ring {
    id: String,
    direct_id: String,
    caller_id: String,
    callee_id: String,
    phase: Phase,
    until: Instant,
    accepted_at: Option<SystemTime>,
    /// Set when a live 1:1 call is moving into a group call (#62). Until this deadline,
    /// joining `moving_to` leaves `d:{id}` as `moved` without cascading `peer_left`.
    moving_until: Option<Instant>,
    moving_to: Option<String>,
}

/// What `ready` says about a ring this person is in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReadyRing {
    pub direct_id: String,
    pub ring_id: String,
    pub caller_id: String,
    pub callee_id: String,
    pub accepted: bool,
}

/// What `ready` says about a direct call this person is seated in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReadyDirect {
    pub direct_id: String,
    pub ring_id: String,
    pub participants: Vec<Participant>,
}

/// A ring the sweep should end. Seats are left before [`Rings::take_due`], while it still exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Due {
    pub id: String,
    pub room_id: String,
    pub direct_id: String,
    pub caller_id: String,
    pub callee_id: String,
    pub accepted: bool,
    pub moving: bool,
}

/// `call.ring` placed a ring, or the caller is told the other side is busy.
pub(crate) enum Start {
    Placed(Notice),
    Busy(Notice),
}

/// A frame for the two parties, or for the caller alone when the other side is busy.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Notice {
    pub users: Vec<String>,
    pub kind: Kind,
    pub record: Option<Record>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Kind {
    Ringing(Card),
    Accepted(Card),
    Declined(Card),
    Cancelled(Card),
    Missed(Card),
    /// The other person is already in a direct call. The caller alone hears this.
    Busy {
        direct_id: String,
    },
    /// Accepted, and media did not come up for both. `call.left` `media_timeout`.
    MediaTimeout(Card),
    /// The seats already told `call.left`. This only writes the log.
    Ended(Card),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Card {
    pub direct_id: String,
    pub ring_id: String,
    pub caller_id: String,
    pub callee_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Record {
    pub ring_id: String,
    pub direct_id: String,
    pub caller_id: String,
    pub callee_id: String,
    pub outcome: &'static str,
    pub accepted_at: Option<f64>,
}

#[derive(Default)]
pub(crate) struct Rings {
    by_id: HashMap<String, Ring>,
    by_user: HashMap<String, String>,
}

impl Rings {
    /// Starts a ring. The other person already in a direct ring or call is `busy`, and so is
    /// the caller. The first of two people ringing each other wins.
    pub fn start(&mut self, direct_id: &str, caller_id: &str, callee_id: &str) -> Start {
        if self.by_user.contains_key(caller_id) || self.by_user.contains_key(callee_id) {
            return Start::Busy(Notice {
                users: vec![caller_id.to_string()],
                kind: Kind::Busy {
                    direct_id: direct_id.to_string(),
                },
                record: None,
            });
        }
        let id = new_id();
        let ring = Ring {
            id: id.clone(),
            direct_id: direct_id.to_string(),
            caller_id: caller_id.to_string(),
            callee_id: callee_id.to_string(),
            phase: Phase::Ringing,
            until: Instant::now() + RING_FOR,
            accepted_at: None,
            moving_until: None,
            moving_to: None,
        };
        let card = ring.card();
        self.by_user.insert(caller_id.to_string(), id.clone());
        self.by_user.insert(callee_id.to_string(), id.clone());
        self.by_id.insert(id, ring);
        Start::Placed(Notice {
            users: vec![caller_id.to_string(), callee_id.to_string()],
            kind: Kind::Ringing(card),
            record: None,
        })
    }

    /// The callee picks up. The ring must still be ringing on this direct.
    pub fn accept(&mut self, direct_id: &str, user_id: &str) -> Result<Notice, &'static str> {
        let ring = self.ring_of(user_id).ok_or("not_found")?;
        if ring.direct_id != direct_id || ring.callee_id != user_id || ring.phase != Phase::Ringing
        {
            return Err("not_found");
        }
        let id = ring.id.clone();
        let ring = self.by_id.get_mut(&id).expect("ring");
        ring.phase = Phase::Accepted;
        ring.until = Instant::now() + SEAT_FOR;
        ring.accepted_at = Some(SystemTime::now());
        let card = ring.card();
        let users = ring.parties();
        Ok(Notice {
            users,
            kind: Kind::Accepted(card),
            record: None,
        })
    }

    pub fn decline(&mut self, direct_id: &str, user_id: &str) -> Result<Notice, &'static str> {
        let ring = self.ring_of(user_id).ok_or("not_found")?;
        if ring.direct_id != direct_id || ring.callee_id != user_id || ring.phase != Phase::Ringing
        {
            return Err("not_found");
        }
        let id = ring.id.clone();
        Ok(self.remove(&id, Kind::Declined, "declined"))
    }

    pub fn cancel(&mut self, direct_id: &str, user_id: &str) -> Result<Notice, &'static str> {
        let ring = self.ring_of(user_id).ok_or("not_found")?;
        if ring.direct_id != direct_id || ring.caller_id != user_id || ring.phase != Phase::Ringing
        {
            return Err("not_found");
        }
        let id = ring.id.clone();
        Ok(self.remove(&id, Kind::Cancelled, "cancelled"))
    }

    /// `call.leave` while this person is only ringing out. A seat is the call registry's job.
    pub fn cancel_outgoing(&mut self, user_id: &str) -> Option<Notice> {
        let ring = self.ring_of(user_id)?;
        if ring.caller_id != user_id || ring.phase != Phase::Ringing {
            return None;
        }
        let id = ring.id.clone();
        Some(self.remove(&id, Kind::Cancelled, "cancelled"))
    }

    /// The SFU room for an accepted direct, if `user_id` is a party and media may start.
    pub fn join_key(&self, direct_id: &str, user_id: &str) -> Result<String, &'static str> {
        let ring = self.ring_of(user_id).ok_or("not_found")?;
        if ring.direct_id != direct_id {
            return Err("not_found");
        }
        if ring.phase == Phase::Ringing {
            return Err("not_found");
        }
        Ok(room_key(&ring.id))
    }

    /// Both people have media. The seat timer no longer ends the call.
    pub fn mark_live(&mut self, room_id: &str) {
        let Some(id) = ring_of_room(room_id) else {
            return;
        };
        if let Some(ring) = self.by_id.get_mut(id) {
            if ring.phase == Phase::Accepted {
                ring.phase = Phase::Live;
            }
        }
    }

    /// A live direct call's room is empty: the call ended. An accepted call whose room is
    /// empty because someone left before both had media is cancelled.
    pub fn on_room_empty(&mut self, room_id: &str) -> Option<Notice> {
        let id = ring_of_room(room_id)?.to_string();
        let phase = self.by_id.get(&id)?.phase;
        match phase {
            Phase::Live => Some(self.remove(&id, Kind::Ended, "ended")),
            Phase::Accepted => Some(self.remove(&id, Kind::Cancelled, "cancelled")),
            Phase::Ringing => None,
        }
    }

    /// Membership ended for `user_id`. Drops a ring they are in. A live call is `ended`;
    /// anything earlier is `cancelled`.
    pub fn drop_user(&mut self, user_id: &str) -> Option<Notice> {
        let id = self.by_user.get(user_id)?.clone();
        let phase = self.by_id.get(&id)?.phase;
        match phase {
            Phase::Live => Some(self.remove(&id, Kind::Ended, "ended")),
            Phase::Ringing | Phase::Accepted => {
                Some(self.remove(&id, Kind::Cancelled, "cancelled"))
            }
        }
    }

    pub fn parties(&self, room_id: &str) -> Option<Vec<String>> {
        let ring = self.by_id.get(ring_of_room(room_id)?)?;
        Some(ring.parties())
    }

    /// Whether `user_id` currently participates in any direct ring or direct call.
    pub fn has_user(&self, user_id: &str) -> bool {
        self.by_user.contains_key(user_id)
    }

    /// Validates that `ring_id` is a `Live` direct call on `direct_id` involving `user_id` and
    /// returns the other party's user id without mutating state.
    pub fn validate_move(
        &self,
        direct_id: &str,
        ring_id: &str,
        user_id: &str,
    ) -> Result<String, &'static str> {
        let ring = self.by_id.get(ring_id).ok_or("not_found")?;
        if ring.direct_id != direct_id || ring.phase != Phase::Live {
            return Err("not_found");
        }
        if ring.caller_id == user_id {
            Ok(ring.callee_id.clone())
        } else if ring.callee_id == user_id {
            Ok(ring.caller_id.clone())
        } else {
            Err("not_found")
        }
    }

    /// Marks a `Live` direct call as moving into `target_room_id` (`g:{call_id}`) with a
    /// `SEAT_FOR` deadline. Returns the other party's user id.
    pub fn begin_move(
        &mut self,
        direct_id: &str,
        ring_id: &str,
        user_id: &str,
        target_room_id: &str,
        now: Instant,
    ) -> Result<String, &'static str> {
        let peer = self.validate_move(direct_id, ring_id, user_id)?;
        let ring = self.by_id.get_mut(ring_id).expect("validated ring");
        ring.moving_until = Some(now + SEAT_FOR);
        ring.moving_to = Some(target_room_id.to_string());
        Ok(peer)
    }

    /// True while `direct_room_id` is a live direct call actively moving into `target_room_id`.
    pub fn is_moving_to(&self, direct_room_id: &str, target_room_id: &str) -> bool {
        let Some(id) = ring_of_room(direct_room_id) else {
            return false;
        };
        self.by_id.get(id).is_some_and(|ring| {
            ring.phase == Phase::Live
                && ring.moving_until.is_some()
                && ring.moving_to.as_deref() == Some(target_room_id)
        })
    }

    pub fn direct_of_room(&self, room_id: &str) -> Option<&str> {
        Some(&self.by_id.get(ring_of_room(room_id)?)?.direct_id)
    }

    pub fn ready(&self, user_id: &str) -> Option<ReadyRing> {
        let ring = self.ring_of(user_id)?;
        if ring.phase == Phase::Live {
            return None;
        }
        Some(ReadyRing {
            direct_id: ring.direct_id.clone(),
            ring_id: ring.id.clone(),
            caller_id: ring.caller_id.clone(),
            callee_id: ring.callee_id.clone(),
            accepted: ring.phase == Phase::Accepted,
        })
    }

    /// Rings whose wait is over, plus live calls whose move-to-group deadline elapsed.
    pub fn due(&self, now: Instant) -> Vec<Due> {
        self.by_id
            .values()
            .filter(|ring| {
                (ring.phase != Phase::Live && ring.until <= now)
                    || (ring.phase == Phase::Live
                        && ring.moving_until.is_some_and(|until| until <= now))
            })
            .map(|ring| Due {
                id: ring.id.clone(),
                room_id: room_key(&ring.id),
                direct_id: ring.direct_id.clone(),
                caller_id: ring.caller_id.clone(),
                callee_id: ring.callee_id.clone(),
                accepted: ring.phase == Phase::Accepted,
                moving: ring.phase == Phase::Live
                    && ring.moving_until.is_some_and(|until| until <= now),
            })
            .collect()
    }

    /// Accepted, and the seat window has elapsed. A ring that just went live is not.
    pub fn accepted_due(&self, id: &str, now: Instant) -> bool {
        self.by_id
            .get(id)
            .is_some_and(|ring| ring.phase == Phase::Accepted && ring.until <= now)
    }

    /// Live, moving to a group call, and the move deadline has elapsed.
    pub fn moving_due(&self, id: &str, now: Instant) -> bool {
        self.by_id.get(id).is_some_and(|ring| {
            ring.phase == Phase::Live && ring.moving_until.is_some_and(|until| until <= now)
        })
    }

    /// Ends one due ring. A live call without an elapsed move deadline stays.
    pub fn take_due(&mut self, id: &str, now: Instant) -> Option<Notice> {
        let (phase, until, moving_until) = {
            let ring = self.by_id.get(id)?;
            (ring.phase, ring.until, ring.moving_until)
        };
        if phase == Phase::Live {
            if moving_until.is_some_and(|u| u <= now) {
                return Some(self.remove(id, Kind::Ended, "ended"));
            }
            return None;
        }
        if until > now {
            return None;
        }
        if phase == Phase::Ringing {
            Some(self.remove(id, Kind::Missed, "missed"))
        } else {
            Some(self.remove(id, Kind::MediaTimeout, "ended"))
        }
    }

    /// Rings whose wait is over, including live calls past their move deadline.
    #[cfg(test)]
    pub fn expire_due(&mut self, now: Instant) -> Vec<Notice> {
        let due: Vec<String> = self
            .by_id
            .iter()
            .filter(|(_, ring)| {
                (ring.phase != Phase::Live && ring.until <= now)
                    || (ring.phase == Phase::Live
                        && ring.moving_until.is_some_and(|until| until <= now))
            })
            .map(|(id, _)| id.clone())
            .collect();
        due.into_iter()
            .map(|id| {
                let phase = self
                    .by_id
                    .get(&id)
                    .map(|ring| ring.phase)
                    .unwrap_or(Phase::Ringing);
                match phase {
                    Phase::Ringing => self.remove(&id, Kind::Missed, "missed"),
                    Phase::Accepted => self.remove(&id, Kind::MediaTimeout, "ended"),
                    Phase::Live => self.remove(&id, Kind::Ended, "ended"),
                }
            })
            .collect()
    }

    fn ring_of(&self, user_id: &str) -> Option<&Ring> {
        self.by_id.get(self.by_user.get(user_id)?)
    }

    fn remove(&mut self, id: &str, kind_of: fn(Card) -> Kind, outcome: &'static str) -> Notice {
        let ring = self.by_id.remove(id).expect("ring");
        self.by_user.remove(&ring.caller_id);
        self.by_user.remove(&ring.callee_id);
        let card = ring.card();
        let record = Record {
            ring_id: ring.id,
            direct_id: ring.direct_id,
            caller_id: ring.caller_id.clone(),
            callee_id: ring.callee_id.clone(),
            outcome,
            accepted_at: ring
                .accepted_at
                .and_then(|at| at.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs_f64())),
        };
        Notice {
            users: vec![ring.caller_id, ring.callee_id],
            kind: kind_of(card),
            record: Some(record),
        }
    }
}

impl Ring {
    fn card(&self) -> Card {
        Card {
            direct_id: self.direct_id.clone(),
            ring_id: self.id.clone(),
            caller_id: self.caller_id.clone(),
            callee_id: self.callee_id.clone(),
        }
    }

    fn parties(&self) -> Vec<String> {
        vec![self.caller_id.clone(), self.callee_id.clone()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(rings: &mut Rings) -> Notice {
        match rings.start("direct", "caller", "callee") {
            Start::Placed(notice) => notice,
            Start::Busy(_) => panic!("ring"),
        }
    }

    #[test]
    fn the_first_ring_wins_and_a_second_is_busy() {
        let mut rings = Rings::default();
        let started = pair(&mut rings);
        assert!(matches!(started.kind, Kind::Ringing(_)));
        let Start::Busy(busy) = rings.start("direct", "callee", "caller") else {
            panic!("busy");
        };
        assert!(matches!(busy.kind, Kind::Busy { .. }));
        assert_eq!(busy.users, vec!["callee".to_string()]);
        assert!(matches!(
            rings.start("other", "caller", "someone"),
            Start::Busy(_)
        ));
    }

    #[test]
    fn decline_cancel_and_accept_follow_who_may() {
        let mut rings = Rings::default();
        pair(&mut rings);
        assert_eq!(rings.cancel("direct", "callee"), Err("not_found"));
        assert_eq!(rings.decline("direct", "caller"), Err("not_found"));
        let accepted = rings.accept("direct", "callee").expect("accept");
        assert!(matches!(accepted.kind, Kind::Accepted(_)));
        assert!(rings.join_key("direct", "caller").is_ok());
        assert_eq!(rings.decline("direct", "callee"), Err("not_found"));
    }

    #[test]
    fn a_ring_that_waits_out_is_missed_and_an_accepted_one_ends() {
        let mut rings = Rings::default();
        pair(&mut rings);
        let missed = rings.expire_due(Instant::now() + RING_FOR);
        assert_eq!(missed.len(), 1);
        assert!(matches!(missed[0].kind, Kind::Missed(_)));
        assert_eq!(
            missed[0].record.as_ref().map(|record| record.outcome),
            Some("missed")
        );
        assert!(rings.ready("caller").is_none());

        pair(&mut rings);
        rings.accept("direct", "callee").expect("accept");
        let ended = rings.expire_due(Instant::now() + SEAT_FOR);
        assert!(matches!(ended[0].kind, Kind::MediaTimeout(_)));
        assert_eq!(
            ended[0].record.as_ref().map(|record| record.outcome),
            Some("ended")
        );
    }

    #[test]
    fn a_live_call_is_not_swept_and_an_empty_room_ends_it() {
        let mut rings = Rings::default();
        let started = pair(&mut rings);
        let Kind::Ringing(card) = started.kind else {
            panic!("ring")
        };
        rings.accept("direct", "callee").expect("accept");
        let key = room_key(&card.ring_id);
        rings.mark_live(&key);
        assert!(rings
            .expire_due(Instant::now() + RING_FOR + SEAT_FOR)
            .is_empty());
        let ended = rings.on_room_empty(&key).expect("ended");
        assert_eq!(ended.record.expect("record").outcome, "ended");
        assert!(rings.parties(&key).is_none());
    }

    #[test]
    fn moving_direct_expires_at_deadline_as_ended() {
        let mut rings = Rings::default();
        let started = pair(&mut rings);
        let Kind::Ringing(card) = started.kind else {
            panic!("ring");
        };
        rings.accept("direct", "callee").expect("accept");
        let key = room_key(&card.ring_id);
        rings.mark_live(&key);

        let now = Instant::now();
        let peer = rings
            .begin_move("direct", &card.ring_id, "caller", "g:grp1", now)
            .expect("begin move");
        assert_eq!(peer, "callee");
        assert!(rings.is_moving_to(&key, "g:grp1"));
        assert!(!rings.is_moving_to(&key, "g:other"));

        // Before SEAT_FOR: not due.
        assert!(rings
            .due(now + SEAT_FOR - Duration::from_secs(1))
            .is_empty());

        // At SEAT_FOR: due with moving = true, take_due ends it with outcome "ended".
        let due = rings.due(now + SEAT_FOR);
        assert_eq!(due.len(), 1);
        assert!(due[0].moving);
        assert!(rings.moving_due(&card.ring_id, now + SEAT_FOR));
        let notice = rings
            .take_due(&card.ring_id, now + SEAT_FOR)
            .expect("ended");
        assert!(matches!(notice.kind, Kind::Ended(_)));
        assert_eq!(notice.record.expect("record").outcome, "ended");
        assert!(!rings.has_user("caller"));
        assert!(!rings.has_user("callee"));
    }
}
