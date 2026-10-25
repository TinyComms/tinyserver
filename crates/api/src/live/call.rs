//! Who is in which room's call. Memory only; a restart ends every call.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;
use tokio::time::{Duration, Instant};

/// Why someone left a call. Sent as `call.left` `reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reason {
    Left,
    JoinedElsewhere,
    Disconnected,
    RoomDeleted,
    Removed,
    SessionEnded,
    Kicked,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Left => "left",
            Self::JoinedElsewhere => "joined_elsewhere",
            Self::Disconnected => "disconnected",
            Self::RoomDeleted => "room_deleted",
            Self::Removed => "removed",
            Self::SessionEnded => "session_ended",
            Self::Kicked => "kicked",
        }
    }
}

/// A change everyone is told about.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Change {
    Joined {
        room_id: String,
        user_id: String,
    },
    Left {
        room_id: String,
        user_id: String,
        reason: Reason,
    },
}

/// Why a join was refused. The `error` code is in `docs/calls.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    Full,
    ServerFull,
    /// The server is shutting down.
    Closing,
}

impl Refused {
    pub fn code(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::ServerFull => "server_full",
            Self::Closing => "unavailable",
        }
    }
}

/// One room's call in `ready.calls`.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct Occupancy {
    pub room_id: String,
    pub participants: Vec<Participant>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct Participant {
    pub user_id: String,
}

/// Where a person sits. `conn` is the socket that joined; `None` once it closed.
struct Seat {
    room_id: String,
    conn: Option<u64>,
    epoch: u64,
}

#[derive(Default)]
pub(crate) struct Calls {
    /// Room to participants, in join order.
    rooms: BTreeMap<String, Vec<String>>,
    seats: HashMap<String, Seat>,
    epoch: u64,
}

impl Calls {
    /// Seats `user_id` in `room_id` for socket `conn`, leaving any other call first. Joining
    /// the room they are already in only moves the seat to `conn`.
    pub fn join(
        &mut self,
        user_id: &str,
        room_id: &str,
        conn: u64,
        room_max: usize,
        server_max: usize,
    ) -> Result<Vec<Change>, Refused> {
        if let Some(seat) = self.seats.get_mut(user_id) {
            if seat.room_id == room_id {
                seat.conn = Some(conn);
                return Ok(Vec::new());
            }
        }
        let here = self.rooms.get(room_id).map_or(0, Vec::len);
        if here >= room_max {
            return Err(Refused::Full);
        }
        if !self.seats.contains_key(user_id) && self.seats.len() >= server_max {
            return Err(Refused::ServerFull);
        }
        let mut changes = Vec::new();
        changes.extend(self.leave(user_id, Reason::JoinedElsewhere));
        self.epoch += 1;
        self.seats.insert(
            user_id.to_string(),
            Seat {
                room_id: room_id.to_string(),
                conn: Some(conn),
                epoch: self.epoch,
            },
        );
        self.rooms
            .entry(room_id.to_string())
            .or_default()
            .push(user_id.to_string());
        changes.push(Change::Joined {
            room_id: room_id.to_string(),
            user_id: user_id.to_string(),
        });
        Ok(changes)
    }

    pub fn leave(&mut self, user_id: &str, reason: Reason) -> Option<Change> {
        let seat = self.seats.remove(user_id)?;
        if let Some(people) = self.rooms.get_mut(&seat.room_id) {
            people.retain(|person| person != user_id);
            if people.is_empty() {
                self.rooms.remove(&seat.room_id);
            }
        }
        Some(Change::Left {
            room_id: seat.room_id,
            user_id: user_id.to_string(),
            reason,
        })
    }

    /// The room `user_id` is in.
    pub fn room_of(&self, user_id: &str) -> Option<&str> {
        self.seats.get(user_id).map(|seat| seat.room_id.as_str())
    }

    /// The socket `conn` closed. If it held the seat, returns an epoch for `expire`.
    pub fn orphan(&mut self, user_id: &str, conn: u64) -> Option<u64> {
        let seat = self.seats.get_mut(user_id)?;
        if seat.conn != Some(conn) {
            return None;
        }
        seat.conn = None;
        self.epoch += 1;
        seat.epoch = self.epoch;
        Some(seat.epoch)
    }

    /// Leaves if the seat is still the one `orphan` left, with no socket rejoined since.
    pub fn expire(&mut self, user_id: &str, epoch: u64) -> Option<Change> {
        let seat = self.seats.get(user_id)?;
        if seat.conn.is_some() || seat.epoch != epoch {
            return None;
        }
        self.leave(user_id, Reason::Disconnected)
    }

    pub fn end_room(&mut self, room_id: &str, reason: Reason) -> Vec<Change> {
        let people = self.rooms.get(room_id).cloned().unwrap_or_default();
        people
            .iter()
            .filter_map(|user_id| self.leave(user_id, reason))
            .collect()
    }

    pub fn clear(&mut self) {
        self.rooms.clear();
        self.seats.clear();
    }

    pub fn snapshot(&self) -> Vec<Occupancy> {
        self.rooms
            .iter()
            .map(|(room_id, people)| Occupancy {
                room_id: room_id.clone(),
                participants: people
                    .iter()
                    .map(|user_id| Participant {
                        user_id: user_id.clone(),
                    })
                    .collect(),
            })
            .collect()
    }
}

/// Joins and leaves one socket may make: a burst, then one more every `every`.
pub(crate) struct Moves {
    burst: f64,
    every: Duration,
    tokens: f64,
    at: Instant,
}

impl Moves {
    pub fn new(burst: u32, every: Duration) -> Self {
        let burst = f64::from(burst.max(1));
        Self {
            burst,
            every: every.max(Duration::from_millis(1)),
            tokens: burst,
            at: Instant::now(),
        }
    }

    pub fn take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.at);
        self.at = now;
        self.tokens =
            (self.tokens + elapsed.as_secs_f64() / self.every.as_secs_f64()).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Calls, Change, Moves, Reason, Refused};
    use std::time::Duration;

    fn joined(room_id: &str, user_id: &str) -> Change {
        Change::Joined {
            room_id: room_id.to_string(),
            user_id: user_id.to_string(),
        }
    }

    fn left(room_id: &str, user_id: &str, reason: Reason) -> Change {
        Change::Left {
            room_id: room_id.to_string(),
            user_id: user_id.to_string(),
            reason,
        }
    }

    #[test]
    fn joining_another_room_leaves_the_first() {
        let mut calls = Calls::default();
        assert_eq!(calls.join("u", "a", 1, 12, 32), Ok(vec![joined("a", "u")]));
        assert_eq!(
            calls.join("u", "b", 1, 12, 32),
            Ok(vec![
                left("a", "u", Reason::JoinedElsewhere),
                joined("b", "u")
            ])
        );
        assert_eq!(calls.room_of("u"), Some("b"));
        assert_eq!(calls.snapshot().len(), 1);
    }

    #[test]
    fn a_second_socket_in_the_same_room_takes_the_seat_without_a_change() {
        let mut calls = Calls::default();
        assert!(calls.join("u", "a", 1, 12, 32).is_ok());
        assert_eq!(calls.join("u", "a", 2, 12, 32), Ok(Vec::new()));
        assert_eq!(calls.orphan("u", 1), None);
        let epoch = calls.orphan("u", 2).expect("seat held by 2");
        assert!(calls.join("u", "a", 3, 12, 32).is_ok());
        assert_eq!(calls.expire("u", epoch), None);
        assert_eq!(calls.room_of("u"), Some("a"));
    }

    #[test]
    fn an_orphaned_seat_expires() {
        let mut calls = Calls::default();
        assert!(calls.join("u", "a", 1, 12, 32).is_ok());
        let epoch = calls.orphan("u", 1).expect("epoch");
        assert_eq!(
            calls.expire("u", epoch),
            Some(left("a", "u", Reason::Disconnected))
        );
        assert!(calls.snapshot().is_empty());
    }

    #[test]
    fn caps_count_people_not_moves() {
        let mut calls = Calls::default();
        assert!(calls.join("u", "a", 1, 2, 3).is_ok());
        assert!(calls.join("v", "a", 2, 2, 3).is_ok());
        assert_eq!(calls.join("w", "a", 3, 2, 3), Err(Refused::Full));
        assert!(calls.join("w", "b", 3, 2, 3).is_ok());
        assert_eq!(calls.join("x", "b", 4, 2, 3), Err(Refused::ServerFull));
        assert!(calls.join("u", "b", 1, 2, 3).is_ok());
    }

    #[test]
    fn the_default_room_cap_refuses_the_thirteenth() {
        let limits = crate::live::Limits::default();
        let mut calls = Calls::default();
        for n in 0..12 {
            let user_id = format!("u{n}");
            let joined = calls.join(
                &user_id,
                "a",
                n,
                limits.call_room_max,
                limits.call_server_max,
            );
            assert!(joined.is_ok(), "{user_id}");
        }
        assert_eq!(
            calls.join("u12", "a", 12, limits.call_room_max, limits.call_server_max),
            Err(Refused::Full)
        );
    }

    #[test]
    fn ending_a_room_empties_it() {
        let mut calls = Calls::default();
        assert!(calls.join("u", "a", 1, 12, 32).is_ok());
        assert!(calls.join("v", "a", 2, 12, 32).is_ok());
        assert_eq!(
            calls.end_room("a", Reason::RoomDeleted),
            vec![
                left("a", "u", Reason::RoomDeleted),
                left("a", "v", Reason::RoomDeleted)
            ]
        );
        assert!(calls.snapshot().is_empty());
    }

    #[test]
    fn moves_allow_a_burst_then_refuse() {
        let mut moves = Moves::new(2, Duration::from_secs(60));
        assert!(moves.take());
        assert!(moves.take());
        assert!(!moves.take());
    }
}
