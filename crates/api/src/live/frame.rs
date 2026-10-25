//! Frames the server sends, and the durable events behind them.

use db::OutboxRow;
use serde::Serialize;
use serde_json::Value;

use super::call::Occupancy;

/// Who may see a durable event. Invites follow the `invites_all` RLS rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Audience {
    Everyone,
    Managers,
    /// Acted on by the server, never sent.
    Server,
}

/// One outbox row, serialised once and shared by every socket.
#[derive(Debug)]
pub(crate) struct Event {
    pub seq: i64,
    pub topic: String,
    pub audience: Audience,
    /// The person the event is about, for `member.*` and `session.ended`.
    pub subject: Option<String>,
    /// The new role, for `member.role`.
    pub role: Option<String>,
    /// The room, for `room.deleted`.
    pub room: Option<String>,
    pub frame: Option<String>,
}

#[derive(Serialize)]
struct Durable<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    seq: i64,
    #[serde(flatten)]
    payload: &'a Value,
}

impl Event {
    pub fn from_row(row: OutboxRow) -> Self {
        let audience = if row.topic.starts_with("invite.") {
            Audience::Managers
        } else if row.topic.starts_with("session.") {
            Audience::Server
        } else {
            Audience::Everyone
        };
        let member = row.payload.get("member");
        let subject = member
            .and_then(|member| member.get("user_id"))
            .or_else(|| row.payload.get("user_id"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let role = member
            .and_then(|member| member.get("role"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let room = row
            .payload
            .get("room_id")
            .and_then(Value::as_str)
            .map(str::to_string);
        let frame = match audience {
            Audience::Server => None,
            Audience::Everyone | Audience::Managers => {
                match serde_json::to_string(&Durable {
                    kind: &row.topic,
                    seq: row.seq,
                    payload: &row.payload,
                }) {
                    Ok(frame) => Some(frame),
                    Err(error) => {
                        tracing::warn!(%error, seq = row.seq, "outbox payload is not an object");
                        None
                    }
                }
            }
        };
        Self {
            seq: row.seq,
            topic: row.topic,
            audience,
            subject,
            role,
            room,
            frame,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct Me<'a> {
    pub user_id: &'a str,
    pub role: &'a str,
}

#[derive(Serialize)]
#[serde(tag = "type")]
pub(crate) enum Out<'a> {
    #[serde(rename = "ready")]
    Ready {
        seq: i64,
        me: Me<'a>,
        online: &'a [String],
        calls: &'a [Occupancy],
    },
    #[serde(rename = "presence")]
    Presence { user_id: &'a str, online: bool },
    #[serde(rename = "call.joined")]
    CallJoined { room_id: &'a str, user_id: &'a str },
    #[serde(rename = "call.left")]
    CallLeft {
        room_id: &'a str,
        user_id: &'a str,
        reason: &'static str,
    },
    /// A client request succeeded.
    #[serde(rename = "ok")]
    Ok {
        #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
        reference: Option<&'a Value>,
    },
    #[serde(rename = "resync")]
    Resync,
    #[serde(rename = "pong")]
    Pong,
    #[serde(rename = "error")]
    Error {
        #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
        reference: Option<&'a Value>,
        code: &'static str,
    },
}

impl Out<'_> {
    pub fn text(&self) -> String {
        // Every variant is plain strings, numbers, and sequences, so this cannot fail.
        serde_json::to_string(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::{Audience, Event, Me, Out};
    use crate::live::call::{Occupancy, Participant};
    use db::OutboxRow;
    use serde_json::{json, Value};

    #[test]
    fn a_durable_frame_is_type_then_seq_then_the_payload() {
        let event = Event::from_row(OutboxRow {
            seq: 7,
            topic: "room.renamed".to_string(),
            payload: json!({"room": {"id": "r", "name": "Lobby"}}),
        });
        assert_eq!(event.audience, Audience::Everyone);
        let frame = event.frame.expect("frame");
        assert!(
            frame.starts_with(r#"{"type":"room.renamed","seq":7,"#),
            "{frame}"
        );
        let value: Value = serde_json::from_str(&frame).expect("json");
        assert_eq!(value["room"]["name"], "Lobby");
    }

    #[test]
    fn invites_go_to_managers_and_sessions_go_nowhere() {
        let invite = Event::from_row(OutboxRow {
            seq: 1,
            topic: "invite.created".to_string(),
            payload: json!({"invite": {"id": "i"}}),
        });
        assert_eq!(invite.audience, Audience::Managers);
        let ended = Event::from_row(OutboxRow {
            seq: 2,
            topic: "session.ended".to_string(),
            payload: json!({"user_id": "u"}),
        });
        assert_eq!(ended.audience, Audience::Server);
        assert_eq!(ended.subject.as_deref(), Some("u"));
        assert!(ended.frame.is_none());
    }

    #[test]
    fn a_member_event_names_its_subject_and_role() {
        let event = Event::from_row(OutboxRow {
            seq: 3,
            topic: "member.role".to_string(),
            payload: json!({"member": {"user_id": "u", "display_name": "A", "role": "admin"}}),
        });
        assert_eq!(event.subject.as_deref(), Some("u"));
        assert_eq!(event.role.as_deref(), Some("admin"));
    }

    #[test]
    fn ready_and_error_have_their_documented_shape() {
        let online = ["u".to_string()];
        let ready = Out::Ready {
            seq: 4,
            me: Me {
                user_id: "u",
                role: "owner",
            },
            online: &online,
            calls: &[Occupancy {
                room_id: "r".to_string(),
                participants: vec![Participant {
                    user_id: "u".to_string(),
                }],
            }],
        };
        assert_eq!(
            ready.text(),
            r#"{"type":"ready","seq":4,"me":{"user_id":"u","role":"owner"},"online":["u"],"calls":[{"room_id":"r","participants":[{"user_id":"u"}]}]}"#
        );
        let reference = json!("7");
        let error = Out::Error {
            reference: Some(&reference),
            code: "unknown_type",
        };
        assert_eq!(
            error.text(),
            r#"{"type":"error","ref":"7","code":"unknown_type"}"#
        );
        assert_eq!(Out::Pong.text(), r#"{"type":"pong"}"#);
        assert_eq!(
            Out::Ok {
                reference: Some(&reference)
            }
            .text(),
            r#"{"type":"ok","ref":"7"}"#
        );
        assert_eq!(
            Out::CallLeft {
                room_id: "r",
                user_id: "u",
                reason: "kicked"
            }
            .text(),
            r#"{"type":"call.left","room_id":"r","user_id":"u","reason":"kicked"}"#
        );
    }
}
