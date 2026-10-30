//! Frames the server sends and reads, and the durable events behind them.

use db::OutboxRow;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::call::{Occupancy, Participant};

/// Who may see a durable event. Invites follow the invite RLS rule, bans the ban one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Audience {
    Everyone,
    /// create_invites or manage_invites.
    Invites,
    /// ban_members.
    Bans,
    /// Only the user ids on the event. Direct messages and their reads use this.
    Users,
    /// Acted on by the server, never sent.
    Server,
}

impl Audience {
    /// Whether someone with server-wide `permissions` gets the frame.
    pub fn admits(self, permissions: i64) -> bool {
        use db::perm;
        match self {
            Self::Everyone => true,
            Self::Invites => permissions & (perm::CREATE_INVITES | perm::MANAGE_INVITES) != 0,
            Self::Bans => perm::has(permissions, perm::BAN_MEMBERS),
            Self::Users | Self::Server => false,
        }
    }
}

/// One outbox row, serialised once and shared by every socket.
#[derive(Debug)]
pub(crate) struct Event {
    pub seq: i64,
    pub topic: String,
    pub audience: Audience,
    /// The person the event is about, for `member.*` and `session.ended`.
    pub subject: Option<String>,
    /// The room, for `room.deleted`.
    pub room: Option<String>,
    /// For `member.timeout`: a timeout was set, not ended.
    pub timed_out: bool,
    /// Set when `audience` is `Users`.
    pub users: Vec<String>,
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
        let audience = if !row.users.is_empty() {
            Audience::Users
        } else if row.topic.starts_with("invite.") {
            Audience::Invites
        } else if row.topic == "member.banned" {
            Audience::Bans
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
        let room = row
            .payload
            .get("room_id")
            .and_then(Value::as_str)
            .map(str::to_string);
        let timed_out = row.topic == "member.timeout"
            && row
                .payload
                .get("timeout_until")
                .is_some_and(|until| !until.is_null());
        let frame = match audience {
            Audience::Server => None,
            Audience::Everyone | Audience::Invites | Audience::Bans | Audience::Users => {
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
            room,
            timed_out,
            users: row.users,
            frame,
        }
    }
}

/// One client message. Which fields a `type` needs is the handler's business.
#[derive(Debug, Deserialize)]
pub(crate) struct Incoming {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(rename = "ref")]
    pub reference: Option<Value>,
    pub room_id: Option<String>,
    /// `typing`: the channel or direct conversation.
    pub conversation_id: Option<String>,
    pub user_id: Option<String>,
    pub sdp: Option<String>,
    pub muted: Option<bool>,
    pub deafened: Option<bool>,
    /// `call.state`: priority speaker held, honoured only with priority_speaker.
    pub priority: Option<bool>,
    /// `call.moderate`.
    pub server_muted: Option<bool>,
    pub server_deafened: Option<bool>,
    /// `call.quality`: `high`, `low`, or `off`.
    pub video: Option<String>,
    /// `call.join`: the highest end-to-end encryption version the client speaks. Read
    /// leniently: a number of 1 or more, anything else is none.
    pub e2ee: Option<Value>,
    /// `call.e2ee`: `key_package`, `commit`, or `invalid`.
    pub op: Option<String>,
    /// `call.e2ee` `commit`: the epoch it moves the group from.
    pub epoch: Option<u64>,
    /// `call.e2ee`: base64 key package or commit, and a commit's welcome.
    pub data: Option<String>,
    pub welcome: Option<String>,
}

impl Incoming {
    /// The end-to-end encryption version a `call.join` offers. 0 is none.
    pub fn e2ee_version(&self) -> u64 {
        self.e2ee.as_ref().and_then(Value::as_u64).unwrap_or(0)
    }
}

impl Incoming {
    /// `None` for anything but a JSON object with a string `type`.
    pub fn parse(text: &str) -> Option<Self> {
        serde_json::from_str(text).ok()
    }
}

#[derive(Serialize)]
pub(crate) struct Me<'a> {
    pub user_id: &'a str,
    pub role: &'a str,
}

#[derive(Serialize)]
pub(crate) struct SlotFrame<'a> {
    pub mid: &'a str,
    pub user_id: &'a str,
}

#[derive(Serialize)]
pub(crate) struct VideoSlotFrame<'a> {
    pub mid: &'a str,
    pub user_id: &'a str,
    pub kind: &'static str,
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
    CallJoined {
        room_id: &'a str,
        #[serde(flatten)]
        participant: &'a Participant,
    },
    #[serde(rename = "call.left")]
    CallLeft {
        room_id: &'a str,
        user_id: &'a str,
        reason: &'static str,
    },
    #[serde(rename = "call.state")]
    CallState {
        room_id: &'a str,
        #[serde(flatten)]
        participant: &'a Participant,
    },
    /// To the person moved: leave and join `room_id`.
    #[serde(rename = "call.moved")]
    CallMoved { room_id: &'a str },
    /// The SFU's answer to `call.join` or `call.offer`.
    #[serde(rename = "call.answer")]
    CallAnswer {
        #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
        reference: Option<&'a Value>,
        call_id: &'a str,
        sdp: &'a str,
    },
    /// Which receive slot carries whom. `video` is null while the video slot carries nobody.
    #[serde(rename = "call.slots")]
    CallSlots {
        call_id: &'a str,
        audio: &'a [SlotFrame<'a>],
        video: Option<VideoSlotFrame<'a>>,
    },
    #[serde(rename = "call.speaking")]
    CallSpeaking {
        room_id: &'a str,
        user_ids: &'a [String],
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
    use super::{Audience, Event, Me, Out, SlotFrame, VideoSlotFrame};
    use crate::live::call::{Occupancy, Participant};
    use db::OutboxRow;
    use serde_json::{json, Value};

    #[test]
    fn a_durable_frame_is_type_then_seq_then_the_payload() {
        let event = Event::from_row(OutboxRow {
            seq: 7,
            topic: "room.renamed".to_string(),
            payload: json!({"room": {"id": "r", "name": "Lobby"}}),
            users: vec![],
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
    fn invites_and_bans_go_to_who_may_see_them_and_sessions_go_nowhere() {
        use db::perm;
        let invite = Event::from_row(OutboxRow {
            seq: 1,
            topic: "invite.created".to_string(),
            payload: json!({"invite": {"id": "i"}}),
            users: vec![],
        });
        assert_eq!(invite.audience, Audience::Invites);
        assert!(invite.audience.admits(perm::CREATE_INVITES));
        assert!(invite.audience.admits(perm::MANAGE_INVITES));
        assert!(!invite.audience.admits(perm::EVERYONE));
        let ban = Event::from_row(OutboxRow {
            seq: 2,
            topic: "member.banned".to_string(),
            payload: json!({"user_id": "u", "ban": {}}),
            users: vec![],
        });
        assert_eq!(ban.audience, Audience::Bans);
        assert_eq!(ban.subject.as_deref(), Some("u"));
        assert!(ban.audience.admits(perm::BAN_MEMBERS));
        assert!(!ban.audience.admits(perm::KICK_MEMBERS));
        let timeout = Event::from_row(OutboxRow {
            seq: 3,
            topic: "member.timeout".to_string(),
            payload: json!({"member": {"user_id": "u"}, "timeout_until": "2026-01-01T00:00:00Z"}),
            users: vec![],
        });
        assert!(timeout.timed_out);
        let ended = Event::from_row(OutboxRow {
            seq: 4,
            topic: "member.timeout".to_string(),
            payload: json!({"member": {"user_id": "u"}, "timeout_until": null}),
            users: vec![],
        });
        assert!(!ended.timed_out);
        let ended = Event::from_row(OutboxRow {
            seq: 2,
            topic: "session.ended".to_string(),
            payload: json!({"user_id": "u"}),
            users: vec![],
        });
        assert_eq!(ended.audience, Audience::Server);
        assert_eq!(ended.subject.as_deref(), Some("u"));
        assert!(ended.frame.is_none());
    }

    #[test]
    fn a_member_event_names_its_subject() {
        let event = Event::from_row(OutboxRow {
            seq: 3,
            topic: "member.role".to_string(),
            payload: json!({"member": {"user_id": "u", "display_name": "A", "role": "admin"}}),
            users: vec![],
        });
        assert_eq!(event.subject.as_deref(), Some("u"));
    }

    #[test]
    fn a_direct_event_names_its_audience() {
        let event = Event::from_row(OutboxRow {
            seq: 9,
            topic: "message.created".to_string(),
            payload: json!({"message": {"id": "m"}}),
            users: vec!["a".to_string(), "b".to_string()],
        });
        assert_eq!(event.audience, Audience::Users);
        assert_eq!(event.users, ["a", "b"]);
        let frame = event.frame.expect("frame");
        assert!(frame.contains("message.created"), "{frame}");
    }

    #[test]
    fn media_frames_have_their_documented_shape() {
        let reference = json!(7);
        let answer = Out::CallAnswer {
            reference: Some(&reference),
            call_id: "c-1",
            sdp: "v=0",
        };
        assert_eq!(
            answer.text(),
            r#"{"type":"call.answer","ref":7,"call_id":"c-1","sdp":"v=0"}"#
        );
        let slots = Out::CallSlots {
            call_id: "c-1",
            audio: &[SlotFrame {
                mid: "1",
                user_id: "u",
            }],
            video: None,
        };
        assert_eq!(
            slots.text(),
            r#"{"type":"call.slots","call_id":"c-1","audio":[{"mid":"1","user_id":"u"}],"video":null}"#
        );
        let slots = Out::CallSlots {
            call_id: "c-1",
            audio: &[],
            video: Some(VideoSlotFrame {
                mid: "2",
                user_id: "u",
                kind: "camera",
            }),
        };
        assert_eq!(
            slots.text(),
            r#"{"type":"call.slots","call_id":"c-1","audio":[],"video":{"mid":"2","user_id":"u","kind":"camera"}}"#
        );
        let speaking = Out::CallSpeaking {
            room_id: "r",
            user_ids: &["u".to_string()],
        };
        assert_eq!(
            speaking.text(),
            r#"{"type":"call.speaking","room_id":"r","user_ids":["u"]}"#
        );
        let participant = Participant {
            user_id: "u".to_string(),
            muted: true,
            deafened: false,
            camera: true,
            sharing: false,
            server_muted: false,
            server_deafened: true,
            suppressed: false,
            priority: true,
            e2ee: true,
        };
        let state = Out::CallState {
            room_id: "r",
            participant: &participant,
        };
        assert_eq!(
            state.text(),
            r#"{"type":"call.state","room_id":"r","user_id":"u","muted":true,"deafened":false,"camera":true,"sharing":false,"server_muted":false,"server_deafened":true,"suppressed":false,"priority":true,"e2ee":true}"#
        );
        let joined = Out::CallJoined {
            room_id: "r",
            participant: &participant,
        };
        assert!(joined
            .text()
            .starts_with(r#"{"type":"call.joined","room_id":"r","user_id":"u","#));
        assert_eq!(
            Out::CallMoved { room_id: "r" }.text(),
            r#"{"type":"call.moved","room_id":"r"}"#
        );
        let slots = Out::CallSlots {
            call_id: "c-1",
            audio: &[],
            video: Some(VideoSlotFrame {
                mid: "2",
                user_id: "u",
                kind: sfu::VideoKind::Share.as_str(),
            }),
        };
        assert_eq!(
            slots.text(),
            r#"{"type":"call.slots","call_id":"c-1","audio":[],"video":{"mid":"2","user_id":"u","kind":"share"}}"#
        );
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
                    muted: false,
                    deafened: true,
                    camera: false,
                    sharing: true,
                    server_muted: false,
                    server_deafened: false,
                    suppressed: false,
                    priority: false,
                    e2ee: false,
                }],
            }],
        };
        assert_eq!(
            ready.text(),
            r#"{"type":"ready","seq":4,"me":{"user_id":"u","role":"owner"},"online":["u"],"calls":[{"room_id":"r","participants":[{"user_id":"u","muted":false,"deafened":true,"camera":false,"sharing":true,"server_muted":false,"server_deafened":false,"suppressed":false,"priority":false,"e2ee":false}]}]}"#
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
