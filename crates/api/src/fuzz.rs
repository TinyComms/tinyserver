//! Entry points for the cargo-fuzz targets in `fuzz/`. Each takes any bytes and must not
//! panic. Not part of the server.

use db::OutboxRow;
use serde_json::Value;

use crate::live::frame::{Event, Incoming, Out};

const TOPICS: [&str; 6] = [
    "room.renamed",
    "room.deleted",
    "member.role",
    "member.removed",
    "invite.created",
    "session.ended",
];

/// One live-socket frame, as a client message and as an outbox payload.
pub fn live_frame(data: &[u8]) {
    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    if let Some(incoming) = Incoming::parse(text) {
        let reply = Out::Error {
            reference: incoming.reference.as_ref(),
            code: "bad_frame",
        };
        assert!(reply.text().starts_with(r#"{"type":"error""#));
    }
    if let Ok(payload) = serde_json::from_str::<Value>(text) {
        let topic = TOPICS[usize::from(pick) % TOPICS.len()];
        let event = Event::from_row(OutboxRow {
            seq: i64::from(pick),
            topic: topic.to_string(),
            payload,
        });
        if let Some(frame) = event.frame {
            assert!(serde_json::from_str::<Value>(&frame).is_ok());
        }
    }
}
