//! Entry points for the cargo-fuzz targets in `fuzz/`. Each takes any bytes and must not
//! panic. Not part of the server.

use db::OutboxRow;
use serde_json::Value;

use crate::live::frame::{Event, Incoming, Out};

const TOPICS: [&str; 9] = [
    "room.renamed",
    "room.deleted",
    "member.role",
    "member.removed",
    "member.banned",
    "member.timeout",
    "invite.created",
    "role.updated",
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
            users: vec![],
        });
        // Valid JSON. Not read back as a `Value`: serde_json takes an object whose first key
        // is its private raw-value token as a raw value, and the payload may have that key.
        if let Some(frame) = event.frame {
            assert!(serde_json::from_str::<serde::de::IgnoredAny>(&frame).is_ok());
        }
    }
}

/// The parsers of what a member of an end-to-end encrypted conversation sends as bytes: key
/// packages, commits, welcomes, application message frames, proposal references and cross
/// signatures. Any bytes, and the same bytes as base64 text.
pub fn e2ee_handshake(data: &[u8]) {
    crate::e2ee_text::fuzz_handshake(data);
}
