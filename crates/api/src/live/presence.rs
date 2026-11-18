//! The availability a person sets for themselves, and the short status text shown with it.
//! Both are memory only: they sit on the person's hub entry and are gone once the last of
//! their sockets has been closed past the presence grace. Delivery never changes; `dnd` and
//! `offline` are advice to clients.

/// The availability a person sets with `presence.set`. `online` on the presence frame keeps
/// its socket meaning, so someone who set `offline` still shows `online: true` while a socket
/// of theirs is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    Online,
    Idle,
    Dnd,
    Offline,
}

impl State {
    /// The names a `presence.set` may send. Anything else is `bad_frame`.
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        match raw {
            "online" => Some(Self::Online),
            "idle" => Some(Self::Idle),
            "dnd" => Some(Self::Dnd),
            "offline" => Some(Self::Offline),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Idle => "idle",
            Self::Dnd => "dnd",
            Self::Offline => "offline",
        }
    }
}

/// What a person has set: one state, and at most one text. Each `presence.set` states both.
#[derive(Debug, Clone)]
pub(crate) struct Setting {
    pub(crate) state: State,
    pub(crate) text: Option<String>,
}

/// The longest status text, in characters. The client clips to the same.
pub(crate) const TEXT_MAX: usize = 128;

/// Checks the text a client sent, before anything is stored from it: trimmed, no control
/// characters, at most `TEXT_MAX`. An empty text clears it.
pub(crate) fn check_text(raw: &str) -> Result<Option<String>, &'static str> {
    let trimmed = raw.trim();
    if trimmed.chars().count() > TEXT_MAX || trimmed.chars().any(char::is_control) {
        return Err("bad_frame");
    }
    Ok((!trimmed.is_empty()).then(|| trimmed.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{check_text, State, TEXT_MAX};

    #[test]
    fn a_state_round_trips_under_its_wire_name_and_nothing_else_parses() {
        for (name, state) in [
            ("online", State::Online),
            ("idle", State::Idle),
            ("dnd", State::Dnd),
            ("offline", State::Offline),
        ] {
            assert_eq!(State::parse(name), Some(state));
            assert_eq!(state.as_str(), name);
        }
        assert_eq!(State::parse("away"), None);
        assert_eq!(State::parse(""), None);
        assert_eq!(State::parse("DND"), None);
    }

    #[test]
    fn status_text_is_trimmed_and_capped_before_it_is_stored() {
        assert_eq!(check_text("back at 4"), Ok(Some("back at 4".to_string())));
        assert_eq!(check_text("  back at 4  "), Ok(Some("back at 4".to_string())));
        assert_eq!(check_text("   "), Ok(None));
        let edge = "x".repeat(TEXT_MAX);
        assert_eq!(check_text(&edge).map(|text| text.chars().count()), Ok(TEXT_MAX));
        let over = "x".repeat(TEXT_MAX + 1);
        assert_eq!(check_text(&over), Err("bad_frame"));
        assert_eq!(check_text("line\nbreak"), Err("bad_frame"));
    }
}
