//! Permission bits, `1 << n`. The same numbers are written into the SQL in
//! `migrations/0005_server.sql`; `docs/calls.md` lists them for clients.

pub const VIEW_CHANNEL: i64 = 1 << 0;
pub const CONNECT: i64 = 1 << 1;
pub const SPEAK: i64 = 1 << 2;
pub const VIDEO: i64 = 1 << 3;
pub const SHARE_SCREEN: i64 = 1 << 4;
pub const VOICE_ACTIVITY: i64 = 1 << 5;
pub const PRIORITY_SPEAKER: i64 = 1 << 6;
pub const CREATE_INVITES: i64 = 1 << 7;
pub const MANAGE_INVITES: i64 = 1 << 8;
pub const MANAGE_CHANNELS: i64 = 1 << 9;
pub const MANAGE_ROLES: i64 = 1 << 10;
pub const KICK_MEMBERS: i64 = 1 << 11;
pub const BAN_MEMBERS: i64 = 1 << 12;
pub const TIMEOUT_MEMBERS: i64 = 1 << 13;
pub const MUTE_MEMBERS: i64 = 1 << 14;
pub const DEAFEN_MEMBERS: i64 = 1 << 15;
pub const MOVE_MEMBERS: i64 = 1 << 16;
pub const DISCONNECT_MEMBERS: i64 = 1 << 17;
pub const VIEW_AUDIT_LOG: i64 = 1 << 18;
pub const MANAGE_SERVER: i64 = 1 << 19;
/// Lists, reads, triages, annotates and links actions to abuse reports. Not in @everyone and not
/// in the room override mask.
pub const MANAGE_REPORTS: i64 = 1 << 20;

/// Every bit this server knows. Unknown bits in a request are dropped.
pub const ALL: i64 = (1 << 21) - 1;
const _: () = assert!(ALL < 1 << 53, "permissions must fit in a JSON number");

/// The bits a room override may allow or deny.
pub const CHANNEL: i64 = VIEW_CHANNEL
    | CONNECT
    | SPEAK
    | VIDEO
    | SHARE_SCREEN
    | VOICE_ACTIVITY
    | PRIORITY_SPEAKER
    | MANAGE_CHANNELS
    | MUTE_MEMBERS
    | DEAFEN_MEMBERS
    | MOVE_MEMBERS
    | DISCONNECT_MEMBERS;

/// What @everyone has on a new server.
pub const EVERYONE: i64 = VIEW_CHANNEL | CONNECT | SPEAK | VIDEO | SHARE_SCREEN | VOICE_ACTIVITY;

/// An owner's rank: above every role.
pub const OWNER_RANK: i32 = i32::MAX;

/// Whether `perms` holds every bit of `bits`.
pub fn has(perms: i64, bits: i64) -> bool {
    perms & bits == bits
}

/// Permissions in a room from the base and the overrides that apply, in the order the server
/// applies them: @everyone's override, then the OR of the member's other roles' overrides.
/// Owners skip this; they have [`ALL`].
pub fn in_room(base: i64, everyone: Option<(i64, i64)>, roles: &[(i64, i64)]) -> i64 {
    let mut perms = base;
    if let Some((allow, deny)) = everyone {
        perms = (perms & !deny) | allow;
    }
    let (allow, deny) = roles
        .iter()
        .fold((0, 0), |(allow, deny), (a, d)| (allow | a, deny | d));
    (perms & !deny) | allow
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_masks_match_the_sql() {
        assert_eq!(ALL, 2_097_151);
        assert_eq!(MANAGE_REPORTS, 1_048_576);
        // Not something a member has by default, and not something a room can override.
        assert_eq!(EVERYONE & MANAGE_REPORTS, 0);
        assert_eq!(CHANNEL & MANAGE_REPORTS, 0);
        assert_eq!(CHANNEL, 246_399);
        assert_eq!(EVERYONE, 63);
    }

    #[test]
    fn everyone_is_applied_before_the_other_roles() {
        // @everyone denies speak, a role allows it back.
        assert!(has(
            in_room(EVERYONE, Some((0, SPEAK)), &[(SPEAK, 0)]),
            SPEAK
        ));
        // @everyone allows video, a role denies it.
        assert!(!has(in_room(0, Some((VIDEO, 0)), &[(0, VIDEO)]), VIDEO));
        // Among the member's roles, an allow beats a deny.
        assert!(has(
            in_room(EVERYONE, None, &[(0, CONNECT), (CONNECT, 0)]),
            CONNECT
        ));
        // Nothing applies: the base stands.
        assert_eq!(in_room(EVERYONE, None, &[]), EVERYONE);
        // A deny on @everyone hides the room.
        assert!(!has(
            in_room(EVERYONE, Some((0, VIEW_CHANNEL)), &[]),
            VIEW_CHANNEL
        ));
    }
}
