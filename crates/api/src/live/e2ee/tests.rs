//! The delivery service against real DAVE clients (`davey`, what tinyclient runs): groups made,
//! grown, shrunk, and built again only through the frames this module sends.

use std::collections::{HashMap, VecDeque};
use std::num::NonZeroU16;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use davey::{DaveSession, MediaType, ProposalsOperationType};
use serde_json::Value;

use super::{mls_group_id, mls_user_id, Outgoing, Refused, Rooms, STUCK};

const ROOM: &str = "0b6f3d0e-1c2a-4d5e-8f90-123456789abc";
const OPUS: &[u8] = &[0x78, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

struct Client {
    session: Option<DaveSession>,
    /// The last `off` said the call is transport only, and who could not encrypt.
    off: Option<Vec<String>>,
}

/// Rooms and the clients in them, with every frame delivered in the order it was sent.
struct Net {
    rooms: Rooms,
    clients: HashMap<String, Client>,
    queue: VecDeque<Outgoing>,
    now: Instant,
    /// Frames of these kinds are dropped on the floor, to make a batch stall.
    drop_ops: Vec<&'static str>,
    /// Commits the server refused or dropped.
    lost_commits: usize,
}

fn user(name: &str) -> String {
    format!("00000000-0000-4000-8000-{name:0>12}")
}

impl Net {
    fn new() -> Self {
        Self {
            rooms: Rooms::new(),
            clients: HashMap::new(),
            queue: VecDeque::new(),
            now: Instant::now(),
            drop_ops: Vec::new(),
            lost_commits: 0,
        }
    }

    fn join(&mut self, name: &str, supports: bool) {
        let user_id = user(name);
        self.clients.insert(
            user_id.clone(),
            Client {
                session: None,
                off: None,
            },
        );
        let out = self.rooms.join(ROOM, &user_id, supports);
        self.queue.extend(out);
        self.run();
    }

    fn leave(&mut self, name: &str) {
        let user_id = user(name);
        self.clients.remove(&user_id);
        let out = self.rooms.leave(ROOM, &user_id, self.now);
        self.queue.extend(out);
        self.run();
    }

    fn roster(&self) -> Vec<u64> {
        self.clients
            .keys()
            .map(|user_id| mls_user_id(user_id))
            .collect()
    }

    fn run(&mut self) {
        while let Some(outgoing) = self.queue.pop_front() {
            self.deliver(outgoing);
        }
    }

    fn deliver(&mut self, outgoing: Outgoing) {
        let frame: Value = serde_json::from_str(&outgoing.frame).expect("json");
        assert_eq!(frame["type"], "call.e2ee");
        assert_eq!(frame["room_id"], ROOM);
        let op = frame["op"].as_str().expect("op").to_string();
        if self.drop_ops.contains(&op.as_str()) {
            return;
        }
        let roster = self.roster();
        let now = self.now;
        let user_id = outgoing.user_id;
        let Some(client) = self.clients.get_mut(&user_id) else {
            return;
        };
        let data = || {
            STANDARD
                .decode(frame["data"].as_str().expect("data"))
                .expect("base64")
        };
        let epoch = frame["epoch"].as_u64().unwrap_or(0);
        match op.as_str() {
            "start" => {
                assert_eq!(frame["version"], 1);
                client.off = None;
                let sender = STANDARD
                    .decode(frame["external_sender"].as_str().expect("sender"))
                    .expect("base64");
                let version = NonZeroU16::new(1).expect("one");
                let mut session =
                    DaveSession::new(version, mls_user_id(&user_id), mls_group_id(ROOM), None)
                        .expect("session");
                session
                    .set_external_sender(&sender)
                    .expect("external sender");
                let package = session.create_key_package().expect("key package");
                client.session = Some(session);
                let out = self
                    .rooms
                    .key_package(ROOM, &user_id, &package, now)
                    .expect("key package taken");
                self.queue.extend(out);
            }
            "off" => {
                client.session = None;
                let users = frame["user_ids"].as_array().expect("user_ids");
                client.off = Some(
                    users
                        .iter()
                        .map(|user| user.as_str().expect("id").to_string())
                        .collect(),
                );
            }
            "proposals" => {
                let payload = data();
                assert_eq!(payload[0], 0, "append");
                let session = client.session.as_mut().expect("a session");
                let made = session
                    .process_proposals(ProposalsOperationType::APPEND, &payload[1..], Some(&roster))
                    .expect("proposals")
                    .expect("a commit");
                match self.rooms.commit(
                    ROOM,
                    &user_id,
                    epoch,
                    &made.commit,
                    made.welcome.as_deref(),
                    now,
                ) {
                    Ok(out) if out.is_empty() => self.lost_commits += 1,
                    Ok(out) => self.queue.extend(out),
                    Err(refused) => panic!("commit refused: {refused:?}"),
                }
            }
            "commit" => {
                let session = client.session.as_mut().expect("a session");
                session.process_commit(&data()).expect("commit applies");
            }
            "welcome" => {
                let session = client.session.as_mut().expect("a session");
                session.process_welcome(&data()).expect("welcome applies");
            }
            other => panic!("unknown op {other}"),
        }
    }

    fn session(&mut self, name: &str) -> &mut DaveSession {
        self.clients
            .get_mut(&user(name))
            .and_then(|client| client.session.as_mut())
            .expect("a session")
    }

    fn code(&mut self, name: &str) -> String {
        let session = self.session(name);
        assert!(session.is_ready(), "{name} has keys");
        session.voice_privacy_code().expect("code").to_string()
    }

    /// Every member's own view of the tree is the server's.
    fn check_leaves(&mut self) {
        let leaves = self.rooms.leaves(ROOM);
        let expected: Vec<Option<u64>> = leaves
            .iter()
            .map(|leaf| leaf.as_deref().map(mls_user_id))
            .collect();
        for leaf in leaves.iter().flatten() {
            let group = self.clients[leaf]
                .session
                .as_ref()
                .and_then(DaveSession::group)
                .expect("a group");
            let mut seen = vec![None; expected.len()];
            for member in group.members() {
                let index = member.index.u32() as usize;
                assert!(index < seen.len(), "leaf {index} past the server's tree");
                let identity: [u8; 8] = member
                    .credential
                    .serialized_content()
                    .try_into()
                    .expect("8 bytes");
                seen[index] = Some(u64::from_be_bytes(identity));
            }
            assert_eq!(seen, expected, "the tree as {leaf} holds it");
        }
    }

    /// Every member has keys and the same code. Returns it.
    fn agreed(&mut self, names: &[&str]) -> String {
        let code = self.code(names[0]);
        for name in &names[1..] {
            assert_eq!(self.code(name), code, "{name} sees the same code");
        }
        self.check_leaves();
        code
    }
}

fn hears(net: &mut Net, from: &str, to: &str) -> bool {
    let sealed = net
        .session(from)
        .encrypt_opus(OPUS)
        .expect("encrypt")
        .into_owned();
    assert_ne!(sealed, OPUS);
    let from_id = mls_user_id(&user(from));
    net.session(to)
        .decrypt(from_id, MediaType::AUDIO, &sealed)
        .is_ok_and(|opus| opus == OPUS)
}

#[test]
fn ids_are_the_documented_hash() {
    assert_eq!(mls_user_id("u"), mls_user_id("u"));
    assert_ne!(
        mls_user_id("u"),
        mls_group_id("u"),
        "labels keep the two apart"
    );
    // Pinned so that tinyclient can check its own copy against the same vector.
    assert_eq!(
        mls_user_id("00000000-0000-4000-8000-000000000001"),
        0x4b7e_2001_4471_bb39
    );
    assert_eq!(
        mls_group_id("0b6f3d0e-1c2a-4d5e-8f90-123456789abc"),
        0xff5f_ff38_49bf_c73d
    );
}

#[test]
fn three_people_join_leave_and_rekey() {
    let mut net = Net::new();
    net.join("a", true);
    assert!(!net.session("a").is_ready(), "alone, there is no group yet");
    net.join("b", true);
    assert_eq!(net.rooms.epoch(ROOM), 1);
    let first = net.agreed(&["a", "b"]);
    assert!(hears(&mut net, "a", "b") && hears(&mut net, "b", "a"));

    // Said before c joins: c will never read it.
    let before = net
        .session("a")
        .encrypt_opus(OPUS)
        .expect("encrypt")
        .into_owned();
    net.join("c", true);
    assert_eq!(net.rooms.epoch(ROOM), 2, "a join is a new epoch");
    let second = net.agreed(&["a", "b", "c"]);
    assert_ne!(first, second, "a new epoch, a new code");
    let a_id = mls_user_id(&user("a"));
    assert!(net
        .session("c")
        .decrypt(a_id, MediaType::AUDIO, &before)
        .is_err());
    assert!(hears(&mut net, "a", "c") && hears(&mut net, "c", "b"));

    // b leaves. Its session is kept to show what it could still read.
    let mut b = net.clients.remove(&user("b")).expect("b");
    let out = net.rooms.leave(ROOM, &user("b"), net.now);
    net.queue.extend(out);
    net.run();
    assert_eq!(net.rooms.epoch(ROOM), 3, "a leave is a new epoch");
    let third = net.agreed(&["a", "c"]);
    assert_ne!(second, third);
    let after = net
        .session("a")
        .encrypt_opus(OPUS)
        .expect("encrypt")
        .into_owned();
    let b_session = b.session.as_mut().expect("b's session");
    assert!(
        b_session.decrypt(a_id, MediaType::AUDIO, &after).is_err(),
        "who left cannot read what is said after"
    );
    assert!(net
        .session("c")
        .decrypt(a_id, MediaType::AUDIO, &after)
        .is_ok());
}

#[test]
fn the_server_tree_follows_holes_and_trims() {
    let mut net = Net::new();
    for name in ["a", "b", "c", "d"] {
        net.join(name, true);
    }
    net.agreed(&["a", "b", "c", "d"]);
    net.leave("b");
    assert_eq!(net.rooms.leaves(ROOM)[1], None, "b's leaf is blank");
    net.agreed(&["a", "c", "d"]);
    net.join("e", true);
    assert_eq!(
        net.rooms.leaves(ROOM)[1].as_deref(),
        Some(user("e").as_str())
    );
    net.agreed(&["a", "c", "d", "e"]);
    net.leave("d");
    assert_eq!(
        net.rooms.leaves(ROOM).len(),
        3,
        "a blank last leaf is trimmed"
    );
    net.agreed(&["a", "c", "e"]);
    net.leave("a");
    net.agreed(&["c", "e"]);
    assert_eq!(
        net.rooms.epoch(ROOM),
        7,
        "one epoch for each join after the first and each leave"
    );
}

#[test]
fn a_creator_who_leaves_before_committing_hands_the_group_on() {
    let mut net = Net::new();
    net.drop_ops = vec!["proposals"];
    net.join("a", true);
    net.join("b", true);
    net.join("c", true);
    // a was asked to commit and never did; then it left.
    net.drop_ops.clear();
    net.leave("a");
    net.agreed(&["b", "c"]);
    assert_eq!(net.rooms.leaves(ROOM).len(), 2);
}

#[test]
fn only_the_first_commit_counts() {
    let mut net = Net::new();
    net.join("a", true);
    net.join("b", true);
    net.join("c", true);
    // c's add went to a and b; both committed, one lost.
    assert_eq!(net.lost_commits, 1);
    net.agreed(&["a", "b", "c"]);
}

#[test]
fn a_stuck_batch_builds_the_group_again() {
    let mut net = Net::new();
    net.join("a", true);
    net.join("b", true);
    net.drop_ops = vec!["proposals"];
    net.join("c", true);
    assert_eq!(net.rooms.tick(net.now + Duration::from_secs(1)), Vec::new());
    net.drop_ops.clear();
    let out = net.rooms.tick(net.now + STUCK);
    assert_eq!(out.len(), 3, "start for everyone");
    net.queue.extend(out);
    net.run();
    net.agreed(&["a", "b", "c"]);
}

#[test]
fn someone_who_cannot_encrypt_turns_it_off_and_leaving_turns_it_on() {
    let mut net = Net::new();
    net.join("a", true);
    net.join("b", true);
    net.agreed(&["a", "b"]);
    net.join("x", false);
    let x = user("x");
    for name in ["a", "b"] {
        assert_eq!(
            net.clients[&user(name)].off.as_deref(),
            Some(&[x.clone()][..])
        );
        assert!(net.clients[&user(name)].session.is_none());
    }
    assert!(
        net.clients[&x].off.is_none(),
        "who cannot encrypt hears nothing of it"
    );
    // A joiner who can encrypt is told at once.
    net.join("c", true);
    assert!(net.clients[&user("c")].off.is_some());
    assert_eq!(
        net.rooms.key_package(ROOM, &user("c"), b"x", net.now),
        Err(Refused::NotFound),
        "no group while it is off"
    );
    net.leave("x");
    net.agreed(&["a", "b", "c"]);
}

#[test]
fn a_key_package_must_be_the_senders_own() {
    let mut net = Net::new();
    net.join("a", true);
    net.join("b", true);
    let version = NonZeroU16::new(1).expect("one");
    let mut forged =
        DaveSession::new(version, mls_user_id(&user("b")), mls_group_id(ROOM), None).expect("s");
    let package = forged.create_key_package().expect("kp");
    assert_eq!(
        net.rooms.key_package(ROOM, &user("a"), &package, net.now),
        Err(Refused::Bad)
    );
    assert_eq!(
        net.rooms
            .key_package(ROOM, &user("a"), b"not a key package", net.now),
        Err(Refused::Bad)
    );
    assert_eq!(
        net.rooms.key_package(ROOM, &user("z"), &package, net.now),
        Err(Refused::NotFound),
        "not in the call"
    );
}

#[test]
fn an_invalid_member_is_removed_and_added_again() {
    let mut net = Net::new();
    for name in ["a", "b", "c"] {
        net.join(name, true);
    }
    net.agreed(&["a", "b", "c"]);
    let epoch = net.rooms.epoch(ROOM);
    let out = net
        .rooms
        .invalid(ROOM, &user("b"), net.now)
        .expect("in the call");
    // b starts again as the client does: a fresh session and key package.
    net.queue.extend(out);
    let version = NonZeroU16::new(1).expect("one");
    let sender = net.rooms.signer.package.clone();
    let mut session =
        DaveSession::new(version, mls_user_id(&user("b")), mls_group_id(ROOM), None).expect("s");
    session
        .set_external_sender(&STANDARD.decode(sender).expect("b64"))
        .expect("sender");
    let package = session.create_key_package().expect("kp");
    net.clients.get_mut(&user("b")).expect("b").session = Some(session);
    net.run();
    let out = net
        .rooms
        .key_package(ROOM, &user("b"), &package, net.now)
        .expect("taken");
    net.queue.extend(out);
    net.run();
    assert!(net.rooms.epoch(ROOM) > epoch);
    net.agreed(&["a", "b", "c"]);
}

#[test]
fn a_commit_from_someone_not_asked_or_malformed_is_refused() {
    let mut net = Net::new();
    net.drop_ops = vec!["proposals"];
    net.join("a", true);
    net.join("b", true);
    // a was asked; b was not, and nothing it sends counts.
    assert_eq!(
        net.rooms
            .commit(ROOM, &user("b"), 0, b"junk", None, net.now),
        Ok(Vec::new())
    );
    assert_eq!(
        net.rooms
            .commit(ROOM, &user("a"), 0, b"junk", None, net.now),
        Err(Refused::Bad)
    );
    assert_eq!(
        net.rooms
            .commit(ROOM, &user("a"), 7, b"junk", None, net.now),
        Ok(Vec::new()),
        "another epoch is late, not wrong"
    );
}
