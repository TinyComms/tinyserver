//! Who is connected, who is online, who is in which call, and the one task that reads the
//! outbox.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use db::PgPool;
use sqlx::postgres::PgListener;
use tokio::sync::{broadcast, mpsc, oneshot, watch, Notify};
use tokio::task::JoinHandle;

use super::call::{Access, Calls, Change, Moderation, Occupancy, Reason, Refused, Session};
use super::e2ee;
use super::frame::{Event, Out, SlotFrame, VideoSlotFrame};
use super::presence::{Setting, State};
use super::socket::Close;
use super::Limits;

/// Events a socket may fall behind by before it gets `resync`.
const BACKLOG: usize = 1024;
/// Outbox rows read per query.
const BATCH: i64 = 256;
/// Frames for one socket alone, such as `call.slots`. A socket this far behind misses some.
const DIRECT: usize = 64;

pub(crate) struct Hub {
    pub pool: PgPool,
    pub limits: Limits,
    pub events: broadcast::Sender<Arc<Event>>,
    /// Presence and call frames, already serialised. Every member gets every one.
    ephemeral: broadcast::Sender<Arc<str>>,
    people: Mutex<People>,
    open: AtomicUsize,
    drained: Notify,
    stop: watch::Sender<bool>,
    dispatcher: Mutex<Option<JoinHandle<()>>>,
    ready: watch::Sender<bool>,
    pub media: Option<sfu::Media>,
    /// People connected since `last_seen_at` was last written.
    seen: Mutex<HashSet<String>>,
    /// The operator's suspension, for what a socket may still do.
    pub operator: crate::Operator,
}

#[derive(Default)]
struct People {
    users: HashMap<String, Person>,
    next_conn: u64,
    calls: Calls,
    rings: super::ring::Rings,
    group_calls: super::group_call::GroupCalls,
    /// The latest `call.slots` frame for each SFU participant, seated or not yet.
    slots: HashMap<String, Arc<str>>,
    /// End-to-end encryption: the MLS delivery service for each room's call.
    e2ee: e2ee::Rooms,
    /// True when the SFU's last load report showed a stalled media tick (>= 50 ms).
    media_overloaded: bool,
}

impl People {
    /// Sends `frame` to socket `conn` of `user_id` alone. Dropped if that socket is behind.
    fn direct(&self, user_id: &str, conn: u64, frame: Arc<str>) {
        let Some(person) = self.users.get(user_id) else {
            return;
        };
        if let Some(found) = person.conns.iter().find(|entry| entry.id == conn) {
            let _ = found.direct.try_send(frame);
        }
    }

    /// Every socket of `user_id`. A socket that is behind misses the frame.
    fn fanout(&self, user_id: &str, frame: Arc<str>) {
        let Some(person) = self.users.get(user_id) else {
            return;
        };
        for conn in &person.conns {
            let _ = conn.direct.try_send(Arc::clone(&frame));
        }
    }

    /// Sends `frame` to the socket holding `user_id`'s seat.
    fn to_seat(&self, user_id: &str, frame: Arc<str>) {
        if let Some(conn) = self.calls.conn_of(user_id) {
            self.direct(user_id, conn, frame);
        }
    }

    /// Whether `user_id` has at least one connected socket that declared `name`.
    #[allow(dead_code)]
    fn has_feature(&self, user_id: &str, name: &str) -> bool {
        self.users
            .get(user_id)
            .is_some_and(|person| person.conns.iter().any(|conn| conn.features.contains(name)))
    }

    /// Whether the socket currently holding `user_id`'s call seat declared `name`.
    #[allow(dead_code)]
    fn seat_has_feature(&self, user_id: &str, name: &str) -> bool {
        let Some(conn_id) = self.calls.conn_of(user_id) else {
            return false;
        };
        self.users.get(user_id).is_some_and(|person| {
            person
                .conns
                .iter()
                .find(|conn| conn.id == conn_id)
                .is_some_and(|conn| conn.features.contains(name))
        })
    }

    /// Sends `call.e2ee` frames, each to the socket holding its person's seat, or keeps them
    /// for the next one while that seat has none.
    fn e2ee(&mut self, frames: Vec<e2ee::Outgoing>) {
        for outgoing in frames {
            let frame: Arc<str> = Arc::from(outgoing.frame);
            if !self.calls.hold(&outgoing.user_id, &frame) {
                self.to_seat(&outgoing.user_id, frame);
            }
        }
    }
}

/// Online while this exists. It outlives the last socket by the presence grace.
#[derive(Default)]
struct Person {
    bot: bool,
    conns: Vec<Conn>,
    epoch: u64,
    /// The availability and text the person set. Memory only: gone with the entry.
    presence: Option<Setting>,
}

struct Conn {
    id: u64,
    kick: oneshot::Sender<Close>,
    direct: mpsc::Sender<Arc<str>>,
    proofs: mpsc::UnboundedSender<Proof>,
    features: HashSet<String>,
}

/// Answered once a socket has shown it is alive. Dropped if it closes first.
pub(crate) type Proof = oneshot::Sender<()>;

/// What a socket gets when it joins the hub.
pub(crate) struct Joined {
    pub conn: u64,
    pub kicked: oneshot::Receiver<Close>,
    pub presence: broadcast::Receiver<Arc<str>>,
    /// Frames for this socket alone.
    pub direct: mpsc::Receiver<Arc<str>>,
    /// Asks this socket to show it is alive.
    pub proofs: mpsc::UnboundedReceiver<Proof>,
    pub online: Vec<String>,
    pub calls: Vec<Occupancy>,
    pub ring: Option<super::ring::ReadyRing>,
    pub direct_call: Option<super::ring::ReadyDirect>,
    pub group_calls: Vec<super::group_call::ReadyGroupCall>,
}

/// One reserved socket. Dropping it frees the place.
pub(crate) struct Slot {
    hub: Arc<Hub>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.hub.open.fetch_sub(1, Ordering::AcqRel);
        self.hub.drained.notify_waiters();
    }
}

impl Hub {
    pub fn start(
        pool: PgPool,
        limits: Limits,
        media: Option<(sfu::Media, mpsc::Receiver<sfu::Event>)>,
    ) -> Arc<Self> {
        let (media, media_events) = match media {
            Some((media, events)) => (Some(media), Some(events)),
            None => (None, None),
        };
        let (events, _) = broadcast::channel(BACKLOG);
        let (ephemeral, _) = broadcast::channel(BACKLOG);
        let (stop, _) = watch::channel(false);
        let hub = Arc::new(Self {
            operator: crate::Operator::new(pool.clone()),
            pool,
            limits,
            events,
            ephemeral,
            people: Mutex::new(People::default()),
            open: AtomicUsize::new(0),
            drained: Notify::new(),
            stop,
            dispatcher: Mutex::new(None),
            ready: watch::channel(false).0,
            media,
            seen: Mutex::new(HashSet::new()),
        });
        let task = tokio::spawn(dispatch(hub.clone(), hub.stop.subscribe()));
        *lock(&hub.dispatcher) = Some(task);
        if let Some(events) = media_events {
            tokio::spawn(follow_media(hub.clone(), events, hub.stop.subscribe()));
        }
        tokio::spawn(remember(hub.clone(), hub.stop.subscribe()));
        tokio::spawn(rekey(hub.clone(), hub.stop.subscribe()));
        tokio::spawn(sweep_rings(hub.clone(), hub.stop.subscribe()));
        hub
    }

    /// `user_id` is connected now. Written to `last_seen_at` with the next batch.
    pub fn saw(&self, user_id: &str) {
        lock(&self.seen).insert(user_id.to_string());
    }

    /// Also ends every call and stops the SFU. The `1012` close is how callers learn it.
    pub fn close(&self) {
        self.stop.send_replace(true);
        let mut people = lock(&self.people);
        people.calls.clear();
        people.rings = super::ring::Rings::default();
        people.group_calls.clear();
        people.slots.clear();
        people.e2ee.clear();
        if let Some(media) = &self.media {
            media.shutdown();
        }
    }

    /// `off` without an SFU, `up` while it runs, `down` once it stopped.
    pub fn media_status(&self) -> &'static str {
        match &self.media {
            None => "off",
            Some(media) if media.running() => "up",
            Some(_) => "down",
        }
    }

    /// The SFU stopped with nobody asking it to: a poll failed or its thread panicked.
    pub fn media_failed(&self) -> bool {
        !self.closing() && self.media_status() == "down"
    }

    /// Do not establish a socket cursor before the dispatcher has its starting cursor.
    pub async fn ready(&self) {
        let _ = self.ready.subscribe().wait_for(|ready| *ready).await;
    }

    pub fn closing(&self) -> bool {
        *self.stop.borrow()
    }

    pub fn stopping(&self) -> watch::Receiver<bool> {
        self.stop.subscribe()
    }

    pub fn sockets(&self) -> usize {
        self.open.load(Ordering::Acquire)
    }

    pub async fn closed(&self, timeout: Duration) -> bool {
        let task = lock(&self.dispatcher).take();
        tokio::time::timeout(timeout, async {
            if let Some(task) = task {
                let _ = task.await;
            }
            loop {
                let drained = self.drained.notified();
                if self.sockets() == 0 {
                    break;
                }
                drained.await;
            }
        })
        .await
        .is_ok()
    }

    pub fn reserve(self: &Arc<Self>) -> Option<Slot> {
        let before = self.open.fetch_add(1, Ordering::AcqRel);
        let slot = Slot { hub: self.clone() };
        (before < self.limits.sockets_total).then_some(slot)
    }

    /// Adds a socket for `user_id`. The first one brings the person online. Past the per-user
    /// cap, the oldest socket is told to close.
    pub fn join(&self, user_id: &str, bot: bool, features: HashSet<String>) -> Joined {
        let (kick, kicked) = oneshot::channel();
        let (direct, inbox) = mpsc::channel(DIRECT);
        let (proofs, asked) = mpsc::unbounded_channel();
        let mut people = lock(&self.people);
        people.next_conn += 1;
        let conn = people.next_conn;
        let arrived = !people.users.contains_key(user_id);
        let person = people.users.entry(user_id.to_string()).or_default();
        person.bot = bot;
        while person.conns.len() >= self.limits.sockets_per_user.max(1) {
            let oldest = person.conns.remove(0);
            let _ = oldest.kick.send(Close::Replaced);
        }
        person.conns.push(Conn {
            id: conn,
            kick,
            direct,
            proofs,
            features,
        });
        if arrived && !bot {
            self.announce(user_id, true, None);
        }
        // Subscribed under the lock, so every presence frame after this snapshot reaches it.
        let presence = self.ephemeral.subscribe();
        let mut online: Vec<String> = people
            .users
            .iter()
            .filter(|(_, person)| !person.bot)
            .map(|(id, _)| id.clone())
            .collect();
        online.sort();
        Joined {
            conn,
            kicked,
            presence,
            direct: inbox,
            proofs: asked,
            online,
            calls: people.calls.snapshot(),
            ring: people.rings.ready(user_id),
            direct_call: direct_ready(&people, user_id),
            group_calls: if bot {
                Vec::new()
            } else {
                people
                    .group_calls
                    .ready(user_id, |room_id| people.calls.participants_of(room_id))
            },
        }
    }

    /// Whether `session` is the device in `user_id`'s seat.
    pub fn seated(&self, user_id: &str, session: Session) -> bool {
        lock(&self.people).calls.seated(user_id, session)
    }

    /// The socket in `user_id`'s seat, if it is open and `session`'s, asked to show it is alive:
    /// its id, and what answers. The answer's sender is dropped if the socket closes first.
    pub fn challenge(
        &self,
        user_id: &str,
        session: Session,
    ) -> Option<(u64, oneshot::Receiver<()>)> {
        let mut people = lock(&self.people);
        if !people.calls.seated(user_id, session) {
            return None;
        }
        let from = people.calls.conn_of(user_id)?;
        let (proof, answered) = oneshot::channel();
        if let Some(conn) = people
            .users
            .get(user_id)
            .and_then(|person| person.conns.iter().find(|entry| entry.id == from))
        {
            let _ = conn.proofs.send(proof);
        }
        people.calls.contest(user_id);
        Some((from, answered))
    }

    /// Socket `from` answered `challenge`, and keeps the seat.
    pub fn kept(&self, user_id: &str, from: u64) {
        lock(&self.people).calls.uncontest(user_id, from);
    }

    /// Moves `session`'s seat to socket `conn` if no socket holds it, or only `from`, which is
    /// told it was replaced. The latest `call.slots` and what was held, to send. The seat keeps
    /// the frames until `delivered`.
    pub fn regain(
        &self,
        user_id: &str,
        session: Session,
        conn: u64,
        from: Option<u64>,
    ) -> Vec<Arc<str>> {
        let mut people = lock(&self.people);
        let Some(regained) = people.calls.regain(user_id, session, conn, from) else {
            return Vec::new();
        };
        tracing::info!(conn, "call seat regained");
        if let Some(person) = people.users.get_mut(user_id) {
            if let Some(at) = person.conns.iter().position(|entry| Some(entry.id) == from) {
                let _ = person.conns.remove(at).kick.send(Close::Replaced);
            }
        }
        let slots = regained
            .call_id
            .and_then(|call_id| people.slots.get(&call_id).cloned());
        slots.into_iter().chain(regained.frames).collect()
    }

    /// Socket `conn` sent what `regain` gave it.
    pub fn delivered(&self, user_id: &str, conn: u64) {
        lock(&self.people).calls.delivered(user_id, conn);
    }

    /// Removes a socket. When it was the person's last, they go offline after the grace.
    pub fn leave(self: &Arc<Self>, user_id: &str, conn: u64) {
        let epoch = {
            let mut people = lock(&self.people);
            let Some(person) = people.users.get_mut(user_id) else {
                return;
            };
            let had = person.conns.len();
            person.conns.retain(|entry| entry.id != conn);
            if person.conns.len() == had || !person.conns.is_empty() {
                return;
            }
            person.epoch += 1;
            person.epoch
        };
        let hub = self.clone();
        let user_id = user_id.to_string();
        tokio::spawn(async move {
            tokio::time::sleep(hub.limits.presence_grace).await;
            let mut people = lock(&hub.people);
            let gone = people
                .users
                .get(&user_id)
                .is_some_and(|person| person.conns.is_empty() && person.epoch == epoch);
            if gone {
                let person = people.users.remove(&user_id);
                if let Some(person) = person.filter(|person| !person.bot) {
                    hub.announce(&user_id, false, person.presence.as_ref());
                }
            }
        });
    }

    fn announce(&self, user_id: &str, online: bool, presence: Option<&Setting>) {
        let (state, text) = match presence {
            Some(setting) => (Some(setting.state.as_str()), setting.text.as_deref()),
            None => (None, None),
        };
        let frame = Out::Presence {
            user_id,
            online,
            state,
            text,
        }
        .text();
        let _ = self.ephemeral.send(Arc::from(frame));
    }

    /// Records the availability `user_id` set and tells everyone, as online and offline are
    /// told. The same audience as today's presence, and nothing about delivery changes.
    /// Memory only. `not_found` when the person has no socket on this hub any more.
    pub fn set_presence(
        &self,
        user_id: &str,
        state: State,
        text: Option<String>,
    ) -> Result<(), &'static str> {
        let mut people = lock(&self.people);
        let Some(person) = people.users.get_mut(user_id) else {
            return Err("not_found");
        };
        let setting = Setting { state, text };
        person.presence = Some(setting.clone());
        self.announce(user_id, true, Some(&setting));
        Ok(())
    }

    /// How many people `room_id` takes for `user_id`: its own limit, else the optional
    /// server ceiling, and the server ceiling for someone moved there. `None` means no cap.
    fn room_limit(
        &self,
        calls: &Calls,
        user_id: &str,
        room_id: &str,
        user_limit: i32,
    ) -> Option<usize> {
        let max = self.limits.call_room_max;
        match usize::try_from(user_limit) {
            Ok(limit) if limit > 0 && !calls.ticket(user_id, room_id) => {
                Some(max.map_or(limit, |m| limit.min(m)))
            }
            _ => max,
        }
    }

    /// Checks whether the server's measured capacity (media thread load and upload budget)
    /// can carry one more seat for `user_id` in `room_id`.
    fn capacity_check(&self, people: &People, user_id: &str, room_id: &str) -> Result<(), Refused> {
        if people.calls.room_of(user_id).is_some() {
            return Ok(());
        }
        if people.media_overloaded {
            return Err(Refused::ServerFull);
        }
        if let Some(budget) = self.limits.call_egress_kbps {
            let projected =
                people
                    .calls
                    .projected_audio_kbps(user_id, room_id, self.limits.call_audio_slots);
            if projected > u64::from(budget) {
                return Err(Refused::ServerFull);
            }
        }
        Ok(())
    }

    /// Whether `call_join` would seat `user_id` in `room_id` now. Checked before media is
    /// set up, because an SFU join replaces the person's media in any other room.
    pub fn call_check(&self, user_id: &str, room_id: &str, user_limit: i32) -> Result<(), Refused> {
        if self.closing() {
            return Err(Refused::Closing);
        }
        let people = lock(&self.people);
        let limit = self.room_limit(&people.calls, user_id, room_id, user_limit);
        people
            .calls
            .check(user_id, room_id, limit, self.limits.call_server_max)?;
        self.capacity_check(&people, user_id, room_id)
    }

    /// Seats `user_id` in `room_id` for socket `conn`, with the SFU's answer if the join had
    /// media. `e2ee`: their app can encrypt end to end. Refused once the hub is closing.
    #[allow(clippy::too_many_arguments)]
    pub fn call_join(
        &self,
        user_id: &str,
        room_id: &str,
        conn: u64,
        answer: Option<&sfu::Answer>,
        user_limit: i32,
        access: Access,
        e2ee: bool,
        session: Session,
    ) -> Result<(), Refused> {
        let call_id = answer.map(|answer| answer.call_id.as_str());
        let mut people = lock(&self.people);
        if self.closing() {
            return Err(Refused::Closing);
        }
        if super::call::is_direct_room(room_id) {
            let accepted = people
                .rings
                .direct_of_room(room_id)
                .is_some_and(|direct_id| {
                    people.rings.join_key(direct_id, user_id).ok().as_deref() == Some(room_id)
                });
            if !accepted {
                // SFU preparation awaited outside this lock. A timeout or removal can end
                // the ring in that interval. Do not seat an orphan or retain its transport.
                drop(people);
                if let Some(call_id) = call_id {
                    self.forget(call_id);
                }
                return Err(Refused::NotFound);
            }
        }
        if super::call::is_group_room(room_id) && !people.group_calls.can_seat(room_id, user_id) {
            drop(people);
            if let Some(call_id) = call_id {
                self.forget(call_id);
            }
            return Err(Refused::NotFound);
        }
        let limit = self.room_limit(&people.calls, user_id, room_id, user_limit);
        if let Err(refused) = self.capacity_check(&people, user_id, room_id) {
            if super::call::is_group_room(room_id) {
                let seated = people.calls.people(room_id).len();
                if let Some(event) = people.group_calls.cancel_ring_for_room(
                    room_id,
                    user_id,
                    user_id,
                    seated,
                    std::time::Instant::now(),
                ) {
                    send_group_ring(&people, &event);
                }
            }
            return Err(refused);
        }
        let previous = people.calls.room_of(user_id).map(str::to_string);
        let again = previous.as_deref() == Some(room_id);
        let changes = match people.calls.join(
            user_id,
            room_id,
            conn,
            call_id.map(str::to_string),
            limit,
            self.limits.call_server_max,
            access,
            e2ee,
        ) {
            Ok(changes) => changes,
            Err(refused) => {
                if super::call::is_group_room(room_id) {
                    let seated = people.calls.people(room_id).len();
                    if let Some(event) = people.group_calls.cancel_ring_for_room(
                        room_id,
                        user_id,
                        user_id,
                        seated,
                        std::time::Instant::now(),
                    ) {
                        send_group_ring(&people, &event);
                    }
                }
                return Err(refused);
            }
        };
        people.calls.set_session(user_id, session);
        self.tell(&mut people, changes);
        // A seat with media is in the room's group, or is why the room has none. Taking the
        // same seat again with new media is a leave and a join: the old keys went with it.
        if answer.is_some() {
            if again {
                let frames = people
                    .e2ee
                    .leave(room_id, user_id, std::time::Instant::now());
                people.e2ee(frames);
            }
            let frames = people.e2ee.join(room_id, user_id, e2ee);
            people.e2ee(frames);
        }
        if let Some(answer) = answer {
            let change =
                people
                    .calls
                    .set_media(user_id, &answer.call_id, answer.camera, answer.share);
            self.tell(&mut people, change);
        }
        let now = std::time::Instant::now();
        if super::call::is_group_room(room_id) {
            let seated = people.calls.people(room_id).len();
            people.group_calls.on_seated(room_id, user_id, seated, now);
        }
        if people.calls.note_direct_pair(room_id) {
            people.rings.mark_live(room_id);
        }
        let mut notices = Vec::new();
        let mut group_ended = Vec::new();
        if let Some(previous) = previous.as_deref() {
            if previous != room_id {
                if super::call::is_direct_room(previous) && people.calls.people(previous).is_empty()
                {
                    if let Some(notice) = people.rings.on_room_empty(previous) {
                        notices.push(notice);
                    }
                } else if super::call::is_group_room(previous) {
                    let remaining = people.calls.people(previous).len();
                    if let Some(ended) = people.group_calls.on_left(previous, remaining, now) {
                        group_ended.push(ended);
                    }
                }
            }
        }
        // A new SFU participant starts unmoderated.
        if let Some(moderation) = people.calls.moderation(user_id) {
            if moderation.silenced || moderation.hushed {
                self.apply(Some(moderation));
            }
        }
        // Slots the SFU sent before the seat existed. The socket reads them after its answer.
        if let Some(frame) = call_id.and_then(|call_id| people.slots.get(call_id)) {
            people.direct(user_id, conn, frame.clone());
        }
        self.announce_settled(people, notices, group_ended);
        Ok(())
    }

    /// Drops an SFU participant that never got a seat.
    pub fn forget(&self, call_id: &str) {
        let mut people = lock(&self.people);
        people.slots.remove(call_id);
        if let Some(media) = &self.media {
            media.leave(call_id);
        }
    }

    /// `user_id`'s SFU participant, if they are in a call with media.
    pub fn call_of(&self, user_id: &str) -> Option<String> {
        lock(&self.people)
            .calls
            .call_of(user_id)
            .map(str::to_string)
    }

    /// Records mute, deafen, and priority, tells everyone, and tells the SFU. False if not in
    /// a call.
    pub fn call_state(&self, user_id: &str, muted: bool, deafened: bool, priority: bool) -> bool {
        let mut people = lock(&self.people);
        if people.calls.room_of(user_id).is_none() {
            return false;
        }
        let change = people.calls.set_state(user_id, muted, deafened, priority);
        if let (Some(media), Some(call_id)) = (&self.media, people.calls.call_of(user_id)) {
            media.state(call_id, muted, deafened);
        }
        self.tell(&mut people, change);
        true
    }

    /// Server mute or deafen `user_id` in `room_id`'s call, tell everyone, and tell the SFU.
    /// False if they are not in that call.
    pub fn moderate(
        &self,
        room_id: &str,
        user_id: &str,
        server_muted: Option<bool>,
        server_deafened: Option<bool>,
    ) -> bool {
        let mut people = lock(&self.people);
        let Some((change, moderation)) =
            people
                .calls
                .moderate(room_id, user_id, server_muted, server_deafened)
        else {
            return false;
        };
        self.apply(moderation);
        self.tell(&mut people, change);
        true
    }

    /// Tells `user_id` to move to `to_room`, whose limit they may pass for a while. False if
    /// they are not in a call.
    pub fn call_move(&self, user_id: &str, to_room: &str) -> bool {
        let mut people = lock(&self.people);
        if people.calls.room_of(user_id).is_none() {
            return false;
        }
        people.calls.issue_ticket(user_id, to_room);
        let frame: Arc<str> = Arc::from(Out::CallMoved { room_id: to_room }.text());
        people.to_seat(user_id, frame);
        true
    }

    /// The room whose call `user_id` is in.
    pub fn room_of(&self, user_id: &str) -> Option<String> {
        lock(&self.people)
            .calls
            .room_of(user_id)
            .map(str::to_string)
    }

    fn apply(&self, moderation: Option<Moderation>) {
        if let (Some(media), Some(moderation)) = (&self.media, moderation) {
            media.moderate(&moderation.call_id, moderation.silenced, moderation.hushed);
        }
    }

    /// Re-reads the permissions of everyone in a call, after a role or an override changed,
    /// and suppresses or frees them and their priority to match.
    fn refresh(self: &Arc<Self>) {
        let hub = self.clone();
        tokio::spawn(async move {
            let rooms = lock(&hub.people).calls.occupied();
            for (room_id, people) in rooms {
                if super::call::is_private_room(&room_id) {
                    continue;
                }
                let permissions = match db::room_permissions(&hub.pool, &room_id, &people).await {
                    Ok(permissions) => permissions,
                    Err(error) => {
                        tracing::warn!(%error, "call permissions not read");
                        continue;
                    }
                };
                let mut guard = lock(&hub.people);
                for (user_id, bits) in permissions {
                    if let Some((change, moderation)) =
                        guard.calls.set_access(&room_id, &user_id, access(bits))
                    {
                        hub.apply(moderation);
                        hub.tell(&mut guard, Some(change));
                    }
                }
                drop(guard);
            }
        });
    }

    /// Records whether `user_id`'s camera sends and whether they share after `answer`, and
    /// tells everyone if either changed.
    pub fn call_media(&self, user_id: &str, answer: &sfu::Answer) {
        let mut people = lock(&self.people);
        let change = people
            .calls
            .set_media(user_id, &answer.call_id, answer.camera, answer.share);
        tracing::info!(
            call_id = %answer.call_id,
            seat_call_id = ?people.calls.call_of(user_id),
            camera = answer.camera,
            share = answer.share,
            told = change.is_some(),
            "call media"
        );
        self.tell(&mut people, change);
    }

    /// Who shares their screen in `room_id`'s call.
    pub fn sharer(&self, room_id: &str) -> Option<String> {
        lock(&self.people).calls.sharer(room_id).map(str::to_string)
    }

    /// Ends `user_id`'s share in `room_id`, tells everyone, and stops it in the SFU. False if
    /// they were not sharing there.
    pub fn end_share(&self, room_id: &str, user_id: &str) -> bool {
        let mut people = lock(&self.people);
        let Some((call_id, change)) = people.calls.end_share(room_id, user_id) else {
            return false;
        };
        if let (Some(media), Some(call_id)) = (&self.media, call_id) {
            media.end_share(&call_id);
        }
        self.tell(&mut people, Some(change));
        true
    }

    /// Ends `user_id`'s call, if they are in one. `end_rings` also drops a direct ring they are
    /// in: a ban or a removal. `call.leave` with no seat only cancels a ring this person placed.
    pub fn call_leave(&self, user_id: &str, reason: Reason, end_rings: bool) {
        let mut people = lock(&self.people);
        let room = people.calls.room_of(user_id).map(str::to_string);
        let mut changes = people.calls.leave(user_id, reason);
        if end_rings {
            // Either party may still be preparing media, with no seat of their own yet.
            // End the other party's accepted seat before removing the ring and its timer.
            if let Some(ring) = people.rings.ready(user_id).filter(|ring| ring.accepted) {
                changes.extend(
                    people
                        .calls
                        .end_room(&super::ring::room_key(&ring.ring_id), reason),
                );
            }
        }
        self.tell(&mut people, changes);
        let (notices, group_ended) = settle_calls(&mut people, room.as_deref(), user_id, end_rings);
        self.announce_settled(people, notices, group_ended);
    }

    /// Ends `user_id`'s call if it is in `room_id`. False if they were not there.
    pub fn call_kick(&self, room_id: &str, user_id: &str) -> bool {
        let mut people = lock(&self.people);
        if people.calls.room_of(user_id) != Some(room_id) {
            return false;
        }
        let change = people.calls.leave(user_id, Reason::Kicked);
        self.tell(&mut people, change);
        let (notices, group_ended) = settle_calls(&mut people, Some(room_id), user_id, false);
        self.announce_settled(people, notices, group_ended);
        true
    }

    pub fn in_call(&self, room_id: &str, user_id: &str) -> bool {
        lock(&self.people).calls.room_of(user_id) == Some(room_id)
    }

    pub fn end_room(&self, room_id: &str, reason: Reason) {
        let mut people = lock(&self.people);
        let changes = people.calls.end_room(room_id, reason);
        self.tell(&mut people, changes);
        let mut notices = Vec::new();
        let mut group_ended = Vec::new();
        if super::call::is_direct_room(room_id) {
            if let Some(notice) = people.rings.on_room_empty(room_id) {
                notices.push(notice);
            }
        } else if super::call::is_group_room(room_id) {
            if let Some(group_id) = people
                .group_calls
                .meta_of_room(room_id)
                .map(|(gid, _, _)| gid.to_string())
            {
                if let Some((_, ended)) = people.group_calls.end_group(&group_id) {
                    group_ended.push(ended);
                }
            }
        }
        self.announce_settled(people, notices, group_ended);
    }

    /// Socket `conn` closed with `reason`. If it held its person's seat, they leave now, or
    /// after the presence grace when `reason` is `None` and no socket of theirs rejoins first.
    pub fn hang_up(self: &Arc<Self>, user_id: &str, conn: u64, reason: Option<Reason>) {
        let epoch = {
            let mut people = lock(&self.people);
            let Some(epoch) = people.calls.orphan(user_id, conn) else {
                return;
            };
            if let Some(reason) = reason {
                let room = people.calls.room_of(user_id).map(str::to_string);
                let changes = people.calls.leave(user_id, reason);
                self.tell(&mut people, changes);
                let (notices, group_ended) =
                    settle_calls(&mut people, room.as_deref(), user_id, false);
                self.announce_settled(people, notices, group_ended);
                return;
            }
            epoch
        };
        let hub = self.clone();
        let user_id = user_id.to_string();
        tokio::spawn(async move {
            tokio::time::sleep(hub.limits.presence_grace).await;
            let mut people = lock(&hub.people);
            let room = people.calls.room_of(&user_id).map(str::to_string);
            let changes = people.calls.expire(&user_id, epoch);
            let left = !changes.is_empty();
            hub.tell(&mut people, changes);
            let (notices, group_ended) = if left {
                settle_calls(&mut people, room.as_deref(), &user_id, false)
            } else {
                (Vec::new(), Vec::new())
            };
            hub.announce_settled(people, notices, group_ended);
        });
    }

    /// Acts on durable events that end calls or change what people in them may do.
    fn follow(self: &Arc<Self>, event: &Event) {
        match event.topic.as_str() {
            "room.deleted" => {
                if let Some(room_id) = &event.room {
                    self.end_room(room_id, Reason::RoomDeleted);
                }
            }
            "member.removed" => {
                if let Some(user_id) = &event.subject {
                    self.call_leave(user_id, Reason::Removed, true);
                }
            }
            "member.banned" => {
                if let Some(user_id) = &event.subject {
                    self.call_leave(user_id, Reason::Banned, true);
                }
            }
            "member.timeout" if event.timed_out => {
                if let Some(user_id) = &event.subject {
                    self.call_leave(user_id, Reason::TimedOut, true);
                }
            }
            "group.member_left" => {
                if let (Some(group_id), Some(user_id)) = (&event.group, &event.subject) {
                    self.on_group_member_left(group_id, user_id);
                }
            }
            "group.deleted" => {
                if let Some(group_id) = &event.group {
                    self.on_group_deleted(group_id);
                }
            }
            "group.member_added" => {
                if let (Some(group_id), Some(user_id)) = (&event.group, &event.subject) {
                    self.on_group_member_added(group_id, user_id);
                }
            }
            "role.updated" | "role.deleted" | "member.roles" | "member.role" | "room.updated" => {
                self.refresh();
            }
            _ => {}
        }
    }

    /// Sends call changes, and drops the media of anyone who left. Called with `people`
    /// locked, so frames go out in registry order.
    fn tell(&self, people: &mut People, changes: impl IntoIterator<Item = Change>) {
        for change in changes {
            if let Change::Left {
                room_id,
                user_id,
                call_id,
                ..
            } = &change
            {
                if let Some(call_id) = call_id {
                    people.slots.remove(call_id);
                    if let Some(media) = &self.media {
                        media.leave(call_id);
                    }
                }
                let frames = people
                    .e2ee
                    .leave(room_id, user_id, std::time::Instant::now());
                people.e2ee(frames);
            }
            let (room_id, extra) = match &change {
                Change::Joined { room_id, .. } | Change::State { room_id, .. } => {
                    (room_id.clone(), None)
                }
                Change::Left {
                    room_id, user_id, ..
                } => (room_id.clone(), Some(user_id.clone())),
            };
            match super::call::room_kind(&room_id) {
                super::call::RoomKind::Group => {
                    let Some((group_id, call_id, mut users)) = people
                        .group_calls
                        .meta_of_room(&room_id)
                        .map(|(gid, cid, members)| {
                            (gid.to_string(), cid.to_string(), members.to_vec())
                        })
                    else {
                        continue;
                    };
                    let frame = match &change {
                        Change::Joined { participant, .. } => Out::CallGroupJoined {
                            group_id: &group_id,
                            call_id: &call_id,
                            participant,
                        }
                        .text(),
                        Change::Left {
                            user_id, reason, ..
                        } => Out::CallGroupLeft {
                            group_id: &group_id,
                            call_id: &call_id,
                            user_id,
                            reason: reason.as_str(),
                        }
                        .text(),
                        Change::State { participant, .. } => Out::CallGroupState {
                            group_id: &group_id,
                            call_id: &call_id,
                            participant,
                        }
                        .text(),
                    };
                    if let Some(extra) = extra {
                        if !users.iter().any(|user| user == &extra) {
                            users.push(extra);
                        }
                    }
                    let frame: Arc<str> = Arc::from(frame);
                    for user in users {
                        people.fanout(&user, Arc::clone(&frame));
                    }
                }
                super::call::RoomKind::Direct => {
                    let frame = match &change {
                        Change::Joined {
                            room_id,
                            participant,
                        } => Out::CallJoined {
                            room_id,
                            direct_id: people.rings.direct_of_room(room_id),
                            participant,
                        }
                        .text(),
                        Change::Left {
                            room_id,
                            user_id,
                            reason,
                            ..
                        } => Out::CallLeft {
                            room_id,
                            direct_id: people.rings.direct_of_room(room_id),
                            user_id,
                            reason: reason.as_str(),
                        }
                        .text(),
                        Change::State {
                            room_id,
                            participant,
                        } => Out::CallState {
                            room_id,
                            direct_id: people.rings.direct_of_room(room_id),
                            participant,
                        }
                        .text(),
                    };
                    let mut users = people
                        .rings
                        .parties(&room_id)
                        .unwrap_or_else(|| people.calls.people(&room_id).to_vec());
                    if let Some(extra) = extra {
                        if !users.iter().any(|user| user == &extra) {
                            users.push(extra);
                        }
                    }
                    let frame: Arc<str> = Arc::from(frame);
                    for user in users {
                        people.fanout(&user, Arc::clone(&frame));
                    }
                }
                super::call::RoomKind::Room => {
                    let frame = match &change {
                        Change::Joined {
                            room_id,
                            participant,
                        } => Out::CallJoined {
                            room_id,
                            direct_id: None,
                            participant,
                        }
                        .text(),
                        Change::Left {
                            room_id,
                            user_id,
                            reason,
                            ..
                        } => Out::CallLeft {
                            room_id,
                            direct_id: None,
                            user_id,
                            reason: reason.as_str(),
                        }
                        .text(),
                        Change::State {
                            room_id,
                            participant,
                        } => Out::CallState {
                            room_id,
                            direct_id: None,
                            participant,
                        }
                        .text(),
                    };
                    let _ = self.ephemeral.send(Arc::from(frame));
                }
            }
        }
    }

    /// One `call.e2ee` from socket `conn` of `user_id`. Only the socket holding a seat with
    /// media may send one.
    pub fn call_e2ee(
        &self,
        user_id: &str,
        conn: u64,
        op: &str,
        epoch: Option<u64>,
        data: Option<&str>,
        welcome: Option<&str>,
    ) -> Result<(), &'static str> {
        let mut people = lock(&self.people);
        let room_id = match people.calls.room_of(user_id) {
            Some(room_id)
                if people.calls.conn_of(user_id) == Some(conn)
                    && people.calls.call_of(user_id).is_some() =>
            {
                room_id.to_string()
            }
            _ => return Err(e2ee::Refused::NotFound.code()),
        };
        let now = std::time::Instant::now();
        let sent = match op {
            "key_package" => {
                let data = e2ee::decode(data).map_err(e2ee::Refused::code)?;
                people.e2ee.key_package(&room_id, user_id, &data, now)
            }
            "commit" => {
                let Some(epoch) = epoch else {
                    return Err(e2ee::Refused::BadFrame.code());
                };
                let data = e2ee::decode(data).map_err(e2ee::Refused::code)?;
                let welcome = match welcome {
                    Some(welcome) => {
                        Some(e2ee::decode(Some(welcome)).map_err(e2ee::Refused::code)?)
                    }
                    None => None,
                };
                people
                    .e2ee
                    .commit(&room_id, user_id, epoch, &data, welcome.as_deref(), now)
            }
            "invalid" => people.e2ee.invalid(&room_id, user_id, now),
            _ => return Err(e2ee::Refused::BadFrame.code()),
        };
        let frames = sent.map_err(e2ee::Refused::code)?;
        people.e2ee(frames);
        Ok(())
    }

    /// Places a direct ring. `busy` when either person already has one. The caller hears
    /// `call.busy`; both hear `call.ringing` when it is placed.
    pub fn start_ring(
        &self,
        direct_id: &str,
        caller_id: &str,
        callee_id: &str,
    ) -> Result<(), &'static str> {
        let mut people = lock(&self.people);
        let notice = match people.rings.start(direct_id, caller_id, callee_id) {
            super::ring::Start::Placed(notice) | super::ring::Start::Busy(notice) => notice,
        };
        let busy = matches!(notice.kind, super::ring::Kind::Busy { .. });
        self.announce_rings(people, [notice]);
        if busy {
            Err("busy")
        } else {
            Ok(())
        }
    }

    pub fn accept_ring(&self, direct_id: &str, user_id: &str) -> Result<(), &'static str> {
        self.finish_ring(|rings| rings.accept(direct_id, user_id))
    }

    pub fn decline_ring(&self, direct_id: &str, user_id: &str) -> Result<(), &'static str> {
        self.finish_ring(|rings| rings.decline(direct_id, user_id))
    }

    pub fn cancel_ring(&self, direct_id: &str, user_id: &str) -> Result<(), &'static str> {
        self.finish_ring(|rings| rings.cancel(direct_id, user_id))
    }

    /// The media room for an accepted direct, or `not_found`.
    pub fn direct_join_key(&self, direct_id: &str, user_id: &str) -> Result<String, &'static str> {
        lock(&self.people).rings.join_key(direct_id, user_id)
    }

    /// Ends one accepted/live direct attempt, including when this party has not taken a
    /// media seat yet. Their current unrelated room stays. A stale attempt has no effects.
    pub fn leave_direct(
        &self,
        direct_id: &str,
        ring_id: &str,
        user_id: &str,
    ) -> Result<(), &'static str> {
        let mut people = lock(&self.people);
        let room_id = people.rings.join_key(direct_id, user_id)?;
        if room_id != super::ring::room_key(ring_id) {
            return Err("not_found");
        }
        if people.calls.room_of(user_id) == Some(room_id.as_str()) {
            let changes = people.calls.leave(user_id, Reason::Left);
            self.tell(&mut people, changes);
        }
        let changes = people.calls.end_room(&room_id, Reason::PeerLeft);
        self.tell(&mut people, changes);
        let notice = people
            .rings
            .drop_user(user_id)
            .expect("validated direct attempt");
        self.announce_rings(people, [notice]);
        Ok(())
    }

    /// Starts a group call if none is running (checking capacity for the starter first), or
    /// resends `call.group.started` to the asker alone if one is already live.
    pub fn start_group_call(
        &self,
        group_id: &str,
        started_by: &str,
        members: Vec<String>,
    ) -> Result<(), Refused> {
        let mut people = lock(&self.people);
        if self.closing() {
            return Err(Refused::Closing);
        }
        if people.group_calls.active_room(group_id).is_none() {
            // Check capacity for the starter before starting or ringing anyone.
            const PENDING_ROOM: &str = "g:pending";
            people.calls.check(
                started_by,
                PENDING_ROOM,
                self.limits.call_room_max,
                self.limits.call_server_max,
            )?;
            self.capacity_check(&people, started_by, PENDING_ROOM)?;
        }
        let now = std::time::Instant::now();
        let People {
            users,
            calls,
            rings,
            group_calls,
            ..
        } = &mut *people;
        let outcome = group_calls.start(
            group_id,
            started_by,
            members,
            |uid| rings.has_user(uid) || calls.room_of(uid).is_some_and(super::call::is_group_room),
            |uid| {
                users
                    .get(uid)
                    .is_some_and(|p| !p.bot && !p.conns.is_empty())
            },
            |room_id| calls.participants_of(room_id),
            now,
        );
        match outcome {
            super::group_call::StartOutcome::Created { card, recipients } => {
                send_group_started(&people, &card, &recipients);
            }
            super::group_call::StartOutcome::Existing { card } => {
                send_group_started(&people, &card, &[started_by.to_string()]);
            }
        }
        Ok(())
    }

    /// Rings `user_ids` in a live group call. The sender must be seated in `g:{call_id}`.
    pub fn ring_group_call(
        &self,
        group_id: &str,
        call_id: &str,
        by: &str,
        user_ids: &[String],
        members: Vec<String>,
    ) -> Result<(), &'static str> {
        let mut people = lock(&self.people);
        let room_id = people
            .group_calls
            .room_for(group_id, call_id)
            .ok_or("not_found")?;
        if people.calls.room_of(by) != Some(room_id.as_str()) {
            return Err("not_found");
        }
        let _ = people.group_calls.join_key(group_id, Some(members));
        let seated = people.calls.people(&room_id).to_vec();
        let now = std::time::Instant::now();
        let People {
            users,
            calls,
            rings,
            group_calls,
            ..
        } = &mut *people;
        let events = group_calls.ring(
            group_id,
            call_id,
            by,
            user_ids,
            &seated,
            |uid| rings.has_user(uid) || calls.room_of(uid).is_some_and(super::call::is_group_room),
            |uid| {
                users
                    .get(uid)
                    .is_some_and(|p| !p.bot && !p.conns.is_empty())
            },
            now,
        )?;
        for event in &events {
            send_group_ring(&people, event);
        }
        Ok(())
    }

    /// Stops ringing `user_ids` in a live group call. The sender must be seated in `g:{call_id}`.
    pub fn unring_group_call(
        &self,
        group_id: &str,
        call_id: &str,
        by: &str,
        user_ids: &[String],
    ) -> Result<(), &'static str> {
        let mut people = lock(&self.people);
        let room_id = people
            .group_calls
            .room_for(group_id, call_id)
            .ok_or("not_found")?;
        if people.calls.room_of(by) != Some(room_id.as_str()) {
            return Err("not_found");
        }
        let seated_count = people.calls.people(&room_id).len();
        let events = people.group_calls.unring(
            group_id,
            call_id,
            by,
            user_ids,
            seated_count,
            std::time::Instant::now(),
        )?;
        for event in &events {
            send_group_ring(&people, event);
        }
        Ok(())
    }

    /// Stops `user_id`'s own ring in `(group_id, call_id)` on all their devices.
    pub fn decline_group_call(
        &self,
        group_id: &str,
        call_id: &str,
        user_id: &str,
    ) -> Result<(), &'static str> {
        let mut people = lock(&self.people);
        let room_id = people
            .group_calls
            .room_for(group_id, call_id)
            .ok_or("not_found")?;
        let seated_count = people.calls.people(&room_id).len();
        let event = people.group_calls.decline(
            group_id,
            call_id,
            user_id,
            seated_count,
            std::time::Instant::now(),
        )?;
        send_group_ring(&people, &event);
        Ok(())
    }

    /// The media room `g:{call_id}` for `group_id`'s live call, or `not_found`.
    pub fn group_join_key(
        &self,
        group_id: &str,
        members: Vec<String>,
    ) -> Result<String, &'static str> {
        lock(&self.people)
            .group_calls
            .join_key(group_id, Some(members))
            .ok_or("not_found")
    }

    /// Marks `user_id`'s ring on `group_id` as `answered` before SFU media setup begins.
    pub fn mark_group_answered(&self, group_id: &str, user_id: &str) {
        let mut people = lock(&self.people);
        let seated = people
            .group_calls
            .active_room(group_id)
            .map_or(0, |room_id| people.calls.people(&room_id).len());
        if let Some(event) =
            people
                .group_calls
                .mark_answered(group_id, user_id, seated, std::time::Instant::now())
        {
            send_group_ring(&people, &event);
        }
    }

    /// Cancels `user_id`'s pending ring on `room_id` (used when capacity refuses their join).
    pub fn cancel_group_ring(&self, room_id: &str, user_id: &str) {
        let mut people = lock(&self.people);
        let seated = people.calls.people(room_id).len();
        if let Some(event) = people.group_calls.cancel_ring_for_room(
            room_id,
            user_id,
            user_id,
            seated,
            std::time::Instant::now(),
        ) {
            send_group_ring(&people, &event);
        }
    }

    /// Leaves only `(group_id, call_id)`, leaving any unrelated seat untouched.
    pub fn leave_group(
        &self,
        group_id: &str,
        call_id: &str,
        user_id: &str,
    ) -> Result<(), &'static str> {
        let mut people = lock(&self.people);
        let room_id = people
            .group_calls
            .room_for(group_id, call_id)
            .ok_or("not_found")?;
        let now = std::time::Instant::now();
        let mut group_ended = Vec::new();
        if people.calls.room_of(user_id) == Some(room_id.as_str()) {
            let changes = people.calls.leave(user_id, Reason::Left);
            self.tell(&mut people, changes);
            let remaining = people.calls.people(&room_id).len();
            if let Some(ended) = people.group_calls.on_left(&room_id, remaining, now) {
                group_ended.push(ended);
            }
        } else {
            let seated = people.calls.people(&room_id).len();
            if let Some(event) = people
                .group_calls
                .cancel_ring_for_room(&room_id, user_id, user_id, seated, now)
            {
                send_group_ring(&people, &event);
            }
        }
        self.announce_settled(people, Vec::new(), group_ended);
        Ok(())
    }

    fn on_group_member_left(&self, group_id: &str, user_id: &str) {
        let mut people = lock(&self.people);
        let Some(room_id) = people.group_calls.active_room(group_id) else {
            return;
        };
        let now = std::time::Instant::now();
        if people.calls.room_of(user_id) == Some(room_id.as_str()) {
            let changes = people.calls.leave(user_id, Reason::Removed);
            self.tell(&mut people, changes);
        }
        let remaining = people.calls.people(&room_id).len();
        let (_, cancelled) = people
            .group_calls
            .on_member_removed(group_id, user_id, remaining, now);
        if let Some(event) = cancelled {
            send_group_ring(&people, &event);
        }
        let ended = people.group_calls.on_left(&room_id, remaining, now);
        self.announce_settled(people, Vec::new(), ended);
    }

    fn on_group_deleted(&self, group_id: &str) {
        let mut people = lock(&self.people);
        let Some(room_id) = people.group_calls.active_room(group_id) else {
            return;
        };
        let changes = people.calls.end_room(&room_id, Reason::RoomDeleted);
        self.tell(&mut people, changes);
        let ended = people
            .group_calls
            .end_group(group_id)
            .map(|(_, ended)| ended);
        self.announce_settled(people, Vec::new(), ended);
    }

    fn on_group_member_added(&self, group_id: &str, user_id: &str) {
        let mut people = lock(&self.people);
        let People {
            calls, group_calls, ..
        } = &mut *people;
        let card = group_calls
            .on_member_added(group_id, user_id, |room_id| calls.participants_of(room_id));
        if let Some(card) = card {
            send_group_started(&people, &card, &[user_id.to_string()]);
        }
    }

    fn announce_settled(
        &self,
        people: MutexGuard<'_, People>,
        notices: impl IntoIterator<Item = super::ring::Notice>,
        group_ended: impl IntoIterator<Item = super::group_call::EndedEvent>,
    ) {
        let notices: Vec<_> = notices.into_iter().collect();
        let group_ended: Vec<_> = group_ended.into_iter().collect();
        for ended in &group_ended {
            for ring in &ended.cancelled_rings {
                send_group_ring(&people, ring);
            }
            send_group_ended(&people, ended);
        }
        self.announce_rings(people, notices);
        for ended in group_ended {
            self.record_group_call(ended);
        }
    }

    fn record_group_call(&self, ended: super::group_call::EndedEvent) {
        let record = ended.record;
        tracing::info!(
            group_id = %record.group_id,
            call_id = %record.call_id,
            user_id = %record.started_by,
            outcome = record.outcome,
            "group call ended"
        );
        let call = db::GroupCallRecord {
            call_id: record.call_id,
            group_id: record.group_id,
            started_by: record.started_by,
            outcome: record.outcome,
            started_at: record.started_at,
            people: record.people,
        };
        let pool = self.pool.clone();
        tokio::spawn(async move {
            if let Err(error) = db::record_group_call(&pool, &call).await {
                tracing::warn!(
                    %error,
                    group_id = %call.group_id,
                    call_id = %call.call_id,
                    outcome = call.outcome,
                    "group call not recorded"
                );
            }
        });
    }

    fn finish_ring(
        &self,
        action: impl FnOnce(&mut super::ring::Rings) -> Result<super::ring::Notice, &'static str>,
    ) -> Result<(), &'static str> {
        let mut people = lock(&self.people);
        let notice = action(&mut people.rings)?;
        self.announce_rings(people, [notice]);
        Ok(())
    }

    /// Queue ring frames before releasing the mutation lock. Another socket's accept or a
    /// timer must not publish a later state first. Database work begins after the lock drops.
    fn announce_rings(
        &self,
        people: MutexGuard<'_, People>,
        notices: impl IntoIterator<Item = super::ring::Notice>,
    ) {
        let notices: Vec<_> = notices.into_iter().collect();
        use super::ring::Kind;
        for notice in &notices {
            let frame = match &notice.kind {
                Kind::Ringing(card) => Some(Out::CallRinging { card }.text()),
                Kind::Accepted(card) => Some(Out::CallAccepted { card }.text()),
                Kind::Declined(card) => Some(Out::CallDeclined { card }.text()),
                Kind::Cancelled(card) => Some(Out::CallCancelled { card }.text()),
                Kind::Missed(card) => Some(Out::CallMissed { card }.text()),
                Kind::Busy { direct_id } => Some(Out::CallBusy { direct_id }.text()),
                Kind::MediaTimeout(_) | Kind::Ended(_) => None,
            };
            if let Some(frame) = frame {
                let frame: Arc<str> = Arc::from(frame);
                for user in &notice.users {
                    people.fanout(user, Arc::clone(&frame));
                }
            }
        }
        drop(people);
        for notice in notices {
            self.record_ring(notice);
        }
    }

    fn record_ring(&self, notice: super::ring::Notice) {
        if let Some(record) = &notice.record {
            tracing::info!(
                direct_id = %record.direct_id,
                ring_id = %record.ring_id,
                user_id = %record.caller_id,
                callee_id = %record.callee_id,
                outcome = record.outcome,
                "direct call ended"
            );
        }
        if let Some(record) = notice.record {
            let call = db::DirectCallRecord {
                ring_id: record.ring_id,
                direct_id: record.direct_id,
                caller_id: record.caller_id,
                callee_id: record.callee_id,
                outcome: record.outcome,
                accepted_at: record.accepted_at,
            };
            let pool = self.pool.clone();
            tokio::spawn(async move {
                if let Err(error) = db::record_direct_call(&pool, &call).await {
                    tracing::warn!(
                        %error,
                        direct_id = %call.direct_id,
                        ring_id = %call.ring_id,
                        outcome = call.outcome,
                        "direct call not recorded"
                    );
                }
            });
        }
    }

    /// Ends rings whose wait is over. An accepted call's seats go first, while the ring still
    /// names the pair, so `call.left` reaches both.
    fn expire_rings(&self) {
        let now = std::time::Instant::now();
        let due = lock(&self.people).rings.due(now);
        for item in due {
            let mut people = lock(&self.people);
            if people.rings.accepted_due(&item.id, now) {
                let seated = people.calls.people(&item.room_id).to_vec();
                for user_id in &seated {
                    let changes = people.calls.leave(user_id, Reason::MediaTimeout);
                    self.tell(&mut people, changes);
                }
                for user_id in [&item.caller_id, &item.callee_id] {
                    if seated.iter().any(|seated_id| seated_id == user_id) {
                        continue;
                    }
                    let frame: Arc<str> = Arc::from(
                        Out::CallLeft {
                            room_id: &item.room_id,
                            direct_id: Some(&item.direct_id),
                            user_id,
                            reason: "media_timeout",
                        }
                        .text(),
                    );
                    people.fanout(&item.caller_id, Arc::clone(&frame));
                    people.fanout(&item.callee_id, frame);
                }
            }
            let notice = people.rings.take_due(&item.id, now);
            self.announce_rings(people, notice);
        }

        let mut people = lock(&self.people);
        let swept = {
            let People {
                calls, group_calls, ..
            } = &mut *people;
            group_calls.sweep(now, |room_id| calls.people(room_id).to_vec())
        };
        for event in &swept.ring_events {
            send_group_ring(&people, event);
        }
        let mut group_ended = swept.ended;
        for (room_id, lone_user) in swept.alone_leaves {
            if people.calls.room_of(&lone_user) == Some(room_id.as_str()) {
                let changes = people.calls.leave(&lone_user, Reason::Alone);
                self.tell(&mut people, changes);
                let remaining = people.calls.people(&room_id).len();
                if let Some(ended) = people.group_calls.on_left(&room_id, remaining, now) {
                    group_ended.push(ended);
                }
            }
        }
        self.announce_settled(people, Vec::new(), group_ended);
    }

    /// Acts on what the SFU reports.
    fn hear(&self, event: sfu::Event) {
        let mut people = lock(&self.people);
        match event {
            sfu::Event::Connected { call_id } => {
                tracing::debug!(%call_id, "media connected");
            }
            sfu::Event::Slots {
                call_id,
                audio,
                video,
            } => {
                let slots: Vec<SlotFrame<'_>> = audio
                    .iter()
                    .map(|slot| SlotFrame {
                        mid: &slot.mid,
                        user_id: &slot.user_id,
                    })
                    .collect();
                let video = video.as_ref().map(|slot| VideoSlotFrame {
                    mid: &slot.mid,
                    user_id: &slot.user_id,
                    kind: slot.kind.as_str(),
                });
                let frame: Arc<str> = Arc::from(
                    Out::CallSlots {
                        call_id: &call_id,
                        audio: &slots,
                        video,
                    }
                    .text(),
                );
                if let Some(user_id) = people.calls.holder(&call_id) {
                    people.to_seat(user_id, frame.clone());
                }
                people.slots.insert(call_id, frame);
            }
            sfu::Event::Speaking { room_id, user_ids } => {
                let frame: Arc<str> = match super::call::room_kind(&room_id) {
                    super::call::RoomKind::Group => {
                        let Some((group_id, call_id)) = people
                            .group_calls
                            .meta_of_room(&room_id)
                            .map(|(gid, cid, _)| (gid.to_string(), cid.to_string()))
                        else {
                            return;
                        };
                        Arc::from(
                            Out::CallGroupSpeaking {
                                group_id: &group_id,
                                call_id: &call_id,
                                user_ids: &user_ids,
                            }
                            .text(),
                        )
                    }
                    super::call::RoomKind::Direct | super::call::RoomKind::Room => {
                        let direct_id = people.rings.direct_of_room(&room_id).map(str::to_string);
                        Arc::from(
                            Out::CallSpeaking {
                                room_id: &room_id,
                                direct_id: direct_id.as_deref(),
                                user_ids: &user_ids,
                            }
                            .text(),
                        )
                    }
                };
                for user_id in people.calls.people(&room_id) {
                    people.to_seat(user_id, frame.clone());
                }
            }
            sfu::Event::Left { call_id, lost } => {
                people.slots.remove(&call_id);
                let Some(user_id) = people.calls.holder(&call_id).map(str::to_string) else {
                    return;
                };
                let room = people.calls.room_of(&user_id).map(str::to_string);
                let reason = match lost {
                    sfu::Lost::Timeout => Reason::MediaTimeout,
                    sfu::Lost::Gone => Reason::MediaLost,
                };
                let changes = people.calls.leave(&user_id, reason);
                self.tell(&mut people, changes);
                let (notices, group_ended) =
                    settle_calls(&mut people, room.as_deref(), &user_id, false);
                self.announce_settled(people, notices, group_ended);
            }
            sfu::Event::Load {
                egress_kbps,
                participants,
                longest_turn_ms,
            } => {
                people.media_overloaded = longest_turn_ms >= 50;
                tracing::debug!(
                    egress_kbps,
                    participants,
                    longest_turn_ms,
                    overloaded = people.media_overloaded,
                    "media load"
                );
            }
        }
    }
}

/// Writes who was connected to `last_seen_at` every `seen_every`, in one query, and once more
/// when the hub closes.
async fn remember(hub: Arc<Hub>, mut stop: watch::Receiver<bool>) {
    let mut ticks = tokio::time::interval(hub.limits.seen_every);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let last = tokio::select! {
            _ = stop.wait_for(|stopped| *stopped) => true,
            _ = ticks.tick() => false,
        };
        let users: Vec<String> = lock(&hub.seen).drain().collect();
        if let Err(error) = db::touch_seen(&hub.pool, &users).await {
            tracing::debug!(%error, "last seen not recorded");
        }
        if last {
            return;
        }
    }
}

/// Ends direct rings whose answer window, or seat window, has run out.
async fn sweep_rings(hub: Arc<Hub>, mut stop: watch::Receiver<bool>) {
    let mut ticks = tokio::time::interval(Duration::from_secs(1));
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = stop.wait_for(|stopped| *stopped) => return,
            _ = ticks.tick() => {}
        }
        hub.expire_rings();
    }
}

/// Builds again any E2EE group whose batch of proposals got no commit in time.
async fn rekey(hub: Arc<Hub>, mut stop: watch::Receiver<bool>) {
    let mut ticks = tokio::time::interval(Duration::from_secs(1));
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = stop.wait_for(|stopped| *stopped) => return,
            _ = ticks.tick() => {}
        }
        let people = &mut *lock(&hub.people);
        let frames = people.e2ee.tick(std::time::Instant::now());
        people.e2ee(frames);
    }
}

/// Feeds SFU events to the hub until it closes or the SFU stops.
async fn follow_media(
    hub: Arc<Hub>,
    mut events: mpsc::Receiver<sfu::Event>,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = stop.wait_for(|stopped| *stopped) => return,
            event = events.recv() => match event {
                Some(event) => hub.hear(event),
                None => {
                    tracing::warn!("media stopped");
                    return;
                }
            },
        }
    }
}

/// How soon a lost or refused `LISTEN` connection is tried again.
const LISTEN_RETRY: Duration = Duration::from_millis(500);

/// Reads outbox rows past the last one sent, in seq order, on every wake and every poll.
/// Ids are handed out in commit order, so a cursor in memory never skips a row.
async fn dispatch(hub: Arc<Hub>, mut stop: watch::Receiver<bool>) {
    let mut cursor = loop {
        match db::outbox_bounds(&hub.pool).await {
            Ok(bounds) => break bounds.head,
            Err(error) => tracing::warn!(%error, "outbox read failed"),
        }
        tokio::select! {
            _ = stop.changed() => return,
            () = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    };
    hub.ready.send_replace(true);
    let mut listener: Option<PgListener> = None;
    let mut poll = tokio::time::interval(hub.limits.poll);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        if *stop.borrow() {
            return;
        }
        if listener.is_none() {
            listener = listen(&hub.pool).await;
        }
        tokio::select! {
            _ = stop.changed() => return,
            _ = poll.tick() => {}
            // A listener that is gone is tried again soon, not at the next poll. Rows written
            // meanwhile are read by the drain below, so the retry loses nothing.
            () = tokio::time::sleep(LISTEN_RETRY), if listener.is_none() => {}
            woke = wake(listener.as_mut()) => {
                if let Err(error) = woke {
                    tracing::warn!(%error, "outbox listener lost");
                    listener = None;
                }
            }
        }
        cursor = drain(&hub, cursor).await;
    }
}

async fn listen(pool: &PgPool) -> Option<PgListener> {
    let mut listener = match PgListener::connect_with(pool).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::warn!(%error, "outbox listener connect failed");
            return None;
        }
    };
    match listener.listen(db::WAKE_CHANNEL).await {
        Ok(()) => Some(listener),
        Err(error) => {
            tracing::warn!(%error, "outbox listen failed");
            None
        }
    }
}

/// A notification, or a reconnect that may have missed one. Either way the outbox is read.
async fn wake(listener: Option<&mut PgListener>) -> Result<(), sqlx::Error> {
    match listener {
        Some(listener) => listener.try_recv().await.map(|_| ()),
        None => std::future::pending().await,
    }
}

async fn drain(hub: &Arc<Hub>, mut cursor: i64) -> i64 {
    loop {
        let rows = match db::outbox_after(&hub.pool, cursor, BATCH).await {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!(%error, "outbox read failed");
                return cursor;
            }
        };
        let full = rows.len() as i64 == BATCH;
        for row in rows {
            cursor = row.seq;
            let event = Arc::new(Event::from_row(row));
            hub.follow(&event);
            let _ = hub.events.send(event);
        }
        if !full {
            return cursor;
        }
    }
}

/// What permissions in a room mean for someone in its call.
pub(crate) fn access(permissions: i64) -> Access {
    use db::perm;
    Access {
        suppressed: !perm::has(permissions, perm::SPEAK),
        priority_speaker: perm::has(permissions, perm::PRIORITY_SPEAKER),
    }
}

impl Hub {
    /// Sends one ephemeral frame to every socket of each user.
    pub(crate) fn relay(&self, user_ids: &[String], frame: &str) {
        let frame: Arc<str> = Arc::from(frame);
        let people = lock(&self.people);
        for user_id in user_ids {
            people.fanout(user_id, Arc::clone(&frame));
        }
    }
}

fn direct_ready(people: &People, user_id: &str) -> Option<super::ring::ReadyDirect> {
    let room = people.calls.room_of(user_id)?;
    if !super::call::is_direct_room(room) {
        return None;
    }
    let direct_id = people.rings.direct_of_room(room)?.to_string();
    let ring_id = room.strip_prefix("d:")?.to_string();
    Some(super::ring::ReadyDirect {
        direct_id,
        ring_id,
        participants: people.calls.participants_of(room),
    })
}

fn send_group_started(
    people: &People,
    card: &super::group_call::StartedCard,
    recipients: &[String],
) {
    let frame: Arc<str> = Arc::from(
        Out::CallGroupStarted {
            group_id: &card.group_id,
            call_id: &card.call_id,
            started_by: &card.started_by,
            started_at: &card.started_at,
            rings: &card.rings,
            participants: &card.participants,
        }
        .text(),
    );
    for user in recipients {
        people.fanout(user, Arc::clone(&frame));
    }
}

fn send_group_ring(people: &People, event: &super::group_call::RingEvent) {
    let frame: Arc<str> = Arc::from(
        Out::CallGroupRing {
            group_id: &event.group_id,
            call_id: &event.call_id,
            user_id: &event.user_id,
            state: event.state,
            by: &event.by,
        }
        .text(),
    );
    for user in &event.recipients {
        people.fanout(user, Arc::clone(&frame));
    }
}

fn send_group_ended(people: &People, ended: &super::group_call::EndedEvent) {
    let frame: Arc<str> = Arc::from(
        Out::CallGroupEnded {
            group_id: &ended.group_id,
            call_id: &ended.call_id,
            outcome: ended.outcome,
        }
        .text(),
    );
    for user in &ended.recipients {
        people.fanout(user, Arc::clone(&frame));
    }
}

/// A direct or group room that just emptied writes its outcome. `end_rings` also drops rings
/// when a ban, removal, or timeout ends membership. `call.leave` with no seat only cancels a
/// direct ring this person placed. Leaving a community room does not.
fn settle_calls(
    people: &mut People,
    room: Option<&str>,
    user_id: &str,
    end_rings: bool,
) -> (Vec<super::ring::Notice>, Vec<super::group_call::EndedEvent>) {
    let notices = settle_direct(people, room, user_id, end_rings);
    let now = std::time::Instant::now();
    let mut group_ended = Vec::new();
    if let Some(room) = room {
        if super::call::is_group_room(room) {
            let remaining = people.calls.people(room).len();
            if let Some(ended) = people.group_calls.on_left(room, remaining, now) {
                group_ended.push(ended);
            }
        }
    }
    if end_rings {
        let cancelled = {
            let People {
                calls, group_calls, ..
            } = people;
            group_calls.drop_user_rings(user_id, |r| calls.people(r).len(), now)
        };
        for event in &cancelled {
            send_group_ring(people, event);
        }
    }
    (notices, group_ended)
}

/// A direct room that just emptied writes its outcome. `end_rings` also drops a ring when a
/// ban, removal, or timeout ends membership. `call.leave` with no seat only cancels a ring
/// this person placed. Leaving a community room does not.
fn settle_direct(
    people: &mut People,
    room: Option<&str>,
    user_id: &str,
    end_rings: bool,
) -> Vec<super::ring::Notice> {
    let mut notices = Vec::new();
    if let Some(room) = room {
        if super::call::is_direct_room(room) && people.calls.people(room).is_empty() {
            if let Some(notice) = people.rings.on_room_empty(room) {
                notices.push(notice);
            }
        }
    }
    if end_rings {
        if let Some(notice) = people.rings.drop_user(user_id) {
            notices.push(notice);
        }
    } else if room.is_none() {
        if let Some(notice) = people.rings.cancel_outgoing(user_id) {
            notices.push(notice);
        }
    }
    notices
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    /// A hub whose people map holds one plain person, and a subscriber to its presence.
    fn presence_hub(grace: Duration) -> (Arc<Hub>, broadcast::Receiver<Arc<str>>) {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/direct_call_unit")
            .expect("lazy pool");
        let limits = Limits {
            presence_grace: grace,
            ..Limits::default()
        };
        let hub = Hub::start(pool, limits, None);
        lock(&hub.people)
            .users
            .insert("u".into(), Person::default());
        let watcher = hub.ephemeral.subscribe();
        (hub, watcher)
    }

    async fn next_frame(watcher: &mut broadcast::Receiver<Arc<str>>) -> Value {
        let frame = tokio::time::timeout(Duration::from_secs(2), watcher.recv())
            .await
            .expect("a frame in time")
            .expect("sent");
        serde_json::from_str(&frame).expect("json")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn setting_a_state_is_broadcast_with_the_text_the_person_set() {
        let (hub, mut watcher) = presence_hub(Limits::default().presence_grace);
        hub.set_presence("u", State::Idle, None)
            .expect("the person is on the hub");
        assert_eq!(
            next_frame(&mut watcher).await,
            json!({"type": "presence", "user_id": "u", "online": true, "state": "idle"})
        );
        hub.set_presence("u", State::Dnd, Some("back at 4".into()))
            .expect("the person is on the hub");
        assert_eq!(
            next_frame(&mut watcher).await,
            json!({"type": "presence", "user_id": "u", "online": true, "state": "dnd", "text": "back at 4"})
        );
        assert!(hub.set_presence("gone", State::Idle, None).is_err());
        hub.close();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn going_offline_announces_the_state_the_person_had_set() {
        let (hub, mut watcher) = presence_hub(Duration::from_millis(50));
        let (kick, _kicked) = oneshot::channel();
        let (direct, _inbox) = mpsc::channel(16);
        let (proofs, _asked) = mpsc::unbounded_channel();
        {
            let mut people = lock(&hub.people);
            let person = people.users.get_mut("u").expect("person");
            person.conns.push(Conn {
                id: 1,
                kick,
                direct,
                proofs,
                features: HashSet::new(),
            });
            person.presence = Some(Setting {
                state: State::Dnd,
                text: Some("back at 4".into()),
            });
        }
        hub.leave("u", 1);
        assert_eq!(
            next_frame(&mut watcher).await,
            json!({"type": "presence", "user_id": "u", "online": false, "state": "dnd", "text": "back at 4"})
        );
        hub.close();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_accept_never_overtakes_the_ringing_frame() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/direct_call_unit")
            .expect("lazy pool");
        let hub = Hub::start(pool, Limits::default(), None);
        let (sent, mut heard) = mpsc::channel(16);
        let (kick, _kicked) = oneshot::channel();
        let (proofs, _proof_requests) = mpsc::unbounded_channel();
        lock(&hub.people).users.insert(
            "caller".into(),
            Person {
                conns: vec![Conn {
                    id: 1,
                    kick,
                    direct: sent,
                    proofs,
                    features: HashSet::new(),
                }],
                ..Person::default()
            },
        );
        for _ in 0..512 {
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let observer_hub = hub.clone();
            let observer_barrier = barrier.clone();
            let observer = std::thread::spawn(move || {
                observer_barrier.wait();
                loop {
                    if lock(&observer_hub.people).rings.ready("callee").is_some() {
                        break;
                    }
                    std::thread::yield_now();
                }
                observer_hub
                    .accept_ring("direct", "callee")
                    .expect("accept");
            });
            barrier.wait();
            hub.start_ring("direct", "caller", "callee").expect("ring");
            observer.join().expect("observer");
            let first: serde_json::Value =
                serde_json::from_str(&heard.try_recv().expect("first event")).expect("json");
            let second: serde_json::Value =
                serde_json::from_str(&heard.try_recv().expect("second event")).expect("json");
            assert_eq!(
                first["type"], "call.ringing",
                "mutation order is delivery order"
            );
            assert_eq!(second["type"], "call.accepted");
            lock(&hub.people).rings.drop_user("caller");
        }
        hub.close();
    }

    #[tokio::test]
    async fn a_direct_that_expired_while_media_was_prepared_cannot_take_a_seat() {
        // Prepare and connect real media before the final admission. A ring can expire
        // while the socket awaits SFU preparation, so rejecting only its seat is insufficient.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/direct_call_unit")
            .expect("lazy pool");
        let loopback = std::net::Ipv4Addr::LOCALHOST;
        let config = sfu::Config::new((loopback, 0).into(), loopback.into());
        let (media, events) = sfu::start(config).expect("SFU");
        let hub = Hub::start(pool, Limits::default(), Some((media.clone(), events)));
        let room_id = {
            let mut people = lock(&hub.people);
            people.rings.start("direct", "caller", "callee");
            people.rings.accept("direct", "callee").expect("accepted");
            people.rings.join_key("direct", "caller").expect("join key")
        };
        let mut client = sfu::client::Client::new((loopback, 0).into(), 1).expect("media client");
        let offer = client.offer().to_owned();
        let answer = media
            .join(&room_id, "caller", &offer)
            .await
            .expect("media prepared");
        client.accept(&answer.sdp).expect("media answer");
        let running = client.start(b'A').expect("media transport");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while !running.connected() {
            assert!(
                std::time::Instant::now() < deadline,
                "media never connected"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        {
            let mut people = lock(&hub.people);
            let notices = people
                .rings
                .expire_due(std::time::Instant::now() + super::super::ring::SEAT_FOR);
            assert_eq!(notices.len(), 1, "the ring ended during media preparation");
        }
        let result = hub.call_join(
            "caller",
            &room_id,
            1,
            Some(&answer),
            2,
            Access::default(),
            false,
            [0; 32],
        );
        assert!(
            result.is_err(),
            "an expired direct cannot gain a ghost seat"
        );
        assert!(hub.room_of("caller").is_none());
        assert_eq!(
            media.offer(&answer.call_id, &offer).await,
            Err(sfu::Refused::NotFound),
            "rejected media and its connected transport must be removed"
        );
        hub.close();
    }

    #[tokio::test]
    async fn removing_an_unseated_callee_ends_the_callers_accepted_seat() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/direct_call_unit")
            .expect("lazy pool");
        let hub = Hub::start(pool, Limits::default(), None);
        let room_id = {
            let mut people = lock(&hub.people);
            people.rings.start("direct", "caller", "callee");
            people.rings.accept("direct", "callee").expect("accepted");
            people.rings.join_key("direct", "caller").expect("join key")
        };
        hub.call_join(
            "caller",
            &room_id,
            1,
            None,
            2,
            Access::default(),
            false,
            [0; 32],
        )
        .expect("the caller has a seat; the callee is still connecting");
        hub.call_leave("callee", Reason::Removed, true);
        assert!(
            hub.room_of("caller").is_none(),
            "removing either party ends the accepted call"
        );
        assert!(lock(&hub.people).rings.ready("caller").is_none());
        hub.close();
    }

    #[tokio::test]
    async fn socket_features_are_tracked_per_conn_and_per_seat() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/features_unit")
            .expect("lazy pool");
        let hub = Hub::start(pool, Limits::default(), None);

        let first = hub.join("alice", false, HashSet::new());
        {
            let people = lock(&hub.people);
            assert!(!people.has_feature("alice", "group_calls"));
            assert!(!people.seat_has_feature("alice", "group_calls"));
        }

        let mut with_gc = HashSet::new();
        with_gc.insert("group_calls".to_string());
        let second = hub.join("alice", false, with_gc);
        {
            let people = lock(&hub.people);
            assert!(people.has_feature("alice", "group_calls"));
            assert!(!people.seat_has_feature("alice", "group_calls"));
        }

        // Put `first` (without group_calls) in a call seat.
        hub.call_join(
            "alice",
            "room-1",
            first.conn,
            None,
            12,
            Access::default(),
            false,
            [1; 32],
        )
        .expect("join room");
        {
            let people = lock(&hub.people);
            assert!(people.has_feature("alice", "group_calls"));
            assert!(!people.seat_has_feature("alice", "group_calls"));
        }

        // Move the seat to `second` (with group_calls).
        hub.call_leave("alice", Reason::Left, true);
        hub.call_join(
            "alice",
            "room-1",
            second.conn,
            None,
            12,
            Access::default(),
            false,
            [2; 32],
        )
        .expect("join room on second socket");
        {
            let people = lock(&hub.people);
            assert!(people.has_feature("alice", "group_calls"));
            assert!(people.seat_has_feature("alice", "group_calls"));
        }

        // Dropping `second` removes the feature from `alice`.
        hub.leave("alice", second.conn);
        {
            let people = lock(&hub.people);
            assert!(!people.has_feature("alice", "group_calls"));
            assert!(!people.seat_has_feature("alice", "group_calls"));
        }
        hub.close();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn group_call_busy_voice_unring_capacity_and_privacy_isolation() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/group_call_unit")
            .expect("lazy pool");
        let limits = Limits {
            call_room_max: Some(2),
            ..Limits::default()
        };
        let hub = Hub::start(pool, limits, None);
        let mut a = hub.join("a", false, HashSet::new());
        let mut b = hub.join("b", false, HashSet::new());
        let mut c = hub.join("c", false, HashSet::new());
        let mut d = hub.join("d", false, HashSet::new());
        let outsider = hub.join("outsider", false, HashSet::new());
        let mut watcher = hub.ephemeral.subscribe();

        // B is in a 1:1 direct call (with X), C is in a voice room.
        hub.start_ring("d-bx", "b", "x").expect("direct ring");
        let _ = b.direct.try_recv(); // call.ringing
        hub.call_join(
            "c",
            "voice-1",
            c.conn,
            None,
            0,
            Access::default(),
            false,
            [3; 32],
        )
        .expect("c in voice room");
        let _ = watcher.try_recv(); // voice room call.joined

        let members = vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
        ];
        hub.start_group_call("g1", "a", members.clone())
            .expect("start group call");

        // All four members get call.group.started; B is busy, C (in voice room) and D are rung.
        let started_a: Value =
            serde_json::from_str(&a.direct.try_recv().expect("started a")).expect("json");
        assert_eq!(started_a["type"], "call.group.started");
        let call_id = started_a["call_id"].as_str().expect("call_id").to_string();
        let state_of = |uid: &str| {
            started_a["rings"]
                .as_array()
                .expect("rings")
                .iter()
                .find(|r| r["user_id"] == uid)
                .and_then(|r| r["state"].as_str())
        };
        assert_eq!(state_of("b"), Some("busy"));
        assert_eq!(state_of("c"), Some("ringing"));
        assert_eq!(state_of("d"), Some("ringing"));
        // B still got call.group.started despite being busy.
        let started_b: Value =
            serde_json::from_str(&b.direct.try_recv().expect("started b")).expect("json");
        assert_eq!(started_b["type"], "call.group.started");
        let _ = c.direct.try_recv().expect("started c");
        let _ = d.direct.try_recv().expect("started d");

        // Unring from A before A is seated is refused.
        assert_eq!(
            hub.unring_group_call("g1", &call_id, "a", &["d".to_string()]),
            Err("not_found")
        );

        // A and C join the group call (g:{call_id}).
        let room_id = super::super::group_call::room_key(&call_id);
        hub.call_join(
            "a",
            &room_id,
            a.conn,
            None,
            0,
            Access::default(),
            false,
            [1; 32],
        )
        .expect("a join");
        hub.mark_group_answered("g1", "c");
        hub.call_join(
            "c",
            &room_id,
            c.conn,
            None,
            0,
            Access::default(),
            false,
            [3; 32],
        )
        .expect("c join");

        // Now room_max (2) is full: D trying to join gets Refused::Full and D's ring is cancelled!
        assert_eq!(
            hub.call_join(
                "d",
                &room_id,
                d.conn,
                None,
                0,
                Access::default(),
                false,
                [4; 32]
            ),
            Err(Refused::Full)
        );
        // Drain D's frames and verify D received call.group.ring cancelled.
        let mut saw_cancelled = false;
        while let Ok(raw) = d.direct.try_recv() {
            let v: Value = serde_json::from_str(&raw).expect("json");
            if v["type"] == "call.group.ring" && v["user_id"] == "d" && v["state"] == "cancelled" {
                saw_cancelled = true;
            }
        }
        assert!(saw_cancelled, "refused join must end the person's ring");

        // ready.calls and server-wide ephemeral broadcast NEVER contain a g: room!
        let snapshot = lock(&hub.people).calls.snapshot();
        assert!(
            snapshot.iter().all(|o| !o.room_id.starts_with("g:")),
            "ready.calls leaked g: room: {snapshot:?}"
        );
        while let Ok(raw) = watcher.try_recv() {
            assert!(
                !raw.contains(&room_id) && !raw.contains("call.group."),
                "ephemeral broadcast leaked group call frame: {raw}"
            );
        }
        // Outsider has no group_calls in ready.
        let outsider_ready = hub.join("outsider2", false, HashSet::new());
        assert!(outsider_ready.group_calls.is_empty());
        assert!(outsider_ready
            .calls
            .iter()
            .all(|o| !o.room_id.starts_with("g:")));

        // Seated A can unring a ringing member (re-add E? check unring ok on non-ringing D).
        hub.unring_group_call("g1", &call_id, "a", &["d".to_string()])
            .expect("unring on non-ringing is ok");
        drop(outsider);
        hub.close();
    }
}
