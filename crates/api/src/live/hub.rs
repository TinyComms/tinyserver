//! Who is connected, who is online, who is in which call, and the one task that reads the
//! outbox.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use db::PgPool;
use sqlx::postgres::PgListener;
use tokio::sync::{broadcast, oneshot, watch, Notify};
use tokio::task::JoinHandle;

use super::call::{Calls, Change, Occupancy, Reason, Refused};
use super::frame::{Event, Out};
use super::socket::Close;
use super::Limits;

/// Events a socket may fall behind by before it gets `resync`.
const BACKLOG: usize = 1024;
/// Outbox rows read per query.
const BATCH: i64 = 256;

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
}

#[derive(Default)]
struct People {
    users: HashMap<String, Person>,
    next_conn: u64,
    calls: Calls,
}

/// Online while this exists. It outlives the last socket by the presence grace.
#[derive(Default)]
struct Person {
    conns: Vec<Conn>,
    epoch: u64,
}

struct Conn {
    id: u64,
    kick: oneshot::Sender<Close>,
}

/// What a socket gets when it joins the hub.
pub(crate) struct Joined {
    pub conn: u64,
    pub kicked: oneshot::Receiver<Close>,
    pub presence: broadcast::Receiver<Arc<str>>,
    pub online: Vec<String>,
    pub calls: Vec<Occupancy>,
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
    pub fn start(pool: PgPool, limits: Limits) -> Arc<Self> {
        let (events, _) = broadcast::channel(BACKLOG);
        let (ephemeral, _) = broadcast::channel(BACKLOG);
        let (stop, _) = watch::channel(false);
        let hub = Arc::new(Self {
            pool,
            limits,
            events,
            ephemeral,
            people: Mutex::new(People::default()),
            open: AtomicUsize::new(0),
            drained: Notify::new(),
            stop,
            dispatcher: Mutex::new(None),
        });
        let task = tokio::spawn(dispatch(hub.clone(), hub.stop.subscribe()));
        *lock(&hub.dispatcher) = Some(task);
        hub
    }

    /// Also ends every call. The `1012` close is how callers learn it.
    pub fn close(&self) {
        self.stop.send_replace(true);
        lock(&self.people).calls.clear();
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
    pub fn join(&self, user_id: &str) -> Joined {
        let (kick, kicked) = oneshot::channel();
        let mut people = lock(&self.people);
        people.next_conn += 1;
        let conn = people.next_conn;
        let arrived = !people.users.contains_key(user_id);
        let person = people.users.entry(user_id.to_string()).or_default();
        while person.conns.len() >= self.limits.sockets_per_user.max(1) {
            let oldest = person.conns.remove(0);
            let _ = oldest.kick.send(Close::Replaced);
        }
        person.conns.push(Conn { id: conn, kick });
        if arrived {
            self.announce(user_id, true);
        }
        // Subscribed under the lock, so every presence frame after this snapshot reaches it.
        let presence = self.ephemeral.subscribe();
        let mut online: Vec<String> = people.users.keys().cloned().collect();
        online.sort();
        Joined {
            conn,
            kicked,
            presence,
            online,
            calls: people.calls.snapshot(),
        }
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
                people.users.remove(&user_id);
                hub.announce(&user_id, false);
            }
        });
    }

    fn announce(&self, user_id: &str, online: bool) {
        let frame = Out::Presence { user_id, online }.text();
        let _ = self.ephemeral.send(Arc::from(frame));
    }

    /// Seats `user_id` in `room_id` for socket `conn`. Refused once the hub is closing.
    pub fn call_join(&self, user_id: &str, room_id: &str, conn: u64) -> Result<(), Refused> {
        let mut people = lock(&self.people);
        if self.closing() {
            return Err(Refused::Closing);
        }
        let changes = people.calls.join(
            user_id,
            room_id,
            conn,
            self.limits.call_room_max,
            self.limits.call_server_max,
        )?;
        self.tell(changes);
        Ok(())
    }

    /// Ends `user_id`'s call, if they are in one.
    pub fn call_leave(&self, user_id: &str, reason: Reason) {
        let mut people = lock(&self.people);
        let change = people.calls.leave(user_id, reason);
        self.tell(change);
    }

    /// Ends `user_id`'s call if it is in `room_id`. False if they were not there.
    pub fn call_kick(&self, room_id: &str, user_id: &str) -> bool {
        let mut people = lock(&self.people);
        if people.calls.room_of(user_id) != Some(room_id) {
            return false;
        }
        let change = people.calls.leave(user_id, Reason::Kicked);
        self.tell(change);
        true
    }

    pub fn in_call(&self, room_id: &str, user_id: &str) -> bool {
        lock(&self.people).calls.room_of(user_id) == Some(room_id)
    }

    pub fn end_room(&self, room_id: &str, reason: Reason) {
        let mut people = lock(&self.people);
        let changes = people.calls.end_room(room_id, reason);
        self.tell(changes);
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
                let change = people.calls.leave(user_id, reason);
                self.tell(change);
                return;
            }
            epoch
        };
        let hub = self.clone();
        let user_id = user_id.to_string();
        tokio::spawn(async move {
            tokio::time::sleep(hub.limits.presence_grace).await;
            let mut people = lock(&hub.people);
            let change = people.calls.expire(&user_id, epoch);
            hub.tell(change);
        });
    }

    /// Acts on durable events that end calls.
    fn follow(&self, event: &Event) {
        match event.topic.as_str() {
            "room.deleted" => {
                if let Some(room_id) = &event.room {
                    self.end_room(room_id, Reason::RoomDeleted);
                }
            }
            "member.removed" => {
                if let Some(user_id) = &event.subject {
                    self.call_leave(user_id, Reason::Removed);
                }
            }
            _ => {}
        }
    }

    /// Sends call changes. Called with `people` locked, so frames go out in registry order.
    fn tell(&self, changes: impl IntoIterator<Item = Change>) {
        for change in changes {
            let frame = match &change {
                Change::Joined { room_id, user_id } => Out::CallJoined { room_id, user_id }.text(),
                Change::Left {
                    room_id,
                    user_id,
                    reason,
                } => Out::CallLeft {
                    room_id,
                    user_id,
                    reason: reason.as_str(),
                }
                .text(),
            };
            let _ = self.ephemeral.send(Arc::from(frame));
        }
    }
}

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

async fn drain(hub: &Hub, mut cursor: i64) -> i64 {
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

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}
