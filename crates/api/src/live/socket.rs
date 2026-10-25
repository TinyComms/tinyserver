//! One live socket: `ready`, the replay, then events, presence, and calls until something
//! closes it.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use db::{Caller, CommunityError, SessionError};
use tokio::sync::broadcast::error::RecvError;
use tokio::time::{Instant, MissedTickBehavior};

use super::call::{Moves, Reason, Refused};
use super::frame::{Audience, Event, Incoming, Me as MeFrame, Out};
use super::hub::{Hub, Joined, Slot};

/// Why the server closed a socket. The code and reason are in `docs/calls.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Close {
    Idle,
    SessionEnded,
    Resync,
    Removed,
    Replaced,
    SlowDown,
    Restart,
    Unavailable,
    TextOnly,
    TooBig,
}

impl Close {
    fn frame(self) -> CloseFrame {
        let (code, reason) = match self {
            Self::Idle => (4000, "idle"),
            Self::SessionEnded => (4001, "session_ended"),
            Self::Resync => (4002, "resync"),
            Self::Removed => (4003, "removed"),
            Self::Replaced => (4008, "replaced"),
            Self::SlowDown => (4029, "slow_down"),
            Self::Restart => (1012, "restart"),
            Self::Unavailable => (1011, "unavailable"),
            Self::TextOnly => (1003, "text_only"),
            Self::TooBig => (1009, "too_big"),
        };
        CloseFrame {
            code,
            reason: reason.into(),
        }
    }
}

/// How a socket ends: with a close frame, or with the peer already gone.
enum End {
    Close(Close),
    Gone,
}

type Step = Result<(), End>;

pub(crate) struct Me {
    pub token: String,
    pub user_id: String,
    pub role: String,
}

impl Me {
    fn manages(&self) -> bool {
        matches!(self.role.as_str(), "owner" | "admin")
    }

    fn caller(&self) -> Caller {
        Caller {
            user_id: self.user_id.clone(),
            role: self.role.clone(),
        }
    }
}

/// A request that succeeded.
enum Done {
    /// Sent as `ok`.
    Ok,
    /// Sent as `call.answer`.
    Answer(sfu::Answer),
}

/// What a request gets back: `ok` or `call.answer`, or `error` with this code.
type Answer = Result<Done, &'static str>;

pub(crate) async fn run(
    hub: Arc<Hub>,
    mut socket: WebSocket,
    slot: Slot,
    mut me: Me,
    since: Option<i64>,
) {
    let joined = hub.join(&me.user_id);
    let conn = joined.conn;
    tracing::info!(user_id = %me.user_id, conn, "live socket opened");
    let end = serve(&hub, &mut socket, &mut me, since, joined).await;
    let reason = match end {
        End::Close(Close::Removed) => Some(Reason::Removed),
        End::Close(Close::SessionEnded) => Some(Reason::SessionEnded),
        _ => None,
    };
    if let End::Close(close) = end {
        tracing::info!(user_id = %me.user_id, conn, ?close, "live socket closed");
        let frame = Message::Close(Some(close.frame()));
        let _ = tokio::time::timeout(Duration::from_secs(1), socket.send(frame)).await;
    } else {
        tracing::info!(user_id = %me.user_id, conn, "live socket gone");
    }
    hub.hang_up(&me.user_id, conn, reason);
    hub.leave(&me.user_id, conn);
    drop(slot);
}

async fn serve(
    hub: &Hub,
    socket: &mut WebSocket,
    me: &mut Me,
    since: Option<i64>,
    joined: Joined,
) -> End {
    let Joined {
        conn,
        mut kicked,
        mut presence,
        mut direct,
        online,
        calls,
    } = joined;
    // Subscribed before the outbox is read, so nothing falls between the replay and the stream.
    let mut events = hub.events.subscribe();
    let mut stop = hub.stopping();
    let limits = hub.limits;

    let bounds = match db::outbox_bounds(&hub.pool).await {
        Ok(bounds) => bounds,
        Err(error) => {
            tracing::warn!(%error, "outbox read failed");
            return End::Close(Close::Unavailable);
        }
    };
    let mut last = match since {
        Some(since) if since < bounds.pruned_through || since > bounds.head => {
            return resync(hub, socket).await;
        }
        Some(since) => since,
        None => bounds.head,
    };
    let ready = Out::Ready {
        seq: last,
        me: MeFrame {
            user_id: &me.user_id,
            role: &me.role,
        },
        online: &online,
        calls: &calls,
    };
    if let Err(end) = send(hub, socket, ready.text()).await {
        return end;
    }
    if since.is_some() {
        let rows = match db::outbox_after(&hub.pool, last, limits.replay_max + 1).await {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!(%error, "outbox replay failed");
                return End::Close(Close::Unavailable);
            }
        };
        if rows.len() as i64 > limits.replay_max {
            return resync(hub, socket).await;
        }
        for row in rows {
            last = row.seq;
            if let Err(end) = deliver(hub, socket, me, &Event::from_row(row)).await {
                return end;
            }
        }
    }

    let mut seen = Instant::now();
    let mut recheck = tokio::time::interval_at(Instant::now() + limits.recheck, limits.recheck);
    recheck.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut bucket = Bucket::new(limits.messages_per_second, limits.message_burst);
    let mut moves = Moves::new(limits.call_move_burst, limits.call_move_every);
    let mut asking = Asking {
        conn,
        bucket: &mut bucket,
        moves: &mut moves,
    };

    loop {
        let step = tokio::select! {
            close = &mut kicked => Err(End::Close(close.unwrap_or(Close::Replaced))),
            () = stopped(&mut stop) => Err(End::Close(Close::Restart)),
            event = events.recv() => match event {
                Ok(event) if event.seq <= last => Ok(()),
                Ok(event) => {
                    last = event.seq;
                    deliver(hub, socket, me, &event).await
                }
                Err(RecvError::Lagged(_)) => return resync(hub, socket).await,
                Err(RecvError::Closed) => Err(End::Close(Close::Restart)),
            },
            frame = presence.recv() => match frame {
                Ok(frame) => send(hub, socket, frame.to_string()).await,
                Err(RecvError::Lagged(_)) => return resync(hub, socket).await,
                Err(RecvError::Closed) => Err(End::Close(Close::Restart)),
            },
            Some(frame) = direct.recv() => send(hub, socket, frame.to_string()).await,
            message = socket.recv() => {
                seen = Instant::now();
                receive(hub, socket, me, &mut asking, message).await
            }
            () = tokio::time::sleep_until(seen + limits.idle) => Err(End::Close(Close::Idle)),
            _ = recheck.tick() => check(hub, me).await,
        };
        if let Err(end) = step {
            return end;
        }
    }
}

/// Resolves once the hub is closing, including when it already was.
async fn stopped(stop: &mut tokio::sync::watch::Receiver<bool>) {
    let _ = stop.wait_for(|stopped| *stopped).await;
}

async fn resync(hub: &Hub, socket: &mut WebSocket) -> End {
    match send(hub, socket, Out::Resync.text()).await {
        Ok(()) => End::Close(Close::Resync),
        Err(end) => end,
    }
}

/// Sends one durable event if this socket may see it, and acts on events about this person.
async fn deliver(hub: &Hub, socket: &mut WebSocket, me: &mut Me, event: &Event) -> Step {
    let mine = event.subject.as_deref() == Some(me.user_id.as_str());
    let visible = match event.audience {
        Audience::Everyone => true,
        Audience::Managers => me.manages(),
        Audience::Server => false,
    };
    if visible {
        if let Some(frame) = &event.frame {
            send(hub, socket, frame.clone()).await?;
        }
    }
    if !mine {
        return Ok(());
    }
    match event.topic.as_str() {
        "member.removed" => Err(End::Close(Close::Removed)),
        "member.role" => {
            if let Some(role) = &event.role {
                me.role.clone_from(role);
            }
            Ok(())
        }
        "session.ended" => check(hub, me).await,
        _ => Ok(()),
    }
}

/// Re-reads the session. A database error keeps the socket; the next check tries again.
async fn check(hub: &Hub, me: &mut Me) -> Step {
    match db::current_session(&hub.pool, &me.token).await {
        Ok(identity) => {
            me.role = identity.role;
            Ok(())
        }
        Err(SessionError::Unauthorized | SessionError::InvalidCredentials) => {
            Err(End::Close(Close::SessionEnded))
        }
        Err(SessionError::Database(error)) => {
            tracing::warn!(%error, "live session check failed");
            Ok(())
        }
    }
}

/// Per-socket state for client requests.
struct Asking<'a> {
    conn: u64,
    bucket: &'a mut Bucket,
    moves: &'a mut Moves,
}

async fn receive(
    hub: &Hub,
    socket: &mut WebSocket,
    me: &mut Me,
    asking: &mut Asking<'_>,
    message: Option<Result<Message, axum::Error>>,
) -> Step {
    let message = match message {
        None => return Err(End::Gone),
        Some(Ok(message)) => message,
        Some(Err(error)) => {
            if is_too_big(&error) {
                return Err(End::Close(Close::TooBig));
            }
            return Err(End::Gone);
        }
    };
    let text = match message {
        Message::Text(text) => text,
        Message::Binary(_) => return Err(End::Close(Close::TextOnly)),
        Message::Ping(_) | Message::Pong(_) => return Ok(()),
        Message::Close(_) => return Err(End::Gone),
    };
    match asking.bucket.take() {
        Take::Allowed => {}
        Take::Warn => {
            let warning = Out::Error {
                reference: None,
                code: "slow_down",
            };
            return send(hub, socket, warning.text()).await;
        }
        Take::Dropped => return Ok(()),
        Take::Exceeded => return Err(End::Close(Close::SlowDown)),
    }
    let Some(incoming) = Incoming::parse(text.as_str()) else {
        let reply = Out::Error {
            reference: None,
            code: "bad_frame",
        };
        return send(hub, socket, reply.text()).await;
    };
    let room_id = incoming.room_id.as_deref();
    let sdp = incoming.sdp.as_deref();
    let answer = match incoming.kind.as_str() {
        "ping" => return send(hub, socket, Out::Pong.text()).await,
        "call.join" => call_join(hub, me, asking, room_id, sdp).await?,
        "call.leave" => call_leave(hub, me, asking),
        "call.kick" => call_kick(hub, me, room_id, incoming.user_id.as_deref()).await?,
        "call.offer" => call_offer(hub, me, asking, sdp).await,
        "call.state" => call_state(hub, me, incoming.muted, incoming.deafened),
        "call.quality" => call_quality(hub, me, incoming.video.as_deref()),
        _ => Err("unknown_type"),
    };
    let reference = incoming.reference.as_ref();
    let reply = match &answer {
        Ok(Done::Ok) => Out::Ok { reference },
        Ok(Done::Answer(answer)) => Out::CallAnswer {
            reference,
            call_id: &answer.call_id,
            sdp: &answer.sdp,
        },
        Err(code) => Out::Error { reference, code },
    };
    send(hub, socket, reply.text()).await
}

/// Re-reads the session before a call request. An ended session closes the socket.
async fn fresh(hub: &Hub, me: &mut Me) -> Result<Answer, End> {
    match db::current_session(&hub.pool, &me.token).await {
        Ok(identity) => {
            me.role = identity.role;
            Ok(Ok(Done::Ok))
        }
        Err(SessionError::Unauthorized | SessionError::InvalidCredentials) => {
            Err(End::Close(Close::SessionEnded))
        }
        Err(SessionError::Database(error)) => {
            tracing::warn!(%error, "live session check failed");
            Ok(Err("unavailable"))
        }
    }
}

async fn room_exists(hub: &Hub, me: &Me, room_id: &str) -> Answer {
    match db::room_exists(&hub.pool, &me.caller(), room_id).await {
        Ok(true) => Ok(Done::Ok),
        Ok(false) => Err("not_found"),
        Err(error) => {
            tracing::warn!(%error, "room check failed");
            Err("unavailable")
        }
    }
}

/// Any member may join any room they can see. Leaves the person's other call first. With
/// an SFU running the join must carry an offer, and the reply is the answer.
async fn call_join(
    hub: &Hub,
    me: &mut Me,
    asking: &mut Asking<'_>,
    room_id: Option<&str>,
    sdp: Option<&str>,
) -> Result<Answer, End> {
    let Some(room_id) = room_id else {
        return Ok(Err("bad_frame"));
    };
    let media = match (&hub.media, sdp) {
        (None, None) => None,
        (Some(_), None) => return Ok(Err("bad_frame")),
        (None, Some(_)) => return Ok(Err(Refused::NoMedia.code())),
        (Some(media), Some(_)) if !media.running() => return Ok(Err(Refused::NoMedia.code())),
        (Some(media), Some(sdp)) => Some((media, sdp)),
    };
    if !asking.moves.take() {
        return Ok(Err("slow_down"));
    }
    if let Err(code) = fresh(hub, me).await? {
        return Ok(Err(code));
    }
    if let Err(code) = room_exists(hub, me, room_id).await {
        return Ok(Err(code));
    }
    let answer = match media {
        None => None,
        Some((media, sdp)) => {
            if let Err(refused) = hub.call_check(&me.user_id, room_id) {
                return Ok(Err(refused.code()));
            }
            match media.join(room_id, &me.user_id, sdp).await {
                Ok(answer) => Some(answer),
                Err(refused) => return Ok(Err(media_code(refused))),
            }
        }
    };
    let call_id = answer.as_ref().map(|answer| answer.call_id.as_str());
    let camera = answer.as_ref().is_some_and(|answer| answer.camera);
    if let Err(refused) = hub.call_join(&me.user_id, room_id, asking.conn, call_id, camera) {
        if let Some(call_id) = call_id {
            hub.forget(call_id);
        }
        return Ok(Err(refused.code()));
    }
    // A delete that committed during the first check was followed before this seat existed.
    if let Err("not_found") = room_exists(hub, me, room_id).await {
        hub.end_room(room_id, Reason::RoomDeleted);
        return Ok(Err("not_found"));
    }
    Ok(Ok(answer.map_or(Done::Ok, Done::Answer)))
}

fn media_code(refused: sfu::Refused) -> &'static str {
    match refused {
        sfu::Refused::BadSdp => "bad_sdp",
        sfu::Refused::NotFound => "not_found",
        sfu::Refused::Unavailable => Refused::NoMedia.code(),
    }
}

/// Renegotiates the caller's media. The SFU answers, and a camera that started or stopped
/// is shown to everyone as `call.state`.
async fn call_offer(hub: &Hub, me: &Me, asking: &mut Asking<'_>, sdp: Option<&str>) -> Answer {
    let Some(sdp) = sdp else {
        return Err("bad_frame");
    };
    let Some(media) = &hub.media else {
        return Err(Refused::NoMedia.code());
    };
    if !asking.moves.take() {
        return Err("slow_down");
    }
    let Some(call_id) = hub.call_of(&me.user_id) else {
        return Err("not_found");
    };
    let answer = media.offer(&call_id, sdp).await.map_err(media_code)?;
    hub.call_camera(&me.user_id, &call_id, answer.camera);
    Ok(Done::Answer(answer))
}

/// What the caller's one video slot may carry. Not being in a call with media is
/// `not_found`.
fn call_quality(hub: &Hub, me: &Me, video: Option<&str>) -> Answer {
    let video = match video {
        Some("high") => sfu::Quality::High,
        Some("low") => sfu::Quality::Low,
        Some("off") => sfu::Quality::Off,
        _ => return Err("bad_frame"),
    };
    let (Some(media), Some(call_id)) = (&hub.media, hub.call_of(&me.user_id)) else {
        return Err("not_found");
    };
    media.quality(&call_id, video);
    Ok(Done::Ok)
}

/// Mute and deafen, shown to everyone. Not being in a call is `not_found`.
fn call_state(hub: &Hub, me: &Me, muted: Option<bool>, deafened: Option<bool>) -> Answer {
    let (Some(muted), Some(deafened)) = (muted, deafened) else {
        return Err("bad_frame");
    };
    if !hub.call_state(&me.user_id, muted, deafened) {
        return Err("not_found");
    }
    Ok(Done::Ok)
}

/// Leaving with no call is not an error.
fn call_leave(hub: &Hub, me: &Me, asking: &mut Asking<'_>) -> Answer {
    if !asking.moves.take() {
        return Err("slow_down");
    }
    hub.call_leave(&me.user_id, Reason::Left);
    Ok(Done::Ok)
}

/// Owners and admins may remove someone from a call. An admin may not remove an owner.
async fn call_kick(
    hub: &Hub,
    me: &mut Me,
    room_id: Option<&str>,
    user_id: Option<&str>,
) -> Result<Answer, End> {
    let (Some(room_id), Some(user_id)) = (room_id, user_id) else {
        return Ok(Err("bad_frame"));
    };
    if let Err(code) = fresh(hub, me).await? {
        return Ok(Err(code));
    }
    if !me.manages() {
        return Ok(Err("forbidden"));
    }
    if !hub.in_call(room_id, user_id) {
        return Ok(Err("not_found"));
    }
    match db::kick_from_call(&hub.pool, &me.caller(), room_id, user_id).await {
        Ok(()) => {}
        Err(CommunityError::Forbidden) => return Ok(Err("forbidden")),
        Err(CommunityError::NotFound) => return Ok(Err("not_found")),
        Err(error) => {
            tracing::warn!(%error, "call kick failed");
            return Ok(Err("unavailable"));
        }
    }
    hub.call_kick(room_id, user_id);
    Ok(Ok(Done::Ok))
}

fn is_too_big(error: &axum::Error) -> bool {
    use std::error::Error as _;
    let mut source = error.source();
    while let Some(inner) = source {
        if let Some(tungstenite) = inner.downcast_ref::<tokio_tungstenite::tungstenite::Error>() {
            return matches!(
                tungstenite,
                tokio_tungstenite::tungstenite::Error::Capacity(_)
            );
        }
        source = inner.source();
    }
    false
}

/// A send that does not finish within the limit drops the socket. Nothing queues behind it
/// except the bounded broadcast backlog, and a socket that falls past that gets `resync`.
async fn send(hub: &Hub, socket: &mut WebSocket, text: String) -> Step {
    match tokio::time::timeout(hub.limits.send_timeout, socket.send(Message::text(text))).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(End::Gone),
        Err(_) => {
            tracing::info!("live socket too slow; dropped");
            Err(End::Gone)
        }
    }
}

enum Take {
    Allowed,
    /// The first message over the rate. The client is told once.
    Warn,
    Dropped,
    /// A burst's worth dropped in a row.
    Exceeded,
}

/// Client messages: `rate` a second with a `burst` above that.
struct Bucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    at: Instant,
    dropped: u32,
}

impl Bucket {
    fn new(rate: u32, burst: u32) -> Self {
        Self {
            rate: f64::from(rate.max(1)),
            burst: f64::from(burst.max(1)),
            tokens: f64::from(burst.max(1)),
            at: Instant::now(),
            dropped: 0,
        }
    }

    fn take(&mut self) -> Take {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        self.at = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            self.dropped = 0;
            return Take::Allowed;
        }
        self.dropped += 1;
        if f64::from(self.dropped) >= self.burst {
            Take::Exceeded
        } else if self.dropped == 1 {
            Take::Warn
        } else {
            Take::Dropped
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Bucket, Close, Take};

    #[test]
    fn a_burst_passes_then_one_warning_then_a_close() {
        let mut bucket = Bucket::new(1, 3);
        for _ in 0..3 {
            assert!(matches!(bucket.take(), Take::Allowed));
        }
        assert!(matches!(bucket.take(), Take::Warn));
        assert!(matches!(bucket.take(), Take::Dropped));
        assert!(matches!(bucket.take(), Take::Exceeded));
    }

    #[test]
    fn close_codes_match_the_design() {
        assert_eq!(Close::SessionEnded.frame().code, 4001);
        assert_eq!(Close::Removed.frame().code, 4003);
        assert_eq!(Close::Resync.frame().code, 4002);
        assert_eq!(Close::Restart.frame().code, 1012);
    }
}
