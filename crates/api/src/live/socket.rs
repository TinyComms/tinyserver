//! One live socket: `ready`, the replay, then events and presence until something closes it.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use db::SessionError;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::broadcast::error::RecvError;
use tokio::time::{Instant, MissedTickBehavior};

use super::frame::{Audience, Event, Me as MeFrame, Out};
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
}

#[derive(Deserialize)]
struct Incoming {
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "ref")]
    reference: Option<Value>,
}

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
    if let End::Close(close) = end {
        tracing::info!(user_id = %me.user_id, conn, ?close, "live socket closed");
        let frame = Message::Close(Some(close.frame()));
        let _ = tokio::time::timeout(Duration::from_secs(1), socket.send(frame)).await;
    } else {
        tracing::info!(user_id = %me.user_id, conn, "live socket gone");
    }
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
        mut kicked,
        mut presence,
        online,
        ..
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
        calls: [],
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
            message = socket.recv() => {
                seen = Instant::now();
                receive(hub, socket, &mut bucket, message).await
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

async fn receive(
    hub: &Hub,
    socket: &mut WebSocket,
    bucket: &mut Bucket,
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
    match bucket.take() {
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
    let reply = match serde_json::from_str::<Incoming>(text.as_str()) {
        Ok(incoming) if incoming.kind == "ping" => Out::Pong.text(),
        Ok(incoming) => Out::Error {
            reference: incoming.reference.as_ref(),
            code: "unknown_type",
        }
        .text(),
        Err(_) => Out::Error {
            reference: None,
            code: "bad_frame",
        }
        .text(),
    };
    send(hub, socket, reply).await
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
