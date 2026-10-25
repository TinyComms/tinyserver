# Calls

Design for voice and video in tinyserver. Slices 1 and 2, the live socket and call occupancy, are built; the rest is not. Read it with [`README.md`](../README.md), [`deploy/README.md`](../deploy/README.md), and [`crates/sfu/src/lib.rs`](../crates/sfu/src/lib.rs).

## Recommendation

A room is a voice channel. People drop in and out; nobody rings anyone. Signaling, presence, and room changes travel over one authenticated WebSocket at `GET /v1/live`, through the cloudflared tunnel that already carries HTTPS. Media goes straight to a str0m SFU inside the tinyserver process: one thread, one UDP port, and ICE-TCP on the same port number. The compose file publishes that one port and nothing else. A host that cannot open a port (CGNAT, or an owner who wants the address hidden) turns on a relay mode later: the SFU allocates on Cloudflare Realtime TURN and never shows its own address. tinyclient adds str0m to `mediad` and keeps its existing Opus, jitter buffer, and audio device code.

| Decision | Choice |
| --- | --- |
| Realtime channel | WebSocket at `/v1/live`, bearer session, JSON frames |
| Durable fan-out | `outbox` row in the same transaction as the change, `LISTEN app_wake`, one in-process broadcast |
| Ephemeral state | Presence, occupancy, speaking, signaling. Memory only |
| Media | WebRTC through str0m 0.24 in `crates/sfu`, ICE-lite, DTLS-SRTP |
| Audio | Opus, mono, 32 kb/s, in-band FEC, DTX |
| Video | H.264 constrained baseline. Camera simulcast in two layers. One share per room |
| What each listener receives | Every speaker's audio, and one video: the share if there is one, otherwise the active speaker |
| Network | Publish one UDP port and the same TCP port. HTTP stays behind the tunnel |
| No-port mode | Cloudflare Realtime TURN, minted by tinyserver, in a later slice |
| Persistence | None for media or call state. A restart ends every call; clients rejoin |

## Constraints that shaped this

| Fact | Source | Consequence |
| --- | --- | --- |
| A cloudflared public hostname proxies HTTP(S), and TCP only as a stream over WebSocket that needs `cloudflared` on the client. UDP is not a public hostname service type. | [Cloudflare Tunnel protocols](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/protocols/) | Signaling fits the tunnel. Media does not. |
| WebSockets work on every Cloudflare plan. Idle ones are closed, and Cloudflare restarts can drop them. | [Cloudflare WebSockets](https://developers.cloudflare.com/network/websockets/) | App-level ping every 25 s. Clients must reconnect and resume. |
| Spectrum (Cloudflare's UDP proxy) needs an Enterprise plan with Spectrum as a paid add-on for custom TCP/UDP applications. | [Spectrum protocols per plan](https://developers.cloudflare.com/spectrum/protocols-per-plan/) | Not a default for a community server. |
| Cloudflare Realtime TURN: UDP 3478 and 443, TCP 3478 and 80, TLS 5349 and 443. $0.05/GB from edge to TURN client, 1,000 GB free a month. Per allocation, roughly 5–10 kpps and 50–100 Mbps. Credentials come from a REST call with a `ttl` and can be revoked. No TCP allocations (RFC 6062). Permissions to private IPs are refused. | [TURN](https://developers.cloudflare.com/realtime/turn/), [credentials](https://developers.cloudflare.com/realtime/turn/generate-credentials/), [FAQ](https://developers.cloudflare.com/realtime/turn/faq/) | Works as a hidden-origin relay with only outbound traffic from the host. One allocation per participant. |
| str0m 0.24.1 (October 2026) is sans-IO with no internal threads. Its author runs it as a production SFU. It does ICE over UDP and TCP, simulcast, VP8, VP9, H.264, AV1, Opus, TWCC bandwidth estimation, NACK, PLI, and RED. It does not do TURN itself: relay candidates are sockets the application adds. Releases still break the API every few weeks. | [str0m README](https://github.com/algesten/str0m), [changelog](https://github.com/algesten/str0m/blob/main/CHANGELOG.md), [crates.io](https://crates.io/crates/str0m) | Pin an exact version. Keep str0m types inside `crates/sfu`. SVC is not a listed feature; use simulcast. |
| tinyclient's `mediad` is a sync, single-UDP-socket, 20 ms loop with cpal audio, libopus (`unsafe-libopus`), FEC/PLC, and a jitter buffer. It speaks Discord voice: plain RTP with AEAD, not SRTP, and no ICE or DTLS. No WebRTC crate is in its `Cargo.lock`. It has no video and no echo cancellation. | tinyclient `docs/architecture.md`, `crates/mediad` | The client needs a WebRTC transport. str0m fits its "no async runtime" rule. Audio code carries over. |
| tinyclient's product rule: one video surface, either the active speaker or one share, and one hardware H.264 encode for a share. | tinyclient `docs/product/06-calls.md` | The SFU forwards one video per listener. H.264 is the video codec. |

## Realtime channel

### Why WebSocket

Signaling needs both directions on one ordered stream. SSE would need a second HTTP path for every client message. The tunnel carries WebSocket upgrades on every plan. tinyclient already ships `tungstenite` (sync) in `mediad`, so `chatd` can use the same crate without an async runtime.

### Connect

```
GET /v1/live?since=<seq>
Authorization: Bearer <session token>
Upgrade: websocket
```

| Rule | Value |
| --- | --- |
| Auth | The existing session token, in the `Authorization: Bearer` header only. tinyclient's `tungstenite` sets headers on the handshake request, so there is no query-string token to leak into logs. Checked before the upgrade: no token or a bad one is a plain `401 {"error":"unauthorized"}`. Then checked again every 60 s, at once on a `session.ended` event, and on every `call.join` and `call.kick`. An expired or deleted session closes the socket with `4001 session_ended`. Sign-out, sign-out everywhere, and a password change all emit `session.ended`, so their sockets close within one event delivery. |
| Membership | Removed member: the socket gets `member.removed` about itself, then closes with `4003 removed`. Their call ends at once with `call.left {reason: "removed"}`. |
| Query | `since=<seq>`, a non-negative integer. Anything else is `400 {"error":"invalid"}`. Other parameters are ignored. |
| Frame size | 64 KiB, for one frame and one message. SDP with simulcast fits. Bigger closes the socket with `1009 too_big`. Binary frames close it with `1003 text_only`. |
| Client message rate | 20 a second, burst 40. A message over that is dropped, and the first one dropped gets `error {code: "slow_down"}`. 40 dropped in a row closes with `4029 slow_down`. |
| Sockets per user | 3. A fourth closes the oldest with `4008 replaced`. |
| Sockets in all | 1,024. Over that, `503 {"error":"busy"}` before the upgrade. |
| Keepalive | Client sends `ping` every 25 s. Server answers `pong`. No traffic for 60 s closes with `4000 idle`. WebSocket ping frames count as traffic. |
| Slow consumer | The server never buffers without bound. A send that does not finish in 10 s drops the socket. A socket more than 1,024 events behind gets `resync` and is closed. |
| Shutdown | SIGTERM ends every call, closes every socket with `1012 restart`, refuses new ones with `503 {"error":"restarting"}`, and waits up to 5 s for them to go. No `call.left` is sent; the close is the signal. |
| Encoding | JSON text frames, one object each, `type` first. Unknown types from the server are ignored by the client. |

Close codes:

| Code | Reason | Client does |
| --- | --- | --- |
| `1009` | `too_big` | Fix the sender |
| `1011` | `unavailable` | The database did not answer. Reconnect with backoff and `since`. |
| `1012` | `restart` | Reconnect with backoff and `since` |
| `4000` | `idle` | Reconnect with `since` |
| `4001` | `session_ended` | Sign in again |
| `4002` | `resync` | Refetch rooms, members, and invites, then reconnect without `since` |
| `4003` | `removed` | Stop. The account is no longer a member. |
| `4008` | `replaced` | Another device of the same person took the place. Do not reconnect in a loop. |
| `4029` | `slow_down` | Reconnect after a pause |

Browsers cannot set the `Authorization` header on a WebSocket, so a hostile page cannot open this socket with someone's session. No `Origin` check is needed.

### Two kinds of events

| Kind | Examples | Path | Has `seq` | Survives reconnect |
| --- | --- | --- | --- | --- |
| Durable | room created, renamed, deleted; member joined, role changed, renamed, removed; invite created, accepted, revoked | `outbox` row, written in the transaction that made the change | Yes | Yes, replayed from `since` |
| Ephemeral | presence, occupancy, speaking, call signaling | Memory, sent straight to the sockets that need it | No | No. `ready` carries a fresh snapshot |

Call occupancy is ephemeral. `call.joined` and `call.left` never touch the outbox and carry no `seq`, so `since` does not replay them. Every `ready`, with or without `since`, carries the whole of `calls`; the client replaces its occupancy with it and applies `call.joined` and `call.left` after that. The socket subscribes to call frames under the same lock that takes the snapshot, so nothing between the two is lost or counted twice. Durable and ephemeral frames take separate paths, so `room.deleted` and that room's `call.left` frames can arrive in either order.

### Outbox and LISTEN/NOTIFY

The `outbox` table and the `outbox_wake` trigger are in `0001_init.sql`; `0003_live.sql` adds the rest.

1. Every room, member, invite, and session write in `crates/db` calls `app_emit(topic, payload)` in the same transaction, just before it commits: `topic` like `room.renamed`, `payload` the public shape of the change. `app_accept_invite` emits from inside the function, because the invite row is behind RLS for the person accepting. A rolled-back change never emits. The runtime role cannot insert, update, or delete outbox rows itself.
2. `app_emit` takes one transaction-scoped advisory lock before it inserts, so ids are handed out in commit order. Without it, a transaction that took id 10 could commit after one that took id 11, and a reader at 11 would never see 10. The lock is held only from the emit to the commit.
3. The commit fires `pg_notify('app_wake', topic)`.
4. One dispatcher task holds a `sqlx::postgres::PgListener` on `app_wake`. It starts at the newest id and keeps that cursor in memory. On a wake, on a listener reconnect, and every 5 s regardless, it reads `WHERE id > cursor ORDER BY id` and sends each row into a `tokio::sync::broadcast` channel of 1,024. Because of step 2 a cursor never skips a row, so `sent_at` is not used. The listener takes one connection, so the runtime pool has six.
5. Each socket task subscribes to that channel before it reads the outbox, and filters per recipient. Invite events go to owners and admins only, matching `invites_all`. A `member.role` event for the socket's own user updates that socket's cached role, so a promotion starts invite events on the same socket. `session.ended` is never sent; it makes that user's sockets re-check their session.
6. The row `id` is the event `seq`. Seqs only grow, but have gaps: rolled-back ids, and events the socket may not see. A client reconnects with `?since=<last seq>`. `ready.seq` is then `since`, and the server replays rows with `id > since` that the caller may see, then streams. Without `since`, `ready.seq` is the newest seq, and the client should fetch REST state after `ready`.
7. `resync`, then close with `4002`, when `since` is below the highest pruned seq, above the newest seq (a seq this server never issued), more than 1,000 events back, or when the socket falls more than 1,024 events behind live.
8. The existing 10-minute sweep (`app_sweep`) deletes outbox rows older than 24 h. It deletes every id up to the newest old row, so what is kept is one unbroken run, and it records the highest deleted id in `outbox_pruned`. A client may resume up to 24 h back.

One process means one dispatcher, so there is no ordering problem across nodes.

Audit rows stay out of the live channel. `GET /v1/audit` is unchanged.

### Server to client

| `type` | Fields | When |
| --- | --- | --- |
| `ready` | `seq`, `me {user_id, role}`, `online [user_id]`, `calls [{room_id, participants [{user_id}]}]` | First frame after connect. Snapshot of everything ephemeral. `online` is sorted and includes the caller. `calls` lists rooms with anyone in them, sorted by `room_id`, participants in join order. Later slices add fields to each participant. |
| `room.created`, `room.renamed` | `seq`, `room {id, name, created_by, created_at}` | Durable. The same shape as `GET /v1/rooms`. |
| `room.deleted` | `seq`, `room_id` | Durable. Ends that room's call: everyone in it gets `call.left {reason: "room_deleted"}`. |
| `member.joined`, `member.role`, `member.renamed` | `seq`, `member {user_id, display_name, role}` | Durable. No email; `GET /v1/members` has it. `member.renamed` is a display name change. |
| `member.removed` | `seq`, `user_id` | Durable |
| `invite.created`, `invite.accepted` | `seq`, `invite {id, role, created_by, expires_at, accepted_at, accepted_by}` | Durable. Owners and admins only. The same shape as `GET /v1/invites`. |
| `invite.revoked` | `seq`, `invite_id` | Durable. Owners and admins only. Invites the sweep deletes after they expire send nothing. |
| `presence` | `user_id`, `online` | First socket opens, or last socket closes after a 10 s grace. Several sockets for one person are one presence. |
| `call.joined` | `room_id`, `user_id` | Ephemeral. Someone joined a room's call. Sent to every member, including the person who joined, so the sidebar shows who is in which room. |
| `call.left` | `room_id`, `user_id`, `reason` | Ephemeral. Someone left a room's call. `reason` is below. Sent to every member. |
| `ok` | `ref` | A `call.join`, `call.leave`, or `call.kick` succeeded. Sent before the `call.joined` or `call.left` it caused. |
| `call.answer` | `ref`, `call_id`, `sdp` | From slice 3. Reply to `call.join` or `call.offer` |
| `call.slots` | `call_id`, `audio [{mid, user_id}]`, `video {mid, user_id, kind}` | From slice 3. Which receive slot carries whom. `kind` is `camera` or `share`. |
| `call.speaking` | `room_id`, `user_ids` | From slice 3. At most 4 a second, in-call sockets only |
| `resync` | none | The server closes with `4002` next. Client refetches rooms and members, then reconnects with no `since`. |
| `error` | `ref`, `code` | A client request failed. `ref` is echoed when the request had one. |
| `pong` | none | Reply to `ping` |

### Client to server

| `type` | Fields | Meaning |
| --- | --- | --- |
| `ping` | none | Keepalive |
| `call.join` | `ref`, `room_id`, `sdp` | Join the room's call. Leaves any other call first. `sdp` is the offer from slice 3; until then it is ignored and may be left out. |
| `call.leave` | `ref` | Hang up. Not being in a call is not an error. Closing the socket that joined does the same after a 10 s grace. |
| `call.kick` | `ref`, `room_id`, `user_id` | Owners and admins only. Removes someone from that room's call. |
| `call.offer` | `ref`, `sdp` | From slice 3. Renegotiate, for example to start a camera or a share |
| `call.state` | `muted`, `deafened` | From slice 3. Shown to others. The SFU also stops forwarding a muted publisher. |
| `call.quality` | `video` (`high`, `low`, `off`) | From slice 5. What the listener's one video surface can use |

`ref` is any JSON value. It is echoed in the `ok` or `error` reply. Requests without one get replies without one.

Error codes:

| Code | Meaning |
| --- | --- |
| `not_found` | `call.join`: no such room, or `room_id` is not a room id. `call.kick`: that person is not in that room's call. |
| `forbidden` | `call.kick` from a member, or from an admin against an owner |
| `full` | The room's call has 12 people |
| `server_full` | 32 people are in calls on the server |
| `slow_down` | With a `ref`: too many joins and leaves from this socket. Without one: too many messages. |
| `unavailable` | The database did not answer, or the server is shutting down. Try again. |
| `unknown_type` | A `type` this server does not take, such as `call.offer` before slice 3 |
| `bad_frame` | Not a JSON object with a `type`, or a request without a field it needs |
| `share_taken`, `bad_sdp`, `media_unavailable` | From later slices |

`call.left` reasons:

| Reason | When |
| --- | --- |
| `left` | `call.leave` |
| `joined_elsewhere` | The same person joined another room |
| `disconnected` | The socket that joined closed and none of the person's sockets joined again within 10 s |
| `room_deleted` | The room was deleted |
| `removed` | The person was removed from the community |
| `session_ended` | The socket that joined closed with `4001 session_ended` |
| `kicked` | An owner or admin sent `call.kick` |

```json
{"type":"ready","seq":41,"me":{"user_id":"9d1e…","role":"member"},"online":["5a0c…","9d1e…"],"calls":[]}
{"type":"room.renamed","seq":42,"room":{"id":"0b6f…","name":"Lobby","created_by":"5a0c…","created_at":"2026-10-24T12:00:00Z"}}
{"type":"presence","user_id":"5a0c…","online":false}
```

```json
{"type":"ready","seq":41,"me":{"user_id":"9d1e…","role":"member"},"online":["5a0c…","9d1e…"],"calls":[{"room_id":"0b6f…","participants":[{"user_id":"5a0c…"}]}]}
{"type":"call.join","ref":"7","room_id":"0b6f…"}
{"type":"ok","ref":"7"}
{"type":"call.joined","room_id":"0b6f…","user_id":"9d1e…"}
{"type":"call.kick","ref":"8","room_id":"0b6f…","user_id":"9d1e…"}
{"type":"error","ref":"8","code":"forbidden"}
{"type":"call.left","room_id":"0b6f…","user_id":"9d1e…","reason":"left"}
```

From slice 3, a join also carries media:

```json
{"type":"call.join","ref":"7","room_id":"0b6f…","sdp":"v=0\r\n…"}
{"type":"call.answer","ref":"7","call_id":"c-3f2a…","sdp":"v=0\r\n…"}
{"type":"call.slots","call_id":"c-3f2a…","audio":[{"mid":"1","user_id":"9d1e…"}],"video":{"mid":"5","user_id":"9d1e…","kind":"camera"}}
```

## Signaling and SDP

The client is always the offerer. The server never sends an offer, so there is no glare and no rollback.

| Offer contents | Why |
| --- | --- |
| One `sendonly` audio m-line | The client's microphone. Opus, `useinbandfec=1`, `usedtx=1`, RFC 6464 audio level extension. |
| One `sendonly` video m-line, inactive until the camera starts | H.264 simulcast with `rid` `h` and `l` |
| One `sendonly` video m-line, inactive until a share starts | H.264, single layer |
| `N - 1` `recvonly` audio m-lines, where `N` is the room cap | One per possible other speaker. Mapped by `call.slots`. |
| One `recvonly` video m-line | The single video surface |

Starting or stopping a camera or share is a `call.offer` that flips that m-line's direction. Nobody joining or leaving changes SDP; only `call.slots` changes.

The answer carries the SFU's ICE-lite credentials, its DTLS fingerprint, and its candidates: one UDP host candidate and one TCP passive candidate on the public address. The client does not trickle. The SFU learns the client's NAT address from its first STUN check (a peer-reflexive candidate). ICE credentials are random per join and only travel over the authenticated socket.

## SFU

### Shape

`crates/sfu` owns one OS thread. It holds the UDP socket, the ICE-TCP listener, and one `str0m::Rtc` per participant. It never touches Postgres or the session table. The API crate never sees an RTP packet.

```
 tokio runtime (api crate)                       sfu thread (std, mio)
 ┌───────────────────────────┐   Command (mpsc)  ┌────────────────────────────┐
 │ /v1/live socket tasks     │ ────────────────▶ │ rooms: room_id → Call      │
 │ dispatcher (outbox)       │                   │ Call: user_id → Rtc, slots │
 │ call registry (who/where) │ ◀──────────────── │ UDP :50000, TCP :50000     │
 └───────────────────────────┘   Event (mpsc)    └────────────────────────────┘
```

| Piece | Choice |
| --- | --- |
| Loop | `mio::Poll` over the UDP socket, the TCP listener and accepted TCP streams, and a `mio::Waker`. Timeout is the earliest `Output::Timeout` across all `Rtc`s, capped at 50 ms. Each `Rtc` is drained until it returns a timeout, as str0m requires. |
| Packet routing | Look up the source address in a map. Unknown address: only STUN is accepted, routed by ICE username, everything else dropped. `Rtc::accepts` decides. |
| ICE-TCP | RFC 4571 framing (2-byte length). A TCP stream with no valid STUN in 5 s is closed. At most 64 unauthenticated streams. |
| Media API | str0m frame mode, as in its `chat` example. Switching which speaker feeds the one video slot is a frame-level choice, and str0m rewrites sequence numbers and timestamps. RTP mode is a later optimisation. |
| Simulcast | Per listener, pick `h` or `l` from str0m's bandwidth estimate and the listener's `call.quality`. Switch only on a keyframe; ask the publisher for one with PLI. |
| Active speaker | From the RFC 6464 audio level on each publisher's audio, smoothed, with a 1.5 s hold. No decoding. |
| Share | One per room. While a share is on, every listener's video slot carries it, and cameras stop being forwarded. |
| Crypto | str0m's `aws-lc-rs` provider, its default. `rust-crypto` is the fallback if the build image struggles. |
| Version | Pin `str0m = "=0.24.1"`. Bump on purpose, with the call tests. |

### Commands and events

| API → SFU | | SFU → API | |
| --- | --- | --- | --- |
| `Join {room_id, user_id, conn_id, offer, reply}` | Returns the answer or `Full` / `BadSdp` | `Connected {room_id, user_id}` | ICE and DTLS are up |
| `Offer {user_id, offer, reply}` | Renegotiate | `Slots {room_id, user_id, slots}` | Send `call.slots` |
| `State {user_id, muted, deafened}` | | `Speaking {room_id, user_ids}` | Throttled |
| `Quality {user_id, video}` | | `Left {room_id, user_id, reason}` | ICE timeout (consent fails for 30 s), or DTLS failure |
| `Leave {user_id, reason}` | | `Load {egress_kbps, participants}` | Every 5 s, for `/health` and limits |
| `EndRoom {room_id, reason}` | Room deleted | | |
| `Shutdown` | Graceful stop | | |

Commands go through a bounded `std::sync::mpsc` channel and wake the loop with the `Waker`. Events go back through a bounded `tokio::sync::mpsc` channel with `try_send`. A full channel drops `Speaking` and `Load`, and nothing else.

### Who may join

The API decides; the SFU trusts the command. On `call.join`:

1. The socket is under its join and leave rate: 5 at once, then one more every 3 s. Over it gets `slow_down`.
2. The session is still valid. Re-read it from Postgres, as `GET /v1/me` does. An ended session closes the socket with `4001`.
3. The caller is a member. Any role may join any room. Per-room permissions are an open question below.
4. The room exists and is visible under RLS (`rooms_select`).
5. The room and the server are under their caps.
6. If the user is already in a call, on any socket, that call ends with `joined_elsewhere`. Joining the room they are already in changes nothing and sends nothing.

The room is checked again after the seat is taken. A delete that committed in between would otherwise leave a seat in a room that is gone.

### Call registry

`crates/api/src/live/call.rs` holds who is in which call. It sits under the same lock as presence, and every change is sent to every socket from inside that lock, so frames go out in the order the registry changed.

| Rule | Behaviour |
| --- | --- |
| One call per person | A seat belongs to the person, not the socket. Any of their sockets may leave it. |
| The socket that joined | Holds the seat. A later `call.join` to the same room from another of their sockets takes the seat over without a frame. |
| That socket closes | The person leaves with `disconnected` after the presence grace (10 s), unless one of their sockets joins again first. A close with `4003` or `4001` leaves at once with `removed` or `session_ended`. |
| Room deleted | The dispatcher sees `room.deleted` and ends the room's call with `room_deleted`. |
| Member removed | The dispatcher sees `member.removed` and ends their call with `removed`, even if the socket that joined had already gone. |
| Kick | `call.kick` re-reads the caller's session. A member gets `forbidden`. The target must be in that room's call. An admin may not kick an owner. The check and the `call.kick` audit row (`subject` `call`, `detail {room_id, user_id}`) are one transaction, then the person leaves with `kicked`. |
| Audit | Joins and leaves are not audited. Only `call.kick` is. |
| Restart | `Live::close` empties the registry before the sockets close with `1012`. |

Removal, room deletion, and a deleted session all reach the API as outbox events or session checks. From slice 3 the API then sends `Leave` or `EndRoom`. One user is in at most one call.

### Limits

| Limit | Default | Setting |
| --- | --- | --- |
| People in one room's call | 12. The 13th gets `full`. | `TINYSERVER_CALL_ROOM_MAX` |
| People in calls on the server | 32. The 33rd gets `server_full`. Moving between rooms does not count twice. | `TINYSERVER_CALL_SERVER_MAX` |
| Joins and leaves per socket | 5 at once, then one every 3 s. Over it gets `slow_down`. | |
| Audio from each publisher | Opus mono 32 kb/s. Up to 64 kb/s accepted. | |
| Camera | Simulcast `h` 1280×720 at about 1.2 Mb/s, `l` 640×360 at about 350 kb/s. 30 fps. | |
| Share | One per room. Up to 1920×1080, 2.5 Mb/s, 5–15 fps. | |
| Server upload budget | Unset means no budget. When set, listeners drop to `l`, then to audio only. | `TINYSERVER_MEDIA_EGRESS_KBPS` |
| Join without media | `Connected` must arrive within 15 s or the slot is freed | |

What a host uploads, roughly. With 8 people and cameras on, each listener gets 7 audio streams (about 50 kb/s each with headers) and one 1.2 Mb/s video: about 1.55 Mb/s each, 12.5 Mb/s in all. The same call with audio only is about 2.8 Mb/s. Home upload is usually the first limit, which is why the budget setting exists.

### Restart

Calls live in memory and end on restart. That is the trade for keeping RTP out of Postgres.

| Step | Behaviour |
| --- | --- |
| SIGTERM | The API empties the call registry, and from slice 3 sends `Shutdown` to the SFU. Every live socket closes with `1012 restart`, and the process exits. No `call.left` is sent. |
| Crash | Sockets drop. Nothing in Postgres needs cleaning. |
| Client | Reconnects `/v1/live` with backoff (0.5 s, 1, 2, 4, cap 10). If it was in a call and the user did not hang up, `mediad` sends a fresh `call.join` to the same room. Target: back in the call within 5 s of the server answering. |
| Durable events | Replayed from `since`. Nothing is lost. |

## Network exposure

### The problem

The tunnel is the only way in today, and the host publishes nothing. That hides the host's address and needs no port forwarding. WebRTC media needs a UDP path to the SFU, and the tunnel cannot carry one for a public client.

### Options

| Option | Port on the host | Hides the host address | Works behind CGNAT | Extra cost | Work | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| A. Publish one UDP port, ICE-TCP on the same number | 1 UDP, 1 TCP | No | No | None | Small | **Default** |
| B. SFU allocates on Cloudflare Realtime TURN, advertises only the relay | None | Yes | Yes | $0.05/GB over 1,000 GB a month | Medium: a TURN client in `crates/sfu` | **Opt-in, slice 7** |
| C. Self-hosted coturn | Still needs published ports | No | No | None | Another service | Rejected. It only adds TURN/TLS on 443, which ICE-TCP mostly covers. |
| D. Cloudflare Realtime SFU instead of str0m | None | Yes | Yes | Per GB | Rewrite of the media plane | Rejected. Media leaves the community's server. |
| E. cloudflared private network routing (WARP) | None | Yes | Yes | None | Every member runs WARP | Rejected for members |
| F. Spectrum UDP | None | Yes | Yes | Enterprise plan plus add-on | Small | Rejected for cost |

### A: the default deploy change

The server joins a third network that Docker can publish from. HTTP on 8080 stays unpublished and behind the tunnel.

```diff
   tinyserver:
     environment:
       DATABASE_URL: postgres://app_runtime:${APP_RUNTIME_PASSWORD}@postgres:5432/tinyserver
       BIND: 0.0.0.0:8080
+      TINYSERVER_MEDIA_PORT: ${TINYSERVER_MEDIA_PORT:-50000}
+      TINYSERVER_PUBLIC_IP: ${TINYSERVER_PUBLIC_IP:?set TINYSERVER_PUBLIC_IP}
+      TINYSERVER_LAN_IP: ${TINYSERVER_LAN_IP:-}
+    ports:
+      - "${TINYSERVER_MEDIA_PORT:-50000}:${TINYSERVER_MEDIA_PORT:-50000}/udp"
+      - "${TINYSERVER_MEDIA_PORT:-50000}:${TINYSERVER_MEDIA_PORT:-50000}/tcp"
     networks:
       - inside
+      - media
 ...
 networks:
   inside:
     internal: true
   edge:
+  media:
```

| Detail | Rule |
| --- | --- |
| Same port inside and out | The SFU advertises the port it binds. Keep host and container numbers equal. |
| Public address | `TINYSERVER_PUBLIC_IP` is required. The server does not guess it, because guessing needs an outbound STUN call and a wrong guess fails silently. |
| Same-LAN members | Many home routers do not hairpin. `TINYSERVER_LAN_IP` adds a second host candidate for members on the same network. |
| Router | Forward the UDP and TCP port to the host. `deploy/README.md` says this in one line. |
| Docker | Default iptables DNAT keeps the client's source address, which ICE needs. |
| IPv6 | Not in the first cut. `TINYSERVER_PUBLIC_IP6` later. |
| Restrictive client networks | ICE-TCP covers networks that block UDP. An owner whose host has 443/tcp free can map 443 to the TCP port for networks that only allow 443. |

### Security of an open media port

| Concern | Answer |
| --- | --- |
| The host address becomes visible to every member, in the SDP answer | True. The tunnel hid it before. `deploy/README.md` says so, and relay mode (B) is the answer for owners who care. |
| Strangers sending packets | Unknown sources get STUN handling only. Without the per-join ICE password, which only travels over the authenticated socket, nothing else is processed. |
| Parser exposure | str0m parses STUN, DTLS, and SRTP from the internet. Pin the version, follow its fixes (0.23.1 hardened SRTP and RTCP parsing), and fuzz the packet entry point. |
| Media privacy | DTLS-SRTP from client to SFU. The SFU sees plaintext media, as every SFU does without E2EE. Cloudflare sees signaling, and so the DTLS fingerprints, but not media in mode A. |
| Egress | Joining `media` gives the server a route out, which it did not have. In mode A the server makes no outbound connections. An owner can add a `DOCKER-USER` rule allowing only replies. |
| Floods | Per-source packet rate limit before str0m. Caps on rooms and the server. TCP stream caps above. |

### B: relay mode on Cloudflare Realtime TURN

For a host that cannot or will not open a port. Only outbound traffic leaves the host.

1. The owner creates a Realtime TURN key in the Cloudflare account that already runs the tunnel, and sets `TINYSERVER_TURN_KEY_ID` and `TINYSERVER_TURN_API_TOKEN`.
2. On each `call.join`, tinyserver calls `generate-ice-servers` with a `ttl` of 4 h, and revokes the credential when that participant leaves.
3. The SFU opens one allocation per participant over UDP 3478, falling back to TLS on 443. One per participant keeps each allocation well under the 5–10 kpps limit.
4. The SFU advertises only the relay address. The client sends its server-reflexive candidate (one STUN request to `stun.cloudflare.com`) in a `call.candidate` message, and the SFU creates a permission for that address.
5. Allocation refresh every 5 min, permission refresh every 4 min, channel binding for the data path.

str0m has no TURN client. The slice adds a small sans-IO one in `crates/sfu` (allocate, refresh, permission, channel bind) or adopts a crate after review. TURN credentials are never shown to clients in this design; only the server allocates.

Cost, budgeted as if every byte both ways is billed: a 6-person camera call is about 8 GB an hour; audio only is under 1 GB an hour. The free 1,000 GB covers about 125 camera-call hours a month.

## Client impact (tinyclient)

### Reuse

| Piece | Where today | Use for Tiny calls |
| --- | --- | --- |
| `mediad` process, stdin/stdout frames, one call per process | `crates/mediad`, `docs/architecture.md` | Unchanged |
| chatd call lifecycle: deadlines, `Joined` only on `Connected`, failure always sends `CallLeave` | `chatd` `media.rs` | Unchanged |
| `Call`, `CallState`, `Participant`, meters, devices, cues | `crates/protocol/src/call.rs` | Unchanged |
| cpal capture and playback, device hot-swap, resample to 48 kHz | `mediad` `audio.rs` | Unchanged |
| Opus encode and decode, FEC, PLC | `mediad` `opus.rs` | Switch to mono 32 kb/s VOIP and turn on DTX for Tiny |
| Jitter buffer on RTP sequence numbers | `mediad` `jitter.rs` | Fed by str0m frames or RTP |
| 20 ms loop, one UDP socket, no async runtime | `mediad` `media.rs` | Same loop, with str0m driving it |
| `tungstenite` | `mediad` | Reused in `chatd` for `/v1/live` |

### Add

| Piece | Notes |
| --- | --- |
| `chatd`: a live socket thread in the Tiny adapter | `tungstenite` over the existing TLS stack. Ping, resume with `since`, map events to `Change::Occupants` and `Change::Presence`. Set `call: Native` on Tiny rooms. |
| `chatd`: rooms in the Tiny slice | The adapter has no rooms today (`crates/protocol/src/tiny.rs` says so). Rooms become call targets. |
| `protocol`: a Tiny join | New optional variant or fields, because `VoiceJoin` is Discord-shaped and the protocol only takes optional additions. It carries the SDP offer out from `mediad` and the answer and `call.slots` back in, relayed by `chatd`. `mediad` still never talks to the network for signaling. |
| `mediad`: str0m transport | Replaces `gateway.rs`, `session.rs`, and `rtp.rs` for Tiny. Discord keeps its own path. Use str0m's `apple-crypto` on macOS and `rust-crypto` elsewhere, to avoid OpenSSL and keep to one TLS stack. |
| `mediad`: echo cancellation and noise suppression | Missing today, and needed for open speakers on any call. OS voice processing (macOS VoiceProcessingIO, Windows communications mode) or `webrtc-audio-processing` bindings. |
| `mediad`: RFC 6464 audio level on send | The SFU picks the active speaker from it |
| Video, later | Camera capture, H.264 encode in two sizes, decode, and one render surface. Share uses the one hardware H.264 encode the product doc already plans. |

### Change

| Item | Change |
| --- | --- |
| Tiny adapter header comment | No longer "no calls, or media". |
| mediad size | str0m and its crypto add a few MB, well under the "tens of MB" a full WebRTC stack would. Measure in slice 3. |
| Reconnect | A Tiny call survives a server restart by rejoining. `Reconnecting` already exists in `CallState`. |

## Open questions for the owner

| Question | Recommended default |
| --- | --- |
| Text messages in rooms? tinyclient's Tiny slice has "no conversations". | No, not in this milestone. Rooms are voice channels. The outbox and live socket would carry messages later without redesign. |
| Ringing and 1:1 calls? | No. Drop-in rooms only. A two-person room covers a 1:1. |
| Screen share? | Yes, in slice 6. One share per room, H.264, replaces the speaker video while on. |
| Recording? | None. The SFU never writes media to disk. Revisit only with a per-call consent prompt. |
| E2EE? | Off for now. DTLS-SRTP to a server the community runs. Keep the SFU from reading payloads beyond what simulcast and keyframes need, so SFrame, or DAVE-style MLS (tinyclient already ships `davey`), can come later. |
| Per-room permissions (who may join, speak, share)? | Every member may join, speak, and share in every room. Owners and admins may end a share or remove someone from a call. |
| Room size? | 12 per room, 32 per server. Raise after load testing. |
| Port or relay? | Publish one port (A). Offer relay mode (B) for CGNAT and hidden-origin hosts. |
| Show who is in a call to members not in it? | Yes, as in Discord. It is what makes drop-in rooms work. |
| Audit call joins? | No. Presence is not an admin action. Audit only "removed from call" and "share ended" by an admin. |
| Guests without an account? | No. Invites already make accounts. |

## Slices

Each slice is one PR, merges on its own, and leaves the server working.

| # | Slice | Scope | Acceptance check | Size |
| --- | --- | --- | --- | --- |
| 1 | **Live socket and presence** (built) | `GET /v1/live` with bearer auth, ping, limits, `ready`, `presence`. Outbox writes in every room, member, and invite change. Dispatcher on `LISTEN app_wake`, replay with `since`, `resync`, 24 h sweep. No media. | Integration test: two sessions connect; A renames a room; B gets `room.renamed` with a `seq`. B reconnects with an old `since` and gets the missed events. A removed member's socket closes with `4003`. A rolled-back write emits nothing. | M, ~800 lines |
| 2 | **Call occupancy without media** (built) | `call.join`, `call.leave`, and `call.kick`, the call registry, authorization, caps, a join and leave rate, `joined_elsewhere`, `call.joined` and `call.left` to every member, `ready.calls`. `call.join` ignores `sdp`. `call.state` moves to slice 3, with the media it describes. | Integration tests: a join reaches everyone and later `ready` frames; joining elsewhere leaves the first room; a second socket is one seat; a dropped socket leaves after the grace; caps return `full` and `server_full`; a deleted room empties; a removed member leaves; kick works for an admin, fails against an owner and for a member, and is audited. | S, ~400 lines |
| 3 | **SFU audio, UDP** | `crates/sfu` thread with mio, str0m pinned, ICE-lite, DTLS-SRTP, Opus forwarding, slots, active speaker, consent timeout, graceful shutdown. Compose and `deploy/README.md` gain the media port. `/health` reports `media`. | A headless test client (str0m, in `crates/sfu/tests`) joins with two peers on loopback; each receives the other's Opus frames within 2 s; killing one peer frees its slot within 35 s. Manual: two machines on different networks talk. | L, ~1,500 lines |
| 4 | **ICE-TCP and hardening** | TCP passive candidate on the same port, RFC 4571 framing, stream caps, per-source rate limit, a fuzz target for the packet entry point, `TINYSERVER_LAN_IP`. | Test client with UDP blocked connects over TCP. Fuzz runs 10 minutes without a panic. A flood from an unknown source does not raise CPU above a set bound. | M, ~600 lines |
| 5 | **Camera video** | H.264 simulcast receive, per-listener layer choice from bandwidth estimate and `call.quality`, speaker-switched video slot with PLI, `TINYSERVER_MEDIA_EGRESS_KBPS`. | Test client publishes two layers; a listener capped at 500 kb/s gets `l`; switching speaker delivers the new speaker's keyframe within 1 s. | L, ~1,000 lines |
| 6 | **Screen share** | Share m-line, one share per room, `share_taken`, share wins the video slot, admin ends a share. | Second share returns `share_taken`. While a share runs every listener's video slot carries it; stopping it brings the speaker back. | S, ~400 lines |
| 7 | **Relay mode** | Cloudflare Realtime TURN credentials, sans-IO TURN client in `crates/sfu`, relay-only candidates, `call.candidate`, revoke on leave. Compose variant without `ports:`. | With no published ports and only outbound traffic allowed, two clients on different networks talk. The SDP answer contains no host address. Credentials are revoked when a participant leaves. | L, ~1,200 lines |

The tinyclient side runs alongside: live socket and rooms after slice 1, occupancy after 2, audio calls with str0m in `mediad` after 3, video after 5. Slice 3 is the point where the two repos meet; its headless str0m test client becomes the reference for `mediad`.
