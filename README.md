# tinyserver

Self-hosted voice and video for [tinyclient](https://github.com/itz4blitz/tinyclient). One server, one community. It is written in Rust. [MIT licensed](LICENSE).

The project is early. An owner can sign in, make rooms, and invite people, and every signed-in device sees changes live. Members can join a room's call, everyone sees who is in it, and the people in it hear each other, see the active speaker's camera, and see a screen when someone shares one, through the server's SFU.

## What works today

| | |
| --- | --- |
| **Owner** | `bootstrap` creates the first owner from the environment. It refuses to run twice. |
| **Sign-in** | `POST /v1/session` returns a token. `GET /v1/me` reads it. `DELETE /v1/session` ends it. `DELETE /v1/sessions` ends every session you have. |
| **Account** | `PATCH /v1/me` changes your display name. `POST /v1/me/password` changes your password and signs out your other sessions. |
| **Rooms** | A member lists rooms. An owner or admin adds, renames, and removes them. |
| **People** | A member lists people. An owner or admin changes a role or removes someone. A removed person is signed out everywhere. The last owner stays. An admin cannot change an owner. |
| **Invites** | An owner or admin creates an invite for an admin or a member. The token is returned once and lasts 7 days. `DELETE /v1/invites/{id}` revokes one nobody has accepted. `POST /v1/invites/accept` creates the account, or brings an existing one back, and signs in. |
| **Audit** | An owner or admin reads `GET /v1/audit`. |
| **Live** | `GET /v1/live` is a WebSocket with the same bearer token. It sends `ready` with who is online, then room, member, and invite changes in order with a `seq`, and presence. Reconnect with `?since=<seq>` to get what was missed, up to 24 hours back. Invite events go to owners and admins only. Frames and limits are in [`docs/calls.md`](docs/calls.md#realtime-channel). |
| **Calls** | Over the live socket, a member sends `call.join` for a room and `call.leave` to hang up. Everyone sees `call.joined` and `call.left`, and `ready.calls` lists who is in each call. One call per person. 12 per room and 32 per server, set with `TINYSERVER_CALL_ROOM_MAX` and `TINYSERVER_CALL_SERVER_MAX`. An owner or admin sends `call.kick` to remove someone, or `call.share_end` to end a screen share, and both are audited; an admin cannot do either to an owner. Calls live in memory and a restart ends them. |
| **Audio** | `call.join` carries a WebRTC offer and gets `call.answer`. Audio goes over one UDP port, or ICE-TCP on the same number for networks that block UDP, to a str0m SFU in the server, which forwards each person's Opus to everyone else in the room. `call.slots` says which receive slot carries whom, `call.speaking` who is talking, and `call.state` who is muted or deafened. Media runs when `TINYSERVER_PUBLIC_IP` is set, on `TINYSERVER_MEDIA_PORT` (50000); `TINYSERVER_LAN_IP` adds the host's home-network address for members on it. Without a public address calls have no audio and an offer gets `media_unavailable`. Members see the host's address. Setup is in [`deploy/README.md`](deploy/README.md#calls-and-the-media-port). |
| **Video** | A camera starts and stops with `call.offer`, and everyone sees it in `call.state` and `ready`. Each listener gets one video, the active speaker's camera, or the previous speaker's when they are the one talking; `call.slots` `video` says whose. Cameras send H.264 in two simulcast layers, and the SFU picks one per listener from its bandwidth estimate and `call.quality`. A screen share starts and stops with `call.offer` too, one per room; a second sharer gets `share_taken`. While it runs it replaces the camera in every other listener's video, as `kind` `share`, and `call.state` and `ready` say who is `sharing`. `TINYSERVER_MEDIA_EGRESS_KBPS` sets an upload budget: shares are planned first, then cameras drop to the low layer, then to audio only. |
| **Health** | `GET /health`, with `media` `off`, `up`, or `down`, and `transports`, the media transports up: `udp`, `tcp`, and `lan` |

## Run

From a checkout:

```sh
cp .env.example .env
docker compose up -d
cargo run -- migrate
cargo run -- bootstrap
cargo run -- serve
```

`.env.example` is the local default. Copy it to `.env` and keep that file to yourself. `bootstrap` reads `TINYSERVER_OWNER_EMAIL`, `TINYSERVER_OWNER_NAME`, and `TINYSERVER_OWNER_PASSWORD`. The password stays in the environment.

`GET /health` is ready when `schema` is `ready` and `db_role` is `app_runtime`. The server listens on `127.0.0.1:8080` unless `BIND` says otherwise.

## Test

`cargo test` runs the unit tests and the SFU tests in [`crates/sfu/tests`](crates/sfu/tests), which send audio and H.264 video between headless clients on `127.0.0.1`. The integration tests in [`crates/api/tests`](crates/api/tests) need Postgres and pass without running when it is not configured:

```sh
export TEST_DATABASE_URL_MIGRATE=postgres://app_owner:app_owner@127.0.0.1:54329/tinyserver?sslmode=disable
export TEST_DATABASE_URL=postgres://app_runtime:app_runtime@127.0.0.1:54329/tinyserver?sslmode=disable
cargo test
```

Each test creates its own database as `app_owner`, migrates it, serves it as `app_runtime`, and drops it. Only the host, roles, and passwords in those URLs are used. CI runs the same tests against `postgres:17-alpine`.

## Repository

| Path | What it is |
| --- | --- |
| [`crates/db`](crates/db) | Migrations, the first owner, sessions, accounts, rooms, invites, and the outbox |
| [`crates/api`](crates/api) | Health, sign-in, your account, rooms, people, invites, the audit log, the live socket, and who is in each call |
| [`crates/server`](crates/server) | `migrate`, `bootstrap`, `serve` |
| [`crates/sfu`](crates/sfu) | The SFU: one thread, one UDP socket and an ICE-TCP listener on the same port, str0m. Also the headless test client that tinyclient's `mediad` follows, and its canned H.264 clips in [`fixtures`](crates/sfu/fixtures) |
| [`fuzz`](fuzz) | cargo-fuzz targets for live-socket frames, SDP offers, ICE-TCP framing, packets into str0m, and video routing. Outside the workspace; `cargo +nightly fuzz run sdp_offer` |
