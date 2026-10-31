# tinyserver

Self-hosted voice and video for [tinyclient](https://github.com/itz4blitz/tinyclient). One server, one community. It is written in Rust. [MIT licensed](LICENSE).

The project is early. People sign in through an OpenID Connect provider. An owner names the server, makes roles with permissions, rooms in categories, and invites, and every signed-in device sees changes live. Members can join a room's call, everyone sees who is in it, and the people in it hear each other, see the active speaker's camera, and see a screen when someone shares one, through the server's SFU.

## What works today

| | |
| --- | --- |
| **Owner** | While there is no owner, `bootstrap` prints a single-use owner invite good for 24 hours; whoever signs in with it is the owner. While that invite still works a later `bootstrap` keeps it and prints nothing new. With an owner it does nothing. `bootstrap --owner-invite` makes a new one anyway. |
| **Sign-in** | No passwords. tinyclient opens the browser at an OpenID Connect provider, Pocket ID with passkeys by default, and gets a one-time code back on a loopback redirect; see [Sign-in](#sign-in). With Pocket ID, an invite also makes the person's account there. `GET /v1/me` reads the session. `DELETE /v1/session` ends it. `DELETE /v1/sessions` ends every session you have. |
| **Account** | `PATCH /v1/me` changes your display name. Email comes from the provider and may be `null`. |
| **Server** | `GET /v1/server` has the name, description, welcome text, icon, default and AFK rooms. `manage_server` changes them and uploads the icon. `GET /v1/capabilities` lists what this server supports. |
| **Roles** | Roles carry permission bits and a position; owners are a flag above them. Each room can allow or deny bits per role. You act only on people and roles below your rank. Details in [`docs/server.md`](docs/server.md). |
| **Rooms** | A member lists the rooms they may see, in categories, with their own permissions in each. `manage_channels` adds, edits, orders, and removes rooms and categories; a room has a topic, a user limit, a bitrate, push-to-talk only, and video on or off. |
| **People** | A member lists people, with their roles and when they were last seen. With the permission, someone gives roles, kicks with a reason, times out for up to 28 days, or bans; a ban holds every sign-in identity of that person, so no invite or group lets them back. A removed or banned person is signed out everywhere. The last owner stays. |
| **Bots** | Someone with `manage_server` calls `POST /v1/bots` with `{name, scopes}` or `{name, permissions}` and is shown the token once. `permissions` `1` is `rooms.read` and `512` is `rooms.write`. When both are sent, the integer wins. The bot uses `Authorization: Bot <token>`. `rooms.read` lists rooms and receives room and call events on `GET /v1/live`. `rooms.write` adds, renames, and removes rooms. `members.read` lists people and receives member and presence events. A bot with neither, or only `rooms.write`, stays connected and receives no room or member payload. It cannot join or change a call. `GET /v1/bots` lists them. `DELETE /v1/bots/{id}` revokes the token. A bot is not a member. |
| **Messages** | Someone who can manage channels creates a text channel. A member who can view it reads it, and one who can speak posts, reacts, and uploads. `POST /v1/directs` opens a direct conversation with another member. The author can edit or soft-delete a message. A `client_id` makes a retry return the same message. Uploads go to `POST /v1/media`; the response is not 201 until the file is clean, and nobody can fetch an attachment until then. Weaponized types, liar files, and archives (unless `manage_server` turns `allow_archives` on) are refused with 415 `unsupported_media`. PNG, JPEG, WebP, and GIF are re-encoded before storage. Images and GIFs default to 8 MiB and other files to 25 MiB; `manage_server` may raise either on `PATCH /v1/server`, up to 100 MiB. A scanner that is down or times out is 503 `unavailable` and no 201. Signed download URLs, status codes, caps, and compose settings are in [`docs/server.md`](docs/server.md#messages-and-attachments). Reads move a cursor forward. Channel events go to every live socket. Direct messages, typing, and direct read cursors go only to the two people. |
| **Invites** | `create_invites` makes an invite with a label, roles to give, a number of uses, and an expiry: 7 days and one use unless asked otherwise. The token is returned once. `DELETE /v1/invites/{id}` revokes one. tinyclient sends the token with a sign-in, which makes the account, or brings an existing one back. |
| **Audit** | `view_audit_log` reads `GET /v1/audit`, with names and reasons, paged with `before`, filtered by actor and action. |
| **Live** | `GET /v1/live` is a WebSocket with the same bearer token. It sends `ready` with who is online, then room, member, invite, and message changes in order with a `seq`, and presence. Reconnect with `?since=<seq>` to get what was missed, up to 24 hours back. Invite and ban events go only to people who may see them. Direct messages go only to the two people. Frames and limits are in [`docs/calls.md`](docs/calls.md#realtime-channel). |
| **Calls** | Over the live socket, a member sends `call.join` for a room and `call.leave` to hang up. Everyone sees `call.joined` and `call.left`, and `ready.calls` lists who is in each call. One call per person. 12 per room and 32 per server, set with `TINYSERVER_CALL_ROOM_MAX` and `TINYSERVER_CALL_SERVER_MAX`. A room's `user_limit` lowers its cap. Room permissions decide who may join (`connect`) and speak (`speak`; without it you join suppressed). With the permission and a rank above them, someone sends `call.kick`, `call.share_end`, `call.moderate` to server mute or deafen, or `call.move` to move them to another room; all are audited. Timeouts and bans end calls. Calls live in memory and a restart ends them. |
| **Audio** | `call.join` carries a WebRTC offer and gets `call.answer`. Audio goes over one UDP port, or ICE-TCP on the same number for networks that block UDP, to a str0m SFU in the server, which forwards each person's Opus to everyone else in the room. `call.slots` says which receive slot carries whom, `call.speaking` who is talking, and `call.state` who is muted or deafened. Media runs when `TINYSERVER_PUBLIC_IP` is set, on `TINYSERVER_MEDIA_PORT` (50000); `TINYSERVER_LAN_IP` adds the host's home-network address for members on it. Without a public address calls have no audio and an offer gets `media_unavailable`. Members see the host's address. Setup is in [`deploy/README.md`](deploy/README.md#calls-and-the-media-port). |
| **End-to-end encryption** | When every app in a call can, the apps make one MLS group (Discord's DAVE design) and encrypt each Opus frame; the server relays the group's messages and forwards audio it cannot read. One app that cannot turns the call to transport only, and the others say who. A room's `e2ee_required` refuses apps that cannot. The capability is `e2ee_calls`. Frames, the threat model, and what the server still sees are in [`docs/calls.md`](docs/calls.md#end-to-end-encryption). |
| **Video** | A camera starts and stops with `call.offer`, and everyone sees it in `call.state` and `ready`. Each listener gets one video, the active speaker's camera, or the previous speaker's when they are the one talking; `call.slots` `video` says whose. Cameras send H.264 in two simulcast layers, and the SFU picks one per listener from its bandwidth estimate and `call.quality`. A screen share starts and stops with `call.offer` too, one per room; a second sharer gets `share_taken`. While it runs it replaces the camera in every other listener's video, as `kind` `share`, and `call.state` and `ready` say who is `sharing`. `TINYSERVER_MEDIA_EGRESS_KBPS` sets an upload budget: shares are planned first, then cameras drop to the low layer, then to audio only. |
| **Health** | `GET /health`, with `media` `off`, `up`, or `down`, and `transports`, the media transports up: `udp`, `tcp`, and `lan` |

## Sign-in

tinyserver is a confidential client of one or more OpenID Connect providers. A person is the issuer and subject in a verified ID token; email never links accounts.

| Route | |
| --- | --- |
| `GET /v1/auth/config` | `{"methods":["oidc"],"provider_name":"Pocket ID","providers":[{"id","name"}]}` |
| `POST /v1/auth/start` | `{redirect_uri, code_challenge, code_challenge_method, state, invite?, provider?}`. The redirect must be `http://127.0.0.1:<port>/callback` or `http://[::1]:<port>/callback`, the method `S256`. Returns `{authorize_url}`; anything wrong is `400 {"error":"bad_request"}`. The pending sign-in lasts 10 minutes. With an invite and a provider that makes accounts, `authorize_url` is the join page below instead of the provider. |
| `GET /v1/auth/join?state=` | A page: "I'm new here" or "I already have an account". The second is a link to the provider's sign-in, the same one `start` would have returned. |
| `POST /v1/auth/join` | The "I'm new here" form. While the invite could still be accepted, the server asks Pocket ID for one sign-up token (single use, 15 minutes) and shows two steps: make the account and passkey at Pocket ID in a new tab, then continue to sign-in here. Once per sign-in; a second try shows the way on and no second token. An unknown, expired, or used-up invite ends the sign-in with `error=not_member` and makes nothing. 3 tries a minute per address. |
| `GET /v1/auth/callback` | Where the provider sends the browser. The server makes the code exchange with its secret and its own PKCE verifier, checks the ID token, and applies the invite or checks membership. Then `302` to tinyclient with `code` and `state`, or `error` of `not_member`, `denied`, or `failed`. An expired or used state gets a small page and no redirect. |
| `POST /v1/auth/token` | `{code, code_verifier}`. The one-time code lasts 60 seconds and works once. Returns `{token, user_id, email, display_name, role}`, else `400 {"error":"invalid_grant"}`. |
| `POST /v1/auth/backchannel-logout` | OpenID Connect Back-Channel Logout 1.0, for providers that send it. |

`start` and `token` allow 5 tries a minute per address. Groups from the provider can let people join or give them the admin role when the owner sets that up; never owner. A banned person is sent back with `error=banned`. The pages the browser sees here load nothing and run no script; their one stylesheet is allowed by its hash. Configuration is in [`deploy/README.md`](deploy/README.md#pocket-id) and [`deploy/README.md`](deploy/README.md#other-providers).

## Run

From a checkout:

```sh
cp .env.example .env
docker compose up -d
cargo run -- migrate
cargo run -- bootstrap
cargo run -- serve
```

`.env.example` is the local default. Copy it to `.env` and keep that file to yourself. `serve` needs a sign-in provider: set `TINYSERVER_PUBLIC_URL`, `TINYSERVER_OIDC_ISSUER`, `TINYSERVER_OIDC_CLIENT_ID`, and `TINYSERVER_OIDC_CLIENT_SECRET_FILE`. It stops at start when discovery cannot be read or names another issuer. `bootstrap` prints the owner invite.

`GET /health` is ready when `schema` is `ready` and `db_role` is `app_runtime`. The server listens on `127.0.0.1:8080` unless `BIND` says otherwise.

## Test

`cargo test` runs the unit tests and the SFU tests in [`crates/sfu/tests`](crates/sfu/tests), which send audio and H.264 video between headless clients on `127.0.0.1`. The integration tests in [`crates/api/tests`](crates/api/tests) need Postgres and pass without running when it is not configured:

```sh
export TEST_DATABASE_URL_MIGRATE=postgres://app_owner:app_owner@127.0.0.1:54329/tinyserver?sslmode=disable
export TEST_DATABASE_URL=postgres://app_runtime:app_runtime@127.0.0.1:54329/tinyserver?sslmode=disable
cargo test
```

Each test creates its own database as `app_owner`, migrates it, serves it as `app_runtime`, and drops it. Sign-in tests run a small OpenID Connect provider in the test process, with test-only keys in [`crates/api/tests/fixtures`](crates/api/tests/fixtures). Only the host, roles, and passwords in those URLs are used. CI runs the same tests against `postgres:17-alpine`.

## Repository

| Path | What it is |
| --- | --- |
| [`crates/db`](crates/db) | Migrations, the owner invite, sign-in, sessions, accounts, server settings, roles and permissions, rooms, categories, invites, bans, and the outbox |
| [`crates/api`](crates/api) | Health, sign-in through OpenID Connect, your account, server settings, roles, rooms, people, invites, bans, the audit log, the live socket, and who is in each call |
| [`crates/server`](crates/server) | `migrate`, `bootstrap`, `serve`, and `identities` and `relink-identity` for a provider whose subjects changed |
| [`crates/sfu`](crates/sfu) | The SFU: one thread, one UDP socket and an ICE-TCP listener on the same port, str0m. Also the headless test client that tinyclient's `mediad` follows, and its canned H.264 clips in [`fixtures`](crates/sfu/fixtures) |
| [`fuzz`](fuzz) | cargo-fuzz targets for live-socket frames, SDP offers, ICE-TCP framing, packets into str0m, and video routing. Outside the workspace; `cargo +nightly fuzz run sdp_offer` |

## Application bots

Create an installation with a member session and `manage_server` permission:

```http
POST /v1/bots
Authorization: Bearer <member-session>
Content-Type: application/json

{"name":"Herald","scopes":["rooms.read","members.read"]}
```

The response contains the token once. Store it privately, then use `Authorization: Bot <token>`. `GET /v1/bots` lists installations without tokens; `DELETE /v1/bots/{id}` revokes one. Existing sockets notice revocation at their next credential recheck.

`rooms.read` permits room listing and public room/call occupancy events. `members.read` permits member listing and presence/member events. `rooms.write` permits room creation, rename, settings changes, and deletion. A `permissions` integer may replace the scopes array: `1` grants `rooms.read`, `512` grants `rooms.write`; members.read must be requested through scopes. If both forms are present, permissions takes precedence.

Bots are not members, do not appear online as people, and cannot join/control calls, receive call keys, read/post messages, create invites, or manage roles. The desktop bot API helper is available to Rust callers; this release does not add a bot management screen.
