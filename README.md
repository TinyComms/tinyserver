# tinyserver

Self-hosted community server for [tinyclient](https://github.com/TinyComms/tinyclient): voice, video, and text on one deployment. The site is [tinyclient.io](https://tinyclient.io). The server is written in Rust and is [MIT licensed](LICENSE).

One deployment is one community. People sign in through an OpenID Connect provider. Pocket ID, with passkeys, is the provider a deployment ships with. An owner names the community, makes roles with permissions, voice rooms and text channels in categories, and invites. Signed-in devices see changes live. In a room's call, people hear each other through the server's SFU, and each listener sees one video: a screen share while someone is sharing, otherwise the active speaker's camera. Members also post in text channels and in direct conversations. Someone who manages the server can add an application bot with a few scopes.

The project is early.

## What works today

| | |
| --- | --- |
| **Owner** | While there is no owner, `bootstrap` prints a single-use owner invite good for 24 hours. Whoever signs in with it is the owner. While that invite still works, a later `bootstrap` keeps it, does not print the token again, and prints the expiry plus how to replace it. With an owner, `bootstrap` does nothing. `bootstrap --owner-invite` makes a new one anyway. With `TINYSERVER_PUBLIC_URL` set, a new invite is also printed as a `https://tinyclient.io/invite#` link. |
| **Sign-in** | No passwords. tinyclient opens the browser at an OpenID Connect provider, Pocket ID with passkeys by default, and gets a one-time code back on a loopback redirect. With Pocket ID, an invite can also make the person's account there. `GET /v1/me` reads the session. `DELETE /v1/session` ends it. `DELETE /v1/sessions` ends every session you have. |
| **Account** | `PATCH /v1/me` changes your display name. Email comes from the provider and may be null. `PUT /v1/me/avatar` sets your picture from a PNG, JPEG, or WebP of at most 256 KiB, and `DELETE /v1/me/avatar` clears it. `GET /v1/users/{user_id}/avatar` fetches one. Member lists carry the picture's hash. |
| **Server** | `GET /v1/server` is this community: name, description, welcome text, icon, default room, and AFK room. The default name is Tiny server. `manage_server` changes them and uploads the icon. `GET /v1/capabilities` returns the server version and a feature list: `server`, `roles`, `categories`, `bans`, `timeouts`, `invite_options`, `audit_query`, `voice_moderation`, `e2ee_calls`, `upload_limits`, `file_scan`. |
| **Roles** | Roles carry permission bits and a position. Owners are a flag above them. Each voice room and each text channel can allow or deny bits per role. You act only on people and roles below your rank. Details are in [`docs/server.md`](docs/server.md). |
| **Rooms** | A room is a voice channel. A member lists the rooms they may see, in categories, with their own permissions in each. `manage_channels` adds, edits, orders, and removes rooms and categories. A room has a topic, a user limit, a bitrate, push-to-talk only, video on or off, and whether end-to-end encryption is required. |
| **Messages** | `manage_channels` creates a text channel, which can sit in a category. A member who can view it reads it. A member who can speak posts, reacts, and uploads. `POST /v1/directs` opens a direct conversation with another member. The author can edit or soft-delete a message. A `client_id` makes a retry return the same message. Uploads go to `POST /v1/media` as an image, GIF, video, or other file. The response is 201 only after the file scans clean, and nobody can fetch an attachment until then. Weaponized types, liar files, and archives (unless `manage_server` turns `allow_archives` on) are refused with 415 `unsupported_media`. PNG, JPEG, WebP, and GIF are re-encoded before storage. Images and GIFs default to 8 MiB and other files to 25 MiB. `manage_server` may raise either on `PATCH /v1/server`, up to 100 MiB. A scanner that is down or times out is 503 `unavailable` and no 201. Reads move a cursor forward. Channel events go to every live socket that may see them. Direct messages, typing, and direct read cursors go only to the two people. |
| **People** | A member lists people, with their roles, picture hash, and when they were last seen. With the permission, someone gives roles, kicks with a reason, times out for up to 28 days, or bans. A ban holds every sign-in identity of that person. A removed or banned person is signed out everywhere. The last owner stays. |
| **Bots** | Someone with `manage_server` calls `POST /v1/bots` with `{name, scopes}` or `{name, permissions}` and is shown the token once. The bot sends `Authorization: Bot <token>`. `permissions` `1` is `rooms.read` and `512` is `rooms.write`. When `permissions` is sent, it replaces `scopes`, so `members.read` is kept only when the integer is left out. `rooms.read` lists rooms and, on `GET /v1/live`, receives room events plus `call.joined`, `call.left`, and `call.state`. `rooms.write` creates a room, changes its settings, and deletes it. `members.read` lists people and receives member and presence events. A bot with neither, or only `rooms.write`, stays connected and receives no room or member payload. It cannot join or change a call, and it cannot read or post messages. `GET /v1/bots` lists them. `DELETE /v1/bots/{id}` revokes the token. An open socket notices at its next credential check, every 60 seconds. A bot is not a member and does not show up as a person online. |
| **Invites** | `create_invites` makes an invite with a label, roles to give, a number of uses, and an expiry. Left unspecified, that is 7 days and one use. The token is returned once. `DELETE /v1/invites/{id}` revokes one. tinyclient sends the token with a sign-in, which makes the account, or brings an existing one back. |
| **Audit** | `view_audit_log` reads `GET /v1/audit`, with names and reasons, paged with `before`, filtered by actor and action. |
| **Live** | `GET /v1/live` is a WebSocket with the same bearer token. It sends `ready` with who is online, then room, member, invite, and message changes in order with a `seq`, and presence. Reconnect with `?since=<seq>` to get what was missed, up to 24 hours back. Invite and ban events go only to people who may see them. Direct messages go only to the two people. Frames and limits are in [`docs/calls.md`](docs/calls.md#realtime-channel). |
| **Calls** | Over the live socket, a member sends `call.join` for a room and `call.leave` to hang up. Everyone sees `call.joined` and `call.left`, and `ready.calls` lists who is in each call. One call per person. 12 per room and 32 per server, set with `TINYSERVER_CALL_ROOM_MAX` and `TINYSERVER_CALL_SERVER_MAX`. A room's `user_limit` lowers its cap. Room permissions decide who may join (`connect`) and speak (`speak`; without it you join suppressed and your audio is not forwarded). With the permission and a rank above them, someone sends `call.kick`, `call.share_end`, `call.moderate` to server mute or deafen, or `call.move` to move them to another room; all are audited. Timeouts and bans end calls. Calls live in memory and a restart ends them. |
| **Audio** | `call.join` carries a WebRTC offer and gets `call.answer`. Media goes over one UDP port, or ICE-TCP on the same number for networks that block UDP, to a str0m SFU in the server, which forwards each other person's Opus. `call.slots` says which receive slot carries whom, `call.speaking` who is talking, and `call.state` who is muted or deafened. Media runs when `TINYSERVER_PUBLIC_IP` is an IPv4 address, on `TINYSERVER_MEDIA_PORT` (50000); `TINYSERVER_LAN_IP` adds the host's home-network address for members on it. Without that address an offer gets `media_unavailable` and the call has no media. Members see the host's address. Setup is in [`deploy/README.md`](deploy/README.md#calls-and-the-media-port). |
| **End-to-end encryption** | DTLS ends at the server. When every app in a call can, the apps also make one MLS group (Discord's DAVE design, version 1) and seal each Opus frame and the H.264 picture. The picture's one-byte NAL header stays clear. The server relays the group's messages and does not hold the group secret, so it cannot read those frames. One app that cannot turns the call to transport only, and the others say who. A room's `e2ee_required` refuses a media join from an app that cannot. The capability is `e2ee_calls`. Frames, the threat model, and what the server still sees are in [`docs/calls.md`](docs/calls.md#end-to-end-encryption). |
| **Video** | A camera or a screen share starts and stops with `call.offer`, and everyone sees it in `call.state` and `ready`. One share per room; a second sharer gets `share_taken`. Each listener gets that share while someone else is sharing, otherwise one H.264 camera: the active speaker's when it is live, otherwise another live camera. The listener does not get their own picture. `call.slots` `video` says whose, with `kind` `camera` or `share`. Cameras send two simulcast layers, `h` and `l`, and the SFU picks one per listener from its bandwidth estimate, `call.quality`, and `TINYSERVER_MEDIA_EGRESS_KBPS`. Shares are planned first in that budget, then cameras drop to the low layer, then to audio only. |
| **Health** | `GET /health` reports `media` as `off`, `up`, or `down`, and `transports` for the media paths that are up: `udp` and `tcp`, and `lan` when `TINYSERVER_LAN_IP` is set. |

## Sign-in

tinyserver keeps no passwords. It is a confidential client of one or more OpenID Connect providers. A person is the issuer and subject in a verified ID token. Email never links accounts, and the same person at two providers is two accounts.

[tinyclient](https://tinyclient.io) opens the system browser. This server keeps the pending sign-in for 10 minutes, exchanges the provider's code with its own secret and its own PKCE verifier, checks the ID token, and sends the browser on to tinyclient's loopback listener with a one-time code. That code lasts 60 seconds and works once. tinyclient trades it, with its own verifier, for a session.

The provider in [`deploy/compose.yml`](deploy/compose.yml) is Pocket ID. People sign in there with a passkey. `TINYSERVER_OIDC_SIGNUP=pocket-id`, the compose default, lets an invite make the Pocket ID account. `none` turns that off. Pocket ID is the only provider that makes accounts. `AUTH_PUBLIC_URL` is its public issuer. `TINYAUTH_PUBLIC_URL` still fills that in when `AUTH_PUBLIC_URL` is unset.

| Route | |
| --- | --- |
| `GET /v1/auth/config` | No session. `{"methods":["oidc"],"provider_name","providers":[{"id","name"}]}`. `provider_name` is the default provider's name. With one provider the id is `default`. Compose names it Pocket ID unless `TINYSERVER_OIDC_PROVIDER_NAME` is set. |
| `POST /v1/auth/start` | `{redirect_uri, code_challenge, code_challenge_method, state, invite?, provider?}`. The redirect is `http://127.0.0.1:<port>/callback` or `http://[::1]:<port>/callback`, port 1 to 65535 with no leading zero. The method is `S256`. `provider` is an id from config; omitted means the first. Returns `{authorize_url}`. A bad body is `400 {"error":"bad_request"}`. A failed save is `500 {"error":"unavailable"}`. Over the limit is `429 {"error":"slow_down"}`. The pending sign-in lasts 10 minutes. With an invite and a provider that makes accounts, `authorize_url` is the join page instead of the provider. |
| `GET /v1/auth/join?state=` | A page: "I'm new here" or "I already have an account". The second is the provider's sign-in, the same URL `start` would have returned. Nothing is spent. An expired sign-in is a small page and no redirect. |
| `POST /v1/auth/join` | "I'm new here". While the invite could still be accepted, the server asks Pocket ID for one sign-up token (single use, 15 minutes) and shows two steps: make the account and passkey at Pocket ID in a new tab, then continue to sign-in here. Once per sign-in; a second try shows the way on and makes no second token. An unknown, expired, or used-up invite ends the sign-in with `error=not_member` and makes nothing. If Pocket ID does not answer, the page is `502` and the try can be repeated. 3 tries a minute per address and 30 a minute in all; over that, a `429` page. |
| `GET /v1/auth/callback` | Where the provider sends the browser (`${TINYSERVER_PUBLIC_URL}/v1/auth/callback`). The server checks the ID token and applies the invite or the group rules. Then `302` to tinyclient with `code` and `state`, or `error` of `not_member`, `denied`, `failed`, or `banned`. `denied` is the provider's `access_denied`, `consent_required`, `login_required`, or `interaction_required`. An expired or used state gets a small page and no redirect. |
| `POST /v1/auth/token` | `{code, code_verifier}`. Returns `{token, user_id, email, display_name, role}`. A bad, expired, or reused code, or a verifier that does not match, is `400 {"error":"invalid_grant"}` (a mismatch still spends the code). A database failure is `500 {"error":"unavailable"}`. |
| `POST /v1/auth/backchannel-logout` | OpenID Connect Back-Channel Logout 1.0. The provider posts `logout_token`. `200` with no body, or `400 {"error":"invalid_request"}`. |

`start` and `token` allow 5 tries a minute per address and 120 a minute in all. The address is `cf-connecting-ip`. Without a usable one, those clients share one bucket. The caps are in this process.

The session token is shown once. Send `Authorization: Bearer <token>` (that prefix, exact). Postgres stores only its SHA-256. It lasts `TINYSERVER_SESSION_MAX_DAYS`, 1 to 365, 30 when unset. Nothing extends it, and no provider refresh token is kept. `GET /v1/me` reads it. `DELETE /v1/session` ends that session. `DELETE /v1/sessions` ends every session you have. Both answer `204`. A live socket whose token is gone closes with `4001` `session_ended`. A provider logout ends the sessions its token names (`sid`, `sub`, or both), audited as `session.logout`. "Sign out everywhere" is audited as `session.close_all`.

Groups from the ID token can let someone join, or give a member the admin role, when the operator sets `TINYSERVER_OIDC_MEMBER_GROUPS` and `TINYSERVER_OIDC_ADMIN_GROUPS`. Unset member groups means an invite is required to join. An admin group does not make an owner. Leaving the group leaves the role in place. The claim is `groups` unless `TINYSERVER_OIDC_GROUPS_CLAIM` is set. A banned person is sent back with `error=banned`.

The pages the browser sees here load nothing and run no script. Their one stylesheet is allowed by its hash.

`serve` needs `TINYSERVER_PUBLIC_URL`, `TINYSERVER_OIDC_ISSUER`, `TINYSERVER_OIDC_CLIENT_ID`, and a client secret file or `TINYSERVER_OIDC_PRIVATE_KEY_FILE` (`private_key_jwt`), not both. The issuer in discovery must be the configured issuer, character for character. An unreachable provider is tried again for about a minute. Several providers: `TINYSERVER_OIDC_PROVIDERS`, first one the default. Pocket ID, other providers, and logout registration are in [`deploy/README.md`](deploy/README.md#pocket-id) and [`deploy/README.md`](deploy/README.md#other-providers).

## Run

A checkout runs tinyserver on your machine against Postgres from [`docker-compose.yml`](docker-compose.yml). A community runs [`deploy/compose.yml`](deploy/compose.yml) (Postgres, tinyserver, Pocket ID, clamd, and a Cloudflare tunnel). That setup is [Running a community](deploy/README.md).

### On your machine

Rust is stable ([`rust-toolchain.toml`](rust-toolchain.toml)). From the checkout:

```sh
cp .env.example .env
docker compose up -d --wait
cargo run -p tinyserver -- migrate
cargo run -p tinyserver -- bootstrap
cargo run -p tinyserver -- serve
```

`docker compose` here is the repo-root file, project name `tinyserver`. It publishes Postgres 17 on `0.0.0.0:54329` and nothing else. [`deploy/compose.yml`](deploy/compose.yml) uses the same project name for a different stack. Do not use this `.env` as that stack's environment file.

`.env.example` is the local default. Copy it to `.env` and keep that file to yourself. The process loads `.env` from the current directory and does not override variables already set.

`migrate` and `bootstrap` use `DATABASE_URL_MIGRATE` (`app_owner`). `serve` uses `DATABASE_URL` (`app_runtime`). Those passwords have to match `APP_OWNER_PASSWORD` and `APP_RUNTIME_PASSWORD`. [`docker/postgres/init/01-roles.sh`](docker/postgres/init/01-roles.sh) applies them only when the data volume is new.

`serve` will not start until a scanner is set. Use `TINYSERVER_CLAMD_SOCKET` as `host:port`, or `TINYSERVER_ALLOW_FAKE_SCAN=1` when no clamd is running. The example leaves both commented out. On Windows a filesystem path is an error. A socket wins when both are set.

`serve` also needs `TINYSERVER_PUBLIC_URL`, `TINYSERVER_OIDC_ISSUER`, `TINYSERVER_OIDC_CLIENT_ID`, and a client secret or a PKCS#1 RSA private key (`TINYSERVER_OIDC_PRIVATE_KEY_FILE`). Prefer `TINYSERVER_OIDC_CLIENT_SECRET_FILE`. Set the file or `TINYSERVER_OIDC_CLIENT_SECRET`, not both. The example issuer `https://auth.example.org` and `./secrets/oidc_client_secret` are placeholders: the file has to exist, and discovery has to reach the issuer you set. https only, except http to `127.0.0.1`, `localhost`, or `[::1]`. A missing or empty secret stops at once. Discovery that cannot be read is tried again for about a minute. A document that names another issuer stops at once.

`TINYSERVER_MEDIA_HMAC_SECRET` is 32 bytes as hex (64 characters), from `openssl rand -hex 32`. `serve` still starts when it is empty. Signed attachment URLs are then left off, and a download that presents a signature is rejected. The community compose file will not start until it is set.

With `TINYSERVER_PUBLIC_IP` set, as in the example (`127.0.0.1`), `serve` binds UDP and TCP on `TINYSERVER_MEDIA_PORT` (50000) on every interface. Leave the public address unset and the server still runs, calls have no media, and an offer gets `media_unavailable`.

`bootstrap` prints an owner invite when it creates one. With `TINYSERVER_PUBLIC_URL` set that is a `https://tinyclient.io/invite#…` link and a `tc1.` code. While an earlier invite still works it prints a reminder and not the token. With an owner it prints nothing. `bootstrap --owner-invite` makes a new one and retires the old one.

`GET /health` is 200 with `"ok": true` when `public.memberships` exists and media is not `down`. `"schema"` is `ready` or `missing`. `"db_role"` is the user in `DATABASE_URL` (`app_runtime` for this `.env`). `"media"` is `off`, `up`, or `down`. While media is up, `"transports"` is `udp` and `tcp`, plus `lan` when `TINYSERVER_LAN_IP` is set. The process listens on `127.0.0.1:8080` unless `BIND` says otherwise.

### A community

Use [Running a community](deploy/README.md). From `deploy/`, the environment file has to set the database passwords, `TINYSERVER_PUBLIC_URL`, `AUTH_PUBLIC_URL`, `TUNNEL_TOKEN`, and `TINYSERVER_MEDIA_HMAC_SECRET` before `setup.sh`, because that script renders the whole compose file. `TINYAUTH_PUBLIC_URL` still fills `AUTH_PUBLIC_URL` when the new name is unset.

```sh
sh pocket-id/setup.sh <first-admin-username>
docker compose up -d
```

`setup.sh` writes `deploy/secrets` (mode `0700`, secret files `0444`), starts Pocket ID, and registers the OIDC client `tinyserver`. The username is the first Pocket ID admin. The script prints a one-time link `${AUTH_PUBLIC_URL}/lc/<token>`, good for an hour.

The first container start migrates and, while there is no owner, prints one owner invite to the logs. Paste the code into tinyclient. A later start does not print that token again. With an owner, bootstrap prints nothing.

HTTP listens on 8080 inside the network and is not published on the host. The tunnel is what carries the chat hostname to `http://tinyserver:8080` and the auth hostname to `http://pocket-id:1411`. Both hostnames are set on the tunnel in Cloudflare. The host publishes only `TINYSERVER_MEDIA_PORT` (50000 unless set), UDP and TCP. Pocket ID and clamd publish no port. clamd is `clamd:3310` on the `media` network, which has a route out so signature updates can run. Postgres and Pocket ID stay on the internal network.

## Test

`cargo test` runs the unit tests and the SFU tests in [`crates/sfu/tests`](crates/sfu/tests). Those bind `127.0.0.1` on a free port and talk between headless str0m clients: audio, H.264 camera and screen share, bandwidth, and ICE-TCP. They need no database. The headless client is the one [tinyclient](https://github.com/TinyComms/tinyclient)'s `mediad` follows.

The integration tests in [`crates/api/tests`](crates/api/tests) need Postgres. If `TEST_DATABASE_URL_MIGRATE` or `TEST_DATABASE_URL` is unset, a test prints `skipped` and passes without connecting. With both set, each test connects with those URLs, replaces only the database name, creates `tinyserver_test_<uuid>` as `app_owner`, migrates it, serves it as `app_runtime`, and drops it. The name in the URL is the maintenance database. Host, port, user, password, and the rest of the connect options stay. Local Postgres from `docker compose` publishes `54329`. The roles are the ones [`docker/postgres/init/01-roles.sh`](docker/postgres/init/01-roles.sh) creates:

```sh
export TEST_DATABASE_URL_MIGRATE=postgres://app_owner:app_owner@127.0.0.1:54329/tinyserver?sslmode=disable
export TEST_DATABASE_URL=postgres://app_runtime:app_runtime@127.0.0.1:54329/tinyserver?sslmode=disable
cargo test
```

The harness sets `TINYSERVER_ALLOW_FAKE_SCAN=1` and a test media HMAC secret, and clears `TINYSERVER_CLAMD_SOCKET`, so uploads scan with `FakeEngine`. Sign-in tests run a small OpenID Connect provider in the test process. Its keys, only for tests, are in [`crates/api/tests/fixtures`](crates/api/tests/fixtures), with `tiny.png` and `tiny.gif` for attachment tests. Signup tests stand in for Pocket ID's sign-up API.

[CI](.github/workflows/ci.yml) on [tinyserver](https://github.com/TinyComms/tinyserver) runs `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings`, and the same `cargo test` against `postgres:17-alpine` on port 5432, after that role script. A separate nightly job runs every cargo-fuzz target for 60 seconds. It does not gate the `check` job.

## Repository

Source is [TinyComms/tinyserver](https://github.com/TinyComms/tinyserver). The app is [TinyComms/tinyclient](https://github.com/TinyComms/tinyclient).

| Path | What it is |
| --- | --- |
| [`crates/db`](crates/db) | Postgres access, under row level security for `app_runtime`. Migrations in [`crates/db/migrations`](crates/db/migrations) (`0001_init.sql` through `0012_bots.sql`) run as `app_owner` from `db::migrate`. Accounts and avatars, sign-in, sessions, the owner invite, server settings, roles, rooms, categories, invites, bans, messages, attachments, bots, scan verdicts, and the outbox |
| [`crates/api`](crates/api) | HTTP and the live socket: health, OpenID Connect, your account, server settings, roles, rooms, people, invites, bans, bots, messages and scanned uploads, the audit log, who is in each call, and end-to-end encryption. Call packets stay in `sfu` |
| [`crates/server`](crates/server) | The `tinyserver` binary: `migrate`, `bootstrap`, `serve`, `identities`, and `relink-identity` |
| [`crates/sfu`](crates/sfu) | The SFU: one thread, one UDP socket and an ICE-TCP listener on the same port, str0m. The headless client in [`client.rs`](crates/sfu/src/client.rs), and its H.264 clips in [`fixtures`](crates/sfu/fixtures) |
| [`fuzz`](fuzz) | cargo-fuzz on nightly, outside this workspace. `live_frame`, `sdp_offer`, `tcp_frames`, `packets`, `video_routing`. `cargo +nightly fuzz run sdp_offer -- -max_total_time=60` |
| [`docker-compose.yml`](docker-compose.yml) | Local Postgres 17 on port `54329`. First boot runs [`docker/postgres/init/01-roles.sh`](docker/postgres/init/01-roles.sh) |
| [`deploy`](deploy) | Community compose, Pocket ID setup, and the entrypoint that migrates, bootstraps, and serves. See [`deploy/README.md`](deploy/README.md) |
| [`docs`](docs) | [`calls.md`](docs/calls.md) and [`server.md`](docs/server.md) |
| [`.github/workflows/ci.yml`](.github/workflows/ci.yml) | Format, clippy, `cargo test`, and the nightly fuzz job |
| [`Dockerfile`](Dockerfile) | Release build of the `tinyserver` binary |
| [`rust-toolchain.toml`](rust-toolchain.toml) | `stable`. The fuzz job installs nightly itself |
