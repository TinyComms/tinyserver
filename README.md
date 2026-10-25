# tinyserver

Self-hosted voice and video for [tinyclient](https://github.com/itz4blitz/tinyclient). One server, one community. It is written in Rust. [MIT licensed](LICENSE).

The project is early. An owner can sign in, make rooms, and invite people, and every signed-in device sees changes live. Calls are not here yet. Media is not started.

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
| **Health** | `GET /health` |

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

`cargo test` runs the unit tests. The integration tests in [`crates/api/tests`](crates/api/tests) need Postgres and pass without running when it is not configured:

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
| [`crates/api`](crates/api) | Health, sign-in, your account, rooms, people, invites, the audit log, and the live socket |
| [`crates/server`](crates/server) | `migrate`, `bootstrap`, `serve` |
| [`crates/sfu`](crates/sfu) | The media boundary. Nothing is listening yet |
