# tinyserver

Self-hosted voice and video for [tinyclient](https://github.com/itz4blitz/tinyclient). One server, one community. It is written in Rust. [MIT licensed](LICENSE).

The project is early. An owner can sign in, make rooms, and invite people. Calls are not here yet. Media is not started.

## What works today

| | |
| --- | --- |
| **Owner** | `bootstrap` creates the first owner from the environment. It refuses to run twice. |
| **Sign-in** | `POST /v1/session` returns a token. `GET /v1/me` reads it. `DELETE /v1/session` ends it. |
| **Rooms** | A member lists rooms. An owner or admin adds, renames, and removes them. |
| **People** | A member lists people. An owner or admin changes a role or removes someone. The last owner stays. An admin cannot change an owner. |
| **Invites** | An owner or admin creates an invite for an admin or a member. The token is returned once and lasts 7 days. `POST /v1/invites/accept` creates the account, or brings an existing one back, and signs in. |
| **Audit** | An owner or admin reads `GET /v1/audit`. |
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
| [`crates/db`](crates/db) | Migrations, the first owner, sessions, rooms, and invites |
| [`crates/api`](crates/api) | Health, sign-in, rooms, people, invites, and the audit log |
| [`crates/server`](crates/server) | `migrate`, `bootstrap`, `serve` |
| [`crates/sfu`](crates/sfu) | The media boundary. Nothing is listening yet |
