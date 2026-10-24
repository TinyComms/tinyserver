# tinyserver

Self-hosted voice and video for [tinyclient](https://github.com/itz4blitz/tinyclient). One server, one community. It is written in Rust. [MIT licensed](LICENSE).

The project is early. An owner can sign in from tinyclient. Rooms, invites, and calls are not here yet. Media is not started.

## What works today

| | |
| --- | --- |
| **Owner** | `bootstrap` creates the first owner from the environment. It refuses to run twice. |
| **Sign-in** | `POST /v1/session` returns a token. `GET /v1/me` reads it. `DELETE /v1/session` ends it. |
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

## Repository

| Path | What it is |
| --- | --- |
| [`crates/db`](crates/db) | Migrations, the first owner, and sessions |
| [`crates/api`](crates/api) | `GET /health`, `POST /v1/session`, `GET /v1/me`, `DELETE /v1/session` |
| [`crates/server`](crates/server) | `migrate`, `bootstrap`, `serve` |
| [`crates/sfu`](crates/sfu) | The media boundary. Nothing is listening yet |
