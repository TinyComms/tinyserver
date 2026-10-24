# tinyserver

Self-hosted voice and video for tinyclient. One VPS, one community. People, rooms, and invites live in Postgres. Media is not in this build.

The database roles follow the Premier Studio Postgres starter. `app_owner` migrates and creates the first owner. `app_runtime` serves, with row level security forced on. Identity (`users`, `sessions`) is not authorization. Membership role is.

## Run the database

Postgres runs on Zen. From a checkout of this repo on Zen:

```bash
cp .env.example .env
docker compose up -d
```

Port `54329` is published on the tailnet. The values in `.env.example` are local defaults.

## Run the process

On a machine that can reach that port:

```bash
cp .env.example .env
cargo run -- migrate
cargo run -- bootstrap
cargo run -- serve
```

`GET /health` is ready when `schema` is `ready` and `db_role` is `app_runtime`.

`bootstrap` reads `TINYSERVER_OWNER_EMAIL`, `TINYSERVER_OWNER_NAME`, and `TINYSERVER_OWNER_PASSWORD`. It refuses to run twice. The password stays in the environment, not on the command line.

## What is here

| Path | Role |
|---|---|
| `crates/db` | Migrations, owner bootstrap, sessions |
| `crates/api` | `GET /health`, `POST /v1/session`, `GET /v1/me`, `DELETE /v1/session` |
| `crates/sfu` | Media boundary. The plane is not started |
| `crates/server` | `migrate`, `bootstrap`, `serve` |

Invites, rooms, and calls are not here. Media is not started.

## Rules that stay

- The serving process never connects as `app_owner`.
- RTP does not go in Postgres.
- Direct membership writes are rejected. Role changes go through `app_set_member_role` and `app_remove_member`.
- The last owner cannot be removed or demoted. An admin cannot touch an owner.
