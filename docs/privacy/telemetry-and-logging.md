# Telemetry and logging: what is missing from `docs/logging.md`

[`../logging.md`](../logging.md) documents the server's log knobs and what the redactor drops. This file adds what that one does not: every log sink in the whole stack, what the default log lines reveal about a person's activity, where redaction does not apply, a telemetry inventory, and the changes needed before anyone can advertise "no activity logs". Server facts are from `crates/server/src/log_policy.rs`, `crates/api/src/**`, `crates/sfu/src/**` and `deploy/compose.yml`. Client facts are from tinyclient `docs/logging.md` and `SECURITY.md` at `26916e9` (read only).

## 1. Every sink in the stack

| Sink | Writer | Level and content | Form | Readable by | Retention |
|---|---|---|---|---|---|
| tinyserver stderr | `RedactLayer` in `log_policy.rs` | `info` and above by default, `TINYSERVER_LOG_LEVEL` raises or lowers it. Event lines only | Text line `level target message field=value ...`, values cut at 300 characters | Host, through Docker | Docker `json-file`, 10 MB times 3 files per container. Bounded by size, not time. Docker adds a timestamp to each line |
| tinyserver debug ring | Same layer | `debug` and above while `TINYSERVER_LOG_RING=on` (default), whatever the operator level | In process memory | Host (process memory) | About 2000 lines and at most one hour |
| Debug bundle | `export_bundle`, on `SIGUSR1` (Unix only) | The ring | File `{data dir}/logs/bundle-<unix>.log`, mode 0600. In compose the data dir is a tmpfs, so bundles do not survive a container stop | Host | Deleted at the next `serve` start when older than `TINYSERVER_LOG_BUNDLE_HOURS` (24). `TINYSERVER_LOG_EXPORT=off` writes none |
| Panic and fatal error text | Rust's default panic hook; `anyhow` errors returned from `main` | The panic message and location; `Error: ...` with the context chain | Written to stderr **outside** the redactor | Host, through Docker | As stderr |
| `tinyserver-init` output | `tinyserver migrate`, `bootstrap` | "migrations applied", "owner invite created", a path | Same layer | Host | `json-file`, as above. The token is written to a file and never to the log |
| Postgres | Postgres | Default server log. Errors, and by Postgres's behaviour constraint-violation `DETAIL` lines with key values | Text, `json-file` | Host | 10 MB times 3. Not verified for this stack's exact settings |
| Pocket ID | Pocket ID (`LOG_JSON=true`) | Unreviewed. Pocket ID also keeps an **audit log in its own database** with client IPs (see [`metadata.md`](metadata.md) section 12) | JSON, `json-file`; audit events in SQLite | Host | 10 MB times 3; audit events 90 days by default |
| clamd | ClamAV | Unreviewed | `json-file` | Host | 10 MB times 3 |
| cloudflared | Cloudflare | Unreviewed | `json-file` | Host | 10 MB times 3 |
| Docker daemon, the host's journal, the hypervisor | Outside this repository | | | Host | Host's choice |

There is **no HTTP access log**: no tower or tracing layer logs requests (`crates/api/src/observe.rs` makes a span, and nothing renders it, see section 4). A request is logged only when a handler emits an event.

## 2. What the default `info` stream says about activity

The redactor removes values and field names that hold content or secrets. It keeps ids and static reasons. Those ids are enough, with the timestamp Docker adds, to rebuild who was connected when. Events at `info` or `warn` in the server (grep of `tracing::info!` and `tracing::warn!` in `crates/`, 2026-10-31):

| Event | Fields | Where |
|---|---|---|
| `live socket opened`, `live socket closed`, `live socket gone` | `user_id`, `conn` (a connection counter), close reason | `crates/api/src/live/socket.rs` |
| `session opened` | `user_id` | `crates/api/src/auth.rs` |
| `signed in at the provider` | `provider`, `user_id`, `role`, `joined` | `auth.rs` |
| `session closed`, `sessions closed` | `user_id` (count of sessions) | `session.rs`, `account.rs` |
| `back-channel logout` | `issuer`, number of sessions ended | `auth.rs` |
| `sign-in started` | `provider`, whether an invite was carried | `auth.rs` |
| `sign-in refused: not a member`, `banned` | `provider`, whether an invite was carried. No identity | `auth.rs` |
| `account deleted`, `display name changed`, `avatar set/removed` | `user_id` | `account.rs` |
| Moderation and settings: `member banned`, `ban lifted`, `member removed`, `roles changed`, `owner changed`, `timeout changed`, `role created/changed/deleted`, `override set`, `room created/renamed/deleted`, `invite created/revoked`, `bot created/revoked`, `server settings changed`, `layout changed` | The acting `user_id`, and the id of the person or object | `admin.rs`, `community.rs`, `bot.rs` |
| `media joined`, `media lost` (and debug: `media connected`, `media dropped`) | `call_id` (random, per join), camera and share flags, loss reason | `crates/sfu/src/engine.rs` |
| `message failed`, `upload failed` | `user_id`, `room_id`, a static reason, a byte count | `messages.rs` |
| `rate limited` | the route template | `limit.rs` |
| `identity relinked` | `user_id`, `issuer` | `crates/server/src/main.rs` |

Consequences, stated plainly:

- **The default operator log is a connection history.** For each member it says when each live socket opened and closed. `last_seen_at` in Postgres says the same thing more coarsely. Anything that advertises "we do not record when you are online" is false for the default configuration.
- It contains **no IP address** (the `peer` field is dropped on this sink and the limiter logs only a route), **no message text, file name, token, email or display name** (field-name denylist plus value scanning; tests `drops_body_and_access_token_keeps_user_id`, `redacts_bearer_pem_jwt_ice_and_userinfo`), and **no call roster** (joins and leaves are not logged; only the opening and closing of sockets and per-call media events with a random `call_id`).
- A `call_id` is not linkable to a `user_id` in a log line. Each `media joined` line has only `call_id` (`engine.rs`, line "media joined"). Joining the two needs the socket events and timing, which Docker's timestamps provide.
- Lines from `tinyserver serve` carry no per-request identifier: the `req_id` the docs mention is never printed (section 4).
- At `debug` or `trace` the volume rises. Dependencies (`reqwest`, `hyper`, `h2`, `sqlx`, `tower`, `str0m`) are capped at `warn`, and every target that is not `tinyserver`, `api`, `sfu` or one of those is also capped at `warn` (`target_ceiling`).

## 3. What redaction does and does not cover

| Covered | Not covered |
|---|---|
| Event fields named `body`, `content`, `text`, `filename`, `token`, `secret`, `key`, `email`, `display_name`, `subject`, `detail`, `sdp`, `code` and others, the encrypted-text fields `ciphertext`, `key_package`, `commit`, `welcome`, `proposal`, `handshake`, `cross_signature`, `external_sender` and their plurals (#23; test `drops_what_end_to_end_encrypted_text_could_carry`, and `crates/api/tests/e2ee_text.rs` `a_canary_said_only_through_encrypted_paths_is_nowhere_on_the_server` checks every log line at every level), and any field ending in `_token`, `_secret`, `_password`, `_cookie`, `_key` (dropped) | A field the code names something else. Redaction is by name first. A new `tracing::info!(note = %something_sensitive)` would be written. The test suite has no check that fails when one is added |
| Values in any field or message: Bearer tokens, JWT-shaped strings, PEM blocks, URL userinfo, `a=ice-pwd`, `token=` style parameters, a list of vendor token prefixes | Free text in an error: `%error` fields are scanned and cut at 300 characters, not parsed. A database or provider error that quoted a value would be written if the value did not match a pattern |
| `RUST_LOG` is ignored | Panic and `anyhow` output, which bypass the layer entirely (section 1) |

Tests: `crates/server/src/log_policy.rs` unit tests; `crates/api/tests/signup_logs.rs` (`the_api_key_and_signup_tokens_never_reach_the_logs`) runs the sign-up flow and checks the captured log.

## 4. Corrections to existing documents

Found while writing this inventory. They are listed in the final report so the owners can fix them; this file does not edit those documents.

| Document | Statement | Finding |
|---|---|---|
| `docs/logging.md`, last paragraph | "Each HTTP request span carries `req_id` ... and the matched route template." | The span exists (`observe.rs`), but `RedactLayer::on_event` reads only the event's own fields and ignores span context (`_ctx` is unused), so `req_id` and `route` are **never printed**. Either the sentence should say that, or the layer should render span fields |
| `docs/logging.md`, "Never recorded" | "Read it with `docker compose exec tinyserver cat /var/lib/tinyserver/owner-invite`" | In `deploy/compose.yml` the init container writes to `/bootstrap` and the server mounts it read only at `/bootstrap`. The right command is in `deploy/README.md`: `cat /bootstrap/owner-invite`. Fixed in `docs/logging.md` on `hardening/privacy-architecture` |
| `docs/server.md`, "Bootstrap" | The invite file is `{TINYSERVER_DATA_DIR}/owner-invite` | True for a single-container run; in compose `TINYSERVER_DATA_DIR` for the init container is `/bootstrap` |
| `docs/calls.md`, E2EE "What it protects" (last paragraph) | "At `trace` the WebSocket library itself prints whole frames ... run the server at `debug` or above." | After the log policy change, targets other than `tinyserver`, `api` and `sfu` are capped at `warn`, so a WebSocket library's `trace` output is not emitted at any setting. The advice is unnecessary, not harmful |

## 5. Telemetry inventory

| Component | Telemetry | Evidence |
|---|---|---|
| tinyserver | None: no exporter, no analytics, no crash upload, no update check, no outbound call except the OIDC provider (`reqwest` in `oidc.rs`: discovery, keys, code exchange, sign-up tokens), Postgres, clamd | `Cargo.lock` has no telemetry crate (see [`metadata.md`](metadata.md) section 15); `grep` of `crates/` for HTTP clients finds `oidc.rs` only |
| `crates/sfu` | None. `Load` events are in-process and logged at debug | `docs/calls.md` |
| Pocket ID | Disabled by `ANALYTICS_DISABLED=true` and `VERSION_CHECK_DISABLED=true`; the container also has no route out | `deploy/compose.yml`; [Pocket ID docs](https://pocket-id.org/docs/configuration/environment-variables) |
| ClamAV | `freshclam` fetches signatures from ClamAV mirrors. It sends no file content; the mirrors see the host's address | `deploy/compose.yml` comments; mirror logging not reviewed |
| cloudflared | It maintains the tunnel to Cloudflare, which is the service's purpose. Other data it may report to Cloudflare was not reviewed. `--no-autoupdate` is set | `deploy/compose.yml` |
| Docker, host OS | Outside this repository | |
| tinyclient | No telemetry, no crash upload. Logs stay on the machine. It asks GitHub for the latest release, asks Wikipedia for the summary of a linked article, and talks to the networks the person signs in to | Client `SECURITY.md` ("There is no telemetry and no crash upload"), `docs/architecture.md`. The GitHub endpoint was not located in the client source; **not verified** |
| TinyCloud control plane, billing, support tooling | Not in this repository | |

## 6. Engineering requirements before advertising "no activity logs"

These are changes, not existing behaviour.

1. Decide the default level for managed tenants. At `warn`, the connection and moderation events in section 2 are not written; moderation stays in `audit_log`. Check what incident response still needs at that level.
2. Install a panic hook and a fatal-error path that go through `redact_value`, or accept that panic text is unredacted and say so.
3. Add a test that fails when a new log call names a field or interpolates a value that is not in an allow-list of safe names (a log-line allowlist test), and a test that runs the main flows and greps the captured stderr for emails, display names, subjects, tokens and addresses.
4. Either render the span fields (`req_id`, `route`) or stop documenting them.
5. Configure Docker log retention by time as well as size for tenant containers (the `local` driver supports `max-size` and `max-file`; time-based expiry needs the host's logging stack), and document who can read the host's journal.
6. Configure Postgres logging explicitly (`log_min_messages`, `log_error_verbosity = terse` to drop `DETAIL`, no statement logging) and review Pocket ID's log content and audit-log retention (`AUDIT_LOG_RETENTION_DAYS`).
7. Decide whether the debug ring should exist in tenant stacks (`TINYSERVER_LOG_RING=off` removes it, and with it `SIGUSR1` bundles).
8. Review clamd's and cloudflared's log content.

## 7. Client logging

The client's own document is `docs/logging.md` in the tinyclient repository. In short: four files under the support directory, rolled at 2 MiB with two generations, mode 0600 on Unix; bundles only when the person chooses Save debug log; panics to `crash.log` after redaction; `protocol::redact` on every line; names and `peer` dropped. Tiny-server call frames and sessions are not logged. Not re-verified here.
