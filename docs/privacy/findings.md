# Security and privacy findings

Audit of tinyserver at `bbe1cd7` and tinyclient at `26916e9` (both `origin/main` on 2026-10-31), made by reading the code. Each finding names how it was established:

- **Reproduced**: a test failed before the fix and passes after it.
- **Read**: confirmed by reading the cited code, with no failing test written first.
- **Reported**: found by an audit pass over the code and not independently re-checked. Treat as likely, not proven.

Severity is exposure if the flaw is abused by the party named, not likelihood. `Status` is what this branch does about it. A finding is only "Fixed" when a test in this branch fails without the fix, or, for S2, S13 and S14, when it was checked by running the containers. `client:` statuses describe tinyclient's `hardening/privacy-architecture` branch, which is not merged and was not re-run here.

Paths are in tinyserver unless marked `client:`.

## Summary

| # | Severity | Finding | Status |
|---|---|---|---|
| S1 | High | Private-channel messages reach every member's socket | Fixed |
| S2 | High | The serving container holds the database owner credentials | Fixed |
| S3 | High | Text messages and attachments are plaintext to the server | Remediation in progress, see `docs/e2ee-text.md` |
| S4 | High | A server, or one old client, can turn call E2EE off with no check by the others | Mitigated client-side (opt-in), residual risk documented |
| S5 | Medium | Invite token stored in `idempotency_keys` | Fixed |
| S6 | Medium | Every member can read every member's email | Fixed |
| S7 | Medium | Rate-limit key is a forgeable header, raw IPs held in memory | Fixed |
| S8 | Medium | No account deletion; edit and delete leave text in the outbox | Fixed |
| S9 | Medium | Plaintext attachments hit disk before the scan verdict | Open; sealed uploads (specified in `docs/e2ee-text.md`, not built) would remove it for encrypted conversations |
| S10 | Medium | Call identity: any member can be impersonated by the server (8-byte ids, server-attested roster) | Documented, residual |
| S11 | Medium | No backup story, no encrypted backups | Open, planned; no tooling in this branch |
| S12 | Medium | No per-tenant isolation contract or checks | Open, planned; no contract or checks in this branch |
| S13 | Low | Dev compose published Postgres on `0.0.0.0` with known passwords | Fixed |
| S14 | Low | Resource limits missing on most containers | Fixed |
| S15 | Low | Migrations were not tracked as a build input | Fixed |
| S16 | Low | Last-seen time and how a member joined are visible to every member | Documented |
| C1 | High | `client:` Tiny text and files are plaintext to the server; local cache unencrypted | Open; remediation in progress elsewhere, not merged |
| C2 | High | `client:` Accepts a server `off` frame and carries on unencrypted | Fixed (opt-in require mode) |
| C3 | Medium | `client:` Identity key written non-atomically, overwritten when unreadable | Fixed |
| C4 | Medium | `client:` Identity key is plaintext on disk, not in the OS keychain | Open, see limits |
| C5 | Medium | `client:` Cleartext http accepted for any typed host | Hardened |
| C6 | Medium | `client:` Updater integrity is weak | Hardened where possible |
| C7 | Low | `client:` Notification previews default to full text | Changed |
| C8 | Low | `client:` File permissions: support dir, sqlite, crash log, verified.json | Hardened |

## Findings

### S1 High: private-channel messages reach every member's socket (Reproduced)

- **Files**: `crates/api/src/live/frame.rs` (`Event::from_row`), `crates/api/src/live/socket.rs` (`sees_durable`), `crates/db/migrations/0008_messages.sql`.
- **Behavior**: channel events were stored with a NULL audience, which `from_row` maps to "everyone", and delivery only checks the socket is not a bot. HTTP reads checked `view_channel`; the live socket did not.
- **Exposure**: a member denied `view_channel` still received `message.created`, `message.edited`, `message.deleted`, `reaction.updated` and `channel.updated` (including a 200 character preview of the last message) live, and again from the 24 hour `?since=` replay.
- **Remediation**: `0013_private_channel_events.sql`. Every emit passes through `app_emit` and `app_emit_to`; both now narrow a NULL audience on a channel event to the members who can view that channel when the channel can be restricted, and leave it NULL when every member can view it.
- **Tests**: `a_private_channels_events_reach_only_members_who_can_view_it` (`crates/api/tests/messages.rs`). It checks the live socket, the replay path and the stored outbox rows. It failed before the migration was embedded and passes after.
- **Limits**: the audience is the set that could view the channel when the event was emitted. A member who gains access later does not get earlier events. A member who loses access is not told the channel is gone until their client refetches. `channel.deleted` still carries only the channel id to everyone.

### S2 High: the serving container holds the owner database credentials (Read, and verified by running)

- **Files**: `deploy/compose.yml`, `deploy/entrypoint.sh`, `crates/server/src/main.rs`.
- **Behavior**: `DATABASE_URL_MIGRATE` (role `app_owner`, which has CREATEDB and BYPASSRLS) was in the environment of the process that serves the internet, because migrate, bootstrap and serve shared one entrypoint.
- **Exposure**: remote code execution in the server defeats row-level security and can rewrite the schema.
- **Remediation**: a one-shot `tinyserver-init` service holds the owner password, runs `migrate` and `bootstrap` and writes the owner invite to a volume the server mounts read only. The server container has `DATABASE_URL` only.
- **Tests**: run by hand: the init container, with the compose restrictions (read-only root, all capabilities dropped, uid 10001), migrated a database and wrote a mode 0600 invite; a serving container's environment held no `DATABASE_URL_MIGRATE`. No automated test: it needs Docker, and no script for it is in this branch.
- **Limits**: the app runtime role can still read and write every table through its row-level security and definer functions. A flaw that executes arbitrary SQL as `app_runtime` is not contained by this.

### S3 High: text messages and attachments are plaintext to the server (Read)

- **Files**: `crates/db/migrations/0008_messages.sql` (`messages.body`, `attachments`), `crates/db/src/messages.rs`, `crates/api/src/messages.rs`.
- **Behavior**: message bodies are plaintext columns, attachment bytes are plaintext files in the upload volume, names and types are plaintext, and the 200 character last-message preview is built from the body.
- **Exposure**: anyone with read access to Postgres, its backups or write-ahead log, the upload volume, or the server's memory reads every conversation.
- **Remediation** (specified, not built in this branch): see `docs/e2ee-text.md`: per-conversation MLS groups, ciphertext-only storage, client-side sealed attachments, explicit per-conversation `e2ee` flag, no downgrade, no in-place conversion of existing history.
- **Limits**: see the "What this does not protect" section of that document.

### S4 High: a server or one old client can disable call E2EE (Read)

- **Files**: `crates/api/src/live/e2ee.rs`, `crates/api/src/live/socket.rs`, `client:crates/mediad/src/e2ee.rs`.
- **Behavior**: whether a participant "can encrypt" is self-declared; one participant without it turns the call to transport only for everyone, and the `off` and `start` frames are unauthenticated JSON from the server. `e2ee_required` defaults to false and is enforced only when media runs.
- **Exposure**: a malicious or compromised server can listen to calls by sending `off`. A malicious member can force a downgrade. The server cannot be stopped from doing this by anything the server does; it can only be made visible and refusable.
- **Remediation**: `client:` mediad now has a `required` mode: on `off` the call is blocked (nothing sent or played) and the badge says so. The setting is off by default so an older server or app does not stop working.
- **Tests**: mediad unit tests for the blocked mode.
- **Limits**: with the setting off (the default) a downgrade is shown but not refused. The roster the client checks against is server-provided.

### S5 Medium: invite token stored in the idempotency table (Reproduced)

- **Files**: `crates/db/src/community.rs` (`finish`), `0001_init.sql`.
- **Behavior**: with an `Idempotency-Key`, the full response, including the one-time invite token, was stored for a day so a retry could return it, although every other table keeps only a hash of the token.
- **Remediation**: the token is never stored. A replay returns the invite without a token and `"token_unavailable": true`.
- **Tests**: `an_invite_lets_a_person_in_once_and_not_after_it_expires` now asserts the replay has no token and the table holds no copy.
- **Limits**: a caller that lost the first response must create a new invite. `tinyclient` does not send `Idempotency-Key`.

### S6 Medium: every member can read every member's email (Reproduced for the behavior, test added with the fix)

- **Files**: `crates/db/src/community.rs` (`member_select`).
- **Remediation**: `email` is returned to the person themself and to holders of `manage_server`. Display names are unchanged.
- **Tests**: `a_member_sees_their_own_email_and_not_another_members` (`crates/api/tests/privacy.rs`).
- **Limits**: `last_seen_at` and `joined_via` are still visible to all members. The email is still stored in plaintext in Postgres.

### S7 Medium: forgeable rate-limit key, raw addresses in memory (Reproduced by unit tests)

- **Files**: `crates/api/src/limit.rs`, `crates/server/src/main.rs`.
- **Behavior**: the key was the `cf-connecting-ip` header from whoever sent it, held as the raw address string; a direct caller could rotate the header to get a fresh allowance; a missing header shared one bucket.
- **Remediation**: the real peer address is read from the connection; the header is believed only from a trusted proxy (`TINYSERVER_TRUSTED_PROXIES`, default private, loopback, link-local and 100.64.0.0/10 peers); the key stored is a truncated SHA-256 under a per-process random secret, IPv6 grouped by /64; windows stay 60 seconds, in memory only.
- **Tests**: nine unit tests in `limit.rs`.
- **Limits**: a keyed hash of an IPv4 address is brute-forceable by anyone who holds the secret; the secret exists only in process memory. When no address is available the limiter does not fail open: callers share one bucket, which is a denial-of-service lever only for the three sign-in routes.

### S8 Medium: no account deletion; edits and deletes remain in live history (Reproduced)

- **Files**: `crates/db/migrations/0014_account_deletion.sql`, `crates/db/src/account.rs`, `crates/api/src/account.rs`.
- **Behavior**: nothing deleted a user. A removed member kept their email, name, provider identity, messages and audit-log names for ever. An edited or deleted message stayed readable as first sent in the outbox for 24 hours of reconnect replay.
- **Remediation**: `DELETE /v1/me` with a typed confirmation tombstones the user and removes identity, sessions, bots, unused invites, messages' text and attachments, reactions, read marks, profile events and audit-log names; a trigger rewrites earlier outbox rows when a message is edited or deleted. A sole owner is refused with `409 last_owner`.
- **Tests**: `deleting_an_account_removes_the_person_and_what_they_said`.
- **Limits**: write-ahead log, dead rows before vacuum, backups and anything a client or another member already stored are out of reach. A ban survives deletion on purpose, so the banned provider identity is retained.

### S10 Medium: call identity is server-attested (Read)

- **Files**: `crates/api/src/live/e2ee.rs`.
- **Behavior**: an MLS identity is an 8 byte hash of the user id, with no certificate binding it to an account; the roster the clients compare against is the server's.
- **Exposure**: a server that wants to hear a call must also add its own key under a roster name; clients flag unlisted or duplicate members and changed keys, so this is detectable, but only by people who verified safety numbers.
- **Remediation**: none in this branch for calls. The text design uses full 16 byte ids and cross-signed device keys.
- **Limits**: documented in `docs/privacy/threat-model.md`.

### S11 Medium: backups (Read)

- **Behavior**: the only documentation is a manual `pg_dump` as the Postgres superuser, unencrypted, and no coverage of the upload volume.
- **Remediation**: none yet. Backup tooling is planned; nothing for it is in this branch.

### S12 Medium: multi-tenant isolation (Read)

- **Behavior**: tinyserver is single-community by design. The compose file is isolated well for one community, but roles are cluster-global and the database name is fixed, so a shared Postgres cluster would collide; the media port is per-instance.
- **Remediation**: none yet. An isolation contract (`docs/privacy/tenancy.md`), a per-tenant template and checks are planned; none is in this branch.

### S13, S14, S15 Low (Read, and S15 reproduced)

- Dev compose published Postgres on every interface with the passwords from `.env.example`; it now binds to 127.0.0.1.
- Only Pocket ID had memory and process limits; tinyserver, Postgres, ClamAV and the tunnel now have limits and `no-new-privileges`, and Postgres and the tunnel drop capabilities. Postgres was started with the reduced capability set to check it boots.
- `sqlx::migrate!` does not make the migrations directory a build input on stable Rust, so a new migration could be left out of a cached build. `crates/db/build.rs` fixes it. This is why the first run of the S1 test used a stale migration list.

### S16 Low: other metadata visible to members (Read)

`last_seen_at`, `joined_via`, timeouts and the audit log's display names (before S8) are visible to members or admins. Documented in `docs/privacy/metadata.md`.

### C1 High: Tiny text and files are plaintext, local cache unencrypted (Read)

- **Files**: `client:crates/chatd/src/adapters/tiny/messages.rs`, `upload.rs`, `store.rs`, `blobs.rs`.
- **Behavior**: `post_message` sends `{"body": text}`; uploads are plaintext multipart; `chat.sqlite` is plain SQLite with `LIKE` search and plaintext drafts; downloaded media is plaintext on disk.
- **Remediation**: the client implements the protocol in `docs/e2ee-text.md`.
- **Limits**: the local cache of an end-to-end conversation protects only against someone who gets the file without the OS user's keychain. A person with their own logged-in session can read it.

### C2, C3 (Read)

Covered under S4 and "Fixed" above. C3 test: `the_identity_key_is_kept_and_read_back` extended to check the damaged file is moved aside, no temp file is left, and permissions are 0600 and 0700 on Unix.

### C4 Medium: identity key plaintext on disk (Read)

The call identity key is two hex lines in `<support>/e2ee/<account>/identity.key`, mode 0600 on Unix and inherited ACL on Windows (Roaming `%APPDATA%`). The text E2EE specification puts device keys in the OS keychain; that is not built. The call identity key keeps its file for compatibility with the shipped format and is a known remaining item.

### C5, C6, C7, C8 (Read)

Hardening details and what could not be done are in the client's `SECURITY.md`.

## Not findings

- No telemetry, analytics or crash-upload dependency exists in either `Cargo.lock` (searched for sentry, posthog, segment, opentelemetry, bugsnag, rollbar, datadog, prometheus).
- The server's log path does not contain tokens, SDP, message bodies, or OIDC codes in any `tracing` call that was read, and `RUST_LOG` is ignored.
- The SFU does not send one participant's address to another; the client never learns other participants' addresses.
- Session, invite and bot tokens are 32 random bytes stored as SHA-256 hashes.
- PKCE S256, `state`, `nonce`, exact loopback redirect matching and RFC 9207 `iss` checks are present in sign-in.

## Corrections and additions from the documentation pass

Made while writing the privacy documents, 2026-10-31, at `ea3cd39`. Corrections to this ledger are applied above (S7: nine tests, not seven, and the default trusted range also covers 100.64.0.0/10; S16 summary line; S2, S3, S9, S11, S12, C1 and C4 no longer claim tooling or code that is not in this branch). The items below are **Read** unless stated, and are rated by the same scale.

### Not matching this branch

- S2, S11 and S12 cited `deploy/tests/`, `deploy/backup/` and `deploy/tenant/`. None exists at `ea3cd39`. The entries above now describe them as planned.
- "Not findings", SFU addresses: established by reading `crates/sfu/src/engine.rs` (`candidates`); no test asserts it. The "no telemetry crate" statement was re-checked against both `Cargo.lock` files (server and client).
- C4 said text E2EE keys "are stored through the OS keychain". That is the specification, not merged code; corrected above.

### New findings

| # | Severity | Finding | Where |
|---|---|---|---|
| N1 | Medium | Panic and fatal-error output bypass the log redactor: no panic hook is installed and `anyhow` errors print straight to stderr | `crates/server/src/main.rs`, `log_policy.rs` |
| N2 | Medium | The default `info` log records socket open and close with `user_id`, and Docker timestamps each line: a connection history. "No activity logs" cannot be claimed at the default level | `crates/api/src/live/socket.rs`, [`telemetry-and-logging.md`](telemetry-and-logging.md) |
| N3 | Medium | `DELETE /v1/me` does not delete the Pocket ID account (passkeys, username, optional email, an audit log with client IPs kept 90 days by default). It also leaves `directs` rows and free-text `audit_log.reason` | `0014_account_deletion.sql`, `crates/api/src/oidc.rs` |
| N4 | Medium | No per-user or per-address rate limit on REST writes or uploads, and no storage quota. Only the three sign-in routes and the live socket are limited | `crates/api/src/limit.rs` |
| N5 | Low | `deploy/README.md` "Moving from Tinyauth" step 6 runs `identities` and `relink-identity` with `docker compose exec tinyserver`; since S2 that container has no `DATABASE_URL_MIGRATE`, so they failed. **Fixed** in `hardening/privacy-architecture`: they run in `tinyserver-init`, which now also has `TINYSERVER_OIDC_ISSUER`, and `deploy/README.md` has an upgrade section | `deploy/README.md`, `deploy/compose.yml` |
| N6 | Low | The owner invite file stays on its volume until the next `tinyserver-init` run after an owner exists, not until the owner signs up. Documented in `deploy/README.md`: run `up` once more after the owner signs in | `crates/server/src/main.rs` |
| N7 | Low | `bans` and `ban_identities` are never swept, including expired bans; the audit log is never pruned | `app_sweep`, `crates/db/src/sweep.rs` |
| N8 | Low | `GET /health` is unauthenticated and returns `db_role` | `crates/api/src/health.rs` |
| N9 | Low | A binary rollback below the E2EE version could accept plaintext into an encrypted conversation unless `migrate` fails first. Relies on sqlx's default; untested | [`migration.md`](migration.md) |
| N10 | Low | No backup tooling exists at this commit (S11 is planned only). The only procedure is an unencrypted manual `pg_dump` | `deploy/README.md` |

### Documents that disagree with the code

| Document | Says | Code says |
|---|---|---|
| `docs/logging.md` | The request span carries `req_id` | The layer never renders span fields; `req_id` is never printed |
| `docs/logging.md`, `docs/server.md` | The owner invite is read from `/var/lib/tinyserver/owner-invite` (or `{TINYSERVER_DATA_DIR}/owner-invite`) | In compose it is `/bootstrap/owner-invite`. **Fixed**: `docs/logging.md` in `hardening/privacy-architecture`, `docs/server.md` here |
| `docs/server.md`, `docs/calls.md` | Channel events go to every member socket; channel message and reaction events use a null audience | Replaced by `0013`: a channel that can be restricted narrows the audience to its viewers. **Fixed** here |
| `docs/server.md` | Lists no `DELETE /v1/me` and no `account.delete` audit action | Both exist (`crates/api/src/account.rs`, `0014`). **Fixed** here, with the narrowed `email` on `GET /v1/members` |
| `docs/calls.md` | At `trace` the WebSocket library prints whole frames | Targets other than `tinyserver`, `api` and `sfu` are capped at `warn` |
| tinyclient `SECURITY.md` | Video and screen share on a Tiny server are not end-to-end encrypted | `crates/mediad/src/e2ee.rs` has `seal_video`, used by `tiny.rs` at `26916e9`; `docs/calls.md` and the README say sealed |
