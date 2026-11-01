# Metadata and content inventory

Every place user content or sensitive metadata exists in a tinyserver stack, what is there, in what form, who can read it, how long it stays, and whether end-to-end encryption (E2EE) covers it. Built by reading the migrations, the API and server code, `deploy/compose.yml` and the client repository (read only). Section 15 says how to re-check each part.

Status words are explained in [`README.md`](README.md). **Text and attachment E2EE: the server side is implemented and tested (#23, migrations `0020` to `0023`); the client side is on tinyclient main (#126, #127)** ([`../e2ee-text.md`](../e2ee-text.md)). Where this inventory says a column holds ciphertext, the server stores only what the client sent; that the client encrypts it is asserted by tinyclient's tests, not run here. Call E2EE is implemented ([`../calls.md`](../calls.md)).

Reading the columns:

- **Form**: plaintext, hash (a SHA-256 digest only), ciphertext, or in memory only.
- **Readable by**: *member* means through the API with the permissions named; *app* means the `app_runtime` Postgres role (so a flaw in tinyserver that runs SQL, or code execution in the process); *owner role* means `app_owner`, which has `BYPASSRLS`; *host* means anyone with root on the machine or the hypervisor, who can read volumes, backups and process memory. Each later column includes the earlier ones.
- **E2EE**: whether E2EE covers it, today and as specified.

## 1. PostgreSQL

Database `tinyserver` (`tenant_<name>` for a tenant made by `deploy/tenant/tenant.sh`). The API connects as `app_runtime` (`NOSUPERUSER NOBYPASSRLS`; for a tenant, `<name>_runtime`, a member of the NOLOGIN group `app_runtime`). Tables that have row-level security are marked RLS. `users`, `sessions` and `idempotency_keys` have none: `0001_init.sql` states "Identity has no RLS", and `app_runtime` can read them in full, so the limits on who sees an email or an avatar are in the application's queries, not in the database. Postgres runs with no disk-level or column-level encryption in this stack.

| Table | Columns that matter | Form | Readable by | Kept | E2EE |
|---|---|---|---|---|---|
| `users` | `id`, `email` (optional, from the IdP at first sign-in), `display_name` (from the IdP's `name`, else `preferred_username`, else the email's local part), `avatar`, `avatar_sha`, `avatar_type`, `deleted_at`, `created_at` | Plaintext. Avatar is a re-encoded image up to 256 KiB | Member: display name and avatar hash of every member; email only for oneself and for `manage_server` holders. App, owner role, host: all | Until the person deletes the account (then email, name and avatar are cleared; the row stays as a tombstone) | No |
| `user_identities` | `issuer`, `subject`, `user_id`, `created_at` | Plaintext | Not readable by members at all. App, owner role, host | Until account deletion. A ban copies it into `ban_identities` and that copy stays | No |
| `sessions` | `token_hash`, `user_id`, `expires_at`, `created_at`, `issuer`, `sid` | Hash of a 32 random byte token. No IP, no user agent, no device name | App, owner role, host. A hash cannot be replayed, but the owner role can insert a row with a hash it chose | `TINYSERVER_SESSION_MAX_DAYS` (30 by default), not extended by use. Swept every 10 minutes; ended by sign-out, kick, ban, back-channel logout, account deletion | n/a |
| `memberships` | `user_id`, `owner`, `created_at`, `last_seen_at`, `joined_via`, `timeout_until`. RLS | Plaintext | Member: all of it, for every member (`last_seen_at` and `joined_via` are in `GET /v1/members`). Bots with `members.read` | Until kick, ban or account deletion | No |
| `member_roles`, `roles` | Role names, colours, permission bits, positions. RLS | Plaintext | Every member | Until deleted | No |
| `invites` | `token_hash`, `created_by`, `expires_at`, `accepted_at`, `accepted_by`, `label`, `max_uses`, `uses`, `role_ids`. RLS | Hash of the token. The token itself is not stored | Holders of `create_invites` or `manage_invites` | Expired, never-accepted invites are deleted by the sweep. Accepted invites stay, with who accepted | No |
| `audit_log` | `actor_id`, `action`, `subject`, `subject_user_id`, `reason` (free text up to 512), `detail` jsonb, `created_at`. RLS | Plaintext. Display names are joined at read time, not stored | `view_audit_log` holders (and the definer functions). App, owner role, host | **Indefinitely.** No sweep touches it. Account deletion strips `display_name`, `name` and `email` keys from `detail` and keeps the ids | No |
| `rooms`, `room_overrides`, `categories` | Voice room names, topics, limits, `e2ee_required`, overrides. RLS | Plaintext | Members who can view the room | Until deleted | No. A room name is metadata even in an E2EE community |
| `channels`, `channel_overrides` | Text channel names, topics, overrides. RLS | Plaintext | Members who can view the channel | Until deleted (a delete removes its messages and attachment files) | No |
| `directs` | `low_user_id`, `high_user_id`, `created_at`. RLS | Plaintext | The two people. App, owner role, host | Until deleted. **Not removed on account deletion**: the row points at the tombstone | No. Who talks to whom stays visible |
| `messages` | `channel_id` or `direct_id`, `author_id`, `body` (up to 4000 characters), `reply_to`, `client_id`, `created_at`, `edited_at`, `deleted_at`. RLS | **Plaintext** | Members who can view the channel, or the two people of a direct. App, owner role, host | Until the author deletes it, the channel is deleted, or the account is deleted. A deleted message stays as a tombstone with author and timestamps | For a conversation created encrypted: `body` is empty and `ciphertext` (up to 32 KiB), `epoch`, `device_id`, `msg_kind` and `target_id` (`0022`) are stored; an edit is a row of its own; a delete removes the ciphertext and the edits. Author, timestamps, sizes and which message an edit targets stay visible. Plaintext conversations: no |
| `attachments` | `message_id`, `uploader_id`, `name`, `mime`, `kind`, `bytes`, `width`, `height`, `duration`, `created_at`. RLS | **Plaintext name and type** | As for the message | As for the message; unlinked uploads for at most one hour | For a sealed upload: name and type are fixed to `sealed` and `application/octet-stream`, `kind` and `scan_status` are `sealed`; the sealed size and uploader stay visible. Plaintext uploads: no |
| `reactions` | `message_id`, `user_id`, `emoji`, `created_at`. RLS | Plaintext | As for the message | Until the message or the person goes | **Not encrypted in v1**, even in an E2EE conversation (`e2ee-text.md` section 8). Shows who reacted to which message id |
| `reads` | `user_id`, `kind`, `conversation_id`, `message_id`, `read_at`. RLS | Plaintext | The person; for a direct, also the other person | Until the person is deleted | No |
| `outbox` | `topic`, `payload` jsonb, `audience` (user ids or null), `created_at` | Plaintext. Holds full message objects (bodies), member objects, channel objects with a last-message preview | Not RLS-protected; `app_runtime` can read all rows. Members receive only what the audience allows (`0013`). Owner role, host | **24 hours**, deleted by the sweep every 10 minutes. Edits and deletes rewrite earlier rows (`0014`) | Today no. Specified: ciphertext |
| `outbox_pruned` | One row: the highest deleted event id | | | | n/a |
| `idempotency_keys` | `key` (begins with the caller's user id), `request_hash`, `status_code`, `response` jsonb | Plaintext. The response for room and invite creation. Invite tokens are removed before storing (`token_unavailable`) | App, owner role, host | 1 day | n/a |
| `auth_pending` | `state_hash`, `provider`, the server's PKCE `verifier` and `nonce` (plaintext), `client_redirect` (a loopback URL with a port), client challenge and state, `invite_hash`, `signup_at` | Mixed: hashes plus the server's own provider-leg secrets | App, owner role, host | 10 minutes | n/a |
| `auth_codes` | `code_hash`, `user_id`, `client_challenge`, `issuer`, `sid` | Hash | App, owner role, host | 60 seconds, deleted on the first try | n/a |
| `bans` | `user_id`, `reason` (free text up to 512), `banned_by`, `created_at`, `expires_at`. RLS | Plaintext | `ban_members` holders | **No sweep deletes bans**, expired ones included (read of `app_sweep` and `sweep.rs`) | No |
| `ban_identities` | `issuer`, `subject`, `user_id` | Plaintext | Not readable by members. App, owner role, host | Kept after the banned person deletes their account, on purpose, so a ban survives | No |
| `bots` | `name`, `token_hash`, `scopes`, `permissions`, `created_by`, `revoked_at`. RLS | Hash | `manage_server` holders | Revoked rows stay | n/a |
| `server_settings` | Name, description, welcome text, icon bytes (up to 256 KiB), limits | Plaintext | Every member | Until changed | No |
| `reports` (`0015`) | `kind`, `category`, `reporter_id`, `reported_user_id`, `message_id`, `channel_id`, `direct_id`, `note` (up to 2000), `evidence` (up to 32 KiB, always `evidence_unverified`), `status`, `preserve`, `preserved_by`, `linked_audit_ids`, timestamps. RLS (`reports_select`); the runtime role cannot write it | Plaintext. Never a copy of a message body; `evidence` is whatever the reporter's client sent | `manage_reports` holders, except on reports about themselves. Not the reporter, not the reported person. Owner role, host | Resolved: `TINYSERVER_REPORT_RETENTION_DAYS` (default 90). Open: until triaged. Held: until released. Account deletion strips note and evidence as in [`abuse-response.md`](abuse-response.md) | No. Evidence from an encrypted conversation is plaintext the reporter disclosed |
| `report_notes` (`0015`) | `report_id`, `author_id`, `body` (up to 2000), `created_at`. RLS | Plaintext | As the report | With the report; deleted from unheld reports about a person who deletes their account | No |
| `operator_state` (`0016`) | One row: `mode`, `notice`, `since`, `legal_hold`, `legal_hold_since` | Plaintext | Runtime role: read only. Members: mode and notice through `GET /v1/status`, never the hold. Owner role writes | Current state | n/a |
| `operator_events` (`0016`) | `at`, `action` (suspend, resume, hold, release), `mode`, `reason` (up to 500) | Plaintext. No actor | Owner role and host only; the runtime role has no privilege on it | **Indefinitely** | n/a |
| `channels.e2ee`, `directs.e2ee`, `server_settings.e2ee_text`, `e2ee_group_devices_max`, `sealed_files_per_hour`, `sealed_bytes_per_day` (`0020`) | Whether each conversation is encrypted (never cleared) and the community's E2EE settings | Plaintext | Every member who can view the conversation; settings to every member | Until deleted | n/a: these are what says a conversation is encrypted |
| `e2ee_devices` (`0020`) | `device_id`, `user_id`, public `signature_key`, `cross_signature`, `label` (optional, up to 80 characters, sent by the client), `low_keys`, `created_at`, `revoked_at`. RLS; reached only through definer functions | Plaintext public keys. No private key | Every member sees every member's active devices (id, public key, cross-signature, created time; `app_e2ee_user_devices` in `0021`); the label only its owner. App, owner role, host | **Indefinitely**: revocation and account deletion set `revoked_at`, they do not delete the row or its label (finding N16) | Not encrypted: which devices a person has is visible |
| `e2ee_key_packages`, `e2ee_key_package_hashes` (`0020`) | Public MLS key packages per device (up to 50 and a last-resort one), their expiry; hashes of used ones | Public MLS objects | App, owner role, host | Claimed packages are deleted; expired ones swept; all deleted when the device is revoked | No secret |
| `e2ee_server_key` (`0020`) | One row: the server's external sender public key **and private key** | Plaintext private key | App (through definer functions), owner role, host, every backup | Indefinitely | Opens nothing; signs Add and Remove proposals (finding N15) |
| `e2ee_upload_ledger` (`0020`) | `user_id`, `bytes`, `created_at` of each sealed upload | Plaintext | App, owner role, host | Two days | Rate and volume accounting only |
| `e2ee_groups`, `e2ee_leaves`, `e2ee_pending` (`0021`) | Per encrypted conversation: the epoch; which user's which device is at which leaf and since which epoch; pending Add and Remove proposals with key packages | Plaintext metadata and public MLS objects | App, owner role, host. Members read their own group's state | While the group exists; pending rows until committed | Not encrypted: group membership by device |
| `e2ee_handshake` (`0021`) | Public proposals, commits (up to 4 MiB) and Welcomes (one per added device) per epoch | Public MLS handshake messages | Members of the group (a Welcome only for its device). App, owner role, host | Welcomes 30 days; proposals and commits while the group exists | Holds no secret that opens a message |
| `e2ee_trees` (`0021`) | Public ratchet trees of recent epochs, in parts of at most 1 MiB | Public MLS objects | Members of the group. App, owner role, host | The last 8 epochs | Public |
| `e2ee_community_root` (`0023`) | The community root public key, the policy it signed, its signature, a version | Plaintext public key and policy | Every member | Until replaced (replacing is audited) | Public |
| `_sqlx_migrations` | Migration versions and checksums | | | | n/a |

**What is not in any table:** passwords (dropped in `0004`), IP addresses, user agents, phone numbers, call history (who joined which call, for how long), message read receipts in channels beyond one cursor per person, location. A case-insensitive search of the sixteen migrations for column definitions named `ip`, `*_ip`, `*address`, `user_agent`, `agent`, `device*`, `phone*`, `location`, `country`, `city`, or of type `inet` or `cidr`, finds none (2026-10-31 for `0001`–`0014`, 2026-11-01 for `0015` and `0016`); no test asserts it. The report rate limit is counted per reporter in the database, not per address. The same search over `0020` to `0023` (#23) finds no address, agent, phone or location column; the `device*` hits are `device_id` columns (a random UUID per install) and `e2ee_devices.label`, an optional device name of up to 80 characters the client sends (finding N16). The E2EE tables are listed above. They hold no key that opens a message; `e2ee_server_key` holds the server's external sender private key (finding N15).

**Write-ahead log and dead rows.** Postgres keeps deleted and edited data in WAL and in dead tuples until checkpoints and vacuum clear them, and in any base backup or snapshot that covers that time. `DELETE /v1/me` and message deletes cannot reach these (`0014_account_deletion.sql`, "What this does not do"). Retention of WAL archives: none configured in this repository.

**Postgres server log.** The compose file leaves Postgres logging at its defaults and sends it to Docker's `json-file` driver (10 MB times 3). By Postgres's behaviour, constraint-violation errors include a `DETAIL` line with the offending key values (for instance an `(issuer, subject)` pair). Not verified for this stack's settings.

## 2. Application memory (the tinyserver process)

All of it is readable by the host and by a code-execution flaw in the process. None of it is written to disk by tinyserver, except where noted.

| What | Detail | Lifetime |
|---|---|---|
| Live sockets | The raw bearer token per socket (re-checked every 60 seconds), the user id, permissions, and per-socket queues of frames | Until the socket closes |
| Presence and call registry | Who is online, who sits in which room's call, mute, deafen, camera, share flags, server mute | Until leave. Gone on restart (calls end) |
| SFU state | Per participant: the client's network address as learned from STUN, ICE credentials, DTLS keys, RTP/SRTP state, and **the media payload in transit**: plaintext Opus and H.264 in a transport-only call, DAVE ciphertext in an E2EE call | Until the participant leaves or is dropped |
| E2EE call delivery state | Key packages waiting, the leaf tree, epoch, one batch of proposals, and the server's MLS **external sender private key** (made at start, never written or logged) | Until the call empties; the key until restart |
| Rate-limit buckets | A truncated SHA-256 of the client address (IPv6 by /64) under a per-process random secret, with hit times | 60 seconds per hit; the secret until restart |
| Secrets read at start | OIDC client secret or private key, the Pocket ID API key, the media HMAC secret, database URL | Process lifetime |
| The debug ring | About 2000 recent log lines at debug level, at most one hour old (`RING_LIMIT`, `RING_TTL` in `log_policy.rs`). On by default | Written to disk only on `SIGUSR1`; see section 5 |
| Upload processing | An uploaded file is held while it is scanned and, for images, decoded and re-encoded | Seconds |
| The OIDC key set cache | The provider's public keys | Refreshed at most every 10 seconds when an unknown key id appears |

## 3. Filesystem and volumes

| Volume or path | Contents | Form | Readable by | Kept | E2EE |
|---|---|---|---|---|---|
| `tinyserver_pg` (or `TINYSERVER_PG_DIR`) | The Postgres data directory: everything in section 1, WAL | Plaintext | Host | Until the volume is destroyed | As section 1 |
| `tinyserver_uploads` at `/data/uploads` | One file per attachment, named by random UUID | Plaintext for plaintext uploads; sealed blobs, as received, for sealed uploads (#23) | Host. The `tinyserver` container (uid 10001) | Until the message, channel or account is deleted, or the one-hour orphan sweep. Deleted with `unlink`; bytes are not overwritten | Sealed uploads: yes, ciphertext only (canary test); plaintext uploads: no |
| `tinyserver_bootstrap` | `owner-invite`: the owner invite link, the `tc1.` code (which embeds the server origin) and expiry, mode 0600 | Plaintext token | Host; the server container reads it read only | Until the next `tinyserver-init` run after an owner exists removes it (`remove_owner_invite`). **Not removed at the moment the owner signs up** | n/a |
| `/var/lib/tinyserver` (tmpfs in the server container) | `logs/bundle-<unix>.log` written on `SIGUSR1`, mode 0600 | Redacted log lines | Host | Memory only: lost on container stop. `TINYSERVER_LOG_BUNDLE_HOURS` (24) applies at the next start | n/a |
| `pocketid_data` (or `POCKETID_DATA_DIR`) | Pocket ID's SQLite database, signing key, uploads | See section 12 | Host | Until destroyed | n/a |
| `deploy/secrets/` (or `TINYSERVER_SECRETS_DIR`) | `oidc_client_secret`, `pocketid_api_key`, `pocketid_encryption_key`. The directory is 0700, the files 0444 so containers can read them as their own users | Plaintext | Host. Any process on the host that can traverse the directory; the files are world-readable inside it | Until deleted | n/a |
| `deploy/.env` | Database passwords, `TUNNEL_TOKEN`, `TINYSERVER_MEDIA_HMAC_SECRET`, public URLs and IPs | Plaintext | Host | | n/a |
| `deploy/tenant/tenants/<name>/` (or `TENANT_DIR`) | `tenant.env` (mode 0600: database superuser, owner and runtime passwords, tunnel token, media signing key, limits) and `secrets/` as above, per tenant | Plaintext | Host | Until `operator.sh delete`, which `shred -u`s the files and removes the directory | n/a |
| `tenants/<name>/backup.key`, `backup.recipient` | The tenant's age identity from `operator.sh keygen`, mode 0600, and its public recipient | Plaintext private key | Host | Until moved or `delete` shreds it. **On the same host as the data it protects** | n/a |
| `clamav_db` | ClamAV signature database | Public data | Host | | n/a |

## 4. Backups

| What | Contents | Form | Readable by | Kept |
|---|---|---|---|---|
| `operator.sh backup` bundle (#20) | `pg_dump -Fc` of the whole database (section 1, reports included), the upload volume, Pocket ID's data, the three secrets, a manifest and checksums. Not `tenant.env` | age-encrypted to the `--recipient`s and to the tenant's key if `keygen` made one. **Inside, plaintext messages and attachments today** | Holders of a matching identity: the operator, and anyone with host root while `backup.key` is on the host | Wherever the operator writes it, as long as it is kept. No schedule or expiry |
| `operator.sh export` bundle | The same, plus the compose file, `01-roles.sh` and a README | age-encrypted only to the owner's recipients | The owner | The owner's choice |
| Working copy during a backup or restore | The plaintext bundle | A tmpfs (`TINYSERVER_BACKUP_TMPFS`, 4g by default) in a throwaway container on the community's internal network, no route out | Host, process memory | The life of the helper container |
| Manual `pg_dump -U postgres tinyserver` in [`../../deploy/README.md`](../../deploy/README.md)'s Tinyauth steps | The database only | **Unencrypted** | Whoever has the file | Until deleted |

Tests: `deploy/tests/hooks.sh` (Docker and `age`; not in CI). See [`migration.md`](migration.md) section 5, [`retention-and-deletion.md`](retention-and-deletion.md) and [`findings.md`](findings.md) S11, N11.

## 5. Logs

Detail, with line-level examples and sinks, is in [`telemetry-and-logging.md`](telemetry-and-logging.md). Summary:

| Sink | Contents | Readable by | Kept | Covered by E2EE |
|---|---|---|---|---|
| tinyserver stderr to Docker `json-file` | Redacted event lines: level, target, message, allowed fields. At the default `info`: sign-in and sign-out events with `user_id`, "live socket opened/closed" with `user_id` and a connection number, moderation actions with ids, upload and message failures with ids and reasons. Docker stamps each line with a time. `peer` (client address) is always dropped | Host | 10 MB times 3 per container; by size, not by time | n/a. Contains no message text by construction |
| The in-memory ring and `SIGUSR1` bundles | Same lines at debug, including `call_id` and "media joined/lost"; `peer` addresses only when `TINYSERVER_LOG_PEER_IP=on` | Host, process memory | One hour in memory; bundles 24 hours | n/a |
| Panic and fatal-error output | The Rust default panic hook and `anyhow` exit errors write directly to stderr and **do not pass through the redactor** (`crates/server` installs no panic hook) | Host | As stderr | n/a. Contents not verified |
| Other containers' stdout/stderr | Postgres, Pocket ID (`LOG_JSON=true`), clamd, cloudflared, each to `json-file` 10 MB times 3 | Host | As above | n/a. Contents not reviewed |

## 6. Reverse proxy and Cloudflare tunnel

| What | Detail |
|---|---|
| Traffic | Cloudflare terminates TLS. It handles every HTTP request and WebSocket frame for the chat and auth hostnames in plaintext (see [`threat-model.md`](threat-model.md) 3.5). The server itself reads only `cf-connecting-ip` (for the sign-in limiter, believed only from a trusted proxy peer) |
| Credential | `TUNNEL_TOKEN` in the `cloudflared` container's environment and in `deploy/.env`. Anyone who reads it can run a connector for the tunnel |
| `cloudflared` container | Outbound only, `read_only`, capabilities dropped, memory limit 256 MB. Fixed address `172.30.53.10` on the inside network |
| Cloudflare's records | Account, DNS, tunnel configuration, request analytics and logs under whatever plan is used. Retention and access are Cloudflare's. Not reviewed |
| E2EE | Cloudflare sees ciphertext for the content of encrypted conversations and sealed files, and everything else in plaintext |

## 7. Hosting provider and host

| What | Detail |
|---|---|
| Disks and snapshots | Everything in section 3 |
| Memory | Everything in section 2 |
| Network metadata | Source and destination address, port, size and time of every packet to and from the host, including the media port: client addresses, call duration, approximate bitrate. [`network.md`](network.md) section 9 |
| Billing and account records of the hosting provider | The provider's; not reviewed |
| Hypervisor or console access | Equals root |

## 8. Network

Addresses are not in the database. They exist in: Cloudflare's edge (every HTTP client); the host's network stack and anything that records flows; the SFU's memory (media clients); Pocket ID's audit log (auth hostname clients, through `X-Forwarded-For`); the sign-in limiter's hashed buckets; the debug ring only when `TINYSERVER_LOG_PEER_IP=on`. Full treatment in [`network.md`](network.md).

## 9. Monitoring

tinyserver has no metrics endpoint, no tracing exporter and no telemetry. `GET /health` is unauthenticated and returns `ok`, `db_role`, `schema`, `media` and `transports`. Docker health checks exist for Postgres, Pocket ID and clamd. No Prometheus, OpenTelemetry, Sentry or similar library is in `Cargo.lock` (searched for sentry, posthog, segment, opentelemetry, bugsnag, rollbar, datadog, prometheus; one search, 2026-10-31). **TinyCloud's own monitoring is not built**; anything it adds is new collection and needs an entry here first.

## 10. Crash reports

None are collected or uploaded by tinyserver or tinyclient (client `SECURITY.md`: "There is no telemetry and no crash upload"). The client writes `crash.log` locally with a redacted panic. The server writes panics to stderr, unredacted (section 5).

## 11. clamd

Every attachment is sent to clamd (`clamd:3310`, `media` network) in plaintext, unless it is a sealed upload. clamd does not publish its port. It sits on a network with a route out so that `freshclam` can fetch signatures; the mirrors see the host's address. clamd's logs and any retention of scanned bytes were not reviewed. Sealed uploads are not sent to clamd at all (`a_sealed_upload_is_opaque_and_stored_as_it_came`).

## 12. Pocket ID (the auth provider in the compose file)

Third-party software, pinned to `v2.19.1-distroless` by digest. Its documentation ([environment variables](https://pocket-id.org/docs/configuration/environment-variables)) states which of its settings matter here. The compose file's settings are in `deploy/compose.yml`.

| What | Detail | Source |
|---|---|---|
| Accounts | Username, first and last name (may be blank), optional email, passkey public keys, group membership | `deploy/README.md`; Pocket ID |
| Audit log | Pocket ID keeps audit events and records the client IP address, with `AUDIT_LOG_RETENTION_DAYS` defaulting to 90 days. This stack does not set it, so 90 days applies unless the pinned version differs. The documentation page does not say which other fields (user agent, event type) are stored | Pocket ID docs, fetched 2026-10-31. Not verified against `v2.19.1` |
| Client IP | `TRUST_PROXY` is set to cloudflared's fixed address, so Pocket ID reads the forwarded client address from cloudflared | `deploy/compose.yml` |
| Geolocation | Off. No `MAXMIND_LICENSE_KEY`; `CLOUDFLARE_LOCATION_HEADERS` not set | `deploy/compose.yml`; Pocket ID docs |
| Analytics and version check | Off (`ANALYTICS_DISABLED=true`, `VERSION_CHECK_DISABLED=true`). Pocket ID is also on the `inside` network, which has no route out | `deploy/compose.yml` |
| Email | No SMTP is configured: no mail is sent, email is optional (`REQUIRE_USER_EMAIL=false`) and never marked verified (`EMAILS_VERIFIED=false`) | `deploy/compose.yml` |
| Secrets | Its encryption key and the static admin API key are files in `secrets/`. The API key acts as an administrator. tinyserver holds it too, to create sign-up tokens | `deploy/README.md` |
| Deleting a tinyserver account | Does **not** delete the Pocket ID account ([`authentication.md`](authentication.md) section 7) | No code path found |

## 13. Administrative tooling

The `tinyserver` binary's commands (`crates/server/src/main.rs`):

| Command | Needs | Reads or changes | Audited |
|---|---|---|---|
| `migrate` | `DATABASE_URL_MIGRATE` (`app_owner`) | Schema | No |
| `bootstrap` | same | Creates an owner invite if there is no owner; writes it to a file; removes the file if an owner exists | `bootstrap` when it creates one |
| `bootstrap --owner-invite` | same | A new single-use owner invite **even when an owner exists**; earlier unused owner invites stop working | `bootstrap`, `invite.revoke` |
| `identities` | same | Prints every account's user id, display name, issuer and subject to the terminal | No |
| `relink-identity` | same | Moves an account's `(issuer, subject)` | `identity.relink`, null actor |
| `operator status`, `suspend --read-only` or `--offline --notice TEXT`, `resume`, `hold [--reason TEXT]`, `release` | `DATABASE_URL_MIGRATE` | Reads or writes `operator_state`; every change adds an `operator_events` row with no actor. Run by `deploy/tenant/operator.sh` in a one-off init container | Not in `audit_log` |
| `serve` | `DATABASE_URL` (`app_runtime`) | The server | n/a |

`DATABASE_URL_MIGRATE` exists only in the `tinyserver-init` container (finding S2). The commands that need it are therefore run as `docker compose run --rm --entrypoint tinyserver tinyserver-init <command>`. [`../../deploy/README.md`](../../deploy/README.md) step 6 of "Moving from Tinyauth" and its upgrade section give these commands (finding N5, fixed). Direct SQL as `app_owner` is possible for anyone with the password and bypasses row-level security and the audit log.

## 14. Client devices (read only, at tinyclient `26916e9`)

Included because the person's device is where E2EE keys and plaintext live.

| What | Where | Form |
|---|---|---|
| Sessions for each network, including Tiny servers | OS credential store, service `tinyclient` | Protected by the OS. On macOS the access list allows any app running as the user |
| Message cache and media cache | `chat.sqlite`, `media/` | **Not encrypted at rest**; deleted rows can remain in free pages |
| Tiny call identity key | `e2ee/<account>/identity.key` | Two hex lines, mode 0600 on Unix, inherited ACL on Windows (finding C4, open) |
| Verified keys | `e2ee/<account>/verified.json` | |
| Logs | `logs/*.log`, rolled at 2 MiB, two generations; bundles only on Save debug log | Redacted lines |
| Text E2EE (tinyclient #127) | `<support>/e2ee/Tiny-<user>/text/`: the engine's snapshot (identity key, trust store, MLS groups) sealed under a state key, opened messages sealed one by one under a cache key, both keys in the account's keychain item; `notes.json` with handshake positions and verified safety numbers; sealed files waiting to upload under `e2ee/outgoing/`. Owner-only directories. **chatd's SQLite store and media cache keep opened text and files in plaintext**, as for every network | Implemented (tinyclient `the_cache_opens_only_its_own_rows_under_its_own_key`, `the_folder_is_the_owners_alone`, not run here). The plaintext store is open (finding C1) |

## 15. How this inventory was checked, and how to repeat it

| Claim | Check |
|---|---|
| The tables and columns in section 1 | `grep -n -E "CREATE TABLE\|ADD COLUMN\|DROP COLUMN" crates/db/migrations/*.sql` |
| Which tables have RLS and which grants `app_runtime` has | `grep -n -E "ENABLE ROW\|CREATE POLICY\|REVOKE ALL\|GRANT" crates/db/migrations/*.sql` |
| What the sweep deletes | `crates/db/migrations/0004_oidc.sql` (`app_sweep`), `crates/db/src/sweep.rs` |
| No address is written by the server | `grep -rn -i "peer_addr\|remote_addr\|ConnectInfo\|cf-connecting" crates --include=*.rs` finds only `limit.rs` (hashed key) and the SFU |
| Log fields and redaction | `crates/server/src/log_policy.rs`; tests `drops_body_and_access_token_keeps_user_id`, `redacts_bearer_pem_jwt_ice_and_userinfo`, `peer_is_operator_blind_and_ring_gated` |
| The compose settings quoted | `deploy/compose.yml` |
| Telemetry libraries | `grep -n -i -E 'name = "(sentry\|posthog\|segment\|opentelemetry\|bugsnag\|rollbar\|datadog\|prometheus)' Cargo.lock` |

A test that fails when a new migration adds a column named like an address, agent or device would turn two of those rows from "read" into "enforced". It does not exist.
