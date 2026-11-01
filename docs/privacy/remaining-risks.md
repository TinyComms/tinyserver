# Remaining risks

What has not been independently reviewed, what attack surface is left, which assumptions the rest of these documents stand on, and where anonymity and end-to-end encryption (E2EE) stop. It is the honest end of the matrix in [`guarantees.md`](guarantees.md). Status words are in [`README.md`](README.md). The findings that were fixed are in [`findings.md`](findings.md); this file is about what remains after them.

**No independent security review, penetration test or cryptographic audit of tinyserver or tinyclient has taken place.** Nothing in the repository or in the documents read for these files says otherwise. Every "implemented, tested" in the other documents means a test written by the authors passes, not that a third party tried to break it.

## 1. What needs independent review, in priority order

| # | Area | Why | Where |
|---|---|---|---|
| 1 | **Text and attachment E2EE design and implementation** (server #23, client tinyclient #126 and #127) | New cryptographic state machine. `e2ee-text.md` section 12 lists what the authors themselves cannot cover with tests: the group-state machine under network partitions, the safety-number construction beyond what the MLS exporter provides, key package exhaustion attacks, the sealed-blob format. Additional items found while writing these documents: the use of a server as the MLS external sender with **client-side** enforcement of cross-signed credentials (a client bug removes the protection); reuse of the `last_resort` key package after exhaustion; the server's persistent external sender private key, which is a row in Postgres and so in every backup (finding N15, G9); commit races and epoch rollback detection; whether the AAD binding of the header and `conversation_id ‖ attachment_id` is sufficient, and the unbound case when the client did not choose the id; removal latency when no member is online | [`../e2ee-text.md`](../e2ee-text.md), [`encryption-architecture.md`](encryption-architecture.md) |
| 2 | **Call E2EE** (implemented) | Based on DAVE with the `davey` crate and a server delivery service built on `openmls`. MLS ids are 64-bit hashes of user ids (a roster check is the defence, finding S10). Sender keys are shared by every member and frames are unsigned (a member can forge another's audio). The identity key is a plaintext file (finding C4). The server can downgrade a call. The roster comes from the server. Video sealing is not verified (client `SECURITY.md` and code disagree) | `crates/api/src/live/e2ee.rs`, client `crates/mediad/src/e2ee.rs` |
| 3 | **Authorization in SQL** | Roles, overrides, hierarchy, audience narrowing, bans and invites are enforced in about 2,600 lines of SQL across `0005_server.sql` and `0008_messages.sql` (mostly functions and policies), with `SECURITY DEFINER` functions that must set `search_path` and check the caller themselves. `users`, `sessions` and `idempotency_keys` have no row-level security. The caller identity comes from a per-request setting (`app.user_id`). A flaw in a definer function, or a query that forgets the setting, is a cross-member read or privilege escalation | `crates/db/migrations/`, `crates/db/src/` |
| 4 | **Sign-in and session handling** | Custom verification around the `openidconnect` crate (allowed algorithms, `azp`, `iat` window, back-channel logout token validation, the loopback redirect rules, the one-time code), the server-rendered `/v1/auth/join` page (HTML, CSRF, framing), the sign-up token flow with a powerful Pocket ID API key, sessions that are bearer secrets with no binding | `crates/api/src/auth.rs`, `oidc.rs` |
| 5 | **Parsers exposed to the internet** | str0m's STUN, DTLS and SRTP handling on the open media port; the hand-written RFC 4571 framing for ICE-TCP; SDP offer handling; WebSocket frame handling; multipart upload parsing; image decoding and re-encoding and the zip central-directory parser run **in the server process** on untrusted bytes; the clamd protocol client and YARA rules. Fuzz targets exist and CI runs each for 60 seconds (`docs/calls.md`); that is a smoke test, not a campaign | `crates/sfu`, `crates/api/src/messages.rs`, `fuzz/` |
| 6 | **Deployment and secrets** | `deploy/compose.yml` and `pocket-id/setup.sh`: secret files are mode 0444 inside a 0700 directory; `tinyserver-uploads` runs as root with `CHOWN`; `docker/postgres/init/01-roles.sh` now passes identifiers and passwords as psql variables quoted by psql (`:'x'`, `%L`, `%I`), so the quoting risk noted earlier is gone at `c4ae28b` (read; `deploy/tests/roles.sh` exercises the script); `deploy/tenant/operator.sh` (560 lines of shell that runs `pg_dump`, `pg_restore`, `tar` and `age` with superuser and owner passwords in a helper container's environment) and `tenant.sh`, reviewed by nobody outside the authors; the tunnel token and HMAC secret in `.env`; the `media` network's route out | `deploy/`, `docker/` |
| 7 | **Multi-tenant isolation** | The contract is [`tenancy.md`](tenancy.md) and the authors' checks are `deploy/tests/isolation.sh` and `roles.sh` (Docker; not in CI). Nobody else has tried to cross tenants. Still out of the repository's reach: the shared kernel, the host's UID ranges, cgroups, nftables, the metadata address, disk encryption, and the TinyCloud provisioning that would run `tenant.sh` | `deploy/tenant/`, `deploy/tests/`, `docker/postgres/init/01-roles.sh` |
| 8 | **Operator access** | The operator can sign in as any member, become owner, read the database and every abuse report, open any backup encrypted to its recipient, and roll a community back with `restore` ([`threat-model.md`](threat-model.md) 3.7). `operator_events` records suspensions and holds without an actor; nothing records reads. No staff access control or approval process exists to review | Not built |
| 9 | **tinyclient** | The window decodes images from other people in the GUI process; the local socket is unauthenticated; the cache and the call identity key are unencrypted; macOS releases are ad-hoc signed; the updater's integrity is weak (finding C6). The client's own `SECURITY.md` states these | tinyclient |
| 10 | **Supply chain** | `Cargo.lock` is committed and images are pinned (Pocket ID and the setup curl image by digest). No `cargo audit` or `cargo deny` configuration was found in the repository. `str0m` releases break the API every few weeks (`docs/calls.md`). Reproducible builds and image signature checks: not verified | `Cargo.lock`, `deploy/` |

Recommended scope for a first engagement: items 1 to 4 together, because the design review of the E2EE (1) depends on how identity (4) and authorization (3) bind devices to people.

## 2. Residual attack surface

| Surface | Who can reach it | Controls in place | What is left |
|---|---|---|---|
| `GET /health` | Anyone | Fixed JSON fields | Reports `db_role` and schema and media state to strangers. Minor information disclosure |
| `/v1/auth/*` | Anyone | Rate limits (5 a minute per address, 120 in all; 3 and 30 for the join page), PKCE, `state`, one-time codes | A global cap of 120 a minute is a denial-of-service lever against sign-in. Limits are keyed by address and the address is not available behind an untrusted proxy |
| Media port, UDP and TCP | Anyone | Per-source packet budget, STUN only from unknown sources, TCP stream caps | A volumetric flood fills the one media thread, the kernel or the link. No upstream mitigation (Cloudflare does not proxy UDP on the plans assumed) |
| Authenticated REST | A member | Permissions and row-level security, per-file size caps, scan gate | No per-user rate limit, no storage or request quota: a member can fill the disk and database and spend CPU |
| Live socket | A member | Per-user (3) and total (1,024) socket caps, 20 frames a second per socket, 64 KiB frames | 1,024 sockets can be held by a few accounts |
| Uploads | A member | Type policy, re-encode, scan, size limits | Parsers in the server process; sealed uploads (#23) are not parsed or scanned at all, beyond the blob's framing |
| Bots | Holders of a bot token | Scopes | A token is a bearer secret; `members.read` shows presence and the member list |
| Code execution in tinyserver | Via a parser or logic flaw | Read-only root, no capabilities, limits, no owner password, no route to Postgres owner | All community data via `app_runtime`; memory secrets; the route out of the `media` network |
| Cloudflare account and tunnel token | Whoever holds them | None in the application | Serve a fake origin; read traffic ([`threat-model.md`](threat-model.md) 3.5) |
| Pocket ID | Its administrator and API key holder | Pinned image, read-only root, no route out | Can sign in as anyone; creates accounts; holds an IP audit log |
| Host | Operator, provider | None possible | Everything not sealed |
| tinyclient devices | Other local users and processes | OS permissions | See `SECURITY.md` "Known limits" |
| Backups | Whoever holds the file and a matching age identity | `operator.sh` encrypts with age; plaintext only in a tmpfs inside a container with no route out (`deploy/tests/hooks.sh`) | The tenant's key sits on the same host as the data until moved; the operator's key opens everything encrypted to it; a restore resurrects deleted data (N11) |
| Operator hooks | Anyone who can run Docker on the host | They listen on no port; `tinyserver operator` needs the owner password | Whoever has Docker on the host has everything anyway |

## 3. Assumptions

These are the premises the other documents rest on. If one is false, the dependent guarantees fail.

1. The Rust standard library, `sqlx`, `axum`, `str0m`, `openmls`, `davey`, `aws-lc-rs` and the RustCrypto crates behave as documented.
2. MLS (RFC 9420), DAVE, AES-GCM, P-256 ECDSA and the STREAM construction are correctly composed by the specifications. No review of the composition has been done.
3. The operating system's keychain protects secrets from other users, and the random-number source is sound.
4. Cloudflare delivers traffic faithfully (it can do otherwise; see category 4 in [`guarantees.md`](guarantees.md)).
5. Docker enforces the isolation, capability and network restrictions in `deploy/compose.yml` as configured, including `internal: true` on `inside`.
6. Pocket ID `v2.19.1` and its configuration behave as its documentation says. Its source was not reviewed.
7. The host's clock is roughly correct.
8. One community per stack, one stack per tenant ([`tenancy.md`](tenancy.md)).
9. People verify safety numbers and call codes if they depend on them for protection against the server.
10. The client binary a person runs is the one built from the public source.

## 4. The limits of anonymity

TinyComms is not an anonymity system. A person is anonymous toward some parties and not toward others.

| Toward | What they can learn |
|---|---|
| Other members | Display name, avatar, roles, when they joined and how (invite or group), **`last_seen_at` for everyone** (visible to all members through `GET /v1/members`), whether they are online, which call they are in and when, whom they reacted to, their direct conversation's read cursor, their messages and timing. An invite links a person to whoever invited them |
| The community's administrators | The above, plus an email address if the sign-in provider sent one (`manage_server`), the audit log, bans and reasons |
| The community's moderators (`manage_reports`) | Every report a person filed, with who filed it, and every report about them unless the moderator is its subject; the reporter's note and the evidence their client sent. The reported person is not told who reported, but may infer it (the only other person in a direct) ([`abuse-response.md`](abuse-response.md)) |
| Another community the same person joined | Nothing by tinyserver's design. The same email, name, avatar, writing style, join times, or a shared identity provider would link them |
| Cloudflare and the host's network | A person's IP address and when they connect |
| TinyCloud | Which payer owns which tenant; everything the operator can read; no payer-to-member link unless it builds one |
| The identity provider | The username, the passkey, an email if entered, and the client address in its audit log. In a managed tenant that provider is run by TinyCloud or the owner |
| A network adversary that sees two endpoints | Timing and volume correlation between a person's traffic and the host's. Not defended against |

Things that weaken anonymity without any provider acting: a display name or avatar that is recognisable; the member list visible to every member; presence and call occupancy visible to every member; the fact that a community's owner knows whom they invited; a person's own device (E2EE keys, notification previews). A person who needs anonymity from their own community needs a username and avatar that do not identify them, no email at the provider, and an address that does not either; this is [`authentication.md`](authentication.md) section 3 plus a VPN or proxy of their own. The client's HTTP headers (for example `User-Agent` and version strings) as seen by Cloudflare and the host were not reviewed.

## 5. The limits of E2EE

What E2EE here does and does not do, for the product page and for support.

| Limit | Detail |
|---|---|
| Members | Anyone in the conversation can copy, forward, screenshot or leak what they receive, and a member who is added later cannot read the past but can read the future |
| Metadata | The server sees who is in a conversation, who posted and when, sizes, counts, reactions, presence, call membership and the audio level in calls ([`metadata.md`](metadata.md)) |
| Endpoints | A compromised or unlocked device reads everything it can. The local cache and the call identity key are not encrypted at rest (findings C1, C4). The OS may show notification previews |
| First device | Trust on first use. A server present when a person first registers can substitute that device. Safety numbers compared out of band are the only defence |
| A person with no devices | The operator can add one for them (`e2ee-text.md` section 3) |
| Downgrade of calls | The server can turn a call to transport only, visibly. An app in "require" mode blocks instead; that mode is off by default |
| Roster and ghost members | The server proposes members. Apps refuse unlisted or non-cross-signed ones, but the roster of a call is server-provided (finding S10). A verified safety number is the check |
| Forgery inside a group | Calls: any member can make frames that look like another's. Text: authors are authenticated by MLS |
| Reactions | Plaintext in v1 |
| Availability | The server can withhold, delay or drop anything. E2EE protects confidentiality and integrity, not delivery |
| Key loss | Losing every device means a new identity and no history. There is no key backup in v1 |
| No history for new devices | By design |
| Removal | A removed member stops receiving new ciphertext at once and loses future keys at the next commit; if no member is online the commit waits. They keep what they already have |
| Moderation and abuse | No moderator delete in encrypted conversations in v1; the server cannot scan sealed files or read content. Handling depends on reports, whose evidence is whatever the reporter's client sends and cannot be verified ([`abuse-response.md`](abuse-response.md)) |
| Search and previews | Client-side only |
| Regulation | Pending proposals could reach E2EE services ([`compliance.md`](compliance.md) section 8.5) |
| Review | Not independently reviewed (section 1) |

## 6. Unknowns this documentation set could not resolve

| Unknown | Where it matters |
|---|---|
| Pocket ID `v2.19.1` audit log fields and retention in practice | [`metadata.md`](metadata.md) section 12 |
| Cloudflare's retention, regional options, and what cloudflared reports to Cloudflare | Category 4; residency |
| Contents of Postgres, Pocket ID, clamd and cloudflared logs | [`telemetry-and-logging.md`](telemetry-and-logging.md) |
| Whether tinyclient's video sealing runs in a real call | G1.2 |
| The client's update endpoint and what it sends | G3.10 |
| Whether `migrate` fails when the database is ahead of the binary | [`migration.md`](migration.md) section 2 |
| Whether the Docker `json-file` logs and the host's journal are accessible to anyone beyond root | Operator controls |
| Whether a no-email configuration works end to end | [`authentication.md`](authentication.md) section 3 |
| Cost and capacity numbers | [`performance.md`](performance.md) |
