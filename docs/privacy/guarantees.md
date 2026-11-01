# The matrix of privacy guarantees

This is the reference for what TinyComms, run as a managed service (TinyCloud), can and cannot promise about privacy. Every other document in this directory feeds it. Each guarantee has an ID, a status and an **Evidence** cell that names a test, a file, or says "not verified". If a row has no test, it says so.

State described: tinyserver branch `hardening/privacy-docs` on `ea3cd39` plus the documents in this directory; tinyclient `26916e9` read only. **Text and attachment E2EE is in progress and not merged** ([`../e2ee-text.md`](../e2ee-text.md)). Every row that depends on it is marked **E2EE-text: not yet verified** and must not be advertised. A final verification pass will update the statuses; section 7 lists the rows that change.

## 0. How to read this

**The five categories** (used the same way in every document in this directory):

| # | Category | What it means | Strength |
|---|---|---|---|
| 1 | Information the server **cryptographically cannot decrypt** | The server holds ciphertext and no key. No operator action changes that | Enforced by cryptography. Holds against the operator, the host and a court order served on them (they have nothing to read) |
| 2 | Information whose access is **operationally restricted** | The server holds it in a readable form. Software and deployment choices restrict who can read it. Someone with enough access (the database owner role, host root, a compromised process) can read it | Enforced by code and configuration, not by cryptography. Honest wording must say "restricted", never "cannot" |
| 3 | Information the provider **chooses not to collect** | The product has no field, table or log line for it | A design choice. It holds as long as the code is the code that runs; an operator could add collection |
| 4 | Information **necessarily visible to infrastructure providers** | Cloudflare, the hosting provider and the network see it because of where they sit | Cannot be removed by any change to tinyserver or tinyclient |
| 5 | Information **retained for billing, security or compliance** | Kept on purpose, for a stated reason and a time | A policy and a record, which this table lists so it can be bounded |

**Status words:** *Implemented, tested* (a test named in Evidence fails if the property breaks); *Implemented* (code does it, no test asserts it); *Designed* (written down, not built); *In progress* (being built elsewhere, not merged); *Not done*; *Not verified*.

**Evidence** is a test (path and name), a file, a document, or "not verified". A claim backed only by a document in this repository is as good as that document; where it was cross-checked against code, it says so.

## 1. Category 1: the server cannot decrypt it

| ID | Guarantee | Status | Evidence | Conditions and limits |
|---|---|---|---|---|
| G1.1 | In a call where every app joined with E2EE, the server and Cloudflare cannot decode **voice** | Implemented, tested | `crates/api/tests/e2ee.rs`: `three_apps_agree_on_a_code_the_server_cannot_know`, `only_the_seat_holder_speaks_mls_and_only_as_itself`; `crates/api/src/live/e2ee/tests.rs` (ten unit tests); the module holds no group secret (`crates/api/src/live/e2ee.rs`, header and structs). Client side not re-run | **Not always on.** One app that cannot encrypt turns the call to transport only; a hostile server can send `off` or claim someone cannot encrypt. The apps say so loudly (test `an_app_that_cannot_encrypt_turns_the_call_to_transport_only_unless_required`). Opt-in "require" mode in tinyclient blocks instead (finding S4). Sender keys are shared by members, so a member can forge frames as another. RTP headers and the audio level stay in clear |
| G1.2 | In an E2EE call, **video and screen share** are sealed by the same group | Implemented in the client at `26916e9` (`crates/mediad/src/e2ee.rs` `seal_video`, `tiny.rs`); server seals nothing | The client's `SECURITY.md` says "video ... not end-to-end encrypted ... this release seals only audio". It contradicts the client code and `docs/calls.md`. **Not verified by a running call** | The one byte H.264 NAL header stays clear. Do not advertise until verified |
| G1.3 | Text, edits and reply text of an **encrypted conversation** cannot be read by the server | **In progress**. E2EE-text: not yet verified | `docs/e2ee-text.md` sections 1, 4 to 6, tests listed in section 11 (not run here) | Only conversations created encrypted. Existing conversations are never converted (G2.1 applies to them). Members can copy anything they can read |
| G1.4 | Attachment **contents, names and types** of a sealed attachment cannot be read by the server | **In progress**. E2EE-text: not yet verified | `docs/e2ee-text.md` section 5 | The server does not scan sealed files |
| G1.5 | The server stores no key that opens an encrypted message or call frame | Calls: implemented (design and code reading). Text: **in progress** | Calls: `live/e2ee.rs`. Text: the specification says no table holds such a key; the server's persistent external sender key can sign proposals only. Not verified | The external sender key lets a server propose members; clients must refuse unlisted or uncross-signed ones (client behaviour, needs review) |
| G1.6 | A device added to an encrypted conversation must be approved by one of the person's own devices | **In progress**. E2EE-text: not yet verified | `docs/e2ee-text.md` section 3 | First device is trust on first use; a person with no device is vulnerable to the operator ([`threat-model.md`](threat-model.md) 3.7) |
| G1.7 | A restore of an old database backup cannot silently roll an encrypted conversation back | **In progress**. E2EE-text: not yet verified | `docs/e2ee-text.md` section 9 | |

What category 1 does **not** contain: any existing text, any attachment in a plaintext conversation, calls in transport-only mode, call and conversation **metadata** (who, when, how big), reactions, names, topics.

## 2. Category 2: operationally restricted

The operator and anyone with the database owner role or host root can read these today. Wording must be "other members cannot", "is not delivered to", "is not stored", never "the operator cannot".

| ID | Guarantee | Status | Evidence | Conditions and limits |
|---|---|---|---|---|
| G2.1 | A message in a plaintext conversation is delivered and returned only to members who can view it | Implemented, tested | `crates/api/tests/messages.rs`: `a_private_channels_events_reach_only_members_who_can_view_it` (live socket, replay and outbox), `a_direct_message_is_not_delivered_to_a_third_member`; migrations `0008`, `0013` | The audience is fixed when the event is emitted; a member who gains access later does not get earlier events (finding S1). Plaintext in Postgres, WAL, backups, and visible to the host |
| G2.2 | Only the person and `manage_server` holders can read an email address | Implemented, tested | `crates/api/tests/privacy.rs`: `a_member_sees_their_own_email_and_not_another_members` | `app_runtime` can read `users` in full: the limit is in the application's query (no RLS on `users`) |
| G2.3 | Session, invite, bot token, one-time code and sign-in state are stored as SHA-256 hashes, not values | Implemented | `crates/db/migrations/0001_init.sql`, `0004_oidc.sql`, `0012_bots.sql` (`token_hash`, `code_hash`, `state_hash`, `invite_hash`); `crates/db/src/session.rs` (32 random bytes). No test asserts it | The `auth_pending` row holds the server's own PKCE verifier and nonce in plaintext for 10 minutes. The owner role can insert a session with a hash it chose |
| G2.4 | An invite token is never stored; an idempotent replay returns `token_unavailable` | Implemented, tested | `crates/api/tests/http.rs`: `an_invite_lets_a_person_in_once_and_not_after_it_expires` (asserts the replay has no token and the table holds no copy, per `findings.md` S5) | Owner invite link is written once to a file on a volume (mode 0600) and persists until the next init after an owner exists |
| G2.5 | The serving process does not hold the database owner credentials | Implemented. Verified by hand, not by an automated test | `deploy/compose.yml` (`tinyserver-init` holds `DATABASE_URL_MIGRATE`, the server holds only `DATABASE_URL`); `findings.md` S2 | A flaw that runs SQL as `app_runtime` is not contained |
| G2.6 | The runtime role cannot write the live-event history directly | Implemented, tested | `crates/api/tests/live.rs`: `the_runtime_role_cannot_write_the_outbox_directly` | |
| G2.7 | Roles, bans and permissions are enforced in Postgres by row-level security and definer functions | Implemented, tested | `crates/api/tests/server.rs`: `roles_follow_the_hierarchy`, `overrides_shape_room_permissions_and_visibility`, `a_ban_removes_the_person_and_keeps_them_out`; `crates/api/tests/http.rs`: `an_admin_cannot_change_or_remove_an_owner`, `the_last_owner_cannot_be_demoted_or_removed` | |
| G2.8 | A bot can do only what its scopes allow, receives no message frames, and cannot be a member | Implemented, tested | `crates/api/tests/bots.rs`: `a_bot_can_do_only_what_it_was_granted`; `crates/api/tests/bot_live.rs` | |
| G2.9 | Attachments in plaintext conversations are downloadable only by people who can see the message (or the uploader for an hour), through a session or a valid signed URL, and only after a clean scan | Implemented, tested | `crates/api/tests/messages.rs`: `a_scanning_attachment_download_is_locked`, `a_message_cannot_name_an_unscanned_attachment`, `a_bad_hmac_is_refused`, `an_eicar_upload_is_blocked` | clamd sees the plaintext. Files are plaintext on disk |
| G2.10 | Operator logs contain no message text, file names, tokens, emails, display names, SDP or OIDC codes | Implemented, tested | `crates/server/src/log_policy.rs` tests `drops_body_and_access_token_keeps_user_id`, `redacts_bearer_pem_jwt_ice_and_userinfo`; `crates/api/tests/signup_logs.rs`: `the_api_key_and_signup_tokens_never_reach_the_logs` | Panic and fatal-error output bypass the redactor. A new log call with an unlisted field name is not caught. Ids and connection times are logged (G5.4) |
| G2.11 | The sign-in limiter does not store addresses and cannot be bypassed by forging a header | Implemented, tested | Nine unit tests in `crates/api/src/limit.rs`; `crates/api/tests/limit.rs` | Only three routes are limited (see [`network.md`](network.md)) |
| G2.12 | Containers run read-only, without capabilities, with memory and process limits; the sign-in provider and Postgres have no route out | Implemented | `deploy/compose.yml`. Not tested automatically | `tinyserver` and `clamd` are on `media`, which has a route out |
| G2.13 | A deleted account's name, email, picture, identity and sessions are removed, its messages emptied | Implemented, tested | `crates/api/tests/privacy.rs`: `deleting_an_account_removes_the_person_and_what_they_said` | See G5.9 and [`retention-and-deletion.md`](retention-and-deletion.md): WAL, backups, devices, the Pocket ID account and audit `reason` text are not reached |
| G2.14 | Sessions end on sign-out, sign-out everywhere, provider back-channel logout, kick, ban and expiry; live sockets close | Implemented, tested | `crates/api/tests/http.rs`: `an_owner_reads_me_and_signs_out`; `crates/api/tests/account.rs`; `crates/api/tests/auth.rs`: `back_channel_logout_ends_the_sessions_the_provider_names`, `a_session_from_sign_in_ends_after_the_configured_days`; `crates/api/tests/live.rs`: `sign_out_and_a_provider_logout_close_other_sockets`, `a_removed_member_is_closed_with_4003` | A stolen token works until revoked or expired (not bound to a device or address) |
| G2.15 | Staff access to tenant data is limited and logged | **Not built.** Policy only | None. See [`threat-model.md`](threat-model.md) 3.7 | Must not be described as a technical guarantee |
| G2.16 | Uploaded plaintext images are re-encoded and risky types refused | Implemented, tested | `crates/api/tests/messages.rs`: `an_html_upload_is_unsupported_media`, `a_pe_named_as_png_is_unsupported_media`, `a_zip_is_unsupported_until_the_server_allows_archives` | Not a privacy property; listed because it affects what the server parses |

## 3. Category 3: the provider chooses not to collect

| ID | We do not collect | Status | Evidence | Conditions and limits |
|---|---|---|---|---|
| G3.1 | Passwords | Implemented | `0004_oidc.sql` drops `users.password_hash`; sign-in is OIDC only. `crates/api/tests/auth.rs` covers sign-in end to end | The identity provider has its own credentials (passkeys) |
| G3.2 | IP addresses, user agents, device names, phone numbers in the database | Implemented. No test asserts it | Search of the fourteen migrations for such column definitions finds none ([`metadata.md`](metadata.md) section 1); `crates/api/src/limit.rs` stores only a keyed hash for 60 seconds in memory | Cloudflare, the host and Pocket ID see addresses (category 4, G5.5). The SFU holds client addresses in memory during a call |
| G3.3 | Client addresses in logs | Implemented, tested | `peer_is_operator_blind_and_ring_gated` | `TINYSERVER_LOG_PEER_IP=on` lets the debug ring hold them |
| G3.4 | Telemetry, analytics, crash uploads, version checks from tinyserver | Implemented | `Cargo.lock` has none of sentry, posthog, segment, opentelemetry, bugsnag, rollbar, datadog, prometheus; the only HTTP client is the OIDC one (`crates/api/src/oidc.rs`). Pocket ID: `ANALYTICS_DISABLED`, `VERSION_CHECK_DISABLED` in `deploy/compose.yml`. No test | Docker, the host, cloudflared and clamd were not reviewed |
| G3.5 | Call history: who joined which call, when, for how long | Implemented | `docs/calls.md` ("Audit call joins? No"); the call registry is memory only (`crates/api/src/live/call.rs`). No test asserts nothing is stored | The info-level log records socket open and close with `user_id` (G5.4); per-call `call_id` lines exist. Moderation actions in calls are audited |
| G3.6 | Call recordings | Implemented | `docs/calls.md` ("Recording? None. The SFU never writes media to disk"). Not tested | |
| G3.7 | Government ID, phone number, a required email | Implemented | Sign-up needs an invite and a passkey. `REQUIRE_USER_EMAIL=false` in `deploy/compose.yml`. A no-email configuration (`TINYSERVER_OIDC_SCOPES=openid profile`) is untested ([`authentication.md`](authentication.md) section 3) | Payer details are a separate matter (G5.6) |
| G3.8 | A link between a person's accounts in different communities | Implemented | One database and one identity provider per stack; no shared store ([`authentication.md`](authentication.md) section 8) | Holds only if each tenant has its own provider. A shared or external provider could link; TinyCloud's billing and network layers can |
| G3.9 | Message read receipts in channels, typing history | Implemented | A channel read is stored per person as one cursor and not broadcast; typing is not stored (`docs/server.md`) | A direct's read cursor is shown to the other person |
| G3.10 | Telemetry from tinyclient | Implemented per the client's own documents; **not re-verified** | tinyclient `SECURITY.md`, `docs/logging.md` | The client asks GitHub for releases and Wikipedia for linked articles |

## 4. Category 4: necessarily visible to infrastructure providers

None of this can be hidden by changing tinyserver or tinyclient. Details and sources are in [`network.md`](network.md) section 9 and [`threat-model.md`](threat-model.md).

| ID | Provider | Sees | Evidence |
|---|---|---|---|
| G4.1 | Cloudflare (tunnel, chat and auth hostnames) | Every HTTP request and WebSocket frame in the clear: bearer tokens, plaintext content (until E2EE), ciphertext (after), uploaded files, client addresses, timing, sizes. It can also replace the origin | Architecture of a proxied hostname; `deploy/compose.yml`. Cloudflare's policies not reviewed |
| G4.2 | The hosting provider and anyone with host root | Disk, memory, secrets, Docker logs, every packet metadata including media-port client addresses, call duration and rough bitrate | [`threat-model.md`](threat-model.md) 3.6; `deploy/compose.yml` publishes the media port |
| G4.3 | Network path (ISP, Wi-Fi) | That a person talks to Cloudflare and to the host, when, how much | Inherent |
| G4.4 | Other call participants | The roster, mute, camera, share and speaking state, and the host's public IPv4 (and LAN IP if configured). Not each other's addresses | `docs/calls.md`; `crates/sfu/src/engine.rs` `candidates`. **No test asserts non-disclosure of client addresses** |
| G4.5 | The SFU process and host | All media-path addresses, call timing, packet sizes; payload in transport-only calls | `docs/calls.md` |
| G4.6 | Pocket ID (identity provider) | Username, optional email, passkey public key, client address (audit log) | `deploy/README.md`; Pocket ID docs; [`metadata.md`](metadata.md) section 12 |
| G4.7 | ClamAV signature mirrors | The host's address (freshclam) | `deploy/compose.yml`. Not reviewed beyond that |
| G4.8 | GitHub, Wikipedia, `tinyclient.io` | A client's address when it checks for updates, resolves a linked article, or when someone opens an invite page | tinyclient `docs/architecture.md`; `site/invite/invite.js`. Update endpoint not located |
| G4.9 | DNS and registrar | The hostnames | Inherent |
| G4.10 | Payment processor | Whatever the payer gives it | Not built |

## 5. Category 5: retained for billing, security or compliance

Everything TinyCloud keeps on purpose. Each needs a reason and an end date before launch. The ones marked "not built" are the ones to design under [`compliance.md`](compliance.md).

| ID | Retained | Why | Kept | Status |
|---|---|---|---|---|
| G5.1 | `audit_log`: moderation and settings actions with ids and free-text reasons | Moderation record | Indefinitely, no sweep | Implemented. No expiry. `reason` is not scrubbed on account deletion |
| G5.2 | `bans` and `ban_identities` | A ban must survive deletion and re-sign-up | Indefinitely, expired bans included | Implemented |
| G5.3 | `memberships` including `last_seen_at`, `joined_via`; accepted invites | Operation | While a member; accepted invites indefinitely | Implemented |
| G5.4 | Operator log lines at `info`: sign-in, socket open and close with `user_id`, moderation, per-call media events | Operation and incident response | `json-file` 10 MB times 3 per container, with Docker timestamps | Implemented. **This is a connection history.** Can be turned down (`TINYSERVER_LOG_LEVEL`) |
| G5.5 | Pocket ID's audit events with client IP | The provider's own security log | 90 days by default; not verified for `v2.19.1` | Third party. Setting `AUDIT_LOG_RETENTION_DAYS` is possible |
| G5.6 | Billing records: plan, payment token or transaction id, invoices, tax evidence | Payment, tax | Not defined | **Not built** |
| G5.7 | Tenant to payer mapping | To provision and bill | Not defined | **Not built**; necessary |
| G5.8 | Abuse reports, decisions, statements of reasons, legal-process records, disclosure ledger | Compliance | Not defined | **Not built** ([`abuse-response.md`](abuse-response.md)) |
| G5.9 | Preserved copies under a hold or after a report | Legal obligation | One year after a CyberTipline report under the cited statute; 90 days for a government preservation request | **Not built** |
| G5.10 | Backups | Recovery | Not defined | **Not built** ([`migration.md`](migration.md)) |
| G5.11 | Postgres WAL and dead rows; Cloudflare logs; hosting provider logs | Operation | Their policies | Not reviewed |
| G5.12 | A ledger of deleted account ids to replay after a restore | Honour erasure after restore | Not defined | **Not built** |

## 6. What can honestly be advertised today

Wording that is true for the code and tests in this repository. Each line names the guarantees it rests on and the caveat that must travel with it. Add a caveat only if it is short; the long form belongs on the page that explains it.

| # | Wording | Rests on | Caveat to include | Evidence |
|---|---|---|---|---|
| A1 | "Sign in with a passkey. TinyComms keeps no passwords." | G3.1 | A community can choose another sign-in provider | `0004_oidc.sql`; `crates/api/tests/auth.rs` |
| A2 | "Voice calls between TinyClient apps are end-to-end encrypted when everyone in the call is using an app that supports it. If someone isn't, the call is encrypted only as far as the server, and every app tells you." | G1.1 | The server can force the lower mode but cannot hide it. Say "voice" only until G1.2 is verified | `crates/api/tests/e2ee.rs` |
| A3 | "The server doesn't store your IP address, and its logs don't include it. Cloudflare, which carries your connection, and the network the server runs on can see it." | G3.2, G3.3, G4.1, G4.2 | Name Cloudflare and the host in the same sentence | Schema search; `peer_is_operator_blind_and_ring_gated` |
| A4 | "Members who can't see a channel never receive its messages." | G2.1 | This says nothing about the operator. Do not write "private from us" | `a_private_channels_events_reach_only_members_who_can_view_it` |
| A5 | "You can delete your account. It removes your name, email and picture, empties every message you wrote and ends your sessions. Backups, logs, other people's copies and your sign-in account are separate." | G2.13 | State the exclusions | `deleting_an_account_removes_the_person_and_what_they_said` |
| A6 | "No analytics, no crash reporting and no tracking in the TinyComms server." | G3.4 | For the app: "the app checks GitHub for updates and fetches Wikipedia summaries for links" | `Cargo.lock` search; client docs not re-verified |
| A7 | "Our server logs don't contain message text, file names, tokens, email addresses or display names." | G2.10 | Say "by default"; do not say "no logs" | `log_policy.rs` tests; `signup_logs.rs` |
| A8 | "You don't need an ID document or a phone number to join a community." | G3.7 | About joining, not about paying | Invite and passkey flow in `crates/api/tests/auth.rs` |
| A9 | "We don't record who is in which call, or for how long." | G3.5 | Only if the log level for tenants is lowered, or add "our logs record that a connection opened and closed" | **Not true as stated for the default log level** (G5.4); advertise only after item 1 of [`telemetry-and-logging.md`](telemetry-and-logging.md) section 6 |
| A10 | "Encrypted text and file sharing is in development." | G1.3, G1.4 | Say "in development", never "available" | `docs/e2ee-text.md` |
| A11 | "Each community runs in its own isolated stack." | G2.12 and [`tenancy.md`](tenancy.md) | **Designed**, not built as a service. Advertise only once provisioning exists and the checks in `tenancy.md` pass | `deploy/compose.yml` for one stack |

A9 is listed here so nobody writes it. It is **not** advertisable today.

## 7. What must NOT be claimed

| Claim | Why it is false or unsupported |
|---|---|
| "End-to-end encrypted messaging / chat / files" | Text and attachment E2EE is in progress and not merged. Existing conversations will never be converted. Even afterwards, only conversations created encrypted |
| "We can't read your messages" | We can, today, for every text conversation (host access). Even after E2EE, only for encrypted conversations |
| "Zero-knowledge", "zero-access", "the operator can't see anything" | Category 2 is operator-readable; category 4 is infrastructure-visible; metadata is visible even for E2EE |
| "No logs", "we don't know when you're online" | Info-level logs record socket open and close per `user_id` with Docker timestamps; `last_seen_at` is stored (G5.3, G5.4) |
| "Anonymous", "untraceable", "metadata-free" | Cloudflare and the host see addresses; the membership graph, authors and timestamps are stored; an invite links a person to whoever invited them |
| "Your IP is hidden", "other members never see your IP" | Members learn the host's address. Other members not learning yours is by code reading only; no test exists. In a call the host sees every address |
| "Cloudflare can't see your traffic" | It terminates TLS and sees everything on the HTTP path |
| "Calls are always end-to-end encrypted", "video and screen share are end-to-end encrypted" | The server can force transport-only. Video sealing is unverified and the client's own `SECURITY.md` says it is not sealed |
| "Safety numbers / call codes guarantee nobody is listening" | They only help people who compare them |
| "Deleted means gone", "permanently erased" | Backups, WAL, other devices, Cloudflare and the Pocket ID account are not reached; `unlink` does not overwrite bytes |
| "We share no data with third parties" | Cloudflare, the hosting provider, ClamAV mirrors, GitHub, Wikipedia and a payment processor all see something |
| "Attachments are virus scanned" (for encrypted conversations) or "virus free" | Sealed files are not scanned by design |
| "Secure encrypted backups" | No backup tool exists |
| "Independently audited", "military grade", "unbreakable" | No independent review has happened ([`remaining-risks.md`](remaining-risks.md)) |
| "GDPR compliant", "DMCA compliant", "CALEA exempt", "outside US jurisdiction", "no KYC means we have no legal obligations", "E2EE means we cannot be ordered to do anything" | No legal conclusion is drawn anywhere here; [`compliance.md`](compliance.md) lists questions for counsel |
| "We never hand data to anyone" | The service must be able to act on valid legal process, abuse reports and suspension, and says so |
| "Bots can't see your messages" without qualification | True today of the bot API (G2.8); not a statement about the operator |
| "Unlimited" anything (storage, bandwidth, rooms) | There are caps and no quotas; neither is a promise ([`performance.md`](performance.md)) |

## 8. Rows that change when text E2EE is merged and verified

When the E2EE branch merges, a verification pass must update: G1.3 to G1.7 (run the tests named in `e2ee-text.md` section 11; check the server external sender key's storage; check that the plaintext post is refused); G2.1 (it stays true for plaintext conversations and is moot for encrypted ones); G3.2 (the new tables have no address columns: re-run the schema search); G4 (the metadata the server still sees); A10 (it can become "available" only for conversations created encrypted, with the limits in [`../e2ee-text.md`](../e2ee-text.md) section 8); the must-not-claim list; [`metadata.md`](metadata.md) section 1 (new tables); [`encryption-architecture.md`](encryption-architecture.md); [`migration.md`](migration.md) (actual migration numbers).
