# Threat model

Who can attack tinyserver and tinyclient, what each of them can reach today, and what stops them. It is written for a managed hosting service (TinyCloud) in which the operator of the machines is not the community that uses them. A self-hosting community that runs its own box is the same model with the operator and the owner being one party.

Read [`README.md`](README.md) for the status words (implemented, in progress, designed, not done, not verified). The findings that led to the fixes cited here are in [`findings.md`](findings.md). What is still unreviewed is in [`remaining-risks.md`](remaining-risks.md).

**State of the code this describes:** tinyserver `origin/main` at `c4ae28b` (first written on `ea3cd39`; re-checked after #20 added abuse reports, operator suspension and legal hold, tenants and encrypted backups), and tinyclient at `26916e9` (read only). Text and attachment end-to-end encryption (E2EE) is specified in [`../e2ee-text.md`](../e2ee-text.md); its server side is implemented and tested (#23), and its client side is on tinyclient main: #126 (`0c405dc`, the `crates/e2ee` crate) and #127 (`89188e8`, the Tiny adapter), in no release yet. Every statement below that depends on it says so.

## 1. What is protected

| Asset | Where it lives | Matters because |
|---|---|---|
| Message text, edits, reply text | `messages.body`, the `outbox` payload for 24 hours, backups | The content of private conversation |
| Attachments (bytes, names, types) | Files in the upload volume, `attachments` rows | Same |
| Call audio and video | In flight only. Never stored | Same |
| Who talks to whom, and when | `directs`, `messages.author_id`, `created_at`, `reactions`, `reads`, live occupancy | Social graph and activity pattern, readable without any message text |
| Membership and roles | `memberships`, `member_roles`, `invites`, `bans`, `audit_log` | Who is in a community |
| Identity | `users`, `user_identities` (issuer, subject), optional email | Links a person to an account at an identity provider |
| When a person is online | `memberships.last_seen_at`, live presence, log lines | Activity pattern |
| Network addresses | Cloudflare, the host's network, the SFU's memory, Pocket ID's audit log | Location and identity of a person |
| Credentials | Session, invite and bot tokens (hashed in Postgres), the OIDC client secret, the Pocket ID API key, the media HMAC secret, the database passwords, the tunnel token | Taking over accounts or the service |
| Keys | Device and identity keys in tinyclient, the server's MLS external sender key | The root of E2EE trust |
| Payer identity (TinyCloud) | Not built. See [`compliance.md`](compliance.md) and [`guarantees.md`](guarantees.md) category 5 | Must stay separate from community membership |

## 2. Trust boundaries

```
 person's device                  Cloudflare                 host (one tenant stack)
 ┌────────────────┐  HTTPS/WSS  ┌──────────┐  tunnel   ┌────────────────────────────────────┐
 │ tinyclient     │────────────▶│ edge,    │──────────▶│ cloudflared                        │
 │  chatd,mediad  │             │ TLS ends │ (outbound │   │ inside network (no route out)  │
 │  keychain      │             │ here     │  only)    │   ├─▶ tinyserver :8080 (HTTP, WS)  │
 └───────┬────────┘             └──────────┘           │   ├─▶ pocket-id :1411 (OIDC)       │
         │  UDP/TCP :50000 (media, direct, not via Cloudflare)       │   └─▶ postgres :5432    │
         └────────────────────────────────────────────▶ tinyserver SFU (same process)        │
                                                        │ media network (has a route out)    │
                                                        │   clamd :3310 (scans uploads)      │
                                                        └────────────────────────────────────┘
```

Source: `deploy/compose.yml`, `docs/calls.md` ("Network exposure"). Two facts shape everything:

1. **Cloudflare terminates TLS** for the chat and auth hostnames, so it handles every HTTP request and WebSocket frame in the clear at its edge. This is how a proxied hostname works; see Cloudflare's [Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/) and [WebSockets](https://developers.cloudflare.com/network/websockets/) documentation. Cloudflare's own retention and access policy was not reviewed.
2. **Media does not go through Cloudflare.** The SFU's UDP and TCP port is published on the host and members connect to it directly. The host's public IP address is in every SDP answer (`docs/calls.md`).

## 3. Actors

For each actor: what they can do **today**, what stops them, and what is left. "Plaintext today" means the data is readable by anyone with the access described, because only conversations created encrypted are covered by text and attachment E2EE, and no released client makes them yet. [`metadata.md`](metadata.md) lists every place data lives; [`network.md`](network.md) covers addresses.

### 3.1 Passive network observer (café Wi-Fi, ISP, a transit network)

| Can | Cannot |
|---|---|
| See that a device talks to Cloudflare, with sizes and timing. See UDP and TCP flows to the host's media port, which reveals the host IP and that a call is happening, its duration and approximate bitrate | Read HTTP or WebSocket content (TLS to Cloudflare). Read media (DTLS-SRTP, and DAVE sealing in an E2EE call) |

The server itself speaks plain HTTP inside the compose network and sets `Strict-Transport-Security` on responses (`crates/api/src/lib.rs`, `harden`); TLS is Cloudflare's. tinyclient's treatment of cleartext `http` hosts was hardened (finding C5); the details are in the client's `SECURITY.md` and were not re-verified here. There is no certificate pinning to the origin or to Cloudflare (none found in either repository).

### 3.2 A stranger on the internet (no account)

Reaches: `GET /health` (reports `db_role`, schema state and media state), `GET /v1/auth/config` (provider names), the sign-in routes, and the media port. Everything else answers `401`.

| Stops them | Evidence |
|---|---|
| Sign-in routes are rate limited per peer address (5 a minute, 120 in all; the sign-up form 3 and 30). The key is a keyed hash of the real peer, and a forged `cf-connecting-ip` is believed only from a trusted proxy | `crates/api/src/limit.rs` unit tests (nine); `crates/api/tests/limit.rs` `a_sixth_try_in_a_minute_is_told_to_slow_down` |
| Unknown sources on the media port get STUN handling only, after a per-source packet budget | `crates/sfu` tests; `docs/calls.md` "Security of an open media port" |
| Membership needs an invite or an allowed IdP group | `crates/api/tests/auth.rs` `someone_without_an_invite_is_not_a_member_and_nothing_is_kept` |

Residual: the REST API has no per-address limit outside the three sign-in routes, and no per-user limit on messages, uploads or other writes (`grep` of `crates/` for a rate limiter finds only `limit.rs` and the per-socket limits in `live/`). Disk and CPU exhaustion by an authenticated member is therefore not bounded by the application. See [`performance.md`](performance.md).

### 3.3 A malicious or curious member

| Can | Cannot (evidence) |
|---|---|
| Read everything in channels they can view, copy it, and show it to anyone. This holds with E2EE too | Receive events of a channel they may not view: `a_private_channels_events_reach_only_members_who_can_view_it` (`crates/api/tests/messages.rs`), migration `0013` |
| See the member list, display names, avatars, roles, `last_seen_at` and `joined_via` of everyone | See another member's email: `a_member_sees_their_own_email_and_not_another_members` (`crates/api/tests/privacy.rs`) |
| See who is in each call and who is speaking (`ready.calls`, `call.speaking`) | See another participant's IP address. The SFU answer carries only the SFU's candidates (`crates/sfu/src/engine.rs`, `candidates`). Not asserted by a test |
| Learn the SFU host's public IP address from the SDP | Read another member's direct messages: `a_direct_message_is_not_delivered_to_a_third_member` |
| Join a call with a client that says it cannot encrypt and turn the call to transport only for everyone | Do that without every other app being told (the client names who cannot encrypt). `an_app_that_cannot_encrypt_turns_the_call_to_transport_only_unless_required` |
| Forge audio as another member inside one E2EE call (sender keys derive from the shared group secret, as in DAVE) | Hear a call they are not in |

### 3.4 A community owner or administrator

Roles are enforced in Postgres (`docs/server.md` "Permissions"), and the owner flag sits above every role. An owner or administrator with the right bits can:

| Do | Visible to others |
|---|---|
| Read the member list with emails (`manage_server`), the audit log (`view_audit_log`), bans with reasons | Audited actions go to `audit_log` |
| Kick, ban, time out, move, mute, end a share | Audited |
| Read all plaintext messages in channels they can view (they are members) | Not audited |
| Create bots with `members.read` and `rooms.read` scopes that see occupancy and presence | `bot.create` is audited |
| See nothing of other members' E2EE conversations they are not part of. Server side implemented, tested (`e2ee_text.rs` `nothing_of_another_conversation_is_reachable`, `a_device_reads_only_its_own_welcome_and_nothing_from_before_it_joined`) | n/a |

A moderator cannot delete another member's message in an encrypted conversation (specified: there is no moderator delete in v1, `docs/e2ee-text.md` section 5). That is an abuse-handling cost of E2EE; see [`abuse-response.md`](abuse-response.md).

### 3.5 Cloudflare

| Can | Cannot |
|---|---|
| Read every HTTP request and WebSocket frame for the chat and auth hostnames: the `Authorization` bearer token, all plaintext JSON, uploaded files, the IP address of each client, and timing and sizes | See media on the media port (it is not proxied) |
| Replay or alter traffic, and impersonate the origin to clients, because it holds the TLS certificate for the hostname | Read the content of an encrypted conversation (server #23, client tinyclient #126, #127) or call frames sealed by DAVE. It never receives the media port's traffic, but see the note below on signaling |
| Learn the DTLS fingerprints in call signaling | |
| Block or throttle the hostname | |

A session token seen by Cloudflare is a bearer credential for up to 30 days (`TINYSERVER_SESSION_MAX_DAYS`, default 30). Nothing in the application binds a token to a device or an address (`sessions` has no such column; `0001_init.sql`, `0004_oidc.sql`). This matters if the Cloudflare account, or the tunnel token (`TUNNEL_TOKEN`), is compromised: whoever controls the hostname can serve their own origin for it and receive whatever clients send, bearer tokens included. E2EE-sealed content is outside that reach (calls today; text with server #23 and client tinyclient #127). A transport-only call is not: the DTLS fingerprint that authenticates the media connection travels in the signaling Cloudflare carries, so whoever controls signaling can substitute their own endpoint. Not tested.

### 3.6 The hosting provider (cloud, colo, or whoever has the hypervisor)

Everything on the machine is available to whoever controls it: disk, memory, network. Today that means:

| Reads | Notes |
|---|---|
| The Postgres volume, WAL, and every backup, including plaintext message bodies | Disk encryption by the provider protects only a stolen disk, not a running VM. `operator.sh` backups are age-encrypted, but a tenant's `backup.key` is on the same host until moved, so host root opens those too |
| The upload volume: plaintext attachment files, named by random UUID | Names and types are in Postgres |
| Process memory of tinyserver: bearer tokens held per live socket, the OIDC client secret, the Pocket ID API key, the media HMAC secret, call SDP and ICE credentials, the MLS external sender key, the debug ring | |
| The Docker log files (`json-file`, 10 MB times 3 per container) | Operator log lines carry user ids and timestamps (see [`telemetry-and-logging.md`](telemetry-and-logging.md)) |
| Packet metadata on every network interface, including the media port: client IPs, ports, sizes, timing | Cannot be hidden by anything the application does ([`network.md`](network.md) section 9) |

Without E2EE the provider can read what the server can read. With E2EE (calls implemented; text implemented in server and client, client in no release yet) it can read only metadata, plus anything it takes from a client.

### 3.7 TinyCloud staff (the operator)

The operator is the hosting provider's equivalent for tinyserver, plus control of its configuration and the identity provider. Roles to consider separately: **curious** (looks at what it can see), **malicious insider**, **compromised** (an attacker holds an operator credential), and **coerced** (valid legal process, or not).

Code-level capabilities of anyone with shell access to the stack (read from `deploy/compose.yml`, `docker/postgres/init/01-roles.sh`, `crates/server/src/main.rs`; none of these paths has a test, because they are administrative):

| Capability | How |
|---|---|
| Become an owner of any community | `tinyserver bootstrap --owner-invite` makes a new single-use, 24 hour owner invite even when an owner exists; any Pocket ID account that accepts it becomes an owner (`main.rs`, `Bootstrap`). The new invite writes `bootstrap` and `invite.revoke` audit rows, so the owner can see it happened if they read the audit log |
| Sign in as any member | `app_owner` has `BYPASSRLS` and can insert a `sessions` row with a token hash it chose. Or mint a Pocket ID one-time login link for that user with the Pocket ID API key (`secrets/pocketid_api_key`, an admin key, per `deploy/README.md`). Neither leaves an audit row in tinyserver |
| Learn every account's identity | `tinyserver identities` prints each user id, display name, issuer and subject |
| Rewrite which provider identity belongs to which account | `tinyserver relink-identity` (audited as `identity.relink` with a null actor) |
| Suspend, resume, hold or release a community | `tinyserver operator` with the owner password, through `deploy/tenant/operator.sh` (`0016_operator.sql`). Written to `operator_events` with the reason and no actor; members see the mode and notice, never a hold |
| Take, restore or delete a whole community | `operator.sh backup`, `export`, `restore`, `delete`. A backup encrypted to the operator's recipient is readable by the operator; a restore can roll a community back to an earlier time, deleted accounts included ([`findings.md`](findings.md) N11). None of it leaves a row in tinyserver |
| Read every abuse report | The owner role bypasses the `reports_select` policy. Reporters, evidence and moderators' notes are readable ([`abuse-response.md`](abuse-response.md), "What this does not do") |
| Read everything in 3.6 | Host access |

These are the reason plaintext conversations cannot support the sentence "the operator cannot read your messages". For E2EE conversations the design closes the impersonation path for a person who already has a device: a later device must carry a cross-signature from an active one, the server refuses one without (`a_later_device_needs_a_cross_signature_from_an_active_one`), and clients verify it themselves (`docs/e2ee-text.md` section 3; tinyclient `a_device_the_server_invented_is_rejected`, `an_add_of_a_device_that_is_not_cross_signed_is_rejected`, not run here). It does not close it for a person's first device, for a person with no devices (trust on first use), or for a new person the server admits (G3, G4 in `e2ee-text.md` section 8, open), and it does not help calls (finding S10).

**Operational controls** (separate roles, access logging, two-person approval, no shell access to tenants' data volumes) are an engineering and policy decision for TinyCloud that this repository does not implement. They are not guarantees. Anything that depends on them goes into category 2 of [`guarantees.md`](guarantees.md), never category 1.

### 3.8 Another tenant

[`tenancy.md`](tenancy.md) is the isolation contract, and #20 provides the stack side of it (finding S12): `deploy/tenant/tenant.sh` gives each tenant its own compose project, internal `/24` network, media port, Postgres cluster, database and tenant-named roles with their own passwords, secrets and limits; `docker/postgres/init/01-roles.sh` gives PUBLIC no CONNECT; every container but clamd has a read-only root. `deploy/tests/isolation.sh` checks that no name resolves and no address connects across two tenants, and `roles.sh` that two tenants in one cluster cannot reach each other's database (both need Docker; not in CI, not run for this pass). Out of scope of this repository: the shared kernel (an escape reaches every tenant), per-tenant UID ranges, cgroups, nftables, dropping 169.254.169.254, and disk encryption, all of which the host must provide.

### 3.9 The identity provider

Pocket ID in the compose file, or any OIDC provider the operator configures. An IdP that is compromised, or whose administrator is hostile, can issue an ID token for any `(issuer, subject)` and so sign in as any existing member, or as a new person if the community admits by group claim (`TINYSERVER_OIDC_MEMBER_GROUPS`). Signing in never grants decryption ([`deploy/README.md`](../../deploy/README.md)); in an E2EE conversation a person signing in as someone else gets a new device that other members see as new (tinyclient `a_new_identity_is_reported_and_needs_the_person_to_agree`, not run here).

Pocket ID is third-party software. Its own data (usernames, optional email, passkey public keys, an audit log with client IP addresses kept 90 days by default) is described in [`authentication.md`](authentication.md) and [`metadata.md`](metadata.md).

### 3.10 A compromised tinyserver process (remote code execution)

| Reaches | Does not reach |
|---|---|
| Everything `app_runtime` can read and write through its policies and definer functions, which is all of the community's data. Memory: tokens, secrets, MLS external sender key | The owner role's password (it lives in `tinyserver-init` only; finding S2, fixed, verified by hand, not by an automated test) |
| The `media` network, including clamd, and from there the internet (`media` has a route out) | Other containers' filesystems; the root filesystem is read only and all capabilities are dropped (`deploy/compose.yml`) |
| The Pocket ID API key (a mounted secret): it can create Pocket ID accounts and sign-up tokens | |

Row-level security does not contain this. A flaw that executes arbitrary SQL as `app_runtime` reads and writes every table (finding S2, limits). Defence in depth available: resource limits (finding S14), egress rule on the host, and sealing of message content (server #23, client tinyclient #127), which makes the stored data ciphertext.

### 3.11 A compromised or hostile client device

Reads everything that device can: its keychain items (sessions per network, E2EE keys), its plaintext cache (`chat.sqlite` is not encrypted at rest, tinyclient `SECURITY.md` "Known limits"), the unauthenticated local socket, and its microphone. The call identity key is a plaintext file (finding C4, open). E2EE does not protect against this; nothing does.

### 3.12 Legal process and seizure

A valid order served on TinyCloud, on the hosting provider, on Cloudflare or on the payment processor can reach what each of them holds. What TinyCloud holds is exactly the data in [`metadata.md`](metadata.md). What it can say is bounded by that inventory: it cannot produce message text of an E2EE conversation (server #23, client tinyclient #127), and it can produce everything else in the table. The technical readiness questions are in [`compliance.md`](compliance.md), and the process for reports and orders in [`abuse-response.md`](abuse-response.md). No legal conclusion is drawn here.

### 3.13 Other third parties

| Party | Sees | Where from |
|---|---|---|
| ClamAV signature mirrors | The host's IP when clamd's freshclam updates | `deploy/compose.yml` (`clamd` is on the `media` network "because freshclam needs a route out"). The mirror hostnames and what they log: not verified |
| Wikipedia, GitHub (from the client) | A person's IP when their client resolves a linked Wikipedia article or checks for a release | tinyclient `docs/architecture.md` ("While open, asks GitHub whether a newer release exists, and asks Wikipedia for a linked article's summary"); `crates/tinyclient/src/gui/conversation/wiki.rs`. The update check's endpoint was not found in the client source by `git grep` for `github.com/`; **not verified** beyond the doc |
| `tinyclient.io` | That someone opened an invite page, with their IP and user agent. The invite secret is in the URL fragment, which the browser does not send | `site/invite/invite.js` in the client repo. How the site is hosted and logged: not verified |
| DNS and registrar | The chat and auth hostnames | Inherent |
| Payment processor (TinyCloud) | Payer details | Not built. [`compliance.md`](compliance.md) |

### 3.14 Supply chain

Server: Rust dependencies pinned by `Cargo.lock`; images pinned by tag, Pocket ID and the setup curl image by digest as well (`deploy/compose.yml`, `deploy/README.md` "Images"); `str0m` pinned to `=0.24.1`. A fuzz job covers parsers (`docs/calls.md`). Not verified: reproducible builds, signature verification of images, dependency audit tooling (`cargo audit` or `cargo deny` are not referenced anywhere in the repository), the client updater's integrity (finding C6, hardened where possible). See [`remaining-risks.md`](remaining-risks.md).

## 4. Properties and how each is enforced

The product goal is "enforceable by architecture". This table says which parts of that goal the code enforces, which depend on policy, and which are not done. The same split is the five categories in [`guarantees.md`](guarantees.md).

| Property | Enforced by | Status |
|---|---|---|
| The server cannot hear an end-to-end call | MLS between apps; server is delivery service and external sender, holds no group secret (`crates/api/src/live/e2ee.rs`) | Implemented; downgrade by the server is possible and shown by clients (S4) |
| The server cannot read text and attachments of an E2EE conversation | MLS groups per conversation, sealed uploads | Implemented, tested: server `a_canary_said_only_through_encrypted_paths_is_nowhere_on_the_server`; client tinyclient `an_encrypted_conversation_is_labelled_its_rows_never_read_the_servers_body_and_nothing_goes_plain` (not run here) |
| The server cannot read text of existing conversations | Nothing | **Not done**: existing conversations stay plaintext, never converted in place |
| A member sees only channels they may view | Row-level security, definer functions, outbox audience (`0013`) | Implemented, tested |
| The runtime role cannot bypass row-level security or change schema | `app_runtime` is `NOSUPERUSER NOBYPASSRLS`; owner password only in `tinyserver-init` | Implemented, tested (`deploy/tests/isolation.sh`, `roles.sh`; shell checks, Docker, not in CI) |
| No passwords, no password database | `0004_oidc.sql` drops `password_hash`; sign-in is OIDC | Implemented |
| Tokens are not stored | `sessions.token_hash`, `invites.token_hash`, `bots.token_hash`, `auth_*` store SHA-256 | Implemented (schema); no test asserts it |
| No IP address in the database | No column holds one (`0001`..`0016`) | Implemented (schema); no test asserts it |
| IP address not in default logs | `peer` field dropped on the operator sink; ring only with `TINYSERVER_LOG_PEER_IP=on` | Implemented, tested (`peer_is_operator_blind_and_ring_gated`) |
| No routine inspection of private communications | Cryptography for E2EE conversations; **policy only** elsewhere | Partly. See 3.7 |
| Moderators can act on abuse reports without the server reading conversations | In-community reports holding ids and only what the reporter's client sends; RLS hides a report from its subject (`0015`) | Implemented, tested (`crates/api/tests/reports.rs`) |
| The operator can suspend a community without reading it | `tinyserver operator suspend` (`0016`) | Implemented, tested (`crates/api/tests/operator.rs`) |
| TinyCloud receives and acts on reports and legal process | Control plane and procedures | Not in this repository. See [`abuse-response.md`](abuse-response.md), [`compliance.md`](compliance.md) |

## 5. Scenarios walked through

**A. Operator wants to read a particular DM, today.** Reads `messages.body` with `app_owner` or from a backup. Nothing prevents it, and it leaves no trace. For a conversation created encrypted (server #23, client tinyclient #127; the client starts encrypted direct messages): the operator has ciphertext, `author_id`, the minute, sizes, and reaction ciphertexts with the posting device. It does not have the emoji or which message a reaction answers. It can add a ghost device only by becoming a person who has no device (first-device trust on first use), or by a cross-signed device, which needs a key it does not hold; clients show new devices and changed safety numbers. It can still admit a new account of its own to the conversation (G3, G4, open).

**B. Operator wants to listen to a call.** Must send `off` frames or claim someone cannot encrypt. Every client in the call displays that the call is "encrypted to the server" and names who it says cannot encrypt. A client in `required` mode (opt-in, off by default, finding S4) blocks instead. So: detectable by a person watching, not preventable by the server.

**C. Operator adds itself to a call as a member.** It needs a key package with a credential holding the 8 byte MLS id of a roster name. Apps refuse a proposal to add anyone the call's roster does not name (`docs/calls.md`), but the roster is server-provided (S10). Verified safety numbers are the defence.

**D. Database or backup stolen.** A bundle from `operator.sh backup` is age-encrypted; the case below is a thief who also has a matching identity (the operator's, or the tenant's `backup.key` from the same host), or a raw volume. Today: all plaintext text, member list, emails, avatars, audit log, abuse reports with their evidence. Session and invite tokens are hashes of 32 random bytes and cannot be replayed. Pocket ID's SQLite is in another volume (`pocketid_data`) with its key in `secrets/`; both would need to be taken. For conversations created encrypted (#23): their text and sealed files are ciphertext, but the bundle also holds the server's external sender private key (finding N15) and all metadata; a restore older than the clients' state is detected by clients, which freeze the group (tinyclient `an_epoch_that_goes_backwards_is_detected_and_freezes_the_group`, not run here).

**E. Cloudflare account compromised.** The attacker can serve its own origin for the hostname and collect sign-in codes. It can also read traffic to the real origin. Sealed content is safe; metadata and bearer tokens are not.

**F. A person's device is stolen unlocked.** Everything on it, including a live session. `DELETE /v1/sessions` ends sessions; devices are revoked with `DELETE /v1/e2ee/devices/{id}` (`a_revoked_device_is_removed_and_gets_nothing_more`). History already on the device stays readable to the thief.

## 6. Assumptions

- The client binary is the one built from the public source. The updater is a risk (C6).
- The operating system's keychain, random source and TLS are sound.
- MLS (RFC 9420, `openmls`, `davey`), AES-GCM, P-256 and the STREAM construction are used as their authors specify. No independent review of this use has happened ([`remaining-risks.md`](remaining-risks.md)).
- The host clock is roughly correct (session expiry, ID token `iat`).
- One community per stack, one stack per tenant ([`tenancy.md`](tenancy.md)).

## 7. Out of scope

Denial of service by an adversary that can fill the host's link; physical attacks on a person; coercion of a member to show their screen; traffic analysis by an adversary that sees both ends of a call; anonymity of a person from the community they join (they join by an invite from someone who knows them). The limits of anonymity are in [`remaining-risks.md`](remaining-risks.md).
