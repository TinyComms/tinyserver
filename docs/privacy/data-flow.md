# Data flows

What moves where, who handles it on the way, and what is written down. One table per flow. "Form" is plaintext, TLS-only (the receiving party decrypts it), sealed (only the endpoints can read it) or hash (a one-way digest is kept, not the value).

Read with [`metadata.md`](metadata.md) (every place data rests), [`network.md`](network.md) (addresses) and [`threat-model.md`](threat-model.md) (who the parties are). Status words are explained in [`README.md`](README.md). **Text and attachment E2EE is in progress**; where it changes a flow, the flow is shown twice, "today" and "specified" ([`../e2ee-text.md`](../e2ee-text.md)).

Parties: **C** = tinyclient on a person's device. **CF** = Cloudflare. **S** = tinyserver (HTTP, live socket, SFU in one process). **DB** = Postgres. **IdP** = Pocket ID (or another OIDC provider). **AV** = clamd. **FS** = the upload volume.

## 1. Sign-in with an invite (new person, Pocket ID)

Source: `docs/server.md` "Sign-in", `deploy/README.md` "An invite makes the account", `crates/api/src/auth.rs`, `crates/db/src/auth.rs`.

| # | From to | Path | What travels | Form | Written down |
|---|---|---|---|---|---|
| 1 | C to S | CF | `POST /v1/auth/start`: loopback redirect URI, PKCE challenge (S256), client `state`, the invite token, provider id | TLS, CF sees it | `auth_pending`: hash of the state, the server's own PKCE verifier and nonce, client redirect (a `127.0.0.1` URL with a port), client challenge and state, the invite **hash**. 10 minutes |
| 2 | C opens a browser | to S via CF | `GET /v1/auth/join` page | TLS | Nothing new |
| 3 | S to IdP | inside network | `POST /api/signup-tokens` `{ttl: 15m, usageLimit: 1}` with the Pocket ID API key. Only while the invite could still be accepted, once per pending sign-in | Plain HTTP on the `inside` network | `auth_pending.signup_at` |
| 4 | Browser to IdP | CF (auth hostname) | The person picks a username and makes a passkey | TLS, CF sees page traffic. The passkey private key never leaves the person's authenticator | IdP: user row, username, optional email, passkey public key, audit event with client IP |
| 5 | Browser to S | CF | `GET /v1/auth/callback?code&state&iss` from the IdP redirect | TLS | The server marks nothing yet |
| 6 | S to IdP | inside network | Code exchange (client secret or private-key JWT), discovery, key set | Plain HTTP inside | Nothing |
| 7 | S to DB | inside | Verified ID token claims: `iss`, `sub`, optional `email`, `name` or `preferred_username`, optional `sid`, groups. A new row in `users` (email if present, display name), `user_identities (issuer, subject)`, membership via `app_accept_invite` | | Yes: those rows, an `invite.accept` audit row, a `member.joined` outbox row |
| 8 | S to C | CF, then the browser redirects to the client's loopback | `302 http://127.0.0.1:<port>/callback?code=<one-time>&state=` | The code is useless without the PKCE verifier, and expires in 60 seconds | `auth_codes`: hash of the code, user id, client challenge, issuer, `sid` |
| 9 | C to S | CF | `POST /v1/auth/token {code, code_verifier}` | TLS | The code row is spent on the first try |
| 10 | S to C | CF | `{token, user_id, email, display_name, role}`. The token is 32 random bytes | CF sees the token | `sessions`: SHA-256 of the token, user id, expiry (30 days default), `issuer`, `sid` |

No password exists anywhere in this flow. No IP address, user agent or device name is written by tinyserver. The IdP and Cloudflare do see addresses ([`authentication.md`](authentication.md), [`network.md`](network.md)). Evidence: `crates/api/tests/auth.rs` (`an_invite_lets_a_person_in_and_they_come_back_without_it`, `a_one_time_code_works_once_with_the_right_verifier_inside_a_minute`, `someone_new_with_an_invite_gets_one_single_use_signup_link_and_joins`), `crates/api/tests/signup_logs.rs` (`the_api_key_and_signup_tokens_never_reach_the_logs`).

A returning member skips steps 3 and 4 (the IdP signs them in) and step 7 only finds the existing identity. A person with no invite and no allowed group gets `error=not_member` and nothing is written (`someone_without_an_invite_is_not_a_member_and_nothing_is_kept`).

## 2. A signed-in session

| What | Path | Detail |
|---|---|---|
| REST calls | C to CF to S | `Authorization: Bearer <token>` on every request. S hashes it and looks up `sessions`; it sets `app.user_id` for row-level security |
| Live socket | C to CF to S | `GET /v1/live` with the same header. The socket re-reads the session every 60 seconds. S holds the raw token string in memory for the life of the socket |
| `last_seen_at` | S to DB | Written in batches every 30 seconds for sockets queued on open, close and each recheck. Not on every frame |
| Sign out | C to CF to S | `DELETE /v1/session` or `DELETE /v1/sessions` (all of a person's sessions). A provider back-channel logout to `POST /v1/auth/backchannel-logout` ends sessions by `sid` or `sub` |

## 3. A text message

### Today (plaintext)

| # | From to | What | Form | Written down |
|---|---|---|---|---|
| 1 | C to S via CF | `POST /v1/conversations/{id}/messages {body, reply_to?, client_id?, attachment_ids?}` | TLS only. CF and S read it | |
| 2 | S to DB | One transaction: `messages` row (body, author, timestamps), an `outbox` row with the full message JSON. A 200 character preview of the last message is computed from the body by `app_last_message` and is also embedded in `channel.updated` outbox rows | Plaintext | `messages.body`, `outbox.payload` for 24 hours, WAL, backups |
| 3 | S to other members' sockets | `message.created` frame with the message. For a channel, only to members who can view it (`0013`); for a direct, only to the two people | Plaintext over TLS, CF sees it | |
| 4 | Edit | `PATCH /v1/messages/{id}`. A trigger (`0014`) rewrites the earlier outbox rows to the new text so a reconnecting socket is not replayed the old one | Plaintext | `messages.edited_at`; old text is gone from the table and outbox, but not from WAL, dead rows or backups |
| 5 | Delete | `DELETE /v1/messages/{id}`: body cleared, attachments and reactions removed, files unlinked, `deleted_at` set. The row stays | | The tombstone: author, `created_at`, `deleted_at` |

### Specified (an encrypted conversation, **in progress**)

| # | From to | What | Form |
|---|---|---|---|
| 1 | C encrypts | An MLS application message (RFC 9420) holding JSON `{v, text, reply_to, attachments[], sent_at}` | Sealed. Only group members' devices have keys |
| 2 | C to S via CF | `{ciphertext, epoch, device_id, client_id, kind, target_id?, attachment_ids?}`. A request with a `body` is refused (`400 e2ee_required`) | CF and S see ciphertext and these fields |
| 3 | S to DB | `messages` row with `body = ''`, `ciphertext`, `epoch`, `device_id`, `kind`, and the outbox row | Ciphertext at rest |
| 4 | S to members | The ciphertext. Members whose Remove is pending get nothing | |
| 5 | Group changes | Public MLS handshake messages (proposals, commits, welcomes) are stored in a handshake log. They hold no secret that opens a message | |

Visible to S even when encrypted: who posted, which conversation, when, ciphertext size, the number and sizes of attachments, reactions (not encrypted in v1), who is in the group, which devices a person has. Not visible: text, edits, reply text, attachment contents, names and types. Source: `docs/e2ee-text.md` sections 1 and 6.

## 4. Attachments

### Today

| # | From to | What | Form | Written down |
|---|---|---|---|---|
| 1 | C to S via CF | `POST /v1/media` multipart: the file plus optional width, height, duration | TLS only | |
| 2 | S | Type policy: extension, declared MIME and sniffed type must agree; PE and ELF refused; images re-encoded in the server process; zip central directory checked | The server parses untrusted content | |
| 3 | S to FS | The file is written once as `{upload dir}/{uuid}` (`std::fs::write`, `crates/db/src/messages.rs`) | Plaintext at rest | The file |
| 4 | S to AV | The file is sent over TCP to clamd on the `media` network, plus three in-process YARA rules | Plaintext on the Docker network | clamd may log; its logging was not reviewed |
| 5 | S to DB | After a clean verdict: an `attachments` row with the **original file name**, MIME, kind, byte size, dimensions | Plaintext | `attachments.name`, `mime` |
| 6 | Download | `GET /v1/media/{id}` with the session, and optionally the HMAC-signed query (`ex`, `is`, `hm`, 24 hour life) | TLS | |
| 7 | Delete | Message delete, channel delete, account delete: files are unlinked | | `unlink` only. The bytes are not overwritten and a filesystem snapshot or backup keeps them |

Uploads nobody attached within an hour are deleted by the sweep (every 10 minutes). Evidence: `crates/api/tests/messages.rs` (`an_eicar_upload_is_blocked`, `a_message_cannot_name_an_unscanned_attachment`, `a_scanning_attachment_download_is_locked`, `a_bad_hmac_is_refused`).

### Specified (sealed upload, **in progress**)

The client encrypts the file with AES-256-GCM in the STREAM construction under a random key held only inside the MLS message, and posts `sealed=1`. S stores the blob once, as received, with fixed name `sealed` and type `application/octet-stream`. No sniffing, no image decoding, **no virus scan**: the specification states the server must not claim to scan sealed files. Size, rate, orphan cleanup and "only linkable into an encrypted conversation" are still enforced. Source: `docs/e2ee-text.md` section 5.

## 5. Live events (the outbox)

Every change is an `outbox` row written in the transaction that made it. S's single dispatcher reads rows after a wake (`LISTEN app_wake`), sends them through an in-process broadcast, and each socket filters by audience and permissions. Kept 24 hours, then deleted (`app_sweep`, every 10 minutes). A reconnecting client replays from `?since=`. Source: `docs/calls.md` "Outbox and LISTEN/NOTIFY".

What an outbox payload holds today: member objects (user id, display name, role, avatar hash), room and channel objects (name, topic, overrides), and full message objects with plaintext bodies. `0014` deletes the outbox rows that carry a deleted account's `member.*` events and rewrites message events when a message is edited or deleted. Evidence: `deleting_an_account_removes_the_person_and_what_they_said`.

## 6. A call

| # | From to | What | Via | Form |
|---|---|---|---|---|
| 1 | C to S | `call.join {room_id, sdp, e2ee}`: SDP offer with ICE credentials and the client's DTLS fingerprint | WebSocket, CF sees it | TLS only |
| 2 | S authorizes | Room visibility, `connect`, timeout, caps; nothing about the call is written to Postgres. Joins and leaves are not audited | | |
| 3 | S to C | `call.answer {call_id, sdp}`: SFU ICE-lite credentials, DTLS fingerprint, candidates (the SFU's UDP and TCP host candidates on `TINYSERVER_PUBLIC_IP`, and on `TINYSERVER_LAN_IP` when set) | WebSocket, CF sees it | TLS only |
| 4 | C to SFU | STUN checks, DTLS handshake, SRTP | **Direct** to the host's media port. Not through CF | DTLS-SRTP. The SFU decrypts at the transport layer |
| 5 | SFU forwards | Opus frames, H.264 pictures, to other participants' slots | Direct | In a transport-only call the payload is plaintext inside the SFU. In an E2EE call it is DAVE ciphertext; RTP headers and the RFC 6464 audio level stay in the clear |
| 6 | C and S, E2EE only | `call.e2ee` frames: key packages, proposals, commits, welcomes (public MLS handshake) | WebSocket, CF sees it | Public by design; holds no group secret |
| 7 | S to everyone | `call.joined`, `call.left`, `call.state`, `call.speaking` and the roster in `ready` | WebSocket | Plaintext to every member's socket; ephemeral, never stored |

The SFU learns each participant's address from the first STUN check and keeps it in memory for the life of the participant. The answer to other participants never contains it. Nothing of a call (members, duration, who spoke) is stored by tinyserver. The operator's stderr log does record "media joined" and "media lost" with a random `call_id`, the user ids of socket opens and closes, and Docker adds a timestamp ([`telemetry-and-logging.md`](telemetry-and-logging.md)). Source: `docs/calls.md`. Evidence: `crates/api/tests/e2ee.rs` (`three_apps_agree_on_a_code_the_server_cannot_know`, `only_the_seat_holder_speaks_mls_and_only_as_itself`, `an_app_that_cannot_encrypt_turns_the_call_to_transport_only_unless_required`), `crates/api/src/live/e2ee/tests.rs`.

## 7. Moderation and removal

| Action | Stored | Told to |
|---|---|---|
| Kick, ban, timeout, role change, invite create or revoke, server settings, channel changes, bot create or revoke | `audit_log` row with actor, action, subject, optional reason (up to 512 characters, free text), plus the current display names when read | Permission-filtered live events |
| Ban | `bans` (reason, banned_by, expiry) and `ban_identities` (issuer, subject of every identity the person signed in with) | The banned person's sockets close with `4003` |
| Call kick, share end, server mute, move | `audit_log` | |
| Call joins and leaves, speaking, mute | Not stored | |

The audit log is not pruned by any sweep. Names in audit responses are joined at read time from `users`, so deleting an account changes them to "Deleted user" (`0014` also strips `display_name`, `name` and `email` keys from `audit_log.detail`).

## 8. Account deletion (`DELETE /v1/me`)

C sends `{"confirm": "delete my account"}`. S calls `app_delete_account()` in one transaction. What it removes and what it cannot reach is in [`retention-and-deletion.md`](retention-and-deletion.md). It does **not** contact the IdP: the Pocket ID account, its passkeys, username, email and audit events stay until a Pocket ID administrator removes them. This is a gap, not a design: nothing in `crates/api/src/oidc.rs` calls an IdP delete endpoint.

## 9. Bots

An application token (`Authorization: Bot <token>`, 32 random bytes, hash stored) calls a restricted subset of the API and the live socket. A bot is not a member, receives no message, direct, typing or read frames, and sees rooms and call occupancy (`rooms.read`) and the member list and presence (`members.read`) only if granted. Source: `docs/server.md` "Bots".

## 10. Logs, backups, provisioning

| Flow | State |
|---|---|
| Logs | stderr to Docker's `json-file` (10 MB times 3), an in-memory ring, optional bundle files on `SIGUSR1`. No exporter. Detail in [`telemetry-and-logging.md`](telemetry-and-logging.md) |
| Backups | None shipped in this branch. The documented procedure is a manual `pg_dump` as the Postgres superuser; it does not cover the upload volume, Pocket ID's volume or the secrets directory. See [`migration.md`](migration.md) and finding S11 |
| Provisioning and billing (TinyCloud) | Not built. The constraints are in [`compliance.md`](compliance.md) section 8 and [`guarantees.md`](guarantees.md) category 5 |
| Reports and legal requests | Procedure in [`abuse-response.md`](abuse-response.md) |

## 11. Client side

tinyclient runs four processes (`chatd`, the window, `mediad` during calls, a login window). It keeps sessions in the OS credential store, a plaintext `chat.sqlite` and `media/` cache, and logs under its support directory. Nothing is uploaded: no telemetry, no crash reporting. It does contact GitHub (update check) and Wikipedia (link summaries) on its own account, and `tinyclient.io` when a person opens an invite link in a browser. Source: tinyclient `SECURITY.md`, `docs/logging.md`, `docs/architecture.md` (read only, at `26916e9`).
