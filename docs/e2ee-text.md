# End-to-end encrypted text and attachments

Status: **specification, version 1. Not implemented on this branch.** No code in this repository encrypts text or attachments yet: message bodies and attachments are stored and served in plaintext. The server side is planned for `crates/api/src/e2ee_text/` and new migrations; the client side for tinyclient's `crates/e2ee` and the Tiny adapter. Once that code merges, where this document and the code disagree, the code is wrong or this document is out of date: open an issue. Calls already have end-to-end encryption (`docs/calls.md`); this is the same family of design for stored text.

Nothing here is "implemented" until its tests pass. Section 11 lists the tests that stand for each property, and section 12 says what is not covered.

## 1. Goals and non-goals

An encrypted conversation guarantees that **the server and whoever operates it cannot read message text, edit text, reply text, attachment contents, attachment names or attachment types.** The server stores ciphertext and keeps no key that opens it.

It does not hide: who is in a conversation, who posted and when, ciphertext sizes, how many attachments a message has and their sizes, reactions' existence (reactions are not encrypted in v1, see section 8), who is online, IP addresses (see `docs/privacy/network.md`), and which devices a person has.

It does not protect a conversation from a member: anyone in the group at the time can read, copy and show what they receive.

Non-goals for v1: encrypted search on the server, server-side previews, push notification content from the server, history for new members or new devices, key backup.

## 2. Primitives

Nothing here is custom cryptography. The protocol is MLS, RFC 9420, with the ciphersuite `MLS_128_DHKEMP256_AES128GCM_SHA256_P256` (0x0002), the same as calls, run with the `openmls` crate (pinned in tinyclient already). Attachments use AES-256-GCM in the STREAM construction (Hoang, Reyhanitabar, Rogaway, Vizár, "Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance") as implemented by the RustCrypto `aead::stream` module, with a random 256 bit key per attachment.

## 3. Identities and devices

A **device** is one install of tinyclient signed in to one account. Its **device id** is a random UUID it makes. Its **signing key** is a P-256 key made on the device and never sent anywhere. The credential in every MLS leaf is an MLS basic credential whose content is exactly 32 bytes: the 16 byte user id then the 16 byte device id. The server refuses any key package whose credential is not the authenticated caller's user id and the device id it names.

**Cross-signing.** A person's first device is trusted on first use. Every later device must carry a `cross_signature`: ECDSA P-256 over SHA-256 of `"tiny-e2ee-v1 device-add" || user_id || device_id || signature_key` made by a signing key of one of the person's already active devices. Clients verify this chain themselves before they trust a device; the server checks it too, but a client does not rely on the server having done so. So a server cannot add a device to a person's account that the person's own devices did not approve. This is the defence against server-controlled key substitution once a person has a device. It does not cover a person's first device, nor a person who has lost every device and starts again: either shows other members a **new identity** for that person, and the client says so loudly (section 7).

A device is revoked by the account holder from any session (`DELETE /v1/e2ee/devices/{id}`); this is not a cross-signed act, because a person who lost every device must still be able to remove them. An operator who can sign in as a person can revoke or, for a person with no devices, add one. Devices a server adds or removes on its own show up in the member's device list and the safety numbers change; that is the check.

## 4. Conversation groups

Each conversation (channel or direct) has an `e2ee` flag, fixed at creation and never cleared. An encrypted conversation is one MLS group whose group id is the 16 byte conversation id. Its members are devices.

**The server is the delivery service and an external sender.** It keeps one persistent P-256 key (`e2ee_server_key`, generated at first start). It signs external Add and Remove proposals only. It cannot decrypt, commit or send application messages. Clients pin the external sender public key the first time they see a conversation and show a warning if it changes.

**Who is in the group is decided by permission, not by who asks.** The desired device set of a conversation is every active device of every user who can view it (channel `view_channel`, or the two people of a direct). When that set changes (a member joins, leaves, is kicked or banned, deletes their account, loses `view_channel` through a role or an override, or adds or revokes a device) the server records external proposals: Remove for leaves no longer wanted, Add for wanted devices with a claimed key package. Any member device that sees pending proposals commits them. The first valid commit for an epoch wins (compare-and-swap on the epoch); the rest are refused as stale. Until a removed member's Remove is committed, the server already stops delivering that conversation's ciphertext to them (the same audience narrowing as `0013`) and refuses their posts, so a removed member loses access to *future ciphertext they could fetch* immediately and to *future keys* at the next commit.

Honest limit: if no member device is online, the commit waits. Messages sent in that epoch are still encrypted to the old member set, including to the person being removed, who cannot be sent them by the server but could have kept a key from before. Clients therefore commit pending removals before they send, and refuse to send into an epoch that has a pending Remove.

**Joining.** A joining device gets a Welcome and reads **nothing from before it was added**: a new member and a new device never decrypt history. Their client shows "Messages from before you joined can't be read."

**History is not re-encrypted** when a member is removed; they keep whatever they already had.

## 5. Wire protocol

All routes need a person's bearer session. Bots are refused. Binary values are standard base64. Every request that changes state is rate limited per user.

### Devices and key packages

| Route | Body → result |
|---|---|
| `PUT /v1/e2ee/devices/{device_id}` | `{signature_key, cross_signature?, label?}` → `201 {device}`. `signature_key` is 65 bytes, uncompressed P-256. `cross_signature` is required when the person has an active device. `409` if the id exists. |
| `DELETE /v1/e2ee/devices/{device_id}` | → `204`. Revokes. Queues Remove proposals in every group the device is in. |
| `GET /v1/e2ee/users/{user_id}/devices` | → `[{device_id, signature_key, cross_signature, created_at}]`, active only, for a member. |
| `POST /v1/e2ee/key_packages` | `{device_id, key_packages: [..≤50], last_resort?}` → `204`. Each is validated: ciphersuite, credential, signature key equal to the registered one, lifetime not expired, public. |
| `GET /v1/e2ee/key_packages/count?device_id=` | → `{remaining}`. |

A key package is claimed once by the server when it builds an Add proposal and deleted. If a device has none, the server uses its `last_resort` package, which is never deleted, and marks the device `low_keys`; the device is sent an `e2ee.keys_low` event and uploads more.

### Groups

| Route | Body → result |
|---|---|
| `GET /v1/e2ee/conversations/{id}` | → `{e2ee, epoch, external_sender, members:[{user_id, device_id}], pending}`. |
| `POST /v1/e2ee/conversations/{id}/group` | `{device_id}` → `201`. The first member device starts the group at epoch 0 when none exists (`409` otherwise). It then fetches pending proposals and commits them. |
| `GET /v1/e2ee/conversations/{id}/handshake?after=<seq>&device_id=` | → `[{seq, kind: "proposals"\|"commit"\|"welcome", epoch, data}]` in order. A `welcome` is only returned to the device it is for. |
| `POST /v1/e2ee/conversations/{id}/commit` | `{device_id, epoch, commit, welcomes:[{device_id, data}]}` → `204`, or `409 stale_epoch`, or `400 bad_e2ee`. The commit must be a public message for this group at `epoch` from the sender's own leaf, must apply the pending proposals, and must carry a Welcome for every added device. |

Live events on the socket: `e2ee.handshake {conversation_id, seq}`, `e2ee.keys_low {device_id, remaining}`, `e2ee.device {user_id, device_id, op: "added"|"revoked"}`. They carry no key material.

### Messages

For an encrypted conversation, `POST /v1/conversations/{id}/messages` takes exactly:

```json
{ "ciphertext": "<b64 MLS PrivateMessage>", "epoch": 7, "device_id": "…", "client_id": "…",
  "kind": "message" | "edit", "target_id": "<message id, for an edit>", "attachment_ids": ["…"] }
```

and refuses with `400 e2ee_required` any request that has a `body`. `client_id` is unique per sender device and conversation (`409` replays, idempotent: the original is returned). A plaintext post to an encrypted conversation is never accepted, and a `ciphertext` post to a plaintext conversation is `400 not_e2ee`. There is no fallback.

A message the server returns has `e2ee: true`, `ciphertext`, `epoch`, `device_id`, `kind`, `body: ""`, and the usual `id`, `author_id`, `created_at`, `deleted_at`. Edits are separate `kind: "edit"` rows pointing at `target_id`, which the server only checks was written by the same user and not deleted. The client folds them. Delete is the existing `DELETE /v1/messages/{id}`: the author only, it removes the ciphertext and the attachments and tombstones the row. There is no moderator delete in v1.

The plaintext inside the MLS application message is JSON, UTF-8, at most 16 KiB:

```json
{ "v": 1, "text": "…", "reply_to": "<id>", "attachments": [
  { "id": "…", "key": "<b64 32 bytes>", "name": "…", "mime": "…", "bytes": 12345,
    "sha256": "<b64, of the uploaded ciphertext>", "width": 0, "height": 0 } ],
  "sent_at": 1730000000000 }
```

`edit` messages carry `{"v":1,"text":"…","attachments":[…]}`. The author is whoever MLS authenticates as the sender; a client ignores an edit whose sender is not the author of the target.

### Attachments

`POST /v1/media` with the form field `sealed=1` stores the body as an opaque blob: no content sniffing, no image decoding, no clamd scan, `kind = "sealed"`, name and type are fixed server-side to `sealed` and `application/octet-stream`. The size limit is the server's file limit. The server never writes a plaintext temporary file for it: the body is written once, as received. A sealed blob can be attached only to an encrypted conversation, by id, through `attachment_ids`. Download authorization is the existing conversation check.

The blob is: a header `"TNYA1"` ‖ 1 byte log2 chunk size (16 for 64 KiB) ‖ 7 byte random nonce prefix, then STREAM-encrypted chunks (AES-256-GCM, 32-bit big-endian counter, last-chunk flag), with the attachment's id and the header as associated data for the first chunk. The client checks `sha256` of what it downloaded before it decrypts, and decrypts as a stream so a large file is never held whole in memory. The key lives only inside the message.

Validations that remain possible on the server: size, per-user upload rate and daily volume, orphan cleanup, that the id belongs to the uploader and is linked once, and that it is only linked into an encrypted conversation. Validations that are not possible: file type, malware, image parsing. The server must not claim to scan sealed files. Clients protect themselves: they detect the real type after decrypting, never open a file automatically, decode images with limits on dimensions and memory, and warn on executable types.

## 6. Storage

The server stores, for an encrypted message: ids, timestamps, `epoch`, `device_id`, `kind`, `target_id`, the ciphertext, and for each attachment its id, ciphertext size and uploader. `messages.body` is the empty string. The `last_message` preview of an encrypted channel is empty. Group state is the handshake log (public MLS handshake messages), the device and key package tables, and the external sender key. No table holds a key that opens a message.

The client stores MLS state through the OS keychain-protected key, and caches decrypted messages encrypted with a per-install key kept in the OS keychain, never with the key in the same file.

## 7. What a person sees

- A conversation shows its state in words and an icon: "End-to-end encrypted" or "Not end-to-end encrypted: the server can read this conversation".
- A conversation that was plaintext and is not converted is labelled as such for all time. Nothing silently reclassifies old plaintext as protected.
- A member's device list is visible, and **safety numbers** (a fingerprint over both people's device signing keys) are shown with a one-tap verified mark. A changed or added device of a verified person produces a visible notice in the conversation; a changed external sender key produces a stronger one.
- A device that cannot decrypt a message shows "Can't be decrypted on this device" and never a blank.
- A client that is too old for this protocol sees `e2ee: true` on the conversation and refuses to post plaintext; the server refuses it if it tries.

## 8. Known gaps

- **Reactions** are plaintext in v1 (emoji, message, user). They reveal who reacted to which message id, not what the message says.
- **Mentions and search** work only on the client, on decrypted text.
- **The server's external sender key** can add a ghost device only if clients accept an Add whose credential has no cross-signed device behind it; they do not. Clients still must check, so a client bug removes this protection.
- **Metadata**: see section 1.
- **A first device is trust on first use.** A malicious server that is present when a person first registers could substitute the key of that first device; verifying safety numbers out of band is the only defence.
- **Compromised endpoint** reads everything the device can.
- **Removal latency** as described in section 4.

## 9. Compatibility and migration

| Case | Behavior |
|---|---|
| Old client, new server, plaintext conversation | unchanged |
| Old client, new server, encrypted conversation | listed with `e2ee: true` and empty bodies; plaintext posts are refused with `400 e2ee_required`; it shows blanks and cannot send. It cannot be tricked into a downgrade. |
| New client, old server | `GET /v1/capabilities` lacks `e2ee_text`; the client offers no encrypted conversations and labels every conversation not encrypted |
| Existing conversations | stay plaintext, labelled; **never converted in place** |
| New encrypted conversations | created with `"e2ee": true` on `POST /v1/channels` and `POST /v1/directs`. Server setting `e2ee_text`: `off`, `optional` (default) or `new_required` (new conversations must be encrypted) |

To move a community to encryption: create encrypted channels, tell people, and let an owner delete the plaintext ones (deleting a channel hard-deletes its messages, and the outbox scrub of `0014` covers edits). `tinyserver` does not offer an automatic converter: converting would copy plaintext into ciphertext made by the server, which would give the server the keys.

Rollback: set `e2ee_text` to `off`. Existing encrypted conversations stay readable by clients and cannot be reopened for plaintext; there is no downgrade path by design. Backups of an encrypted conversation contain only ciphertext.

Backup restore: a restored database restores ciphertext and the handshake log; a restore to an earlier time can roll a group back to an earlier epoch than the clients hold. Clients detect an epoch that went backwards and refuse to continue the group: the group is rebuilt (new group, welcome, history not carried).

## 10. Performance

MLS group cost grows with log n of devices for commits and is constant for application messages. A commit for a 1,000-device group is a few KiB. The server parses public handshake messages and does no cryptography on application messages. Large communities should use channels with a bounded device count or accept commit latency; benchmark numbers are in `docs/privacy/benchmarks.md` and are measured, not estimated.

## 11. Tests that stand for the properties

Server (`crates/api/tests/e2ee_text.rs` and unit tests under `e2ee_text/`):

- confidentiality: after an encrypted post, no table, outbox row or log line holds the plaintext; the upload file holds no plaintext
- no downgrade: a body to an encrypted conversation is `400 e2ee_required`; a ciphertext to a plaintext conversation is `400 not_e2ee`
- key package validation: wrong suite, wrong credential, wrong key, expired, over 50, are refused
- device cross-signature required, and a wrong one refused
- replay: the same `client_id` returns the original
- stale epoch: two commits for one epoch, one wins
- removed member: after losing `view_channel` they get no ciphertext and cannot post; a Remove is queued
- device revocation queues Remove and ends delivery to that device
- unauthorized cross-conversation: another conversation's group, handshake and attachments are not readable
- malformed MLS and oversized payloads are refused without panic, and a fuzz target exists
- sealed upload: no sniff, no scan, no plaintext temp file, size and rate limits, only linkable into an encrypted conversation
- migration: old and new clients against old and new servers, as in section 9

Client (`crates/e2ee`): real openmls groups with 3 and 20 devices, add, remove, epoch change; a removed device cannot decrypt a later message; a new device cannot decrypt an earlier one; replay and tamper rejection; attachment encryption round trip, truncation, reorder, bit flip, wrong key; AES-GCM known-answer vectors from NIST and Wycheproof; property tests on the envelope codec and on chunk boundaries.

## 12. Not covered by tests or verified

Anything that needs an independent cryptographic review: the group-state machine under network partitions, the safety-number construction beyond what the MLS exporter provides, key package exhaustion attacks, and the sealed-blob format. These are listed as open in `docs/privacy/remaining-risks.md`.
