# Retention and deletion

How long each kind of data stays, what each deletion path removes, and what a deletion cannot reach. Sources: `crates/db/migrations/0004_oidc.sql` (`app_sweep`), `0014_account_deletion.sql`, `crates/db/src/sweep.rs`, `crates/db/src/messages.rs`, `crates/server/src/main.rs`, `deploy/compose.yml`, and the tests named. Status words are in [`README.md`](README.md). The inventory of where data lives is [`metadata.md`](metadata.md).

## 1. Retention by data class

"Fixed" means no setting changes it. There is no retention policy feature: nothing deletes messages, audit rows or bans by age.

| Data | Kept for | Mechanism | Operator can change it? |
|---|---|---|---|
| Sessions | `TINYSERVER_SESSION_MAX_DAYS` from sign-in (default 30), or until revoked | Expired rows deleted by the sweep every 10 minutes | Yes, 1 to 365 days |
| Pending sign-ins | 10 minutes | Sweep | No |
| One-time sign-in codes | 60 seconds; deleted on the first try | Sweep, and the redeem | No |
| Invites, never accepted | Until `expires_at` (7 days by default; owners and `manage_server` may set none) | Sweep | Per invite |
| Invites, accepted | Indefinitely (with who accepted) | Not swept | No |
| Idempotency keys | 1 day | Sweep | No |
| Live event history (`outbox`) | 24 hours | Sweep. Edits and deletes rewrite earlier rows (`0014`) | No |
| Messages | Until deleted by the author, the channel is deleted, or the author's account is deleted | Soft delete: body emptied, row kept as a tombstone | No |
| Attachments | As the message. Unlinked uploads: one hour | Sweep for orphans; `unlink` on delete | No |
| Reactions, read marks | With the message or the person | Cascade or account deletion | No |
| Audit log | **Indefinitely.** No sweep touches it | | No |
| Bans and banned identities | **Indefinitely**, expired bans included | | No |
| Bots (revoked) | Indefinitely | | No |
| Avatars and server icon | Until replaced or removed; avatar cleared on account deletion | | No |
| Rate-limit buckets | 60 seconds | In memory | No |
| Call state | While the call lasts | In memory; ends on restart | No |
| Operator log lines | 10 MB times 3 per container | Docker `json-file` rotation (by size, not time) | Docker settings |
| Debug ring | One hour, about 2000 lines | In memory | `TINYSERVER_LOG_RING=off` |
| Debug bundles | 24 hours after the next start; on a tmpfs in compose, so lost at container stop | `sweep_bundles` | `TINYSERVER_LOG_BUNDLE_HOURS`, `TINYSERVER_LOG_EXPORT=off` |
| Owner invite file | Until the next `tinyserver-init` after an owner exists | `remove_owner_invite` | No |
| Pocket ID audit events (with client IP) | 90 days by default (Pocket ID's `AUDIT_LOG_RETENTION_DAYS`; not set in this stack; not verified for `v2.19.1`) | Pocket ID | Yes, by setting the variable |
| Postgres WAL, dead tuples | Until checkpoints and vacuum clear them; no WAL archive is configured here | Postgres | Yes, in Postgres settings |
| Backups | **Not defined in this branch** | See [`migration.md`](migration.md) | |
| Cloudflare and hosting provider records | Their policies. Not reviewed | | No |

Implications for what can be advertised: nothing in the code supports "messages are deleted after N days". Message retention is "until someone deletes it". The audit log and ban list grow without bound and contain ids and free-text reasons.

## 2. Deletion paths

### 2.1 Delete a message (`DELETE /v1/messages/{id}`, author only)

Body cleared, reactions and attachment rows deleted, files unlinked, `deleted_at` set. The row stays with `author_id`, `channel_id` or `direct_id`, `created_at`, `edited_at`, `deleted_at`. The outbox rows for that message are rewritten to an empty body and no attachments, and the preview of the channel's last message is blanked (`0014`). There is no moderator delete of another member's message in the specification for encrypted conversations; for plaintext conversations `manage_channels` can delete the whole channel. Test: `a_member_can_post_edit_react_and_read_but_not_create_a_channel`; `deleting_an_account_removes_the_person_and_what_they_said` covers the outbox rewrite on edit.

### 2.2 Delete a channel

`DELETE /v1/channels/{id}` deletes the channel and, by cascade, its messages, reactions and reads; attachment files are unlinked. Audited `channel.delete`. Rows go; WAL and backups keep them.

### 2.3 Kick, ban, timeout

A kick deletes the membership and every session. A ban does that plus writes `bans` and `ban_identities`. Messages the person wrote **stay**. A timeout changes `timeout_until` only.

### 2.4 Account deletion (`DELETE /v1/me`)

Implemented in `0014_account_deletion.sql` by `app_delete_account()`, one transaction, caller only. Typed confirmation `delete my account` required; a sole owner is refused (`409 last_owner`). Test: `deleting_an_account_removes_the_person_and_what_they_said` (`crates/api/tests/privacy.rs`).

| Removed | Evidence |
|---|---|
| `users.email`, `display_name` (set to "Deleted user"), avatar bytes, hash and type; `deleted_at` set | The test asserts `(None, "Deleted user", true, true)` |
| `user_identities`, `memberships` (and `member_roles` by cascade), `sessions` | The test asserts no rows remain |
| Every message the person wrote: body emptied, `deleted_at` set | The test asserts the other member sees an empty body and a `deleted_at` |
| Their attachments and the attachments of their messages, and reactions on and by them; files unlinked after the commit | Read; not asserted by the test |
| `reads`, bots they created, unused invites they created, idempotency keys | Read; not asserted |
| `outbox` rows carrying their member events (name, email) | The test asserts the needles "Ada Lovelace" and the email are not in the outbox |
| `display_name`, `name`, `email` keys inside `audit_log.detail` where they were actor or subject | The test asserts the needles are absent from `audit_log.detail` |

| Kept | Why |
|---|---|
| The `users` row as a tombstone: id, `created_at`, `deleted_at` | Messages, channels, directs and invites point at it |
| `messages` tombstones: `author_id`, conversation id, `created_at`, `edited_at`, `deleted_at`, `reply_to`, `client_id` | Same. They say a message existed, when, and who wrote it by id |
| `directs` rows | They say which two accounts had a conversation. Not deleted |
| `audit_log` rows with `actor_id`, `subject_user_id`, `action`, `reason`, timestamps | The record that something happened. **`reason` is free text and is not scrubbed**: a kick reason that typed a person's name keeps it |
| `bans` and `ban_identities` (the provider identity of a banned person) | A ban must survive deletion. This is the one place an identity outlives its account |
| Accepted invites the person created (`invites.created_by` id) and `invites.accepted_by` pointing at them | Not deleted by the function |
| Channels and rooms they created (`created_by`) | |
| The **Pocket ID account** | tinyserver never calls the provider. Its administrator must delete it |

Not reachable by any in-application deletion:

- **Postgres write-ahead log, dead rows before vacuum, base backups and snapshots, replicas.** Stated in `0014`'s header.
- **Plaintext copies other people hold.** A message someone read stays read; clients cache messages (`chat.sqlite` is not encrypted at rest).
- **Cloudflare's logs, the hosting provider's records, any Docker log line** that mentioned the user id.
- **Files**: `unlink` does not overwrite bytes; a filesystem snapshot or backup keeps them.

### 2.5 Sessions and tokens

`DELETE /v1/session`, `DELETE /v1/sessions`, provider back-channel logout, kick, ban and account deletion remove session rows. Bot tokens are revoked (`revoked_at`), not deleted. Invites are revoked by delete.

## 3. Erasure requests, backups and legal holds

Technical position only. Whether any of this satisfies a legal duty is for counsel ([`compliance.md`](compliance.md) sections 6 and 7).

| Issue | Engineering state | Engineering requirement |
|---|---|---|
| A person asks to erase their data | `DELETE /v1/me` handles the live database. Nothing handles backups, WAL, the IdP or logs | A documented erasure procedure that names every store in [`metadata.md`](metadata.md), with an owner and a time limit for each |
| Backups keep deleted data | No backup is shipped. Any dump contains plaintext today | Choose a backup retention period short enough to be a stated erasure horizon. Encrypt backups with a key that can be destroyed (crypto-shredding). After a restore, **replay deletions**: keep a minimal ledger of deleted account ids (and nothing else) so a restore does not resurrect them. The ledger is itself retained data and goes in [`metadata.md`](metadata.md) when built |
| Legal hold | **Not implemented.** Deletion is immediate and irreversible in the live database. A hold would need a way to freeze a tenant or an account (block `app_delete_account`, message deletes, sweeps and tenant deletion) while a valid order is open | Design a hold flag and its audit trail with [`abuse-response.md`](abuse-response.md). Whether and when a hold may override a deletion request is a question for counsel |
| Report evidence (for example material that must be preserved when reported) | Plaintext conversations can be copied by an administrator with host access. Encrypted conversations cannot be read by the server (**in progress**) | See [`abuse-response.md`](abuse-response.md) and [`compliance.md`](compliance.md) section 2. Preservation of reported content is limited to what reporters provide when the server holds only ciphertext |
| E2EE and deletion | A delete removes ciphertext and attachment blobs from the server. It cannot recall plaintext already on devices. There are no disappearing messages in the specification | State this on the product page |

## 4. Deleting a tenant (TinyCloud)

**Not built.** What a complete tenant deletion has to remove, as a checklist for the control plane:

1. The tenant's containers, the `tinyserver_pg` volume (or `TINYSERVER_PG_DIR`), `tinyserver_uploads`, `tinyserver_bootstrap`, `pocketid_data`, `clamav_db`, the secrets directory and `.env`.
2. The Cloudflare tunnel, its public hostnames and DNS records, and the tunnel token.
3. The router or firewall rule for the media port; the public IP assignment.
4. Backups and their keys (destroying the key is the fast route; see above).
5. Log files on the host and in any collector.
6. What remains by necessity: billing records, abuse-report and legal-process records, any legal hold (category 5 in [`guarantees.md`](guarantees.md)).

Verification that a volume is gone, and the time it takes, are not specified here.

## 5. Client side

Sign-out in tinyclient deletes the credential-store item, the account's rows in `chat.sqlite` and its media directory. It does not vacuum the SQLite file, so deleted content can remain in free pages. The sign-in window's browser cookies are not cleared. The call identity key and verified-keys file are under `e2ee/<account>/`; whether sign-out removes them was not checked. Source: tinyclient `SECURITY.md` ("Sign-out", "Known limits").

## 6. Gaps and decisions

| Gap | Type |
|---|---|
| No message-retention or auto-delete setting | Product decision; not built |
| Audit log and ban list never expire; the audit log's free-text `reason` is not scrubbed on account deletion | Engineering requirement: an expiry or a scrub, once counsel says how long the records must be kept |
| `DELETE /v1/me` does not delete the Pocket ID account | Engineering requirement |
| `directs` rows survive account deletion | Engineering decision: delete the row when both sides are gone or one is a tombstone? |
| No legal hold | Engineering requirement and question for counsel |
| No backup encryption or restore-time replay of deletions | Engineering requirement (finding S11) |
| No secure erase of attachment files | Engineering requirement if disk encryption alone is not accepted; for sealed uploads the file is ciphertext |
