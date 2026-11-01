# Compatibility and migration

What happens to existing plaintext, to old and new clients and servers, to the schema, and to backups, when text and attachment E2EE is introduced and when a community moves hosts. Sources: [`../e2ee-text.md`](../e2ee-text.md) section 9, [`../calls.md`](../calls.md) "Compatibility", `crates/db/src/migrate.rs`, `crates/db/migrations/`, `deploy/compose.yml`, `deploy/README.md`, tinyclient `docs/architecture.md` (read only). Status words are in [`README.md`](README.md). Text E2EE is **in progress**: everything about it here is the specification.

## 1. Existing plaintext

| Statement | Source |
|---|---|
| Existing conversations stay plaintext. They are **never converted in place** | `e2ee-text.md` section 9 |
| The client labels a plaintext conversation as such for all time: "Not end-to-end encrypted: the server can read this conversation". Nothing silently reclassifies old plaintext as protected | section 7 |
| There is no automatic converter: converting would copy plaintext into ciphertext made by the server, which would give the server the keys | section 9 |
| How a community moves: create encrypted channels, tell people, and let an owner delete the plaintext ones. Deleting a channel hard-deletes its messages; the outbox scrub (`0014`) covers edits | section 9 |
| The old plaintext survives in: Postgres WAL and dead rows until cleared, every backup taken before the delete, every client's local cache (`chat.sqlite` is not encrypted at rest), other members' devices | [`retention-and-deletion.md`](retention-and-deletion.md) |
| Attachments of plaintext conversations stay plaintext files in the upload volume, with plaintext names and types in `attachments` | [`metadata.md`](metadata.md) |

A plaintext conversation in a community that also has encrypted ones is not protected by the others. The product page must not describe the community as "end-to-end encrypted"; only individual conversations are.

## 2. Old and new, client and server

Capability discovery is `GET /v1/capabilities`: `e2ee_calls` (implemented) and `e2ee_text` (specified). A server from before capabilities answers 404.

### Text and attachments (specified)

| Client | Server | Conversation | Result |
|---|---|---|---|
| Old | Old | Plaintext | Works as today |
| Old | New | Plaintext | Unchanged |
| Old | New | Encrypted | Listed with `e2ee: true` and empty bodies; plaintext posts are refused (`400 e2ee_required`); it shows blanks and cannot send. It cannot be tricked into a downgrade |
| New | Old | Any | `e2ee_text` is absent from capabilities: the client offers no encrypted conversations and labels every conversation not encrypted |
| New | New, `e2ee_text=off` | Plaintext | No new encrypted conversations. Existing encrypted ones keep working |
| New | New, `optional` (default) | Either | New conversations are encrypted if created with `"e2ee": true` |
| New | New, `new_required` | New ones | Must be encrypted |
| Bots | Any | Encrypted | Bots are refused on every message route and receive no message frames. They cannot read an encrypted conversation, and they cannot read a plaintext one either |

### Calls (implemented)

| Pair | Result |
|---|---|
| New app, new server, everyone new | End-to-end encrypted |
| New app, new server, someone older in the call | Transport only for everyone, each new app names who cannot; encrypted again once they leave. In a room with `e2ee_required` the older app is refused |
| Older app, new server | Unchanged. It never sends `e2ee` and never gets `call.e2ee` |
| New app, older server | No `e2ee_calls` capability; transport only, shown as such |

The downgrade is by design and visible. It is also what a hostile server does ([`threat-model.md`](threat-model.md) scenario B).

### A hazard: a downgrade through rollback

If the server binary is rolled back to one that does not know encrypted conversations after some exist, the old code still sees ordinary `messages` and `channels` rows and would accept a plaintext `body` post from an old client into a conversation that other members' devices treat as encrypted. A new client talking to that server sees no `e2ee_text` capability and labels every conversation not encrypted, so it would not warn. The specification's rollback is a setting (`e2ee_text=off`), not a binary downgrade, and says so. What actually stops a binary downgrade is the migration check in section 3: the init container's `tinyserver migrate` should fail (and the stack not start) when the database holds migrations the binary does not have. That relies on `sqlx` 0.8's default (`ignore_missing` off, so an applied migration absent from the binary is an error). **Not tested in this repository.** The legacy single-container entrypoint (`deploy/entrypoint.sh`) also migrates first when `DATABASE_URL_MIGRATE` is set; `tinyserver serve` alone does not check.

## 3. Schema migrations

| Fact | Detail |
|---|---|
| Mechanism | `sqlx::migrate!("./migrations")`, run by `tinyserver migrate` as `app_owner` (`crates/db/src/migrate.rs`). Files are `NNNN_name.sql`, forward only. **There are no down migrations** |
| When it runs | In the `tinyserver-init` container on every `docker compose up`, before the server (`depends_on: service_completed_successfully`). The serving container has no owner credentials (finding S2) |
| Build input | `crates/db/build.rs` makes `migrations/` a cargo input so a new file cannot be missing from a cached build (finding S15) |
| Main at `c4ae28b` | Ends at `0016_operator.sql` (`0015_abuse_reports.sql`, `0016_operator.sql` came with #20) |
| E2EE migrations | The specification says `0020`–`0029` (devices, key packages, handshake log, conversation flag, sealed uploads). They are not on main. `0017`–`0019` are unused on main; other branches may use them. **Check for number and content collisions when branches merge**: an out-of-order or duplicate version fails the run |
| Locking | `sqlx` takes an advisory lock while migrating; the server is not running during init, so no live traffic competes. Time on a large database was **not measured** (P17 in [`performance.md`](performance.md)) |
| Data migrations | `0013` rewrites event audiences from now on (new rows only); `0014` adds a trigger and a function; neither rewrites existing rows. `0015` adds `manage_reports` to every non-default role that already had `manage_server` (`upgrading_grants_manage_reports_to_owners_and_manage_server_roles_only`); `0016` inserts the single `operator_state` row. The E2EE migrations must not touch existing plaintext |
| Expand and contract | Not practised. An old binary against a new schema is not supported: it either fails the migrate check or runs against columns it ignores |

## 4. Rollback

| What to undo | How | What it costs |
|---|---|---|
| A bad server image, no schema change in it | Redeploy the older image; `up` reruns init; migrate is a no-op | None |
| A bad server image whose migrations are already applied | Not supported by `migrate`. Options: roll forward with a fix; or restore a database backup taken before the upgrade, and lose everything written since | Data loss since the backup. Restores have their own hazards (section 5) |
| Turn text E2EE off | `e2ee_text=off` (specified): no new encrypted conversations. Existing encrypted conversations stay readable by clients and **cannot be reopened for plaintext**. There is no downgrade path by design | Users keep what they have; no data is made readable to the server |
| Turn call E2EE off | Not a server setting. A room's `e2ee_required` can be cleared; the call is transport-only whenever any app cannot encrypt | Visible in the apps |
| A client | Client upgrades change local schema: `chat.sqlite` has `PRAGMA user_version` (4) and "a version change drops and refills the cache" (client `docs/architecture.md`). **For an encrypted conversation a dropped cache is permanent loss of readable history**: MLS deletes message keys after use (RFC 9420's deletion schedule), so a client that loses its cached plaintext cannot decrypt the same ciphertext again unless it kept past message secrets, and a re-added device cannot read earlier messages. How long tinyclient retains them was not checked | Engineering requirement: an encrypted cache must survive client schema changes, with a migration and a test; a client rollback must not drop it |

## 5. Backups and restores

**`deploy/tenant/operator.sh backup`, `export` and `restore`** (#20, finding S11; usage in `deploy/tenant/README.md`, promises in [`tenancy.md`](tenancy.md)). A backup is one age file, encrypted to the `--recipient`s given and to the tenant's own key if `keygen` made one; the plaintext is assembled in a tmpfs inside a throwaway container with no route out and never written to the host's disk. `restore` checks the bundle's checksums before touching anything, refuses under a legal hold, replaces the target's database, uploads, Pocket ID data and secrets, re-owns every object to the target's own roles, and starts the stack, which migrates an older bundle forward. Checked by `deploy/tests/hooks.sh` (Docker and `age`; not in CI, not run for this pass). The manual `pg_dump -U postgres tinyserver` in `deploy/README.md`'s Tinyauth steps still exists and is unencrypted.

### What a backup contains

| Store | Why | In the bundle? |
|---|---|---|
| Postgres database | Everything in [`metadata.md`](metadata.md) section 1 | Yes, `pg_dump -Fc` as the owner role. Plaintext text and attachment metadata inside the encryption |
| `tinyserver_uploads` | Attachment bytes | Yes. Plaintext files inside the encryption |
| `pocketid_data` and `secrets/pocketid_encryption_key` | Pocket ID's accounts, passkeys and signing key. Without them nobody can sign in | Yes; Pocket ID is stopped for the copy |
| `secrets/oidc_client_secret`, `secrets/pocketid_api_key` | To start the stack; the API key acts as a Pocket ID administrator | Yes |
| `.env` or `tenant.env` (`TINYSERVER_MEDIA_HMAC_SECRET`, database passwords, tunnel token) | To start the stack | **No.** The restore target keeps its own |
| E2EE: the server's external sender key (text) | Without it every client shows "external sender key changed". Its storage location is not specified | Not applicable on main; not verified |
| `tinyserver_bootstrap` | Not needed once an owner exists | Not checked |

A backup that holds the database and the secrets together lets whoever opens it read plaintext conversations and sign in as anyone. The requirement was **a key held apart from the tenant host, and destroyable**. What exists: the operator's recipient, held wherever the operator keeps it, and the tenant's own key from `keygen`, which `delete` destroys but which sits on the tenant's host (`tenants/<name>/backup.key`) until the operator moves it ([`encryption-architecture.md`](encryption-architecture.md) section 5). For E2EE conversations a backup would contain only ciphertext (specified, not on main). No schedule, rotation or retention exists.

### Restore hazards

| Hazard | Effect | Requirement |
|---|---|---|
| Sessions revoked after the backup reappear | A token that was signed out or banned since is valid again until expiry | After a restore, delete all `sessions` rows (everyone signs in again), and re-apply bans. **`restore` does neither** ([`findings.md`](findings.md) N11) |
| Accounts deleted after the backup reappear, with their messages | Defeats `DELETE /v1/me` | Keep a minimal ledger of deleted account ids and replay it after a restore ([`retention-and-deletion.md`](retention-and-deletion.md)). **Not built** (N11) |
| Restoring over held data | Overwrites what a legal hold keeps | `restore` refuses under the operator's hold or a held report (`deploy/tests/hooks.sh`) |
| Event sequence | Clients holding a `seq` higher than the restored `outbox` get `resync` (`since` above the newest seq closes with `4002`; `docs/calls.md`) | None. Behaviour documented |
| MLS group rolled back to an earlier epoch | Specified: clients detect an epoch that went backwards and refuse to continue; the group is rebuilt (new group, welcome, history not carried) | Test needed; part of the in-progress work |
| Pocket ID restored to a different time than tinyserver | `(issuer, subject)` pairs can disagree: accounts created or removed on one side only | Restore both from the same instant, or reconcile with `tinyserver identities` and `relink-identity` |
| Upload volume and database at different times | Missing files give `404` on download; orphan files stay | Take them together |
| Restored backup of a deleted tenant | Resurrects data the customer asked to delete | Retention horizon and key destruction. A backup encrypted to the tenant's key alone cannot be restored after `delete` unless an escrow copy of the key survives (`hooks.sh`) |
| Clients ahead of the server's MLS state for calls | A call's group no longer matches | Clients rejoin ([`tenancy.md`](tenancy.md), "Known limits") |

## 6. Provider and host moves

| Move | Notes |
|---|---|
| Tinyauth to Pocket ID (existing) | The issuer stays, every subject changes. Each account is moved by `tinyserver relink-identity`. Since finding S2's change removed `DATABASE_URL_MIGRATE` from the server container, these run as `docker compose run --rm --entrypoint tinyserver tinyserver-init identities`, as `deploy/README.md` step 6 says (finding N5) |
| Self-hosted to TinyCloud | The hostname changes, so the origin in every client, every invite code (`tc1.` embeds the origin) and every session changes: everyone signs in again at the new origin. If the IdP is recreated, subjects change (relink). E2EE: group ids are conversation ids and stay; **the server's text external sender key must move with the data** or clients show their strongest warning. The media IP and port change (clients get them in each SDP) |
| Between tenants or hosts run by the same operator | `operator.sh backup` then `restore` into the new target: a move that works between tenants with different role names and into a plain stack (`hooks.sh`). The source still exists, with the same secrets, until `delete` |
| TinyCloud to self-hosted, or to another provider | The same, plus: `operator.sh export` gives the owner the bundle encrypted only to the owner's recipients, with the compose file, `01-roles.sh` and a README for `restore --stack` (`hooks.sh`: the operator's key cannot open it). The tunnel token and database passwords are not in it; the new host makes its own |
| Pocket ID to another provider | A new issuer is a new set of accounts (`two_providers_make_two_identities_for_one_subject`). Existing accounts are re-pointed by `relink-identity` with `--issuer` |
| Cloudflare to another front | `TINYSERVER_TRUSTED_PROXIES` must name the new proxy or all sign-in routes share one limiter bucket ([`network.md`](network.md) section 3) |

## 7. Open items

| Item | Type |
|---|---|
| Test that `migrate` fails when the database is ahead of the binary | Engineering requirement |
| Down-migration policy or an expand-and-contract rule | Engineering decision |
| Backup tool with encryption: built (`operator.sh`). A deletion ledger, clearing sessions on restore, a schedule and a retention period: not built | Engineering requirement (S11, N11) |
| Client cache survives upgrades for E2EE conversations | Engineering requirement |
| Where the text external sender key is stored, and how it is exported | Specification gap |
| Export and import of a community between providers | Built as `operator.sh export` and `restore --stack`; the receiving provider must run this stack's compose file |
