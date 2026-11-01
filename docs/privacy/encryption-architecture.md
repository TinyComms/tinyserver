# Encryption architecture: keys, owners and lifecycle

A summary of what is encrypted, with what, who holds each key, and when it is made, rotated and lost. It links to the two specifications instead of repeating them: [`../calls.md`](../calls.md) ("End-to-end encryption") for calls and [`../e2ee-text.md`](../e2ee-text.md) for text and attachments. Where they disagree with this file, they win and this file is wrong.

Status words are in [`README.md`](README.md). **Calls: implemented and tested. Text and attachments: the server side is implemented and tested (#23, `crates/api/tests/e2ee_text.rs`); the client side is on tinyclient main: #126 (`0c405dc`, the `crates/e2ee` crate) and #127 (`89188e8`, the Tiny adapter), in no release yet; its tests are named below and were not run here. Backups: encrypted with age by `deploy/tenant/operator.sh` (#20).** TLS and DTLS-SRTP are transport encryption and are listed only so the boundary is clear.

## 1. The layers

| Layer | Protects against | Ends at | Status |
|---|---|---|---|
| TLS between client and Cloudflare | A network observer | Cloudflare's edge | In use; Cloudflare's, not tinyserver's |
| Cloudflare tunnel (cloudflared to Cloudflare) | A network observer between host and Cloudflare | Cloudflare | In use |
| DTLS-SRTP between client and SFU | A network observer on the media path | The SFU (it decrypts) | Implemented (`crates/sfu`) |
| DAVE end-to-end encryption of call frames (MLS group per room call) | The SFU and its operator, Cloudflare, the network | The other participants' apps | Implemented; downgradable by the server, visibly |
| MLS end-to-end encryption of text, edits, replies (group per conversation) | The server, its operator, its database, backups, Cloudflare | Members' devices | Implemented, tested (server here; client in tinyclient #126, #127) |
| Sealed attachments (AES-256-GCM STREAM, key in the MLS message) | Same | Members' devices | Implemented, tested (server here; client in tinyclient #126, #127) |
| Postgres and volumes | A stolen disk | Not encrypted by this stack. Whatever disk encryption the host has (on TinyCloud, the cell's fscrypt key, per [`tenancy.md`](tenancy.md); not in this repository) | No stack-level encryption; plaintext for plaintext conversations, ciphertext for encrypted ones |
| Backup and export bundles (age; `age1` X25519, `ssh-ed25519` or `ssh-rsa` recipients) | Whoever holds the file without a matching identity | Whoever holds an identity for one of the recipients | Implemented: `deploy/tenant/operator.sh backup`, `export`; `deploy/tests/hooks.sh` (no plaintext in the file, another key cannot open it). Inside the encryption the bundle holds plaintext conversations in plaintext, encrypted ones as ciphertext, and the text external sender private key (finding N15) |

## 2. Calls (implemented)

Protocol: MLS (RFC 9420), ciphersuite `MLS_128_DHKEMP256_AES128GCM_SHA256_P256`, applied as Discord's DAVE version 1 does. The apps run it with the `davey` crate. The server (`crates/api/src/live/e2ee.rs`) uses `openmls` only to parse and validate the public handshake messages it relays.

| Item | Detail |
|---|---|
| Group | One per room's call. The group id is the first 8 bytes of SHA-256 over `tiny-e2ee-v1 room ` and the room id |
| Member identity | An MLS basic credential holding the 8 byte **MLS id**: first 8 bytes of SHA-256 over `tiny-e2ee-v1 user ` and the user id |
| Identity key | A P-256 signing key each app makes on its first call and keeps in `e2ee/<account>/identity.key` (a plaintext file, mode 0600 on Unix: finding C4, open). It signs the member's credential, so the same account shows the same key in every call |
| Key packages | Made by each app when it joins and sent as `call.e2ee key_package`; the server holds them in memory until the Add proposal is committed |
| Server key | The server's **external sender** P-256 key: made at process start, in memory only, never written or logged, lost at restart. It signs external Add and Remove proposals and nothing else |
| Who commits | A member's app. The first valid commit for a batch wins. The server orders and relays; it cannot commit or decrypt |
| Frame keys | Per sender, derived from the MLS exporter secret of the epoch, ratcheted per generation; AES-128-GCM with an 8 byte tag. A member who holds the epoch secret can derive every sender's key, so a member can forge a frame as another (as in DAVE) |
| Rekey | Every join and every leave is a commit and a new epoch. Who left cannot read later frames; who joined cannot read earlier ones |
| What stays in the clear | RTP headers and the RFC 6464 audio level (so the SFU can forward and find the speaker); the H.264 NAL header (one byte) |
| Verification | A 30 digit **call code** from the epoch authenticator, the same for everyone in the call (a server that split the call in two would show each half a different code). A 45 digit **safety number** per pair of members, with "Mark as verified" stored in `e2ee/<account>/verified.json` and a loud warning when a verified person's key changes |
| Downgrade | One app that cannot encrypt turns the call to transport only for everyone, and each app names who. The server can also claim someone cannot. A room's `e2ee_required` refuses apps that cannot, but it is a promise the server makes, not one the apps can check. tinyclient has an opt-in "require" mode that blocks media on `off` (finding S4, fixed as opt-in, default off) |
| Server restart | The group and external sender key are gone; calls end; clients rejoin |
| Video | tinyclient's `mediad` seals H.264 pictures with the same group (`crates/mediad/src/e2ee.rs` `seal_video`, called from `tiny.rs`, at `26916e9`); the server does not read NAL headers and does not seal. The client's `SECURITY.md` says the opposite ("video ... are not end-to-end encrypted ... this release seals only audio"). The code and `docs/calls.md` agree with each other; the `SECURITY.md` sentence looks stale. **Not verified by running a call** |

Tests that stand for these properties (server side): `crates/api/tests/e2ee.rs` (`three_apps_agree_on_a_code_the_server_cannot_know`, `only_the_seat_holder_speaks_mls_and_only_as_itself`, `an_app_that_cannot_encrypt_turns_the_call_to_transport_only_unless_required`) and `crates/api/src/live/e2ee/tests.rs` (ten tests, including `three_people_join_leave_and_rekey`, `only_the_first_commit_counts`, `a_key_package_must_be_the_senders_own`, `a_commit_from_someone_not_asked_or_malformed_is_refused`). Client side: tests in tinyclient `crates/mediad/src/e2ee/tests.rs` and `crates/mediad/tests/tiny.rs`; not run here.

What no test shows: that no group secret ever reaches the server (it follows from the protocol and from the module's state, which has no field for one; `e2ee.rs` header and structs), and that an app really drops a clear frame during an E2EE call (client behaviour, per client `SECURITY.md`).

## 3. Text (implemented: server #23, client tinyclient #126 and #127)

This section summarises [`../e2ee-text.md`](../e2ee-text.md). Rows about what the server does are implemented and tested by `crates/api/tests/e2ee_text.rs` (#23). Rows about what clients do are implemented in tinyclient #126 and #127 and asserted by the tinyclient tests named; those were read, not run, here.

| Item | Detail |
|---|---|
| Protocol | MLS, same ciphersuite as calls, with `openmls` in tinyclient |
| Group | One MLS group per encrypted conversation (channel or direct); the group id is the 16 byte conversation id; members are devices. Created with `"e2ee": true`; the flag never clears. **Existing conversations stay plaintext and are never converted in place** |
| Device | One install of tinyclient signed in to an account. Random UUID device id; a P-256 signing key made on the device and never sent anywhere. The MLS credential is 32 bytes: user id then device id. The server refuses a key package whose credential is not the caller's |
| Cross-signing | A person's first device is trusted on first use. Each later device carries an ECDSA P-256 cross-signature from an active device over `"tiny-e2ee-v1 device-add" || user_id || device_id || signature_key`. Clients verify the chain themselves. The server refuses a later device without a valid cross-signature (`a_later_device_needs_a_cross_signature_from_an_active_one`); against a hostile server only the clients' check counts. A new person is not covered (G3, G4 in `e2ee-text.md` section 8) |
| Server key | A **persistent** P-256 key, generated at first start, used as MLS external sender to sign Add and Remove proposals only. Clients pin it on first sight and warn if it changes. The public half is the `e2ee_server_key` row. The private half is a file (`the_servers_external_sender_is_one_key_kept_in_a_file`): a database dump does not hold it. The age backup bundle does, so a restore can still sign. A start with a public key and no file refuses to mint a new one (`a_public_key_with_no_secret_anywhere_is_not_replaced`). Finding N15 |
| Membership | The desired device set is every active device of every user who can view the conversation. The server records external proposals when that changes; any member device commits them. The first valid commit for an epoch wins. A removed member stops receiving ciphertext at once; loses future keys at the next commit. If no member device is online the commit waits. A group holds at most `e2ee_group_devices_max` devices (default 2,000); the rest wait and the count is reported |
| New members and devices | Read nothing from before they were added |
| History | Not re-encrypted on removal; removed members keep what they have |
| Message | `ciphertext` (MLS PrivateMessage) plus `epoch`, `device_id`, `client_id`, `kind` (`message` or `edit`), optional `target_id` and `attachment_ids`. The server refuses a plaintext body to an encrypted conversation and a ciphertext to a plaintext one: no fallback. It also refuses a post whose `kind` and `target_id` differ from the message's MLS authenticated data |
| Inside the ciphertext | JSON, UTF-8, at most 16 KiB: `v`, `text`, `reply_to`, `attachments[]` (id, key, name, mime, bytes, sha256, width, height), `sent_at` |
| Client storage | MLS state through a key in the OS keychain; decrypted cache encrypted with a per-install keychain key, not in the same file |
| Restore of the database to an earlier time | Clients detect an epoch that went backwards and refuse to continue; the group is rebuilt, history not carried |
| Server setting | `e2ee_text`: `off` stops new encrypted conversations (existing ones stay readable by clients and cannot be reopened for plaintext); `required` refuses every plaintext post, edit, conversation and upload (`under_required_the_server_takes_no_plaintext_at_all`) |
| Community root key | An owner's device publishes a P-256 root key and a policy it signed (`GET`/`PUT /v1/e2ee/community`); the server checks the signature, and replacing the root is audited and announced to every member. The client does not pin or check it yet (tinyclient `docs/e2ee-text-client.md`, "Not done") |

## 4. Attachments (implemented: server #23, client tinyclient #127)

| Item | Detail |
|---|---|
| Cipher | AES-256-GCM in the STREAM construction (RustCrypto `aead::stream`), 64 KiB chunks, random 256 bit key per attachment |
| Blob | Header `TNYA1` ‖ log2 chunk size ‖ 7 byte nonce prefix, then chunks. Associated data for the first chunk: the header and `conversation_id ‖ attachment_id` when the client chose the upload's id, else the header alone |
| Where the key lives | Only inside the MLS message (`attachments[].key`) |
| Upload | `POST /v1/media` with `sealed=1`: stored once as received, name and type fixed to `sealed` and `application/octet-stream`; no sniffing, no decoding, **no virus scan**, no temporary file; the only content check is the blob's framing; linkable only into an encrypted conversation (`a_sealed_upload_is_opaque_and_stored_as_it_came`) |
| Integrity | The client checks `sha256` of the downloaded ciphertext before decrypting, and decrypts as a stream |
| Server can still check | Size, per-user rate and daily volume, orphan cleanup, that the id belongs to the uploader and is linked once |
| Server cannot check | File type, malware, image parsing. Clients must sniff after decrypting, never open automatically, decode images with limits |
| Lifecycle | Deleting the message deletes the blob. A key a recipient already holds still opens a copy they kept |

## 5. Key ownership table

| Key | Made by | Held by | Protected by | Rotation | Loss or compromise |
|---|---|---|---|---|---|
| Call identity key (P-256) | tinyclient, first call | Plaintext file on the device | File permissions only | No rotation is described in the client `SECURITY.md` | Impersonation in later calls until peers re-verify; a new install is a new identity |
| Call group secrets, frame keys | The apps, per epoch | App memory | n/a | Every join and leave | Epoch compromise exposes that epoch's frames |
| Server external sender key, calls | tinyserver, at start | Server memory | n/a | At restart | Lets its holder propose members; clients refuse names not on the roster |
| Server external sender key, text | tinyserver, first start | Private half in `{TINYSERVER_DATA_DIR}/e2ee-server-key` or `TINYSERVER_E2EE_KEY_FILE` (compose: `tinyserver_keys`). Public half in `e2ee_server_key`. An age backup carries the file; a database dump does not | File mode 0600 on Unix, and the volume. Not in Postgres after the first start | None. A lost file is not replaced | Lets its holder sign Add proposals; clients refuse a device that is not cross-signed. A new key makes clients warn (finding N15) |
| Device signing key (text, P-256) | tinyclient, per device | Inside the engine's snapshot, sealed under a state key kept in the account's keychain item (tinyclient #127; `the_stored_state_is_authenticated_and_bound_to_its_name_and_key`, `the_blob_holds_no_plaintext_key_material`); the server holds only the public key | The OS | Not specified | Revoke the device (`DELETE /v1/e2ee/devices/{id}`); other members see the change |
| Community root key (P-256) | An owner's device | An owner's device; the client does not publish or pin one yet. The server holds the public key and the signed policy | | Only with `replace`, audited and announced | A new root makes clients warn |
| Key packages | tinyclient | Server holds public key packages until claimed | | Up to 50 uploaded; one claimed per Add; a last-resort package is never deleted | An exhausted pool falls back to the last resort package; the device is flagged `low_keys` |
| MLS group secrets (text) | The devices | Device storage, keychain-protected | | Every commit | Lost device cannot read new messages after removal; old ones it already holds stay |
| Attachment key | The sender's client | Inside the MLS message, so only members | | One per attachment | Anyone who had the message can open the blob |
| Session token | tinyserver | Hash in `sessions`; raw token in the client's keychain and in server memory for a live socket | The OS keychain on the client | Per sign-in | Revoke; 30 day expiry |
| Postgres, upload volume | Not encrypted by this stack | n/a | Host disk encryption, if any | n/a | n/a |
| Operator's backup recipient (age) | The operator, outside this repository | Wherever the operator keeps the identity | The operator | Not handled by the tooling | Its holder reads every backup encrypted to it, which is what makes a backup restorable after the host is lost |
| Tenant backup key (age) | `operator.sh keygen` | `tenants/<name>/backup.key`, mode 0600, **on the same host as the tenant's data**; `backup.recipient` beside it | File permissions; the operator is told to keep an escrow copy, encrypted to a recovery key, off the host | None; `keygen` refuses if a key exists | `operator.sh delete` shreds the host copy (`shred -u` where available; on a journaling or copy-on-write filesystem that is not a guarantee). After that, a backup encrypted to this key alone cannot be opened, unless an escrow copy survives (`deploy/tests/hooks.sh`). While the key is on the host, host root can open those backups. Finding S11 |
| Owner's export recipients (age) | The owner | The owner | The owner | n/a | The operator's key cannot open an export (`deploy/tests/hooks.sh`) |

## 6. What the server keeps deciding

E2EE removes the server's ability to read, not its ability to decide. It still: authorizes who may post and who is in a conversation's desired member set; orders commits; signs Add and Remove proposals; delivers or withholds ciphertext; reports the roster in calls; and can drop or delay anything. The defences against a hostile server are in the clients: they check cross-signatures, pin the external sender key, warn on changed keys, refuse unlisted members, and (calls) show the call code. All of those are client behaviour that a client bug disables. They need independent review ([`remaining-risks.md`](remaining-risks.md)).

## 7. What E2EE does not cover (summary)

[`metadata.md`](metadata.md) has the full list. In short: membership and who talks to whom; the minute a ciphertext was stored, sizes and counts; presence; that a reaction ciphertext was posted and by which device (not the emoji or the message); room, channel and server names, topics and avatars; mentions and search (client only); push content (none is sent); IP addresses; bots (they are refused on message routes and cannot be in an encrypted conversation); moderator deletion in encrypted conversations (none); server-side scanning of sealed files (none); key backup (a non-goal of v1); history for new devices (none); a compromised endpoint.

## 8. Status of each property

| Property | Status | Evidence |
|---|---|---|
| Server cannot decode call audio | Implemented | Section 2 tests; downgrade possible and shown |
| Server cannot decode call video | Implemented in the client; server does not read NAL headers | Client code at `26916e9`; `SECURITY.md` disagrees; not verified by a call |
| Server cannot read text or attachments of an encrypted conversation | Implemented, tested (server here; client in tinyclient) | `e2ee_text.rs` `a_canary_said_only_through_encrypted_paths_is_nowhere_on_the_server`, `there_is_no_downgrade_in_either_direction`; tinyclient `an_encrypted_conversation_is_labelled_its_rows_never_read_the_servers_body_and_nothing_goes_plain` |
| Existing conversations are protected | **Not done**, by design | `e2ee-text.md` section 9 |
| New devices need cross-signing | Implemented, tested (server here; client in tinyclient). New person: not done (G3, G4) | `a_later_device_needs_a_cross_signature_from_an_active_one`; tinyclient `a_device_the_server_invented_is_rejected`, `an_add_of_a_device_that_is_not_cross_signed_is_rejected` |
| Backups are encrypted at rest | Implemented, tested (shell check, not in CI) | `operator.sh backup`; `deploy/tests/hooks.sh`. Limits in section 5 |
| Backups contain only ciphertext for encrypted conversations | Implemented for message and attachment content (they are stored only as ciphertext); the bundle also holds the external sender private key and all metadata | Follows from the canary test over every table and upload file; no backup was opened to check |
| Independent review of any of the above | Not done | [`remaining-risks.md`](remaining-risks.md) |
