# Server management

Roles with permissions, an owner flag above them, per-room overrides, server settings, categories, bans, timeouts, multi-use invites, and an audit log with names. The wire contract tinyclient builds against. Calls and the live socket are in [`calls.md`](calls.md). Text channels, direct messages, attachments, avatars, and bots are in this file. Voice rooms are not text channels.

Everything here is additive: older clients keep working, and `GET /v1/capabilities` answers 404 on servers from before it.

## Permissions

A permission is one bit, `1 << n`. Permissions are JSON numbers; every bit is below 2^53. Unknown bits in a request are dropped.

| n | Name | In a room |
| --- | --- | --- |
| 0 | view_channel | yes |
| 1 | connect | yes |
| 2 | speak | yes |
| 3 | video | yes |
| 4 | share_screen | yes |
| 5 | voice_activity (else push-to-talk only) | yes |
| 6 | priority_speaker | yes |
| 7 | create_invites | |
| 8 | manage_invites | |
| 9 | manage_channels | yes |
| 10 | manage_roles | |
| 11 | kick_members | |
| 12 | ban_members | |
| 13 | timeout_members | |
| 14 | mute_members | yes |
| 15 | deafen_members | yes |
| 16 | move_members | yes |
| 17 | disconnect_members | yes |
| 18 | view_audit_log | |
| 19 | manage_server | |
| 20 | manage_reports (list, read, triage, annotate abuse reports; not in a room override, not in @everyone) | |

All bits: `2097151`. Bits a room override may hold: `246399`. @everyone on a new server: view_channel, connect, speak, video, share_screen, voice_activity, `63`. Before [`0015_abuse_reports.sql`](../crates/db/migrations/0015_abuse_reports.sql) all bits was `1048575`. That migration adds bit 20 and handles roles that already exist: every owner has it through the owner flag, every role other than @everyone that holds manage_server gets it (including "Admin"), and no other role does. @everyone does not get it even if someone gave @everyone manage_server. A client that sends `1048575` or any older value gets exactly what it got before.

| Rule | |
| --- | --- |
| Owner | A flag on the membership, above every role. Owners have every bit everywhere. One or more owners; the last one cannot be demoted, kicked, or banned (`409` `last_owner`). Only owners grant or revoke owner. |
| Base | @everyone OR every role the member has. Server-wide checks use the base. `manage_server` implies nothing else. |
| In a room | The base, then @everyone's override for the room (deny, then allow), then the OR of the member's other roles' overrides (deny, then allow). An allow beats a deny among the member's roles. |
| Rank | A role's `position`: higher is more senior, @everyone is 0. A member's rank is the highest position among their roles, 0 with none; an owner's is `2147483647`. |
| Hierarchy | Kick, ban, timeout, roles, server mute and deafen, move, and disconnect need the person's rank below the caller's (`hierarchy`). A role may be created, edited, given, taken, ordered, or overridden only below the caller's rank. Owners may act on anyone, other owners included, under the last-owner rule. |
| Granting | Someone who is not an owner cannot set a permission bit on a role that they do not have themselves (`forbidden`). |
| Legacy role | Responses keep `role`: `owner` for an owner, `admin` when any of their permissions is manage_server or manage_roles, else `member`. |

Postgres enforces all of it. The API connects as `app_runtime` and sets `app.user_id` per request; row level security reads permissions for that id (`app_has`, `app_room_has`). Roles, member roles, the owner flag, bans, timeouts, and overrides change only through `SECURITY DEFINER` functions in [`0005_server.sql`](../crates/db/migrations/0005_server.sql), which check the permission and the hierarchy themselves and write the audit row.

Upgrading from the three fixed roles: `owner` became the owner flag, `admin` the role "Admin" (position 1, every bit, colour `#3B82F6`, shown separately), `member` just @everyone.

## Errors

`{"error": "<code>"}`, as before, with these added:

| Code | Status | |
| --- | --- | --- |
| `hierarchy` | 403 | The person or role is at or above the caller |
| `default_role` | 400 | @everyone cannot be deleted, renamed, or ordered |
| `banned` | 403 | A banned person on a route that checks membership. `/v1/auth/callback` does not return this JSON. It redirects to the client's loopback with query `error=banned`. |
| `too_large` | 413 | An icon over 256 KiB, or an upload over the server's cap |
| `unsupported_media` | 415 | An icon that is not PNG, JPEG, or WebP; a refused attachment type; a liar file whose extension, MIME, and sniff disagree; PE (MZ) or ELF regardless of name |
| `scanning` | 423 | `GET /v1/media/{id}` while the file is not yet clean |
| `blocked` | 403 | The scanner blocked the file on upload or download |
| `unavailable` | 503 | The scanner is down, timed out, or otherwise could not finish; upload gets no 201 |
| `unauthorized` | 401 | No `Bearer` session, or the token is unknown or expired |
| `forbidden` | 403 | Missing the permission bit |
| `not_found` | 404 | No such role, room, member, ban, category, or icon |
| `invalid` | 400 | A bad name, time, colour, limit, or id |
| `last_owner` | 409 | Demoting, kicking, or banning the last owner |
| `idempotency_conflict` | 409 | `Idempotency-Key` reused with a different body |
| `slow_down` | 429 | Filing a report past 10 in an hour or 50 in a day |
| `read_only` | 503 | The operator suspended the community read-only, and this route writes. The body has `mode` and `notice`. |
| `suspended` | 503 | The operator took the community offline. Every route but `/health` and `/v1/status` answers this, with `mode` and `notice`. |

Community routes return `500` `unavailable` when the database call fails. That is separate from the scanner's `503` `unavailable`.

## Sign-in

tinyserver is an OpenID Connect relying party. It is not an authorization server. A person is `(issuer, subject)` in `user_identities`. Email is stored when the ID token has one that looks like an address, and it never finds an account. The same person at two issuers is two accounts. `0004_oidc.sql` drops `password_hash`. There is no password sign-in and no refresh token.

Compose runs Pocket ID. The issuer is `AUTH_PUBLIC_URL`. `TINYAUTH_PUBLIC_URL` is only the fallback for `AUTH_PUBLIC_URL` when that variable is unset (`TINYSERVER_OIDC_ISSUER` and Pocket ID `APP_URL`). Discovery, the key set, the code exchange, and the sign-up API use `TINYSERVER_OIDC_INTERNAL_URL` when it is set (`http://pocket-id:1411` in compose). The issuer in that discovery document must still be the public issuer. The browser uses the public auth hostname.

`TINYSERVER_OIDC_SCOPES` defaults to `openid profile email`. `openid` is always sent. The client is confidential: a client secret (`client_secret_basic` or `client_secret_post`, whichever discovery offers) or a private-key JWT. Several providers: `TINYSERVER_OIDC_PROVIDERS=pocket-id,google` reads `TINYSERVER_OIDC_POCKET_ID_*` and `TINYSERVER_OIDC_GOOGLE_*`. Without that variable there is one provider, id `default`.

### Routes

No session.

| Route | |
| --- | --- |
| `GET /v1/auth/config` | `{methods: ["oidc"], provider_name, providers: [{id, name}]}` |
| `POST /v1/auth/start` | `{redirect_uri, code_challenge, code_challenge_method, state, invite?, provider?}`. `code_challenge_method` must be `S256`. `redirect_uri` must be `http://127.0.0.1:<port>/callback` or `http://[::1]:<port>/callback`. The client's `state` is 16 to 128 unreserved characters. `invite` is the token from `POST /v1/invites`. → `{authorize_url}` |
| `GET /v1/auth/callback` | The provider's redirect. On success, `302` to the loopback redirect with `code` and the client's `state`. On failure, the same redirect with `error` of `not_member`, `banned`, `denied`, or `failed`. |
| `POST /v1/auth/token` | `{code, code_verifier}` → `{token, user_id, email, display_name, role}`. This object does not include `owner`, `roles`, `permissions`, or `rank`; `GET /v1/me` does. |
| `POST /v1/auth/backchannel-logout` | Form field `logout_token`. `200` with no body. A bad token is `400` `invalid_request`. Sessions for that provider `sid` or subject end. |

`start` keeps the pending sign-in for 10 minutes. The one-time code lives 60 seconds and is spent on the first `token` try, right or wrong. Both are stored as the SHA-256 of the secret. JSON errors on these routes: `bad_request`, `invalid_grant`, and `invalid_request` are `400`; a database failure is `500` `unavailable`.

### New accounts

Account creation at the provider exists only when that provider's `SIGNUP` is `pocket-id` or `pocketid`. Unset, `none`, and `off` leave sign-up off: an invite then works only for someone who already has an account at the provider. Compose defaults `TINYSERVER_OIDC_SIGNUP` to `pocket-id`.

When sign-up is on and `start` carries an invite, `authorize_url` is this server's `/v1/auth/join` page: "I'm new here" or "I already have an account". "I'm new here" asks Pocket ID for one sign-up token, `POST /api/signup-tokens` with `{"ttl":"15m","usageLimit":1}` and `X-API-Key`, and only while `app_invite_usable` is still true. One link per pending sign-in. The page says the link works once, for 15 minutes. A second click does not mint another. An unusable invite ends the sign-in with `error=not_member`.

### Who may come in

A known `(issuer, subject)` who is a member and not banned gets a session. The invite is not consumed. Anyone else needs a usable invite, or a joining group. A ban wins over both. Nothing is written for someone turned away.

Groups default to invite-only. `TINYSERVER_OIDC_MEMBER_GROUPS` and `TINYSERVER_OIDC_ADMIN_GROUPS` are comma lists. The claim name defaults to `groups` (`TINYSERVER_OIDC_GROUPS_CLAIM`). Joining without an invite happens only when member groups are configured. A person in an admin group then joins as admin; otherwise a member group joins as member. The owner role never comes from a claim. `joined_via` is `groups`. An existing member in an admin group is promoted to admin on sign-in. Audited `member.join` or `member.role`.

### Sessions

The session token is 32 random bytes, URL-safe base64 without padding. Postgres stores SHA-256 of that string. It lasts `TINYSERVER_SESSION_MAX_DAYS` (default 30, range 1 to 365) and is not extended by use. `serve` refuses to start when that variable is set outside the range.

`tinyserver identities` lists user id, display name, issuer, and subject. `tinyserver relink-identity --user-id --subject [--issuer]` points that account's row for the issuer at a new subject. The issuer defaults to `TINYSERVER_OIDC_ISSUER`. This is the path when a provider's subjects change and the issuer stays the same, including a move from Tinyauth to Pocket ID at the same address. Audited `identity.relink` with a null actor. It does not merge two accounts.

## REST

The routes in this section need a person's session: `Authorization: Bearer <token>`, with that prefix exact and a non-empty token. "Any member" means any signed-in member. Sign-in routes do not use a session. A `Bot` token is a different prefix; what it may call is under [Bots](#bots).

### Capabilities and me

`GET /v1/capabilities` (any member) → `{"version": "…", "features": ["server", "roles", "categories", "bans", "timeouts", "invite_options", "audit_query", "voice_moderation", "e2ee_calls", "upload_limits", "file_scan", "abuse_reports"]}`. `abuse_reports` means [abuse reports](#abuse-reports) exist. `e2ee_calls` means calls can be end-to-end encrypted ([`calls.md`](calls.md#end-to-end-encryption)): `call.join` takes `e2ee`, the live socket carries `call.e2ee`, and rooms have `e2ee_required`. `file_scan` means a chat upload is scanned before `POST /v1/media` returns `201`, and `GET /v1/media/{id}` stays closed until the row is `clean`. This server always lists `file_scan`. There is no upload path that skips the scan.

`GET /v1/me` and `PATCH /v1/me` add `owner`, `roles [id]` (most senior first), `permissions` (base), and `rank`.

`PATCH /v1/me` takes `{display_name}`. The name is trimmed and must be 1 to 80 characters. The response is the same object as `GET /v1/me`. Audited `account.rename`.

`DELETE /v1/me` takes `{"confirm": "delete my account"}` and deletes the caller's account: `204`. Any other phrase is `400`. A bot is `403`. The only owner gets `409 last_owner` and must make someone else owner first. The `users` row stays as a tombstone named `Deleted user`, with no email and no picture, because messages and audit rows point at it. Their identities, sessions, unredeemed sign-in codes, membership, reactions, read marks, bots, unused invites and idempotency keys are deleted. Every message they wrote is emptied as a message delete empties it, and its attachments and files go. `display_name`, `name` and `email` are taken out of audit rows about them, and their `member.*` outbox rows are deleted. A ban and its `ban_identities` stay, so deleting an account does not undo a ban. Live `member.removed` closes their sockets. Audited `account.delete`. Not reached: the provider account (Pocket ID), `directs` rows, free-text `audit_log.reason`, Postgres WAL and dead rows, backups, and anything a client already stored. See `0014_account_deletion.sql`.

`avatar` is not on `GET /v1/me`. The hash is on `GET /v1/members` and on `member.avatar`. Picture routes are under [Avatars](#avatars). `Authorization: Bot <token>` returns `role` `bot`, `email` `null`, `owner` false, `roles` `[]`, `permissions` `0`, `rank` `-1`, `display_name` the bot name, `user_id` the bot id, and `scopes`. A member session omits `scopes`.

`DELETE /v1/session` ends the presented session, 204. `DELETE /v1/sessions` ends every session for that person, including this one, 204. Audited `session.close_all`.

### Server

| Route | Who | |
| --- | --- | --- |
| `GET /v1/server` | any member | `{name, description, welcome, icon, default_room_id, afk_room_id, afk_timeout_secs, image_max_bytes, file_max_bytes, allow_archives, created_at}`. `icon` is the SHA-256 of the icon in hex, or `null`. A new server is "Tiny server". `image_max_bytes` defaults to 8 MiB (images and GIFs); `file_max_bytes` defaults to 25 MiB (video and every other kind); each may be set up to 100 MiB. `allow_archives` defaults to false. |
| `PATCH /v1/server` | manage_server | Any of the writable fields; the room ids take `null`. Name 1 to 80 characters, description up to 500, welcome up to 2000, `afk_timeout_secs` 0 (off) to 86400, `image_max_bytes` and `file_max_bytes` each from 1 byte through 104857600 (100 MiB), `allow_archives` boolean. Returns the whole object. Audited `server.update`. |
| `GET /v1/server/icon` | any member | The image, its `Content-Type`, and `ETag: "<sha>"`; `If-None-Match` gets 304. 404 without one. |
| `PUT /v1/server/icon` | manage_server | The body is the image: PNG, JPEG, or WebP, sniffed from its first bytes, then re-encoded. The 256 KiB cap applies to the rewritten bytes; a rewrite that grows past that is `413` `too_large`. GIF is not an icon. `icon` in JSON is the SHA-256 hex of the stored rewrite. `PUT /v1/me/avatar` uses this same cap. JSON routes keep the 8 KiB body cap. `POST /v1/media` accepts up to the 100 MiB ceiling plus 1 MiB of multipart overhead. `{icon}`. Audited `server.icon`. |
| `DELETE /v1/server/icon` | manage_server | 204 |

### Roles

| Route | Who | |
| --- | --- | --- |
| `GET /v1/roles` | any member | `[{id, name, color, position, permissions, hoist, default, member_count}]`, most senior first. `color` is `#RRGGBB` or `null`; `default` marks @everyone. |
| `POST /v1/roles` | manage_roles | `{name, color?, permissions?, hoist?}` → 201 role, placed just below the caller's rank (at least 1), or at the top for an owner |
| `PATCH /v1/roles/{id}` | manage_roles | Any of `name`, `color` (`null` clears), `permissions`, `hoist` |
| `DELETE /v1/roles/{id}` | manage_roles | 204. Members lose it; invites stop giving it. |
| `PUT /v1/roles/order` | manage_roles | `{ids}`: every role but @everyone, most senior first → the roles. Positions move between roles; a non-owner cannot move one at or above their rank. |

### Members

| Route | Who | |
| --- | --- | --- |
| `GET /v1/members` | any member | Rows add `owner`, `roles`, `last_seen_at`, `timeout_until` (while one runs), `joined_via` (`invite`, `groups`, or `null` for members from before it was kept), and `avatar` (SHA-256 hex of their picture, or `null`). `role` stays. `email` is the member's own on their row, and on every row for a caller with manage_server; on other rows it is `null`. |
| `PATCH /v1/members/{id}` | legacy | `{role}`: `owner` sets the owner flag (owners only), `admin` adds the most senior role with manage_server or manage_roles, `member` takes those away and the owner flag. → `{role}`. |
| `PUT /v1/members/{id}/roles` | manage_roles | `{role_ids}` replaces their roles → member row |
| `PUT /v1/members/{id}/owner` | owners | `{owner}` → member row |
| `PUT /v1/members/{id}/timeout` | timeout_members | `{until, reason?}`: an RFC 3339 time in the future and at most 28 days and 1 minute ahead, or `null` to end it. A time outside that is `400` `invalid`. → member row. A timeout ends their call and refuses `call.join` with `timed_out`. |
| `DELETE /v1/members/{id}?reason=` | kick_members | Kick: the membership and every session go. The reason goes to the audit row. |

`last_seen_at` is not written on the socket event itself. A person's live socket is queued on open, on close, and on each credential recheck (default 60 seconds). Those ids are written in one update every 30 seconds, and once more when the process is closing. Bots are not queued.

### Bans

| Route | Who | |
| --- | --- | --- |
| `GET /v1/bans` | ban_members | `[{user_id, display_name, email, reason, banned_by, banned_by_name, created_at, expires_at}]`, bans in force |
| `POST /v1/bans` | ban_members | `{user_id, reason?, expires_at?}` → 201 ban. The membership and every session go, sockets close with `4003` and reason `removed` (a kick uses that same frame), and their call ends with `banned`. The ban holds every (issuer, subject) the person signed in with, so an invite, a joining group, and a fresh sign-in are refused. A person who is no longer a member can be banned too. |
| `DELETE /v1/bans/{user_id}` | ban_members | 204. They may come back with a new invite. |

### Categories and layout

| Route | Who | |
| --- | --- | --- |
| `GET /v1/categories` | any member | `[{id, name, position}]`, top first |
| `POST /v1/categories` | manage_channels | `{name}` → 201, placed last |
| `PATCH /v1/categories/{id}` | manage_channels | `{name}` |
| `DELETE /v1/categories/{id}` | manage_channels | 204. Its rooms become uncategorized. |
| `PUT /v1/layout` | manage_channels | `{categories: [{id, room_ids}]}`: the categories in order, `id: null` for the uncategorized rooms, which always come first, and each bucket's rooms in order. Rooms and categories left out keep their place. → `{categories, rooms}` |

### Rooms

`GET /v1/rooms` rows add `category_id`, `position`, `topic`, `user_limit` (0 to 99; 0 means the server cap, `TINYSERVER_CALL_ROOM_MAX`, default 12), `bitrate_kbps` (16 to 128, default 64), `ptt_only`, `video_enabled`, `e2ee_required` (default false), `overrides [{role_id, allow, deny}]`, and `my_permissions`. A positive `user_limit` is also clamped to that cap. A move uses the server cap for 30 seconds even when the room limit is lower. Rooms the caller cannot view are left out; owners see all. Rooms come uncategorized first, then by category, each by `position`.

`POST /v1/rooms` takes `{name, category_id?, topic?, user_limit?, bitrate_kbps?, ptt_only?, video_enabled?, e2ee_required?}` (manage_channels); `PATCH /v1/rooms/{id}` any of those and `position` (manage_channels in that room). `DELETE /v1/rooms/{id}` (manage_channels in that room) is 204. Audited `room.delete`.

`POST /v1/rooms` and `POST /v1/invites` take an optional `Idempotency-Key`. The same caller, route, and key with the same body returns the stored 201 again for a day. A different body is `409` `idempotency_conflict`.

`PUT /v1/rooms/{id}/overrides/{role_id}` `{allow, deny}` and `DELETE` set and clear one role's override; they need manage_roles and manage_channels in the room, and the role below the caller. Bits outside the room set are dropped; a bit in both is allowed.

A `PATCH` that changes only the name is audited `room.rename`. Any other `PATCH` is `room.update`. `POST` is `room.create`. Overrides stay `room.override`.

Clients encode at `bitrate_kbps`; `ptt_only` and `voice_activity` are honoured by the client. The SFU is unchanged by them. `e2ee_required` is the server's: while media runs, a `call.join` without `e2ee` to that room gets `e2ee_required` and takes no seat. People already in the call when it is turned on stay; the call is transport only until they leave. It is a promise the server makes, not one the apps can check: see the threat model in [`calls.md`](calls.md#what-it-protects-and-what-it-does-not). Migration [`0007_e2ee.sql`](../crates/db/migrations/0007_e2ee.sql) adds the column and makes `app_call_access` return it; nothing else about end-to-end encryption is stored.

### Invites

| Route | Who | |
| --- | --- | --- |
| `POST /v1/invites` | create_invites | Legacy `{role}` (`member` or `admin`), or `{role_ids?, label?, max_uses?, expires_in_secs?}`. `max_uses` 1 to 1000, `null` for unlimited, 1 when left out. `expires_in_secs` 60 to 2592000, `null` for never (owners and manage_server only), 7 days when left out. Roles need manage_roles and must be below the caller. → 201 `{id, token, role, expires_at, label, max_uses, role_ids}`; the token is shown once. |
| `GET /v1/invites` | create_invites or manage_invites | Invites that still work. Rows add `label`, `max_uses`, `uses`, `role_ids`, and `created_by_name`; `created_by` and `created_by_name` are `null` for the owner invite from `tinyserver bootstrap`, "Server setup" in clients. `expires_at` is `null` for one that never expires. `accepted_at` and `accepted_by` are the last use. |
| `DELETE /v1/invites/{id}` | manage_invites, or create_invites for one's own | 204 |

Accepting an invite makes the membership, gives its roles, counts a use, and records `joined_via: "invite"`; a banned person is refused before any of it.

### Audit

`GET /v1/audit?limit=1..200&before=<id>&actor=<user id>&action=<prefix>` (view_audit_log): newest first. An omitted `limit` is 50. Rows add `actor_name`, `subject_user_id`, `subject_name`, `reason`, and `detail`. For the next page pass the last row's `id` as `before`. Actions for this area also include `room.create`, `room.rename` (name-only change), `room.delete`, `room.update`, `room.override`, `invite.create`, `invite.revoke`, `invite.accept`, `member.join` (a group join), `member.role` (legacy role change, and an admin-group promotion), `member.roles`, `member.owner`, `member.remove`, `member.timeout`, `member.ban`, `member.unban`, `account.rename`, `account.avatar`, `account.delete`, `session.close_all`, `identity.relink`, `bootstrap`, `server.update`, `server.icon`, `role.create`, `role.update`, `role.delete`, `role.order`, `category.create`, `category.update`, `category.delete`, `layout.update`, `channel.create`, `channel.update`, `channel.delete`, `channel.override`, `call.server_mute`, `call.move`, `bot.create`, `bot.revoke`, and the report rows under [Abuse reports](#abuse-reports). A kick's reason is on its `member.remove` row. Bot routes are under [Bots](#bots).

## Abuse reports

A member can report a message, a member or a channel to the people who run this community. This is only the part inside one community server: it is not a way for anyone outside to read conversations. The policy, what a moderator can and cannot see, and what the operator can and cannot do are in [`privacy/abuse-response.md`](privacy/abuse-response.md). Migration [`0015_abuse_reports.sql`](../crates/db/migrations/0015_abuse_reports.sql). Capability: `abuse_reports`. Bots are refused on every route here.

**Evidence is unverified, and the server says so.** A report may carry `evidence`: text the reporter's own client chose to send. For an end-to-end encrypted conversation that is the plaintext the reporter's client chose to disclose, because the server cannot read it. The server has no way to check that it is genuine: it may be edited, invented, or from a conversation that never happened. Every report that carries evidence is stored with `evidence_unverified: true`, and every response that shows evidence says so. Reporting a message stores the message's id, where it was posted and who posted it. It never stores or reads the message's text; a message's text is in a report only if the reporter sent it as `evidence`.

| Route | Who | |
| --- | --- | --- |
| `POST /v1/reports` | any member who is not banned (a timeout does not stop it) | `{kind, target_id, category, note?, evidence?}`. `kind` is `message`, `member` or `channel`; `target_id` is that object's id. `category` is `spam`, `harassment`, `hate`, `violence`, `sexual`, `illegal`, `impersonation` or `other`. `note` is at most 2000 characters, `evidence` at most 32768 bytes of UTF-8; neither may hold control characters other than newline, return and tab. → `201` `{id, kind, category, status, created_at, evidence_unverified, duplicate: false}`. It names nobody. Reporting the same thing again while the first report is `open` or `reviewing` is `200` with the first report and `duplicate: true`, and stores nothing. |
| `GET /v1/reports?status=&kind=&before=&limit=` | manage_reports | Newest first. `status` is `open`, `reviewing`, `actioned` or `dismissed`; `limit` 1 to 200, 50 when left out; `before` is the last row's `id`. Rows: `{id, kind, category, status, preserve, reported, reporter, message_id, channel_id, direct_id, has_evidence, evidence_unverified, linked_audit_ids, created_at, updated_at, resolved_at}`. `reported` and `reporter` are `{user_id, display_name}` or `null`. No note and no evidence. |
| `GET /v1/reports/{id}` | manage_reports | The row above plus `note`, `evidence`, `preserved_by`, `preserved_at` and `notes [{id, author, body, created_at}]`, the moderators' annotations. |
| `PATCH /v1/reports/{id}` | manage_reports (`preserve`: owners only) | Any of `status`, `note`, `link_audit_id`, `preserve`, together or alone, in one transaction. `status` moves between the four values in any direction; `actioned` and `dismissed` set `resolved_at`, any other clears it. `note` adds a moderator annotation of up to 2000 characters. `link_audit_id` is the `id` of a `member.remove`, `member.ban` or `member.timeout` audit row, and for a report about a person it must be an action against that person; linking one twice adds nothing. `preserve` sets or clears the legal hold. → the full report. An empty `{}` is `400`. |

Errors: `400 invalid` for a bad kind, category, id, status, a note or evidence with control characters, a note over its limit, reporting yourself, or a link that is not an enforcement action against the person reported; `413 too_large` for evidence over 32768 bytes, or any body over 80 KiB on this route; `404 not_found` when the target does not exist **or the caller cannot see it** (a private channel, a direct between other people) and for a report that does not exist or that is about the caller; `403 forbidden` without manage_reports, or `preserve` from someone who is not an owner; `429 slow_down` past 10 new reports an hour or 50 a day for one reporter. The limit is counted in the database per reporter, not per address.

Who sees what. Only holders of manage_reports see reports, and never one about themselves: for a moderator who is the subject of a report, the list leaves it out, `GET` and `PATCH` answer `404` exactly as for an id nobody has, and its audit rows are hidden (`audit_select` shuts out rows whose subject is the caller). The reported member never learns who reported, because they cannot read the report. Moderators do see the reporter, so they can deal with a reporter who misuses the button. The reporter cannot read their own report back: `GET` is `403` for them. There is no live event for reports, so nothing about one is pushed to any socket.

The audit log gets a row for every change, and never any report text. `report.create` (no actor: the audit log does not say who reported; the subject is the person reported), `report.triage` (`from`, `to`), `report.annotate` (the note's id), `report.link` (the audit id and its action), `report.preserve`, `report.unpreserve`, and `report.expire` (a count, written by the retention sweep). Rows whose action starts with `report.` are visible only to holders of manage_reports other than the subject, whatever else they can see in the audit log.

Retention. `actioned` and `dismissed` reports, with their moderator notes, are deleted `TINYSERVER_REPORT_RETENTION_DAYS` days (7 to 3650, default 90, anything else stops `serve` from starting) after they were resolved, by the same sweep that runs at start and every 10 minutes. A report that is `open` or `reviewing` is never aged out. A report with `preserve` is never deleted by the sweep. `preserve` is the legal hold: only an owner can set or clear it, it is audited, it shows in the list, and it is the only thing that stops deletion.

Account deletion (`DELETE /v1/me`). A person who deletes their account loses their link on every report they made (`reporter` becomes `null`), held or not. On reports that are not held, the note and the evidence they wrote are deleted too, and the report stays with its kind, target, category and status. A person who is the subject of reports loses, from every report about them that is not held, the evidence, the reporter's note and the moderators' notes; the report row stays. A held report is never otherwise touched.

## Messages and attachments

Text channels and direct messages are built. They are not voice rooms and they are not a later milestone. Bots are refused on every route in this section with `403 forbidden` and are not members. `POST /v1/media` returns `201` only after a clean scan and a commit. Migrations: [`0008_messages.sql`](../crates/db/migrations/0008_messages.sql), upload caps in [`0009_upload_limits.sql`](../crates/db/migrations/0009_upload_limits.sql), and the scan gate in [`0011_attachment_gate.sql`](../crates/db/migrations/0011_attachment_gate.sql).

A text channel uses the same permission bits as a room, including the room override mask `246399`, in the same order: owner, base, @everyone override, then the member's other roles. `view_channel` (`1`) sees it. `speak` (`4`) posts, reacts, and types. `manage_channels` (`512`) edits and deletes it. Creating one needs `manage_channels` server-wide. A channel the caller cannot view is `404 not_found`.

A direct is one pair of members, stored with the lower user id first. One pair is one conversation. The caller cannot open one with themselves. The other person must be a member and not banned.

Live frames for these objects are in [`calls.md`](calls.md#messages): `channel.created`, `channel.updated`, `channel.deleted`, `direct.created`, `message.created`, `message.edited`, `message.deleted`, `reaction.updated`, and `read.updated`. Channel events go to every member socket when every member can view the channel. When the channel can be restricted (the @everyone role lacks view_channel, or an override on the channel touches it), `0013_private_channel_events.sql` narrows the event to the members who can view it when it is emitted; `channel.deleted` still goes to every member. Direct events, typing, and direct read cursors go only to the two people. An edit or delete rewrites the earlier `message.created` and `message.edited` rows in the outbox, so the 24 hour replay does not hand back text the author took back. A channel read is stored and is not broadcast. Typing is not stored. File bytes never ride on the socket. The open-questions row in `calls.md` that still calls text a later milestone is stale.

| Route | Who | |
| --- | --- | --- |
| `GET /v1/channels` | view_channel on each | Channels the caller can view, ordered by `position`, `name`, `id`. There is no `my_permissions` field. `PUT /v1/layout` does not move these. |
| `POST /v1/channels` | manage_channels | `{name, category_id?, topic?, position?}` → `201` channel. Name 1 to 80 characters. Topic up to 1024, empty when left out. Position defaults to 0. Audited `channel.create`. |
| `PATCH /v1/channels/{id}` | manage_channels in that channel | Any of `name`, `topic` (`null` clears to empty), `position`, `category_id` (`null` uncategorized). Audited `channel.update`. |
| `DELETE /v1/channels/{id}` | manage_channels in that channel | `204`. Messages go with the channel. Attachment files are deleted. Audited `channel.delete`. |
| `PUT /v1/channels/{id}/overrides/{role_id}` | manage_roles, and manage_channels in the channel, role below the caller | `{allow, deny}`. Bits outside `246399` are dropped. A bit in both is allowed. Returns the channel. Audited `channel.override`. |
| `DELETE /v1/channels/{id}/overrides/{role_id}` | same | Clears that role's override and returns the channel. |
| `GET /v1/directs` | the two members | The caller's conversations. |
| `POST /v1/directs` | a member | `{user_id}` → `201` when created, `200` when that pair already has one. |
| `GET /v1/conversations/{id}/messages?before=&limit=` | view_channel, or either person in the direct | `limit` defaults to 50 and must be 1 to 100. `before` is exclusive. The page is oldest-first inside that window. Deleted messages stay, with an empty body and no attachments or reactions. |
| `POST /v1/conversations/{id}/messages` | speak in the channel, or either member of the direct, and not timed out | `{body?, reply_to?, client_id?, attachment_ids?}`. Body is trimmed, at most 4000 characters. Empty body needs at least one attachment. `reply_to` must be a message in that conversation. `client_id` is 1 to 64 characters with no ASCII controls; a retry returns the same message and the status is still `201`. → `201` message. |
| `PATCH /v1/messages/{id}` | the author, with speak, not timed out | `{body}`. A deleted message is `400 invalid`. Empty body is allowed when attachments remain. |
| `DELETE /v1/messages/{id}` | the author, with speak | `204`. Soft delete: body cleared, reactions and attachment rows removed, files deleted, `deleted_at` set. A second delete is `204`. |
| `PUT /v1/messages/{id}/reactions` | speak, not timed out | `{emoji}` toggles. One grapheme, 1 to 16 scalars, no ASCII control. → `{emoji, count, me}`. |
| `DELETE /v1/messages/{id}/reactions` | the member who reacted | `{emoji}` → `204`. Missing reaction is `404`. |
| `POST /v1/conversations/{id}/read` | someone who can see it | `{message_id}` → `204`. The cursor only moves forward. |
| `POST /v1/media` | speak server-wide, or speak in at least one text channel; not timed out | Multipart form, one `file` plus optional `width`, `height`, `duration`. At most 8 parts. → `201` only after a clean scan. |
| `GET /v1/media/{id}` | someone who can see the message, or the uploader while the file is still unlinked and under an hour old | The bytes, after the gate below. |

A timeout may still read. Posting, reacting, uploading, and typing while timed out are `403 forbidden`, not the call socket's `timed_out`. A banned person is `403 banned`.

Channel JSON: `id`, `category_id`, `name`, `topic`, `position`, `created_by`, `created_at`, `overrides [{role_id, allow, deny}]`, `unread`, `last_message`. Direct JSON: `id`, `created_at`, `peer {user_id, display_name}`, `unread`, `last_read`, `peer_read`, `last_message`. `last_message` is `{id, author_id, body, created_at}` with `body` cut at 200 characters, or `null`. `unread` skips the caller's own messages and deleted ones. Peer pictures are not on the direct object; use the member list.

Message JSON: `id`, `author_id`, `body`, `reply_to`, `client_id`, `created_at`, `edited_at`, `deleted_at`, `attachments`, `reactions [{emoji, count, me}]`. An attachment on a message is `{id, name, mime, kind, bytes, width, height, duration}`. `kind` is `image`, `gif`, `video`, or `file`. `scan_status` is on the upload response, not on a message's attachments.

### Type policy

These extensions are always refused, case-insensitive: `lnk`, `iso`, `img`, `vhd`, `vhdx`, `html`, `htm`, `hta`, `svg`, `js`, `vbs`, `cmd`, `bat`, `ps1`, `msi`, `scr`, `jar`, `exe`, `dll`, `com`, `pif`, `wsf`, `one`, `docm`, `xlsm`, `pptm`, `dotm`, `xltm`, `ppsm`. So are `image/svg+xml` and `text/html`, PE (`MZ`) and ELF magic regardless of name, and any upload whose extension, declared MIME, and sniffed type disagree (`415 unsupported_media`). `image/jpg` is stored as `image/jpeg`.

Raster uploads (`image/png`, `image/jpeg`, `image/webp`, `image/gif`) are re-encoded before they are written, so a trailer after the image is not what hits disk. The rewrite fails with `415` when an edge exceeds 16384, the pixel count exceeds 40 million, a GIF has more than 500 frames, the decoded buffer would exceed 256 MiB, or the long edge is more than 50 times the short one. Dimensions on a raster come from the rewrite. Other kinds keep the client's `width`, `height`, and `duration` after a non-negative check. A rewritten image over `image_max_bytes` is `413 too_large`.

`docx`, `xlsx`, and `pptx` are office packages, not the archive opt-in. A package whose central directory names `vbaProject.bin` is refused. Macro extensions in the list above are refused by name.

Archives (`zip`, `7z`, `rar`, `tar`, `gz`, `tgz`, `bz2`) are refused unless `allow_archives` is true (default false; `manage_server` on `PATCH /v1/server`). When archives are allowed, `zip` is still capped from the central directory only: at most 1024 entries, each entry's uncompressed size at most four times its compressed size, total uncompressed at most 200 MiB, no nested open (an entry named as another archive is not opened), no `..`, no absolute or drive-letter name, no symlink, no encrypted entry, no duplicate central-directory name, and no zero compressed size with a non-zero uncompressed size. A zip that does not parse is refused. Other archive kinds are accepted only when the extension and the MIME name the same kind.

### Scanning

`serve` refuses to start unless `TINYSERVER_CLAMD_SOCKET` is set, except when that variable is unset and `TINYSERVER_ALLOW_FAKE_SCAN=1`. If the socket is set, the fake scanner is not used. The socket is `host:port`. A filesystem path works on Unix only. On Windows a path is a startup error. Compose sets `TINYSERVER_CLAMD_SOCKET=clamd:3310` and `TINYSERVER_UPLOAD_DIR=/data/uploads` and does not publish port 3310.

`TINYSERVER_SCAN_ENGINE` is `clamd`, the default and all of the above, or `none`. `none` turns server-side scanning off for a community whose files are sealed on the sending device, where the server could only scan ciphertext: every upload is marked `clean` without being scanned, and `serve` logs a warning when it starts. `none` with `TINYSERVER_CLAMD_SOCKET` also set is a startup error, so a half-changed setting does not run. `deploy/scan-off.yml` is the compose file for it; it also stops clamd running. On a community whose files are not sealed it lets any file through.

The scanner is clamd plus three yara-x rules compiled into the process (`lnk_header`, `html_prefix`, `vba_stream`). There is no rules file and no separate content router. A yara hit is `blocked` before clamd is asked. clamd down, a socket timeout, or any IO error is unavailable even when yara is clean. The fake scanner blocks the EICAR test string and calls everything else clean.

Each scan may run up to `TINYSERVER_SCAN_TIMEOUT_MS` (unset, `0`, or unparseable means 8000; the hard cap is 15000). Three scans run at once. Waiting for a free slot uses the same deadline. Past it, the upload is `503 unavailable` and nothing is committed.

`POST /v1/media` writes the file, marks the row `scanning`, and commits only after the verdict is `clean`, with `scan_status` `clean` on the `201` body. A blocked file is `403 blocked`, the transaction rolls back, and the file is removed. Scanner down or timed out is `503 unavailable`, same rollback, and no `201`. A store or database failure on this route is `500` with `{"error":"unavailable"}`, which is a different status from the scanner's `503`.

`POST /v1/conversations/{id}/messages` accepts an attachment id only when that row is `clean`, owned by the caller, not yet linked, and younger than one hour. Scanning, blocked, error, or a missing id is `400 invalid`. A message cannot point at a file that has not passed.

On `GET /v1/media/{id}`, `uploaded` or `scanning` is `423 scanning`, `blocked` is `403 blocked`, and `error` is `503 unavailable`. Missing id, no access, or bytes missing on disk is `404`. The upload path does not commit `scanning`, `blocked`, or `error`. The download statuses are what a row in that state returns. `0011` marks attachments that were already linked when the gate was added as `clean`, so those stay downloadable.

Unlinked rows older than one hour are deleted by the sweep, which runs at start and every 10 minutes, and their files go with them.

Files are `{TINYSERVER_UPLOAD_DIR}/{attachment uuid}`. Unset, the directory is `uploads`. The database stores metadata, not the bytes.

### Media URLs and download

When `TINYSERVER_MEDIA_HMAC_SECRET` is 64 hex characters (32 bytes), attachment objects gain `url`: `/v1/media/{id}?ex=…&is=…&hm=…`. `ex` is expiry, `is` is issued time, `hm` is HMAC-SHA256 over `v1`, those times, and the path. The minted life is 86400 seconds. Compose refuses to start until the secret is set. If it is unset, the JSON has no `url`.

Clients send the session and, when they use the signed URL, all three query parameters. No query parameters: the session is enough. Any of the three present: all three must be valid for that id and the current time, or `401 unauthorized`.

`Content-Disposition` is `inline` for PNG, JPEG, WebP, and GIF, and `attachment` for everything else, with `filename` and `filename*`.

## Avatars

A member's picture is [`0010_user_avatars.sql`](../crates/db/migrations/0010_user_avatars.sql). It is PNG, JPEG, or WebP, re-encoded the same way as the server icon, at most 256 KiB after the rewrite. GIF is refused. The bytes live on `users`, not in the upload directory, and they are not sent through clamd. This is not the chat-upload `201`.

| Route | Who | |
| --- | --- | --- |
| `PUT /v1/me/avatar` | the member | The body is the image. → `{avatar}` the SHA-256 hex. Audited `account.avatar`. Live `member.avatar` carries `app_member_json`, including `avatar`. |
| `DELETE /v1/me/avatar` | the member | `204`, including when they had none. Same audit and live topic, with `avatar` `null`. |
| `GET /v1/users/{user_id}/avatar` | a member, or a bot with `members.read` | The image, `Content-Type`, `ETag: "<sha>"`, `Cache-Control: private, max-age=3600`. `If-None-Match` gets `304`. `404` when that member has no picture. A bot without `members.read` does not see membership rows, so this is `404` for them too. |

`GET /v1/members` adds `avatar` (the hash, or `null`). `GET /v1/me` does not.

## Bots

Bots are [`0012_bots.sql`](../crates/db/migrations/0012_bots.sql). A bot is an application principal, not a member, and it has no membership row. It does not appear in `GET /v1/members` or in presence. The token is 32 random bytes, URL-safe base64 without padding, shown once. Postgres stores SHA-256 of that string.

Someone with `manage_server` creates and revokes bots. A bot cannot.

| Route | Who | |
| --- | --- | --- |
| `POST /v1/bots` | manage_server | `{name, scopes}` or `{name, permissions}`. Name 1 to 80. → `201` `{id, name, scopes, permissions, token, created_at}`. Audited `bot.create`. |
| `GET /v1/bots` | manage_server | The same fields without `token`, active bots only. |
| `DELETE /v1/bots/{id}` | manage_server | `204`. Unknown or already revoked is `404`. Audited `bot.revoke`. |

`scopes` may be empty, or any unique subset of `rooms.read`, `rooms.write`, and `members.read`. An unknown scope is `400 invalid`.

`permissions`, when present, replaces `scopes`, including `members.read`. The integer is stored as sent when it is zero or positive. A negative integer is rejected. `1` (`VIEW_CHANNEL`, `1 << 0`) is `rooms.read`. `512` (`MANAGE_CHANNELS`, `1 << 9`) is `rooms.write`. Other bits are stored and add no scope. `members.read` has no bit, so it is granted only by the `scopes` array, and only when `permissions` is omitted.

The bot calls the API with `Authorization: Bot <token>`. The prefix is exact. `Bearer` remains a member session. Unknown or revoked is `401`.

`GET /v1/me` for a bot is the shape under Capabilities and me. `GET /v1/live` takes the same `Bot` header. `ready.online` is empty without `members.read`. `ready.calls` is empty without `rooms.read`. A bot with neither, or with only `rooms.write`, stays connected, answers `ping`, and receives no room or member payload.

`rooms.read` lists rooms and receives `room.*` plus `call.joined`, `call.left`, and `call.state`. `members.read` lists members and receives `member.*` and `presence`. `rooms.write` creates, renames, and deletes rooms and receives none of those payloads by itself. A bot does not receive message, direct, typing, or read frames, and it cannot post them. Any client frame whose type starts with `call.` is `forbidden`. Revocation closes the socket with `4001 session_ended` on the next credential check, every 60 seconds.

## Operator suspension and legal hold

`migrations/0016_operator.sql`. One row, `operator_state`, that the runtime role may read and only the owner role may write, through `tinyserver operator` in the init container. Every change is a row in `operator_events`, which the runtime role cannot read.

| Command | Effect |
| --- | --- |
| `tinyserver operator status [--json]` | The mode, notice, since, hold, and the number of reports owners put on hold |
| `tinyserver operator suspend --read-only --notice TEXT` | Reads, signing in and out, `DELETE /v1/me`, and `POST /v1/reports` still work. Every other write is `503 read_only`. On the live socket, `call.join`, `call.offer`, `typing` and the moderation frames get `error {code: "read_only"}`; calls already running go on until they end. |
| `tinyserver operator suspend --offline --notice TEXT` | Only `GET /health` and `GET /v1/status` answer; everything else is `503 suspended`. Open live sockets close with `4010 suspended` at their next session check, within a minute. |
| `tinyserver operator resume` | Normal again. The notice is cleared. |
| `tinyserver operator hold [--reason TEXT]` / `release` | A legal hold. Resolved reports stop expiring, and `deploy/tenant/operator.sh` refuses to delete or overwrite the community. The reason is kept in `operator_events` only. |

The notice is 1 to 500 characters with no control characters but new lines. `GET /v1/status`, with no session, is `{"mode": "normal" | "read_only" | "offline", "notice", "since"}`. It never says whether there is a hold. The server reads the row at most every `TINYSERVER_OPERATOR_REFRESH_MS` (2000 by default; `0` reads it for every request), so a change reaches every request within that; when the row cannot be read the last state read is kept.

## Bootstrap

While there is no owner, `tinyserver bootstrap` keeps an unexpired unused owner invite. The first time, it writes the link and the `tc1.` code (or the raw token when `TINYSERVER_PUBLIC_URL` cannot form a link) to `{TINYSERVER_DATA_DIR}/owner-invite` and prints only that path. In `deploy/compose.yml` this runs in `tinyserver-init` with `TINYSERVER_DATA_DIR=/bootstrap`, so the file is `/bootstrap/owner-invite`, which the server mounts read only. A later start prints a reminder with that invite's expiry and does not write the token again. Once the invite has expired it makes a new one, good for 24 hours, single use. When an owner already exists it removes that file and writes nothing else.

`--owner-invite` makes a new 24-hour single-use owner invite even when one is still valid or an owner exists. Unused earlier owner invites stop working. Each of those writes `invite.revoke`. The new invite writes `bootstrap`. A repeat with no `--owner-invite`, while the current owner invite is still valid, writes no audit row.
