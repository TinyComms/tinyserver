# Server management

Roles with permissions, an owner flag above them, per-room overrides, server settings, categories, bans, timeouts, multi-use invites, and an audit log with names. The wire contract tinyclient builds against. Calls and the live socket are in [`calls.md`](calls.md).

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

All bits: `1048575`. Bits a room override may hold: `246399`. @everyone on a new server: view_channel, connect, speak, video, share_screen, voice_activity, `63`.

| Rule | |
| --- | --- |
| Owner | A flag on the membership, above every role. Owners have every bit everywhere. One or more owners; the last one cannot be demoted, kicked, or banned (`last_owner`). Only owners grant or revoke owner. |
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
| `banned` | 403 | A banned person; `/v1/auth/callback` sends `error=banned` |
| `too_large` | 413 | An icon over 256 KiB, or an upload over the server's cap |
| `unsupported_media` | 415 | An icon that is not PNG, JPEG, or WebP; a refused attachment type; a liar file whose extension, MIME, and sniff disagree; PE (MZ) or ELF regardless of name |
| `scanning` | 423 | `GET /v1/media/{id}` while the file is not yet clean |
| `blocked` | 403 | The scanner blocked the file on upload or download |
| `unavailable` | 503 | The scanner is down, timed out, or otherwise could not finish; upload gets no 201 |

## REST

Every route needs a session. "Any member" means any signed-in member.

### Capabilities and me

`GET /v1/capabilities` (any member) → `{"version": "…", "features": ["server", "roles", "categories", "bans", "timeouts", "invite_options", "audit_query", "voice_moderation", "e2ee_calls", "upload_limits", "file_scan"]}`. `e2ee_calls` means calls can be end-to-end encrypted ([`calls.md`](calls.md#end-to-end-encryption)): `call.join` takes `e2ee`, the live socket carries `call.e2ee`, and rooms have `e2ee_required`. `file_scan` means uploads are scanned before 201 and downloads stay gated until clean; clients without it keep the older upload behaviour.

`GET /v1/me` and `PATCH /v1/me` add `owner`, `roles [id]` (most senior first), `permissions` (base), and `rank`.

### Server

| Route | Who | |
| --- | --- | --- |
| `GET /v1/server` | any member | `{name, description, welcome, icon, default_room_id, afk_room_id, afk_timeout_secs, image_max_bytes, file_max_bytes, allow_archives, created_at}`. `icon` is the SHA-256 of the icon in hex, or `null`. A new server is "Tiny server". `image_max_bytes` defaults to 8 MiB (images and GIFs); `file_max_bytes` defaults to 25 MiB (video and every other kind); each may be set up to 100 MiB. `allow_archives` defaults to false. |
| `PATCH /v1/server` | manage_server | Any of the writable fields; the room ids take `null`. Name 1 to 80 characters, description up to 500, welcome up to 2000, `afk_timeout_secs` 0 (off) to 86400, `image_max_bytes` and `file_max_bytes` each 1 to 100 MiB, `allow_archives` boolean. Returns the whole object. Audited `server.update`. |
| `GET /v1/server/icon` | any member | The image, its `Content-Type`, and `ETag: "<sha>"`; `If-None-Match` gets 304. 404 without one. |
| `PUT /v1/server/icon` | manage_server | The body is the image: PNG, JPEG, or WebP, read from its first bytes, up to 256 KiB. Every other route keeps the 8 KiB body cap. `{icon}`. Audited `server.icon`. |
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
| `GET /v1/members` | any member | Rows add `owner`, `roles`, `last_seen_at`, `timeout_until` (while one runs), and `joined_via` (`invite`, `groups`, or `null` for members from before it was kept). `role` and `email` stay. |
| `PATCH /v1/members/{id}` | legacy | `{role}`: `owner` sets the owner flag (owners only), `admin` adds the most senior role with manage_server or manage_roles, `member` takes those away and the owner flag. → `{role}`. |
| `PUT /v1/members/{id}/roles` | manage_roles | `{role_ids}` replaces their roles → member row |
| `PUT /v1/members/{id}/owner` | owners | `{owner}` → member row |
| `PUT /v1/members/{id}/timeout` | timeout_members | `{until, reason?}`: an RFC 3339 time within 28 days, or `null` to end it → member row. A timeout ends their call and refuses `call.join` with `timed_out`. |
| `DELETE /v1/members/{id}?reason=` | kick_members | Kick: the membership and every session go. The reason goes to the audit row. |

`last_seen_at` is written in batches every 30 s for everyone with a live socket open, and when a socket opens or closes.

### Bans

| Route | Who | |
| --- | --- | --- |
| `GET /v1/bans` | ban_members | `[{user_id, display_name, email, reason, banned_by, banned_by_name, created_at, expires_at}]`, bans in force |
| `POST /v1/bans` | ban_members | `{user_id, reason?, expires_at?}` → 201 ban. The membership and every session go, sockets close with `4003`, and their call ends with `banned`. The ban holds every (issuer, subject) the person signed in with, so an invite, a joining group, and a fresh sign-in are refused. A person who is no longer a member can be banned too. |
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

`GET /v1/rooms` rows add `category_id`, `position`, `topic`, `user_limit` (0 is the server's room cap), `bitrate_kbps` (16 to 128, default 64), `ptt_only`, `video_enabled`, `e2ee_required` (default false), `overrides [{role_id, allow, deny}]`, and `my_permissions`. Rooms the caller cannot view are left out; owners see all. Rooms come uncategorized first, then by category, each by `position`.

`POST /v1/rooms` takes `{name, category_id?, topic?, user_limit?, bitrate_kbps?, ptt_only?, video_enabled?, e2ee_required?}` (manage_channels); `PATCH /v1/rooms/{id}` any of those and `position` (manage_channels in that room). `PUT /v1/rooms/{id}/overrides/{role_id}` `{allow, deny}` and `DELETE` set and clear one role's override; they need manage_roles and manage_channels in the room, and the role below the caller. Bits outside the room set are dropped; a bit in both is allowed. Audited `room.update` and `room.override`.

Clients encode at `bitrate_kbps`; `ptt_only` and `voice_activity` are honoured by the client. The SFU is unchanged by them. `e2ee_required` is the server's: while media runs, a `call.join` without `e2ee` to that room gets `e2ee_required` and takes no seat. People already in the call when it is turned on stay; the call is transport only until they leave. It is a promise the server makes, not one the apps can check: see the threat model in [`calls.md`](calls.md#what-it-protects-and-what-it-does-not). Migration [`0007_e2ee.sql`](../crates/db/migrations/0007_e2ee.sql) adds the column and makes `app_call_access` return it; nothing else about end-to-end encryption is stored.

### Invites

| Route | Who | |
| --- | --- | --- |
| `POST /v1/invites` | create_invites | Legacy `{role}` (`member` or `admin`), or `{role_ids?, label?, max_uses?, expires_in_secs?}`. `max_uses` 1 to 1000, `null` for unlimited, 1 when left out. `expires_in_secs` 60 to 2592000, `null` for never (owners and manage_server only), 7 days when left out. Roles need manage_roles and must be below the caller. → 201 `{id, token, role, expires_at, label, max_uses, role_ids}`; the token is shown once. |
| `GET /v1/invites` | create_invites or manage_invites | Invites that still work. Rows add `label`, `max_uses`, `uses`, `role_ids`, and `created_by_name`; `created_by` and `created_by_name` are `null` for the owner invite from `tinyserver bootstrap`, "Server setup" in clients. `expires_at` is `null` for one that never expires. `accepted_at` and `accepted_by` are the last use. |
| `DELETE /v1/invites/{id}` | manage_invites, or create_invites for one's own | 204 |

Accepting an invite makes the membership, gives its roles, counts a use, and records `joined_via: "invite"`; a banned person is refused before any of it.

### Audit

`GET /v1/audit?limit=1..200&before=<id>&actor=<user id>&action=<prefix>` (view_audit_log): newest first. Rows add `actor_name`, `subject_user_id`, `subject_name`, and `reason`. For the next page pass the last row's `id` as `before`. Actions added: `server.update`, `server.icon`, `role.create`, `role.update`, `role.delete`, `role.order`, `member.roles`, `member.owner`, `member.timeout`, `member.ban`, `member.unban`, `category.create`, `category.update`, `category.delete`, `layout.update`, `room.update`, `room.override`, `call.server_mute`, `call.move`. A kick's reason is on its `member.remove` row.

## Messages and attachments

Text channels, directs, and uploads are in [`calls.md`](calls.md#messages) for live topics. Recipients never `GET /v1/media/{id}` until the attachment is clean. `POST /v1/media` does not return 201 until then either; a message cannot reference an attachment that is still scanning, blocked, or in error.

### Type policy

These extensions are always refused (case-insensitive): `lnk`, `iso`, `img`, `vhd`, `vhdx`, `html`, `htm`, `hta`, `svg`, `js`, `vbs`, `cmd`, `bat`, `ps1`, `msi`, `scr`, `jar`, `exe`, `dll`, `com`, `pif`, `wsf`, `one`, `docm`, `xlsm`, `pptm`, `dotm`, `xltm`, `ppsm`. So are `image/svg+xml` and `text/html`, PE (MZ) and ELF magic regardless of filename, and any upload whose extension, declared MIME, and sniff disagree (415 `unsupported_media`).

Raster uploads (`image/png`, `image/jpeg`, `image/webp`, `image/gif`) are re-encoded before they are written to disk; other kinds are stored as received after type checks.

Archives (`zip`, `7z`, `rar`, `tar`, `gz`, `tgz`, `bz2`) are refused unless `allow_archives` is true on the server (default false; `manage_server` on `PATCH /v1/server`). When archives are allowed, `zip` is still capped: at most 1024 entries, each entry's uncompressed size at most four times its compressed size, total uncompressed at most 200 MiB, depth two (central directory only; an entry named as another archive counts as depth two and is not opened), no `..`, no symlink, no encrypted zip. Other archive kinds are accepted only when extension and MIME name the same archive type.

### Scanning

Production refuses to start unless `TINYSERVER_CLAMD_SOCKET` is set, except when `TINYSERVER_ALLOW_FAKE_SCAN=1` for local development and tests. Compose sets `TINYSERVER_CLAMD_SOCKET=clamd:3310` and `TINYSERVER_UPLOAD_DIR=/data/uploads`. Each scan may run up to `TINYSERVER_SCAN_TIMEOUT_MS` (default 8000, hard cap 15000). clamd runs beside yara-x rules; there is no separate content router.

On upload, a blocked file is 403 `blocked` with no committed row. Scanner down or timed out is 503 `unavailable` with no 201. On download, still scanning is 423 `scanning`; blocked is 403 `blocked`; scanner error is 503 `unavailable`; missing id or no access is 404.

### Media URLs and download

Attachment objects in JSON responses carry a signed `url`: `/v1/media/{id}?ex=…&is=…&hm=…` (expiry, issued time, HMAC-SHA256). Clients fetch with Bearer auth and those query parameters. `GET /v1/media/{id}` without a valid triple may still work for a member with a session alone; the signed URL is what tinyclient uses.

`Content-Disposition` is `inline` for PNG, JPEG, WebP, and GIF; everything else is `attachment`.

## Bootstrap

While there is no owner, `tinyserver bootstrap` keeps an owner invite that still works and prints nothing new; once it has expired it makes a new one and prints it. `--owner-invite` makes a new one at any time and the earlier one stops working. Only a new invite writes the `bootstrap` audit row, so restarts no longer fill the audit log.
