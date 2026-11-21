# Group conversations

Date: 2026-11-05 (revised 2026-11-21 for #56, #58–#61 against `main` through `0054_channel_threads.sql`). Repos: tinyserver and tinyclient.

A group conversation is a conversation of three or more people in one community, started by a member, with an explicit member list. It sits beside a direct message. It is not a text channel, not a category, and not a role.

## The problem

The server already has the other two shapes.

- A text channel is a `channels` row. Who can see it is `view_channel`, role overrides, and the owner flag. Owners have every permission bit, so an owner can open every channel. Categories already exist, a channel may set `category_id`, and `PUT /v1/layout` orders channels alongside voice rooms (`0047_channel_layout.sql`).
- A direct is a `directs` row: one ordered pair, `low_user_id < high_user_id`, unique per pair and `e2ee` flag (plus `is_self` for a person's own device-sync conversation from `0036_e2ee_self.sql`). `POST /v1/directs` takes one `user_id`. Events go only to those two people.

Nothing stores a member-chosen set of three or more. The client can show `ConversationKind::Group` for other networks. The Tiny adapter never emits it. `GET /v1/directs` is decoded as a `Vec` of objects that each require one `peer`. One object without `peer` fails the whole list.

Categories, role-private channels, and one-to-one directs stay as they are.

## What this builds

A member can start a group conversation with two or more other members. People in it can post, read, add a person, leave, and optionally name it. People outside it, including an owner who was not added, get the same `404` a third person gets on someone else's direct.

End-to-end encryption follows the conversation, the way it already does for a channel or a direct (encrypted group creation and MLS support land in #57; plaintext groups land in #61/#60 and refuse `e2ee: true` with `400 e2ee_off` until #57 ships). The server does not gain a new way to read messages. The client uses the warning strings it already has.

Old clients keep working. Groups are a new route. The directs list does not change shape.

## Goals

- A member can create, list, open, name, post in, add to, and leave a group of three or more members. There is no product cap on how many people are in it.
- Membership is the named set only. Roles, overrides, and the owner flag do not add or remove anyone.
- Kick, ban, and account deletion remove the person from the group and from its MLS desired set. Timeout does neither.
- Existing channels, directs, live audiences, bots, reports, and the four `e2ee_text` modes keep their current behavior.
- The desktop chip and the phone strip use the strings already in the client. No new warning sentence.

## Non-goals

- Rebuilding text channels, categories, role overrides, or one-to-one directs.
- Calling a group. That is #63 and TinyComms/tinyclient#291. A group row has no `last_call`.
- A member kicking another member of the group. The community kick and ban already exist.
- Converting a direct into a group, or copying a direct's messages into a group.
- Read receipts broadcast to the group. A direct still shows `peer_read` to the one other person. A group does not.
- @everyone, role mentions, threads, mute stored on the server, disappearing messages, or a moderator delete of one message in a group.
- A product cap on members, and a new server setting for one. `group_full` does not exist. The only ceiling is the one MLS already has, and it counts devices, not people.
- Key backup, a server-held group secret, or sharing one MLS group with a channel or a direct.
- Advertising "End-to-end encrypted messaging" while `docs/privacy/guarantees.md` section 7 still forbids that claim.

## Anti-goals

Any of these is a failure even if a message sends.

- An owner, or anyone with `view_channel`, is in the set or the MLS group without being added.
- A group event goes out with a null or empty audience. Both mean every member socket (`crates/api/src/live/frame.rs`, `Event::from_row`).
- Plaintext is accepted into an encrypted group, or a plaintext or pre-upgrade group is labelled end-to-end encrypted.
- A removed person, or a device that is waiting because the MLS group is over `e2ee_group_devices_max`, can fetch new ciphertext.
- Message text, filenames, keys, tokens, SDP, or ciphertext land in operator logs, the audit reason, the report row, `last_message` of an encrypted group, or the outbox after a delete.
- A report stores the member list, or `manage_reports` joins the group.
- The audit log stores the other member's id on add, leave, or create, so `view_audit_log` can rebuild the set. A direct create writes no such row today.
- Bots become members or receive group message, typing, or read frames.
- `GET /v1/directs` changes shape, or a group object is decoded with the direct list.

## Approaches

**1. A new kind, `group`. Chosen.** Tables `group_dms` and `group_dm_members`. Messages gain `group_dm_id` (since `messages.group_id` is already the MLS group UUID from `0039_e2ee_group_generations.sql`), so a row has exactly one of `channel_id`, `direct_id`, or `group_dm_id`. Routes are `/v1/groups`. Old clients never see them. Channels and directs keep their SQL.

**2. Widen `directs` into a member set.** Rejected. The pair key, the `peer` object, and `WireDirect` are the one-to-one contract. One bad element fails the whole directs list. A two-person row and a ten-person row would share rules that the privacy docs state separately (the direct exception for `peer_read` is one other person).

**3. A private channel plus a role per group.** Rejected. Channel membership is permission, and owners have every bit. `docs/e2ee-text.md` says who is in an encrypted channel is decided by permission, not by who asks. That is the right rule for a channel and the wrong rule for this. It would put every owner in the MLS group.

## Locked acceptance criteria

These are the decisions. A later plan should test them, not reopen them.

### Identity and wire

1. A group is not returned by `GET` or `POST /v1/directs`. `WireDirect.peer` stays required. The Tiny adapter decodes `GET /v1/groups` on its own. A failure there does not clear the directs list.
2. The client cannot choose the group id. The server generates it. `app_open_conversation` resolves a channel, then a direct, then a group. A test shows a channel id does not open as a group and a group id does not open as a channel. No cross-table exclusion constraint.
3. Tables are `group_dms` and `group_dm_members`. The message parent column is `messages.group_dm_id`; the report column is `reports.group_dm_id`. `messages` keeps a check that `num_nonnulls(channel_id, direct_id, group_dm_id) = 1`, and both the plaintext and ciphertext idempotency indexes cover the third parent (`messages_e2ee_client` over `coalesce(channel_id, direct_id, group_dm_id)`). `reads.kind` allows `group` alongside `channel`, `direct`, and `thread`. A group read is never stored as `direct`. The kind word stays `group` (`reads.kind`, `app_open_conversation.kind`, the `kind` field of message events), the routes stay `/v1/groups`, and the topics stay `group.*`. No new API error code contains the word `group`; the four that do (`group_exists`, `no_group`, `not_in_group`, `e2ee_group_too_large`) are about MLS.
4. `GET /v1/capabilities` includes `groups` on a server that has these routes. The client hides group controls when the feature is absent.
5. `POST /v1/groups` is find-or-create. The member set is the caller plus `user_ids`. If a group with exactly that set and that `e2ee` flag exists, the answer is `200` and that group; nothing is created, renamed or announced. Otherwise `201`. Two calls racing for the same set get the same group. A set has at most one group **made by create**. Add, leave, kick, ban and account deletion change a group's set and may make it equal to another group's; that is allowed, both stay, and a later create for that set returns the one with the newest message (then the oldest `created_at`, then the lowest `id`). There is no `client_id` on a group: a retried create finds the group the first try made.

### Membership

6. `POST /v1/groups` takes `user_ids` (the other people), optional `name`, optional `e2ee`. The caller is a member. Fewer than two other ids is `400 invalid`, because two people are a direct. A create takes at most 100 ids, `400 invalid` past that; total membership stays uncapped and further people come in through the add route. The server does not answer `group_full`.
7. Each other id uses the direct's split: missing or not a member is `404 not_found`, banned is `403 banned`, self or a duplicate is `400 invalid`. A bot is not a user, so it is `404 not_found`. Bots stay `403` from `messages::scoped` before SQL, and group routes use that gate.
8. Any current member may add one person who would pass create. Already in is `200` and no second row. An add is never refused for member count (only the MLS device ceiling for encrypted groups in criterion 20). Roles, overrides, and the owner flag do not add or remove anyone.
9. Any current member may `PATCH` the name: 0 to 80 characters after trim, no control characters. Empty is stored empty. The server does not store a title built from display names. No topic, category, or position.
10. Any current member may leave with `DELETE /v1/groups/{id}/members/me`. There is no route to remove another member. The last member's leave deletes the group and its messages. A group that drops to two people, or one, stays a group; it is never merged into a direct.
11. Only a current member can list or open a group. Anyone else, including an owner who is not a member, gets `404` on the group, its messages, its media, and `GET /v1/e2ee/conversations/{id}`, and is not in the MLS desired set.
12. Community kick (`DELETE /v1/members/{id}`), ban, and account deletion drop that person from `group_dm_members` (via `ON DELETE CASCADE` on `memberships(user_id)`) and from the MLS desired set, in the same transaction, before reconcile runs. Account deletion also empties the messages they wrote, as it does today. Timeout does not remove them, does not remove them from the desired set, blocks speak, and still allows read. Someone who is kicked and later rejoins the community is not put back in their old groups.
13. After kick, ban, leave, or account deletion, that person gets `404` on the group. A member who remains can still open it.
14. On create, every initial member has `unread` 0. On add, insert that person's read cursor at the latest message, so `unread` is 0, for a plaintext group and an encrypted group alike. `GET` history is unchanged: plaintext from before the join is still returned, and ciphertext from before the join still does not decrypt. No `read.updated` is emitted. A badge of the whole history is rejected, because it counts messages the new member was not part of, including ciphertext they cannot read.

### History, encryption, events

15. A person who is a member at read time can `GET` plaintext from before they joined. That matches G2.1 (plaintext goes to whoever can view it now). It is not the encrypted rule. Their badge does not count that history. See criterion 14.
16. An encrypted add, including a new device of someone already in, decrypts nothing from before that add. History is not re-encrypted when someone leaves. A removed person keeps what they already decrypted.
17. `e2ee` is fixed at create under the same four modes as a direct (`off`, `optional`, `new_required`, `required`). An omitted `e2ee` is false, then `app_e2ee_may_create` applies, the same as `POST /v1/directs`. Until #57 ships, `POST /v1/groups` with `e2ee: true` returns `400 e2ee_off`, whatever the server setting. Upgrade is one-way (in #57), the same as a channel, and does not relabel old plaintext. Creating the group does not copy messages out of a direct.
18. The group never shares an MLS group with a channel or a direct. The audience hash uses a `group:` prefix. `e2ee_audience_groups` does not bind it to a channel.
19. `app_e2ee_desired` (in #57) has a group branch: active devices of current unbanned members. It must not fall through to the empty result it returns today for an id that is neither a channel nor a direct. An empty desired set is what reconcile uses to delete a group that still has leaves.
20. Beyond the 100-id per-request limit on `POST /v1/groups` (criterion 6), the only size check is the existing MLS device cap, and only for an encrypted group. Create whose devices already exceed `e2ee_group_devices_max` is `400 e2ee_group_too_large`. That setting defaults to 2000 devices and an admin may set it from 2 to 20000. An add to an encrypted group that would take its desired device count past `e2ee_group_devices_max` is refused with `400 e2ee_group_too_large` and adds no one. This is the MLS device ceiling, not a member cap. A plaintext group has no size check. If the group goes over the ceiling later (members enrol more devices), the existing channel rule applies: sends are refused until it fits.
21. Every group event uses an explicit non-empty audience of user ids. Never null, never `{}`. `app_scope_audience` must not widen an explicit audience, and `app_outbox_append` refuses any payload with `kind = 'group'` or a `group_id` key when its audience is NULL. `channel.deleted` stays as it is.
22. Audience for `group.created`, `group.updated`, and `group.member_added` is the current members, including someone just added. Audience for `group.member_left` is the remaining members and the person who left. Audience for `group.deleted` is only the last member. Audience for `group.member_reachable` (#58) is the current members of each group that person is in. None of these go to the rest of the community.
23. Read cursors are stored per member and not broadcast. There is no `peer_read` on a group. This follows the channel half of G3.9. The direct exception stays one other person and does not extend here. `app_mark_read` must not emit `read.updated` for a group.
24. Typing is ephemeral, goes only to other current members who are not the sender (gated by reachability per #58), requires the sender to be a member who may speak, and is not stored.
25. Author-only edit and soft delete, using the existing tombstone: clear plaintext, remove ciphertext and files, rewrite the outbox so replay does not return them. No moderator delete of one message. Plaintext uploads keep the scan gate. Sealed uploads stay opaque: no sniff, no clamd, fixed name and type.
26. Plaintext `client_id` stays unique per author across conversations. Ciphertext `client_id` stays unique per device and conversation, and the conversation key includes `group_dm_id`.

### Reports, audit, logs

27. `reports.kind` stays `message`, `member`, or `channel`. A member reports a group message as `kind=message`. The row stores `message_id` and `reports.group_dm_id` (exposed in JSON as `group_id`), not the body and not the member list. A non-member gets `404`. `manage_reports` does not add the moderator. Evidence stays unverified. `kind=channel` still requires a `channels` row.
28. Operator logs follow the existing denylist. A new field that can hold message text, a filename, a key, or ciphertext is on that denylist or covered by the canary. Audit for `group.create`, `group.add`, `group.leave`, `group.rename`, and `group.delete` stores the actor and the group id (`subject = 'group'`, `subject_user_id = NULL`). Rename may also store the name the member set. Audit does not store another member's id, the member list, message text, or a generated title. `view_audit_log` does not grant a member-list API.
29. New tables follow the messages pattern: forced row level security, `SELECT` only for what `app_open_conversation` allows, no general write grant for `app_runtime`, writes through the security-definer functions.

### Client

30. A group row is `ConversationKind::Group`. It is in the Inbox and in People. On the Tiny People list a group sits in the same list as direct messages, ordered by the same recency. It is not a row under TEXT CHANNELS on the Tiny rail. `in_the_server` already keeps only channels.
31. With `groups` in capabilities, a member starts a group from an open direct: Add people, pick at least one more member, `POST /v1/groups` with the direct's other person plus those ids. A `200` opens the group that already exists. The direct stays. Its messages are not copied. New message of one person stays `POST /v1/directs`.
32. An empty name is shown as the other members' display names in join order, the first two, then `+N` for the rest. Never the viewer's name. Never the word "Chat". A missing display name is "Someone". The avatar uses the existing two-face fallback. The header subtitle is the people count and those names.
33. Unread on an unmuted group with `mentions` stored as 0 is the count pill. `badge_look` already does that. Muted stays the existing bell, with a mention pill only if `mentions > 0`. A member who just joined shows no unread badge until a later message from someone else.
34. Leave uses the existing confirm ("Leave {name} on Tiny?" / "You'll stop getting its messages. To come back, someone in it has to add you.") and then succeeds. Today Tiny `Command::Leave` returns unsupported.
35. The desktop chip is "End-to-end encrypted" or "Not end-to-end encrypted", with the existing tooltips, including "the server can read this conversation." The phone strip is "Encrypted" or "Server can read". A row that will not open says "Can't be decrypted on this device" and never the server's `body`. The late-join sentence stays "Messages from before you joined can't be read." Do not invent an upgrade sentence. Do not relabel pre-upgrade plaintext as encrypted.

### Old clients (#58)

Already-released clients never call `/v1/groups`. A person on an older app can still be added to a group (Option B in #58): the add succeeds, and they will see the group and its plaintext history when they update. To close the silent gap and prevent older clients from receiving orphan `message.*` / `reaction.updated` / `typing` frames for an unknown conversation id:

- `memberships.groups_seen_at timestamptz` records when a member's session has called `GET /v1/groups` (updated at most once a day).
- Each entry of `members` in a group object carries `"reachable": true|false` (`groups_seen_at IS NOT NULL`).
- When a person's `groups_seen_at` transitions from NULL to non-NULL, the server emits `group.member_reachable {"group_id", "user_id"}` to the members of each group that person is in so the client's hint clears without a reload.
- Live `message.*`, `reaction.updated`, and `typing` fan-out for a group excludes members whose `groups_seen_at IS NULL` (falling back to the nil UUID if no member is reachable yet so the audience is never NULL or empty).

## Contract

### Tables

`group_dms`: `id uuid` primary key default `gen_random_uuid()`, `name text not null default ''` with check `char_length(name) <= 80`, `e2ee boolean not null default false`, `created_by uuid not null references users (id)`, `created_at timestamptz not null default now()`, `member_key bytea not null` with check `octet_length(member_key) = 32`. Non-unique index `group_dms_member_key (member_key, e2ee)`.

`group_dm_members`: `group_dm_id uuid not null references group_dms (id) on delete cascade`, `user_id uuid not null references memberships (user_id) on delete cascade`, `joined_at timestamptz not null default now()`, `seq bigint generated always as identity`, primary key `(group_dm_id, user_id)`, index on `user_id`. Deleting a community membership (kick, ban, account deletion) cascades and removes the person's group rows in the same statement before MLS reconcile runs; timeout does not touch `memberships`. An `AFTER INSERT OR DELETE` trigger keeps `group_dms.member_key` current, removes the leaving member's `reads` row (`kind = 'group'`), and emits `group.member_left` when removal happens outside `app_group_leave`. Memberless groups left by kick, ban, or account deletion are removed with their attachment files by `app_group_sweep()` during the periodic sweep.

`messages.group_dm_id` nullable, foreign key to `group_dms (id)` on delete cascade. The parent check becomes `num_nonnulls(channel_id, direct_id, group_dm_id) = 1`. Index `messages_group_dm_seq (group_dm_id, seq) where group_dm_id is not null`. `messages_e2ee_client` is recreated over `coalesce(channel_id, direct_id, group_dm_id)`.

`reads.kind` check allows `('channel', 'direct', 'thread', 'group')`.

`reports.group_dm_id` nullable, foreign key to `group_dms (id)` on delete set null, no member-list column.

`memberships.groups_seen_at timestamptz` nullable (for #58).

`e2ee` on the group is the same one-way flag as on a channel. `app_conv_e2ee` and `app_e2ee_has_plaintext` learn the third table in #61; `app_e2ee_desired`, `app_e2ee_audience_hash`, `app_e2ee_upgrade`, `app_e2ee_repair`, and the UUID reservation / forget triggers land in #57.

The next migration number is the next free file after `0054_channel_threads.sql` (`0055_...`). This checkout has no `0017`–`0019` or `0026`–`0029`. Do not reuse a missing number.

### What migrations `0035`–`0054` changed for a third conversation kind

- **0036** added a self conversation as a `directs` row with `is_self`. Group code that looks at `directs` must not treat it as a pair; the group list must not include it. No group equivalent is needed.
- **0037/0041** every encrypted send runs `app_e2ee_require_current_audience`, which refuses the post unless the MLS leaves are exactly the desired devices. `app_outbox_append` is the single door to the outbox (and guards against a NULL audience on any group event), and the latest `app_e2ee_desired` is in `0041`.
- **0038** `app_e2ee_establish_audience` reads the conversation from `coalesce(channel_id, direct_id, group_dm_id)`.
- **0039** generations: `messages.group_id` is the MLS group UUID; `app_e2ee_generation_stamp` reads `coalesce(channel_id, direct_id, group_dm_id)`; new `group_dms` rows get the UUID reservation and forget triggers in #57.
- **0040** `direct_call_log` and `last_call` are per direct only. Calls in a group are out of scope here (#63).
- **0042** `app_mark_read` emits a self `read.updated` for channels and peer+self for directs; groups emit nothing.
- **0045/0046** moderator delete stays channel-only (`v_channel IS NOT NULL AND app_channel_has(v_channel, 2097152)`). `app_pin_message` and `app_unpin_message` resolve three parents and pass the opener's `audience`.
- **0048** `app_open_conversation` enforces blocks on directs only; `app_unread` skips blocked authors across channels, directs, and groups.
- **0049** `app_store_mentions` accepts `user` mentions of current members in a group and drops `role` and `everyone`; `app_unread_mentions` handles `p_kind = 'group'`.
- **0050** `app_search_messages` includes plaintext messages in groups the caller belongs to and skips encrypted groups.
- **0051/0053/0054** `app_post_message`, `app_post_message_ext`, `app_post_message_thread`, `app_edit_message`, `app_delete_message`, `app_reaction`, `app_custom_reaction`, and `app_list_messages_filtered` all resolve `group_dm_id` and emit with the opener's `audience` instead of the removed `app_audience` helper. Thread replies (`thread_id`) remain channel-only.

### HTTP

| Route | Who | Result |
|---|---|---|
| `GET /v1/groups` | member | `{"groups": [group, ...]}`: groups the caller is in, ordered by `created_at, id`. Updates `memberships.groups_seen_at` (at most once a day). |
| `POST /v1/groups` | member, not banned. A timeout does not block create | `201` created, or `200` if a group with that exact member set and `e2ee` flag already exists. `e2ee: true` returns `400 e2ee_off` until #57 ships. |
| `GET /v1/groups/{id}` | current member | One group. Else `404` |
| `PATCH /v1/groups/{id}` | current member | `{name}` → the group. Audited `group.rename` |
| `POST /v1/groups/{id}/members` | current member | `{user_id}` → `201` and the group, or `200` if already in |
| `DELETE /v1/groups/{id}/members/me` | current member | `204`. Last member deletes the group |

A timed-out member may create, rename, add, and leave. They may not post, react, pin, or type. That matches a timeout on a channel: read stays, speak stops.

Posts, edits, deletes, reactions, history, and read cursors stay on `/v1/conversations/{id}/...` and `/v1/messages/{id}`. The opener knows the third kind.

Operator reads follow `GET /v1/directs` (allowed while `read_only`). Operator writes follow `POST /v1/directs` (refused with `503 read_only`).

### JSON

A group object:

```json
{
  "id": "…",
  "name": "",
  "e2ee": false,
  "plaintext_history": false,
  "created_by": "…",
  "created_at": "…",
  "members": [{"user_id": "…", "display_name": "…", "joined_at": "…", "reachable": true}],
  "unread": 0,
  "last_read": null,
  "last_message": null
}
```

`members` is every current member, including the caller, in join order (`joined_at, seq`). On create, the caller is first, then `user_ids` in the order given. `reachable` is `memberships.groups_seen_at IS NOT NULL` (#58). `last_message` matches a channel: `{id, author_id, body, created_at}` with `body` cut at 200 characters, or null. On an encrypted group the preview body is empty. There is no `peer`, no `peer_read`, and no `last_call`. `unread` follows criterion 14.

### Live events

| Topic | Payload | Audience |
|---|---|---|
| `group.created` | `{"group": {id, name, e2ee, created_by, created_at, members}}` | all current members |
| `group.updated` | `{"group_id", "name"}` | all current members |
| `group.member_added` | `{"group_id", "user_id", "members"}` | all current members, including the new one |
| `group.member_left` | `{"group_id", "user_id"}` | remaining members and the person who left |
| `group.deleted` | `{"group_id"}` | the person whose leave emptied it |
| `group.member_reachable` | `{"group_id", "user_id"}` | all current members of each group that person is in |

Event payloads carry no per-viewer fields (`unread`, `last_read`, `last_message`): one row is serialised once for every socket. Payload keys are `group_id` (not `channel_id` and not `conversation_id` with `kind: "channel"`), so `app_scope_audience` can never match them. Every group event goes through `app_emit_to` with an explicit non-empty array (falling back to the nil UUID if empty).

Message topics stay `message.created`, `message.edited`, `message.deleted`, and `reaction.updated`, with the same payload as a direct (`kind: "group"`), and the audience is the current reachable member ids (falling back to the nil UUID if none are reachable yet).

### Encryption label

The server already exposes `e2ee` on the conversation. The client already maps that flag to the chip and the phone strip. A group sets the same flag. No new copy.

The settings sentence already says the server still sees who is in a conversation, when messages are sent, and how large they are. A group does not change that. Do not write a warning that says the member list is hidden.

## What stays unchanged

- `POST /v1/directs` for an existing pair and `e2ee` flag still returns `200` and the same id. A pair can still have one plaintext direct and one encrypted direct. A twin upgrade is still `409 e2ee_twin`.
- Channel create still needs global `manage_channels` (512). Overrides still need `manage_roles`, the channel bit, the mask `6537855`, and a distinct hierarchy error.
- A member denied `view_channel` on a channel still gets `404` and still misses that channel's events when the channel is restricted.
- Direct message events still go only to the two user ids.
- `read.updated` is emitted only for directs (both parties), channels (reader only), and threads (reader only) — never for a group.
- Bots still have no `memberships` row and still do not see `message.*` or `group.*` on `GET /v1/live`.
- Under `e2ee_text = required`, a new plaintext channel, direct, or group is still refused.

## Calls made here

These were not in a written product request. They are decided in this document so a builder does not guess.

| Call | Why |
|---|---|
| New kind, not a wider direct and not a private channel | Approaches 2 and 3 break the wire or the owner rule |
| Find-or-create by member set and `e2ee` flag | Adding people from a direct or call opens the existing group with those people instead of duplicating it |
| Adding a member when the resulting set equals another group's is allowed; both stay | A leave, kick, ban, or account deletion can already make two groups converge and cannot be refused; create tie-breaks by newest message, oldest `created_at`, lowest `id` |
| Group dropping to two people, or one, stays a group | Never merged into a one-to-one direct |
| No member cap. Floor of 3 at create (max 100 per create call), because two people are a direct | Size follows the community and, for an encrypted group, the existing device cap (`e2ee_group_devices_max`, default 2000, max 20000). Plaintext has no total-membership check |
| Any member may add. No peer kick | Same shape as a direct. Community kick, ban, and reports already exist. G2.22 requires kick, ban, and account deletion to cut ciphertext |
| Plaintext history is visible to a later member | G2.1. Encrypted history is not. The two are different on purpose |
| No group read receipts | G3.9's channel rule. Extending `peer_read` would be a new fan-out |
| Audit stores actor and group id, not the other member | Otherwise `view_audit_log` rebuilds the set. A direct create does not write that |
| Start from a direct, and keep the direct | Moving history would either copy plaintext or pretend encrypted history transferred |
| A person who is added starts at `unread` 0, cursor on the latest message | A badge of the whole history counts ciphertext they cannot decrypt. Scrollback still follows criterion 15 |
| Older clients allowed to be added, flagged via `reachable` and gated on live message events (#58) | A group is durable; they get history when they update, others see the hint, and old clients do not receive orphan frames |
| Client work is part of this feature | A server route nobody can start is the gap the Tiny column already has for text channels |

## Left to the builder

- Function bodies and index names, as long as membership removal cascades before MLS reconcile and timeout does not.
- The exact Add control, as long as it starts from an open direct, posts the ids above, leaves the direct in place, and does not show up when `groups` is missing from capabilities.
- How `joined_at` is displayed. Join order is the title order. The screen does not need to show the timestamp.

## Verification notes

Revised and checked against `main` through `0054_channel_threads.sql` (`fc52f37`), including `0036_e2ee_self.sql`, `0037_e2ee_membership_barrier.sql`, `0038_e2ee_initial_audience.sql`, `0039_e2ee_group_generations.sql`, `0040_direct_calls.sql`, `0041_send_path_locks.sql`, `0042_channel_read_self_event.sql`, `0045_moderator_message_delete.sql`, `0046_channel_pins.sql`, `0047_channel_layout.sql`, `0048_blocks.sql`, `0049_message_mentions.sql`, `0050_message_search.sql`, `0051_message_previews.sql`, `0053_custom_emoji.sql`, and `0054_channel_threads.sql`, plus `docs/privacy/guarantees.md`, `docs/e2ee-text.md`, and `docs/server.md`.
