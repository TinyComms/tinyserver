# Group channels

Date: 2026-11-05. Repos: tinyserver and tinyclient. No branch yet. This is a design, not a claim that the feature is built.

A group channel is a conversation of three or more people in one community, started by a member, with an explicit member list. It sits beside a direct message. It is not a text channel, not a category, and not a role.

## The problem

The server already has the other two shapes.

- A text channel is a `channels` row. Who can see it is `view_channel`, role overrides, and the owner flag. Owners have every permission bit, so an owner can open every channel. Categories already exist, and a channel may set `category_id`. `PUT /v1/layout` does not order text channels.
- A direct is a `directs` row: one ordered pair, `low_user_id < high_user_id`, unique per pair and `e2ee` flag. `POST /v1/directs` takes one `user_id`. Events go only to those two people.

Nothing stores a member-chosen set of three or more. The client can show `ConversationKind::Group` for other networks. The Tiny adapter never emits it. `GET /v1/directs` is decoded as a `Vec` of objects that each require one `peer`. One object without `peer` fails the whole list.

The words "group channel" do not appear in the product docs. This design uses them for the missing member-set conversation. Categories, role-private channels, and one-to-one directs stay as they are.

## What this builds

A member can start a group with two or more other members. People in it can post, read, add a person, leave, and optionally name it. People outside it, including an owner who was not added, get the same `404` a third person gets on someone else's direct.

End-to-end encryption follows the conversation, the way it already does for a channel or a direct. The server does not gain a new way to read messages. The client uses the warning strings it already has.

Old clients keep working. Groups are a new route. The directs list does not change shape.

## Goals

- A member can create, list, open, name, post in, add to, and leave a group of three or more members. There is no product cap on how many people are in it.
- Membership is the named set only. Roles, overrides, and the owner flag do not add or remove anyone.
- Kick, ban, and account deletion remove the person from the group and from its MLS desired set. Timeout does neither.
- Existing channels, directs, live audiences, bots, reports, and the four `e2ee_text` modes keep their current behavior.
- The desktop chip and the phone strip use the strings already in the client. No new warning sentence.

## Non-goals

- Rebuilding text channels, categories, role overrides, or one-to-one directs.
- Nesting text channels under category headers. That is a separate column gap.
- A member kicking another member of the group. The community kick and ban already exist.
- Converting a direct into a group, or copying a direct's messages into a group.
- Read receipts broadcast to the group. A direct still shows `peer_read` to the one other person. A group does not.
- Mention counts, @everyone, threads, pins, mute stored on the server, disappearing messages, or a moderator delete of one message.
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

**1. A new kind, `group`. Chosen.** Tables `groups` and `group_members`. Messages gain `group_id`, so a row has exactly one of `channel_id`, `direct_id`, or `group_id`. Routes are `/v1/groups`. Old clients never see them. Channels and directs keep their SQL.

**2. Widen `directs` into a member set.** Rejected. The pair key, the `peer` object, and `WireDirect` are the one-to-one contract. One bad element fails the whole directs list. A two-person row and a ten-person row would share rules that the privacy docs state separately (the direct exception for `peer_read` is one other person).

**3. A private channel plus a role per group.** Rejected. Channel membership is permission, and owners have every bit. `docs/e2ee-text.md` says who is in an encrypted channel is decided by permission, not by who asks. That is the right rule for a channel and the wrong rule for this. It would put every owner in the MLS group.

## Locked acceptance criteria

These are the decisions. A later plan should test them, not reopen them.

### Identity and wire

1. A group is not returned by `GET` or `POST /v1/directs`. `WireDirect.peer` stays required. The Tiny adapter decodes `GET /v1/groups` on its own. A failure there does not clear the directs list.
2. The client cannot choose the group id. The server generates it. `app_open_conversation` resolves a channel, then a direct, then a group. A test shows a channel id does not open as a group and a group id does not open as a channel. No cross-table exclusion constraint.
3. `messages` keeps a check that exactly one parent is set, and both the plaintext and ciphertext idempotency indexes include the group parent. `reads.kind` may be `group` only after its check allows that word. A group read is never stored as `direct`.
4. `GET /v1/capabilities` includes `groups` on a server that has these routes. The client hides group controls when the feature is absent.
5. Create is not idempotent by member set. Two groups may contain the same people. Optional `client_id` is unique per creator, on the group, and is not the messages `client_id` index and not the global `idempotency_keys` primary key. Another creator may reuse the same string. A replay returns `200` and the same group only while that creator is still a member. If they have left, been kicked, or been banned, and the row still exists, the same `client_id` returns `404` and does not return members. The key stays, so the call does not create a second group. If the group row is already gone, the key is gone with it, and the same `client_id` may create a new group (`201`).

### Membership

6. `POST /v1/groups` takes `user_ids` (the other people), optional `name`, optional `e2ee`, optional `client_id`. The caller is a member. Fewer than two other ids is `400 invalid`, because two people are a direct. A create takes at most 100 ids, `400 invalid` past that; total membership stays uncapped and further people come in through the add route. The server does not answer `group_full`.
7. Each other id uses the direct's split: missing or not a member is `404 not_found`, banned is `403 banned`, self or a duplicate is `400 invalid`. A bot is not a user, so it is `404 not_found`. Bots stay `403` from `messages::scoped` before SQL, and group routes use that gate.
8. Any current member may add one person who would pass create. Already in is `200` and no second row. An add is never refused for size. Roles, overrides, and the owner flag do not add or remove anyone.
9. Any current member may `PATCH` the name: 1 to 80 characters after trim, or empty. Empty is stored empty. The server does not store a title built from display names. No topic, category, or position.
10. Any current member may leave with `DELETE /v1/groups/{id}/members/me`. There is no route to remove another member. The last member's leave deletes the group and its messages.
11. Only a current member can list or open a group. Anyone else, including an owner who is not a member, gets `404` on the group, its messages, its media, and `GET /v1/e2ee/conversations/{id}`, and is not in the MLS desired set.
12. Community kick (`DELETE /v1/members/{id}`), ban, and account deletion drop that person from `group_members` and from the MLS desired set, in the same transaction, before reconcile runs. Account deletion also empties the messages they wrote, as it does today. Timeout does not remove them, does not remove them from the desired set, blocks speak, and still allows read.
13. After kick, ban, leave, or account deletion, that person gets `404` on the group. A member who remains can still open it.
14. On create, every initial member has `unread` 0. On add, insert that person's read cursor at the latest message, so `unread` is 0, for a plaintext group and an encrypted group alike. `GET` history is unchanged: plaintext from before the join is still returned, and ciphertext from before the join still does not decrypt. No `read.updated` is emitted. A badge of the whole history is rejected, because it counts messages the new member was not part of, including ciphertext they cannot read.

### History, encryption, events

15. A person who is a member at read time can `GET` plaintext from before they joined. That matches G2.1 (plaintext goes to whoever can view it now). It is not the encrypted rule. Their badge does not count that history. See criterion 14.
16. An encrypted add, including a new device of someone already in, decrypts nothing from before that add. History is not re-encrypted when someone leaves. A removed person keeps what they already decrypted.
17. `e2ee` is fixed at create under the same four modes as a direct (`off`, `optional`, `new_required`, `required`). An omitted `e2ee` is false, then `app_e2ee_may_create` applies, the same as `POST /v1/directs`. Upgrade is one-way, the same as a channel, and does not relabel old plaintext. Creating the group does not copy messages out of a direct.
18. The group never shares an MLS group with a channel or a direct. The audience hash uses a `group:` prefix. `e2ee_audience_groups` does not bind it to a channel.
19. `app_e2ee_desired` has a group branch: active devices of current unbanned members. It must not fall through to the empty result it returns today for an id that is neither a channel nor a direct. An empty desired set is what reconcile uses to delete a group that still has leaves.
20. Beyond the 100-id per-request limit on `POST /v1/groups` (criterion 6), the only size check is the existing MLS device cap, and only for an encrypted group. Create whose devices already exceed `e2ee_group_devices_max` is `400 e2ee_group_too_large`. That setting defaults to 2000 devices and an admin may set it from 2 to 20000. It is not a member cap. A plaintext group has no total-membership cap. Adding a person to an encrypted group that then grows past the cap uses the existing waiting behavior: the person is a member, a waiting device is not added and cannot decrypt, and a member who already has a device in the group still receives ciphertext. Welcome copies stay under 4 MiB by the existing `app_e2ee_adds_per_commit` batches. Do not add a member ceiling in front of this.
21. Every group event uses an explicit non-empty audience of user ids. Never null, never `{}`. `app_scope_audience` must not widen an explicit audience. `channel.deleted` stays as it is.
22. Audience for `group.created`, `group.updated`, and `group.member_added` is the current members, including someone just added. Audience for `group.member_left` is the remaining members and the person who left. Audience for `group.deleted` is only the last member. None of these go to the rest of the community.
23. Read cursors are stored per member and not broadcast. There is no `peer_read` on a group. This follows the channel half of G3.9. The direct exception stays one other person and does not extend here. `app_mark_read` must not emit `read.updated` for a group.
24. Typing is ephemeral, goes only to other current members who are not the sender, requires the sender to be a member who may speak, and is not stored.
25. Author-only edit and soft delete, using the existing tombstone: clear plaintext, remove ciphertext and files, rewrite the outbox so replay does not return them. No moderator delete of one message. Plaintext uploads keep the scan gate. Sealed uploads stay opaque: no sniff, no clamd, fixed name and type.
26. Plaintext `client_id` stays unique per author across conversations. Ciphertext `client_id` stays unique per device and conversation, and the conversation key includes `group_id`.

### Reports, audit, logs

27. `reports.kind` stays `message`, `member`, or `channel`. A member reports a group message as `kind=message`. The row stores `message_id` and `group_id`, not the body and not the member list. A non-member gets `404`. `manage_reports` does not add the moderator. Evidence stays unverified. `kind=channel` still requires a `channels` row.
28. Operator logs follow the existing denylist. A new field that can hold message text, a filename, a key, or ciphertext is on that denylist or covered by the canary. Audit for `group.create`, `group.add`, `group.leave`, `group.rename`, and `group.delete` may store the actor and the group id. Rename may also store the name the member set. Audit does not store another member's id, the member list, message text, or a generated title. `view_audit_log` does not grant a member-list API.
29. New tables follow the messages pattern: forced row level security, `SELECT` only for what `app_open_conversation` allows, no general write grant for `app_runtime`, writes through the security-definer functions.

### Client

30. A group row is `ConversationKind::Group`. It is in the Inbox and in People. It is not a row under TEXT CHANNELS on the Tiny rail. `in_the_server` already keeps only channels.
31. With `groups` in capabilities, a member starts a group from an open direct: Add people, pick at least one more member, `POST /v1/groups` with the direct's other person plus those ids. The direct stays. Its messages are not copied. New message of one person stays `POST /v1/directs`.
32. An empty name is shown as the other members' display names in join order, the first two, then `+N` for the rest. Never the viewer's name. Never the word "Chat". A missing display name is "Someone". The avatar uses the existing two-face fallback. The header subtitle is the people count and those names.
33. Unread on an unmuted group with `mentions` stored as 0 is the count pill. `badge_look` already does that. This feature does not add mention parsing. Muted stays the existing bell, with a mention pill only if `mentions > 0`. A member who just joined shows no unread badge until a later message from someone else.
34. Leave uses the existing confirm ("Leave {name} on Tiny?" / "You'll stop getting its messages. To come back, someone in it has to add you.") and then succeeds. Today Tiny `Command::Leave` returns unsupported.
35. The desktop chip is "End-to-end encrypted" or "Not end-to-end encrypted", with the existing tooltips, including "the server can read this conversation." The phone strip is "Encrypted" or "Server can read". A row that will not open says "Can't be decrypted on this device" and never the server's `body`. The late-join sentence stays "Messages from before you joined can't be read." Do not invent an upgrade sentence. Do not relabel pre-upgrade plaintext as encrypted.

## Contract

### Tables

`groups`: `id uuid` primary key default `gen_random_uuid()`, `name text not null default ''` with a check of 0 or 1 to 80, `e2ee boolean not null default false`, `created_by uuid not null` references `users`, `client_id text null` check 1 to 64 when set, `created_at timestamptz not null default now()`. Unique `(created_by, client_id)` where `client_id` is not null.

`group_members`: primary key `(group_id, user_id)`, `joined_at timestamptz not null default now()`, both foreign keys. `user_id` references `users`. Deleting a community membership must also delete these rows. A foreign key to `memberships(user_id)` is the right tool if the delete paths all remove that row. Account deletion must still remove the group rows if it removes the user without that path. The builder picks the mechanism. Kick, ban, and account deletion are all covered. Timeout is not.

`messages.group_id` nullable, foreign key to `groups` on delete cascade. The existing XOR check becomes exactly one of the three parents. `messages_e2ee_client` includes the group id in the coalesce.

`reads.kind` check adds `group`.

`reports.group_id` nullable, foreign key, no member-list column.

`e2ee` on the group is the same one-way flag as on a channel. `app_conv_e2ee`, `app_e2ee_upgrade`, and the forget path learn the third table. Deleting a group deletes its `e2ee_groups` row the way deleting a channel does.

The next migration number is the highest existing file plus one (0041 today). This checkout has no `0017`–`0019` or `0026`–`0029`. Do not reuse a missing number.

### HTTP

| Route | Who | Result |
|---|---|---|
| `GET /v1/groups` | member | Groups the caller is in. Not the whole community. |
| `POST /v1/groups` | member, not banned. A timeout does not block create | `201`, or `200` on `client_id` replay while the creator is still a member. `404` if they are not |
| `GET /v1/groups/{id}` | current member | One group. Else `404` |
| `PATCH /v1/groups/{id}` | current member | Name. Audited `group.rename` |
| `POST /v1/groups/{id}/members` | current member | `{user_id}` → `201`, or `200` if already in |
| `DELETE /v1/groups/{id}/members/me` | current member | `204`. Last member deletes the group |

A timed-out member may create and add and leave. They may not post, react, or type. That matches a timeout on a channel: read stays, speak stops.

Posts, edits, deletes, reactions, history, and read cursors stay on `/v1/conversations/{id}/...`. The opener must know the third kind or those routes `404`.

Operator reads follow whatever policy `GET /v1/directs` has. Operator writes follow `POST /v1/directs`, which a read-only operator cannot call.

### JSON

A group object:

```json
{
  "id": "…",
  "name": "",
  "e2ee": false,
  "created_by": "…",
  "created_at": "…",
  "members": [{"user_id": "…", "display_name": "…", "joined_at": "…"}],
  "unread": 0,
  "last_read": null,
  "last_message": null
}
```

`members` is every current member, including the caller, in join order. On create, the caller is first, then `user_ids` in the order given. `last_message` matches a channel: `{id, author_id, body, created_at}` with `body` cut at 200 characters, or null. On an encrypted group the preview body is empty. There is no `peer` and no `peer_read`. `unread` follows criterion 14.

### Live events

| Topic | Payload | Audience |
|---|---|---|
| `group.created` | the group object | current members |
| `group.updated` | `{id, name}` | current members |
| `group.member_added` | `{id, user_id, members}` | current members, including the new one |
| `group.member_left` | `{id, user_id}` | remaining members and the person who left |
| `group.deleted` | `{id}` | the last member only |

Message topics stay `message.created`, `message.edited`, `message.deleted`, and `reaction.updated`, with the same payload as a direct, and the audience is the current member ids. A group id in the payload must not make `app_scope_audience` treat a null audience as a channel. Callers pass the member array.

### Encryption label

The server already exposes `e2ee` on the conversation. The client already maps that flag to the chip and the phone strip. A group sets the same flag. No new copy.

The settings sentence already says the server still sees who is in a conversation, when messages are sent, and how large they are. A group does not change that. Do not write a warning that says the member list is hidden.

## What stays unchanged

- `POST /v1/directs` for an existing pair and `e2ee` flag still returns `200` and the same id. A pair can still have one plaintext direct and one encrypted direct. A twin upgrade is still `409 e2ee_twin`.
- Channel create still needs global `manage_channels` (512). Overrides still need `manage_roles`, the channel bit, the mask `246399`, and a distinct hierarchy error.
- A member denied `view_channel` on a channel still gets `404` and still misses that channel's events when the channel is restricted.
- Direct message events still go only to the two user ids.
- `read.updated` is still emitted only for a direct.
- Bots still have no `memberships` row and still do not see `message.*` on `GET /v1/live`.
- Under `e2ee_text = required`, a new plaintext channel or direct is still refused.

## Calls made here

These were not in a written product request. They are decided in this document so a builder does not guess.

| Call | Why |
|---|---|
| New kind, not a wider direct and not a private channel | Approaches 2 and 3 break the wire or the owner rule |
| No member cap. Floor of 3, because two people are a direct | A cap of 50 was rejected. Size follows the community and, for an encrypted group, the existing device cap (`e2ee_group_devices_max`, default 2000, max 20000). Plaintext has no size check |
| Any member may add. No peer kick | Same shape as a direct. Community kick, ban, and reports already exist. G2.22 requires kick, ban, and account deletion to cut ciphertext |
| Plaintext history is visible to a later member | G2.1. Encrypted history is not. The two are different on purpose |
| No group read receipts | G3.9's channel rule. Extending `peer_read` would be a new fan-out |
| Audit stores actor and group id, not the other member | Otherwise `view_audit_log` rebuilds the set. A direct create does not write that |
| Start from a direct, and keep the direct | Moving history would either copy plaintext or pretend encrypted history transferred |
| A `client_id` replay by someone who left is `404`, and does not return members | Criterion 11. Returning the group would leak the set. Keeping the key stops a second group. A deleted group has no key left, so the same string may create a new one |
| A person who is added starts at `unread` 0, cursor on the latest message | A badge of the whole history counts ciphertext they cannot decrypt. Scrollback still follows criterion 15 |
| Client work is part of this feature | A server route nobody can start is the gap the Tiny column already has for text channels |

## Left to the builder

- Function bodies, index names, and whether membership removal is a trigger or a call inside kick, ban, and account deletion, as long as all three happen before MLS reconcile and timeout does not.
- The exact Add control, as long as it starts from an open direct, posts the ids above, leaves the direct in place, and does not show up when `groups` is missing from capabilities.
- How `joined_at` is displayed. Join order is the title order. The screen does not need to show the timestamp.

## Not verified during the design

No migration was applied and no test suite was run. The criteria cite the schema and docs on this checkout: messages through `0034_e2ee_upgrade.sql`, `docs/privacy/guarantees.md` G2.1, G2.8, G2.22, G3.9, and section 7, `docs/e2ee-text.md` sections 4, 8, and 9, and the Tiny adapter's `WireDirect` decode. Published `main` was not compared commit for commit.
