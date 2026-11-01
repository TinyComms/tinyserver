# First-run setup: what the community keeps

A new server has an owner and nobody else. Before anyone is invited, the owner decides what the
community keeps about its members. That is **setup**: three choices, a preset that makes all three
at once, and one record of when the owner made them.

Nothing here is a banner or a promise. Each choice is enforced where the data is made or read, and
each has a test that fails when it stops holding (section 7).

## 1. When it appears

`GET /v1/setup` returns `"needed": true` until an owner has applied setup once. A client shows
the owner the choices the first time they sign in, and again from its settings whenever the owner
wants to change them. Nobody but an owner can read or change them. An admin with every permission
is not an owner here, on purpose: these choices say what the community keeps about everyone in it.

**An existing community is not changed by upgrading.** The defaults are exactly what the server
did before setup existed. The owner is asked once, and "keep what I have" (`PUT /v1/setup` with
`{}`) is a complete answer.

Setup is not a gate. The server does not stop the owner inviting people before they answer, because
that would break a community that is already running. What members see about themselves does not
depend on the owner having answered: every member can read the choices that are in force from
`GET /v1/server` (`provider_profile`, `activity_visibility`, `sign_in_methods`,
`setup_completed_at`).

## 2. The three choices

### What to keep from a sign-in provider (`provider_profile`)

Applies when someone **first** joins through single sign-on (an OpenID Connect provider such as
Pocket ID). It decides what the new account starts with.

| Value | A new account keeps |
| --- | --- |
| `full` (the default) | the name and the email address the provider gives. People who manage the server can read members' email addresses |
| `name` | the name, never an email address, and never the start of one used as a name |
| `none` | neither. The account starts as "Member" and the person chooses a name |

It does not reach accounts that already exist, and a person signing in again is not changed by
it. Removing addresses already held is a separate, explicit request (section 4). It does not reach
an account made with a passkey: there is no provider, and the name is the one the person typed.

If this deployment has no single sign-on, the choice has nothing to act on, and `GET /v1/setup`
marks it `"relevant": false` so a client can say so.

### Who sees when members were last online (`activity_visibility`)

| Value | Effect |
| --- | --- |
| `everyone` (the default) | every member sees `last_seen_at` and `joined_via` (invite or group) for every member |
| `admins` | only holders of `manage_server` see them. Everyone else gets `null` |
| `nobody` | the server **stops recording** `last_seen_at` and clears what it had. `joined_via` is shown to no one |

`nobody` is a real change to what is stored, not only to what is shown: the live connection no
longer writes last-seen, and the values already written are set to null in the same transaction
that records the choice. `joined_via` is still stored (it says how a membership began, and an
owner or operator can still query it in the database); it is not returned by the API.

Presence while someone is connected, and whether they are in a call, are live state and are not
affected by this choice.

### How members sign in (`sign_in_methods`)

| Value | Effect |
| --- | --- |
| `any` (the default) | every method this deployment offers |
| `passkey` | a sign-in through a provider is refused, and the passkey page stops offering one |

`passkey` closes the provider door for **new sign-ins**. Sessions already open carry on until they
expire or the person signs out. Passkeys already made keep working. A provider that has just
vouched for someone, part-way through signing in when the owner chose, is turned away with
`error=passkey_only`, and the invite they carried is not spent.

It is refused, with a reason the owner can act on, unless:

- **This deployment has passkeys** (`TINYSERVER_AUTH=both` or `passkey`): `409 passkeys_unavailable`.
- **The owner has a passkey themself**: `409 owner_needs_passkey`. Without one the owner would be
  locked out at their next sign-in. The owner adds one with a claim link, as any member does.
- **Every member has a passkey, or the owner says they can wait**: `409 members_without_passkey`
  with `count`. People with only a provider account cannot sign in until the owner gives them a
  claim link (`docs/auth-passkeys.md`). `allow_lockout: true` accepts that.

Starting the server without passkeys while `passkey` is chosen (a rollback to `TINYSERVER_AUTH=oidc`)
does **not** lock everyone out: with no passkeys to honour the choice, the server ignores it and
providers work as before. The choice is still stored, and applies again when passkeys come back.

## 3. The two presets

A preset is a starting point. The owner may still change any one choice after picking one, in the
same request.

| | `provider_profile` | `activity_visibility` | `sign_in_methods` |
| --- | --- | --- | --- |
| **Convenience** | `full` | `everyone` | `any` |
| **Privacy** | `none` | `nobody` | `passkey` |

**Convenience** is how the server worked before there was a setup. **Privacy** keeps the least the
server can keep and still work. The server describes both, and every option, in plain words in
the `GET /v1/setup` response, so a client shows what the server will really do and has no copy of
its own to keep in step.

On a deployment without passkeys, privacy is marked `"available": false` with the reason.
`{"preset": "privacy", "sign_in_methods": "any"}` takes the rest of it: a named choice overrides the
preset.

## 4. What setup can erase

Two requests are one-way, and neither happens unless asked for or implied by the choice.

- `"erase_emails": true` removes the email address of every member, owner included. It is a
  separate request because choosing `name` or `none` is about new accounts, and quietly deleting
  what people have on file is not what that sentence says. The response says how many were erased.
- `activity_visibility: nobody` clears every `last_seen_at`. The response says how many.

Both are one transaction with the choice: if the choice is refused, nothing is erased.

## 5. What setup does not do

Said plainly, because a privacy page that leaves things out is worse than none.

- **There are no usernames.** A member has a display name, which is not unique and is not an
  address, and signs in with a passkey or a provider account. Setup does not add handles, and the
  server does not require or collect an email. Email exists only if a provider sent one and the
  owner chose `full`.
- **It does not turn message encryption on or off.** What the server can read of messages and
  files is described in `docs/privacy/` and `docs/e2ee-text.md`; it does not depend on these
  choices.
- **It does not change what the audit log, an invite, a ban or the operator can see.** The audit
  log names actors by id, and `setup.apply` records the choices and counts, never an address or a
  name.
- **It does not remove data already in backups, the write-ahead log, or a provider's own records.**
  `erase_emails` and `nobody` change rows in the live database.
- **It does not change who can be invited or who can manage the server.** Those are permissions.
- **It does not make anyone anonymous to the owner.** The owner knows whom they invited.

## 6. The API a client builds on

Capabilities advertise it: `GET /v1/capabilities` lists `first_run_setup`. A client that gets no
such feature talks to a server without setup and shows nothing.

### `GET /v1/setup`

Owners only (`403 forbidden` for anyone else, `401` without a session).

```json
{
  "needed": true,
  "completed_at": null,
  "current": {"provider_profile": "full", "activity_visibility": "everyone", "sign_in_methods": "any"},
  "deployment": {"passkeys": true, "sso": false},
  "counts": {"members": 1, "members_without_passkey": 1, "emails_stored": 1, "owner_has_passkey": false},
  "presets": [
    {"id": "convenience", "title": "...", "summary": "...", "choices": {...}, "available": true},
    {"id": "privacy", "title": "...", "summary": "...", "choices": {...}, "available": true, "unavailable": null}
  ],
  "choices": [
    {"id": "provider_profile", "title": "...", "question": "...", "relevant": false,
     "options": [{"id": "full", "title": "...", "effect": "..."}]}
  ],
  "always": ["There are no usernames. ...", "The server sends no analytics or crash reports anywhere."]
}
```

`needed` is true until `completed_at` is set. `deployment` is what the server was started with.
`counts` is what a choice would touch, so the page can say "3 members have no passkey yet" before
the owner chooses. An option's `needs` lists what it depends on (`passkeys`, `owner_has_passkey`).
`relevant: false` means the choice has nothing to act on in this deployment; show it dimmed.

### `PUT /v1/setup`

Owners only. Every field is optional.

```json
{
  "preset": "privacy",
  "provider_profile": "name",
  "activity_visibility": "admins",
  "sign_in_methods": "any",
  "erase_emails": false,
  "allow_lockout": false
}
```

A preset sets all three choices, then any named choice overrides it. `{}` keeps everything as it
is and marks setup done. An unknown preset, value or field is `400 invalid`, and nothing is
applied. The reply:

```json
{"settings": { ...the whole GET /v1/server object... }, "emails_erased": 0, "last_seen_cleared": 0}
```

Refusals are `409` with `error` one of `passkeys_unavailable`, `owner_needs_passkey`,
`members_without_passkey` (plus `count`). A refusal changes nothing, including setup's "done".

Applying is audited `setup.apply` (the choices, the two counts, `allow_lockout`; never a name or an
address) and emits `server.updated`, so every connected client learns the new choices. The same
route changes the choices later; `setup_completed_at` keeps the first time.

While the operator has suspended the community read-only or offline, this write is refused with
everything else that writes.

## 7. What is tested

`crates/api/tests/setup.rs` and, where passkeys are involved, `crates/api/tests/passkey.rs`:

- a new server says setup is needed, offers every option with a sentence of effect, and lists
  `first_run_setup` in its capabilities;
- only an owner may read or change the choices (a member and an admin with every permission are
  refused; no session is `401`), and a refused attempt writes nothing and audits nothing;
- `{}` finishes setup and changes no choice; the first completion time stays the first;
- an unknown choice, preset or field is refused and does not finish setup;
- privacy on a deployment with no passkeys is refused whole, and `sign_in_methods: any` alongside
  it takes the rest;
- what a provider may leave: full, name only (and never the start of an email as a name), nothing,
  and none of it reaches existing accounts or a returning sign-in; a name typed for a passkey is
  untouched;
- `erase_emails` removes every address once, counts them, and the audit row holds neither a name
  nor an address; choosing `none` alone erases nothing;
- last-seen: visible to everyone, then to admins only, then recorded by no one (and cleared), and
  recorded again when everyone is chosen;
- passkeys only: refused while the owner has no passkey, refused with a count while members have
  none, accepted with `allow_lockout`, existing sessions keep working, passkey sign-in works,
  a claim link gets a member in;
- passkeys only turns a provider away at the callback without spending the invite or making an
  account, the passkey page stops offering the provider, and `start` opens the passkey page even
  when the provider is named;
- the choice does not lock anyone out when the server is started without passkeys;
- setup is audited and emits `server.updated`.

Not tested: a client. tinyclient does not yet show these choices (see the client section of the
pull request), so today an owner reaches setup through the API.
