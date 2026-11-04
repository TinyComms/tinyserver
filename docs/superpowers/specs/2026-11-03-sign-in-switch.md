# Sign-in as one switch the owner holds

Date: 2026-11-03. Repos: tinyserver and tinyclient. Branch `feat/sign-in-switch` in each.

## The problem

Sign-in today is decided in two places that have to agree:

- `TINYSERVER_AUTH` on the box (`oidc` / `both` / `passkey`), which needs a shell and a restart,
  and decides whether the passkey routes exist at all.
- `sign_in_methods` in the owner's first-run setup (`any` / `passkey`), which only works once the
  env var already says passkeys.

So the first-run screen shows a Privacy preset the owner cannot pick, with a paragraph telling
them to ask whoever runs the server. For a self-hosted community that is the same person, in the
wrong window. Moving to passkeys is a nine-step shell runbook, and going back is another one.

## What this builds

1. **Passkeys are always on.** The server always serves the passkey page, the claim pages and the
   ceremonies. `TINYSERVER_AUTH` is gone. `TINYSERVER_PUBLIC_URL`, already required, is the relying
   party. The only deployment-level fact left is whether a provider is configured
   (`TINYSERVER_OIDC_ISSUER` or `TINYSERVER_OIDC_PROVIDERS` set).

2. **One three-way choice, in the client, taking effect at once:**

   | `sign_in_methods` | Title in the client | `POST /v1/auth/start` | Who can get in |
   |---|---|---|---|
   | `provider` | Through \<provider\> only | the provider's authorize URL | provider accounts |
   | `any` | Passkeys, or through \<provider\> | the passkey page, with "Sign in with \<provider\> instead" | both |
   | `passkey` | Passkeys only | the passkey page, no provider link | passkeys |

   On a deployment with no provider configured the stored value is irrelevant and the effect is
   always `passkey`. The choice is marked `relevant: false` there.

   Existing servers keep behaving as they do: migration `0033` moves every stored `any` to
   `provider` (today `any` with the env var unset *is* provider-only) and makes `provider` the
   column default. Convenience = `provider`; Privacy = `passkey`; `any` is the migration window
   the owner reaches by customising.

3. **Switching is a checklist, not a refusal.** Moving *to* `passkey` still needs the owner to
   have a passkey, and either every member to have one or `allow_lockout`. Moving *to* `provider`
   gets the mirror guards: the owner has a provider identity, and every member has one or
   `allow_lockout`. `passkeys_unavailable` is gone. `GET /v1/setup` now says enough for a client
   to draw the steps before the owner commits:

   - `counts.owner_has_passkey`, `counts.owner_has_provider`
   - `counts.members_without_passkey`, `counts.members_without_provider`
   - `members: [{user_id, display_name, passkey: bool, provider: bool}]`, every member other
     than you and banned members

4. **The owner hands out claim links from the client.** `POST /v1/setup/claim-links`, owner-only,
   `{"user_ids": [...], "days": 14}` → `{"links": [{"user_id", "display_name", "url"}]}`. One link
   per member, replacing any they had, 1–90 days, audited as `passkey.claim_link` with the owner
   as actor. The client shows them once with Copy per row and Copy all; it never stores them.

5. **Members manage their own passkeys in the client.** Server Settings › Sign-in gets a Passkeys
   section: the list (label, made, last used, synced, flagged), Add (opens the claim page in the
   browser, as "Add a passkey for me" does today), Rename, Remove (not the last one without a
   recovery code left), and New recovery codes (shown once). All on routes that already exist.

6. **The first-run screen and the Privacy page.** Both presets are always selectable. The sign-in
   choice shows three options; under the picked one, when it is not what the server has, a
   checklist: *You have a passkey* ✓/✗ with "Add a passkey for me"; *N of M members have a
   passkey* with "Send passkey links…"; the Apply button, or "Switch anyway" (Danger) when members
   would be locked out. The same shape for `provider` with the provider words.

## What does not change

- The passkey ceremonies, the claim and recovery flows, the pages and their CSP, the RP rules.
- Open sessions carry on through any switch. Passkeys already made keep working.
- A provider that vouched for someone mid-flight when the owner chose `passkey` is turned away
  with `error=passkey_only` and the invite is not spent. The same now happens for a passkey
  ceremony begun under `any` when the owner switches to `provider`: `login/begin` and
  `signup/begin` refuse with `400 {"error":"passkeys_off"}`. Claim and recover always work.
- The CLI (`auth status`, `export-members`, `claim-links`, `retire-oidc-identities`,
  `relink-identity`) stays for operators without a client at hand.
- `GET /v1/setup` keeps sending `deployment.passkeys: true` so an older client still offers
  Privacy. `GET /v1/auth/config` keeps `"methods": ["oidc"]`.
- No usernames. Nothing about `provider_profile` or `activity_visibility`.

## Compatibility

- **Old client, new server:** sees three options for `sign_in_methods`; `tiny_setup::sign_in_words`
  shows `UNKNOWN` for `provider` on the member page, and the owner form lists the option by the
  server's words. Nothing breaks. New refusals `owner_needs_provider` / `members_without_provider`
  reach it as the generic "could not" error, since `setup_refusal` does not know them.
- **New client, old server:** `deployment.passkeys` may be false; `blocked()` keeps its
  "started without passkey sign-in" reason; the checklist draws from the counts it has and
  `members` is empty. `/v1/setup/claim-links` and the passkey list give 404 → the client's `OLDER`
  words.

## Deployment

- `deploy/compose.yml` drops `TINYSERVER_AUTH`. `compose.passkey.yml` keeps its `!override`
  environment, which drops the OIDC variables, and loses only `TINYSERVER_AUTH`.
- `docs/auth-passkeys.md` §2 Modes is replaced by the table above; §8's runbook becomes: back up,
  update, add your own passkey from Server Settings › Sign-in, switch to *Passkeys, or through
  Pocket ID*, send links from Server Settings › Privacy, watch the counts there, switch to
  *Passkeys only*, then (optional, shell) retire Pocket ID identities and remove the container.
  Going back is the same switch the other way; `relink-identity` stays for after a retire.

## Open choices made here

- Three stored values rather than a separate "passkeys on" boolean: one column, one choice, one
  row in the audit log.
- `members` in `GET /v1/setup` is unbounded. Owner-only, and Tiny servers are small; the client
  already bounds what it keeps.
- Claim links are read from the API as secrets and shown once; the server never lists them.
- The old `TINYSERVER_AUTH` value is ignored with a warning in the log, not an error, so an old
  `.env` still starts.
