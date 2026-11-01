# Passkey sign-in

tinyserver can sign people in with passkeys by itself, so a community does not need a separate identity provider. This document says what that is, what it stores, what it cannot do, how to turn it on, and how to move a community that signs in through Pocket ID without losing anyone's account.

Status: implemented and tested against a real Postgres with a software authenticator (section 10 lists exactly what is and is not covered). **The sign-in pages have not been run in a real browser by the people who wrote them.** Do that on your own domain before you move anyone (section 8, step 3).

## 1. What it is

A passkey is a key pair made on a person's device. The device keeps the private half; the server keeps the public half and a counter. Signing in is the device signing a fresh challenge from the server. There is no password to steal or reuse.

tinyserver treats a passkey as one more source of a person's identity, next to OpenID Connect. The identity is the pair `(issuer, subject)`: for a passkey the issuer is `tinyserver:passkey` and the subject is a random 128-bit account id made at sign-up. Invites, bans, roles, sessions, the owner bootstrap and account deletion are the code that already ran for OIDC. Only the proof of "this is that person" is new.

The library that does the WebAuthn work is `webauthn-rs` (0.6.2, pinned, RustCrypto underneath, no OpenSSL). tinyserver does not implement WebAuthn or any cryptography.

## 2. Modes

`TINYSERVER_AUTH` decides how people sign in.

| Value | What happens |
|---|---|
| `oidc` (default, and what an unset value means) | Exactly as before. No passkey route exists. |
| `both` | `POST /v1/auth/start` returns the passkey page. It offers "Sign in with Pocket ID instead", so members who have not moved yet still get in. A client that names the provider (`"provider": "default"`) goes straight to it, as before. |
| `passkey` | Passkeys only. No identity provider is contacted or needed. |

`TINYSERVER_AUTH` is what this deployment *can* do. What the community *accepts* is the owner's choice at [first-run setup](server-setup.md): "passkeys only" there turns a provider sign-in away (and the passkey page stops offering one) while the deployment still runs providers. With `TINYSERVER_AUTH=oidc` there are no passkeys to honour it, so it is ignored and providers work.

tinyclient needs no change to sign in. It never picks a provider: it calls `/v1/auth/start`, opens the `authorize_url` it gets in the system browser, and listens on `127.0.0.1` for the one-time code, which the passkey page sends exactly as the OIDC callback does. (`GET /v1/auth/config` lists `passkey` as a provider and still says `"methods": ["oidc"]`, so an older client does not meet a value it does not know.)

Other settings:

| Variable | Meaning |
|---|---|
| `TINYSERVER_PUBLIC_URL` | Required in every mode. The passkey page and the claim links are served from it. |
| `TINYSERVER_PASSKEY_RP_NAME` | The name a browser shows when it asks for a passkey. Default `TinyComms`. |
| `TINYSERVER_PASSKEY_RP_ID` | The relying party id. Unset means the host of `TINYSERVER_PUBLIC_URL`. See section 6. |
| `TINYSERVER_SESSION_MAX_DAYS` | How long a session lasts. Existing sessions are not touched by switching modes. |

## 3. What is stored, and what is not

For each passkey: its credential id, the public key and counter (inside the library's own serialisation), whether the platform may sync it, a label the person gave it (default "Passkey"), when it was made and when it was last used.

For each account: the display name typed at sign-up, a random subject, and the account's recovery codes as hashes.

Not stored by this module, in any table or log: an IP address, a user agent, an email, a phone number, an attestation statement, or a device model. A test reads the passkey tables' column names and fails if one names any of those. (A member who signed up through Pocket ID may have an email on their account from before; `auth export-members` shows it so the operator can deliver a claim link. Passkey sign-up never asks for one.)

Short-lived rows: a ceremony in progress (the library's challenge state) lives 5 minutes and is deleted the moment it is used or expires. A one-time claim link lives as long as the operator chose, and is kept only as a SHA-256 hash.

Every one of these tables is reached only through `SECURITY DEFINER` functions. The runtime role has no grant on them, and row-level security is forced with no policy, so a grant added by mistake would still show nothing. A test checks all of that.

What the server does see, as with any login: when a sign-in happens and which account it is (`user_id` in the info log, as with OIDC), and the connection's address for as long as the connection lasts, plus whatever sits in front of it (see `docs/privacy/network.md`).

## 4. The flows

All pages are served by tinyserver itself, with one fixed inline script that loads nothing and talks only to this server. The page's content security policy names that script by its hash, allows no other script, no framing, no form posts. No third-party request is made.

**Sign in.** The page asks the browser for a passkey with no username: the browser offers the passkeys it holds for this site and the account's user handle comes back with the signature. The server checks the signature, the challenge, the origin and the counter. A challenge works once.

**Sign up.** Needs an invite, exactly as OIDC does. The person types the name others will see, makes a passkey, and is shown 10 recovery codes before they continue. The account, the invite, the passkey and the codes are written together or not at all, so a failed attempt spends nothing.

**Lost passkeys.** A recovery code (25 characters, 125 bits, any case, dashes optional) lets a person make a new passkey and sign in. The code is used up at that moment. Two tries at one code let one in.

**More than one device.** Each device or synced passkey store is one more passkey on the same account. A signed-in person (who signed in within the last 10 minutes) asks for a link with `POST /v1/me/passkeys/link`; opening it on the other device makes a passkey there. The link is good for an hour and works once. **tinyclient has no screen for this yet**; until it does, the owner issues a claim link (section 8) for a second device the same way.

**Managing them.** `GET /v1/me/passkeys` lists them, `PATCH` renames, `DELETE` removes (the last one only while a recovery code is left), `POST /v1/me/recovery-codes` replaces the set. Removing, replacing codes and making a link need a sign-in within the last 10 minutes, so a stolen old session cannot plant a passkey of its own.

**A passkey that looks copied.** A valid signature with a counter that did not go up is refused and the passkey is turned off until its owner removes it. Many passkeys (those that sync) keep the counter at 0 and are not subject to this.

## 5. When everything is lost

An account has passkeys and recovery codes. If a person loses every passkey and every recovery code, **the account cannot be signed in to again**. The server holds nothing that proves who they are: no email, no phone, no identity document, and that is the point. An owner can invite them again as a new account. Their old messages stay attached to the old account.

The sign-up screen says this in plain words next to the codes. Tell your members before they depend on it.

Signing back in on a new device does not bring back message history for end-to-end encrypted conversations: those keys belong to devices and are separate from signing in.

### Where the pages live

The sign-in and claim pages are served by the community's own tinyserver, at `TINYSERVER_PUBLIC_URL`, through the same tunnel as everything else on that hostname. No port is forwarded, and no second hostname is needed now that Pocket ID is gone. They are not part of `tinyclient.io`: the invite link there is only a launcher that opens the app, and a passkey is bound to the exact site that made it (section 6), so a page on another site could never make or use one for this server.

Each page shows the server's own name and icon, with a small TinyServer mark, so a person can see which community they are signing in to. The server's name and icon are otherwise members-only, so the pages show them only to someone who holds a live sign-in (started from Tiny) or a claim link the owner made. A visitor who only knows the address, or has an expired state, is shown nothing about it. The icon travels inside the page as an image (`img-src data:`), never fetched from anywhere.

## 6. The relying party: do not change it later

A passkey works only for the relying party id it was made for. By default that is the host of `TINYSERVER_PUBLIC_URL`, for example `chat.example.org`. If the community later moves to another host, **every passkey stops working**, and everyone needs a recovery code or a new claim link.

If you may ever move a community between subdomains, set `TINYSERVER_PASSKEY_RP_ID` to the domain above them (`example.org`) **before anyone makes a passkey**. Passkeys then work from any host under that domain. The cost: any site under that domain can ask the browser for these passkeys, so a taken-over subdomain becomes a place to phish them. The default, the exact host, is the safer choice. The setting must be the host itself or a registrable domain above it; anything else stops the server starting.

Pocket ID's passkeys are made for Pocket ID's own host (for example `auth.example.org`), so **they cannot be reused**. Everyone makes a new one for the chat host. That is why the move below uses claim links.

## 7. What an operator can and cannot do

An operator with database access can mint sessions for any account, read who is a member, and delete or ban anyone. Passkeys do not defend against the operator of the server; nothing that signs people in to a server can. What they do give is that no one else, including whoever hosts the database, learns a secret that lets them sign in as a member, and that a leaked database does not hand over passwords.

TinyCloud, the managed host, is in the same position as any operator. See `docs/privacy/threat-model.md`.

## 8. Moving a community from Pocket ID

Keep a plain rule in mind: **a member's account does not change.** They keep their user id, display name, roles, messages and end-to-end device keys. The move adds a passkey identity to the same account. Pocket ID's identity stays until you remove it.

The steps are for the compose deployment in `deploy/` (as run on the Cloudzy host). `HOST` stands for that machine; every `docker compose` command runs in the directory that holds `compose.yml` and `.env`. Nothing here touches a host by itself: you run each step and check it.

Until step 7 the move can be undone by setting `TINYSERVER_AUTH=oidc` again.

### Before you start

- Tell members what is coming, and what a recovery code is.
- Check `docker compose version` is 2.24.4 or later (step 7 needs `!override`).
- Decide the relying party (section 6) now, in `.env`, if you want one other than the exact host.
- Pick a date. A member's current session keeps working after the move, for up to `TINYSERVER_SESSION_MAX_DAYS` (30 by default). When it ends they sign in with a passkey, so they need their link before then.

### Steps

1. **Back up, and check the backup.** On HOST:

   ```
   umask 077
   docker compose exec -T postgres pg_dump -U postgres -d tinyserver -Fc > tinyserver-before-passkeys.dump
   test -s tinyserver-before-passkeys.dump && docker compose exec -T postgres pg_restore --list < tinyserver-before-passkeys.dump | head
   docker run --rm -v tinyserver_tinyserver_uploads:/data:ro -v "$PWD":/out alpine tar -C /data -czf /out/uploads-before-passkeys.tgz .
   ```

   Copy both files off the machine, to somewhere only you can read. (The volume name is `<project>_tinyserver_uploads`; `docker volume ls` shows it.)

2. **Update, staying on Pocket ID.** Pull and rebuild the release that has passkeys and run `docker compose up -d`. Leave `TINYSERVER_AUTH` unset. The migrations (0030 passkeys, 0031 setup) are applied by `tinyserver-init`. Nothing about sign-in changes, and the owner is not yet asked to choose anything: `GET /v1/setup` says `needed` and the defaults are what the server did before. Check that a member can still sign in.

3. **Try passkeys yourself.** Set `TINYSERVER_AUTH=both` in `.env` and run `docker compose up -d tinyserver`. Open tinyclient and start a sign-in: the browser now shows the passkey page with "Sign in with Pocket ID instead". Use a claim link for your own account (step 5), sign in with the passkey, and try it in every browser your members use, on both a phone and a computer. This is the check that has not been done for you.

4. **Export the roster, before Pocket ID is gone.** Make a directory only the server's user can write, and run the CLI as the owner role through the init service (it holds the owner database password; the serving container does not):

   ```
   install -d -m 700 -o 10001 -g 10001 ./auth-out
   docker compose run --rm --no-deps -v "$PWD/auth-out:/out" \
     --entrypoint tinyserver tinyserver-init auth export-members --out /out/members.tsv
   ```

   `members.tsv` lists each member: id, name, the email Pocket ID gave (if any), role, joined, last seen, how many passkeys, whether they are banned, what signs them in, and the provider's own name for them (`identities`, as `issuer subject`). It exists so that, after Pocket ID is gone, you still know who is who, and so a retired identity can be put back.

5. **Make claim links.**

   ```
   docker compose run --rm --no-deps -v "$PWD/auth-out:/out" \
     --entrypoint tinyserver tinyserver-init auth claim-links --all-unclaimed --days 14 --out /out/claims.tsv
   ```

   For one person: `--user <id>` instead of `--all-unclaimed`. A new link for a person replaces their old one. Each link works once, for that member only, and expires. **The tokens are in the file only**: the log gets a count. The files are mode 0600 and are never overwritten.

   Send each person only their own link, by a way you trust (Signal, email, in person). The link carries its token after a `#`, which a browser never sends anywhere, so it is not in any server or proxy log. Anyone who holds an unused link can set up a passkey on that account, so treat a link like a password reset.

   Then move the files off HOST and delete them there:

   ```
   sudo chown "$USER" auth-out/*.tsv && mv auth-out/*.tsv /secure/place/ && rmdir auth-out
   ```

6. **Watch progress.** `docker compose run --rm --no-deps --entrypoint tinyserver tinyserver-init auth status` says how many members have a passkey and lists who does not. Re-issue links as needed (step 5). The owner sees the same count as `members_without_passkey` in `GET /v1/setup`.

7. **Cut over, when you are ready.** Take a fresh backup (step 1). Optionally remove the Pocket ID identities of members who have a passkey and a recovery code, so a compromised Pocket ID can no longer sign them in:

   ```
   docker compose run --rm --no-deps --entrypoint tinyserver tinyserver-init auth retire-oidc-identities          # says what it would do
   docker compose run --rm --no-deps --entrypoint tinyserver tinyserver-init auth retire-oidc-identities --apply
   ```

   Members who have no passkey keep their identity and can still sign in through Pocket ID until you remove it. Then switch to passkeys only and stop Pocket ID:

   ```
   docker compose -f compose.yml -f compose.passkey.yml up -d
   ```

   Keep `AUTH_PUBLIC_URL` in `.env`: compose reads it before the override applies, and it is unused in this mode. Pocket ID's volume is left in place. After you are sure you will not go back, remove the auth hostname from the tunnel in Cloudflare.

   Then the owner makes the community's own choices in the app ([`server-setup.md`](server-setup.md)): what to keep, who sees last-online, and, if Pocket ID is still running in `both`, whether to accept passkeys only. The privacy preset can be chosen here, once the owner has a passkey; it asks for `allow_lockout` if any member has not claimed one yet.

8. **Check.** Sign in with a passkey. Make an invite and sign up a test account with it. Check `auth status`.

9. **Members who have not claimed.** They stay members but cannot sign in once their session ends and Pocket ID is gone. Mint each a link (step 5, `--user`). Since there is no provider to confirm who is asking, give a link only to someone you know is that member.

### Going back

- Before step 7: `TINYSERVER_AUTH=oidc` in `.env`, `docker compose up -d tinyserver`. Passkeys already made stay stored and are unused. If the owner had chosen "passkeys only" in setup, that choice is kept but not applied without passkeys, so no one is locked out.
- After step 7, with Pocket ID's volume intact: `TINYSERVER_AUTH=both docker compose -f compose.yml up -d`. Members whose Pocket ID identity was retired need it back. The `identities` column of `members.tsv` (and the `retire-oidc-identities` listing) has each one's subject: `tinyserver relink-identity --user-id <id> --issuer <issuer> --subject <subject>` per member.
- Last resort: restore the dump from step 1. Everything after it, including passkeys made since, is lost.

### What the move does not do

- It does not carry Pocket ID passkeys over. They are bound to Pocket ID's host and cannot be exported.
- It does not email anyone. tinyserver sends no email; delivering links is yours.
- It does not make members use passkeys on a particular device type.

## 9. Operating notes

- **Rate limits.** The sign-in routes allow 30 posts a minute per address; recovery codes and claim links allow 8. The address is the connection's, or the header your proxy sets (Cloudflare's by default, `TINYSERVER_CLIENT_IP_HEADER` otherwise) only from a trusted proxy (`docs/privacy/network.md`), kept as a keyed hash in memory for a minute.
- **Logs.** Never a token, challenge, credential id, recovery code, claim link, invite or name from tinyserver's own code. A test runs a sign-up, sign-in, recovery and claim with a trace-level subscriber and fails if any secret it generated appears. One thing it found: `webauthn-rs`'s core crate traces each whole registration, credential id included, at TRACE. tinyserver's log policy holds that crate at warn whatever the operator asks for (a unit test checks it), and its warnings and errors carry only fixed text, lengths and flag values. The info log has `user_id` for sign-in events, as it has for OIDC.
- **Deletion.** `DELETE /v1/me` removes the account's passkeys, recovery codes, claim links and any ceremony in progress. A ban stays on the account.
- **Audit.** Adding, removing and flagging a passkey, replacing codes, using a code, claiming, and the operator's claim links and retiring of identities are written to the audit log, with the account but no address.

## 10. What is tested, and what is not

Tested (`crates/api/tests/passkey.rs`, `crates/db/src/passkey.rs`, `crates/api/src/passkey.rs`, and the compose files) against a real Postgres and the library's software authenticator:

- sign-up with an invite, and the account, role, identity and absence of email it makes; sign-in with no username; a challenge working once; a ceremony begun for one sign-in refused for another
- a registration made for another origin refused, and nothing created; an invite that is used up or missing refused, and nothing spent
- a counter that goes back flags the passkey and it stays refused; another account's passkey with a borrowed user handle refused
- recovery codes: stored as hashes only, case and dashes ignored, single use, two tries letting one in, a new set replacing the old
- the last passkey kept unless a recovery code remains; an old session refused for removing, replacing codes and making a link
- claim links: hash-only storage, single use, expiry, wrong or mismatched token, replacement by a newer link, a banned member getting none, a ban holding after the Pocket ID identity is retired, the account (id, name, email, creation time) unchanged and both identities kept
- retiring identities: dry run changes nothing; members without a passkey are skipped; it is audited; the roster is right
- a second device through a self-made link; account deletion removing everything; the tables holding no address, agent, email or phone, closed to the runtime role with row-level security forced; the migration's functions closed to the world
- the pages' policy names exactly their script; `oidc` mode has no passkey routes; `both` offers the provider and still honours a named provider; rate limits
- compose: `docker compose config` accepts the default file (Pocket ID is still a service) and the passkey variant (no Pocket ID service, secret or OIDC variable; the owner database password only in `tinyserver-init`). These were validated, not started: no stack was brought up
- the owner's first-run setup where it meets passkeys: passkeys only refused until the owner has a passkey and members are counted or knowingly left out, a provider turned away without spending its invite, the passkey page no longer offering one, and the choice not applied when the server runs without passkeys (see [`server-setup.md`](server-setup.md) section 7)
- the operator commands, as the real binary against a scratch database seeded like a Pocket ID community: `auth status`, `export-members`, `claim-links` (links only in the file, none in output, log or database; a banned member refused; an existing file never overwritten; bad arguments refused) and `retire-oidc-identities` (nothing to do while nobody has a passkey)
- logs: a trace-level capture of a sign-up, sign-in, recovery and claim finds none of the secrets they made; the server's log policy is checked to hold the WebAuthn crates at warn
- the existing sign-in suites (auth, http, limit, account, privacy, rules, server, signup_logs) and all unit tests still pass, so the default `oidc` mode is unchanged

Not covered, and what that means:

- **A real browser.** The script that runs in the page (`crates/api/src/passkey.js`) is unit-checked only for what it must not contain. The software authenticator stands in for the browser's WebAuthn calls and does not return a user handle, so the tests supply it. Test every browser you support on your own domain.
- **Hardware keys and platform quirks** (resident-key behaviour, Android credential managers). The server asks for a discoverable credential; whether a particular authenticator makes one is the authenticator's decision.
- **The whole move on a copy of your real data.** The sequence is tested end to end on seeded data, not against yours. Rehearse it on a restored backup.
- **Independent security review.** This is new authentication code. The WebAuthn verification is the library's; the handling around it (ceremony state, hand-back to tinyclient, recovery, claim links, session recency) is ours and should be reviewed before the service is described as secure to customers.
- **The Windows file-mode check** for the operator's output files runs only on Unix.
