# Authentication, identity and account lifecycle

How a person proves who they are to a tinyserver community, what identifying data that creates, what can and cannot be recovered, and how identity relates to billing. Sources: `docs/server.md` ("Sign-in"), `deploy/README.md`, `deploy/compose.yml`, `crates/api/src/{auth,oidc,account,session}.rs`, `crates/db/src/auth.rs`, migrations `0001`, `0004`, `0006`, `0014`, and the tests named. Status words are in [`README.md`](README.md).

## 1. The model in six lines

1. tinyserver is an OpenID Connect (OIDC) relying party, not an authorization server. It has **no password column and no password sign-in**: `0004_oidc.sql` drops `users.password_hash`.
2. A person is the pair **(issuer, subject)** from a verified ID token (`user_identities`, primary key `(issuer, subject)`). The same person at two issuers is two accounts; email never links accounts. Test: `two_providers_make_two_identities_for_one_subject`.
3. In the compose deployment the issuer is **Pocket ID**, where people sign in with **passkeys** only. A passkey's private key stays on the person's authenticator.
4. Signing in proves identity to the server. It **never grants decryption**: call keys live in the apps, and text keys live on devices (the server holds only public device keys, #23; the client keeps them sealed under a key in the OS keychain, tinyclient #127).
5. A session is 32 random bytes, stored only as a SHA-256 hash, valid for `TINYSERVER_SESSION_MAX_DAYS` (default 30, range 1 to 365), never extended by use, not bound to a device or an address.
6. Membership is separate from having an account at the provider: a person also needs an invite, or an IdP group the owner has allowed.

## 2. The sign-in protocol, as implemented

| Property | Implementation | Evidence |
|---|---|---|
| Authorization code flow with PKCE S256 on both legs | The client's challenge, and the server's own verifier toward the provider | `start_takes_only_a_loopback_callback_and_s256` |
| Redirect to the client | Only `http://127.0.0.1:<port>/callback` or `http://[::1]:<port>/callback`, exact match | same |
| `state`, `nonce` | 16 to 128 unreserved characters for the client state; the server's own state and nonce toward the provider, stored 10 minutes | `an_expired_spent_or_unknown_state_gets_a_page_and_no_redirect` |
| RFC 9207 `iss` check on the callback | Present | Found by reading `auth.rs`; `docs/privacy/findings.md` "Not findings" |
| ID token validation | Algorithms RS256, ES256 or EdDSA, signature by a key in the provider's key set, `iss` exact, `aud` this client and nothing untrusted, `azp`, `exp`, `iat` near now, `nonce`. An unknown key id makes the server re-read the key set, at most every 10 seconds | `a_bad_id_token_or_provider_error_fails_the_sign_in`, `a_new_signing_key_is_read_once_when_a_token_names_it`, `discovery_needs_the_exact_issuer_and_a_reachable_provider` |
| One-time code to session | 60 second life, spent on the first try, right or wrong; stored as a hash | `a_one_time_code_works_once_with_the_right_verifier_inside_a_minute` |
| Client authentication to the provider | `client_secret_basic`, `client_secret_post`, or `private_key_jwt`, whichever discovery offers | `the_client_authenticates_the_way_the_provider_offers` |
| Redirects from the provider are never followed by the server's HTTP client | `redirect::Policy::none()` so client credentials cannot be sent elsewhere | Read, `oidc.rs` |
| No refresh token, no userinfo call | Profile claims come from the ID token only (`name`, `preferred_username`, `email`, `sid`, groups) | Read; `grep` finds no userinfo request |
| Rate limit | Five tries a minute per address on `start` and `token`, three on `join` | `a_sixth_try_in_a_minute_is_told_to_slow_down` |

Everything the server ever learns about a person from the provider is: `iss`, `sub`, optional `email`, optional name, optional `sid`, and groups (used only for joining and admin promotion, never stored). The access token is not used after the code exchange.

## 3. What identifying information exists, and where

| Datum | tinyserver | Pocket ID | Notes |
|---|---|---|---|
| Subject (`sub`) | `user_identities.subject`, plaintext. Pocket ID's `sub` is the person's Pocket ID user id | The user id | Instance-specific (section 8) |
| Username | Becomes `display_name` through `preferred_username` only when `name` is blank | Required at sign-up | Can be a pseudonym |
| Name | `display_name`: `name`, else `preferred_username`, else the email's local part, else "Member". Editable (`PATCH /v1/me`) | First and last name; may be blank (`tinyserver` copes with an empty name, commit "Use the username when the provider sends a blank name") | |
| Email | `users.email`, **at account creation only** (no `UPDATE users` sets it later), if the ID token has an address-shaped one. Visible to the person and to `manage_server` holders | Optional (`REQUIRE_USER_EMAIL=false`), never marked verified (`EMAILS_VERIFIED=false`). No SMTP is configured | Test: `a_member_sees_their_own_email_and_not_another_members` |
| Passkey | Never | Public key and credential id | |
| Client IP address | Never stored | In Pocket ID's audit log, 90 days by default (unverified for the pinned version) | [`metadata.md`](metadata.md) section 12 |
| Group membership | Not stored. Read from the token each sign-in | Yes | `TINYSERVER_OIDC_MEMBER_GROUPS`, `TINYSERVER_OIDC_ADMIN_GROUPS` |

### Username-only operation

The compose deployment already allows it: email is optional and sign-up is by token with a username and a passkey. For tinyserver never to see an email, the OIDC scope must not include `email`. The default is `openid profile email` (`TINYSERVER_OIDC_SCOPES`); `deploy/compose.yml` does not pass that variable through, so a tenant stack that wants `openid profile` needs the compose file to set it. With no `email` claim, `users.email` is null and the display name falls back to `preferred_username` or "Member". **Not tested**: no test sets the scopes to exclude `email` and checks the stored row. Pocket ID itself may still hold an email a person typed into their profile (`ALLOW_OWN_ACCOUNT_EDIT=true`); whether Pocket ID offers a setting to refuse the field was not verified.

An email is also still useful to a community: a moderator with `manage_server` sees it, which is one way to tell two "Alex" apart. A community that wants anonymity inside it should decide that on purpose.

## 4. Joining

| Route in | Requires | Records |
|---|---|---|
| Invite | A usable invite token (`POST /v1/invites`, shown once, stored as a hash), with an account at the provider (or "I'm new here", which makes one) | `invite.accept` audit row with the invite id and label; `joined_via = invite` |
| IdP group | `TINYSERVER_OIDC_MEMBER_GROUPS` set and the person in one. An admin group makes them admin. **Never owner** | `member.join` with `via groups`; `joined_via = groups` |
| Owner | The first owner joins by an owner invite from `tinyserver bootstrap`; later owners are set by an owner | `bootstrap` audit row |

A known member, not banned, signs in without the invite. A ban holds every `(issuer, subject)` the person used (`ban_identities`), so a new invite, a group claim and a fresh sign-in are all refused (`a_ban_removes_the_person_and_keeps_them_out`). Nothing is written for a person turned away (`someone_without_an_invite_is_not_a_member_and_nothing_is_kept`).

The invite for the sign-up case makes a **single-use, 15 minute Pocket ID sign-up token** through the Pocket ID API, and only while the invite is still usable. tinyserver therefore holds a key that can create Pocket ID accounts (`secrets/pocketid_api_key`); the log never contains it (`the_api_key_and_signup_tokens_never_reach_the_logs`).

## 5. Passkeys, multiple devices, sessions

| Topic | Behaviour |
|---|---|
| Passkeys | Held by the person's authenticator or password manager. Whether a passkey syncs between devices is the authenticator's decision, not tinyserver's or Pocket ID's |
| Several devices | Each sign-in on each device is its own session (its own token). A person can have up to three live sockets; a fourth closes the oldest with `4008 replaced` (`a_fourth_socket_closes_the_oldest`) |
| E2EE devices (server #23; client tinyclient #126, #127) | Each install is a device with its own id and signing key. A later device must carry a cross-signature from an active one, and the server refuses it otherwise (`e2ee_text.rs` `a_later_device_needs_a_cross_signature_from_an_active_one`); the account holder can revoke a device from any session (`a_revoked_device_is_removed_and_gets_nothing_more`). The client checks the chain itself (tinyclient `the_first_device_is_trusted_on_first_use_and_the_rest_must_chain_to_it`) and approves a new device by a pasted link code. The first device is trust on first use, and a new person can be admitted by the server until G3 and G4 are done (`e2ee-text.md` sections 3 and 8) |
| Call identity (implemented) | One P-256 identity key per account per install, a plaintext file (finding C4). A second install has a different key, shown to others as a changed key |
| Ending one session | `DELETE /v1/session`. Test: `an_owner_reads_me_and_signs_out` |
| Ending all of a person's sessions | `DELETE /v1/sessions` (audited `session.close_all`); sockets close on the next recheck. Test: `a_member_changes_a_name_and_signs_out_everywhere` |
| Provider-initiated logout | Back-channel logout at `POST /v1/auth/backchannel-logout`, by `sid` or by `sub`. Pocket ID sends `sub` only. Test: `back_channel_logout_ends_the_sessions_the_provider_names`; `sign_out_and_a_provider_logout_close_other_sockets` |
| Kick or ban | Sessions deleted; sockets close with `4003`; the person's call ends. Tests: `a_removed_member_is_closed_with_4003`, `a_timeout_and_a_ban_end_calls_and_a_ban_closes_sockets` |
| Expiry | Fixed from the moment of sign-in. Test: `a_session_from_sign_in_ends_after_the_configured_days` |
| Stolen token | Usable until it expires or is revoked: the token is not bound to an address or device. A person must sign out everywhere |
| Revoking someone else's session | An operator or owner can delete rows; an owner can kick or ban; there is no "list my sessions" API, so a person cannot see which sessions exist |

## 6. Recovery

Passkey-only sign-in moves recovery out of tinyserver and into two other places: the person's authenticator, and the Pocket ID administrator. Each option below says what it recovers and what it costs in identifying information.

| Situation | What recovers it | What is needed | What is not recovered |
|---|---|---|---|
| Lost one device; the passkey also exists on another device or a synced password manager | Sign in with the other passkey | Nothing | Per-device data on the lost device (see E2EE below) |
| Lost every passkey; the person uses a synced passkey provider | The provider's own recovery | Whatever that provider requires (their identity, not TinyCloud's) | |
| Lost every passkey, no sync | A Pocket ID administrator makes a **one-time login link** (`${AUTH_PUBLIC_URL}/lc/<token>`, valid an hour; `deploy/pocket-id/setup.sh` does it for the first admin) and the person adds a new passkey | The administrator must decide the requester is the account holder. **Nothing in the stack authenticates that**: no email, no security question. A recovery path controlled by an administrator is also an impersonation path for that administrator | |
| Email recovery | **Not enabled**: no SMTP, and Pocket ID's email-based one-time access is off by default | Would require an email on the account, an SMTP relay (a new outbound path and a new party that sees the email), and trust that the mailbox is the person's. Also lets anyone with the mailbox sign in, as Pocket ID's documentation says | |
| Recovery code or secondary credential | Not offered by tinyserver. Whether Pocket ID offers one for this version was not checked | | |

**Cannot be recovered without a recovery credential or identifying information:** the Pocket ID account (so every tinyserver account that depends on it); with text E2EE the keys and therefore the readable history on lost devices. Specified behaviour: a person who has lost every device and starts again appears to other members as a **new identity**, loudly; key backup is a non-goal of v1 (the client shows a recovery key but nothing is backed up under it, tinyclient `docs/e2ee-text-client.md`); a new device reads nothing from before it was added (`e2ee-text.md` sections 3, 4, 8). For calls, a new install means a new identity key and members who verified the old one see a changed key.

**The privacy trade:** the more recoverable an account is, the more its recovery path can be abused. Which policy TinyCloud offers (administrator-issued links, community-owner issued links, or none) is an open decision, listed in section 10.

## 7. Account deletion

`DELETE /v1/me` with `{"confirm": "delete my account"}`. Implemented by `app_delete_account()` in migration `0014`. A sole owner is refused with `409 last_owner`. What it removes and what it cannot reach is in [`retention-and-deletion.md`](retention-and-deletion.md). Test: `deleting_an_account_removes_the_person_and_what_they_said`.

It removes the tinyserver data only. **It does not delete the Pocket ID account** (the passkeys, username, optional email, and audit events stay): no code in `oidc.rs` or `account.rs` calls a provider delete endpoint, and Pocket ID's administrator must remove the user. If the same person signs in again at the same provider they sign in as a stranger: with no invite they are `not_member`, and an invite makes a new tinyserver account (a new user id) at the same `(issuer, subject)`.

A ban survives deletion on purpose: `ban_identities` keeps the `(issuer, subject)` pair.

## 8. Cross-community correlation

| Layer | Can two communities link a person? |
|---|---|
| tinyserver | **No.** One database per community, no shared identity store. The user id is a random UUID per community. Nothing is sent between servers |
| Pocket ID in the compose design | One Pocket ID per community stack, so the `sub` differs per community and so does the passkey credential. A person has a separate account in each. For tenants on one host, `deploy/tenant/tenant.sh new` gives each its own Pocket ID container, data volume, encryption key and API key, and `deploy/tests/isolation.sh` checks no tenant's compose configuration contains another's secrets ([`tenancy.md`](tenancy.md)) |
| A shared Pocket ID, or an external IdP such as Google used as the provider in several communities | **Possibly.** If the provider issues the same `sub` to every relying party, the two communities hold the same subject for one person and could compare. Not verified for any particular provider |
| The same email, display name or avatar in two communities | Yes, by the person's own choice of data |
| Cloudflare, the hosting provider, TinyCloud | Whoever sees the person's IP address, an invite link, or a TinyCloud account holding two tenants can link communities. A TinyCloud control plane that holds `tenant -> payer` links the payer's tenants |
| Invite links | The owner invite and member invites point at `tinyclient.io/invite#...`, which names the server origin in the URL fragment (not sent to the site) |

## 9. Keeping billing and legal identity apart from membership

This is a design constraint for the TinyCloud control plane (billing, provisioning, payer accounts), which is not in this repository. `deploy/tenant/tenant.sh` makes a tenant from a name and URLs and stores no payer data. What the repository supports and what it requires:

1. **Two identity systems.** A payer's account (billing, whatever KYC or sanctions step applies; see [`compliance.md`](compliance.md)) must not share an identifier with a community member's `(issuer, subject)`, email or display name. The tenant's Pocket ID and the billing system should not be able to be joined by value.
2. **What TinyCloud necessarily knows.** Which payer owns which tenant (to provision and to bill) and the tenant's hostnames and ports. This is category 5 in [`guarantees.md`](guarantees.md). It is not hidden by any property of tinyserver.
3. **The first owner.** The owner invite is generated by `tinyserver bootstrap` and lands in `/bootstrap/owner-invite`. The person who accepts it is the owner. If TinyCloud staff handle that file they can accept it first. A provisioning flow that hands the invite to the payer without anyone accepting it in between is a requirement, not an existing behaviour. Accepting it needs a Pocket ID account, whose admin (TinyCloud or the owner) is another decision.
4. **Who administers Pocket ID.** The static admin API key lets its holder create accounts and mint login links for anyone. If TinyCloud holds it, TinyCloud can sign in as any member (threat model 3.7). If only the community owner holds it, TinyCloud staff with host access still can read the secrets file (`tenants/<name>/secrets/pocketid_api_key` for a tenant). The key, with Pocket ID's data, is in every `operator.sh backup` and `export` bundle, so whoever can open a backup can also sign in as any member of the restored copy. The honest statement is that the host operator can always do it; the choice is whether to add operational controls.
5. **Support requests.** If a person asks TinyCloud to prove they own an account, the proof must not require more identifying information than the account itself holds.

## 10. Open questions

| Question | Type |
|---|---|
| Does `TINYSERVER_OIDC_SCOPES=openid profile` produce a clean no-email account end to end? | Engineering. Needs a test |
| Which Pocket ID fields and logs record IPs, user agents or geolocation in `v2.19.1`, and how to shorten retention | Engineering. Not verified |
| Can the Pocket ID account be deleted together with the tinyserver account, and by whom | Engineering requirement: the deletion flow should call Pocket ID's API or document the manual step |
| Who holds the Pocket ID admin credential in a managed tenant, and what recovery policy applies | Product and security decision |
| Offer a recovery credential (a printed code, a second passkey prompt) so recovery needs no administrator | Product decision. Not built |
| A "my sessions" list so a person can revoke one device | Not built |
| Whether TinyCloud may act on a request to recover an account without identifying the requester | Question for counsel |
