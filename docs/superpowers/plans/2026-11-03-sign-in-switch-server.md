# Sign-in switch, server side: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Passkey routes are always mounted, `TINYSERVER_AUTH` is gone, and `sign_in_methods` becomes a three-way owner choice (`provider` / `any` / `passkey`) that takes effect at once, with the counts, member list and claim links a client needs to walk the owner through a switch.

**Architecture:** One migration (`0033`) widens the column, replaces `app_setup_state` and `app_setup_apply`, and adds `app_setup_members` and `app_setup_claim_link`. The api crate loses `AuthMode` and `Option<Passkeys>`; `auth::start`/`config`/`callback` and the passkey ceremonies branch on `effective(posture, sign_in)`. `setup.rs` grows the counts, the member list, two new 409s and `POST /v1/setup/claim-links`.

**Tech Stack:** Rust, axum, sqlx, PostgreSQL (plpgsql SECURITY DEFINER functions), webauthn-rs.

**Spec:** `docs/superpowers/specs/2026-11-03-sign-in-switch.md`

**Worktree:** `C:\Users\gollum\Development\Personal\tiny\_wt-signin-server`, branch `feat/sign-in-switch` off `origin/main` (f15df55). Tests need Docker: `docker start hardening-pg` on Zeppelin, `TEST_DATABASE_URL` as `CONTRIBUTING.md` says; without it the DB tests silently skip, so check the test count.

## Global Constraints

- Stored values of `sign_in_methods`: exactly `provider`, `any`, `passkey`. Column default `provider`.
- `GET /v1/setup` keeps `deployment.passkeys` and it is always `true`. `GET /v1/auth/config` keeps `"methods": ["oidc"]`.
- Error bodies are `{"error": "<snake_case>"}` plus named fields, as today. New ones: `owner_needs_provider`, `members_without_provider` (with `count`), `passkeys_off`.
- Claim links: 1–90 days, default 14; the token is in the URL fragment; the server never lists them.
- Audit action for an owner-made link stays `passkey.claim_link`, now with `actor_id` = the owner.
- No new env vars. An old `TINYSERVER_AUTH` logs one `warn!` and is otherwise ignored.
- Copy in server JSON is the server's own words, plain English, no "SSO" (say "a sign-in provider" or the provider's name).

## Review Focus

1. A server with no provider configured and a stored `provider` value (fresh DB default): start must give the passkey page, not a 500 from `provider(None)` being `None`. Pinned in Task 4.
2. A member whose only identity is a passkey when the owner switches back to `provider`: the mirror guard must count them, and `allow_lockout` must be needed. Pinned in Task 2.
3. A banned member must not be counted in `members_without_*` nor get a claim link. Pinned in Tasks 2 and 5.
4. A passkey ceremony that began under `any` and finishes after the owner picked `provider`: `login/finish` must not sign them in. Pinned in Task 4.
5. An old `.env` with `TINYSERVER_AUTH=passkey` and no OIDC vars: the server must still start, as passkey-only. Pinned in Task 3.

---

### Task 1: Migration 0033 — the column, the state, the apply

**Files:**
- Create: `crates/db/migrations/0033_sign_in_switch.sql`
- Modify: `crates/db/src/setup.rs` (`SignInMethods`, `Posture`, `SetupState`, `SetupChange`, `SetupError`, `classify`, `apply_setup`, `setup_state`)
- Test: `crates/db/src/setup.rs` unit tests (parse/as_str), `crates/api/tests/setup.rs`

**Interfaces:**
- Produces: `SignInMethods::{Provider, Any, Passkey}` with `as_str` → `"provider" | "any" | "passkey"` and `parse`. `Posture::CONVENIENCE.sign_in_methods == Provider`. `SetupState { …, members_without_provider: i32, owner_has_provider: bool }`. `SetupError::{OwnerNeedsProvider, MembersWithoutProvider(i32)}` and no `PasskeysUnavailable`. `pub async fn apply_setup(pool, caller, change) -> Result<Applied, SetupError>` (no `passkeys_available`).

- [ ] **Step 1: Write the migration**

`0033_sign_in_switch.sql`, in this order:
1. `ALTER TABLE server_settings DROP CONSTRAINT <the 0031 check name>` (find it with `\d server_settings` or name it in 0031 if unnamed; `pg_get_constraintdef` in a DO block is acceptable), `ADD CHECK (sign_in_methods IN ('provider','any','passkey'))`, `ALTER COLUMN sign_in_methods SET DEFAULT 'provider'`.
2. `UPDATE server_settings SET sign_in_methods = 'provider' WHERE sign_in_methods = 'any';` with a comment: today `any` with no passkeys was provider-only, so this changes nothing anyone sees.
3. `CREATE OR REPLACE FUNCTION app_setup_state()` returning the 0031 columns plus `members_without_provider integer` and `owner_has_provider boolean`. "Has provider" = `EXISTS (SELECT 1 FROM user_identities i WHERE i.user_id = … AND i.issuer <> 'tinyserver:passkey')`. Both `members_without_*` counts exclude banned members (`NOT app_banned(m.user_id)`), which also changes `members_without_passkey` from 0031; say so in the comment.
4. `DROP FUNCTION app_setup_apply(text,text,text,boolean,boolean,boolean)` and `CREATE FUNCTION app_setup_apply(p_provider_profile text, p_activity_visibility text, p_sign_in_methods text, p_erase_emails boolean, p_allow_lockout boolean)`. Body as 0031 minus the `passkeys_unavailable` branch, plus a mirror branch: when `v_sign_in = 'provider' AND p_sign_in_methods IS NOT NULL AND stored <> 'provider'`: `owner_needs_provider` if the owner has no non-passkey identity; `members_without_provider:<n>` when `n > 0 AND NOT p_allow_lockout`. Use the same exclusion of banned members as step 3.
5. Grants: revoke from PUBLIC, grant to `app_runtime`, for both replaced functions (copy the 0031 DO block shape).

- [ ] **Step 2: Update `crates/db/src/setup.rs`**

Add `Provider` to `SignInMethods` (first variant), `as_str`/`parse`; `CONVENIENCE` uses `Provider`. Remove `PasskeysUnavailable` from `SetupError`; add `OwnerNeedsProvider` and `MembersWithoutProvider(i32)`; `classify` maps the two new messages the way the existing `members_without_passkey:<n>` is parsed. Add the two fields to `SetupState` and read them in `setup_state`. Drop the `passkeys_available` parameter from `apply_setup` and the sixth bind. Fix the stale doc comment at lines 9–10 (enforcement is in `api::auth`, not `auth::sign_in_in`).

- [ ] **Step 3: Fix the compile fallout in `crates/api/src/setup.rs` minimally**

Only what is needed to build: remove `SetupFailure::PasskeysUnavailable` and the `deployment.passkeys` argument to `apply_setup`. Task 5 reshapes the rest.

- [ ] **Step 4: Update the api tests that pin the old world**

In `crates/api/tests/setup.rs`:
- Delete `the_privacy_preset_is_refused_where_there_are_no_passkeys_unless_that_one_choice_is_left_out`.
- `keeping_what_you_have_finishes_setup_and_changes_nothing`: expect `sign_in_methods: "provider"` in the setup reply and in `GET /v1/server`.
- `a_server_that_has_not_been_set_up_says_so_and_offers_what_it_would_do`: expect `presets[1].available == true` and no `unavailable` string (temporary until Task 5 sets the final shape; keep the assertion on `deployment.passkeys == true`).

In `crates/api/tests/passkey.rs`:
- Delete `the_choice_does_not_lock_everyone_out_when_the_server_is_started_without_passkeys`.

- [ ] **Step 5: Run**

Run: `cargo test -p db` and `cargo test -p api --test setup`
Expected: PASS; the setup suite shows a non-zero count (the DB is reachable).

- [ ] **Step 6: Commit**

```bash
git add crates/db/migrations/0033_sign_in_switch.sql crates/db/src/setup.rs crates/api/src/setup.rs crates/api/tests/setup.rs crates/api/tests/passkey.rs
git commit -m "Widen sign_in_methods to provider|any|passkey and drop the passkeys-unavailable refusal"
```

---

### Task 2: The mirror guards, tested end to end

**Do this task after Task 3**: it needs Task 3's `sign_in_with` helper. Task 1 → Task 3 → Task 2 → Task 4 is the order.

**Files:**
- Test: `crates/api/tests/setup.rs`
- Modify: `crates/api/src/setup.rs` (`SetupFailure`, two arms)

**Interfaces:**
- Consumes: Task 1's `apply_setup` and errors; Task 3's `sign_in_with`, `attach_passkey` (moved to `tests/common`). The api maps `OwnerNeedsProvider` → `409 {"error":"owner_needs_provider"}`, `MembersWithoutProvider(n)` → `409 {"error":"members_without_provider","count":n}`.

- [ ] **Step 1: Write the failing test**

`going_back_to_a_provider_waits_for_the_owner_and_members_to_have_one` in `tests/setup.rs`, with a provider-plus-passkeys `SignIn`:
- The first account is made by passkey sign-up with the bootstrap invite, so the owner has no provider identity. Owner `PUT {"sign_in_methods":"any"}` → 200.
- Member Bo joins by passkey sign-up with an invite (no provider identity). Member Cy joins the same way and is then banned by the owner.
- Owner `PUT {"sign_in_methods":"provider"}` → `409 {"error":"owner_needs_provider"}`.
- Owner signs in once through the mock provider with the same session's account linked (use the provider mock's `sign_in()` with the owner's existing subject so the identity is attached, as `two_providers_make_two_identities_for_one_subject` in `tests/auth.rs` does). `PUT provider` → `409 {"error":"members_without_provider","count":1}`: Bo counts, Cy (banned) does not.
- `PUT {"sign_in_methods":"provider","allow_lockout":true}` → 200; `GET /v1/server` says `provider`.
- Bo's open session still works (`GET /v1/me` → 200).

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p api --test setup going_back`
Expected: FAIL: the 409 bodies are not produced.

- [ ] **Step 3: Make it pass** — only the `SetupFailure` arms if Task 1 did the SQL right.

- [ ] **Step 4: Run**: `cargo test -p api --test setup` → PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/api/src/setup.rs crates/api/tests/setup.rs crates/api/tests/common
git commit -m "Refuse a switch back to the provider that would lock the owner or members out"
```

---

### Task 3: Passkeys always on; `TINYSERVER_AUTH` gone

**Files:**
- Modify: `crates/server/src/main.rs:449-536` (`sign_in`, delete `AuthMode`)
- Modify: `crates/api/src/oidc.rs:221-232, 369-470` (`Shared.passkeys: Passkeys`, `SignInConfig`, `discover`, `passkey_only`, delete `with_passkeys`, `passkeys() -> &Passkeys`)
- Modify: `crates/api/src/auth.rs:35-48` (always merge passkey routes), `:534-548` doc comment
- Modify: `crates/api/src/passkey.rs:273-275` (delete `enabled`, its ten call sites use `sign_in.passkeys()`)
- Modify: `crates/api/src/setup.rs:26-40` (`Deployment::of` → `passkeys: true`)
- Modify: `crates/api/src/lib.rs` if `router`/`app` signatures change (they should not)
- Modify: `deploy/compose.yml:92-95`, `deploy/compose.passkey.yml:9-13, 30-36`, `deploy/README.md:180`
- Test: `crates/api/tests/passkey.rs`, `crates/api/tests/auth.rs`, `crates/api/tests/setup.rs`

**Interfaces:**
- Produces: `pub struct SignInConfig { public_url, session_days, providers: Vec<ProviderConfig>, passkeys: Passkeys }`; `SignIn::discover(config)`; `SignIn::passkey_only(public_url, session_days, passkeys)`; `pub(crate) fn passkeys(&self) -> &Passkeys`; `pub(crate) fn has_providers(&self) -> bool`.
- Test helper, `tests/common/mod.rs`: `pub fn passkeys() -> api::Passkeys` (`"https://tiny.test"`, `"Test"`, `None`) and `pub async fn sign_in_with(provider: Option<&Provider>) -> api::SignIn` (`Some` → discover with `.passkeys`, `None` → `passkey_only`). Every test file uses these; `tests/setup.rs` `app()` now passes `Some(sign_in_with(None))`.

- [ ] **Step 1: Write the failing tests**

In `tests/passkey.rs`:
- Rename `without_passkeys_turned_on_there_are_no_passkey_routes` → `the_passkey_routes_are_always_there_and_provider_only_sends_start_to_the_provider`. With a provider configured and the default stored `provider`: `GET /v1/auth/config` lists `providers == [{"id":"default",…}]` only; `POST /v1/auth/start` with no `provider` returns the issuer's authorize URL; `POST /v1/auth/passkey/claim/peek` with a bad token returns **400 `invalid_link`** (not 404); `GET /v1/auth/passkey?state=x` returns 400 or 404 for an unknown state, as it does in passkey-only today, not a route miss. Also `attach_passkey` for an owner succeeds while stored is `provider` (claim works in every mode).
- Rename `both_modes_open_the_passkey_page_and_still_offer_the_provider` → `any_opens_the_passkey_page_and_still_offers_the_provider`; it must first `PUT /v1/setup {"sign_in_methods":"any"}` as owner.
- `config_offers_the_passkey_and_start_opens_its_page` (passkey-only deployment): unchanged, but also assert it holds while the stored value is the default `provider`, i.e. no provider configured means passkeys regardless (Review Focus 1).

In `tests/auth.rs`: `the_config_names_the_providers` keeps its exact JSON (stored default `provider` hides the passkey entry).

In `crates/server/src/main.rs` unit tests (if there is a test module; else skip): `TINYSERVER_AUTH` set to anything does not fail startup config parsing.

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p api --test passkey the_passkey_routes_are_always_there`
Expected: FAIL with 404s.

- [ ] **Step 3: Implement**

- `oidc.rs`: `Shared.passkeys: Passkeys`; `SignInConfig.passkeys`; `discover` keeps "no providers is a ConfigError"; delete `with_passkeys`; `provider_name()` returns `"Passkey"` only when `!has_providers()`, else the first provider's name (the client shows this on the Sign-in page; a provider deployment keeps its provider's name).
- `auth.rs:43-46`: unconditional merge. Update the comment.
- `passkey.rs`: delete `enabled`; `let passkeys = sign_in.passkeys();` at each site.
- `main.rs`: delete `AuthMode`. `sign_in()`: always build `Passkeys::new(...)`; `let providers = if providers_configured() { providers_from_env()? } else { Vec::new() }` where `providers_configured()` is `env_var("TINYSERVER_OIDC_ISSUER").is_ok() || env_var("TINYSERVER_OIDC_PROVIDERS").is_ok()`; empty → `passkey_only`, else `discover` with retries as today. At the top: `if env_var("TINYSERVER_AUTH").is_ok() { tracing::warn!("TINYSERVER_AUTH is no longer read: passkeys are always on, and the owner chooses how members sign in from the client") }`.
- `setup.rs`: `Deployment::of(sign_in)` → `passkeys: true`, `sso: sign_in.map_or(false, |s| s.has_providers())`.
- `deploy/compose.yml`: delete the `TINYSERVER_AUTH` line and the mode comment; add a comment that passkeys are always on and belong to the host of `TINYSERVER_PUBLIC_URL`. `compose.passkey.yml`: delete `TINYSERVER_AUTH: passkey` and its "going back" comment; keep the `!override` environment otherwise (it still drops the OIDC secrets, which is what makes the deployment provider-less). Rename nothing. `README.md:180`: "if you have retired Pocket ID".

- [ ] **Step 4: Run the whole api and server suites**

Run: `cargo test -p api` and `cargo build -p server`
Expected: PASS. `rg TINYSERVER_AUTH crates deploy` → only the `warn!` line.

- [ ] **Step 5: Commit**

```bash
git add crates deploy
git commit -m "Always serve passkeys; drop TINYSERVER_AUTH"
```

---

### Task 4: `start`, `config`, and the ceremonies follow the stored choice

**Files:**
- Modify: `crates/api/src/auth.rs:135-259` (`config`, `start`), `:534-548` (`passkey_only` → `effective`)
- Modify: `crates/api/src/passkey.rs` (`login_begin` ~488, `signup_begin` ~592, `login_finish`, `signup_finish`: refuse when effective is `Provider`)
- Test: `crates/api/tests/passkey.rs`

**Interfaces:**
- Produces: `pub(crate) async fn effective(pool: &PgPool, sign_in: &SignIn) -> Result<db::SignInMethods, AuthApiError>` in `auth.rs`: `Passkey` when `!sign_in.has_providers()`, else the stored value. Used by `start`, `callback` (`== Passkey` replaces `passkey_only`), `config`, and the four passkey handlers.

- [ ] **Step 1: Write the failing tests** in `tests/passkey.rs`

- `switching_to_the_provider_only_turns_a_passkey_ceremony_away_and_keeps_the_claim_and_recovery_pages`: with a provider, owner sets `any`; a member begins `login/begin` (gets options); owner sets `provider` (with `allow_lockout` if needed); `login/finish` → `400 {"error":"passkeys_off"}`, no session made; `signup/begin` → `400 passkeys_off`; `claim/peek` with a real token → 200; `recover/begin` with a valid state and code → still 200.
- Extend `config_offers_the_passkey…`: with a provider and stored `any`, `providers == [{"id":"passkey",…},{"id":"default",…}]`; with stored `provider`, only `default`; with stored `passkey`, only `passkey`.
- Extend `passkeys_only_turns_a_provider_away…`: unchanged assertions; it already covers `effective == Passkey` in the callback.

- [ ] **Step 2: Run to verify they fail**: `cargo test -p api --test passkey switching_to_the_provider_only` → FAIL.

- [ ] **Step 3: Implement**

- `start`: `let effective = effective(&pool, &sign_in).await?;` then `passkey_page = matches!(effective, Any | Passkey) && (effective == Passkey || body.provider is None or "passkey")`. Provider selection: `Passkey` → none; `Any` with page → `provider(None)`; otherwise `provider(body.provider)`; in `Provider` mode a `"provider":"passkey"` is a `400 bad_request` like any unknown id.
- `config`: list the passkey entry only when `effective != Provider`.
- `passkey.rs`: in `login_begin`, `login_finish`, `signup_begin`, `signup_finish`: `if effective(&pool, &sign_in).await.map_err(failed)? == db::SignInMethods::Provider { return Err(bad("passkeys_off")); }` before any DB write.

- [ ] **Step 4: Run**: `cargo test -p api` → PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/api/src/auth.rs crates/api/src/passkey.rs crates/api/tests/passkey.rs
git commit -m "Start, config and the passkey ceremonies follow the owner's sign-in choice"
```

---

### Task 5: `GET /v1/setup` says enough to draw the checklist; `POST /v1/setup/claim-links`

**Files:**
- Modify: `crates/db/migrations/0033_sign_in_switch.sql` (append `app_setup_members`, `app_setup_claim_link`)
- Modify: `crates/db/src/setup.rs` (`SetupMember`, `setup_members`, `claim_link_for`)
- Modify: `crates/api/src/setup.rs` (`choices`, `presets`, `show`, `routes`, new `claim_links` handler)
- Modify: `docs/server-setup.md` §2 table, §3, §6, §7
- Test: `crates/api/tests/setup.rs`

**Interfaces:**
- Produces, db: `pub struct SetupMember { user_id: String, display_name: String, passkey: bool, provider: bool }`; `pub async fn setup_members(pool, caller) -> Result<Vec<SetupMember>, SetupError>`; `pub async fn claim_link_for(pool, caller, user_id: &str, days: i32) -> Result<String /*token*/, SetupError>` (generates the token in Rust with `passkey::new_token`, calls `app_setup_claim_link(p_hash, p_user, p_days)`; `NotFound` for a banned, deleted or non-member id → `SetupError::NoSuchMember`).
- Produces, SQL: `app_setup_members()` SECURITY DEFINER, owner-only (`app_owner_of(app_uid())` else `42501`), returns `(user_id uuid, display_name text, passkey boolean, provider boolean)` for every non-banned membership, ordered by display_name. `app_setup_claim_link(p_hash bytea, p_user uuid, p_days integer)`: owner-only; `p_days BETWEEN 1 AND 90`; refuses a banned/deleted/non-member target with `P0002`; replaces any existing claim for that user; audit `passkey.claim_link` with `actor_id = app_uid()`, `detail {"days": n}`, `subject_user_id = p_user`.
- Produces, API: `GET /v1/setup` adds `counts.members_without_provider`, `counts.owner_has_provider`, `members: [SetupMember…]`. `POST /v1/setup/claim-links` body `{"user_ids": ["…"], "days": 14}` (`days` optional, default 14, `deny_unknown_fields`, at most 200 ids) → `200 {"links": [{"user_id","display_name","url"}]}`; `400 bad_request` for an unknown or banned id (whole request refused, nothing minted); owner-only like the rest of setup.
- `choices()`: `sign_in_methods` options in order `provider`, `any`, `passkey`. Titles: "Through {provider name} only", "Passkeys, or through {provider name}", "Passkeys only" (use the first provider's name; `relevant: deployment.sso`). Effects, one sentence each in the server's words. `needs`: `provider` → `["owner_has_provider"]`, `passkey` → `["owner_has_passkey"]`, `any` → `[]`. Delete the `"passkeys"` need.
- `presets()`: Convenience `sign_in_methods: provider`; Privacy `passkey`; both `available: true`, no `unavailable`.

- [ ] **Step 1: Write the failing tests** in `tests/setup.rs`

- Update `a_server_that_has_not_been_set_up_says_so_and_offers_what_it_would_do`: three options in order; the needs above; both presets available; `members` is an array with the owner in it, `passkey: false, provider: true`.
- `the_owner_can_see_who_is_ready_and_hand_out_passkey_links`: provider + passkeys; owner, Bo (provider only), Cy (banned). `GET /v1/setup`: `members` has owner and Bo, not Cy; `counts.members_without_passkey == 2`, `members_without_provider == 0`. `POST /v1/setup/claim-links {"user_ids":[bo]}` → one link whose `url` starts with `https://tiny.test/v1/auth/passkey/claim#`; Bo's `claim/peek` on its token → 200 with Bo's name; the audit log has `passkey.claim_link` with `actor_id` = owner. A second call for Bo replaces the first (the old token now peeks 400). `{"user_ids":[cy]}` → 400. A member (Bo) calling the route → 403. `{"days": 91}` → 400.

- [ ] **Step 2: Run to verify they fail**: `cargo test -p api --test setup the_owner_can_see_who_is_ready` → FAIL.

- [ ] **Step 3: Implement** SQL → db → api, per the Interfaces block. In `show`, call `setup_members` and put the result under `"members"`.

- [ ] **Step 4: Update `docs/server-setup.md`**: the `sign_in_methods` table (three rows), the refusal list (drop `passkeys_unavailable`, add the two provider ones), the presets table (`provider`), §6 (`members`, the two counts, the new route), §7 the tested list. Delete sentences at lines 77, 84-86, 103, 165 that describe the old deployment gate.

- [ ] **Step 5: Run**: `cargo test -p api` → PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/db crates/api docs/server-setup.md
git commit -m "Setup lists who is ready and mints passkey links for the owner"
```

---

### Task 6: Docs and the runbook

**Files:**
- Modify: `docs/auth-passkeys.md` §2, §7, §8, §9, §10
- Modify: `deploy/README.md` where it mentions `compose.passkey.yml`

- [ ] **Step 1: Rewrite §2 Modes** as the spec's three-row table keyed on the owner's choice, plus one paragraph: a deployment with no provider is always passkeys; the settings table loses the "modes" wording.

- [ ] **Step 2: Rewrite §8 Steps** to: 1 Back up. 2 Update. 3 Add your own passkey (Server Settings › Sign-in › Add a passkey). 4 Choose *Passkeys, or through Pocket ID* (Server Settings › Privacy). 5 Send passkey links from the same page; `auth claim-links` stays for a roster export. 6 Watch the counts there. 7 Choose *Passkeys only*; "Switch anyway" if some have not claimed. 8 Check. 9 Optional, shell: `retire-oidc-identities --apply`, then `compose.passkey.yml` to remove Pocket ID. "Going back": pick *Through Pocket ID only*; after step 9, `relink-identity` per member as today.

- [ ] **Step 3: §10**: replace the three mode lines (209, 211, 214) with what Tasks 3–5 test.

- [ ] **Step 4: Commit**

```bash
git add docs deploy/README.md
git commit -m "Docs: sign-in is one switch the owner holds"
```

---

### Task 7: Whole-branch check

- [ ] `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace` → PASS.
- [ ] `rg -n "TINYSERVER_AUTH|passkeys_unavailable|PasskeysUnavailable|with_passkeys" crates deploy docs` → only the `warn!` and the migration comment.
- [ ] Push once: `git push -u origin feat/sign-in-switch`; open the PR with the spec's "What this builds" as the body.
