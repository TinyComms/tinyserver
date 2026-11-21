# Video received: released desktop client against this server

This is the server's first `"release": true` deploy-gate scenario (`e2e/scenarios/video-received`).
It proves that a released desktop `tinyclient` media core receives and draws a screen share and a
camera sent by another released `tinyclient` through this branch's server, in both a voice room
and a direct call.

## Scope

- **Platforms:** `windows`, `macos`, `linux`.
- **Not applicable:** `android` and `ios` (`not_applicable` in `scenario.json` because the client
  probe is a desktop process pair).
- **Proof scope:** released desktop client media core against this server build; not GUI.

## How to run

Provide an owned disposable Postgres 17 service initialized with `docker/postgres/init/01-roles.sh`
(never a live community database):

```sh
TEST_DATABASE_URL_MIGRATE=postgres://app_owner:...@127.0.0.1:5432/postgres \
TEST_DATABASE_URL=postgres://app_runtime:...@127.0.0.1:5432/postgres \
sh e2e/scenarios/video-received/run.sh
```

What `run.sh` does:

1. Starts this branch's server via the bounded disposable fixture
   (`cargo test -p api --test direct_fixture direct_calls_fixture_for_client -- --ignored --exact --nocapture`),
   which seeds two synthetic accounts plus one video-enabled voice room (`room_id`) and writes
   their details only to a private temporary file.
2. Checks out the last released `tinyclient` `v*` tag into a scratch directory (or uses
   `TINYCLIENT_REF` / `TINYCLIENT_DIR`, below) and runs its `e2e/scenarios/tiny-video-received/drive.py`
   driver (`TinyComms/tinyclient#274`) with `TINY_DIRECT_CALL_FIXTURE` pointing at that file.
3. Passes only when **both**:
   - the client driver exits 0 and prints its proof marker
     (`video-received-proof: room share+camera painted; direct share+camera painted; counters advance; cleared on stop`), **and**
   - the captured server log contains, in order, `video publish` (`source=share`, `on=true`)
     followed by `video slot` (`layer=share`), and `video publish` (`source=camera`, `on=true`)
     followed by `video slot` (`layer=l` or `layer=h`), excluding `video slot empty` and `from=none`.

You can also run the server log check standalone against any captured server log:

```sh
sh e2e/scenarios/video-received/run.sh --check-log /path/to/server.log
```

## Client reference while `tiny-video-received` is pending release

Until a released `tinyclient` tag includes `e2e/scenarios/tiny-video-received/drive.py`, point
`run.sh` at the client branch or local checkout carrying it (as allowed by
`docs/quality-gate.md`):

- `TINYCLIENT_REF=<branch-or-sha>` — fetch that ref from `TINYCLIENT_REPO` (default
  `https://github.com/TinyComms/tinyclient.git`) instead of the latest `v*` tag.
- `TINYCLIENT_DIR=/path/to/tinyclient` — run the driver directly from an existing local checkout.
- `DIRECT_CALL_FIXTURE_SECONDS` — bounded fixture lifetime in seconds (default `600`, max `7200`).
- `PYTHON` — Python interpreter for `drive.py` (default `python3`, falling back to `python`).

## What it asserts (server side)

- **Room:** sender starts a share mid-call with `call.offer`; the viewer's `call.slots` `video`
  names the sender with `kind: "share"` no earlier than the first forwarded keyframe; frames arrive
  on that mid until the share stops; then `video` clears to `null` (or falls back to an active
  camera).
- **Direct call (`d:` room):** the same media path, while no `call.slots`, `call.state`, or
  `call.joined` for that direct call leaks to a third member's socket.
- **Camera with simulcast:** the viewer receives layer `l` or `h`, and the slot map reports
  `kind: "camera"`.
- **With `e2ee_calls` on:** the same paths end to end; the server forwards sealed frames without
  refusing or rewriting them.

## Sabotage check (base-commit failure)

To confirm the scenario catches a broken SFU video plan rather than passing vacuously, disable the
share branch in `Engine::plan_screen` (`crates/sfu/src/engine.rs`) and re-run `run.sh`. The
publisher still logs `video publish ... source="share" on=true`, while the viewer never receives a
`video slot ... layer="share"` transition; both the client probe and `run.sh`'s server log check
fail at the viewer's slot naming the share.
