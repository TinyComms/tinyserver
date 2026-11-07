# The quality gate

The full gate is written once, in tinyclient: [`docs/quality-gate.md`](https://github.com/TinyComms/tinyclient/blob/main/docs/quality-gate.md)
(what is checked, what blocks, the lab's hosts) and [`e2e/README.md`](https://github.com/TinyComms/tinyclient/blob/main/e2e/README.md)
(a scenario, a lab run, a valid recording). This page is only where the server differs.

## What a platform means here

A server change is proved by **the last released tinyclient on each platform, driven against this
branch's server**, with a recording of each. `windows`, `macos`, `linux`, `android` and `ios` in
`e2e/gate.json` and in the template mean that, not a build of the server for them.

Why the released client and not the branch's: the server deploys on its own, and "older clients
keep working" is the rule in `docs/server.md`. A client that has not shipped cannot be the thing
that proves a server did not break the ones that have. A server change that a released client
cannot show yet says so in the pull request and names the client branch that will; the lab then
runs that branch's client for that scenario.

## Differences from the client

- `pr-gate` here maps `crates/**` to all five clients, and `Dockerfile`, `docker/**`,
  `docker-compose.yml` and `deploy/**` to `linux` only (the lab boots the image).
- A migration (`crates/db/migrations/**`) also needs the PR's **Migrations** section: a restore of
  a production-shaped dump run forward, and the rollback written down.
- The release gate is the **deploy** gate. `deploy/release-cut.sh` prints `e2e:` for the lab's run
  of the release suite on the exact `origin/main` SHA being deployed, and blocks without it once
  `e2e/gate.json` has `"release_proof": "enforce"`. A server deploy still does not wait for a
  client release, and a client release does not wait for a server deploy.
- `main` has no branch protection today and allows merge, squash and rebase. Target: squash only,
  required checks `check`, `pr-gate`, `e2e-proof`, no admin bypass. That is a settings change for
  Justin; nothing here applies it.
