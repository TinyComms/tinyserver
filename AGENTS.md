# Agents in tinyserver

## Release captain

These rules are complete here. You do not need `tiny/AGENTS.md` to follow them.

### What the captain does

The captain decides the cut and then stops. It does not merge feature work, fix a failing build, or open a feature pull request. Feature work stays on a branch and merges through a normal pull request into `main`, squashed.

An agent doing feature work does not tag or deploy. It may tell Justin that merged server work is not deployed. It deploys only when Justin explicitly says to deploy the server.

Nothing deploys with no agent in the thread: no scheduler, no GitHub Action, no cron. CI (`ci.yml`) only tests. Merged does not mean live.

### The quality gate

The gate is written in tinyclient (`docs/quality-gate.md`); `docs/quality-gate.md` here says where the server differs. For a feature agent:

- Open the pull request from `.github/pull_request_template.md`, with one type checked.
- A `feature` or `fix` brings an `e2e/scenarios/<id>` in the same pull request. A released client drives it against this branch, and it fails on `main` without the change.
- Do not paste your own screenshots as proof. The lab records each client and posts `e2e-proof`.
- A migration says so in the pull request, with its rollback.

The deploy check prints an `e2e:` line. When `e2e/gate.json` has `"release_proof": "enforce"`, a missing one is a `BLOCK`.

### Not on the daily train

tinyserver has no release train and no tags. `Cargo.toml` staying at `0.1.0` is fine. Do not invent server tags.

A server deploy does not wait for a client release, and a client release does not wait for a server deploy. The written compatibility rules are `docs/server.md` ("older clients keep working, and `GET /v1/capabilities` answers 404 on servers from before it"), the Compatibility table in `docs/calls.md`, and `docs/privacy/migration.md`.

### The check

`deploy/release-cut.sh` prints what is merged and not deployed, names the migration files in that range, and lists every reason it may not deploy today. It changes nothing unless it is passed `--apply`. Run it before every deploy and paste its output into the thread.

- Exit 0: ready. Exit 1: blocked, each reason is a `BLOCK` line. Exit 2: it could not work out the cut.
- The cut is every commit on `origin/main` since the SHA last deployed to the community. Something that should not ship is not merged. There is no list of merged commits to skip.
- The deployed SHA is recorded in `<git common dir>/tinyserver-community-deployed` (for the shared clone, `tinyserver/.git/tinyserver-community-deployed`). It is shared by every worktree and never committed. `--apply` rewrites it after a deploy. If it is missing or wrong, read the SHA from the host and pass `--deployed SHA`.
- `deploy/release-freeze` blocks a deploy on any day it covers. One inclusive range per line, `YYYY-MM-DD YYYY-MM-DD`, in the local date of Justin's Windows machine (Zeppelin). A line that does not parse blocks too. Deploy through it only when Justin says "ship through the freeze" (`--through-freeze`); every other check still runs.
- It also blocks when nothing is merged since the deployed SHA, when CI is not green on that exact `origin/main` SHA, and when the host below is blank.

### The community host

Community host: `tiny-server`
Community dir: `/var/lib/tinyserver`
Build host: `atomicstudio`

`deploy/release-cut.sh` reads those lines. Do not write the community's provider, hostname, IP, or plan size into this repository, the project board, or public docs. Reach the community host as `root` through the 1Password SSH agent: a Git Bash `ssh` cannot open it, so use `C:/Windows/System32/OpenSSH/ssh.exe` (the script does when it exists), and batch each visit into one call, because every call is one approval. It cannot build the image. `atomicstudio` (Tailscale SSH, no prompt) builds it. `atomicstudio` also runs a tinyserver of its own; that one is not the community.

### The deploy

Only when Justin explicitly says to deploy the server, and only after the dry run above is clean. `deploy/release-cut.sh --apply` runs the method in use since 2026-11-02, in one `ssh` to the build host and two to the community host:

1. `git -c core.autocrlf=false archive` of `origin/main` (CRLF breaks `entrypoint.sh`) goes to the build host, which builds `tinyserver:<sha>` and streams `docker save` of it into `docker load` on the community host.
2. The same archive goes to the community host as `<dir>/src-<sha>`, with `deploy/compose.vps.yml` (the host's own overrides, not in this repository) copied in from the live tree.
3. `pg_dump -U postgres tinyserver` into `<dir>/backups/before-<sha>-<time>.sql`.
4. The live tree `<dir>/src` moves to `<dir>/src-pre-<sha>-<time>`, the new tree takes its place, `tinyserver:<sha>` is tagged `tinyserver:local`, and from `<dir>/src/deploy`: `docker compose -p tinyserver --env-file ../../.env -f compose.yml -f compose.vps.yml up -d --no-build`.

Then check the logs it prints, `GET /health` on the chat hostname, and that the migrations it named ran. To roll back, move `src-pre-<sha>-<time>` back to `src`, tag the previous image `tinyserver:local` (`docker images tinyserver` lists them by sha), `up -d --no-build` again, and restore the dump only if a migration has to be undone.

CI publishes `ghcr.io/tinycomms/tinyserver:<sha>` too, but the package is private and the host has no token for it, so the image is built and loaded as above.

### Done

A deploy is done when the host runs the new SHA, the record says so, and `/health` answers. A green CI run by itself is not done.
