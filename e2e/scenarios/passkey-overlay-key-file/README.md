# Passkey overlay: the server keeps its end-to-end key

Run `sh e2e/scenarios/passkey-overlay-key-file/run.sh` on a Linux host with Docker
and Compose 2.24.4 or later. It builds the image from this checkout (set
`E2E_NO_BUILD=1` to use the `tinyserver:local` already there), starts a compose
project of its own, `tinyserver-e2e-passkey-overlay`, and removes it and its
volumes when it ends. It publishes no port and needs no tunnel token. It pulls
the Postgres and Pocket ID images `deploy/compose.yml` names.

1. `deploy/compose.yml` as a new community has it, with Pocket ID. The first
   start writes the key file on the `tinyserver_keys` volume and its public
   half in Postgres.
2. `deploy/compose.passkey.yml` over it, the command in step 9 of
   `docs/auth-passkeys.md`. The server must answer `/health`, say
   `sign-in ready: passkeys only`, still be told the key file's path, and have
   the same key file and the same public key as in step 1.
3. A restart with the overlay still on, and the same key file again.

On the base the overlay replaced tinyserver's whole environment and lost
`TINYSERVER_E2EE_KEY_FILE`. The server then looked for the key under its data
directory, a tmpfs, found the public half in Postgres and no file, and stopped
with `e2ee server key file is missing and the database has no copy`. Step 2
fails there with "tinyserver stopped instead of serving".

`compose.lab.yml` is laid last. It turns off the tunnel, clamd and the published
media port, and nothing the scenario is about.

This is deploy evidence. It does not drive a released tinyclient; that
recording is pending the lab. `crates/server/tests/deploy_compose.rs` checks the
same thing for every combination of the compose files without Docker, and runs
in CI.
