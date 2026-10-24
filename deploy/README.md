# Running a community

Postgres and tinyserver sit on a Docker network that has no route to the internet and no published port. cloudflared is on that network and on a second network that can reach Cloudflare. Sign-in and invite acceptance are limited to a few tries a minute. Passwords are 12 to 128 characters.

The tunnel hostname is the address people type into tinyclient. The database password and the tunnel token stay in the environment file next to the compose file. That file is not committed.

`deploy/compose.yml` reads it. `TINYSERVER_PG_DIR` can be a host directory for the database. Left unset, Docker keeps a named volume.

## The first owner

The first start needs `TINYSERVER_OWNER_EMAIL`, `TINYSERVER_OWNER_NAME`, and `TINYSERVER_OWNER_PASSWORD` in the environment file. The container migrates, creates that owner, and serves. Without them and without an owner, the container stops and says which one is missing.

Once the owner exists, delete the three lines from the environment file and run `docker compose up -d` again. Compose recreates the container without the password, so it no longer shows in `docker inspect`. Later starts migrate and leave the existing owner in place.

## Stopping

`docker stop` sends SIGTERM. The server finishes the requests it has and exits.

## Housekeeping

Every ten minutes the server deletes expired sessions, expired invites nobody used, and expired idempotency keys. Accepted invites stay in the invite list.

## Images

`cloudflare/cloudflared` is pinned to a release tag. Raise it on purpose, after reading the release notes.
