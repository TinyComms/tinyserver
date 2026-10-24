# Running a community

Postgres and tinyserver sit on a Docker network that has no route to the internet and no published port. cloudflared is on that network and on a second network that can reach Cloudflare. Sign-in and invite acceptance are limited to a few tries a minute. Passwords are 12 to 128 characters.

The tunnel hostname is the address people type into tinyclient. The database password, the owner password, and the tunnel token stay in the environment file next to the compose file. That file is not committed.

`deploy/compose.yml` reads it. `TINYSERVER_PG_DIR` can be a host directory for the database. Left unset, Docker keeps a named volume.

A second start migrates and leaves the existing owner in place.
