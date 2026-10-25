# Running a community

Postgres and tinyserver sit on a Docker network that has no route to the internet. cloudflared is on that network and on a second network that can reach Cloudflare, and it carries HTTP and the live socket. The one published port is the media port, UDP and the same number on TCP, for call audio. Sign-in and invite acceptance are limited to a few tries a minute. Passwords are 12 to 128 characters.

The tunnel hostname is the address people type into tinyclient. The database password and the tunnel token stay in the environment file next to the compose file. That file is not committed.

`deploy/compose.yml` reads it. `TINYSERVER_PG_DIR` can be a host directory for the database. Left unset, Docker keeps a named volume.

## The first owner

The first start needs `TINYSERVER_OWNER_EMAIL`, `TINYSERVER_OWNER_NAME`, and `TINYSERVER_OWNER_PASSWORD` in the environment file. The container migrates, creates that owner, and serves. Without them and without an owner, the container stops and says which one is missing.

Once the owner exists, delete the three lines from the environment file and run `docker compose up -d` again. Compose recreates the container without the password, so it no longer shows in `docker inspect`. Later starts migrate and leave the existing owner in place.

## Calls and the media port

Call audio does not fit through the tunnel, so it goes straight to the server on one port number, UDP first and TCP for networks that block UDP. Without it the server still runs, and a `call.join` with an offer gets `media_unavailable`.

1. Set `TINYSERVER_PUBLIC_IP` in the environment file to the address members reach: the router's public IPv4 address. The server does not guess it.
2. `TINYSERVER_MEDIA_PORT` is 50000 unless set. Compose publishes the same number inside and out, on UDP and TCP, because the server advertises the port it binds.
3. On the router, forward that port to the host, both UDP and TCP.
4. On the host firewall, allow both: `ufw allow 50000/udp` and `ufw allow 50000/tcp`.
5. Optional: set `TINYSERVER_LAN_IP` to the host's address on the home network, such as `192.168.1.20`. Many routers do not hairpin, so members at home cannot reach the public address from inside; with this set, the answer offers them the LAN address too. Members elsewhere see it in the SDP but cannot use it.
6. `docker compose up -d`, then check that `GET /health` says `"media": "up"` and lists `"transports": ["udp", "tcp"]`, with `"lan"` as well when step 5 is set.

Every member in a call sees `TINYSERVER_PUBLIC_IP` in the SDP answer. The tunnel no longer hides the host's address from members. Strangers who find the port get STUN handling only; nothing else is processed without the per-join ICE password, which only travels over the signed-in live socket.

Joining the `media` network gives the server a route out, which it did not have. It makes no outbound connections; an owner who wants that enforced can add a `DOCKER-USER` rule that allows only replies.

TCP streams are capped at 256 in all and 16 from one address. One that sends no STUN for a call within 5 s, or nothing at all for 30 s, is closed. A relay mode for hosts that cannot open a port comes in a later release.

## Stopping

`docker stop` sends SIGTERM. The server ends every call, finishes the requests it has, and exits.

## Housekeeping

Every ten minutes the server deletes expired sessions, expired invites nobody used, and expired idempotency keys. Accepted invites stay in the invite list.

## Images

`cloudflare/cloudflared` is pinned to a release tag. Raise it on purpose, after reading the release notes.
