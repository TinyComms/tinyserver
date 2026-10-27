# Running a community

Postgres, tinyserver, and Tinyauth sit on a Docker network that has no route to the internet. cloudflared is on that network and on a second network that can reach Cloudflare, and it carries HTTP and the live socket for the chat hostname and the sign-in pages for the auth hostname. The one published port is the media port, UDP and the same number on TCP, for call audio and video. Starting a sign-in and trading its code are limited to a few tries a minute per address.

tinyserver keeps no passwords. People sign in at an OpenID Connect provider; Tinyauth comes set up as the default one. Signing in proves who someone is to the server. It never grants decryption.

The environment file next to the compose file holds the database passwords, the tunnel token, and the two public URLs. The sign-in secrets are files in `deploy/secrets`. Neither is committed.

`deploy/compose.yml` reads them. `TINYSERVER_PG_DIR` and `TINYAUTH_DATA_DIR` can be host directories. Left unset, Docker keeps named volumes.

## Two hostnames

| Variable | Example | What it is |
| --- | --- | --- |
| `TINYSERVER_PUBLIC_URL` | `https://chat.example.org` | The address people type into tinyclient. The tunnel sends it to `http://tinyserver:8080`. |
| `TINYAUTH_PUBLIC_URL` | `https://auth.example.org` | Tinyauth's sign-in pages and its OIDC issuer. The tunnel sends it to `http://tinyauth:3000`. |

Add both as public hostnames on the tunnel in Cloudflare. Tinyauth needs https; Cloudflare provides it. The issuer is `TINYAUTH_PUBLIC_URL` exactly, with no trailing slash, because that is what Tinyauth puts in its tokens.

tinyserver has no route out, so it reaches Tinyauth inside, at `http://tinyauth:3000` (`TINYSERVER_OIDC_INTERNAL_URL`). Discovery, the keys, and the code exchange go there, with the endpoints Tinyauth names moved to that address. The issuer in discovery and in every ID token must still be the public one. The browser always goes to the public auth hostname.

The other way is to give tinyserver a route out and leave `TINYSERVER_OIDC_INTERNAL_URL` unset; it then reads everything at the public issuer, through Cloudflare. That is the only way for a provider outside this compose file, such as Google; tinyserver is already on the `media` network, which has a route out.

## Tinyauth

Tinyauth (AGPL-3.0, OpenID Certified) runs as `ghcr.io/tinyauthapp/tinyauth:v5.2.0-distroless`, pinned by digest, as user 65532, with a read-only root, no capabilities, `no-new-privileges`, a small `/tmp`, and process and memory limits. It has no published port and only the internal network. It keeps its sessions and its signing key in the `tinyauth_data` volume; the key is made on first start.

It is configured for this server alone: local users from a file, with TOTP; no Docker labels, no analytics, no resources server; secure cookies; 12-hour sessions and 7 days at most; three tries, then 15 minutes locked; ACLs deny by default; JSON logs with the audit stream on; and one OIDC client, `tinyserver`, whose only redirect URI is `${TINYSERVER_PUBLIC_URL}/v1/auth/callback`. It trusts the forwarded-for header only from cloudflared, which has the fixed address `TINYSERVER_TUNNEL_IP` (172.30.53.10) on `TINYSERVER_INSIDE_SUBNET` (172.30.53.0/24). Change both if that range is taken on the host.

Before the first start, make the secrets, from `deploy/`:

```sh
sh tinyauth/setup.sh
```

It writes `secrets/oidc_client_secret`, 32 random bytes in hex that Tinyauth and tinyserver share, and walks through `tinyauth user create` and `tinyauth totp generate` in the pinned image, then adds the `username:bcrypt-hash:totp-secret` line to `secrets/tinyauth_users`. Run it again for each person who should have a Tinyauth account, then `docker compose up -d` so Tinyauth reads the file again. The directory is 0700 and the files 0444, because the containers read them as their own users.

By hand, it is the same:

```sh
mkdir -p secrets && chmod 700 secrets
openssl rand -hex 32 > secrets/oidc_client_secret
docker run --rm -it ghcr.io/tinyauthapp/tinyauth:v5.2.0-distroless user create --interactive
docker run --rm -it ghcr.io/tinyauthapp/tinyauth:v5.2.0-distroless totp generate --interactive
# put the final username:hash:secret line in secrets/tinyauth_users
chmod 444 secrets/oidc_client_secret secrets/tinyauth_users
```

A Tinyauth account is not a membership. People still need an invite, or a group the owner allows, to join.

## The first owner

There is no owner password. The first start migrates and, while there is no owner, prints a single-use owner invite that lasts 24 hours:

```sh
docker compose logs tinyserver | grep -A2 'Owner invite'
```

It is a tinyclient invite code. Paste it into tinyclient's "Join a server" and sign in at Tinyauth; that person becomes the owner. Until someone does, every start prints a new invite and the old one stops working. After that, starts leave the owner alone.

A server from before sign-in moved to OIDC still has its owner, but that account has no provider identity and cannot sign in. Make an owner invite anyway, sign in with it, and remove the old account from the member list:

```sh
docker compose exec tinyserver tinyserver bootstrap --owner-invite
```

## Other providers

Any provider with discovery, the authorization code flow, and a confidential client works: Authentik, Keycloak, Zitadel, Google, and so on. Register the redirect URI `${TINYSERVER_PUBLIC_URL}/v1/auth/callback`.

| Variable | Meaning |
| --- | --- |
| `TINYSERVER_OIDC_ISSUER` | The issuer. Discovery is read from it, and it must match exactly. |
| `TINYSERVER_OIDC_CLIENT_ID` | The client id. |
| `TINYSERVER_OIDC_CLIENT_SECRET_FILE` or `TINYSERVER_OIDC_CLIENT_SECRET` | The secret. tinyserver uses `client_secret_basic`, or `client_secret_post` when that is all discovery offers. |
| `TINYSERVER_OIDC_PRIVATE_KEY_FILE`, `TINYSERVER_OIDC_PRIVATE_KEY_ID` | Instead of a secret: `private_key_jwt` (RFC 7523) with an RSA key in PKCS#1 PEM (`openssl genrsa -traditional`), signed RS256, `kid` set when the id is. |
| `TINYSERVER_OIDC_SCOPES` | `openid profile email` unless set. |
| `TINYSERVER_OIDC_PROVIDER_NAME` | Shown in tinyclient. The issuer's host unless set. |
| `TINYSERVER_OIDC_INTERNAL_URL` | Where tinyserver reaches the provider, when not at the issuer. |
| `TINYSERVER_OIDC_GROUPS_CLAIM` | The ID token claim with the person's groups, an array or a comma list. `groups` unless set. |
| `TINYSERVER_OIDC_MEMBER_GROUPS` | Comma list. Someone in one of these, or in an admin group, joins without an invite, audited as `member.join` with `via` `groups`. Unset is invite only. |
| `TINYSERVER_OIDC_ADMIN_GROUPS` | Comma list. A member in one of these becomes admin when they sign in, audited as `member.role` with `via` `groups`. Leaving the group does not demote anyone; an owner or admin does that. No claim makes an owner. |
| `TINYSERVER_SESSION_MAX_DAYS` | How long a session from sign-in lasts, 1 to 365, 30 unless set. Then tinyclient signs in again. Nothing extends a session, and no provider refresh token is kept. |

Several providers at once: `TINYSERVER_OIDC_PROVIDERS=tinyauth,google`, then the same variables with the id after `OIDC_`, such as `TINYSERVER_OIDC_GOOGLE_ISSUER`, `TINYSERVER_OIDC_GOOGLE_CLIENT_SECRET_FILE`, and `TINYSERVER_OIDC_GOOGLE_NAME` for the name. The first is the default. A person is the pair of issuer and subject, so the same person at two providers is two accounts. Email never links accounts.

PKCE is S256 on every sign-in, whether or not discovery mentions it. ID tokens must be RS256, ES256, or EdDSA, signed by a key in the provider's key set; a token with a key id the server has not seen makes it read the set again, at most every 10 seconds.

## Logout from the provider

A provider that supports OpenID Connect Back-Channel Logout 1.0 can end the sessions it started. Register this as the client's back-channel logout URI:

```
${TINYSERVER_PUBLIC_URL}/v1/auth/backchannel-logout
```

The logout token is checked like an ID token: signature, issuer, audience, `iat`, the logout event, no `nonce`. A `sid` ends the sessions from that provider session; a `sub` ends that person's sessions from that provider; both together end the ones that match both. Their live sockets close at once. Sessions are audited as `session.logout`. Tinyauth 5.2 does not send these; signing out in tinyclient ends its own session, and "Sign out everywhere" ends all of them.

## Calls and the media port

Call audio and video do not fit through the tunnel, so they go straight to the server on one port number, UDP first and TCP for networks that block UDP. Without it the server still runs, and a `call.join` with an offer gets `media_unavailable`.

1. Set `TINYSERVER_PUBLIC_IP` in the environment file to the address members reach: the router's public IPv4 address. The server does not guess it.
2. `TINYSERVER_MEDIA_PORT` is 50000 unless set. Compose publishes the same number inside and out, on UDP and TCP, because the server advertises the port it binds.
3. On the router, forward that port to the host, both UDP and TCP.
4. On the host firewall, allow both: `ufw allow 50000/udp` and `ufw allow 50000/tcp`.
5. Optional: set `TINYSERVER_LAN_IP` to the host's address on the home network, such as `192.168.1.20`. Many routers do not hairpin, so members at home cannot reach the public address from inside; with this set, the answer offers them the LAN address too. Members elsewhere see it in the SDP but cannot use it.
6. Optional: set `TINYSERVER_MEDIA_EGRESS_KBPS` to what the host can upload for calls, in kb/s, such as `8000` on a 10 Mb/s line. The server plans every call together to fit it: everyone gets the high camera layer if that fits, else the low one, else audio only. Each listener with a camera to watch costs about 1,200 kb/s on the high layer and 350 on the low one, and each voice about 50.
7. `docker compose up -d`, then check that `GET /health` says `"media": "up"` and lists `"transports": ["udp", "tcp"]`, with `"lan"` as well when step 5 is set.

Every member in a call sees `TINYSERVER_PUBLIC_IP` in the SDP answer. The tunnel no longer hides the host's address from members. Strangers who find the port get STUN handling only; nothing else is processed without the per-join ICE password, which only travels over the signed-in live socket.

Joining the `media` network gives the server a route out, which it did not have. It makes no outbound connections except to a sign-in provider outside the compose file, when one is configured; an owner who wants that enforced can add a `DOCKER-USER` rule that allows only replies.

TCP streams are capped at 256 in all and 16 from one address. One that sends no STUN for a call within 5 s, or nothing at all for 30 s, is closed. A relay mode for hosts that cannot open a port comes in a later release.

## Stopping

`docker stop` sends SIGTERM. The server ends every call, finishes the requests it has, and exits.

## Housekeeping

Every ten minutes the server deletes expired sessions, expired invites nobody used, expired idempotency keys, sign-ins nobody finished, and one-time codes nobody redeemed. Accepted invites stay in the invite list.

## Images

`cloudflare/cloudflared` is pinned to a release tag and Tinyauth to a release tag and digest. Raise them on purpose, after reading the release notes.
