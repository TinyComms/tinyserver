# Logging

tinyserver logs on this machine only. There is no exporter, no telemetry, and `RUST_LOG` does not change the ceilings.

## Sinks

The operator sink is stderr. Docker's json-file driver keeps 10MB times 3. The default ceiling is `info`.

The debug ring stays in memory (about 2000 lines, lines older than an hour dropped). It is written to disk only when the process receives `SIGUSR1`. The file is `{TINYSERVER_DATA_DIR}/logs/bundle-<unix>.log`, mode `0600`. `TINYSERVER_LOG_EXPORT=off` writes nothing. Bundles older than `TINYSERVER_LOG_BUNDLE_HOURS` (default 24) are deleted on the next start.

In the published image, `TINYSERVER_DATA_DIR` is `/var/lib/tinyserver` on a tmpfs (`uid=10001`, mode `0700`) because the root filesystem is read-only.

## Knobs

| Variable | Default | Meaning |
| --- | --- | --- |
| `TINYSERVER_LOG_LEVEL` | `info` | Operator ceiling: `error`, `warn`, `info`, `debug`, `trace`. |
| `TINYSERVER_LOG_RING` | `on` | `on` keeps a debug ring. `off` gives the ring the operator ceiling. |
| `TINYSERVER_LOG_EXPORT` | `on` | `off` refuses `SIGUSR1` bundles. |
| `TINYSERVER_LOG_PEER_IP` | `off` | `on` lets a client address onto the ring. The operator sink still drops `peer`. |
| `TINYSERVER_LOG_BUNDLE_HOURS` | `24` | How long a bundle file may live. |
| `TINYSERVER_DATA_DIR` | `/var/lib/tinyserver` when that directory exists, else `tinyserver-data` | Invite file and bundles. |

`reqwest`, `hyper`, `h2`, `sqlx`, `tower`, and `str0m` never log above `warn`, on either sink.

## Never recorded

Field names that are dropped, and values that are rewritten to `[redacted]`: message text, filenames, tokens, passwords, cookies, keys, invite secrets, OAuth `code` and verifiers, SDP, `a=ice-pwd`, `a=fingerprint`, PEM, URL userinfo, email, display names, and phone numbers. `user_id`, `room_id`, `call_id`, `req_id`, and a static `reason` stay.

The owner invite token is not printed. It is written to `{TINYSERVER_DATA_DIR}/owner-invite` (mode `0600`). stdout says `owner invite written to {path}`. Read it with `docker compose exec tinyserver cat /var/lib/tinyserver/owner-invite`. The file is removed once an owner exists.

Each HTTP request span carries `req_id` (32 hex characters) and the matched route template. The URI, the query string, and the headers are not on the span.
