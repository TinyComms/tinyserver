# Checks for tenants and the operator's hooks

Shell checks that start real containers. Each makes only containers, networks and volumes named
`tinytenant-test-*`, removes them when it ends, and removes leftovers of an aborted run when it
starts. `purge.sh` removes them by hand. Run one at a time: each purges the prefix.

| Script | What it checks | Needs |
| --- | --- | --- |
| `roles.sh` | `docker/postgres/init/01-roles.sh`: with nothing set it makes what a single community always had; for a tenant, its own role names, a runtime login role that gets everything through the `app_runtime` group so a REVOKE reaches it, no CONNECT for PUBLIC, and a second run that changes nothing. Two tenants in one cluster cannot reach each other's database; what such a cluster still leaks is printed as a known limit. | Docker, `postgres:17-alpine` |
| `isolation.sh` | Two tenants from `tenant.sh`, up: their own project, networks, volumes, subnet, media port, database, roles, passwords and secrets; no name resolves and no address connects across them; each container's capabilities, read-only root, seccomp, no-new-privileges, environment and limits as Docker applied them, including a memory hog, a fork bomb and a busy loop. `--scan none` leaves clamd out for that tenant only. | Docker with Compose 2.24+, cgroup v2, `postgres:17-alpine` |
| `hooks.sh` | `operator.sh` on three tenants with the real schema (every migration, as the tenant's owner): an age-encrypted backup with no plaintext in it; a restore into another tenant where every object and SECURITY DEFINER function belongs to the new owner and every privilege is what it was; an export only the owner's key opens; the legal hold, the operator's or a report's, stopping delete and restore; and delete leaving nothing of the tenant behind. The other tenants are checked untouched throughout. | the above, and `age` on PATH or `TINYSERVER_AGE_IMAGE` |
| `migrations-as-tenant.sh` | The API's integration tests against a database and roles set up as a tenant's are. | the above, and cargo |

The serving and init containers in `isolation.sh` and `hooks.sh` run a stand-in image with the
real service definitions, as `compose.test.yml` explains, so they need no tinyserver build. That
is also why suspend, resume, hold and release, which run the tinyserver binary, are checked by
`crates/api/tests/operator.rs` instead.

What passing means: Docker applies the compose file's settings to the containers it makes, two
tenants cannot reach each other's network, database or files, and the hooks do what
`docs/privacy/tenancy.md` says. It does not mean those settings are enough on a given host: the
kernel is still shared, and the host must still drop the cloud metadata address and give each
tenant its own UID range and disk encryption.
