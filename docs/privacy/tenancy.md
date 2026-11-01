# Many communities on one host

One community is one stack: `deploy/compose.yml`, unchanged. `deploy/tenant/tenant.sh` makes the
environment that turns it into a tenant sharing nothing with another tenant on the same host, and
`deploy/tenant/operator.sh` holds the operator's hooks for it. A single self-hoster runs the same
compose file with their own env file and none of this; every default is what a single community
always had.

This is what TinyServer gives a host that runs many communities, such as TinyCloud. It is not the
whole isolation contract: the host still has to give each tenant its own UID range, its own
cgroup, nftables rules and disk encryption (`design/architecture.md` section 4.3 in TinyCloud).

## What each tenant gets of its own

| Thing | How | Checked by |
| --- | --- | --- |
| Containers, networks, volumes | The compose project name, `tinyserver-<name>`, prefixes all of them | `deploy/tests/isolation.sh` |
| Internal network | Its own `/24` (`TINYSERVER_INSIDE_SUBNET`), `internal: true`, no route out | isolation.sh: no name resolves and no address connects across tenants |
| Media port | Its own, `50000 + index` by default | isolation.sh: each publishes its own and not the other's |
| Postgres | Its own cluster in its own container, with its own superuser password | isolation.sh |
| Database and roles | `tenant_<name>`, `<name>_owner`, `<name>_runtime`, all named for the tenant, with their own random passwords | isolation.sh, roles.sh |
| Secrets | Its own `secrets/` directory: OIDC client secret, Pocket ID API and encryption keys; and its own media signing key and database passwords in `tenant.env` | isolation.sh: no tenant's compose configuration contains another's |
| Limits | Memory, pids and CPU per container, set per tenant in `tenant.env` | isolation.sh: a memory hog is killed, a fork bomb is refused, CPU is throttled |

`tenant.sh new` refuses a name, project, subnet, media port or database name another tenant in the
same directory already has. It does not look at the rest of the host: Docker refuses an
overlapping subnet, and a taken port fails `up`.

## Database roles

Roles in Postgres belong to the cluster, not to a database. With one cluster per tenant that is
harmless, and that is how the stack runs. But the role names `app_owner` and `app_runtime` were
the same everywhere, so a credential leaked from one community named a role every other community
also had, and two communities could never share a cluster. Now:

* A tenant's login roles are named for it. A password for one tenant's role is not a password
  for any other's, in any cluster.
* The migrations still grant to and revoke from `app_runtime`. For a tenant that is a NOLOGIN
  group, with no password and no CONNECT anywhere, and the tenant's runtime login role is its one
  member. `docker/postgres/init/01-roles.sh` grants every privilege the runtime has to that group
  and never to the login role directly, so a migration's `REVOKE ... FROM app_runtime` takes the
  privilege from the login role too. (An earlier draft gave the default privileges to the login
  role, and the runtime role then kept INSERT on tables the migrations narrow, `reports` and the
  outbox among them. `deploy/tests/hooks.sh` checks this against the real schema.)
* `PUBLIC` has no CONNECT on the tenant's database and no privileges on its `public` schema.
  Only the tenant's two login roles may connect.
* The tenant's owner has no CREATEDB. Only the test suite needs it.

If two tenants ever do share one cluster (`deploy/tests/roles.sh` runs that case), each still
cannot connect to the other's database, and a grant to `app_runtime` in one database is useless to
the other tenant's role, which cannot connect there. What a shared cluster still gives away: every
role can list every role and database name, and the tenants share one postgres process, one WAL,
one memory and connection budget, and one superuser. Do not share a cluster.

## Containers

Every service has `no-new-privileges` and limits. All but clamd drop every capability; Postgres
and clamd add back the five their images need to set up their directories and drop to their own
users (`CHOWN DAC_OVERRIDE FOWNER SETGID SETUID`). Every service but clamd has a read-only root
filesystem; Postgres writes only its volume, its socket directory and `/tmp`, both tmpfs. clamd's
root stays writable because its entrypoint writes the `CLAMD_CONF_` settings into `/etc/clamav`.
No service is privileged, mounts the Docker socket, uses a host namespace or maps a device. The
only host path mounted anywhere is the read-only Postgres init directory, and the secrets.

## Turning scanning off

clamd is 85 to 90 percent of a community's memory, and it cannot scan a file sealed on the
sending device. `deploy/scan-off.yml`, or `tenant.sh new --scan none`, runs a community without it:
`TINYSERVER_SCAN_ENGINE=none`, no clamd container, every upload marked clean unscanned, and a
warning in the log at start. The default stays clamd, and `none` with a clamd socket set will not
start. Use it only where attachments are sealed; elsewhere it lets any file through.

## The operator's hooks

None of these listen on any port. They are `deploy/tenant/operator.sh` on the host, which only
someone who can run Docker there can use, and `tinyserver operator`, which needs the database
owner's password and so runs only in a one-off copy of the init container.

| Hook | What it does | What it does not do |
| --- | --- | --- |
| `suspend --read-only` | Members can sign in, read, download, report abuse, sign out and delete their accounts. Nothing else is written. Every refusal carries the notice. | End calls already running; they go on until they end. |
| `suspend --offline` | Only `/health` and `/v1/status` answer, with the notice. Live sockets close with `4010 suspended` within a minute. | Stop the containers. To stop them, `compose stop`; then there is no notice. |
| `resume` | Back to normal; the notice is cleared. | Lift a legal hold. |
| `hold`, `release` | A legal hold: resolved reports stop expiring, and `delete` and `restore` refuse. The reason goes to `operator_events`, which the serving process cannot read; members never see it. A report an owner holds inside the community counts too. | Stop a member deleting their own account. A hold keeps reports and the community; it is not a preservation of every member's data. |
| `backup` | The database (`pg_dump` as the owner), uploads, Pocket ID's data (stopped for the copy) and the three secrets, with a manifest and checksums, encrypted with age to the operator's recipients and to the tenant's own key if `keygen` made one. The plaintext lives in a tmpfs inside a throwaway container with no route out, and in the pipe to age. | Include `tenant.env`: the restore target keeps its own database passwords. |
| `export` | The same bundle for the owner, encrypted only to the owner's recipients, with the compose file, `01-roles.sh` and a README for running it themselves. | Hold anything the operator can read. |
| `restore` | Checks the bundle's checksums before anything is touched, then drops and remakes the database, runs `01-roles.sh`, restores the dump as the target's own owner so every object and every SECURITY DEFINER function is the target's, replaces uploads, Pocket ID data and secrets, and starts the stack, which migrates an older bundle forward. Works between tenants with different role names, and into a plain stack. | Run under a legal hold. A restore into another tenant is a move: the source still exists until it is deleted, with the same secrets. |
| `delete` | Refuses under any hold. Otherwise removes the containers, networks and every volume, overwrites and removes the secrets, the env file and the tenant's backup key, and removes the tenant's directory. | Shred the volumes' blocks. On a disk without per-tenant encryption they stay until reused; on TinyCloud the cell's fscrypt key is what shreds them. |

Crypto-shred, honestly: a backup encrypted only to the tenant's own key (`keygen`) cannot be read
once every copy of that key is gone. `delete` destroys the copy on the host; copies the operator
escrowed elsewhere must be destroyed too. A backup also encrypted to the operator's own recipient
stays readable with that key, which is what makes it restorable after a host is lost. Choose per
tenant which you need.

## Known limits

* Containers share the host kernel. A kernel escape in one tenant reaches every tenant on the host.
* The cloud metadata address, 169.254.169.254, is reachable from a container on the `media`
  network unless the host drops it. Drop it on the host; `isolation.sh` is how to check it there.
* Restoring an earlier backup may leave clients ahead of the server's MLS state for calls. They
  rejoin.
* `operator.sh`'s status, suspend, resume, hold and release run the real `tinyserver` binary and
  are covered by `crates/api/tests/operator.rs`, not by the shell checks, which use a stand-in
  image.
