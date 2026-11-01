# Tenants: many communities on one host

`tenant.sh` turns `deploy/compose.yml`, unchanged, into one tenant among many. `operator.sh` holds
the operator's hooks for a tenant, or for a single community run from the compose file. What each
promises and what it does not is in `docs/privacy/tenancy.md`.

## Make and run a tenant

```sh
sh deploy/tenant/tenant.sh new acme --chat-url https://acme.example.org \
    --auth-url https://auth.acme.example.org --tunnel-token <token>
sh deploy/tenant/tenant.sh compose acme up -d
```

`new` writes `tenants/acme/tenant.env` (0600, passwords included) and `tenants/acme/secrets/`. The
project is `tinyserver-acme`, the database `tenant_acme`, the roles `acme_owner` and
`acme_runtime`, the subnet `10.77.N.0/24` and the media port `50000+N`, with N from the name
unless `--index` says otherwise. `--scan none` runs the tenant without clamd, for sealed
attachments only. Limits are commented out at the end of the env file. `TENANT_DIR` puts the
tenants somewhere else. `compose` passes anything after the name to `docker compose`.

Pocket ID needs its client and first admin, as for a single community: from `deploy/`,
`TINYSERVER_SECRETS_DIR=tenant/tenants/acme/secrets COMPOSE="sh tenant/tenant.sh compose acme" sh pocket-id/setup.sh <username>`.
The secrets are already there, made by `new`; setup registers them.

## Operator hooks

```sh
sh deploy/tenant/operator.sh status   acme
sh deploy/tenant/operator.sh suspend  acme --read-only --notice "Read-only while a report is reviewed."
sh deploy/tenant/operator.sh suspend  acme --offline   --notice "Suspended for nonpayment."
sh deploy/tenant/operator.sh resume   acme
sh deploy/tenant/operator.sh hold     acme --reason "preservation request 2026-12"
sh deploy/tenant/operator.sh release  acme
sh deploy/tenant/operator.sh keygen   acme
sh deploy/tenant/operator.sh backup   acme --out acme-2026-11-01.age --recipient age1...
sh deploy/tenant/operator.sh export   acme --out acme-export.age --recipients-file owner.txt
sh deploy/tenant/operator.sh restore  acme --in acme-2026-11-01.age --identity operator.key
sh deploy/tenant/operator.sh delete   acme --confirm acme
```

For a single community run from `deploy/compose.yml`, give `--stack deploy/.env` in place of the
tenant name.

Backups and exports need `age` on PATH (or `TINYSERVER_AGE_IMAGE`, an image whose entrypoint is
age). `keygen` gives the tenant its own key, which every later backup is also encrypted to; once
every copy of it is gone, so are backups encrypted to it alone. Keep an escrow copy, encrypted to
your recovery key, off the host.

The checks for all of this are in `deploy/tests/`.
