# Device-link relay: API component evidence

Run `sh e2e/scenarios/device-link-relay/run.sh` with both
`TEST_DATABASE_URL_MIGRATE` and `TEST_DATABASE_URL` pointing to an owned,
disposable Postgres initialized with `docker/postgres/init/01-roles.sh`.
The owner needs CREATEDB; each executed test creates and drops its own database.
Missing credentials, empty filters and skipped database fixtures fail the driver.
Main without the feature has no `e2ee_link` test target and fails the driver.

The ten existing API tests exercise capability discovery, same-user session
authorization, opaque message relay, caps/rates, streamed archive ranges,
expiry/deletion/sweeping and log canaries. The default archive cap is 96 MiB.
This does not certify the client archive cryptography, native device churn or
encrypted-history retention. Exact-head native/client proof is pending and the
pull request's merge hold remains in effect. No aggregate lab status is posted.

Migration `0035_e2ee_device_link.sql` coexists with main's `0040_direct_calls.sql`.
History-upgrade validation must use the real migrator on populated databases in
both orders: baseline through 0034 to the combined source, and current main
already through 0040 to the source that adds 0035. Migration metadata must not be
rewritten to make a test pass.

Keep the current database and fix forward. An older SQLx migrator can reject
unknown 0035/0040 versions during startup. A serving-process rollback must keep
the current data and use a verified startup path without that older migrator.
A stale dump restore is quiesced disaster recovery with explicit data-loss and
reconciliation implications, not routine rollback. Nothing deploys or restores
a database automatically.
