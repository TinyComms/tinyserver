# Linked-device membership: API component evidence

Run `sh e2e/scenarios/device-link-membership/run.sh` with both
`TEST_DATABASE_URL_MIGRATE` and `TEST_DATABASE_URL` pointing to an owned,
disposable Postgres initialized with `docker/postgres/init/01-roles.sh`.
The owner needs CREATEDB; every test creates and drops its own database.
Missing credentials, missing targets, empty filters and skipped database fixtures
fail the driver. Main without the self conversation fails its first named test.

These existing HTTP tests use real PostgreSQL and MLS clients in the test
process. They cover self-conversation isolation and retention, initial audience
urgency across bounded commits, linked siblings, revoke/send serialization,
ordinary new-person batching, shared-group splits and durable repair generations.
An HTTP/WebSocket regression also refuses calls to a self conversation without
fanout, history or a busy state, then rings an ordinary two-person direct.
This is API component evidence. It does not certify installed native clients,
device churn, history transfer or client plaintext/ciphertext retention. Exact-head
native proof remains pending and the pull request remains on MERGE HOLD.
No aggregate native lab status is posted; this scenario has `release: false`.

Migrations `0036_e2ee_self.sql`, `0037_e2ee_membership_barrier.sql`,
`0038_e2ee_initial_audience.sql` and `0039_e2ee_group_generations.sql` must coexist
with `0035_e2ee_device_link.sql` and main's `0040_direct_calls.sql`. Upgrade proof
uses the standard compiled `tinyserver migrate` CLI on populated dump restores:
current main already through 0040 adds 0035-0039; device linking already through
0035 and 0040 adds 0036-0039. Existing ciphertext, plaintext, previews, reads,
devices, outbox, call history and migration metadata must survive. New generation
and self-membership columns are additive; compare original column projections
and independently verify their expected backfills. Repeated startup must be safe.

Keep the current database and fix forward. An older SQLx migrator can reject
unknown versions during startup. A serving-process rollback needs a verified
startup path that keeps the current data. A stale dump restore is quiesced
disaster recovery with explicit data-loss and reconciliation implications.
Nothing deploys or restores a database automatically.
