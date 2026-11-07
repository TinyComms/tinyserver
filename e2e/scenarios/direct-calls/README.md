# Direct calls: server integration

Run `sh e2e/scenarios/direct-calls/run.sh` with both `TEST_DATABASE_URL_MIGRATE`
and `TEST_DATABASE_URL` pointing to an owned disposable Postgres 17 service,
initialized with `docker/postgres/init/01-roles.sh`. The owner role needs
CREATEDB. Each test creates and destroys its own uniquely named database.
No existing server or community database is used.

The driver starts the real API on a bound local port and real SFU peers. It
asserts pair-only ring/accept events, outsider exclusion, terminal durable
history, reconnect state, bidirectional voice, camera/share forwarding and
encrypted-call signaling. The named-test and executed-test-count checks reject
empty filters and skipped fixtures. On the base server the first scenario
fails because `call.ring` returns `unknown_type`.

Scoped `call.leave` supplies both `direct_id` and `ring_id`. The scenario checks
that stale cleanup cannot terminate a newer attempt and that ending an accepted
direct before taking a seat preserves the caller's unrelated voice room.

This is server integration evidence. It does not certify a released tinyclient,
desktop GUI, notification UI, or any native platform. Those five client runs
remain pending the matching direct-call client integration; do not post an
aggregate `e2e-proof` from this driver.

For the matching two-chatd probe, `cargo test -p api --test direct_fixture
direct_calls_fixture_for_client -- --ignored --exact --nocapture` starts a
separate, bounded disposable fixture. It requires both database URLs and
`DIRECT_CALL_FIXTURE_FILE`, writes two synthetic sessions only to that private
file, and removes it and the test database on normal expiry. Configure
`DIRECT_CALL_FIXTURE_BIND`, `DIRECT_CALL_FIXTURE_URL` and
`DIRECT_CALL_FIXTURE_SECONDS` for an isolated lab or an SSH tunnel. Set
`DIRECT_CALL_FIXTURE_MEDIA_BIND` to a fixed port when tunneling, and forward
that ICE-TCP port as well as the API. The default
bind is loopback; the maximum lifetime is two hours. This helper must never
point at a community database. No direct conversation is seeded, so the client
can prove creating its first call to the other member.

Migration `0040_direct_calls.sql` is independent of unmerged device-link
migrations. Old clients retain voice-room behavior and may ignore additive
direct-call fields/events. The migration adds history and replaces
`app_direct_json` only to add `last_call`.

Keep the current database and fix forward. An older serving process can read
the additive schema, but its SQLx migrator rejects unknown migration version
0040, so a previous-image startup that reruns that migrator is blocked. A
serving-process rollback must preserve the current database and use a startup
path verified without the older migrator. Restoring a pre-migration dump is
quiesced disaster recovery only: it loses every message and call recorded after
the backup unless that data is separately recovered and reconciled. No reverse
migration or dump restore runs automatically.
