# Message pins

`PUT /v1/messages/{id}/pin` and `DELETE /v1/messages/{id}/pin` are idempotent and answer `204`.
`GET /v1/conversations/{id}/pins` lists the pinned messages, newest pin first, at most 50; the
next pin is `409 pin_limit`. In a channel the `manage_channels` bit (512) decides, and a
channel override moves it per role; in a direct either person pins. A timed out or banned
person may not. `pin.added` and `pin.removed` carry ids only and follow the audience split of
the message topics.

`run.sh` runs the four API tests in `crates/api/tests/messages.rs` against a disposable
Postgres: `TEST_DATABASE_URL_MIGRATE` (owner role, CREATEDB) and `TEST_DATABASE_URL`
(runtime role), as in the other API-component scenarios.
