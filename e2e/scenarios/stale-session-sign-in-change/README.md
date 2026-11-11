# A stale session and the sign-in methods

Run `sh e2e/scenarios/stale-session-sign-in-change/run.sh` with both
`TEST_DATABASE_URL_MIGRATE` and `TEST_DATABASE_URL` pointing to an owned disposable
Postgres 17 service, initialized with `docker/postgres/init/01-roles.sh`. The owner role
needs CREATEDB. Each test creates and destroys its own uniquely named database. No existing
server or community database is used.

The driver calls the real router with a software passkey. A person signs up, their session
is aged three weeks, and they sign in again so a second, fresh session exists. With the old
token, `POST /v1/me/passkeys/link`, `POST /v1/me/recovery-codes` and
`DELETE /v1/me/passkeys/{id}` must each answer `403 recent_sign_in_required` and leave the
claim links, passkeys and recovery codes as they were. With the fresh token the same calls
succeed. On the base server the first test fails: the old token is given a claim link,
because any session of the same person opened in the last ten minutes counted as recent.
The second test is the check that was already there, for a person with one old session.

This is API integration evidence. It does not certify a released tinyclient on any
platform: no released client has a screen for these three calls, and the answer an old
session gets is the `403` it could already get. It says nothing about the image decoding
limits in the same change; those are covered by unit tests in `crates/db/src/media.rs`
and `crates/api/tests/messages.rs`, and the memory they save was not measured against a
running container. Do not post an aggregate `e2e-proof` from this driver.
