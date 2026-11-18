# A new community starts with a general channel

Run `sh e2e/scenarios/fresh-community-general/run.sh` with both
`TEST_DATABASE_URL_MIGRATE` and `TEST_DATABASE_URL` pointing to an owned disposable
Postgres 17 service, initialized with `docker/postgres/init/01-roles.sh`. The owner role
needs CREATEDB. Each test creates and destroys its own uniquely named database. No existing
server or community database is used.

The driver calls the real router as `crates/api/tests/bootstrap_general.rs` does. Bootstrap
makes the owner invite and the first person signs in with it; `GET /v1/channels` must then
answer exactly one channel, named `general`, in no category at position 0, created by that
owner, unread zero, with no overrides, plus the `channel.create` audit row with no actor and
the `channel.created` event a created channel emits. Under `e2ee_text = new_required` the
same channel is encrypted even at the smallest device cap: at the first sign-in no device is
enrolled yet, so nothing about the device state stops the seed. Deleting `general` and
forcing a second owner invite brings no channel back. On the base server the first test
fails: the list is empty.

This is API integration evidence. It does not certify a released tinyclient on any platform:
what a released client sees is `#general` in the channel list it already draws after
`GET /v1/channels`, the same route and JSON shape text channels have always had, and it
cannot yet create, rename or delete the channel, which is the state of every text channel
today (TinyComms/tinyclient#281, TinyComms/tinyclient#283). Do not post an aggregate
`e2e-proof` from this driver alone.
