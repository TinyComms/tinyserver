# Channel read: the reader's own sessions

Run `sh e2e/scenarios/channel-read-self-event/run.sh` with both `TEST_DATABASE_URL_MIGRATE`
and `TEST_DATABASE_URL` pointing to an owned disposable Postgres 17 service, initialized
with `docker/postgres/init/01-roles.sh`. The owner role needs CREATEDB. The test creates
and destroys its own uniquely named database. No existing server or community database is
used.

The driver starts the real API on a bound local port. One person holds two live sockets and
another member holds one, all viewing the same text channel. The other member posts a
message and the first person marks the channel read over HTTP. The test asserts that both
of the reader's sockets receive `read.updated` with `kind` `channel`, the conversation and
the message id, and the reader's own user id; that the other member's socket receives
nothing about it; that a second mark-read of the same message emits nothing; and that the
stored outbox row names the reader alone, so the 24 hour replay hands the event to no one
else. On the base server the first assertion fails because a channel read emitted nothing
and the socket waits in vain.

This is server integration evidence. It does not certify a released tinyclient, desktop
GUI, notification UI, or any native platform. The released client already zeroes the unread
count on `read.updated` for its own user id on any conversation, so it needs no change for
this event; tinyclient issue 284 is what makes the count visible on the channel row.

Privacy stays as documented: who has read a channel is nobody else's business. The frame
carries ids only, never text, and the audience is the one reader. `docs/calls.md`,
`docs/server.md` and the G3.9 row in `docs/privacy/guarantees.md` say the same.

Migration `0042_channel_read_self_event.sql` replaces only the body of `app_mark_read`; no
table changes. Its rollback restores the 0008 body:
`crates/db/rollback/0042_channel_read_self_event.down.sql`.
