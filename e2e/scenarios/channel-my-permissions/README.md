# my_permissions on the channel list: server integration

Run `sh e2e/scenarios/channel-my-permissions/run.sh` with both `TEST_DATABASE_URL_MIGRATE`
and `TEST_DATABASE_URL` pointing to an owned disposable Postgres 17 service,
initialized with `docker/postgres/init/01-roles.sh`. The owner role needs
CREATEDB. The test creates and destroys its own uniquely named database.
No existing server or community database is used.

The driver runs the real API against a fresh database and asserts that rows of
`GET /v1/channels` carry `my_permissions`, the caller's own mask: an owner
keeps every bit in every channel, a member with a channel-only role override
gains `manage_channels` in that channel only, a plain member loses `speak` in
the overridden channel and is not listed the channel they cannot view, and the
reported masks decide the enforced answers (posting, editing a topic). On the
base server the scenario fails because no row carries `my_permissions`.

This is server integration evidence. It does not certify a released
tinyclient. The released client ignores the extra key; a client that shows the
mask before the error is pending the matching client integration.

Migration `0043_channel_my_permissions.sql` adds one function and re-points
the list at it. Its rollback restores `app_list_channels` from
`0008_messages.sql`, drops the function, and removes the migration record.
Nothing is removed from any response or event, so old clients keep working
unchanged.
