-- Undoes migrations/0043_channel_my_permissions.sql. Run as the owner role, in one transaction,
-- then start the previous image. It restores app_list_channels from 0008 as it was, drops the
-- wrapper, and removes the migration's record, so the previous image's migration check passes.

BEGIN;

CREATE OR REPLACE FUNCTION app_list_channels()
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT coalesce(jsonb_agg(app_channel_json(c.id) ORDER BY c.position, c.name, c.id), '[]'::jsonb)
    FROM channels c
    WHERE app_channel_perms_of(c.id, app_uid()) & 1 = 1
      AND app_is_member()
      AND NOT app_banned(app_uid());
$$;

DROP FUNCTION app_channel_json_of(uuid);

DELETE FROM _sqlx_migrations WHERE version = 43;

COMMIT;
