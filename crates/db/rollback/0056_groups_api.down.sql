-- Undoes migrations/0056_groups_api.sql. Run as the owner role, in one transaction, then
-- start the previous build.

BEGIN;

DROP FUNCTION IF EXISTS app_group_leave(uuid);
DROP FUNCTION IF EXISTS app_group_add(uuid, uuid);
DROP FUNCTION IF EXISTS app_group_rename(uuid, text);
DROP FUNCTION IF EXISTS app_group_open(uuid[], text, boolean);
DROP FUNCTION IF EXISTS app_group_get(uuid);
DROP FUNCTION IF EXISTS app_group_list();
DROP FUNCTION IF EXISTS app_group_event_json(uuid);
DROP FUNCTION IF EXISTS app_group_json(uuid);
DROP FUNCTION IF EXISTS app_group_members_json(uuid);

-- Restore `app_group_members_sync` from 0055_group_dms.sql.
CREATE OR REPLACE FUNCTION app_group_members_sync()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_group uuid;
BEGIN
    IF TG_OP = 'DELETE' THEN
        v_group := OLD.group_dm_id;
        DELETE FROM reads
        WHERE user_id = OLD.user_id AND kind = 'group' AND conversation_id = v_group;
    ELSE
        v_group := NEW.group_dm_id;
    END IF;
    UPDATE group_dms g
    SET member_key = app_group_member_key(coalesce(
        (SELECT array_agg(gm.user_id) FROM group_dm_members gm WHERE gm.group_dm_id = v_group),
        '{}'::uuid[]
    ))
    WHERE g.id = v_group;
    RETURN NULL;
END;
$$;

DELETE FROM _sqlx_migrations WHERE version = 56;

COMMIT;
