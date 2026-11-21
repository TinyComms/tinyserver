-- Rollback for 0060_group_calls.sql.
-- Restores `app_group_json` to its 0056 definition and removes group call tables and functions.

BEGIN;

CREATE OR REPLACE FUNCTION app_group_json(p_id uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT jsonb_build_object(
        'id', g.id::text,
        'name', g.name,
        'e2ee', g.e2ee,
        'plaintext_history', g.e2ee AND app_e2ee_has_plaintext(g.id),
        'created_by', g.created_by::text,
        'created_at', app_stamp(g.created_at),
        'members', app_group_members_json(g.id),
        'unread', app_unread('group', g.id),
        'last_read', (
            SELECT r.message_id::text
            FROM reads r
            WHERE r.user_id = app_uid()
              AND r.kind = 'group'
              AND r.conversation_id = g.id
        ),
        'last_message', app_last_message(NULL, NULL, g.id)
    )
    FROM group_dms g
    WHERE g.id = p_id
      AND EXISTS (
          SELECT 1 FROM group_dm_members gm
          WHERE gm.group_dm_id = g.id AND gm.user_id = app_uid()
      );
$$;

REVOKE EXECUTE ON FUNCTION app_group_json(uuid) FROM PUBLIC, app_runtime;

DROP FUNCTION IF EXISTS app_record_group_call(uuid, uuid, uuid, text, double precision, uuid[], text[]);
DROP FUNCTION IF EXISTS app_group_call_access(uuid, uuid);

DROP TABLE IF EXISTS group_call_log_people;
DROP TABLE IF EXISTS group_call_log;

DELETE FROM _sqlx_migrations WHERE version = 60;

COMMIT;
