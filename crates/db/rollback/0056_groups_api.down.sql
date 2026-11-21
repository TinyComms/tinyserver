-- Undoes migrations/0056_groups_api.sql. Run as the owner role, in one transaction, then
-- start the previous build.

BEGIN;

DROP TRIGGER IF EXISTS users_scrub_group_outbox ON users;
DROP FUNCTION IF EXISTS app_group_scrub_deleted_outbox();

-- Restore `app_delete_account` from 0022_e2ee_text_messages.sql.
CREATE OR REPLACE FUNCTION app_delete_account()
RETURNS text[]
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_user uuid := app_uid();
    v_owner boolean;
    v_files text[];
    v_device uuid;
BEGIN
    IF v_user IS NULL OR NOT EXISTS (
        SELECT 1 FROM users WHERE id = v_user AND deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.owners'));
    SELECT owner INTO v_owner FROM memberships WHERE user_id = v_user;
    IF v_owner AND (SELECT count(*) FROM memberships WHERE owner) <= 1 THEN
        RAISE EXCEPTION 'last owner' USING ERRCODE = '42501';
    END IF;

    SELECT coalesce(array_agg(a.id::text), '{}') INTO v_files
    FROM attachments a
    WHERE a.uploader_id = v_user
       OR a.message_id IN (SELECT m.id FROM messages m WHERE m.author_id = v_user);
    DELETE FROM attachments
    WHERE uploader_id = v_user
       OR message_id IN (SELECT m.id FROM messages m WHERE m.author_id = v_user);
    DELETE FROM reactions
    WHERE user_id = v_user
       OR message_id IN (SELECT m.id FROM messages m WHERE m.author_id = v_user);
    UPDATE messages SET body = '', deleted_at = now()
    WHERE author_id = v_user AND deleted_at IS NULL;
    DELETE FROM reads WHERE user_id = v_user;

    FOR v_device IN
        SELECT d.device_id FROM e2ee_devices d WHERE d.user_id = v_user AND d.revoked_at IS NULL
    LOOP
        UPDATE e2ee_devices SET revoked_at = now(), low_keys = false WHERE device_id = v_device;
        DELETE FROM e2ee_key_packages WHERE device_id = v_device;
        DELETE FROM e2ee_handshake WHERE for_device = v_device;
        PERFORM app_emit(
            'e2ee.device',
            jsonb_build_object('user_id', v_user::text, 'device_id', v_device::text, 'op', 'revoked')
        );
    END LOOP;
    DELETE FROM e2ee_upload_ledger WHERE user_id = v_user;

    DELETE FROM bots WHERE created_by = v_user;
    DELETE FROM invites WHERE created_by = v_user AND accepted_at IS NULL;
    DELETE FROM idempotency_keys WHERE key LIKE v_user::text || E'\n%';
    DELETE FROM sessions WHERE user_id = v_user;
    DELETE FROM auth_codes WHERE user_id = v_user;
    DELETE FROM user_identities WHERE user_id = v_user;
    DELETE FROM memberships WHERE user_id = v_user;

    DELETE FROM outbox WHERE payload #>> '{member,user_id}' = v_user::text;

    UPDATE audit_log
    SET detail = detail - 'display_name' - 'name' - 'email'
    WHERE (actor_id = v_user OR subject_user_id = v_user) AND detail IS NOT NULL;

    UPDATE users
    SET email = NULL,
        display_name = 'Deleted user',
        avatar = NULL,
        avatar_type = NULL,
        avatar_sha = NULL,
        deleted_at = now()
    WHERE id = v_user;

    INSERT INTO audit_log (actor_id, action, subject, detail, subject_user_id)
    VALUES (v_user, 'account.delete', 'user', jsonb_build_object('user_id', v_user), v_user);
    RETURN v_files;
END;
$$;
REVOKE EXECUTE ON FUNCTION app_delete_account() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_delete_account() TO app_runtime;

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
