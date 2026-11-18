-- Undoes migrations/0044_channel_pins.sql. Run as the owner role, in one transaction, then
-- start the previous image. It restores the body of app_delete_message from 0022 as it was,
-- drops the account-deletion trigger and the pin functions, and drops the table, so the
-- previous image's migration check passes. The pin rows go with the table; nothing else held
-- one, and no message text or ciphertext was ever in it.

BEGIN;

CREATE OR REPLACE FUNCTION app_delete_message(p_id uuid)
RETURNS text[]
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_author uuid;
    v_channel uuid;
    v_direct uuid;
    v_deleted timestamptz;
    v_kind text;
    v_low uuid;
    v_high uuid;
    v_conv uuid;
    v_files text[];
    v_all uuid[];
BEGIN
    PERFORM app_msg_voice();
    SELECT author_id, channel_id, direct_id, deleted_at
    INTO v_author, v_channel, v_direct, v_deleted
    FROM messages WHERE id = p_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    v_conv := coalesce(v_channel, v_direct);
    SELECT kind, low_user_id, high_user_id INTO v_kind, v_low, v_high
    FROM app_open_conversation(v_conv, true);
    IF v_author <> app_uid() THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    IF v_deleted IS NOT NULL THEN
        RETURN '{}'::text[];
    END IF;
    SELECT p_id || coalesce(array_agg(m.id), '{}') INTO v_all
    FROM messages m WHERE m.target_id = p_id;
    SELECT coalesce(array_agg(id::text), '{}') INTO v_files
    FROM attachments WHERE message_id = ANY (v_all);
    DELETE FROM attachments WHERE message_id = ANY (v_all);
    DELETE FROM reactions WHERE message_id = ANY (v_all);
    UPDATE messages SET body = '', deleted_at = now()
    WHERE id = ANY (v_all) AND deleted_at IS NULL;
    PERFORM app_emit_to(
        'message.deleted',
        jsonb_build_object(
            'conversation_id', v_conv::text,
            'kind', v_kind,
            'message', app_message_json(p_id, app_uid())
        ),
        app_audience(v_kind, v_low, v_high)
    );
    RETURN v_files;
END;
$$;

DROP TRIGGER users_forget_channel_pins ON users;
DROP FUNCTION app_pins_forget_user();
DROP FUNCTION app_pin_message(uuid);
DROP FUNCTION app_unpin_message(uuid);
DROP FUNCTION app_list_pins(uuid);
DROP TABLE channel_pins;

DELETE FROM _sqlx_migrations WHERE version = 44;

COMMIT;
