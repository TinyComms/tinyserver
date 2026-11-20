-- Undoes migrations/0042_channel_read_self_event.sql. Run as the owner role, in one
-- transaction, then start the previous image. It restores the body from 0008_messages.sql
-- as it was and removes the migration's record, so the previous image's migration check
-- passes. The reads table is untouched. A read.updated row already in the outbox stays and
-- is delivered to the reader it names, as any stored event is.

BEGIN;

CREATE OR REPLACE FUNCTION app_mark_read(p_conversation uuid, p_message uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_kind text;
    v_channel uuid;
    v_direct uuid;
    v_low uuid;
    v_high uuid;
    v_at timestamptz;
    v_old uuid;
    v_old_at timestamptz;
    v_old_id uuid;
BEGIN
    SELECT kind, channel_id, direct_id, low_user_id, high_user_id
    INTO v_kind, v_channel, v_direct, v_low, v_high
    FROM app_open_conversation(p_conversation, false);
    SELECT created_at INTO v_at
    FROM messages
    WHERE id = p_message
      AND (channel_id IS NOT DISTINCT FROM v_channel)
      AND (direct_id IS NOT DISTINCT FROM v_direct);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    SELECT message_id INTO v_old
    FROM reads
    WHERE user_id = app_uid() AND kind = v_kind AND conversation_id = p_conversation;
    IF v_old IS NOT NULL THEN
        SELECT created_at, id INTO v_old_at, v_old_id FROM messages WHERE id = v_old;
        IF v_old_at IS NOT NULL AND (v_at, p_message) <= (v_old_at, v_old_id) THEN
            RETURN;
        END IF;
    END IF;
    INSERT INTO reads (user_id, kind, conversation_id, message_id)
    VALUES (app_uid(), v_kind, p_conversation, p_message)
    ON CONFLICT (user_id, kind, conversation_id) DO UPDATE
    SET message_id = EXCLUDED.message_id, read_at = now();
    IF v_kind = 'direct' THEN
        PERFORM app_emit_to(
            'read.updated',
            jsonb_build_object(
                'conversation_id', p_conversation::text,
                'kind', 'direct',
                'user_id', app_uid()::text,
                'message_id', p_message::text
            ),
            ARRAY[v_low, v_high]
        );
    END IF;
END;
$$;

DELETE FROM _sqlx_migrations WHERE version = 42;

COMMIT;
