-- A channel read told nobody. The cursor moved, but the reader's other sessions were not
-- told, so a channel read on the laptop left the phone's unread count stale until its next
-- reload (issue #53). A direct read already tells its two people.
--
-- The channel branch now emits read.updated with an audience of the reader alone. Who has
-- read a channel stays nobody else's business: an explicit audience is never widened by
-- app_scope_audience (0013_private_channel_events.sql), so the payload's kind 'channel'
-- does not turn this into a channel-wide event. The frame carries ids only, never text.
--
-- The cursor rule is unchanged: the function returns early when the cursor would not move
-- forward, so a repeated or stale read emits nothing. The cursor stays one per person; the
-- client zeroes its count on read.updated for its own user id on any conversation.
--
-- Rollback: crates/db/rollback/0042_channel_read_self_event.down.sql restores the 0008 body.

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
    ELSIF v_kind = 'channel' THEN
        PERFORM app_emit_to(
            'read.updated',
            jsonb_build_object(
                'conversation_id', p_conversation::text,
                'kind', 'channel',
                'user_id', app_uid()::text,
                'message_id', p_message::text
            ),
            ARRAY[app_uid()]
        );
    END IF;
END;
$$;
