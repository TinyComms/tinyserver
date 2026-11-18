-- Pins: which messages a conversation keeps at hand (issue #71). A pin is a message id, who
-- pinned it, and when. It holds no text and no ciphertext, so the same routes serve plaintext
-- and encrypted conversations, and an encrypted conversation's pin list is the same ciphertext
-- rows its message list returns.
--
-- Who may pin: in a channel, `manage_channels` (512) in that channel, the same bit and the
-- same check that edits and deletes the channel; until a dedicated moderation bit exists, this
-- is the mask's moderator split. In a direct, either person. A timed out or banned person may
-- not (app_msg_voice). At most 50 pins per conversation, checked before the insert; the 51st is
-- refused with P0E23, `409 pin_limit` on the API. The count and the insert run under one
-- transaction advisory lock, so two pins cannot pass the cap together.
--
-- Live topics `pin.added` and `pin.removed` carry ids only. A channel event is narrowed to the
-- channel's viewers by app_scope_audience, a direct event goes to the two people, as for
-- message events.
--
-- NOTE: staged as 0044 while PRs #75, #76 and #77 hold 0042 and 0043. Renumber on rebase; a
-- migration that has shipped is never edited, so only a not-yet-merged number moves.

-- `channel_id` is the conversation: a channels.id or a directs.id, as `reads` names either
-- through its kind and conversation_id. A message lives in one conversation, so the message id
-- is the whole key and a second pin of one message is a no-op.
CREATE TABLE channel_pins (
    channel_id uuid NOT NULL,
    message_id uuid NOT NULL PRIMARY KEY REFERENCES messages (id) ON DELETE CASCADE,
    pinned_by uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    pinned_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX channel_pins_order ON channel_pins (channel_id, pinned_at DESC, message_id);

ALTER TABLE channel_pins ENABLE ROW LEVEL SECURITY;
ALTER TABLE channel_pins FORCE ROW LEVEL SECURITY;

REVOKE ALL ON channel_pins FROM app_runtime;

-- Pins a message. Idempotent: a message that is already pinned answers without an event, and
-- the API still says 204. A deleted message is not there to pin.
CREATE FUNCTION app_pin_message(p_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_channel uuid;
    v_direct uuid;
    v_deleted timestamptz;
    v_kind text;
    v_low uuid;
    v_high uuid;
    v_conv uuid;
BEGIN
    PERFORM app_msg_voice();
    SELECT channel_id, direct_id, deleted_at INTO v_channel, v_direct, v_deleted
    FROM messages WHERE id = p_id;
    IF NOT FOUND OR v_deleted IS NOT NULL THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    v_conv := coalesce(v_channel, v_direct);
    SELECT kind, low_user_id, high_user_id INTO v_kind, v_low, v_high
    FROM app_open_conversation(v_conv, false);
    IF v_kind = 'channel' AND NOT app_channel_has(v_channel, 512) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    IF EXISTS (SELECT 1 FROM channel_pins WHERE message_id = p_id) THEN
        RETURN;
    END IF;
    -- The count and the insert are one critical section, so two pins of the same conversation
    -- cannot pass the cap together. Pins are rare; one community-wide key is enough. The
    -- already-pinned check runs again here, so two pins of one message announce one event.
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.pins'));
    IF EXISTS (SELECT 1 FROM channel_pins WHERE message_id = p_id) THEN
        RETURN;
    END IF;
    IF (
        SELECT count(*) FROM channel_pins WHERE channel_id = v_conv
    ) >= 50 THEN
        RAISE EXCEPTION 'pin limit' USING ERRCODE = 'P0E23';
    END IF;
    INSERT INTO channel_pins (channel_id, message_id, pinned_by)
    VALUES (v_conv, p_id, app_uid())
    ON CONFLICT (message_id) DO NOTHING;
    IF v_kind = 'channel' THEN
        PERFORM app_audit(
            'message.pin', 'message',
            jsonb_build_object('message_id', p_id, 'channel_id', v_channel),
            NULL, NULL
        );
    END IF;
    PERFORM app_emit_to(
        'pin.added',
        jsonb_build_object(
            'conversation_id', v_conv::text,
            'kind', v_kind,
            'message_id', p_id::text,
            'pinned_by', app_uid()::text
        ),
        app_audience(v_kind, v_low, v_high)
    );
END;
$$;

-- Takes a pin back. Idempotent: a message that is not pinned answers without an event, and the
-- API still says 204.
CREATE FUNCTION app_unpin_message(p_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_channel uuid;
    v_direct uuid;
    v_deleted timestamptz;
    v_kind text;
    v_low uuid;
    v_high uuid;
    v_conv uuid;
BEGIN
    PERFORM app_msg_voice();
    SELECT channel_id, direct_id, deleted_at INTO v_channel, v_direct, v_deleted
    FROM messages WHERE id = p_id;
    IF NOT FOUND OR v_deleted IS NOT NULL THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    v_conv := coalesce(v_channel, v_direct);
    SELECT kind, low_user_id, high_user_id INTO v_kind, v_low, v_high
    FROM app_open_conversation(v_conv, false);
    IF v_kind = 'channel' AND NOT app_channel_has(v_channel, 512) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    DELETE FROM channel_pins WHERE message_id = p_id;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    IF v_kind = 'channel' THEN
        PERFORM app_audit(
            'message.unpin', 'message',
            jsonb_build_object('message_id', p_id, 'channel_id', v_channel),
            NULL, NULL
        );
    END IF;
    PERFORM app_emit_to(
        'pin.removed',
        jsonb_build_object(
            'conversation_id', v_conv::text,
            'kind', v_kind,
            'message_id', p_id::text,
            'pinned_by', app_uid()::text
        ),
        app_audience(v_kind, v_low, v_high)
    );
END;
$$;

-- The pinned messages of one conversation, newest pin first, at most 50. The cap is enforced
-- at the pin, so the list is bounded by construction; the LIMIT says so again. The rows are
-- what the message list returns for them, ciphertext included.
CREATE FUNCTION app_list_pins(p_conversation uuid)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    PERFORM app_open_conversation(p_conversation, false);
    RETURN coalesce((
        SELECT jsonb_agg(
            app_message_json(p.message_id, app_uid())
            ORDER BY p.pinned_at DESC, p.message_id
        )
        FROM (
            SELECT message_id, pinned_at FROM channel_pins
            WHERE channel_id = p_conversation
            ORDER BY pinned_at DESC, message_id
            LIMIT 50
        ) p
    ), '[]'::jsonb);
END;
$$;

-- A deleted message takes its pin with it. Messages are deleted softly, so no foreign key
-- fires. The message.deleted event reaches the same people as a pin.removed would, so the
-- delete emits no pin event of its own.
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
    DELETE FROM channel_pins WHERE message_id = ANY (v_all);
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

-- A deleted account tombstones the user row, so no foreign key fires. Their pins go, and so do
-- pins of the messages they wrote, the way their reactions do (0014).
CREATE FUNCTION app_pins_forget_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    DELETE FROM channel_pins
    WHERE pinned_by = NEW.id
       OR message_id IN (SELECT m.id FROM messages m WHERE m.author_id = NEW.id);
    RETURN NULL;
END;
$$;

REVOKE EXECUTE ON FUNCTION app_pins_forget_user() FROM PUBLIC;

CREATE TRIGGER users_forget_channel_pins
    AFTER UPDATE OF deleted_at ON users
    FOR EACH ROW
    WHEN (OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL)
    EXECUTE FUNCTION app_pins_forget_user();

REVOKE EXECUTE ON FUNCTION app_pin_message(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_pin_message(uuid) TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_unpin_message(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_unpin_message(uuid) TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_list_pins(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_list_pins(uuid) TO app_runtime;

-- Rollback: crates/db/rollback/0044_channel_pins.down.sql restores the body of
-- app_delete_message from 0022, drops the trigger and the pin functions, and drops the table.
-- Nothing here rewrites data; the table is new and empty on a fresh start.
