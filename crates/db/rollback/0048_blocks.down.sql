-- Undoes migrations/0048_blocks.sql. Run as the owner role, in one transaction, then start the
-- previous image. Restores `app_open_conversation`, `app_open_direct`, `app_direct_parties`, and
-- `app_unread` to their prior bodies and drops the block functions and `blocks` table.

BEGIN;

CREATE OR REPLACE FUNCTION app_open_conversation(p_id uuid, p_need_speak boolean)
RETURNS TABLE (kind text, channel_id uuid, direct_id uuid, low_user_id uuid, high_user_id uuid)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_channel uuid;
    v_low uuid;
    v_high uuid;
BEGIN
    PERFORM app_msg_gate();
    SELECT id INTO v_channel FROM channels WHERE id = p_id;
    IF FOUND THEN
        IF app_channel_perms_of(v_channel, app_uid()) & 1 <> 1 THEN
            RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
        END IF;
        IF p_need_speak THEN
            PERFORM app_msg_voice();
            IF app_channel_perms_of(v_channel, app_uid()) & 4 <> 4 THEN
                RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
            END IF;
        END IF;
        kind := 'channel';
        channel_id := v_channel;
        direct_id := NULL;
        low_user_id := NULL;
        high_user_id := NULL;
        RETURN NEXT;
        RETURN;
    END IF;
    SELECT d.id, d.low_user_id, d.high_user_id INTO v_channel, v_low, v_high
    FROM directs d
    WHERE d.id = p_id AND app_uid() IN (d.low_user_id, d.high_user_id);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    IF p_need_speak THEN
        PERFORM app_msg_voice();
        IF NOT app_is_member_of(v_low) OR NOT app_is_member_of(v_high) THEN
            RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
        END IF;
        IF app_banned(v_low) OR app_banned(v_high) THEN
            RAISE EXCEPTION 'banned' USING ERRCODE = '42501';
        END IF;
    END IF;
    kind := 'direct';
    channel_id := NULL;
    direct_id := p_id;
    low_user_id := v_low;
    high_user_id := v_high;
    RETURN NEXT;
END;
$$;

CREATE OR REPLACE FUNCTION app_open_direct(p_user uuid, p_e2ee boolean, OUT body jsonb, OUT created boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_low uuid;
    v_high uuid;
    v_id uuid;
    v_e2ee boolean := coalesce(p_e2ee, false);
BEGIN
    PERFORM app_msg_gate();
    IF p_user IS NULL OR p_user = app_uid() THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF NOT app_is_member_of(p_user) THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    IF app_banned(p_user) THEN
        RAISE EXCEPTION 'banned' USING ERRCODE = '42501';
    END IF;
    v_low := least(app_uid(), p_user);
    v_high := greatest(app_uid(), p_user);
    SELECT id INTO v_id FROM directs
    WHERE low_user_id = v_low AND high_user_id = v_high AND e2ee = v_e2ee;
    IF FOUND THEN
        body := app_direct_json(v_id);
        created := false;
        RETURN;
    END IF;
    PERFORM app_e2ee_may_create(v_e2ee);
    INSERT INTO directs (low_user_id, high_user_id, e2ee)
    VALUES (v_low, v_high, v_e2ee) RETURNING id INTO v_id;
    created := true;
    body := app_direct_json(v_id);
    PERFORM app_emit_to(
        'direct.created',
        jsonb_build_object('direct', app_direct_json(v_id)),
        ARRAY[v_low, v_high]
    );
END;
$$;

CREATE OR REPLACE FUNCTION app_direct_parties(p_direct uuid, p_user uuid)
RETURNS TABLE (
    low_user_id uuid,
    high_user_id uuid,
    low_timed_out boolean,
    high_timed_out boolean
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT d.low_user_id,
           d.high_user_id,
           coalesce(mlow.timeout_until > now(), false),
           coalesce(mhigh.timeout_until > now(), false)
    FROM directs d
    JOIN memberships mlow ON mlow.user_id = d.low_user_id
    JOIN memberships mhigh ON mhigh.user_id = d.high_user_id
    WHERE d.id = p_direct
      AND p_user IN (d.low_user_id, d.high_user_id)
      AND NOT app_banned(d.low_user_id)
      AND NOT app_banned(d.high_user_id);
$$;

CREATE OR REPLACE FUNCTION app_unread(p_kind text, p_conversation uuid)
RETURNS integer
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT count(*)::integer
    FROM messages m
    WHERE m.deleted_at IS NULL
      AND m.msg_kind = 'message'
      AND m.author_id <> app_uid()
      AND ((p_kind = 'channel' AND m.channel_id = p_conversation)
           OR (p_kind = 'direct' AND m.direct_id = p_conversation))
      AND NOT EXISTS (
          SELECT 1
          FROM reads r
          JOIN messages cursor_message ON cursor_message.id = r.message_id
          WHERE r.user_id = app_uid()
            AND r.kind = p_kind
            AND r.conversation_id = p_conversation
            AND m.seq <= cursor_message.seq
      );
$$;

DROP FUNCTION app_unblock_user(uuid);
DROP FUNCTION app_block_user(uuid);
DROP FUNCTION app_list_blocks();
DROP FUNCTION app_blocked_pair(uuid, uuid);
DROP TABLE blocks;

DELETE FROM _sqlx_migrations WHERE version = 48;

COMMIT;
