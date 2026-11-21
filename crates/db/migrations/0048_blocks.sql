-- Member blocking (issue #65).
--
-- A member may block another user so that neither can send direct messages, react, type, open a
-- new direct, or ring the other. Channel messages from a blocked user keep arriving for the app
-- to hide, and do not count in the blocker's `unread`. Only the blocker can see their own block
-- list (not even owners or moderators). Not audited. Account deletion removes rows by cascade;
-- bans and kicks leave rows in place so a block survives rejoining.

CREATE TABLE blocks (
    blocker_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    blocked_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (blocker_id, blocked_id),
    CHECK (blocker_id <> blocked_id)
);

CREATE INDEX blocks_blocked ON blocks (blocked_id);

ALTER TABLE blocks ENABLE ROW LEVEL SECURITY;
ALTER TABLE blocks FORCE ROW LEVEL SECURITY;

REVOKE ALL ON blocks FROM app_runtime;
GRANT SELECT ON blocks TO app_runtime;

CREATE POLICY blocks_select ON blocks
    FOR SELECT USING (blocker_id = app_uid());

-- True when either person has blocked the other.
CREATE FUNCTION app_blocked_pair(p_a uuid, p_b uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT EXISTS (
        SELECT 1 FROM blocks
        WHERE (blocker_id = p_a AND blocked_id = p_b)
           OR (blocker_id = p_b AND blocked_id = p_a)
    );
$$;

REVOKE EXECUTE ON FUNCTION app_blocked_pair(uuid, uuid) FROM PUBLIC;

-- The caller's own block list: [{user_id, display_name, created_at}].
CREATE FUNCTION app_list_blocks()
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    PERFORM app_msg_gate();
    RETURN coalesce((
        SELECT jsonb_agg(jsonb_build_object(
            'user_id', b.blocked_id::text,
            'display_name', u.display_name,
            'created_at', app_stamp(b.created_at)
        ) ORDER BY b.created_at DESC, b.blocked_id)
        FROM blocks b
        JOIN users u ON u.id = b.blocked_id
        WHERE b.blocker_id = app_uid()
    ), '[]'::jsonb);
END;
$$;

-- Blocks `p_user`. Idempotent. Cannot block yourself. Target must exist (member or not).
-- Capped at 1000 rows per blocker (P0E24 -> 409 block_limit). Emits `block.updated` to the
-- blocker's own sockets only. Not audited.
CREATE FUNCTION app_block_user(p_user uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    PERFORM app_msg_gate();
    IF p_user IS NULL OR p_user = app_uid() THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM users WHERE id = p_user) THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    IF EXISTS (SELECT 1 FROM blocks WHERE blocker_id = app_uid() AND blocked_id = p_user) THEN
        RETURN;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.blocks.' || app_uid()::text, 0));
    IF EXISTS (SELECT 1 FROM blocks WHERE blocker_id = app_uid() AND blocked_id = p_user) THEN
        RETURN;
    END IF;
    IF (SELECT count(*) FROM blocks WHERE blocker_id = app_uid()) >= 1000 THEN
        RAISE EXCEPTION 'block limit' USING ERRCODE = 'P0E24';
    END IF;
    INSERT INTO blocks (blocker_id, blocked_id)
    VALUES (app_uid(), p_user)
    ON CONFLICT (blocker_id, blocked_id) DO NOTHING;
    PERFORM app_emit_to(
        'block.updated',
        jsonb_build_object('user_id', p_user::text, 'blocked', true),
        ARRAY[app_uid()]
    );
END;
$$;

-- Unblocks `p_user`. Idempotent. Emits `block.updated` to the blocker's own sockets only when a
-- row was removed. Not audited.
CREATE FUNCTION app_unblock_user(p_user uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    PERFORM app_msg_gate();
    IF p_user IS NULL THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    DELETE FROM blocks WHERE blocker_id = app_uid() AND blocked_id = p_user;
    IF FOUND THEN
        PERFORM app_emit_to(
            'block.updated',
            jsonb_build_object('user_id', p_user::text, 'blocked', false),
            ARRAY[app_uid()]
        );
    END IF;
END;
$$;

-- Replaces `app_open_conversation` from 0008_messages.sql to refuse writes (messages, E2EE
-- messages, reactions, typing) in a direct when either person has blocked the other. Reading
-- existing history (`p_need_speak = false`) stays allowed for both.
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
        IF app_blocked_pair(v_low, v_high) THEN
            RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
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

-- Replaces `app_open_direct` from 0022_e2ee_text_messages.sql to refuse creating a new direct when
-- either person has blocked the other. An existing direct stays in both lists.
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
    IF app_blocked_pair(v_low, v_high) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
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

-- Replaces `app_direct_parties` from 0040_direct_calls.sql so `call.ring` and direct call joins
-- are refused when either person has blocked the other.
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
      AND NOT app_banned(d.high_user_id)
      AND NOT app_blocked_pair(d.low_user_id, d.high_user_id);
$$;

-- Replaces `app_unread` from 0025_e2ee_remaining.sql so messages from a person the caller has
-- blocked do not count in `unread` (works for both plaintext and encrypted messages).
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
      AND NOT EXISTS (
          SELECT 1 FROM blocks b
          WHERE b.blocker_id = app_uid() AND b.blocked_id = m.author_id
      )
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

REVOKE EXECUTE ON FUNCTION app_list_blocks() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_list_blocks() TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_block_user(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_block_user(uuid) TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_unblock_user(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_unblock_user(uuid) TO app_runtime;

CREATE FUNCTION app_blocks_forget_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    DELETE FROM blocks WHERE blocker_id = NEW.id OR blocked_id = NEW.id;
    RETURN NULL;
END;
$$;

REVOKE EXECUTE ON FUNCTION app_blocks_forget_user() FROM PUBLIC;

CREATE TRIGGER users_forget_blocks
    AFTER UPDATE OF deleted_at ON users
    FOR EACH ROW
    WHEN (OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL)
    EXECUTE FUNCTION app_blocks_forget_user();
