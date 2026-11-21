-- Mentions in plaintext messages, role mentionability, `mention_everyone`, and unread mention
-- counts (issue #68).
--
-- Permission bit 22, `mention_everyone`, is 1 << 22 = 4194304. All bits are now 8388607, and the
-- override mask is now 6537855: channel-scoped, not in @everyone (63). Existing roles follow
-- 0015 and 0045: owners hold every bit through the owner flag, and every non-@everyone role that
-- already held manage_server (524288) receives it.
--
-- Mentions on plaintext messages are stored in `message_mentions` and returned on message JSON
-- (absent on encrypted rows, where mentions live inside the sealed payload). Offsets are UTF-8
-- byte offsets into the stored body. Spans outside the body, unknown ids, users who cannot view
-- the conversation, and unauthorized role/everyone mentions are dropped rather than refused.

-- 1. Permission bit 22: mention_everyone (4194304).

ALTER TABLE roles DROP CONSTRAINT roles_permissions_check;
ALTER TABLE roles
    ADD CONSTRAINT roles_permissions_check
    CHECK (permissions >= 0 AND permissions <= 8388607);
ALTER TABLE roles ADD COLUMN mentionable boolean NOT NULL DEFAULT false;

UPDATE roles SET permissions = permissions | 4194304
WHERE NOT is_default AND permissions & 524288 <> 0;

ALTER TABLE room_overrides DROP CONSTRAINT room_overrides_allow_check;
ALTER TABLE room_overrides DROP CONSTRAINT room_overrides_deny_check;
ALTER TABLE room_overrides
    ADD CONSTRAINT room_overrides_allow_check
        CHECK (allow >= 0 AND allow & ~6537855::bigint = 0),
    ADD CONSTRAINT room_overrides_deny_check
        CHECK (deny >= 0 AND deny & ~6537855::bigint = 0);

ALTER TABLE channel_overrides DROP CONSTRAINT channel_overrides_allow_check;
ALTER TABLE channel_overrides DROP CONSTRAINT channel_overrides_deny_check;
ALTER TABLE channel_overrides
    ADD CONSTRAINT channel_overrides_allow_check
        CHECK (allow >= 0 AND allow & ~6537855::bigint = 0),
    ADD CONSTRAINT channel_overrides_deny_check
        CHECK (deny >= 0 AND deny & ~6537855::bigint = 0);

CREATE OR REPLACE FUNCTION app_perms_of(p_user uuid)
RETURNS bigint
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT CASE
        WHEN m.user_id IS NULL THEN 0::bigint
        WHEN m.owner THEN 8388607::bigint
        ELSE coalesce((SELECT permissions FROM roles WHERE is_default), 0)
             | coalesce((SELECT bit_or(r.permissions)
                         FROM member_roles mr JOIN roles r ON r.id = mr.role_id
                         WHERE mr.user_id = p_user), 0)
    END
    FROM (SELECT p_user AS u) x
    LEFT JOIN memberships m ON m.user_id = x.u;
$$;

CREATE OR REPLACE FUNCTION app_room_perms_of(p_room uuid, p_user uuid)
RETURNS bigint
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_owner boolean;
    v_perms bigint;
    v_allow bigint;
    v_deny bigint;
BEGIN
    SELECT owner INTO v_owner FROM memberships WHERE user_id = p_user;
    IF v_owner IS NULL THEN
        RETURN 0;
    END IF;
    IF v_owner THEN
        RETURN 8388607;
    END IF;
    v_perms := app_perms_of(p_user);
    SELECT o.allow, o.deny INTO v_allow, v_deny
    FROM room_overrides o JOIN roles r ON r.id = o.role_id
    WHERE o.room_id = p_room AND r.is_default;
    IF FOUND THEN
        v_perms := (v_perms & ~v_deny) | v_allow;
    END IF;
    SELECT coalesce(bit_or(o.allow), 0), coalesce(bit_or(o.deny), 0) INTO v_allow, v_deny
    FROM room_overrides o JOIN member_roles mr ON mr.role_id = o.role_id
    WHERE o.room_id = p_room AND mr.user_id = p_user;
    RETURN (v_perms & ~v_deny) | v_allow;
END;
$$;

CREATE OR REPLACE FUNCTION app_channel_perms_of(p_channel uuid, p_user uuid)
RETURNS bigint
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_owner boolean;
    v_perms bigint;
    v_allow bigint;
    v_deny bigint;
BEGIN
    SELECT owner INTO v_owner FROM memberships WHERE user_id = p_user;
    IF v_owner IS NULL THEN
        RETURN 0;
    END IF;
    IF v_owner THEN
        RETURN 8388607;
    END IF;
    v_perms := app_perms_of(p_user);
    SELECT o.allow, o.deny INTO v_allow, v_deny
    FROM channel_overrides o JOIN roles r ON r.id = o.role_id
    WHERE o.channel_id = p_channel AND r.is_default;
    IF FOUND THEN
        v_perms := (v_perms & ~v_deny) | v_allow;
    END IF;
    SELECT coalesce(bit_or(o.allow), 0), coalesce(bit_or(o.deny), 0) INTO v_allow, v_deny
    FROM channel_overrides o JOIN member_roles mr ON mr.role_id = o.role_id
    WHERE o.channel_id = p_channel AND mr.user_id = p_user;
    RETURN (v_perms & ~v_deny) | v_allow;
END;
$$;

CREATE OR REPLACE FUNCTION app_set_override(p_room uuid, p_role uuid, p_allow bigint, p_deny bigint)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_actor uuid := app_uid();
    v_position integer;
BEGIN
    PERFORM app_require(1024);
    IF NOT app_room_has(p_room, 512) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rooms WHERE id = p_room) THEN
        RAISE EXCEPTION 'room not found' USING ERRCODE = 'P0002';
    END IF;
    SELECT position INTO v_position FROM roles WHERE id = p_role;
    IF v_position IS NULL THEN
        RAISE EXCEPTION 'role not found' USING ERRCODE = 'P0002';
    END IF;
    IF NOT app_owner_of(v_actor) AND v_position >= app_rank_of(v_actor) THEN
        RAISE EXCEPTION 'hierarchy' USING ERRCODE = '42501';
    END IF;
    IF p_allow IS NULL THEN
        DELETE FROM room_overrides WHERE room_id = p_room AND role_id = p_role;
    ELSE
        INSERT INTO room_overrides (room_id, role_id, allow, deny)
        VALUES (p_room, p_role, p_allow & 6537855, p_deny & 6537855 & ~p_allow)
        ON CONFLICT (room_id, role_id) DO UPDATE
        SET allow = EXCLUDED.allow, deny = EXCLUDED.deny;
    END IF;
    PERFORM app_audit('room.override', 'room',
                      jsonb_build_object('id', p_room, 'role_id', p_role,
                                         'allow', p_allow & 6537855,
                                         'deny', p_deny & 6537855 & ~coalesce(p_allow, 0)),
                      NULL, NULL);
END;
$$;

CREATE OR REPLACE FUNCTION app_set_channel_override(
    p_channel uuid,
    p_role uuid,
    p_allow bigint,
    p_deny bigint
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_actor uuid := app_uid();
    v_position integer;
    v_allow bigint;
    v_deny bigint;
BEGIN
    PERFORM app_msg_gate();
    PERFORM app_require(1024);
    IF NOT EXISTS (SELECT 1 FROM channels WHERE id = p_channel) THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    IF app_channel_perms_of(p_channel, v_actor) & 1 <> 1 THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    IF NOT app_channel_has(p_channel, 512) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    SELECT position INTO v_position FROM roles WHERE id = p_role;
    IF v_position IS NULL THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    IF NOT app_owner_of(v_actor) AND v_position >= app_rank_of(v_actor) THEN
        RAISE EXCEPTION 'hierarchy' USING ERRCODE = '42501';
    END IF;
    IF p_allow IS NULL THEN
        DELETE FROM channel_overrides WHERE channel_id = p_channel AND role_id = p_role;
    ELSE
        v_allow := p_allow & 6537855;
        v_deny := p_deny & 6537855 & ~v_allow;
        INSERT INTO channel_overrides (channel_id, role_id, allow, deny)
        VALUES (p_channel, p_role, v_allow, v_deny)
        ON CONFLICT (channel_id, role_id) DO UPDATE
        SET allow = EXCLUDED.allow, deny = EXCLUDED.deny;
    END IF;
    PERFORM app_audit(
        'channel.override', 'channel',
        jsonb_build_object('id', p_channel, 'role_id', p_role, 'allow', p_allow, 'deny', p_deny),
        NULL, NULL
    );
    PERFORM app_emit(
        'channel.updated',
        jsonb_build_object('channel', app_channel_json(p_channel))
    );
    RETURN app_channel_json(p_channel);
END;
$$;

-- 2. Roles: optional mentionable flag (column added above before updating roles).

DROP FUNCTION app_role_create(text, text, bigint, boolean);
CREATE FUNCTION app_role_create(
    p_name text,
    p_color text,
    p_perms bigint,
    p_hoist boolean,
    p_mentionable boolean DEFAULT false
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_actor uuid := app_uid();
    v_rank integer;
    v_position integer;
    v_id uuid;
BEGIN
    PERFORM app_require(1024);
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.owners'));
    IF NOT app_owner_of(v_actor) AND p_perms & ~app_perms_of(v_actor) <> 0 THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    v_rank := app_rank_of(v_actor);
    IF app_owner_of(v_actor) THEN
        SELECT coalesce(max(position), 0) + 1 INTO v_position FROM roles;
    ELSE
        v_position := greatest(v_rank, 1);
        UPDATE roles SET position = position + 1 WHERE position >= v_position;
    END IF;
    INSERT INTO roles (name, color, position, permissions, hoist, mentionable)
    VALUES (p_name, p_color, v_position, p_perms, coalesce(p_hoist, false), coalesce(p_mentionable, false))
    RETURNING id INTO v_id;
    PERFORM app_audit('role.create', 'role',
                      jsonb_build_object('id', v_id, 'name', p_name, 'permissions', p_perms,
                                         'mentionable', coalesce(p_mentionable, false)),
                      NULL, NULL);
    RETURN v_id;
END;
$$;

DROP FUNCTION app_role_update(uuid, text, text, bigint, boolean);
CREATE FUNCTION app_role_update(
    p_id uuid,
    p_name text,
    p_color text,
    p_perms bigint,
    p_hoist boolean,
    p_mentionable boolean DEFAULT false
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_actor uuid := app_uid();
    v_role roles%ROWTYPE;
BEGIN
    PERFORM app_require(1024);
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.owners'));
    SELECT * INTO v_role FROM roles WHERE id = p_id FOR UPDATE;
    IF v_role.id IS NULL THEN
        RAISE EXCEPTION 'role not found' USING ERRCODE = 'P0002';
    END IF;
    IF NOT app_owner_of(v_actor) THEN
        IF v_role.position >= app_rank_of(v_actor) THEN
            RAISE EXCEPTION 'hierarchy' USING ERRCODE = '42501';
        END IF;
        IF (p_perms # v_role.permissions) & ~app_perms_of(v_actor) <> 0 THEN
            RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
        END IF;
    END IF;
    IF v_role.is_default AND p_name <> v_role.name THEN
        RAISE EXCEPTION 'default role' USING ERRCODE = '22023';
    END IF;
    UPDATE roles
    SET name = p_name,
        color = p_color,
        permissions = p_perms,
        hoist = p_hoist,
        mentionable = coalesce(p_mentionable, false)
    WHERE id = p_id;
    PERFORM app_audit('role.update', 'role',
                      jsonb_build_object('id', p_id, 'name', p_name, 'color', p_color,
                                         'permissions', p_perms, 'hoist', p_hoist,
                                         'mentionable', coalesce(p_mentionable, false),
                                         'was', jsonb_build_object(
                                             'name', v_role.name, 'color', v_role.color,
                                             'permissions', v_role.permissions,
                                             'hoist', v_role.hoist,
                                             'mentionable', v_role.mentionable)),
                      NULL, NULL);
END;
$$;

REVOKE EXECUTE ON FUNCTION app_role_create(text, text, bigint, boolean, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_role_create(text, text, bigint, boolean, boolean) TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_role_update(uuid, text, text, bigint, boolean, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_role_update(uuid, text, text, bigint, boolean, boolean) TO app_runtime;

-- 3. Mentions table.

CREATE TABLE message_mentions (
    message_id uuid NOT NULL REFERENCES messages (id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('user', 'role', 'everyone')),
    target_id uuid,
    start_at integer NOT NULL CHECK (start_at >= 0),
    end_at integer NOT NULL CHECK (end_at > start_at),
    CHECK ((kind = 'everyone' AND target_id IS NULL) OR (kind <> 'everyone' AND target_id IS NOT NULL))
);

CREATE INDEX message_mentions_message ON message_mentions (message_id, start_at, end_at);
CREATE INDEX message_mentions_target ON message_mentions (target_id) WHERE kind = 'user';
CREATE INDEX message_mentions_role ON message_mentions (target_id) WHERE kind = 'role';

ALTER TABLE message_mentions ENABLE ROW LEVEL SECURITY;
ALTER TABLE message_mentions FORCE ROW LEVEL SECURITY;

REVOKE ALL ON message_mentions FROM app_runtime;

-- Validates and replaces mention rows for one plaintext message.
CREATE FUNCTION app_store_mentions(
    p_message uuid,
    p_kind text,
    p_channel uuid,
    p_low uuid,
    p_high uuid,
    p_body text,
    p_mentions jsonb
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_elem jsonb;
    v_mkind text;
    v_start integer;
    v_end integer;
    v_target_text text;
    v_target uuid;
    v_body_len integer := octet_length(coalesce(p_body, ''));
    v_mentionable boolean;
BEGIN
    DELETE FROM message_mentions WHERE message_id = p_message;
    IF p_mentions IS NULL THEN
        RETURN;
    END IF;
    IF jsonb_typeof(p_mentions) <> 'array' THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF jsonb_array_length(p_mentions) > 50 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    FOR v_elem IN SELECT value FROM jsonb_array_elements(p_mentions) LOOP
        IF jsonb_typeof(v_elem) <> 'object' THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
        v_mkind := v_elem->>'kind';
        IF v_mkind IS NULL OR v_mkind NOT IN ('user', 'role', 'everyone') THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
        BEGIN
            v_start := (v_elem->>'start')::integer;
            v_end := (v_elem->>'end')::integer;
        EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
            CONTINUE;
        END;
        IF v_start IS NULL OR v_end IS NULL OR v_start < 0 OR v_end <= v_start OR v_end > v_body_len THEN
            CONTINUE;
        END IF;
        IF v_mkind = 'everyone' THEN
            IF p_kind = 'channel' AND p_channel IS NOT NULL AND app_channel_has(p_channel, 4194304) THEN
                INSERT INTO message_mentions (message_id, kind, target_id, start_at, end_at)
                VALUES (p_message, 'everyone', NULL, v_start, v_end);
            END IF;
        ELSIF v_mkind = 'user' THEN
            v_target_text := v_elem->>'id';
            IF v_target_text IS NULL THEN
                CONTINUE;
            END IF;
            BEGIN
                v_target := v_target_text::uuid;
            EXCEPTION WHEN invalid_text_representation THEN
                CONTINUE;
            END;
            IF NOT EXISTS (SELECT 1 FROM users u WHERE u.id = v_target AND u.deleted_at IS NULL) THEN
                CONTINUE;
            END IF;
            IF NOT EXISTS (SELECT 1 FROM memberships m WHERE m.user_id = v_target)
               OR app_banned(v_target) THEN
                CONTINUE;
            END IF;
            IF p_kind = 'channel' THEN
                IF p_channel IS NULL OR app_channel_perms_of(p_channel, v_target) & 1 <> 1 THEN
                    CONTINUE;
                END IF;
            ELSE
                IF v_target NOT IN (p_low, p_high) THEN
                    CONTINUE;
                END IF;
            END IF;
            INSERT INTO message_mentions (message_id, kind, target_id, start_at, end_at)
            VALUES (p_message, 'user', v_target, v_start, v_end);
        ELSIF v_mkind = 'role' THEN
            IF p_kind <> 'channel' OR p_channel IS NULL THEN
                CONTINUE;
            END IF;
            v_target_text := v_elem->>'id';
            IF v_target_text IS NULL THEN
                CONTINUE;
            END IF;
            BEGIN
                v_target := v_target_text::uuid;
            EXCEPTION WHEN invalid_text_representation THEN
                CONTINUE;
            END;
            SELECT r.mentionable INTO v_mentionable
            FROM roles r WHERE r.id = v_target AND NOT r.is_default;
            IF NOT FOUND THEN
                CONTINUE;
            END IF;
            IF v_mentionable OR app_channel_has(p_channel, 4194304) THEN
                INSERT INTO message_mentions (message_id, kind, target_id, start_at, end_at)
                VALUES (p_message, 'role', v_target, v_start, v_end);
            END IF;
        END IF;
    END LOOP;
END;
$$;

REVOKE EXECUTE ON FUNCTION app_store_mentions(uuid, text, uuid, uuid, uuid, text, jsonb) FROM PUBLIC, app_runtime;

-- 4. Unread mention count beside app_unread, and channel/direct JSON.

CREATE OR REPLACE FUNCTION app_unread_mentions(p_kind text, p_conversation uuid)
RETURNS integer
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT count(*)::integer
    FROM messages m
    WHERE m.deleted_at IS NULL
      AND NOT m.e2ee
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
      )
      AND EXISTS (
          SELECT 1
          FROM message_mentions mm
          WHERE mm.message_id = m.id
            AND (
                (mm.kind = 'user' AND mm.target_id = app_uid())
                OR mm.kind = 'everyone'
                OR (mm.kind = 'role' AND EXISTS (
                    SELECT 1 FROM member_roles mr
                    WHERE mr.user_id = app_uid() AND mr.role_id = mm.target_id
                ))
            )
      );
$$;

REVOKE EXECUTE ON FUNCTION app_unread_mentions(text, uuid) FROM PUBLIC, app_runtime;

CREATE OR REPLACE FUNCTION app_channel_json(p_id uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT jsonb_build_object(
        'id', c.id::text,
        'category_id', c.category_id::text,
        'name', c.name,
        'topic', c.topic,
        'position', c.position,
        'created_by', c.created_by::text,
        'created_at', app_stamp(c.created_at),
        'e2ee', c.e2ee,
        'plaintext_history', c.e2ee AND app_e2ee_has_plaintext(c.id),
        'overrides', coalesce((
            SELECT jsonb_agg(jsonb_build_object(
                'role_id', o.role_id::text,
                'allow', o.allow,
                'deny', o.deny
            ) ORDER BY o.role_id)
            FROM channel_overrides o
            WHERE o.channel_id = c.id
        ), '[]'::jsonb),
        'unread', app_unread('channel', c.id),
        'mentions', app_unread_mentions('channel', c.id),
        'last_message', app_last_message(c.id, NULL)
    )
    FROM channels c
    WHERE c.id = p_id;
$$;

CREATE OR REPLACE FUNCTION app_direct_json(p_id uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT jsonb_build_object(
        'id', d.id::text,
        'created_at', app_stamp(d.created_at),
        'e2ee', d.e2ee,
        'plaintext_history', d.e2ee AND app_e2ee_has_plaintext(d.id),
        'peer', jsonb_build_object(
            'user_id', peer.id::text,
            'display_name', peer.display_name
        ),
        'unread', app_unread('direct', d.id),
        'mentions', app_unread_mentions('direct', d.id),
        'last_read', (
            SELECT r.message_id::text FROM reads r
            WHERE r.user_id = app_uid() AND r.kind = 'direct' AND r.conversation_id = d.id
        ),
        'peer_read', (
            SELECT r.message_id::text FROM reads r
            WHERE r.user_id = CASE WHEN d.low_user_id = app_uid() THEN d.high_user_id ELSE d.low_user_id END
              AND r.kind = 'direct' AND r.conversation_id = d.id
        ),
        'last_message', app_last_message(NULL, d.id),
        'last_call', (
            SELECT jsonb_build_object(
                'id', c.id::text,
                'outcome', c.outcome,
                'caller_id', c.caller_id::text,
                'accepted_at', app_stamp(c.accepted_at),
                'ended_at', app_stamp(c.ended_at)
            )
            FROM direct_call_log c
            WHERE c.direct_id = d.id
            ORDER BY c.ended_at DESC, c.id DESC
            LIMIT 1
        )
    )
    FROM directs d
    JOIN users peer ON peer.id = CASE
        WHEN d.low_user_id = app_uid() THEN d.high_user_id ELSE d.low_user_id END
    WHERE d.id = p_id AND app_uid() IN (d.low_user_id, d.high_user_id);
$$;

-- 5. Message JSON: mentions on plaintext rows, absent on encrypted rows.

CREATE OR REPLACE FUNCTION app_message_json(p_id uuid, p_viewer uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT jsonb_build_object(
        'id', m.id::text,
        'author_id', m.author_id::text,
        'body', CASE WHEN m.deleted_at IS NULL THEN m.body ELSE '' END,
        'reply_to', m.reply_to::text,
        'client_id', m.client_id,
        'created_at', app_stamp(m.created_at),
        'edited_at', CASE WHEN m.edited_at IS NULL THEN NULL ELSE app_stamp(m.edited_at) END,
        'deleted_at', CASE WHEN m.deleted_at IS NULL THEN NULL ELSE app_stamp(m.deleted_at) END,
        'deleted_by', CASE WHEN m.deleted_by <> m.author_id THEN m.deleted_by::text END,
        'e2ee', m.e2ee,
        'attachments', coalesce((
            SELECT jsonb_agg(jsonb_build_object(
                'id', a.id::text,
                'name', a.name,
                'mime', a.mime,
                'kind', a.kind,
                'bytes', a.bytes,
                'width', a.width,
                'height', a.height,
                'duration', a.duration
            ) ORDER BY a.sort, a.created_at, a.id)
            FROM attachments a
            WHERE a.message_id = m.id AND m.deleted_at IS NULL
        ), '[]'::jsonb),
        'reactions', coalesce((
            SELECT jsonb_agg(jsonb_build_object(
                'emoji', r.emoji,
                'count', r.count,
                'me', r.me
            ) ORDER BY r.emoji)
            FROM (
                SELECT emoji, count(*) AS count, bool_or(user_id = p_viewer) AS me
                FROM reactions
                WHERE message_id = m.id AND m.deleted_at IS NULL
                GROUP BY emoji
            ) r
        ), '[]'::jsonb)
    ) || CASE WHEN m.e2ee THEN jsonb_build_object(
        'kind', m.msg_kind,
        'ciphertext', CASE WHEN m.deleted_at IS NULL
            THEN translate(encode(m.ciphertext, 'base64'), E'\n', '') END,
        'epoch', m.epoch,
        'generation', m.generation,
        'group_id', m.group_id::text,
        'device_id', m.device_id::text,
        'target_id', m.target_id::text,
        'seq', m.seq
    ) ELSE jsonb_build_object(
        'mentions', coalesce((
            SELECT jsonb_agg(
                CASE WHEN mm.target_id IS NULL THEN
                    jsonb_build_object('kind', mm.kind, 'start', mm.start_at, 'end', mm.end_at)
                ELSE
                    jsonb_build_object('kind', mm.kind, 'id', mm.target_id::text, 'start', mm.start_at, 'end', mm.end_at)
                END
                ORDER BY mm.start_at, mm.end_at, mm.kind, mm.target_id
            )
            FROM message_mentions mm
            WHERE mm.message_id = m.id AND m.deleted_at IS NULL
        ), '[]'::jsonb)
    ) END
    FROM messages m
    WHERE m.id = p_id;
$$;

-- 6. Post, edit, delete messages.

DROP FUNCTION app_post_message(uuid, text, uuid, text, uuid[]);
CREATE FUNCTION app_post_message(
    p_conversation uuid,
    p_body text,
    p_reply uuid,
    p_client text,
    p_attachments uuid[],
    p_mentions jsonb DEFAULT NULL
)
RETURNS jsonb
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
    v_body text := coalesce(btrim(p_body), '');
    v_client text := nullif(btrim(p_client), '');
    v_id uuid;
    v_existing uuid;
    v_linked integer;
    v_payload jsonb;
BEGIN
    SELECT kind, channel_id, direct_id, low_user_id, high_user_id
    INTO v_kind, v_channel, v_direct, v_low, v_high
    FROM app_open_conversation(p_conversation, true);
    IF app_conv_e2ee(p_conversation) THEN
        RAISE EXCEPTION 'e2ee required' USING ERRCODE = 'P0E01';
    END IF;
    PERFORM app_e2ee_plaintext_allowed();
    IF v_client IS NOT NULL AND (
        char_length(v_client) > 64 OR v_client ~ E'[\\x00-\\x1F\\x7F]'
    ) THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF v_client IS NOT NULL THEN
        SELECT id INTO v_existing
        FROM messages
        WHERE author_id = app_uid() AND client_id = v_client AND NOT e2ee;
        IF FOUND THEN
            RETURN app_message_json(v_existing, app_uid());
        END IF;
    END IF;
    IF char_length(v_body) > 4000 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF v_body = '' AND coalesce(cardinality(p_attachments), 0) = 0 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF p_reply IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM messages m
        WHERE m.id = p_reply
          AND (m.channel_id IS NOT DISTINCT FROM v_channel)
          AND (m.direct_id IS NOT DISTINCT FROM v_direct)
    ) THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    IF coalesce(cardinality(p_attachments), 0) > 0 THEN
        IF (
            SELECT count(*) FROM attachments a
            WHERE a.id = ANY (p_attachments)
              AND a.uploader_id = app_uid()
              AND a.message_id IS NULL
              AND a.created_at > now() - interval '1 hour'
              AND a.scan_status = 'clean'
              AND a.kind <> 'sealed'
        ) <> cardinality(p_attachments) THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
    END IF;
    BEGIN
        INSERT INTO messages (channel_id, direct_id, author_id, body, reply_to, client_id)
        VALUES (v_channel, v_direct, app_uid(), v_body, p_reply, v_client)
        RETURNING id INTO v_id;
    EXCEPTION
        WHEN unique_violation THEN
            SELECT id INTO v_existing
            FROM messages
            WHERE author_id = app_uid() AND client_id = v_client AND NOT e2ee;
            RETURN app_message_json(v_existing, app_uid());
    END;
    IF coalesce(cardinality(p_attachments), 0) > 0 THEN
        UPDATE attachments a
        SET message_id = v_id, sort = s.ord::integer
        FROM unnest(p_attachments) WITH ORDINALITY AS s(id, ord)
        WHERE a.id = s.id
          AND a.uploader_id = app_uid()
          AND a.message_id IS NULL
          AND a.scan_status = 'clean'
          AND a.kind <> 'sealed';
        GET DIAGNOSTICS v_linked = ROW_COUNT;
        IF v_linked <> cardinality(p_attachments) THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
    END IF;
    PERFORM app_store_mentions(v_id, v_kind, v_channel, v_low, v_high, v_body, p_mentions);
    v_payload := jsonb_build_object(
        'conversation_id', p_conversation::text,
        'kind', v_kind,
        'message', app_message_json(v_id, app_uid())
    );
    PERFORM app_emit_to('message.created', v_payload, app_audience(v_kind, v_low, v_high));
    RETURN v_payload->'message';
END;
$$;

DROP FUNCTION app_edit_message(uuid, text);
CREATE FUNCTION app_edit_message(
    p_id uuid,
    p_body text,
    p_mentions jsonb DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_author uuid;
    v_channel uuid;
    v_direct uuid;
    v_deleted timestamptz;
    v_e2ee boolean;
    v_body text := coalesce(btrim(p_body), '');
    v_kind text;
    v_low uuid;
    v_high uuid;
    v_conv uuid;
    v_files integer;
BEGIN
    PERFORM app_msg_voice();
    SELECT author_id, channel_id, direct_id, deleted_at, e2ee
    INTO v_author, v_channel, v_direct, v_deleted, v_e2ee
    FROM messages WHERE id = p_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    v_conv := coalesce(v_channel, v_direct);
    SELECT kind, low_user_id, high_user_id INTO v_kind, v_low, v_high
    FROM app_open_conversation(v_conv, true);
    IF v_e2ee THEN
        RAISE EXCEPTION 'e2ee required' USING ERRCODE = 'P0E01';
    END IF;
    PERFORM app_e2ee_plaintext_allowed();
    IF v_author <> app_uid() THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    IF v_deleted IS NOT NULL THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF char_length(v_body) > 4000 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    SELECT count(*) INTO v_files FROM attachments WHERE message_id = p_id;
    IF v_body = '' AND v_files = 0 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    UPDATE messages SET body = v_body, edited_at = now() WHERE id = p_id;
    PERFORM app_store_mentions(p_id, v_kind, v_channel, v_low, v_high, v_body, p_mentions);
    PERFORM app_emit_to(
        'message.edited',
        jsonb_build_object(
            'conversation_id', v_conv::text,
            'kind', v_kind,
            'message', app_message_json(p_id, app_uid())
        ),
        app_audience(v_kind, v_low, v_high)
    );
    RETURN app_message_json(p_id, app_uid());
END;
$$;

REVOKE EXECUTE ON FUNCTION app_post_message(uuid, text, uuid, text, uuid[], jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_post_message(uuid, text, uuid, text, uuid[], jsonb) TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_edit_message(uuid, text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_edit_message(uuid, text, jsonb) TO app_runtime;

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
    v_mine boolean;
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
    v_mine := v_author = app_uid();
    v_conv := coalesce(v_channel, v_direct);
    SELECT kind, low_user_id, high_user_id INTO v_kind, v_low, v_high
    FROM app_open_conversation(v_conv, v_mine);
    IF NOT v_mine AND NOT (v_channel IS NOT NULL AND app_channel_has(v_channel, 2097152)) THEN
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
    DELETE FROM message_mentions WHERE message_id = ANY (v_all);
    UPDATE messages SET body = '', deleted_at = now(),
        deleted_by = CASE WHEN v_mine THEN NULL ELSE app_uid() END
    WHERE id = ANY (v_all) AND deleted_at IS NULL;
    IF NOT v_mine THEN
        PERFORM app_audit('message.delete', 'message',
                          jsonb_build_object('message_id', p_id, 'channel_id', v_channel),
                          v_author, NULL);
    END IF;
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

-- 7. Account deletion and role deletion clear mention rows pointing at them.

CREATE FUNCTION app_mentions_forget_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    DELETE FROM message_mentions
    WHERE (kind = 'user' AND target_id = NEW.id)
       OR message_id IN (SELECT m.id FROM messages m WHERE m.author_id = NEW.id);
    RETURN NULL;
END;
$$;

REVOKE EXECUTE ON FUNCTION app_mentions_forget_user() FROM PUBLIC;

CREATE TRIGGER users_forget_message_mentions
    AFTER UPDATE OF deleted_at ON users
    FOR EACH ROW
    WHEN (OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL)
    EXECUTE FUNCTION app_mentions_forget_user();

CREATE FUNCTION app_mentions_forget_role()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    DELETE FROM message_mentions
    WHERE kind = 'role' AND target_id = OLD.id;
    RETURN NULL;
END;
$$;

REVOKE EXECUTE ON FUNCTION app_mentions_forget_role() FROM PUBLIC;

CREATE TRIGGER roles_forget_message_mentions
    AFTER DELETE ON roles
    FOR EACH ROW
    EXECUTE FUNCTION app_mentions_forget_role();

-- Rollback: crates/db/rollback/0049_message_mentions.down.sql drops the triggers,
-- message_mentions table, unread-mentions helper, roles.mentionable, and restores bit masks
-- to 4194303 / 2343551 and the 0045/0046 functions.
