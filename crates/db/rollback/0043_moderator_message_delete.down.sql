-- Undoes migrations/0043_moderator_message_delete.sql. Run as the owner role, in one
-- transaction, then start the previous image. It strips the bit from every row that holds it,
-- puts the masks and the function bodies back to their 0005, 0008, 0015 and 0022 shapes, drops
-- the column, and leaves the tombstones: a message a moderator removed stays removed, and only
-- the record of who removed it goes with the column.

BEGIN;

-- 1. The bit and the rows that hold it. The constraints come back only after nothing holds
--    the bit any more, and role permissions are stripped before the constraint on roles.

UPDATE roles SET permissions = permissions & ~2097152;
UPDATE room_overrides SET allow = allow & ~2097152, deny = deny & ~2097152;
UPDATE channel_overrides SET allow = allow & ~2097152, deny = deny & ~2097152;

ALTER TABLE roles DROP CONSTRAINT roles_permissions_check;
ALTER TABLE roles
    ADD CONSTRAINT roles_permissions_check
    CHECK (permissions >= 0 AND permissions <= 2097151);

ALTER TABLE room_overrides DROP CONSTRAINT room_overrides_allow_check;
ALTER TABLE room_overrides DROP CONSTRAINT room_overrides_deny_check;
ALTER TABLE room_overrides
    ADD CONSTRAINT room_overrides_allow_check
        CHECK (allow >= 0 AND allow & ~246399::bigint = 0),
    ADD CONSTRAINT room_overrides_deny_check
        CHECK (deny >= 0 AND deny & ~246399::bigint = 0);

ALTER TABLE channel_overrides DROP CONSTRAINT channel_overrides_allow_check;
ALTER TABLE channel_overrides DROP CONSTRAINT channel_overrides_deny_check;
ALTER TABLE channel_overrides
    ADD CONSTRAINT channel_overrides_allow_check
        CHECK (allow >= 0 AND allow & ~246399::bigint = 0),
    ADD CONSTRAINT channel_overrides_deny_check
        CHECK (deny >= 0 AND deny & ~246399::bigint = 0);

-- 2. The function bodies, as 0015, 0005, 0008, 0022 and 0022 had them.

CREATE OR REPLACE FUNCTION app_perms_of(p_user uuid)
RETURNS bigint
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT CASE
        WHEN m.user_id IS NULL THEN 0::bigint
        WHEN m.owner THEN 2097151::bigint
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
        RETURN 2097151;
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
        RETURN 2097151;
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
        VALUES (p_room, p_role, p_allow & 246399, p_deny & 246399 & ~p_allow)
        ON CONFLICT (room_id, role_id) DO UPDATE
        SET allow = EXCLUDED.allow, deny = EXCLUDED.deny;
    END IF;
    PERFORM app_audit('room.override', 'room',
                      jsonb_build_object('id', p_room, 'role_id', p_role,
                                         'allow', p_allow & 246399,
                                         'deny', p_deny & 246399 & ~coalesce(p_allow, 0)),
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
        v_allow := p_allow & 246399;
        v_deny := p_deny & 246399 & ~v_allow;
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
        'device_id', m.device_id::text,
        'target_id', m.target_id::text
    ) ELSE '{}'::jsonb END
    FROM messages m
    WHERE m.id = p_id;
$$;

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

-- 3. The column. The message.delete audit rows stay: they say a moderation happened, and
--    deleting history is not what a rollback is for.

ALTER TABLE messages DROP COLUMN deleted_by;

COMMIT;
