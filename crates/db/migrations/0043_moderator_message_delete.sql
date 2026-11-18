-- 0042 is staged by other pull requests; renumber to the next free number at rebase time.
--
-- A moderator can delete another member's message. Issue #70.
--
-- Permission bit 21, `manage_messages`, is 1 << 21 = 2097152. All bits are now 4194303, and the
-- override mask is now 2343551: the bit is channel-scoped, so a room or channel override may
-- allow or deny it like view_channel or manage_channels. It is NOT part of @everyone (63).
-- Existing roles: every owner has it through the owner flag, as owners have every bit; every
-- role other than @everyone that already held manage_server (524288) gets it, which includes
-- the "Admin" role every server upgraded from the three fixed roles has. @everyone is excluded
-- on purpose, and so is every other role: deleting other people's messages is handed out
-- deliberately, one role at a time. The rule is the one 0015_abuse_reports.sql used for
-- manage_reports.
--
-- A delete stays the author's tombstone. The body (or the ciphertext) is cleared, attachment
-- and reaction rows go, the files are returned for deletion, and the outbox rows are scrubbed.
-- What changes is who may run it: the author, as before, or a holder of manage_messages in the
-- channel the message sits in, found through the same app_channel_has every channel check uses.
-- A direct stays author-only. The moderator needs view_channel, not speak, and the function
-- never reads the message's text: the tombstone writes '' over it and the frame carries ids,
-- never content. A moderator who cannot view the channel still gets "not found", as before.
--
-- The action is audited `message.delete` when the actor is not the author: actor, the author as
-- its subject, and ids in the detail. No text, no ciphertext, no attachment names. The row sits
-- in the audit log beside the kick, ban and timeout rows a report links today.
--
-- `messages.deleted_by` says who removed a message when that was not the author. It rides the
-- message JSON and the `message.deleted` frame as `deleted_by`, so a client can say "removed by
-- a moderator". An author's own delete leaves it NULL and every frame keeps its old shape.
-- Older clients ignore the extra key, as they do every added one.

-- 1. The permission bit.

ALTER TABLE roles DROP CONSTRAINT roles_permissions_check;
ALTER TABLE roles
    ADD CONSTRAINT roles_permissions_check
    CHECK (permissions >= 0 AND permissions <= 4194303);

UPDATE roles SET permissions = permissions | 2097152
WHERE NOT is_default AND permissions & 524288 <> 0;

-- 2. The override mask. A room or channel override may now hold manage_messages too. The set
-- functions below clip again on the way in, so they move with the mask.

ALTER TABLE room_overrides DROP CONSTRAINT room_overrides_allow_check;
ALTER TABLE room_overrides DROP CONSTRAINT room_overrides_deny_check;
ALTER TABLE room_overrides
    ADD CONSTRAINT room_overrides_allow_check
        CHECK (allow >= 0 AND allow & ~2343551::bigint = 0),
    ADD CONSTRAINT room_overrides_deny_check
        CHECK (deny >= 0 AND deny & ~2343551::bigint = 0);

ALTER TABLE channel_overrides DROP CONSTRAINT channel_overrides_allow_check;
ALTER TABLE channel_overrides DROP CONSTRAINT channel_overrides_deny_check;
ALTER TABLE channel_overrides
    ADD CONSTRAINT channel_overrides_allow_check
        CHECK (allow >= 0 AND allow & ~2343551::bigint = 0),
    ADD CONSTRAINT channel_overrides_deny_check
        CHECK (deny >= 0 AND deny & ~2343551::bigint = 0);

-- Owners hold every bit. These three functions spelled "every bit" as 2097151.

CREATE OR REPLACE FUNCTION app_perms_of(p_user uuid)
RETURNS bigint
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT CASE
        WHEN m.user_id IS NULL THEN 0::bigint
        WHEN m.owner THEN 4194303::bigint
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
        RETURN 4194303;
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
        RETURN 4194303;
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

-- The override writers spelled the mask as 246399 and would have dropped the bit silently.

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
        VALUES (p_room, p_role, p_allow & 2343551, p_deny & 2343551 & ~p_allow)
        ON CONFLICT (room_id, role_id) DO UPDATE
        SET allow = EXCLUDED.allow, deny = EXCLUDED.deny;
    END IF;
    PERFORM app_audit('room.override', 'room',
                      jsonb_build_object('id', p_room, 'role_id', p_role,
                                         'allow', p_allow & 2343551,
                                         'deny', p_deny & 2343551 & ~coalesce(p_allow, 0)),
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
        v_allow := p_allow & 2343551;
        v_deny := p_deny & 2343551 & ~v_allow;
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

-- 3. Who removed it. NULL when the author did, and NULL again if the author's account goes.
--    The key is attached NOT VALID and validated in a second pass: validating scans messages
--    under a lock that lets writes continue, where an inline key would stop them for the scan.

ALTER TABLE messages ADD COLUMN deleted_by uuid;
ALTER TABLE messages ADD CONSTRAINT messages_deleted_by_fkey
    FOREIGN KEY (deleted_by) REFERENCES users (id) ON DELETE SET NULL NOT VALID;
ALTER TABLE messages VALIDATE CONSTRAINT messages_deleted_by_fkey;

-- 4. The message JSON says so. The key is NULL on every message nobody else removed.

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
        'device_id', m.device_id::text,
        'target_id', m.target_id::text
    ) ELSE '{}'::jsonb END
    FROM messages m
    WHERE m.id = p_id;
$$;

-- 5. The delete. The author, as before; or manage_messages in the message's channel. The checks
-- keep their order, so every refusal a caller could get before, they still get: a message that
-- does not exist, or a channel the caller cannot view, is "not found" before any of this talks.

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
    -- The author opens with speak, as before. A moderator opens without it: removing a message
    -- is not posting one. Whoever cannot open the conversation gets "not found" here.
    SELECT kind, low_user_id, high_user_id INTO v_kind, v_low, v_high
    FROM app_open_conversation(v_conv, v_mine);
    -- A direct stays author-only. In a channel the same app_channel_has every channel check
    -- uses decides, and an owner holds every bit through the owner flag.
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

-- Rollback: crates/db/rollback/0043_moderator_message_delete.down.sql drops the column, puts
-- the masks and the three functions back to 2097151 and 246399, and puts the author-only delete
-- back. Tombstoned rows stay tombstoned; a deleted_by the column held is gone with it.
