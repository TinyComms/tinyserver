-- Text channels, direct messages, messages, reactions, read cursors, and attachments.
-- Applies after 0007_e2ee.sql. It uses categories, roles, channel-scoped permission bits,
-- bans, timeouts, and app_emit from that schema. It does not apply to a database whose
-- newest migration is 0004.

DO $$
BEGIN
    IF to_regprocedure('app_perms_of(uuid)') IS NULL
       OR to_regprocedure('app_room_perms_of(uuid, uuid)') IS NULL
       OR to_regprocedure('app_banned(uuid)') IS NULL
       OR to_regprocedure('app_is_member()') IS NULL
       OR to_regclass('public.categories') IS NULL
       OR to_regclass('public.roles') IS NULL
       OR NOT EXISTS (
           SELECT 1 FROM information_schema.columns
           WHERE table_schema = 'public' AND table_name = 'memberships'
             AND column_name = 'timeout_until'
       ) THEN
        RAISE EXCEPTION '0008_messages.sql applies after 0007_e2ee.sql';
    END IF;
END $$;

-- Some live events are only for a set of user ids. NULL is every member socket.
ALTER TABLE outbox ADD COLUMN audience uuid[];

-- A targeted emit. NULL audience is everyone, the same as app_emit.
CREATE FUNCTION app_emit_to(p_topic text, p_payload jsonb, p_audience uuid[])
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_id bigint;
BEGIN
    IF p_topic !~ '^[a-z]+\.[a-z_]+$' THEN
        RAISE EXCEPTION 'invalid topic' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.outbox'));
    INSERT INTO outbox (topic, payload, audience)
    VALUES (p_topic, p_payload, p_audience)
    RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION app_emit_to(text, jsonb, uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_emit_to(text, jsonb, uuid[]) TO app_runtime;

CREATE TABLE channels (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    category_id uuid REFERENCES categories (id) ON DELETE SET NULL,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
    topic text NOT NULL DEFAULT '' CHECK (char_length(topic) <= 1024),
    position integer NOT NULL DEFAULT 0,
    created_by uuid NOT NULL REFERENCES users (id),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX channels_category ON channels (category_id);

-- Same shape as room_overrides. Bits are the channel-scoped mask, 246399.
CREATE TABLE channel_overrides (
    channel_id uuid NOT NULL REFERENCES channels (id) ON DELETE CASCADE,
    role_id uuid NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    allow bigint NOT NULL DEFAULT 0 CHECK (allow >= 0 AND allow & ~246399::bigint = 0),
    deny bigint NOT NULL DEFAULT 0 CHECK (deny >= 0 AND deny & ~246399::bigint = 0),
    PRIMARY KEY (channel_id, role_id),
    CHECK (allow & deny = 0)
);

CREATE INDEX channel_overrides_role ON channel_overrides (role_id);

-- The pair is stored in uuid order, so one row is one conversation.
CREATE TABLE directs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    low_user_id uuid NOT NULL REFERENCES users (id),
    high_user_id uuid NOT NULL REFERENCES users (id),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (low_user_id < high_user_id),
    UNIQUE (low_user_id, high_user_id)
);

CREATE TABLE messages (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    channel_id uuid REFERENCES channels (id) ON DELETE CASCADE,
    direct_id uuid REFERENCES directs (id) ON DELETE CASCADE,
    author_id uuid NOT NULL REFERENCES users (id),
    body text NOT NULL DEFAULT '' CHECK (char_length(body) <= 4000),
    reply_to uuid REFERENCES messages (id) ON DELETE SET NULL,
    client_id text CHECK (
        client_id IS NULL OR char_length(client_id) BETWEEN 1 AND 64
    ),
    created_at timestamptz NOT NULL DEFAULT now(),
    edited_at timestamptz,
    deleted_at timestamptz,
    CHECK ((channel_id IS NULL) <> (direct_id IS NULL))
);

CREATE UNIQUE INDEX messages_client
    ON messages (author_id, client_id)
    WHERE client_id IS NOT NULL;

CREATE INDEX messages_channel_order
    ON messages (channel_id, created_at, id)
    WHERE channel_id IS NOT NULL;

CREATE INDEX messages_direct_order
    ON messages (direct_id, created_at, id)
    WHERE direct_id IS NOT NULL;

CREATE TABLE attachments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id uuid REFERENCES messages (id) ON DELETE CASCADE,
    uploader_id uuid NOT NULL REFERENCES users (id),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    mime text NOT NULL CHECK (char_length(mime) BETWEEN 1 AND 127),
    kind text NOT NULL CHECK (kind IN ('image', 'gif', 'video', 'file')),
    bytes integer NOT NULL CHECK (bytes > 0 AND bytes <= 26214400),
    width integer CHECK (width IS NULL OR width >= 0),
    height integer CHECK (height IS NULL OR height >= 0),
    duration integer CHECK (duration IS NULL OR duration >= 0),
    sort integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (
        (kind IN ('image', 'gif') AND bytes <= 8388608)
        OR kind IN ('video', 'file')
    )
);

CREATE INDEX attachments_message ON attachments (message_id, sort, created_at, id);
CREATE INDEX attachments_orphan ON attachments (created_at) WHERE message_id IS NULL;

CREATE TABLE reactions (
    message_id uuid NOT NULL REFERENCES messages (id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    emoji text NOT NULL CHECK (char_length(emoji) BETWEEN 1 AND 16),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (message_id, user_id, emoji)
);

CREATE TABLE reads (
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('channel', 'direct')),
    conversation_id uuid NOT NULL,
    message_id uuid NOT NULL REFERENCES messages (id) ON DELETE CASCADE,
    read_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, kind, conversation_id)
);

-- Permissions in one text channel. Owners have every bit. Everyone else: base permissions,
-- then the @everyone override, then the OR of their other roles' overrides.
CREATE FUNCTION app_channel_perms_of(p_channel uuid, p_user uuid)
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
        RETURN 1048575;
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

CREATE FUNCTION app_channel_has(p_channel uuid, p_bits bigint)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT (app_channel_perms_of(p_channel, app_uid()) & p_bits) = p_bits;
$$;

-- A signed-in member who is not banned. Timeouts still read.
CREATE FUNCTION app_msg_gate()
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    IF NOT app_is_member() THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    IF app_banned(app_uid()) THEN
        RAISE EXCEPTION 'banned' USING ERRCODE = '42501';
    END IF;
END;
$$;

-- Posting, reacting, uploading, and typing. A timeout cannot.
CREATE FUNCTION app_msg_voice()
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    PERFORM app_msg_gate();
    IF EXISTS (
        SELECT 1 FROM memberships
        WHERE user_id = app_uid() AND timeout_until > now()
    ) THEN
        RAISE EXCEPTION 'timed out' USING ERRCODE = '42501';
    END IF;
END;
$$;

CREATE FUNCTION app_stamp(p_at timestamptz)
RETURNS text
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT to_char(p_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"');
$$;

CREATE FUNCTION app_message_json(p_id uuid, p_viewer uuid)
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
    )
    FROM messages m
    WHERE m.id = p_id;
$$;

CREATE FUNCTION app_last_message(p_channel uuid, p_direct uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT jsonb_build_object(
        'id', m.id::text,
        'author_id', m.author_id::text,
        'body', left(m.body, 200),
        'created_at', app_stamp(m.created_at)
    )
    FROM messages m
    WHERE m.deleted_at IS NULL
      AND (m.channel_id = p_channel OR m.direct_id = p_direct)
    ORDER BY m.created_at DESC, m.id DESC
    LIMIT 1;
$$;

CREATE FUNCTION app_unread(p_kind text, p_conversation uuid)
RETURNS integer
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT count(*)::integer
    FROM messages m
    WHERE m.deleted_at IS NULL
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
            AND (m.created_at, m.id) <= (cursor_message.created_at, cursor_message.id)
      );
$$;

CREATE FUNCTION app_channel_json(p_id uuid)
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
        'last_message', app_last_message(c.id, NULL)
    )
    FROM channels c
    WHERE c.id = p_id;
$$;

-- Resolves a conversation the caller can see. Raises not found otherwise.
-- p_need_speak also requires speak and a voice that is not timed out.
CREATE FUNCTION app_open_conversation(p_id uuid, p_need_speak boolean)
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

CREATE FUNCTION app_list_channels()
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT coalesce(jsonb_agg(app_channel_json(c.id) ORDER BY c.position, c.name, c.id), '[]'::jsonb)
    FROM channels c
    WHERE app_channel_perms_of(c.id, app_uid()) & 1 = 1
      AND app_is_member()
      AND NOT app_banned(app_uid());
$$;

CREATE FUNCTION app_create_channel(
    p_name text,
    p_category uuid,
    p_topic text,
    p_position integer
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_id uuid;
    v_name text := btrim(p_name);
    v_topic text := coalesce(btrim(p_topic), '');
BEGIN
    PERFORM app_msg_gate();
    IF NOT app_has(512) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    IF v_name IS NULL OR char_length(v_name) < 1 OR char_length(v_name) > 80
       OR char_length(v_topic) > 1024 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF p_category IS NOT NULL AND NOT EXISTS (SELECT 1 FROM categories WHERE id = p_category) THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    INSERT INTO channels (category_id, name, topic, position, created_by)
    VALUES (p_category, v_name, v_topic, coalesce(p_position, 0), app_uid())
    RETURNING id INTO v_id;
    PERFORM app_audit(
        'channel.create', 'channel',
        jsonb_build_object('id', v_id, 'name', v_name),
        NULL, NULL
    );
    PERFORM app_emit('channel.created', jsonb_build_object('channel', app_channel_json(v_id)));
    RETURN app_channel_json(v_id);
END;
$$;

CREATE FUNCTION app_update_channel(p_id uuid, p_patch jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_name text;
    v_topic text;
    v_position integer;
    v_category uuid;
BEGIN
    PERFORM app_msg_gate();
    IF NOT EXISTS (SELECT 1 FROM channels WHERE id = p_id) THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    IF app_channel_perms_of(p_id, app_uid()) & 1 <> 1 THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    IF NOT app_channel_has(p_id, 512) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    IF p_patch IS NULL OR p_patch = '{}'::jsonb THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF p_patch ? 'name' THEN
        v_name := btrim(p_patch->>'name');
        IF v_name IS NULL OR char_length(v_name) < 1 OR char_length(v_name) > 80 THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
        UPDATE channels SET name = v_name WHERE id = p_id;
    END IF;
    IF p_patch ? 'topic' THEN
        v_topic := coalesce(btrim(p_patch->>'topic'), '');
        IF char_length(v_topic) > 1024 THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
        UPDATE channels SET topic = v_topic WHERE id = p_id;
    END IF;
    IF p_patch ? 'position' THEN
        v_position := (p_patch->>'position')::integer;
        UPDATE channels SET position = v_position WHERE id = p_id;
    END IF;
    IF p_patch ? 'category_id' THEN
        IF p_patch->'category_id' = 'null'::jsonb OR p_patch->>'category_id' IS NULL THEN
            UPDATE channels SET category_id = NULL WHERE id = p_id;
        ELSE
            v_category := (p_patch->>'category_id')::uuid;
            IF NOT EXISTS (SELECT 1 FROM categories WHERE id = v_category) THEN
                RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
            END IF;
            UPDATE channels SET category_id = v_category WHERE id = p_id;
        END IF;
    END IF;
    PERFORM app_audit(
        'channel.update', 'channel',
        jsonb_build_object('id', p_id),
        NULL, NULL
    );
    PERFORM app_emit('channel.updated', jsonb_build_object('channel', app_channel_json(p_id)));
    RETURN app_channel_json(p_id);
END;
$$;

CREATE FUNCTION app_delete_channel(p_id uuid)
RETURNS text[]
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_files text[];
BEGIN
    PERFORM app_msg_gate();
    IF NOT EXISTS (SELECT 1 FROM channels WHERE id = p_id) THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    IF app_channel_perms_of(p_id, app_uid()) & 1 <> 1 THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    IF NOT app_channel_has(p_id, 512) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    SELECT coalesce(array_agg(a.id::text), '{}') INTO v_files
    FROM attachments a
    JOIN messages m ON m.id = a.message_id
    WHERE m.channel_id = p_id;
    DELETE FROM reads WHERE kind = 'channel' AND conversation_id = p_id;
    DELETE FROM channels WHERE id = p_id;
    PERFORM app_audit('channel.delete', 'channel', jsonb_build_object('id', p_id), NULL, NULL);
    PERFORM app_emit('channel.deleted', jsonb_build_object('channel_id', p_id));
    RETURN v_files;
END;
$$;

-- Like room overrides: manage_roles, manage_channels in the channel, and a role below the caller.
-- A null allow deletes the row.
CREATE FUNCTION app_set_channel_override(
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

CREATE FUNCTION app_direct_json(p_id uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT jsonb_build_object(
        'id', d.id::text,
        'created_at', app_stamp(d.created_at),
        'peer', jsonb_build_object(
            'user_id', peer.id::text,
            'display_name', peer.display_name
        ),
        'unread', app_unread('direct', d.id),
        'last_read', (
            SELECT r.message_id::text FROM reads r
            WHERE r.user_id = app_uid() AND r.kind = 'direct' AND r.conversation_id = d.id
        ),
        'peer_read', (
            SELECT r.message_id::text FROM reads r
            WHERE r.user_id = CASE WHEN d.low_user_id = app_uid() THEN d.high_user_id ELSE d.low_user_id END
              AND r.kind = 'direct' AND r.conversation_id = d.id
        ),
        'last_message', app_last_message(NULL, d.id)
    )
    FROM directs d
    JOIN users peer ON peer.id = CASE
        WHEN d.low_user_id = app_uid() THEN d.high_user_id ELSE d.low_user_id END
    WHERE d.id = p_id AND app_uid() IN (d.low_user_id, d.high_user_id);
$$;

CREATE FUNCTION app_list_directs()
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT coalesce(
        jsonb_agg(app_direct_json(d.id) ORDER BY d.created_at, d.id),
        '[]'::jsonb
    )
    FROM directs d
    WHERE app_uid() IN (d.low_user_id, d.high_user_id)
      AND app_is_member()
      AND NOT app_banned(app_uid());
$$;

-- Get or create the direct conversation with another current member. Neither may be banned.
CREATE FUNCTION app_open_direct(p_user uuid, OUT body jsonb, OUT created boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_low uuid;
    v_high uuid;
    v_id uuid;
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
    SELECT id INTO v_id FROM directs WHERE low_user_id = v_low AND high_user_id = v_high;
    IF FOUND THEN
        body := app_direct_json(v_id);
        created := false;
        RETURN;
    END IF;
    INSERT INTO directs (low_user_id, high_user_id) VALUES (v_low, v_high) RETURNING id INTO v_id;
    created := true;
    body := app_direct_json(v_id);
    PERFORM app_emit_to(
        'direct.created',
        jsonb_build_object(
            'direct', jsonb_build_object(
                'id', v_id::text,
                'low_user_id', v_low::text,
                'high_user_id', v_high::text,
                'created_at', body->>'created_at'
            )
        ),
        ARRAY[v_low, v_high]
    );
END;
$$;

CREATE FUNCTION app_audience(p_kind text, p_low uuid, p_high uuid)
RETURNS uuid[]
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT CASE WHEN p_kind = 'direct' THEN ARRAY[p_low, p_high] ELSE NULL END;
$$;

CREATE FUNCTION app_list_messages(p_conversation uuid, p_before uuid, p_limit integer)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_kind text;
    v_channel uuid;
    v_direct uuid;
    v_low uuid;
    v_high uuid;
BEGIN
    SELECT kind, channel_id, direct_id, low_user_id, high_user_id
    INTO v_kind, v_channel, v_direct, v_low, v_high
    FROM app_open_conversation(p_conversation, false);
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF p_before IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM messages m
        WHERE m.id = p_before
          AND (m.channel_id = v_channel OR m.direct_id = v_direct)
    ) THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    RETURN coalesce((
        SELECT jsonb_agg(app_message_json(page.id, app_uid()) ORDER BY page.created_at, page.id)
        FROM (
            SELECT m.id, m.created_at
            FROM messages m
            WHERE (m.channel_id = v_channel OR m.direct_id = v_direct)
              AND (
                  p_before IS NULL OR (m.created_at, m.id) < (
                      SELECT b.created_at, b.id FROM messages b WHERE b.id = p_before
                  )
              )
            ORDER BY m.created_at DESC, m.id DESC
            LIMIT p_limit
        ) page
    ), '[]'::jsonb);
END;
$$;

CREATE FUNCTION app_post_message(
    p_conversation uuid,
    p_body text,
    p_reply uuid,
    p_client text,
    p_attachments uuid[]
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
    IF v_client IS NOT NULL AND (
        char_length(v_client) > 64 OR v_client ~ E'[\\x00-\\x1F\\x7F]'
    ) THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF v_client IS NOT NULL THEN
        SELECT id INTO v_existing
        FROM messages
        WHERE author_id = app_uid() AND client_id = v_client;
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
            WHERE author_id = app_uid() AND client_id = v_client;
            RETURN app_message_json(v_existing, app_uid());
    END;
    IF coalesce(cardinality(p_attachments), 0) > 0 THEN
        UPDATE attachments a
        SET message_id = v_id, sort = s.ord::integer
        FROM unnest(p_attachments) WITH ORDINALITY AS s(id, ord)
        WHERE a.id = s.id
          AND a.uploader_id = app_uid()
          AND a.message_id IS NULL;
        GET DIAGNOSTICS v_linked = ROW_COUNT;
        IF v_linked <> cardinality(p_attachments) THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
    END IF;
    v_payload := jsonb_build_object(
        'conversation_id', p_conversation::text,
        'kind', v_kind,
        'message', app_message_json(v_id, app_uid())
    );
    PERFORM app_emit_to('message.created', v_payload, app_audience(v_kind, v_low, v_high));
    RETURN v_payload->'message';
END;
$$;

CREATE FUNCTION app_edit_message(p_id uuid, p_body text)
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
    v_body text := coalesce(btrim(p_body), '');
    v_kind text;
    v_low uuid;
    v_high uuid;
    v_conv uuid;
    v_files integer;
BEGIN
    PERFORM app_msg_voice();
    SELECT author_id, channel_id, direct_id, deleted_at
    INTO v_author, v_channel, v_direct, v_deleted
    FROM messages WHERE id = p_id;
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

-- Clears the body, drops attachment rows, and returns their ids so the caller can delete files.
CREATE FUNCTION app_delete_message(p_id uuid)
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
    SELECT coalesce(array_agg(id::text), '{}') INTO v_files
    FROM attachments WHERE message_id = p_id;
    DELETE FROM attachments WHERE message_id = p_id;
    DELETE FROM reactions WHERE message_id = p_id;
    UPDATE messages SET body = '', deleted_at = now() WHERE id = p_id;
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

CREATE FUNCTION app_emoji_ok(p_emoji text)
RETURNS void
LANGUAGE plpgsql
IMMUTABLE
AS $$
BEGIN
    IF p_emoji IS NULL
       OR char_length(p_emoji) < 1
       OR char_length(p_emoji) > 16
       OR p_emoji ~ E'[\\x00-\\x1F\\x7F]' THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
END;
$$;

CREATE FUNCTION app_reaction(p_message uuid, p_emoji text, p_on boolean)
RETURNS jsonb
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
    v_count integer;
    v_me boolean;
BEGIN
    PERFORM app_emoji_ok(p_emoji);
    PERFORM app_msg_voice();
    SELECT channel_id, direct_id, deleted_at INTO v_channel, v_direct, v_deleted
    FROM messages WHERE id = p_message;
    IF NOT FOUND OR v_deleted IS NOT NULL THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    v_conv := coalesce(v_channel, v_direct);
    SELECT kind, low_user_id, high_user_id INTO v_kind, v_low, v_high
    FROM app_open_conversation(v_conv, true);
    IF p_on THEN
        INSERT INTO reactions (message_id, user_id, emoji)
        VALUES (p_message, app_uid(), p_emoji)
        ON CONFLICT DO NOTHING;
    ELSE
        DELETE FROM reactions
        WHERE message_id = p_message AND user_id = app_uid() AND emoji = p_emoji;
    END IF;
    SELECT count(*)::integer, coalesce(bool_or(user_id = app_uid()), false)
    INTO v_count, v_me
    FROM reactions
    WHERE message_id = p_message AND emoji = p_emoji;
    PERFORM app_emit_to(
        'reaction.updated',
        jsonb_build_object(
            'message_id', p_message::text,
            'conversation_id', v_conv::text,
            'kind', v_kind,
            'emoji', p_emoji,
            'on', p_on,
            'user_id', app_uid()::text,
            'count', v_count
        ),
        app_audience(v_kind, v_low, v_high)
    );
    RETURN jsonb_build_object('emoji', p_emoji, 'count', v_count, 'me', v_me);
END;
$$;

-- Puts the reaction on if it was off, and takes it off if it was on.
CREATE FUNCTION app_toggle_reaction(p_message uuid, p_emoji text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_on boolean;
BEGIN
    PERFORM app_emoji_ok(p_emoji);
    SELECT EXISTS (
        SELECT 1 FROM reactions
        WHERE message_id = p_message AND user_id = app_uid() AND emoji = p_emoji
    ) INTO v_on;
    RETURN app_reaction(p_message, p_emoji, NOT v_on);
END;
$$;

CREATE FUNCTION app_clear_reaction(p_message uuid, p_emoji text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    PERFORM app_emoji_ok(p_emoji);
    IF NOT EXISTS (
        SELECT 1 FROM reactions
        WHERE message_id = p_message AND user_id = app_uid() AND emoji = p_emoji
    ) THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    PERFORM app_reaction(p_message, p_emoji, false);
END;
$$;

-- The cursor only moves forward. A direct read tells both people.
CREATE FUNCTION app_mark_read(p_conversation uuid, p_message uuid)
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

-- Who else should see a typing frame. Requires speak, and refuses a timeout or a ban.
CREATE FUNCTION app_typing_recipients(p_conversation uuid)
RETURNS text[]
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_kind text;
    v_channel uuid;
    v_direct uuid;
    v_low uuid;
    v_high uuid;
BEGIN
    SELECT kind, channel_id, direct_id, low_user_id, high_user_id
    INTO v_kind, v_channel, v_direct, v_low, v_high
    FROM app_open_conversation(p_conversation, true);
    IF v_kind = 'direct' THEN
        RETURN ARRAY[
            CASE WHEN v_low = app_uid() THEN v_high ELSE v_low END::text
        ];
    END IF;
    RETURN coalesce((
        SELECT array_agg(m.user_id::text)
        FROM memberships m
        WHERE m.user_id <> app_uid()
          AND app_channel_perms_of(v_channel, m.user_id) & 1 = 1
    ), '{}'::text[]);
END;
$$;

CREATE FUNCTION app_save_attachment(
    p_name text,
    p_mime text,
    p_kind text,
    p_bytes integer,
    p_width integer,
    p_height integer,
    p_duration integer
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_id uuid;
    v_name text := btrim(p_name);
BEGIN
    PERFORM app_msg_voice();
    IF NOT (
        app_has(4) OR EXISTS (
            SELECT 1 FROM channels c
            WHERE app_channel_perms_of(c.id, app_uid()) & 4 = 4
        )
    ) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    IF p_kind IS NULL OR p_kind NOT IN ('image', 'gif', 'video', 'file') THEN
        RAISE EXCEPTION 'unsupported media' USING ERRCODE = '22023';
    END IF;
    IF p_bytes IS NULL OR p_bytes < 1
       OR (p_kind IN ('image', 'gif') AND p_bytes > 8388608)
       OR p_bytes > 26214400 THEN
        RAISE EXCEPTION 'too large' USING ERRCODE = '22023';
    END IF;
    IF v_name IS NULL OR char_length(v_name) < 1 OR char_length(v_name) > 200
       OR p_mime IS NULL OR char_length(p_mime) < 1 OR char_length(p_mime) > 127 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    INSERT INTO attachments (
        uploader_id, name, mime, kind, bytes, width, height, duration
    ) VALUES (
        app_uid(), v_name, p_mime, p_kind, p_bytes, p_width, p_height, p_duration
    ) RETURNING id INTO v_id;
    RETURN jsonb_build_object(
        'id', v_id::text,
        'name', v_name,
        'mime', p_mime,
        'kind', p_kind,
        'bytes', p_bytes,
        'width', p_width,
        'height', p_height,
        'duration', p_duration
    );
END;
$$;

CREATE FUNCTION app_attachment_meta(p_id uuid, OUT name text, OUT mime text)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_message uuid;
    v_uploader uuid;
    v_created timestamptz;
    v_channel uuid;
    v_direct uuid;
BEGIN
    PERFORM app_msg_gate();
    SELECT a.message_id, a.uploader_id, a.created_at, a.name, a.mime
    INTO v_message, v_uploader, v_created, name, mime
    FROM attachments a
    WHERE a.id = p_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    IF v_message IS NULL THEN
        IF v_uploader = app_uid() AND v_created > now() - interval '1 hour' THEN
            RETURN;
        END IF;
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    SELECT channel_id, direct_id INTO v_channel, v_direct FROM messages WHERE id = v_message;
    PERFORM app_open_conversation(coalesce(v_channel, v_direct), false);
END;
$$;

-- Rows nobody attached within an hour. The caller deletes the files named by the ids.
CREATE FUNCTION app_drop_orphan_attachments()
RETURNS text[]
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_ids text[];
BEGIN
    SELECT coalesce(array_agg(id::text), '{}') INTO v_ids
    FROM attachments
    WHERE message_id IS NULL AND created_at <= now() - interval '1 hour';
    DELETE FROM attachments WHERE id::text = ANY (v_ids);
    RETURN v_ids;
END;
$$;

REVOKE ALL ON channels, channel_overrides, directs, messages, attachments, reactions, reads
    FROM app_runtime;
GRANT SELECT ON channels, channel_overrides, directs, messages, attachments, reactions, reads
    TO app_runtime;

ALTER TABLE channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE channels FORCE ROW LEVEL SECURITY;
CREATE POLICY channels_select ON channels
    FOR SELECT USING (app_channel_has(id, 1));

ALTER TABLE channel_overrides ENABLE ROW LEVEL SECURITY;
ALTER TABLE channel_overrides FORCE ROW LEVEL SECURITY;
CREATE POLICY channel_overrides_select ON channel_overrides
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM channels c
            WHERE c.id = channel_id AND app_channel_has(c.id, 1)
        )
    );

ALTER TABLE directs ENABLE ROW LEVEL SECURITY;
ALTER TABLE directs FORCE ROW LEVEL SECURITY;
CREATE POLICY directs_select ON directs
    FOR SELECT USING (app_is_member() AND app_uid() IN (low_user_id, high_user_id));

ALTER TABLE messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE messages FORCE ROW LEVEL SECURITY;
CREATE POLICY messages_select ON messages
    FOR SELECT USING (
        (channel_id IS NOT NULL AND app_channel_has(channel_id, 1))
        OR (direct_id IS NOT NULL AND EXISTS (
            SELECT 1 FROM directs d
            WHERE d.id = direct_id AND app_uid() IN (d.low_user_id, d.high_user_id)
        ))
    );

ALTER TABLE attachments ENABLE ROW LEVEL SECURITY;
ALTER TABLE attachments FORCE ROW LEVEL SECURITY;
CREATE POLICY attachments_select ON attachments
    FOR SELECT USING (
        (message_id IS NULL AND uploader_id = app_uid() AND created_at > now() - interval '1 hour')
        OR message_id IN (SELECT id FROM messages)
    );

ALTER TABLE reactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE reactions FORCE ROW LEVEL SECURITY;
CREATE POLICY reactions_select ON reactions
    FOR SELECT USING (message_id IN (SELECT id FROM messages));

ALTER TABLE reads ENABLE ROW LEVEL SECURITY;
ALTER TABLE reads FORCE ROW LEVEL SECURITY;
CREATE POLICY reads_select ON reads
    FOR SELECT USING (
        user_id = app_uid()
        OR (kind = 'direct' AND conversation_id IN (SELECT id FROM directs))
    );

DO $$
DECLARE
    v_function text;
BEGIN
    FOREACH v_function IN ARRAY ARRAY[
        'app_channel_perms_of(uuid, uuid)',
        'app_channel_has(uuid, bigint)',
        'app_msg_gate()',
        'app_msg_voice()',
        'app_stamp(timestamp with time zone)',
        'app_message_json(uuid, uuid)',
        'app_last_message(uuid, uuid)',
        'app_unread(text, uuid)',
        'app_channel_json(uuid)',
        'app_open_conversation(uuid, boolean)',
        'app_list_channels()',
        'app_create_channel(text, uuid, text, integer)',
        'app_update_channel(uuid, jsonb)',
        'app_delete_channel(uuid)',
        'app_set_channel_override(uuid, uuid, bigint, bigint)',
        'app_direct_json(uuid)',
        'app_list_directs()',
        'app_open_direct(uuid)',
        'app_audience(text, uuid, uuid)',
        'app_list_messages(uuid, uuid, integer)',
        'app_post_message(uuid, text, uuid, text, uuid[])',
        'app_edit_message(uuid, text)',
        'app_delete_message(uuid)',
        'app_emoji_ok(text)',
        'app_reaction(uuid, text, boolean)',
        'app_toggle_reaction(uuid, text)',
        'app_clear_reaction(uuid, text)',
        'app_mark_read(uuid, uuid)',
        'app_typing_recipients(uuid)',
        'app_save_attachment(text, text, text, integer, integer, integer, integer)',
        'app_attachment_meta(uuid)',
        'app_drop_orphan_attachments()'
    ]
    LOOP
        EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', v_function);
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO app_runtime', v_function);
    END LOOP;
END $$;
