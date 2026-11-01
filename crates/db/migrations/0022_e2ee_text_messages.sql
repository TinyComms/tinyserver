-- End-to-end encrypted text, part 3: messages, sealed uploads, and what changes in the functions
-- that already existed.
--
-- A ciphertext message is a messages row with e2ee set, an empty body, and the ciphertext, the
-- epoch and the sending device beside it. The server checks who may post it, that it is for the
-- group's current epoch, and that the sending device is in the group; it cannot check what it
-- says. There is no downgrade in either direction: a body for an encrypted conversation is
-- refused (P0E01), a ciphertext for a plaintext one is refused (P0E02).

-- The JSON of a message. A ciphertext message also says what it is and where it goes.
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

-- An edit is a row of its own and is not a message in the list: it is not a preview and not
-- unread.
CREATE OR REPLACE FUNCTION app_last_message(p_channel uuid, p_direct uuid)
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
      AND m.msg_kind = 'message'
      AND (m.channel_id = p_channel OR m.direct_id = p_direct)
    ORDER BY m.created_at DESC, m.id DESC
    LIMIT 1;
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
            AND (m.created_at, m.id) <= (cursor_message.created_at, cursor_message.id)
      );
$$;

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

-- A new conversation follows the server's e2ee_text setting. An existing one is never changed.
CREATE FUNCTION app_e2ee_may_create(p_e2ee boolean)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_mode text;
BEGIN
    SELECT s.e2ee_text INTO v_mode FROM server_settings s;
    IF p_e2ee AND v_mode = 'off' THEN
        RAISE EXCEPTION 'e2ee is off' USING ERRCODE = 'P0E12';
    END IF;
    IF NOT p_e2ee AND v_mode = 'new_required' THEN
        RAISE EXCEPTION 'e2ee required' USING ERRCODE = 'P0E01';
    END IF;
END;
$$;

REVOKE EXECUTE ON FUNCTION app_e2ee_may_create(boolean) FROM PUBLIC, app_runtime;

DROP FUNCTION app_create_channel(text, uuid, text, integer);

CREATE FUNCTION app_create_channel(
    p_name text,
    p_category uuid,
    p_topic text,
    p_position integer,
    p_e2ee boolean DEFAULT false
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
    v_e2ee boolean := coalesce(p_e2ee, false);
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
    PERFORM app_e2ee_may_create(v_e2ee);
    INSERT INTO channels (category_id, name, topic, position, created_by, e2ee)
    VALUES (p_category, v_name, v_topic, coalesce(p_position, 0), app_uid(), v_e2ee)
    RETURNING id INTO v_id;
    PERFORM app_audit(
        'channel.create', 'channel',
        jsonb_build_object('id', v_id, 'name', v_name, 'e2ee', v_e2ee),
        NULL, NULL
    );
    PERFORM app_emit('channel.created', jsonb_build_object('channel', app_channel_json(v_id)));
    RETURN app_channel_json(v_id);
END;
$$;

DROP FUNCTION app_open_direct(uuid);

-- Get or create the direct conversation of this kind with another current member. A pair may
-- have a plaintext direct and an encrypted one. Neither person may be banned.
CREATE FUNCTION app_open_direct(p_user uuid, p_e2ee boolean, OUT body jsonb, OUT created boolean)
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
        jsonb_build_object(
            'direct', jsonb_build_object(
                'id', v_id::text,
                'low_user_id', v_low::text,
                'high_user_id', v_high::text,
                'created_at', body->>'created_at',
                'e2ee', v_e2ee
            )
        ),
        ARRAY[v_low, v_high]
    );
END;
$$;

-- A plaintext post. An encrypted conversation takes ciphertext only, with no fallback.
CREATE OR REPLACE FUNCTION app_post_message(
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
    IF app_conv_e2ee(p_conversation) THEN
        RAISE EXCEPTION 'e2ee required' USING ERRCODE = 'P0E01';
    END IF;
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
        -- A sealed upload belongs only in an encrypted conversation.
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
    v_payload := jsonb_build_object(
        'conversation_id', p_conversation::text,
        'kind', v_kind,
        'message', app_message_json(v_id, app_uid())
    );
    PERFORM app_emit_to('message.created', v_payload, app_audience(v_kind, v_low, v_high));
    RETURN v_payload->'message';
END;
$$;

-- A ciphertext post: a message, or an edit of one of the sender's own. It must be for the
-- group's current epoch and from a device that is in the group and not being removed. A replay
-- of the same client id from the same device in the same conversation returns the original.
CREATE FUNCTION app_post_e2ee_message(
    p_conversation uuid,
    p_ciphertext bytea,
    p_epoch bigint,
    p_device uuid,
    p_client text,
    p_kind text,
    p_target uuid,
    p_attachments uuid[],
    p_has_body boolean
)
RETURNS TABLE (r_message jsonb, r_created boolean)
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
    v_client text := nullif(btrim(p_client), '');
    v_id uuid;
    v_existing uuid;
    v_epoch bigint;
    v_linked integer;
    v_payload jsonb;
    v_author uuid;
BEGIN
    SELECT kind, channel_id, direct_id, low_user_id, high_user_id
    INTO v_kind, v_channel, v_direct, v_low, v_high
    FROM app_open_conversation(p_conversation, true);
    IF NOT app_conv_e2ee(p_conversation) THEN
        RAISE EXCEPTION 'not e2ee' USING ERRCODE = 'P0E02';
    END IF;
    IF p_has_body THEN
        RAISE EXCEPTION 'e2ee required' USING ERRCODE = 'P0E01';
    END IF;
    PERFORM app_e2ee_gate(p_conversation, p_device, true);
    IF p_kind IS NULL OR p_kind NOT IN ('message', 'edit')
       OR (p_kind = 'edit') <> (p_target IS NOT NULL) THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF v_client IS NOT NULL AND (
        char_length(v_client) > 64 OR v_client ~ E'[\\x00-\\x1F\\x7F]'
    ) THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF v_client IS NOT NULL THEN
        SELECT m.id INTO v_existing FROM messages m
        WHERE m.e2ee AND m.device_id = p_device AND m.client_id = v_client
          AND coalesce(m.channel_id, m.direct_id) = p_conversation;
        IF FOUND THEN
            RETURN QUERY SELECT app_message_json(v_existing, app_uid()), false;
            RETURN;
        END IF;
    END IF;
    IF p_ciphertext IS NULL OR octet_length(p_ciphertext) < 1 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF octet_length(p_ciphertext) > 20480 THEN
        RAISE EXCEPTION 'too large' USING ERRCODE = '22023';
    END IF;
    IF coalesce(cardinality(p_attachments), 0) > 10 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;

    -- Shared, so a commit (which takes it for update) and a post are one after the other.
    SELECT g.epoch INTO v_epoch FROM e2ee_groups g
    WHERE g.conversation_id = p_conversation FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no group' USING ERRCODE = 'P0E05';
    END IF;
    IF v_epoch <> p_epoch THEN
        RAISE EXCEPTION 'stale epoch' USING ERRCODE = 'P0E03';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM e2ee_leaves l
                   WHERE l.conversation_id = p_conversation AND l.device_id = p_device)
       OR EXISTS (SELECT 1 FROM e2ee_pending p
                  WHERE p.conversation_id = p_conversation AND p.device_id = p_device
                    AND p.op = 'remove') THEN
        RAISE EXCEPTION 'not in group' USING ERRCODE = 'P0E07';
    END IF;

    IF p_kind = 'edit' THEN
        SELECT m.author_id INTO v_author FROM messages m
        WHERE m.id = p_target AND m.e2ee AND m.msg_kind = 'message' AND m.deleted_at IS NULL
          AND (m.channel_id IS NOT DISTINCT FROM v_channel)
          AND (m.direct_id IS NOT DISTINCT FROM v_direct);
        IF NOT FOUND THEN
            RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
        END IF;
        IF v_author <> app_uid() THEN
            RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
        END IF;
    END IF;

    IF coalesce(cardinality(p_attachments), 0) > 0 THEN
        -- Only sealed uploads, and only the caller's own, unlinked and fresh.
        IF (
            SELECT count(*) FROM attachments a
            WHERE a.id = ANY (p_attachments)
              AND a.uploader_id = app_uid()
              AND a.message_id IS NULL
              AND a.created_at > now() - interval '1 hour'
              AND a.kind = 'sealed'
        ) <> cardinality(p_attachments) THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
    END IF;
    BEGIN
        INSERT INTO messages (channel_id, direct_id, author_id, body, client_id,
                              e2ee, ciphertext, epoch, device_id, msg_kind, target_id)
        VALUES (v_channel, v_direct, app_uid(), '', v_client,
                true, p_ciphertext, p_epoch, p_device, p_kind, p_target)
        RETURNING id INTO v_id;
    EXCEPTION
        WHEN unique_violation THEN
            SELECT m.id INTO v_existing FROM messages m
            WHERE m.e2ee AND m.device_id = p_device AND m.client_id = v_client
              AND coalesce(m.channel_id, m.direct_id) = p_conversation;
            RETURN QUERY SELECT app_message_json(v_existing, app_uid()), false;
            RETURN;
    END;
    IF coalesce(cardinality(p_attachments), 0) > 0 THEN
        UPDATE attachments a
        SET message_id = v_id, sort = s.ord::integer
        FROM unnest(p_attachments) WITH ORDINALITY AS s(id, ord)
        WHERE a.id = s.id
          AND a.uploader_id = app_uid()
          AND a.message_id IS NULL
          AND a.kind = 'sealed';
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
    RETURN QUERY SELECT v_payload->'message', true;
END;
$$;

-- A plaintext edit. An encrypted message is edited by a ciphertext post of kind edit.
CREATE OR REPLACE FUNCTION app_edit_message(p_id uuid, p_body text)
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

-- Clears the body (and a ciphertext), drops attachment rows, and returns their ids so the caller
-- can delete files. Deleting an encrypted message also deletes the edits made of it.
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

-- An edited or deleted message is still in the outbox as first sent. A deleted ciphertext
-- message loses its ciphertext there too.
CREATE OR REPLACE FUNCTION app_scrub_outbox()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    UPDATE outbox
    SET payload = CASE
        WHEN NEW.deleted_at IS NULL THEN
            jsonb_set(payload, '{message,body}', to_jsonb(NEW.body))
        WHEN NEW.e2ee THEN
            jsonb_set(
                jsonb_set(jsonb_set(payload, '{message,body}', '""'::jsonb),
                          '{message,attachments}', '[]'::jsonb),
                '{message,ciphertext}', 'null'::jsonb
            )
        ELSE
            jsonb_set(jsonb_set(payload, '{message,body}', '""'::jsonb),
                      '{message,attachments}', '[]'::jsonb)
        END
    WHERE topic IN ('message.created', 'message.edited')
      AND payload #>> '{message,id}' = NEW.id::text;
    IF NEW.deleted_at IS NOT NULL THEN
        -- The 200 character preview of a channel's last message.
        UPDATE outbox
        SET payload = jsonb_set(payload, '{channel,last_message,body}', '""'::jsonb)
        WHERE topic IN ('channel.created', 'channel.updated')
          AND payload #>> '{channel,last_message,id}' = NEW.id::text;
    END IF;
    RETURN NULL;
END;
$$;

-- A sealed upload is read by the server as bytes and nothing else: no type, no decode, no scan.
-- Size is the server's file limit, and the rate is per person. It is the same permission as
-- any upload.
CREATE FUNCTION app_save_sealed_attachment(p_bytes integer)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_id uuid;
    v_file bigint;
    v_per_hour integer;
    v_per_day bigint;
    v_files integer;
    v_bytes bigint;
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
    SELECT s.file_max_bytes, s.sealed_files_per_hour, s.sealed_bytes_per_day
    INTO v_file, v_per_hour, v_per_day FROM server_settings s;
    IF p_bytes IS NULL OR p_bytes < 1 OR p_bytes > v_file THEN
        RAISE EXCEPTION 'too large' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.e2ee.upload.' || app_uid()::text, 0));
    SELECT count(*) FILTER (WHERE l.created_at > now() - interval '1 hour'),
           coalesce(sum(l.bytes), 0)
    INTO v_files, v_bytes
    FROM e2ee_upload_ledger l
    WHERE l.user_id = app_uid() AND l.created_at > now() - interval '1 day';
    IF v_files >= v_per_hour OR v_bytes + p_bytes > v_per_day THEN
        RAISE EXCEPTION 'slow down' USING ERRCODE = 'P0E11';
    END IF;
    INSERT INTO e2ee_upload_ledger (user_id, bytes) VALUES (app_uid(), p_bytes);
    INSERT INTO attachments (uploader_id, name, mime, kind, bytes, scan_status)
    VALUES (app_uid(), 'sealed', 'application/octet-stream', 'sealed', p_bytes, 'sealed')
    RETURNING id INTO v_id;
    RETURN jsonb_build_object(
        'id', v_id::text,
        'name', 'sealed',
        'mime', 'application/octet-stream',
        'kind', 'sealed',
        'bytes', p_bytes,
        'width', NULL,
        'height', NULL,
        'duration', NULL,
        'scan_status', 'sealed'
    );
END;
$$;

-- A sealed file downloads like any other, to whoever may read the conversation. It was never
-- scanned, so it has no scan verdict to wait for.
CREATE OR REPLACE FUNCTION app_attachment_meta(p_id uuid, OUT name text, OUT mime text)
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
    v_scan text;
BEGIN
    PERFORM app_msg_gate();
    SELECT a.message_id, a.uploader_id, a.created_at, a.name, a.mime, a.scan_status
    INTO v_message, v_uploader, v_created, name, mime, v_scan
    FROM attachments a
    WHERE a.id = p_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    IF v_message IS NULL THEN
        IF v_uploader = app_uid() AND v_created > now() - interval '1 hour' THEN
            NULL;
        ELSE
            RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
        END IF;
    ELSE
        SELECT channel_id, direct_id INTO v_channel, v_direct FROM messages WHERE id = v_message;
        PERFORM app_open_conversation(coalesce(v_channel, v_direct), false);
    END IF;
    IF v_scan IN ('uploaded', 'scanning') THEN
        RAISE EXCEPTION 'scanning' USING ERRCODE = 'P0423';
    ELSIF v_scan = 'blocked' THEN
        RAISE EXCEPTION 'blocked' USING ERRCODE = 'P0403';
    ELSIF v_scan = 'error' THEN
        RAISE EXCEPTION 'unavailable' USING ERRCODE = 'P0503';
    END IF;
END;
$$;

-- Deleting an account also revokes its devices: their leaves are removed by the membership
-- trigger, their key packages and welcomes are deleted here. The rest is 0014.
CREATE OR REPLACE FUNCTION app_delete_account()
RETURNS text[]
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_user uuid := app_uid();
    v_owner boolean;
    v_files text[];
    v_device uuid;
BEGIN
    IF v_user IS NULL OR NOT EXISTS (
        SELECT 1 FROM users WHERE id = v_user AND deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.owners'));
    SELECT owner INTO v_owner FROM memberships WHERE user_id = v_user;
    IF v_owner AND (SELECT count(*) FROM memberships WHERE owner) <= 1 THEN
        RAISE EXCEPTION 'last owner' USING ERRCODE = '42501';
    END IF;

    SELECT coalesce(array_agg(a.id::text), '{}') INTO v_files
    FROM attachments a
    WHERE a.uploader_id = v_user
       OR a.message_id IN (SELECT m.id FROM messages m WHERE m.author_id = v_user);
    DELETE FROM attachments
    WHERE uploader_id = v_user
       OR message_id IN (SELECT m.id FROM messages m WHERE m.author_id = v_user);
    DELETE FROM reactions
    WHERE user_id = v_user
       OR message_id IN (SELECT m.id FROM messages m WHERE m.author_id = v_user);
    UPDATE messages SET body = '', deleted_at = now()
    WHERE author_id = v_user AND deleted_at IS NULL;
    DELETE FROM reads WHERE user_id = v_user;

    FOR v_device IN
        SELECT d.device_id FROM e2ee_devices d WHERE d.user_id = v_user AND d.revoked_at IS NULL
    LOOP
        UPDATE e2ee_devices SET revoked_at = now(), low_keys = false WHERE device_id = v_device;
        DELETE FROM e2ee_key_packages WHERE device_id = v_device;
        DELETE FROM e2ee_handshake WHERE for_device = v_device;
        PERFORM app_emit(
            'e2ee.device',
            jsonb_build_object('user_id', v_user::text, 'device_id', v_device::text, 'op', 'revoked')
        );
    END LOOP;
    DELETE FROM e2ee_upload_ledger WHERE user_id = v_user;

    DELETE FROM bots WHERE created_by = v_user;
    DELETE FROM invites WHERE created_by = v_user AND accepted_at IS NULL;
    DELETE FROM idempotency_keys WHERE key LIKE v_user::text || E'\n%';
    DELETE FROM sessions WHERE user_id = v_user;
    DELETE FROM user_identities WHERE user_id = v_user;
    DELETE FROM memberships WHERE user_id = v_user;

    -- Their join, rename and profile events, with the name and email they carry.
    DELETE FROM outbox WHERE payload #>> '{member,user_id}' = v_user::text;

    UPDATE audit_log
    SET detail = detail - 'display_name' - 'name' - 'email'
    WHERE (actor_id = v_user OR subject_user_id = v_user) AND detail IS NOT NULL;

    UPDATE users
    SET email = NULL,
        display_name = 'Deleted user',
        avatar = NULL,
        avatar_type = NULL,
        avatar_sha = NULL,
        deleted_at = now()
    WHERE id = v_user;

    INSERT INTO audit_log (actor_id, action, subject, detail, subject_user_id)
    VALUES (v_user, 'account.delete', 'user', jsonb_build_object('user_id', v_user), v_user);
    RETURN v_files;
END;
$$;

-- What the periodic sweep removes of this feature: ledger rows older than two days, key packages
-- that expired, and welcomes nobody picked up in 30 days. Returns how many rows went.
CREATE FUNCTION app_e2ee_sweep()
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_total bigint := 0;
    v_n bigint;
BEGIN
    DELETE FROM e2ee_upload_ledger WHERE created_at < now() - interval '2 days';
    GET DIAGNOSTICS v_n = ROW_COUNT;
    v_total := v_total + v_n;
    DELETE FROM e2ee_key_packages WHERE NOT last_resort AND expires_at <= now();
    GET DIAGNOSTICS v_n = ROW_COUNT;
    v_total := v_total + v_n;
    DELETE FROM e2ee_handshake WHERE kind = 'welcome' AND created_at < now() - interval '30 days';
    GET DIAGNOSTICS v_n = ROW_COUNT;
    v_total := v_total + v_n;
    RETURN v_total;
END;
$$;

DO $$
DECLARE
    v_function text;
BEGIN
    FOREACH v_function IN ARRAY ARRAY[
        'app_create_channel(text, uuid, text, integer, boolean)',
        'app_open_direct(uuid, boolean)',
        'app_post_e2ee_message(uuid, bytea, bigint, uuid, text, text, uuid, uuid[], boolean)',
        'app_save_sealed_attachment(integer)',
        'app_e2ee_sweep()'
    ]
    LOOP
        EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', v_function);
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO app_runtime', v_function);
    END LOOP;
END $$;

-- The setting, for GET /v1/capabilities, which a bot may read too. It says nothing a client
-- cannot learn by trying.
CREATE FUNCTION app_e2ee_text_mode()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT s.e2ee_text FROM server_settings s;
$$;

REVOKE EXECUTE ON FUNCTION app_e2ee_text_mode() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_e2ee_text_mode() TO app_runtime;
