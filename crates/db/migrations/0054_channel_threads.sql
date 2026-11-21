-- Channel threads (issue #73).
--
-- A message in a channel can be the root of a thread. Replies carry `messages.thread_id`
-- referencing the root (ON DELETE CASCADE). Constraints: the root is in the same channel,
-- is not itself a thread reply, and is not in a direct.
--
-- `reads` allows `kind = 'thread'` with `conversation_id` = the root's id.
-- `thread_follows (thread_id, user_id)` tracks who follows each thread (auto-followed when
-- replying or starting a thread, and explicitly via PUT/DELETE /v1/messages/{id}/thread/follow).
--
-- `GET /v1/conversations/{id}/messages?threads=1` omits thread replies from the channel list;
-- without `threads=1`, already-released clients still see every message in order.

ALTER TABLE messages ADD COLUMN thread_id uuid REFERENCES messages (id) ON DELETE CASCADE;
CREATE INDEX messages_thread_order ON messages (thread_id, seq) WHERE thread_id IS NOT NULL;

ALTER TABLE reads DROP CONSTRAINT IF EXISTS reads_kind_check;
ALTER TABLE reads ADD CONSTRAINT reads_kind_check
    CHECK (kind IN ('channel', 'direct', 'thread'));

CREATE TABLE thread_follows (
    thread_id uuid NOT NULL REFERENCES messages (id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (thread_id, user_id)
);

CREATE INDEX thread_follows_user ON thread_follows (user_id, thread_id);

ALTER TABLE thread_follows ENABLE ROW LEVEL SECURITY;
ALTER TABLE thread_follows FORCE ROW LEVEL SECURITY;
REVOKE ALL ON thread_follows FROM app_runtime;

-- Unread count for one thread root for `p_viewer`.
CREATE FUNCTION app_thread_unread(p_root uuid, p_viewer uuid)
RETURNS integer
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT CASE WHEN p_viewer IS NULL THEN 0 ELSE (
        SELECT count(*)::integer
        FROM messages m
        WHERE m.thread_id = p_root
          AND m.deleted_at IS NULL
          AND m.msg_kind = 'message'
          AND m.author_id <> p_viewer
          AND NOT EXISTS (
              SELECT 1
              FROM reads r
              JOIN messages cursor_message ON cursor_message.id = r.message_id
              WHERE r.user_id = p_viewer
                AND r.kind = 'thread'
                AND r.conversation_id = p_root
                AND m.seq <= cursor_message.seq
          )
    ) END;
$$;

REVOKE EXECUTE ON FUNCTION app_thread_unread(uuid, uuid) FROM PUBLIC;

-- Thread summary for a root message, or NULL when it has no non-deleted replies.
CREATE FUNCTION app_thread_summary(p_root uuid, p_viewer uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT CASE WHEN s.replies > 0 THEN jsonb_build_object(
        'replies', s.replies,
        'last_reply_at', app_stamp(s.last_reply_at),
        'participants', coalesce((
            SELECT jsonb_agg(p.author_id::text ORDER BY p.last_seq DESC)
            FROM (
                SELECT m2.author_id, max(m2.seq) AS last_seq
                FROM messages m2
                WHERE m2.thread_id = p_root
                  AND m2.deleted_at IS NULL
                  AND m2.msg_kind = 'message'
                GROUP BY m2.author_id
                ORDER BY max(m2.seq) DESC
                LIMIT 3
            ) p
        ), '[]'::jsonb),
        'unread', app_thread_unread(p_root, p_viewer)
    ) END
    FROM (
        SELECT count(*)::integer AS replies, max(m.created_at) AS last_reply_at
        FROM messages m
        WHERE m.thread_id = p_root
          AND m.deleted_at IS NULL
          AND m.msg_kind = 'message'
    ) s;
$$;

REVOKE EXECUTE ON FUNCTION app_thread_summary(uuid, uuid) FROM PUBLIC;

-- Channel unread excludes thread replies so thread cursors clear thread unread without
-- touching the channel's unread count.
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
      AND ((p_kind = 'channel' AND m.channel_id = p_conversation AND m.thread_id IS NULL)
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

-- Update app_message_json to carry `thread_id` on replies and `thread` summary on roots.
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
        'thread_id', m.thread_id::text,
        'thread', CASE WHEN m.thread_id IS NULL THEN app_thread_summary(m.id, p_viewer) END,
        'client_id', m.client_id,
        'created_at', app_stamp(m.created_at),
        'edited_at', CASE WHEN m.edited_at IS NULL THEN NULL ELSE app_stamp(m.edited_at) END,
        'deleted_at', CASE WHEN m.deleted_at IS NULL THEN NULL ELSE app_stamp(m.deleted_at) END,
        'deleted_by', CASE WHEN m.deleted_by <> m.author_id THEN m.deleted_by::text END,
        'e2ee', m.e2ee,
        'emoji', CASE WHEN m.deleted_at IS NULL THEN m.emoji_spans ELSE '[]'::jsonb END,
        'sticker_id', CASE WHEN m.deleted_at IS NULL THEN m.sticker_id::text END,
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
            SELECT jsonb_agg(
                CASE WHEN r.emoji_id IS NULL THEN
                    jsonb_build_object(
                        'emoji', r.emoji,
                        'count', r.count,
                        'me', r.me
                    )
                ELSE
                    jsonb_build_object(
                        'emoji', r.emoji,
                        'emoji_id', r.emoji_id::text,
                        'name', r.name,
                        'count', r.count,
                        'me', r.me
                    )
                END
                ORDER BY r.emoji, r.emoji_id NULLS FIRST
            )
            FROM (
                SELECT
                    coalesce(':' || e.name || ':', rx.emoji) AS emoji,
                    rx.emoji_id,
                    e.name,
                    count(*) AS count,
                    bool_or(rx.user_id = p_viewer) AS me
                FROM reactions rx
                LEFT JOIN emoji e ON e.id = rx.emoji_id
                WHERE rx.message_id = m.id AND m.deleted_at IS NULL
                GROUP BY rx.emoji_id, coalesce(':' || e.name || ':', rx.emoji), e.name
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
    ) ELSE '{}'::jsonb END
    FROM messages m
    WHERE m.id = p_id;
$$;

-- Filtered message history: when `p_threads` is true, thread replies are omitted from the
-- channel list.
CREATE FUNCTION app_list_messages_filtered(
    p_conversation uuid,
    p_before uuid,
    p_limit integer,
    p_threads boolean
)
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
        SELECT jsonb_agg(app_message_json(page.id, app_uid()) ORDER BY page.seq)
        FROM (
            SELECT m.id, m.seq
            FROM messages m
            WHERE (m.channel_id = v_channel OR m.direct_id = v_direct)
              AND (NOT p_threads OR m.thread_id IS NULL)
              AND (
                  p_before IS NULL OR m.seq < (
                      SELECT b.seq FROM messages b WHERE b.id = p_before
                  )
              )
            ORDER BY m.seq DESC
            LIMIT p_limit
        ) page
    ), '[]'::jsonb);
END;
$$;

-- Paged replies in one thread root. A caller who cannot view the channel gets 404.
CREATE FUNCTION app_list_thread_messages(p_root uuid, p_before uuid, p_limit integer)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_channel uuid;
    v_root_thread uuid;
BEGIN
    SELECT channel_id, thread_id INTO v_channel, v_root_thread
    FROM messages WHERE id = p_root;
    IF NOT FOUND OR v_channel IS NULL OR v_root_thread IS NOT NULL THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    PERFORM app_open_conversation(v_channel, false);
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF p_before IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM messages m
        WHERE m.id = p_before AND m.thread_id = p_root
    ) THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    RETURN coalesce((
        SELECT jsonb_agg(app_message_json(page.id, app_uid()) ORDER BY page.seq)
        FROM (
            SELECT m.id, m.seq
            FROM messages m
            WHERE m.thread_id = p_root
              AND (
                  p_before IS NULL OR m.seq < (
                      SELECT b.seq FROM messages b WHERE b.id = p_before
                  )
              )
            ORDER BY m.seq DESC
            LIMIT p_limit
        ) page
    ), '[]'::jsonb);
END;
$$;

-- Advances the caller's read cursor for one thread root without touching the channel cursor.
CREATE FUNCTION app_mark_thread_read(p_root uuid, p_message uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_channel uuid;
    v_root_thread uuid;
    v_seq bigint;
    v_old uuid;
    v_old_seq bigint;
BEGIN
    SELECT channel_id, thread_id INTO v_channel, v_root_thread
    FROM messages WHERE id = p_root;
    IF NOT FOUND OR v_channel IS NULL OR v_root_thread IS NOT NULL THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    PERFORM app_open_conversation(v_channel, false);
    SELECT seq INTO v_seq
    FROM messages
    WHERE id = p_message AND (id = p_root OR thread_id = p_root);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    SELECT message_id INTO v_old
    FROM reads
    WHERE user_id = app_uid() AND kind = 'thread' AND conversation_id = p_root;
    IF v_old IS NOT NULL THEN
        SELECT seq INTO v_old_seq FROM messages WHERE id = v_old;
        IF v_old_seq IS NOT NULL AND v_seq <= v_old_seq THEN
            RETURN;
        END IF;
    END IF;
    INSERT INTO reads (user_id, kind, conversation_id, message_id)
    VALUES (app_uid(), 'thread', p_root, p_message)
    ON CONFLICT (user_id, kind, conversation_id) DO UPDATE
    SET message_id = EXCLUDED.message_id, read_at = now();
    PERFORM app_emit_to(
        'read.updated',
        jsonb_build_object(
            'conversation_id', p_root::text,
            'kind', 'thread',
            'user_id', app_uid()::text,
            'message_id', p_message::text
        ),
        ARRAY[app_uid()]
    );
END;
$$;

CREATE FUNCTION app_follow_thread(p_root uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_channel uuid;
    v_root_thread uuid;
BEGIN
    SELECT channel_id, thread_id INTO v_channel, v_root_thread
    FROM messages WHERE id = p_root;
    IF NOT FOUND OR v_channel IS NULL OR v_root_thread IS NOT NULL THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    PERFORM app_open_conversation(v_channel, false);
    INSERT INTO thread_follows (thread_id, user_id)
    VALUES (p_root, app_uid())
    ON CONFLICT (thread_id, user_id) DO NOTHING;
END;
$$;

CREATE FUNCTION app_unfollow_thread(p_root uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_channel uuid;
    v_root_thread uuid;
BEGIN
    SELECT channel_id, thread_id INTO v_channel, v_root_thread
    FROM messages WHERE id = p_root;
    IF NOT FOUND OR v_channel IS NULL OR v_root_thread IS NOT NULL THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    PERFORM app_open_conversation(v_channel, false);
    DELETE FROM thread_follows WHERE thread_id = p_root AND user_id = app_uid();
END;
$$;

-- Followed threads the caller can still view, with their root message and unread summary.
CREATE FUNCTION app_list_followed_threads()
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    PERFORM app_msg_gate();
    RETURN coalesce((
        SELECT jsonb_agg(
            jsonb_build_object(
                'channel_id', t.channel_id::text,
                'message_id', t.thread_id::text,
                'message', app_message_json(t.thread_id, app_uid()),
                'thread', coalesce(
                    app_thread_summary(t.thread_id, app_uid()),
                    jsonb_build_object(
                        'replies', 0,
                        'last_reply_at', NULL,
                        'participants', '[]'::jsonb,
                        'unread', 0
                    )
                )
            )
            ORDER BY t.sort_at DESC, t.thread_id
        )
        FROM (
            SELECT
                tf.thread_id,
                m.channel_id,
                coalesce(
                    (SELECT max(r.created_at) FROM messages r
                     WHERE r.thread_id = tf.thread_id AND r.deleted_at IS NULL),
                    m.created_at
                ) AS sort_at
            FROM thread_follows tf
            JOIN messages m ON m.id = tf.thread_id
            WHERE tf.user_id = app_uid()
              AND m.channel_id IS NOT NULL
              AND app_channel_has(m.channel_id, 1)
        ) t
    ), '[]'::jsonb);
END;
$$;

-- Extended post_message accepting optional `p_thread` (channel thread root id).
CREATE FUNCTION app_post_message_thread(
    p_conversation uuid,
    p_body text,
    p_reply uuid,
    p_client text,
    p_attachments uuid[],
    p_emoji jsonb,
    p_sticker uuid,
    p_thread uuid
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
    v_body text := btrim(coalesce(p_body, ''));
    v_client text := nullif(p_client, '');
    v_emoji jsonb := coalesce(p_emoji, '[]'::jsonb);
    v_existing uuid;
    v_id uuid;
    v_linked integer;
    v_payload jsonb;
    v_span jsonb;
    v_span_id uuid;
    v_start integer;
    v_end integer;
    v_body_len integer;
    v_root_channel uuid;
    v_root_thread uuid;
    v_root_author uuid;
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
    IF p_sticker IS NOT NULL THEN
        IF NOT EXISTS (SELECT 1 FROM emoji WHERE id = p_sticker AND kind = 'sticker') THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
    END IF;
    IF v_body = '' AND coalesce(cardinality(p_attachments), 0) = 0 AND p_sticker IS NULL THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF jsonb_typeof(v_emoji) <> 'array' OR jsonb_array_length(v_emoji) > 64 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    v_body_len := char_length(v_body);
    FOR v_span IN SELECT value FROM jsonb_array_elements(v_emoji) LOOP
        BEGIN
            v_span_id := (v_span->>'id')::uuid;
            v_start := (v_span->>'start')::integer;
            v_end := (v_span->>'end')::integer;
        EXCEPTION WHEN others THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END;
        IF v_span_id IS NULL OR v_start IS NULL OR v_end IS NULL
           OR v_start < 0 OR v_end <= v_start OR v_end > v_body_len THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM emoji WHERE id = v_span_id AND kind = 'emoji') THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
    END LOOP;
    IF p_thread IS NOT NULL THEN
        IF v_kind <> 'channel' THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
        SELECT channel_id, thread_id, author_id
        INTO v_root_channel, v_root_thread, v_root_author
        FROM messages WHERE id = p_thread;
        IF NOT FOUND OR v_root_channel IS DISTINCT FROM v_channel THEN
            RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
        END IF;
        IF v_root_thread IS NOT NULL THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
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
        INSERT INTO messages (
            channel_id, direct_id, author_id, body, reply_to, client_id,
            emoji_spans, sticker_id, thread_id
        )
        VALUES (
            v_channel, v_direct, app_uid(), v_body, p_reply, v_client,
            v_emoji, p_sticker, p_thread
        )
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
    IF p_thread IS NOT NULL THEN
        INSERT INTO thread_follows (thread_id, user_id)
        VALUES (p_thread, app_uid()), (p_thread, v_root_author)
        ON CONFLICT (thread_id, user_id) DO NOTHING;
    END IF;
    v_payload := jsonb_build_object(
        'conversation_id', p_conversation::text,
        'kind', v_kind,
        'message', app_message_json(v_id, app_uid())
    );
    PERFORM app_emit_to('message.created', v_payload, app_audience(v_kind, v_low, v_high));
    IF p_thread IS NOT NULL THEN
        PERFORM app_emit_to(
            'thread.updated',
            jsonb_build_object(
                'conversation_id', p_conversation::text,
                'kind', 'channel',
                'message_id', p_thread::text,
                'thread', app_thread_summary(p_thread, NULL)
            ),
            app_audience(v_kind, v_low, v_high)
        );
    END IF;
    RETURN v_payload->'message';
END;
$$;

-- Deleting a thread reply also emits thread.updated for its root.
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
    v_thread uuid;
    v_mine boolean;
    v_kind text;
    v_low uuid;
    v_high uuid;
    v_conv uuid;
    v_files text[];
    v_all uuid[];
BEGIN
    PERFORM app_msg_voice();
    SELECT author_id, channel_id, direct_id, deleted_at, thread_id
    INTO v_author, v_channel, v_direct, v_deleted, v_thread
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
    IF v_thread IS NOT NULL THEN
        PERFORM app_emit_to(
            'thread.updated',
            jsonb_build_object(
                'conversation_id', v_conv::text,
                'kind', 'channel',
                'message_id', v_thread::text,
                'thread', app_thread_summary(v_thread, NULL)
            ),
            app_audience(v_kind, v_low, v_high)
        );
    END IF;
    RETURN v_files;
END;
$$;

REVOKE EXECUTE ON FUNCTION app_list_messages_filtered(uuid, uuid, integer, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_list_messages_filtered(uuid, uuid, integer, boolean) TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_list_thread_messages(uuid, uuid, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_list_thread_messages(uuid, uuid, integer) TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_mark_thread_read(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_mark_thread_read(uuid, uuid) TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_follow_thread(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_follow_thread(uuid) TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_unfollow_thread(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_unfollow_thread(uuid) TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_list_followed_threads() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_list_followed_threads() TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_post_message_thread(uuid, text, uuid, text, uuid[], jsonb, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_post_message_thread(uuid, text, uuid, text, uuid[], jsonb, uuid, uuid) TO app_runtime;

-- Rollback: crates/db/rollback/0054_channel_threads.down.sql restores app_delete_message,
-- app_message_json, app_unread, drops thread functions, thread_follows, and messages.thread_id.
