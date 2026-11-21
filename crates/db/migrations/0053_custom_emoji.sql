-- Custom emoji and stickers (issue #66).
--
-- Stored in Postgres like server icons and avatars. Names are 2 to 32 lowercase ASCII
-- alphanumerics and underscores, unique across the community. `kind` is 'emoji' (<= 256 KiB)
-- or 'sticker' (<= 512 KiB, <= 512 px). At most 200 per kind; the 201st is refused with
-- P0E24 (`409 emoji_limit`). Manage permission is `manage_server` (524288).
--
-- Reactions gain nullable `emoji_id` with ON DELETE CASCADE so deleting a custom emoji removes
-- its reactions while leaving message text intact. Messages gain `emoji_spans` (validated spans
-- pointing at custom emoji ids) and nullable `sticker_id` (ON DELETE SET NULL).

CREATE TABLE emoji (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind text NOT NULL DEFAULT 'emoji' CHECK (kind IN ('emoji', 'sticker')),
    name text NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9_]{2,32}$'),
    mime text NOT NULL CHECK (mime IN ('image/png', 'image/jpeg', 'image/webp', 'image/gif')),
    bytes bytea NOT NULL CHECK (
        octet_length(bytes) > 0
        AND (
            (kind = 'emoji' AND octet_length(bytes) <= 262144)
            OR (kind = 'sticker' AND octet_length(bytes) <= 524288)
        )
    ),
    sha256 text NOT NULL CHECK (char_length(sha256) = 64),
    animated boolean NOT NULL DEFAULT false,
    created_by uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX emoji_kind_name ON emoji (kind, name, id);

ALTER TABLE emoji ENABLE ROW LEVEL SECURITY;
ALTER TABLE emoji FORCE ROW LEVEL SECURITY;
REVOKE ALL ON emoji FROM app_runtime;

ALTER TABLE messages ADD COLUMN emoji_spans jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE messages ADD COLUMN sticker_id uuid REFERENCES emoji (id) ON DELETE SET NULL;

ALTER TABLE reactions ADD COLUMN emoji_id uuid REFERENCES emoji (id) ON DELETE CASCADE;
ALTER TABLE reactions DROP CONSTRAINT IF EXISTS reactions_emoji_check;
ALTER TABLE reactions ADD CONSTRAINT reactions_emoji_check
    CHECK (char_length(emoji) BETWEEN 1 AND 36);
ALTER TABLE reactions DROP CONSTRAINT IF EXISTS reactions_pkey;

CREATE UNIQUE INDEX reactions_unicode_uniq
    ON reactions (message_id, user_id, emoji)
    WHERE emoji_id IS NULL;

CREATE UNIQUE INDEX reactions_custom_uniq
    ON reactions (message_id, user_id, emoji_id)
    WHERE emoji_id IS NOT NULL;

CREATE FUNCTION app_emoji_list_json(p_kind text DEFAULT NULL)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT coalesce(
        jsonb_agg(
            jsonb_build_object(
                'id', e.id::text,
                'kind', e.kind,
                'name', e.name,
                'animated', e.animated,
                'sha256', e.sha256
            ) ORDER BY e.name, e.id
        ),
        '[]'::jsonb
    )
    FROM emoji e
    WHERE p_kind IS NULL OR e.kind = p_kind;
$$;

REVOKE EXECUTE ON FUNCTION app_emoji_list_json(text) FROM PUBLIC;

CREATE FUNCTION app_list_emoji(p_kind text DEFAULT NULL)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    PERFORM app_msg_gate();
    IF p_kind IS NOT NULL AND p_kind NOT IN ('emoji', 'sticker') THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    RETURN app_emoji_list_json(p_kind);
END;
$$;

CREATE FUNCTION app_get_emoji(p_id uuid)
RETURNS TABLE (bytes bytea, mime text, sha256 text)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    PERFORM app_msg_gate();
    RETURN QUERY
    SELECT e.bytes, e.mime, e.sha256
    FROM emoji e
    WHERE e.id = p_id;
END;
$$;

CREATE FUNCTION app_create_emoji(
    p_kind text,
    p_name text,
    p_mime text,
    p_bytes bytea,
    p_sha256 text,
    p_animated boolean
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_id uuid;
    v_row jsonb;
BEGIN
    PERFORM app_msg_voice();
    IF NOT app_has(524288) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    IF p_kind NOT IN ('emoji', 'sticker') THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF p_name IS NULL OR p_name !~ '^[a-z0-9_]{2,32}$' THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.emoji'));
    IF (SELECT count(*) FROM emoji WHERE kind = p_kind) >= 200 THEN
        RAISE EXCEPTION 'emoji limit' USING ERRCODE = 'P0E25';
    END IF;
    INSERT INTO emoji (kind, name, mime, bytes, sha256, animated, created_by)
    VALUES (p_kind, p_name, p_mime, p_bytes, p_sha256, p_animated, app_uid())
    RETURNING id INTO v_id;
    v_row := jsonb_build_object(
        'id', v_id::text,
        'kind', p_kind,
        'name', p_name,
        'animated', p_animated,
        'sha256', p_sha256
    );
    PERFORM app_audit(
        'emoji.create', 'emoji',
        jsonb_build_object('emoji_id', v_id::text, 'kind', p_kind, 'name', p_name),
        NULL, NULL
    );
    PERFORM app_emit_to(
        'emoji.updated',
        jsonb_build_object('emoji', app_emoji_list_json(NULL)),
        NULL
    );
    RETURN v_row;
END;
$$;

CREATE FUNCTION app_rename_emoji(p_id uuid, p_name text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_kind text;
    v_animated boolean;
    v_sha text;
    v_old text;
    v_row jsonb;
BEGIN
    PERFORM app_msg_voice();
    IF NOT app_has(524288) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    IF p_name IS NULL OR p_name !~ '^[a-z0-9_]{2,32}$' THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    SELECT kind, name, animated, sha256
    INTO v_kind, v_old, v_animated, v_sha
    FROM emoji WHERE id = p_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    UPDATE emoji SET name = p_name WHERE id = p_id;
    UPDATE reactions SET emoji = ':' || p_name || ':' WHERE emoji_id = p_id;
    v_row := jsonb_build_object(
        'id', p_id::text,
        'kind', v_kind,
        'name', p_name,
        'animated', v_animated,
        'sha256', v_sha
    );
    PERFORM app_audit(
        'emoji.update', 'emoji',
        jsonb_build_object('emoji_id', p_id::text, 'old_name', v_old, 'name', p_name),
        NULL, NULL
    );
    PERFORM app_emit_to(
        'emoji.updated',
        jsonb_build_object('emoji', app_emoji_list_json(NULL)),
        NULL
    );
    RETURN v_row;
END;
$$;

CREATE FUNCTION app_delete_emoji(p_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_kind text;
    v_name text;
BEGIN
    PERFORM app_msg_voice();
    IF NOT app_has(524288) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    DELETE FROM emoji WHERE id = p_id RETURNING kind, name INTO v_kind, v_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    PERFORM app_audit(
        'emoji.delete', 'emoji',
        jsonb_build_object('emoji_id', p_id::text, 'kind', v_kind, 'name', v_name),
        NULL, NULL
    );
    PERFORM app_emit_to(
        'emoji.updated',
        jsonb_build_object('emoji', app_emoji_list_json(NULL)),
        NULL
    );
END;
$$;

-- Custom emoji reaction: toggles or clears a reaction keyed by emoji_id.
CREATE FUNCTION app_custom_reaction(p_message uuid, p_emoji_id uuid, p_on boolean)
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
    v_name text;
    v_label text;
    v_count integer;
    v_me boolean;
BEGIN
    PERFORM app_msg_voice();
    SELECT name INTO v_name FROM emoji WHERE id = p_emoji_id AND kind = 'emoji';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    v_label := ':' || v_name || ':';
    SELECT channel_id, direct_id, deleted_at INTO v_channel, v_direct, v_deleted
    FROM messages WHERE id = p_message;
    IF NOT FOUND OR v_deleted IS NOT NULL THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    v_conv := coalesce(v_channel, v_direct);
    SELECT kind, low_user_id, high_user_id INTO v_kind, v_low, v_high
    FROM app_open_conversation(v_conv, true);
    IF p_on THEN
        INSERT INTO reactions (message_id, user_id, emoji, emoji_id)
        VALUES (p_message, app_uid(), v_label, p_emoji_id)
        ON CONFLICT (message_id, user_id, emoji_id) WHERE emoji_id IS NOT NULL DO NOTHING;
    ELSE
        DELETE FROM reactions
        WHERE message_id = p_message AND user_id = app_uid() AND emoji_id = p_emoji_id;
    END IF;
    SELECT count(*)::integer, coalesce(bool_or(user_id = app_uid()), false)
    INTO v_count, v_me
    FROM reactions
    WHERE message_id = p_message AND emoji_id = p_emoji_id;
    PERFORM app_emit_to(
        'reaction.updated',
        jsonb_build_object(
            'message_id', p_message::text,
            'conversation_id', v_conv::text,
            'kind', v_kind,
            'emoji', v_label,
            'emoji_id', p_emoji_id::text,
            'name', v_name,
            'on', p_on,
            'user_id', app_uid()::text,
            'count', v_count
        ),
        app_audience(v_kind, v_low, v_high)
    );
    RETURN jsonb_build_object(
        'emoji', v_label,
        'emoji_id', p_emoji_id::text,
        'name', v_name,
        'count', v_count,
        'me', v_me
    );
END;
$$;

REVOKE EXECUTE ON FUNCTION app_custom_reaction(uuid, uuid, boolean) FROM PUBLIC;

CREATE FUNCTION app_toggle_custom_reaction(p_message uuid, p_emoji_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_on boolean;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM reactions
        WHERE message_id = p_message AND user_id = app_uid() AND emoji_id = p_emoji_id
    ) INTO v_on;
    RETURN app_custom_reaction(p_message, p_emoji_id, NOT v_on);
END;
$$;

CREATE FUNCTION app_clear_custom_reaction(p_message uuid, p_emoji_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM reactions
        WHERE message_id = p_message AND user_id = app_uid() AND emoji_id = p_emoji_id
    ) THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    PERFORM app_custom_reaction(p_message, p_emoji_id, false);
END;
$$;

-- Update unicode app_reaction so its ON CONFLICT targets the partial unicode index.
CREATE OR REPLACE FUNCTION app_reaction(p_message uuid, p_emoji text, p_on boolean)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_channel uuid;
    v_direct uuid;
    v_deleted timestamptz;
    v_e2ee boolean;
    v_kind text;
    v_low uuid;
    v_high uuid;
    v_conv uuid;
    v_count integer;
    v_me boolean;
BEGIN
    PERFORM app_emoji_ok(p_emoji);
    PERFORM app_msg_voice();
    SELECT channel_id, direct_id, deleted_at, e2ee
    INTO v_channel, v_direct, v_deleted, v_e2ee
    FROM messages WHERE id = p_message;
    IF NOT FOUND OR v_deleted IS NOT NULL THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    IF v_e2ee THEN
        RAISE EXCEPTION 'e2ee required' USING ERRCODE = 'P0E01';
    END IF;
    v_conv := coalesce(v_channel, v_direct);
    SELECT kind, low_user_id, high_user_id INTO v_kind, v_low, v_high
    FROM app_open_conversation(v_conv, true);
    IF p_on THEN
        INSERT INTO reactions (message_id, user_id, emoji, emoji_id)
        VALUES (p_message, app_uid(), p_emoji, NULL)
        ON CONFLICT (message_id, user_id, emoji) WHERE emoji_id IS NULL DO NOTHING;
    ELSE
        DELETE FROM reactions
        WHERE message_id = p_message AND user_id = app_uid()
          AND emoji = p_emoji AND emoji_id IS NULL;
    END IF;
    SELECT count(*)::integer, coalesce(bool_or(user_id = app_uid()), false)
    INTO v_count, v_me
    FROM reactions
    WHERE message_id = p_message AND emoji = p_emoji AND emoji_id IS NULL;
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

-- Update app_message_json to include emoji spans, sticker_id, and custom reaction metadata.
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
            WHERE a.message_id = m.id AND NOT a.is_preview AND m.deleted_at IS NULL
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
        ), '[]'::jsonb),
        'previews', coalesce((
            SELECT jsonb_agg(
                jsonb_strip_nulls(jsonb_build_object(
                    'url', mp.url,
                    'site', mp.site,
                    'title', mp.title,
                    'description', mp.description,
                    'image_attachment_id', mp.image_attachment_id::text
                ))
                ORDER BY mp.sort
            )
            FROM message_previews mp
            WHERE mp.message_id = m.id AND m.deleted_at IS NULL
        ), '[]'::jsonb)
    ) END
    FROM messages m
    WHERE m.id = p_id;
$$;

-- Extended post_message accepting validated custom emoji spans and optional sticker_id.
CREATE FUNCTION app_post_message_ext(
    p_conversation uuid,
    p_body text,
    p_reply uuid,
    p_client text,
    p_attachments uuid[],
    p_emoji jsonb,
    p_sticker uuid
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
            channel_id, direct_id, author_id, body, reply_to, client_id, emoji_spans, sticker_id
        )
        VALUES (
            v_channel, v_direct, app_uid(), v_body, p_reply, v_client, v_emoji, p_sticker
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
    v_payload := jsonb_build_object(
        'conversation_id', p_conversation::text,
        'kind', v_kind,
        'message', app_message_json(v_id, app_uid())
    );
    PERFORM app_emit_to('message.created', v_payload, app_audience(v_kind, v_low, v_high));
    RETURN v_payload->'message';
END;
$$;

REVOKE EXECUTE ON FUNCTION app_list_emoji(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_list_emoji(text) TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_get_emoji(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_get_emoji(uuid) TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_create_emoji(text, text, text, bytea, text, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_create_emoji(text, text, text, bytea, text, boolean) TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_rename_emoji(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_rename_emoji(uuid, text) TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_delete_emoji(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_delete_emoji(uuid) TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_toggle_custom_reaction(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_toggle_custom_reaction(uuid, uuid) TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_clear_custom_reaction(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_clear_custom_reaction(uuid, uuid) TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_post_message_ext(uuid, text, uuid, text, uuid[], jsonb, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_post_message_ext(uuid, text, uuid, text, uuid[], jsonb, uuid) TO app_runtime;

-- Rollback: crates/db/rollback/0053_custom_emoji.down.sql drops the emoji table, columns,
-- indexes and functions, and restores app_message_json and app_reaction.
