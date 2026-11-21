-- Sender-supplied link previews for plaintext messages (issue #67).
--
-- The server never fetches linked URLs. The sender's app unfurls a link once before posting,
-- optionally uploads the preview image through the standard scanned/re-encoded media route,
-- and attaches up to 3 previews to the message. Preview images are bound to the message with
-- `attachments.is_preview = true` so download authorization and cleanup match normal attachments,
-- while keeping them out of the message's `attachments` array.
--
-- Encrypted conversations carry previews inside the sealed payload; plaintext `previews` on a
-- ciphertext post is refused with `400 e2ee_required`, and encrypted rows omit `previews`.

-- 1. Preview image flag on attachments and message_previews table.

ALTER TABLE attachments ADD COLUMN is_preview boolean NOT NULL DEFAULT false;

CREATE TABLE message_previews (
    message_id uuid NOT NULL REFERENCES messages (id) ON DELETE CASCADE,
    sort integer NOT NULL CHECK (sort >= 1 AND sort <= 3),
    url text NOT NULL,
    site text,
    title text,
    description text,
    image_attachment_id uuid REFERENCES attachments (id) ON DELETE SET NULL,
    PRIMARY KEY (message_id, sort)
);

CREATE INDEX message_previews_image ON message_previews (image_attachment_id)
    WHERE image_attachment_id IS NOT NULL;

ALTER TABLE message_previews ENABLE ROW LEVEL SECURITY;
ALTER TABLE message_previews FORCE ROW LEVEL SECURITY;

REVOKE ALL ON message_previews FROM app_runtime;

-- Validates and stores previews for a plaintext message, returning attachment ids of any
-- previously-bound preview images that are no longer referenced and should be unlinked from disk.
CREATE FUNCTION app_store_previews(
    p_message uuid,
    p_body text,
    p_previews jsonb
)
RETURNS text[]
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_elem jsonb;
    v_sort integer := 0;
    v_url text;
    v_site text;
    v_title text;
    v_desc text;
    v_img_text text;
    v_img uuid;
    v_seen_imgs uuid[] := '{}';
    v_removed text[];
BEGIN
    IF p_previews IS NULL THEN
        -- Edit without explicit previews: drop any preview whose URL is no longer in the body.
        DELETE FROM message_previews
        WHERE message_id = p_message
          AND position(url IN coalesce(p_body, '')) = 0;
    ELSE
        IF jsonb_typeof(p_previews) <> 'array' THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
        IF jsonb_array_length(p_previews) > 3 THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;

        DELETE FROM message_previews WHERE message_id = p_message;

        FOR v_elem IN SELECT value FROM jsonb_array_elements(p_previews) LOOP
            v_sort := v_sort + 1;
            IF jsonb_typeof(v_elem) <> 'object' THEN
                RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
            END IF;
            v_url := v_elem->>'url';
            IF v_url IS NULL OR char_length(v_url) = 0 OR char_length(v_url) > 2048
               OR v_url ~ E'[\\x00-\\x1F\\x7F]'
               OR v_url !~* '^https?://'
               OR position(v_url IN coalesce(p_body, '')) = 0 THEN
                RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
            END IF;

            v_site := v_elem->>'site';
            IF v_site IS NOT NULL AND (char_length(v_site) > 100 OR v_site ~ E'[\\x00-\\x1F\\x7F]') THEN
                RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
            END IF;

            v_title := v_elem->>'title';
            IF v_title IS NOT NULL AND (char_length(v_title) > 200 OR v_title ~ E'[\\x00-\\x1F\\x7F]') THEN
                RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
            END IF;

            v_desc := v_elem->>'description';
            IF v_desc IS NOT NULL AND (char_length(v_desc) > 500 OR v_desc ~ E'[\\x00-\\x1F\\x7F]') THEN
                RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
            END IF;

            v_img_text := v_elem->>'image_attachment_id';
            v_img := NULL;
            IF v_img_text IS NOT NULL THEN
                BEGIN
                    v_img := v_img_text::uuid;
                EXCEPTION WHEN invalid_text_representation THEN
                    RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
                END;
                IF v_img = ANY (v_seen_imgs) THEN
                    RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
                END IF;
                IF NOT EXISTS (
                    SELECT 1 FROM attachments a
                    WHERE a.id = v_img
                      AND a.uploader_id = app_uid()
                      AND a.scan_status = 'clean'
                      AND a.kind = 'image'
                      AND (
                          (a.message_id IS NULL AND a.created_at > now() - interval '1 hour')
                          OR (a.message_id = p_message AND a.is_preview)
                      )
                ) THEN
                    RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
                END IF;
                UPDATE attachments
                SET message_id = p_message, is_preview = true, sort = 0
                WHERE id = v_img AND message_id IS NULL;
                v_seen_imgs := array_append(v_seen_imgs, v_img);
            END IF;

            INSERT INTO message_previews (
                message_id, sort, url, site, title, description, image_attachment_id
            )
            VALUES (
                p_message, v_sort, v_url,
                nullif(v_site, ''), nullif(v_title, ''), nullif(v_desc, ''),
                v_img
            );
        END LOOP;
    END IF;

    -- Clean up any preview images bound to this message that are no longer referenced.
    SELECT coalesce(array_agg(a.id::text), '{}') INTO v_removed
    FROM attachments a
    WHERE a.message_id = p_message
      AND a.is_preview
      AND NOT EXISTS (
          SELECT 1 FROM message_previews mp
          WHERE mp.message_id = p_message AND mp.image_attachment_id = a.id
      );
    IF cardinality(v_removed) > 0 THEN
        DELETE FROM attachments
        WHERE id::text = ANY (v_removed);
    END IF;
    RETURN coalesce(v_removed, '{}'::text[]);
END;
$$;

REVOKE EXECUTE ON FUNCTION app_store_previews(uuid, text, jsonb) FROM PUBLIC, app_runtime;

-- 2. Message JSON: exclude preview images from `attachments`, add `previews` on plaintext rows.

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
            WHERE a.message_id = m.id AND NOT a.is_preview AND m.deleted_at IS NULL
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

-- 3. Post, edit, delete messages.

DROP FUNCTION app_post_message(uuid, text, uuid, text, uuid[], jsonb);
CREATE FUNCTION app_post_message(
    p_conversation uuid,
    p_body text,
    p_reply uuid,
    p_client text,
    p_attachments uuid[],
    p_mentions jsonb DEFAULT NULL,
    p_previews jsonb DEFAULT NULL
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
    IF p_previews IS NOT NULL THEN
        PERFORM app_store_previews(v_id, v_body, p_previews);
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

DROP FUNCTION app_edit_message(uuid, text, jsonb);
CREATE FUNCTION app_edit_message(
    p_id uuid,
    p_body text,
    p_mentions jsonb DEFAULT NULL,
    p_previews jsonb DEFAULT NULL
)
RETURNS TABLE (r_message jsonb, r_removed_files text[])
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
    v_old_body text;
    v_body text;
    v_mine boolean;
    v_mod_strip boolean;
    v_kind text;
    v_low uuid;
    v_high uuid;
    v_conv uuid;
    v_files integer;
    v_removed text[];
BEGIN
    PERFORM app_msg_voice();
    SELECT author_id, channel_id, direct_id, deleted_at, e2ee, body
    INTO v_author, v_channel, v_direct, v_deleted, v_e2ee, v_old_body
    FROM messages WHERE id = p_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    v_mine := v_author = app_uid();
    v_mod_strip := NOT v_mine
        AND p_body IS NULL
        AND p_mentions IS NULL
        AND p_previews IS NOT NULL
        AND jsonb_typeof(p_previews) = 'array'
        AND jsonb_array_length(p_previews) = 0;
    v_conv := coalesce(v_channel, v_direct);
    SELECT kind, low_user_id, high_user_id INTO v_kind, v_low, v_high
    FROM app_open_conversation(v_conv, v_mine);
    IF v_e2ee THEN
        RAISE EXCEPTION 'e2ee required' USING ERRCODE = 'P0E01';
    END IF;
    PERFORM app_e2ee_plaintext_allowed();
    IF NOT v_mine AND NOT (
        v_mod_strip AND v_channel IS NOT NULL AND app_channel_has(v_channel, 2097152)
    ) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    IF v_deleted IS NOT NULL THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF p_body IS NULL AND p_previews IS NULL THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF p_body IS NOT NULL THEN
        v_body := coalesce(btrim(p_body), '');
        IF char_length(v_body) > 4000 THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
        SELECT count(*) INTO v_files
        FROM attachments WHERE message_id = p_id AND NOT is_preview;
        IF v_body = '' AND v_files = 0 THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
        UPDATE messages SET body = v_body, edited_at = now() WHERE id = p_id;
        PERFORM app_store_mentions(p_id, v_kind, v_channel, v_low, v_high, v_body, p_mentions);
    ELSE
        v_body := v_old_body;
    END IF;
    v_removed := app_store_previews(p_id, v_body, p_previews);
    PERFORM app_emit_to(
        'message.edited',
        jsonb_build_object(
            'conversation_id', v_conv::text,
            'kind', v_kind,
            'message', app_message_json(p_id, app_uid())
        ),
        app_audience(v_kind, v_low, v_high)
    );
    RETURN QUERY SELECT app_message_json(p_id, app_uid()), v_removed;
END;
$$;

REVOKE EXECUTE ON FUNCTION app_post_message(uuid, text, uuid, text, uuid[], jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_post_message(uuid, text, uuid, text, uuid[], jsonb, jsonb) TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_edit_message(uuid, text, jsonb, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_edit_message(uuid, text, jsonb, jsonb) TO app_runtime;

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
    DELETE FROM message_previews WHERE message_id = ANY (v_all);
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

-- 4. Account deletion clears preview rows for the user's messages.

CREATE FUNCTION app_previews_forget_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    DELETE FROM message_previews
    WHERE message_id IN (SELECT m.id FROM messages m WHERE m.author_id = NEW.id);
    RETURN NULL;
END;
$$;

REVOKE EXECUTE ON FUNCTION app_previews_forget_user() FROM PUBLIC;

CREATE TRIGGER users_forget_message_previews
    AFTER UPDATE OF deleted_at ON users
    FOR EACH ROW
    WHEN (OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL)
    EXECUTE FUNCTION app_previews_forget_user();

-- Rollback: crates/db/rollback/0052_message_previews.down.sql drops the trigger,
-- message_previews table, attachments.is_preview, and restores the 0050 message functions.
