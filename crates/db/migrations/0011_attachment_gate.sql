-- Fail-closed scan gate for chat attachments.
-- scan_status starts uploaded; POST /v1/media does not return 201 until clean.
-- allow_archives is reserved for the later archive-opt-in task (default false).

ALTER TABLE attachments
    ADD COLUMN scan_status text NOT NULL DEFAULT 'uploaded'
        CHECK (scan_status IN ('uploaded', 'scanning', 'clean', 'blocked', 'error')),
    ADD COLUMN scanned_at timestamptz;

-- Linked files from before this gate were already delivered; leave them downloadable.
UPDATE attachments
SET scan_status = 'clean', scanned_at = now()
WHERE message_id IS NOT NULL AND scan_status = 'uploaded';

ALTER TABLE server_settings
    ADD COLUMN allow_archives boolean NOT NULL DEFAULT false;

CREATE OR REPLACE FUNCTION app_save_attachment(
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
    v_image bigint;
    v_file bigint;
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
    SELECT image_max_bytes, file_max_bytes INTO v_image, v_file FROM server_settings;
    IF p_bytes IS NULL OR p_bytes < 1
       OR (p_kind IN ('image', 'gif') AND p_bytes > v_image)
       OR (p_kind IN ('video', 'file') AND p_bytes > v_file) THEN
        RAISE EXCEPTION 'too large' USING ERRCODE = '22023';
    END IF;
    IF v_name IS NULL OR char_length(v_name) < 1 OR char_length(v_name) > 200
       OR p_mime IS NULL OR char_length(p_mime) < 1 OR char_length(p_mime) > 127 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    INSERT INTO attachments (
        uploader_id, name, mime, kind, bytes, width, height, duration, scan_status
    ) VALUES (
        app_uid(), v_name, p_mime, p_kind, p_bytes, p_width, p_height, p_duration, 'uploaded'
    ) RETURNING id INTO v_id;
    RETURN jsonb_build_object(
        'id', v_id::text,
        'name', v_name,
        'mime', p_mime,
        'kind', p_kind,
        'bytes', p_bytes,
        'width', p_width,
        'height', p_height,
        'duration', p_duration,
        'scan_status', 'uploaded'
    );
END;
$$;

CREATE OR REPLACE FUNCTION app_set_attachment_scan(p_id uuid, p_status text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    PERFORM app_msg_voice();
    IF p_status IS NULL OR p_status NOT IN ('scanning', 'clean', 'blocked', 'error') THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    UPDATE attachments
    SET scan_status = p_status,
        scanned_at = CASE
            WHEN p_status IN ('clean', 'blocked', 'error') THEN now()
            ELSE scanned_at
        END
    WHERE id = p_id AND uploader_id = app_uid();
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
END;
$$;

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
              AND a.scan_status = 'clean'
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
          AND a.message_id IS NULL
          AND a.scan_status = 'clean';
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

DO $$
DECLARE
    v_function text;
BEGIN
    FOREACH v_function IN ARRAY ARRAY[
        'app_save_attachment(text, text, text, integer, integer, integer, integer)',
        'app_set_attachment_scan(uuid, text)',
        'app_post_message(uuid, text, uuid, text, uuid[])',
        'app_attachment_meta(uuid)'
    ]
    LOOP
        EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', v_function);
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO app_runtime', v_function);
    END LOOP;
END $$;
