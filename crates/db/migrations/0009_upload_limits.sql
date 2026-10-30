-- How large an upload may be. An admin with manage_server sets these on server_settings.
-- Images and GIFs use image_max_bytes. Video and every other file use file_max_bytes.
-- Both start at the previous caps (8 MiB and 25 MiB) and cannot pass 100 MiB.

ALTER TABLE server_settings
    ADD COLUMN image_max_bytes bigint NOT NULL DEFAULT 8388608
        CHECK (image_max_bytes BETWEEN 1 AND 104857600),
    ADD COLUMN file_max_bytes bigint NOT NULL DEFAULT 26214400
        CHECK (file_max_bytes BETWEEN 1 AND 104857600);

-- The attachment row may be as large as the ceiling. The function below applies the
-- configured cap, which is never above that ceiling.
ALTER TABLE attachments DROP CONSTRAINT attachments_bytes_check;
ALTER TABLE attachments ADD CONSTRAINT attachments_bytes_check CHECK (bytes > 0 AND bytes <= 104857600);
ALTER TABLE attachments DROP CONSTRAINT attachments_check;

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
