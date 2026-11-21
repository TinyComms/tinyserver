-- Undoes migrations/0047_channel_layout.sql. Run as the owner role, in one transaction, then
-- start the previous image. Restores `app_create_channel` from 0022_e2ee_text_messages.sql and
-- drops the layout helpers. The renumbered positions stay valid for previous images.

BEGIN;

CREATE OR REPLACE FUNCTION app_create_channel(
    p_name text,
    p_category uuid,
    p_topic text,
    p_position integer,
    p_e2ee boolean
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
    IF v_e2ee AND (SELECT count(*) FROM app_e2ee_desired(v_id)) > app_e2ee_group_devices_max() THEN
        RAISE EXCEPTION 'group too large' USING ERRCODE = 'P0E16';
    END IF;
    PERFORM app_audit(
        'channel.create', 'channel',
        jsonb_build_object('id', v_id, 'name', v_name, 'e2ee', v_e2ee),
        NULL, NULL
    );
    PERFORM app_emit('channel.created', jsonb_build_object('channel', app_channel_json(v_id)));
    RETURN app_channel_json(v_id);
END;
$$;

DROP FUNCTION app_layout_move_channel(uuid, uuid, integer);
DROP FUNCTION app_category_next_position(uuid);

DELETE FROM _sqlx_migrations WHERE version = 47;

COMMIT;
