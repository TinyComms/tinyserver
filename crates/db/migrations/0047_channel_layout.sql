-- Unified channel and room ordering for `PUT /v1/layout` (issue #54).
--
-- 1. One-time renumbering: per category (and for the uncategorized bucket), give text channels
--    positions 0..n in their current (position, name, id) order, then voice rooms n.. in their
--    current (position, name, id) order. Nothing moves on screen for released clients, which draw
--    text above voice regardless of position.
-- 2. New channels (when position is omitted) and new rooms land after the last item in their
--    category across both tables, via `app_category_next_position`.
-- 3. `app_layout_move_channel` moves a single channel inside `PUT /v1/layout`, checking
--    `app_channel_has(id, 512)` and emitting `channel.updated` (narrowed to viewers by
--    `app_scope_audience`) only when the channel's category or position actually changed.

WITH ranked_channels AS (
    SELECT id,
           category_id,
           (row_number() OVER (PARTITION BY category_id ORDER BY position, name, id) - 1)::integer AS new_pos
    FROM channels
)
UPDATE channels c
SET position = rc.new_pos
FROM ranked_channels rc
WHERE c.id = rc.id;

WITH channel_counts AS (
    SELECT category_id, count(*)::integer AS cnt
    FROM channels
    GROUP BY category_id
),
ranked_rooms AS (
    SELECT r.id,
           (coalesce(cc.cnt, 0)
            + row_number() OVER (PARTITION BY r.category_id ORDER BY r.position, r.name, r.id)
            - 1)::integer AS new_pos
    FROM rooms r
    LEFT JOIN channel_counts cc
      ON cc.category_id IS NOT DISTINCT FROM r.category_id
)
UPDATE rooms r
SET position = rr.new_pos
FROM ranked_rooms rr
WHERE r.id = rr.id;

-- Next position at the end of a category (or the uncategorized bucket when NULL), counting both
-- text channels and voice rooms.
CREATE FUNCTION app_category_next_position(p_category uuid)
RETURNS integer
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT coalesce(max(pos) + 1, 0)::integer
    FROM (
        SELECT position AS pos FROM channels WHERE category_id IS NOT DISTINCT FROM p_category
        UNION ALL
        SELECT position AS pos FROM rooms WHERE category_id IS NOT DISTINCT FROM p_category
    ) items;
$$;

REVOKE EXECUTE ON FUNCTION app_category_next_position(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_category_next_position(uuid) TO app_runtime;

-- Replaces `app_create_channel` from 0022_e2ee_text_messages.sql so an omitted `p_position`
-- places the new channel after the last item in its category across both tables.
CREATE OR REPLACE FUNCTION app_create_channel(
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
    v_position integer;
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
    v_position := coalesce(p_position, app_category_next_position(p_category));
    INSERT INTO channels (category_id, name, topic, position, created_by, e2ee)
    VALUES (p_category, v_name, v_topic, v_position, app_uid(), v_e2ee)
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

-- Moves one text channel during `PUT /v1/layout`. A missing, hidden, or unmanageable channel
-- raises P0002 (404) so the whole layout transaction rolls back. Emits `channel.updated` only
-- when the row's category or position actually changed.
CREATE FUNCTION app_layout_move_channel(p_id uuid, p_category uuid, p_position integer)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_old_category uuid;
    v_old_position integer;
BEGIN
    PERFORM app_msg_gate();
    IF NOT app_has(512) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    SELECT category_id, position INTO v_old_category, v_old_position
    FROM channels
    WHERE id = p_id;
    IF NOT FOUND
       OR NOT app_channel_has(p_id, 1)
       OR NOT app_channel_has(p_id, 512) THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    IF v_old_category IS NOT DISTINCT FROM p_category AND v_old_position = p_position THEN
        RETURN false;
    END IF;
    UPDATE channels
    SET category_id = p_category, position = p_position
    WHERE id = p_id;
    PERFORM app_emit('channel.updated', jsonb_build_object('channel', app_channel_json(p_id)));
    RETURN true;
END;
$$;

REVOKE EXECUTE ON FUNCTION app_layout_move_channel(uuid, uuid, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_layout_move_channel(uuid, uuid, integer) TO app_runtime;
