-- A plaintext conversation can be turned on to end-to-end encryption, once, by a member who can
-- speak in it. Messages and files already stored stay as they are: the server already has them,
-- and this does not re-encrypt them or hold a key. Posts from then on are ciphertext only.
-- There is still no way back to plaintext.

CREATE FUNCTION app_e2ee_has_plaintext(p_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM messages m
        WHERE (m.channel_id = p_id OR m.direct_id = p_id)
          AND NOT m.e2ee
          AND m.deleted_at IS NULL
    );
$$;

REVOKE EXECUTE ON FUNCTION app_e2ee_has_plaintext(uuid) FROM PUBLIC, app_runtime;

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
        'plaintext_history', c.e2ee AND app_e2ee_has_plaintext(c.id),
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
        'plaintext_history', d.e2ee AND app_e2ee_has_plaintext(d.id),
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

-- Turns a plaintext conversation into an encrypted one. Already encrypted is the same answer
-- again, and does not announce it a second time. `e2ee_text = off` refuses a new upgrade.
-- A channel whose audience is already over the device cap is not upgraded. A pair that already
-- has an encrypted direct keeps the plaintext one as it is (`e2ee twin`).
CREATE FUNCTION app_e2ee_upgrade(p_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_kind text;
    v_low uuid;
    v_high uuid;
    v_mode text;
BEGIN
    SELECT kind, low_user_id, high_user_id
    INTO v_kind, v_low, v_high
    FROM app_open_conversation(p_id, true);
    IF app_conv_e2ee(p_id) THEN
        IF v_kind = 'channel' THEN
            RETURN app_channel_json(p_id);
        END IF;
        RETURN app_direct_json(p_id);
    END IF;
    SELECT s.e2ee_text INTO v_mode FROM server_settings s;
    IF v_mode = 'off' THEN
        RAISE EXCEPTION 'e2ee is off' USING ERRCODE = 'P0E12';
    END IF;
    IF v_kind = 'channel'
       AND (SELECT count(*) FROM app_e2ee_desired(p_id)) > app_e2ee_group_devices_max() THEN
        RAISE EXCEPTION 'group too large' USING ERRCODE = 'P0E16';
    END IF;
    IF v_kind = 'direct' AND EXISTS (
        SELECT 1 FROM directs other
        WHERE other.low_user_id = v_low
          AND other.high_user_id = v_high
          AND other.e2ee
          AND other.id <> p_id
    ) THEN
        RAISE EXCEPTION 'e2ee twin' USING ERRCODE = 'P0E19';
    END IF;
    BEGIN
        IF v_kind = 'channel' THEN
            UPDATE channels SET e2ee = true WHERE id = p_id AND NOT e2ee;
        ELSE
            UPDATE directs SET e2ee = true WHERE id = p_id AND NOT e2ee;
        END IF;
    EXCEPTION
        WHEN unique_violation THEN
            RAISE EXCEPTION 'e2ee twin' USING ERRCODE = 'P0E19';
    END;
    PERFORM app_audit(
        'e2ee.upgrade', v_kind,
        jsonb_build_object('id', p_id, 'plaintext_history', app_e2ee_has_plaintext(p_id)),
        NULL, NULL
    );
    IF v_kind = 'channel' THEN
        PERFORM app_emit('channel.updated', jsonb_build_object('channel', app_channel_json(p_id)));
        PERFORM app_emit(
            'e2ee.upgraded',
            jsonb_build_object(
                'kind', 'channel',
                'conversation_id', p_id::text,
                'plaintext_history', app_e2ee_has_plaintext(p_id)
            )
        );
        RETURN app_channel_json(p_id);
    END IF;
    PERFORM app_emit_to(
        'e2ee.upgraded',
        jsonb_build_object(
            'conversation_id', p_id::text,
            'plaintext_history', app_e2ee_has_plaintext(p_id)
        ),
        ARRAY[v_low, v_high]
    );
    RETURN app_direct_json(p_id);
END;
$$;

REVOKE EXECUTE ON FUNCTION app_e2ee_upgrade(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_e2ee_upgrade(uuid) TO app_runtime;
