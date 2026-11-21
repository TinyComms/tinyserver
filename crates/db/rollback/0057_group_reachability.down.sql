-- Undoes migrations/0057_group_reachability.sql. Run as the owner role, in one transaction,
-- then start the previous build.

BEGIN;

-- Restore `app_typing_recipients` from 0055_group_dms.sql.
CREATE OR REPLACE FUNCTION app_typing_recipients(p_conversation uuid)
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
    v_group uuid;
BEGIN
    SELECT kind, channel_id, direct_id, low_user_id, high_user_id, group_dm_id
    INTO v_kind, v_channel, v_direct, v_low, v_high, v_group
    FROM app_open_conversation(p_conversation, true);
    IF v_kind = 'direct' THEN
        RETURN ARRAY[
            CASE WHEN v_low = app_uid() THEN v_high ELSE v_low END::text
        ];
    ELSIF v_kind = 'group' THEN
        RETURN coalesce((
            SELECT array_agg(gm.user_id::text)
            FROM group_dm_members gm
            WHERE gm.group_dm_id = v_group
              AND gm.user_id <> app_uid()
        ), '{}'::text[]);
    END IF;
    RETURN coalesce((
        SELECT array_agg(m.user_id::text)
        FROM memberships m
        WHERE m.user_id <> app_uid()
          AND app_channel_perms_of(v_channel, m.user_id) & 1 = 1
    ), '{}'::text[]);
END;
$$;

-- Restore `app_open_conversation` from 0055_group_dms.sql.
CREATE OR REPLACE FUNCTION app_open_conversation(p_id uuid, p_need_speak boolean)
RETURNS TABLE (
    kind text,
    channel_id uuid,
    direct_id uuid,
    low_user_id uuid,
    high_user_id uuid,
    group_dm_id uuid,
    audience uuid[]
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_channel uuid;
    v_low uuid;
    v_high uuid;
    v_group uuid;
    v_group_e2ee boolean;
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
        group_dm_id := NULL;
        audience := NULL;
        RETURN NEXT;
        RETURN;
    END IF;
    SELECT d.id, d.low_user_id, d.high_user_id INTO v_channel, v_low, v_high
    FROM directs d
    WHERE d.id = p_id AND app_uid() IN (d.low_user_id, d.high_user_id);
    IF FOUND THEN
        IF p_need_speak THEN
            PERFORM app_msg_voice();
            IF NOT app_is_member_of(v_low) OR NOT app_is_member_of(v_high) THEN
                RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
            END IF;
            IF app_banned(v_low) OR app_banned(v_high) THEN
                RAISE EXCEPTION 'banned' USING ERRCODE = '42501';
            END IF;
            IF app_blocked_pair(v_low, v_high) THEN
                RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
            END IF;
        END IF;
        kind := 'direct';
        channel_id := NULL;
        direct_id := p_id;
        low_user_id := v_low;
        high_user_id := v_high;
        group_dm_id := NULL;
        audience := ARRAY[v_low, v_high];
        RETURN NEXT;
        RETURN;
    END IF;
    SELECT g.id, g.e2ee INTO v_group, v_group_e2ee
    FROM group_dms g
    JOIN group_dm_members gm ON gm.group_dm_id = g.id
    WHERE g.id = p_id AND gm.user_id = app_uid();
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    IF v_group_e2ee THEN
        RAISE EXCEPTION 'e2ee is off' USING ERRCODE = 'P0E12';
    END IF;
    IF p_need_speak THEN
        PERFORM app_msg_voice();
    END IF;
    kind := 'group';
    channel_id := NULL;
    direct_id := NULL;
    low_user_id := NULL;
    high_user_id := NULL;
    group_dm_id := v_group;
    audience := app_group_audience(v_group, NULL);
    RETURN NEXT;
END;
$$;

-- Restore `app_group_list` and `app_group_members_json` from 0056_groups_api.sql.
CREATE OR REPLACE FUNCTION app_group_list()
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    PERFORM app_msg_gate();
    RETURN jsonb_build_object(
        'groups',
        coalesce((
            SELECT jsonb_agg(app_group_json(g.id) ORDER BY g.created_at, g.id)
            FROM group_dms g
            JOIN group_dm_members gm ON gm.group_dm_id = g.id
            WHERE gm.user_id = app_uid()
        ), '[]'::jsonb)
    );
END;
$$;

CREATE OR REPLACE FUNCTION app_group_members_json(p_id uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT coalesce(
        jsonb_agg(
            jsonb_build_object(
                'user_id', gm.user_id::text,
                'display_name', u.display_name,
                'joined_at', app_stamp(gm.joined_at)
            )
            ORDER BY gm.joined_at, gm.seq
        ),
        '[]'::jsonb
    )
    FROM group_dm_members gm
    JOIN users u ON u.id = gm.user_id
    WHERE gm.group_dm_id = p_id;
$$;

DROP FUNCTION IF EXISTS app_group_reachable_audience(uuid);
ALTER TABLE memberships DROP COLUMN IF EXISTS groups_seen_at;

DELETE FROM _sqlx_migrations WHERE version = 57;

COMMIT;
