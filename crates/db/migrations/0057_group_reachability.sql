-- Older-client handling for group conversations (issue #58, Option B).
--
-- Already-released clients never call `GET /v1/groups`, so a member on an older app can be added
-- to a group and not see it until they update. Rather than refusing the add (Option A), the add
-- succeeds and the server tracks capability without a new header via `memberships.groups_seen_at`:
--   * Set (at most once a day) when a member calls `GET /v1/groups`.
--   * Exposed per member on group JSON as `"reachable": true|false` (`groups_seen_at IS NOT NULL`).
--   * First transition from NULL to non-NULL emits `group.member_reachable {"group_id", "user_id"}`
--     to every group that member belongs to, clearing the client hint without a reload.
--   * Because older clients (`v0.2.71`) handle `message.created` for unknown conversation ids
--     without having recorded the conversation, live audiences for group `message.*`,
--     `reaction.updated`, `pin.*`, and `typing` exclude members whose `groups_seen_at` is NULL
--     (falling back to the nil UUID if nobody is reachable yet, never NULL or empty).
--
-- Rollback: crates/db/rollback/0057_group_reachability.down.sql.

ALTER TABLE memberships ADD COLUMN groups_seen_at timestamptz;

-- Audience for group message/reaction/pin live events: current members whose client has called
-- `GET /v1/groups` at least once. Falls back to the nil UUID if empty so `Event::from_row` can
-- never treat an empty audience as "everyone".
CREATE FUNCTION app_group_reachable_audience(p_id uuid)
RETURNS uuid[]
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT CASE
        WHEN cardinality(u.ids) = 0 THEN ARRAY['00000000-0000-0000-0000-000000000000'::uuid]
        ELSE u.ids
    END
    FROM (
        SELECT coalesce(array_agg(gm.user_id), '{}'::uuid[]) AS ids
        FROM group_dm_members gm
        JOIN memberships m ON m.user_id = gm.user_id
        WHERE gm.group_dm_id = p_id
          AND m.groups_seen_at IS NOT NULL
    ) u;
$$;

REVOKE EXECUTE ON FUNCTION app_group_reachable_audience(uuid) FROM PUBLIC, app_runtime;

-- Add `"reachable": m.groups_seen_at IS NOT NULL` to each member entry in group objects.
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
                'joined_at', app_stamp(gm.joined_at),
                'reachable', m.groups_seen_at IS NOT NULL
            )
            ORDER BY gm.joined_at, gm.seq
        ),
        '[]'::jsonb
    )
    FROM group_dm_members gm
    JOIN users u ON u.id = gm.user_id
    JOIN memberships m ON m.user_id = gm.user_id
    WHERE gm.group_dm_id = p_id;
$$;

-- Calling `GET /v1/groups` records `memberships.groups_seen_at` (at most once a day). On the
-- first transition from NULL to non-NULL, emits `group.member_reachable` to each group the
-- caller belongs to.
CREATE OR REPLACE FUNCTION app_group_list()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_me uuid := app_uid();
    v_seen timestamptz;
    v_gid uuid;
BEGIN
    PERFORM app_msg_gate();
    SELECT m.groups_seen_at INTO v_seen FROM memberships m WHERE m.user_id = v_me;
    IF v_seen IS NULL THEN
        UPDATE memberships
        SET groups_seen_at = now()
        WHERE user_id = v_me AND groups_seen_at IS NULL;
        IF FOUND THEN
            FOR v_gid IN
                SELECT gm.group_dm_id
                FROM group_dm_members gm
                WHERE gm.user_id = v_me
                ORDER BY gm.group_dm_id
            LOOP
                PERFORM app_emit_to(
                    'group.member_reachable',
                    jsonb_build_object(
                        'group_id', v_gid::text,
                        'user_id', v_me::text
                    ),
                    app_group_audience(v_gid, NULL)
                );
            END LOOP;
        END IF;
    ELSIF v_seen < now() - interval '1 day' THEN
        UPDATE memberships
        SET groups_seen_at = now()
        WHERE user_id = v_me;
    END IF;
    RETURN jsonb_build_object(
        'groups',
        coalesce((
            SELECT jsonb_agg(app_group_json(g.id) ORDER BY g.created_at, g.id)
            FROM group_dms g
            JOIN group_dm_members gm ON gm.group_dm_id = g.id
            WHERE gm.user_id = v_me
        ), '[]'::jsonb)
    );
END;
$$;

-- Gate live message/reaction/pin event audiences on groups to reachable members only.
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
    audience := app_group_reachable_audience(v_group);
    RETURN NEXT;
END;
$$;

-- Exclude unreachable (older-client) members from group typing fan-out.
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
            JOIN memberships m ON m.user_id = gm.user_id
            WHERE gm.group_dm_id = v_group
              AND gm.user_id <> app_uid()
              AND m.groups_seen_at IS NOT NULL
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
