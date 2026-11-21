-- Group conversations HTTP API support: find-or-create, list, get, rename, add member,
-- leave, live events, and audit rows (issue #60).
--
-- Rollback: crates/db/rollback/0056_groups_api.down.sql.

-- 1. JSON builders for group objects and live events.

-- Current members in join order (`joined_at, seq`).
CREATE FUNCTION app_group_members_json(p_id uuid)
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

REVOKE EXECUTE ON FUNCTION app_group_members_json(uuid) FROM PUBLIC, app_runtime;

-- Full group object for the calling member, including per-viewer unread/read/last_message.
CREATE FUNCTION app_group_json(p_id uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT jsonb_build_object(
        'id', g.id::text,
        'name', g.name,
        'e2ee', g.e2ee,
        'plaintext_history', g.e2ee AND app_e2ee_has_plaintext(g.id),
        'created_by', g.created_by::text,
        'created_at', app_stamp(g.created_at),
        'members', app_group_members_json(g.id),
        'unread', app_unread('group', g.id),
        'last_read', (
            SELECT r.message_id::text
            FROM reads r
            WHERE r.user_id = app_uid()
              AND r.kind = 'group'
              AND r.conversation_id = g.id
        ),
        'last_message', app_last_message(NULL, NULL, g.id)
    )
    FROM group_dms g
    WHERE g.id = p_id
      AND EXISTS (
          SELECT 1 FROM group_dm_members gm
          WHERE gm.group_dm_id = g.id AND gm.user_id = app_uid()
      );
$$;

REVOKE EXECUTE ON FUNCTION app_group_json(uuid) FROM PUBLIC, app_runtime;

-- Shared event payload for `group.created` (no per-viewer fields).
CREATE FUNCTION app_group_event_json(p_id uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT jsonb_build_object(
        'id', g.id::text,
        'name', g.name,
        'e2ee', g.e2ee,
        'created_by', g.created_by::text,
        'created_at', app_stamp(g.created_at),
        'members', app_group_members_json(g.id)
    )
    FROM group_dms g
    WHERE g.id = p_id;
$$;

REVOKE EXECUTE ON FUNCTION app_group_event_json(uuid) FROM PUBLIC, app_runtime;

-- 2. Trigger update: emit `group.member_left` when a member is removed outside `app_group_leave`
--    (i.e. kick, ban, or account deletion), provided at least one member remains.

CREATE OR REPLACE FUNCTION app_group_members_sync()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_group uuid;
BEGIN
    IF TG_OP = 'DELETE' THEN
        v_group := OLD.group_dm_id;
        DELETE FROM reads
        WHERE user_id = OLD.user_id AND kind = 'group' AND conversation_id = v_group;
    ELSE
        v_group := NEW.group_dm_id;
    END IF;
    UPDATE group_dms g
    SET member_key = app_group_member_key(coalesce(
        (SELECT array_agg(gm.user_id) FROM group_dm_members gm WHERE gm.group_dm_id = v_group),
        '{}'::uuid[]
    ))
    WHERE g.id = v_group;
    IF TG_OP = 'DELETE'
       AND coalesce(current_setting('app.group_leaving', true), '') <> '1'
       AND EXISTS (SELECT 1 FROM group_dms WHERE id = v_group)
       AND EXISTS (SELECT 1 FROM group_dm_members WHERE group_dm_id = v_group)
    THEN
        PERFORM app_emit_to(
            'group.member_left',
            jsonb_build_object(
                'group_id', v_group::text,
                'user_id', OLD.user_id::text
            ),
            app_group_audience(v_group, NULL)
        );
    END IF;
    RETURN NULL;
END;
$$;

-- 3. Group routes SQL functions.

CREATE FUNCTION app_group_list()
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

CREATE FUNCTION app_group_get(p_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    PERFORM app_msg_gate();
    IF NOT EXISTS (
        SELECT 1 FROM group_dm_members gm
        WHERE gm.group_dm_id = p_id AND gm.user_id = app_uid()
    ) THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    RETURN app_group_json(p_id);
END;
$$;

-- Find-or-create a group conversation by exact member set (caller + p_users) and e2ee flag.
CREATE FUNCTION app_group_open(
    p_users uuid[],
    p_name text,
    p_e2ee boolean,
    OUT body jsonb,
    OUT created boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_me uuid := app_uid();
    v_e2ee boolean := coalesce(p_e2ee, false);
    v_name text := btrim(coalesce(p_name, ''));
    v_count integer;
    v_distinct integer;
    v_u uuid;
    v_all uuid[];
    v_key bytea;
    v_existing uuid;
    v_id uuid;
BEGIN
    PERFORM app_msg_gate();
    -- Encrypted group conversations ship in #57.
    IF v_e2ee THEN
        RAISE EXCEPTION 'e2ee is off' USING ERRCODE = 'P0E12';
    END IF;
    IF p_users IS NULL THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    v_count := coalesce(cardinality(p_users), 0);
    IF v_count < 2 OR v_count > 100 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF char_length(v_name) > 80 OR v_name ~ E'[\\x00-\\x1F\\x7F]' THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    SELECT count(DISTINCT u) INTO v_distinct
    FROM unnest(p_users) AS u
    WHERE u IS NOT NULL;
    IF v_distinct <> v_count OR v_me = ANY (p_users) THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    FOREACH v_u IN ARRAY p_users LOOP
        IF app_banned(v_u) THEN
            RAISE EXCEPTION 'banned' USING ERRCODE = '42501';
        END IF;
        IF NOT app_is_member_of(v_u) THEN
            RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
        END IF;
    END LOOP;

    v_all := ARRAY[v_me] || p_users;
    v_key := app_group_member_key(v_all);
    PERFORM pg_advisory_xact_lock(
        hashtextextended('tinyserver.group_dm.' || encode(v_key, 'hex') || ':' || v_e2ee::text, 0)
    );

    SELECT g.id INTO v_existing
    FROM group_dms g
    WHERE g.member_key = v_key
      AND g.e2ee = v_e2ee
      AND EXISTS (
          SELECT 1 FROM group_dm_members gm
          WHERE gm.group_dm_id = g.id AND gm.user_id = v_me
      )
    ORDER BY (
        SELECT max(m.seq) FROM messages m WHERE m.group_dm_id = g.id
    ) DESC NULLS LAST,
    g.created_at ASC,
    g.id ASC
    LIMIT 1;

    IF FOUND THEN
        body := app_group_json(v_existing);
        created := false;
        RETURN;
    END IF;

    PERFORM app_e2ee_may_create(v_e2ee);

    INSERT INTO group_dms (name, e2ee, created_by, member_key)
    VALUES (v_name, v_e2ee, v_me, v_key)
    RETURNING id INTO v_id;

    INSERT INTO group_dm_members (group_dm_id, user_id)
    SELECT v_id, u.uid
    FROM unnest(v_all) WITH ORDINALITY AS u(uid, ord)
    ORDER BY u.ord;

    PERFORM app_audit('group.create', 'group', jsonb_build_object('id', v_id), NULL, NULL);
    PERFORM app_emit_to(
        'group.created',
        jsonb_build_object('group', app_group_event_json(v_id)),
        app_group_audience(v_id, NULL)
    );

    body := app_group_json(v_id);
    created := true;
END;
$$;

CREATE FUNCTION app_group_rename(p_id uuid, p_name text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_name text := btrim(coalesce(p_name, ''));
BEGIN
    PERFORM app_msg_gate();
    IF char_length(v_name) > 80 OR v_name ~ E'[\\x00-\\x1F\\x7F]' THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    PERFORM 1 FROM group_dms WHERE id = p_id FOR UPDATE;
    IF NOT FOUND OR NOT EXISTS (
        SELECT 1 FROM group_dm_members gm
        WHERE gm.group_dm_id = p_id AND gm.user_id = app_uid()
    ) THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    UPDATE group_dms SET name = v_name WHERE id = p_id;
    PERFORM app_audit(
        'group.rename', 'group',
        jsonb_build_object('id', p_id, 'name', v_name),
        NULL, NULL
    );
    PERFORM app_emit_to(
        'group.updated',
        jsonb_build_object('group_id', p_id::text, 'name', v_name),
        app_group_audience(p_id, NULL)
    );
    RETURN app_group_json(p_id);
END;
$$;

CREATE FUNCTION app_group_add(
    p_id uuid,
    p_user uuid,
    OUT body jsonb,
    OUT added boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_latest uuid;
BEGIN
    PERFORM app_msg_gate();
    PERFORM 1 FROM group_dms WHERE id = p_id FOR UPDATE;
    IF NOT FOUND OR NOT EXISTS (
        SELECT 1 FROM group_dm_members gm
        WHERE gm.group_dm_id = p_id AND gm.user_id = app_uid()
    ) THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    IF p_user IS NULL THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF EXISTS (
        SELECT 1 FROM group_dm_members gm
        WHERE gm.group_dm_id = p_id AND gm.user_id = p_user
    ) THEN
        body := app_group_json(p_id);
        added := false;
        RETURN;
    END IF;
    IF app_banned(p_user) THEN
        RAISE EXCEPTION 'banned' USING ERRCODE = '42501';
    END IF;
    IF NOT app_is_member_of(p_user) THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;

    INSERT INTO group_dm_members (group_dm_id, user_id)
    VALUES (p_id, p_user);

    -- Start the added person at unread 0 by placing their read cursor on the newest message.
    SELECT m.id INTO v_latest
    FROM messages m
    WHERE m.group_dm_id = p_id
    ORDER BY m.seq DESC
    LIMIT 1;
    IF v_latest IS NOT NULL THEN
        INSERT INTO reads (user_id, kind, conversation_id, message_id)
        VALUES (p_user, 'group', p_id, v_latest)
        ON CONFLICT (user_id, kind, conversation_id) DO UPDATE
        SET message_id = EXCLUDED.message_id, read_at = now();
    END IF;

    -- Do not store p_user in audit detail or subject_user_id so audit cannot rebuild membership.
    PERFORM app_audit('group.add', 'group', jsonb_build_object('id', p_id), NULL, NULL);
    PERFORM app_emit_to(
        'group.member_added',
        jsonb_build_object(
            'group_id', p_id::text,
            'user_id', p_user::text,
            'members', app_group_members_json(p_id)
        ),
        app_group_audience(p_id, NULL)
    );

    body := app_group_json(p_id);
    added := true;
END;
$$;

CREATE FUNCTION app_group_leave(p_id uuid)
RETURNS text[]
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_me uuid := app_uid();
    v_files text[];
BEGIN
    PERFORM app_msg_gate();
    PERFORM 1 FROM group_dms WHERE id = p_id FOR UPDATE;
    IF NOT FOUND OR NOT EXISTS (
        SELECT 1 FROM group_dm_members gm
        WHERE gm.group_dm_id = p_id AND gm.user_id = v_me
    ) THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;

    PERFORM set_config('app.group_leaving', '1', true);
    DELETE FROM group_dm_members WHERE group_dm_id = p_id AND user_id = v_me;

    IF EXISTS (SELECT 1 FROM group_dm_members WHERE group_dm_id = p_id) THEN
        PERFORM app_audit('group.leave', 'group', jsonb_build_object('id', p_id), NULL, NULL);
        PERFORM app_emit_to(
            'group.member_left',
            jsonb_build_object('group_id', p_id::text, 'user_id', v_me::text),
            app_group_audience(p_id, v_me)
        );
        PERFORM set_config('app.group_leaving', '', true);
        RETURN '{}'::text[];
    END IF;

    SELECT coalesce(array_agg(a.id::text), '{}') INTO v_files
    FROM attachments a
    JOIN messages m ON m.id = a.message_id
    WHERE m.group_dm_id = p_id;

    DELETE FROM reads WHERE kind = 'group' AND conversation_id = p_id;
    DELETE FROM group_dms WHERE id = p_id;

    PERFORM app_audit('group.delete', 'group', jsonb_build_object('id', p_id), NULL, NULL);
    PERFORM app_emit_to(
        'group.deleted',
        jsonb_build_object('group_id', p_id::text),
        ARRAY[v_me]
    );
    PERFORM set_config('app.group_leaving', '', true);
    RETURN v_files;
END;
$$;

REVOKE EXECUTE ON FUNCTION app_group_list() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_group_list() TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_group_get(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_group_get(uuid) TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_group_open(uuid[], text, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_group_open(uuid[], text, boolean) TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_group_rename(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_group_rename(uuid, text) TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_group_add(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_group_add(uuid, uuid) TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_group_leave(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_group_leave(uuid) TO app_runtime;
