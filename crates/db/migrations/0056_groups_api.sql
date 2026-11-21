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

-- Scrub a deleted account's display_name from recent `group.created` and `group.member_added`
-- outbox rows so `GET /v1/live?since=` cannot replay the deleted name within the 24h window.
CREATE OR REPLACE FUNCTION app_group_scrub_deleted_outbox()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_uid text := NEW.id::text;
BEGIN
    IF OLD.deleted_at IS NOT NULL OR NEW.deleted_at IS NULL THEN
        RETURN NULL;
    END IF;

    UPDATE outbox
    SET payload = jsonb_set(
        payload,
        '{group,members}',
        coalesce(
            (
                SELECT jsonb_agg(
                    CASE
                        WHEN elem ->> 'user_id' = v_uid
                        THEN jsonb_set(elem, '{display_name}', to_jsonb('Deleted user'::text))
                        ELSE elem
                    END
                )
                FROM jsonb_array_elements(payload -> 'group' -> 'members') AS elem
            ),
            '[]'::jsonb
        )
    )
    WHERE topic = 'group.created'
      AND jsonb_typeof(payload -> 'group' -> 'members') = 'array'
      AND EXISTS (
          SELECT 1
          FROM jsonb_array_elements(payload -> 'group' -> 'members') AS elem
          WHERE elem ->> 'user_id' = v_uid
      );

    UPDATE outbox
    SET payload = jsonb_set(
        payload,
        '{members}',
        coalesce(
            (
                SELECT jsonb_agg(
                    CASE
                        WHEN elem ->> 'user_id' = v_uid
                        THEN jsonb_set(elem, '{display_name}', to_jsonb('Deleted user'::text))
                        ELSE elem
                    END
                )
                FROM jsonb_array_elements(payload -> 'members') AS elem
            ),
            '[]'::jsonb
        )
    )
    WHERE topic = 'group.member_added'
      AND jsonb_typeof(payload -> 'members') = 'array'
      AND EXISTS (
          SELECT 1
          FROM jsonb_array_elements(payload -> 'members') AS elem
          WHERE elem ->> 'user_id' = v_uid
      );

    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS users_scrub_group_outbox ON users;
CREATE TRIGGER users_scrub_group_outbox
AFTER UPDATE OF deleted_at ON users
FOR EACH ROW
EXECUTE FUNCTION app_group_scrub_deleted_outbox();

-- Lock any `group_dms` rows the deleting user belongs to in deterministic `id` order BEFORE
-- updating `messages`, matching `app_edit_message` / `app_delete_message`'s (group_dms -> messages)
-- lock order and preventing 40P01 deadlocks under concurrent group edits/deletes.
CREATE OR REPLACE FUNCTION app_delete_account()
RETURNS text[]
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_user uuid := app_uid();
    v_owner boolean;
    v_files text[];
    v_device uuid;
BEGIN
    IF v_user IS NULL OR NOT EXISTS (
        SELECT 1 FROM users WHERE id = v_user AND deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.owners'));
    SELECT owner INTO v_owner FROM memberships WHERE user_id = v_user;
    IF v_owner AND (SELECT count(*) FROM memberships WHERE owner) <= 1 THEN
        RAISE EXCEPTION 'last owner' USING ERRCODE = '42501';
    END IF;

    PERFORM 1
    FROM group_dms g
    JOIN group_dm_members gm ON gm.group_dm_id = g.id
    WHERE gm.user_id = v_user
    ORDER BY g.id
    FOR UPDATE OF g;

    SELECT coalesce(array_agg(a.id::text), '{}') INTO v_files
    FROM attachments a
    WHERE a.uploader_id = v_user
       OR a.message_id IN (SELECT m.id FROM messages m WHERE m.author_id = v_user);
    DELETE FROM attachments
    WHERE uploader_id = v_user
       OR message_id IN (SELECT m.id FROM messages m WHERE m.author_id = v_user);
    DELETE FROM reactions
    WHERE user_id = v_user
       OR message_id IN (SELECT m.id FROM messages m WHERE m.author_id = v_user);
    UPDATE messages SET body = '', deleted_at = now()
    WHERE author_id = v_user AND deleted_at IS NULL;
    DELETE FROM reads WHERE user_id = v_user;

    FOR v_device IN
        SELECT d.device_id FROM e2ee_devices d WHERE d.user_id = v_user AND d.revoked_at IS NULL
    LOOP
        UPDATE e2ee_devices SET revoked_at = now(), low_keys = false WHERE device_id = v_device;
        DELETE FROM e2ee_key_packages WHERE device_id = v_device;
        DELETE FROM e2ee_handshake WHERE for_device = v_device;
        PERFORM app_emit(
            'e2ee.device',
            jsonb_build_object('user_id', v_user::text, 'device_id', v_device::text, 'op', 'revoked')
        );
    END LOOP;
    DELETE FROM e2ee_upload_ledger WHERE user_id = v_user;

    DELETE FROM bots WHERE created_by = v_user;
    DELETE FROM invites WHERE created_by = v_user AND accepted_at IS NULL;
    DELETE FROM idempotency_keys WHERE key LIKE v_user::text || E'\n%';
    DELETE FROM sessions WHERE user_id = v_user;
    -- A code from a sign-in that was under way names the account until it expires (as 0014).
    DELETE FROM auth_codes WHERE user_id = v_user;
    DELETE FROM user_identities WHERE user_id = v_user;
    DELETE FROM memberships WHERE user_id = v_user;

    -- Their join, rename and profile events, with the name and email they carry.
    DELETE FROM outbox WHERE payload #>> '{member,user_id}' = v_user::text;

    UPDATE audit_log
    SET detail = detail - 'display_name' - 'name' - 'email'
    WHERE (actor_id = v_user OR subject_user_id = v_user) AND detail IS NOT NULL;

    UPDATE users
    SET email = NULL,
        display_name = 'Deleted user',
        avatar = NULL,
        avatar_type = NULL,
        avatar_sha = NULL,
        deleted_at = now()
    WHERE id = v_user;

    INSERT INTO audit_log (actor_id, action, subject, detail, subject_user_id)
    VALUES (v_user, 'account.delete', 'user', jsonb_build_object('user_id', v_user), v_user);
    RETURN v_files;
END;
$$;
REVOKE EXECUTE ON FUNCTION app_delete_account() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_delete_account() TO app_runtime;
