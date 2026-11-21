-- Undoes migrations/0059_e2ee_groups.sql. Run as the owner role, in one transaction,
-- then start the previous build.

BEGIN;

DROP TRIGGER IF EXISTS group_dms_e2ee_forget ON group_dms;
DROP TRIGGER IF EXISTS group_dms_e2ee_uuid ON group_dms;
DROP TRIGGER IF EXISTS e2ee_reconcile_group_dm_members ON group_dm_members;

-- Restore `app_last_message` from 0055_group_dms.sql.
CREATE OR REPLACE FUNCTION app_last_message(p_channel uuid, p_direct uuid, p_group uuid DEFAULT NULL)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT jsonb_build_object(
        'id', m.id::text,
        'author_id', m.author_id::text,
        'body', left(m.body, 200),
        'created_at', app_stamp(m.created_at)
    )
    FROM messages m
    WHERE m.deleted_at IS NULL
      AND m.msg_kind = 'message'
      AND (m.channel_id = p_channel OR m.direct_id = p_direct OR m.group_dm_id = p_group)
    ORDER BY m.seq DESC
    LIMIT 1;
$$;

-- Restore `app_e2ee_upgrade` from 0055_group_dms.sql.
CREATE OR REPLACE FUNCTION app_e2ee_upgrade(p_id uuid)
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
    IF v_kind = 'group' THEN
        RAISE EXCEPTION 'e2ee is off' USING ERRCODE = 'P0E12';
    END IF;
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

-- Restore `app_group_add` and `app_group_open` from 0056_groups_api.sql.
CREATE OR REPLACE FUNCTION app_group_add(
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

CREATE OR REPLACE FUNCTION app_group_open(
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

-- Restore `app_e2ee_repair` and `app_e2ee_create_group` from 0039_e2ee_group_generations.sql.
CREATE OR REPLACE FUNCTION app_e2ee_repair(p_conv uuid, p_binding jsonb, p_hash bytea)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE h e2ee_generation_heads; g e2ee_groups; v_device uuid; v_key bytea; v_new uuid; v_from bigint; v_to bigint; v_epoch bigint; v_existing jsonb;
BEGIN
 PERFORM app_e2ee_gate(p_conv,NULL,true);
 PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.e2ee.' || p_conv::text,0));
 PERFORM app_e2ee_gate(p_conv,NULL,true);
 PERFORM app_e2ee_generation_head(p_conv);
 SELECT * INTO h FROM e2ee_generation_heads WHERE conversation_id=p_conv FOR UPDATE;
 IF EXISTS(SELECT 1 FROM e2ee_groups WHERE conversation_id=p_conv AND shared_from IS NOT NULL)
 OR EXISTS(SELECT 1 FROM e2ee_groups WHERE shared_from=p_conv) THEN RAISE EXCEPTION 'repair unavailable' USING ERRCODE='P0E22'; END IF;
 v_device:=(p_binding->>'device_id')::uuid;
 IF (p_binding->>'user_id')::uuid<>app_uid() OR (p_binding->>'conversation_id')::uuid<>p_conv THEN RAISE EXCEPTION 'not allowed' USING ERRCODE='42501'; END IF;
 SELECT signature_key INTO v_key FROM e2ee_devices WHERE device_id=v_device AND user_id=app_uid() AND revoked_at IS NULL;
 IF v_key IS NULL OR v_key<>decode(p_binding->>'signature_key','base64') THEN RAISE EXCEPTION 'bad device' USING ERRCODE='P0E13'; END IF;
 SELECT binding INTO v_existing FROM e2ee_generation_bindings WHERE conversation_id=p_conv AND binding_hash=p_hash;
 IF FOUND THEN
  RETURN jsonb_build_object('generation',(v_existing->>'to_generation')::bigint,
   'group_id',v_existing->>'group_id','head_hash',translate(encode(p_hash,'base64'),E'\n',''),
   'binding',v_existing,'created',false);
 END IF;
 IF (SELECT e2ee_audience_groups FROM server_settings) THEN RAISE EXCEPTION 'repair unavailable' USING ERRCODE='P0E22'; END IF;
 v_from:=(p_binding->>'from_generation')::bigint; v_to:=(p_binding->>'to_generation')::bigint;
 v_epoch:=(p_binding->>'from_epoch')::bigint; v_new:=(p_binding->>'group_id')::uuid;
 IF v_from<>h.generation OR v_to<>h.generation+1 OR (p_binding->>'from_group_id')::uuid<>h.group_id
  OR decode(p_binding->>'previous_hash','base64')<>h.head_hash THEN RAISE EXCEPTION 'generation changed' USING ERRCODE='P0E21'; END IF;
 IF decode(p_binding->>'server_key_hash','base64')<>(SELECT sha256(signature_key) FROM e2ee_server_key) THEN RAISE EXCEPTION 'bad binding' USING ERRCODE='P0E15'; END IF;
 SELECT * INTO g FROM e2ee_groups WHERE conversation_id=p_conv FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'no group' USING ERRCODE='P0E05'; END IF;
 IF g.shared_from IS NOT NULL OR EXISTS(SELECT 1 FROM e2ee_groups WHERE shared_from=p_conv) THEN RAISE EXCEPTION 'repair unavailable' USING ERRCODE='P0E22'; END IF;
 IF g.epoch<>v_epoch THEN RAISE EXCEPTION 'stale epoch' USING ERRCODE='P0E03'; END IF;
 IF NOT EXISTS(SELECT 1 FROM e2ee_leaves WHERE conversation_id=p_conv AND device_id=v_device AND user_id=app_uid())
 OR EXISTS(SELECT 1 FROM e2ee_pending WHERE conversation_id=p_conv AND device_id=v_device AND op='remove') THEN RAISE EXCEPTION 'not in group' USING ERRCODE='P0E07'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.e2ee.uuid.' || v_new::text,0));
 IF v_new=h.group_id OR v_new=p_conv OR EXISTS(SELECT 1 FROM e2ee_reserved_group_ids WHERE group_id=v_new) OR EXISTS(SELECT 1 FROM e2ee_generation_bindings WHERE group_id=v_new)
 OR EXISTS(SELECT 1 FROM e2ee_groups WHERE conversation_id=v_new OR group_id=v_new)
 OR EXISTS(SELECT 1 FROM channels WHERE id=v_new) OR EXISTS(SELECT 1 FROM directs WHERE id=v_new)
 THEN RAISE EXCEPTION 'group exists' USING ERRCODE='P0E06'; END IF;
 INSERT INTO e2ee_generation_members SELECT p_conv,h.generation,l.device_id,l.joined_epoch FROM e2ee_leaves l WHERE l.conversation_id=p_conv ON CONFLICT DO NOTHING;
 INSERT INTO e2ee_reserved_group_ids VALUES(v_new);
 INSERT INTO e2ee_generation_bindings VALUES(p_conv,v_to,v_new,p_hash,p_binding);
 UPDATE e2ee_generation_heads SET generation=v_to,group_id=v_new,head_hash=p_hash WHERE conversation_id=p_conv;
 DELETE FROM e2ee_pending WHERE conversation_id=p_conv;
 DELETE FROM e2ee_leaves WHERE conversation_id=p_conv;
 UPDATE e2ee_groups SET generation=v_to,group_id=v_new,epoch=0,audience_hash=NULL,context=NULL,audience_established=false,
 last_committer=NULL,last_commit_at=NULL,last_commit_path=false,proposals_at=NULL,updated_at=now() WHERE conversation_id=p_conv;
 INSERT INTO e2ee_leaves(conversation_id,leaf_index,user_id,device_id,joined_epoch) VALUES(p_conv,0,app_uid(),v_device,0);
 PERFORM app_e2ee_reconcile(p_conv);
 PERFORM app_e2ee_hint(p_conv);
 RETURN app_e2ee_generation_head(p_conv) || jsonb_build_object('binding',p_binding,'created',true);
END;
$$;

CREATE OR REPLACE FUNCTION app_e2ee_create_group(p_conv uuid, p_device uuid, p_context bytea)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_hash bytea;
    v_existing uuid;
    v_share boolean;
    v_group uuid;
BEGIN
    PERFORM app_e2ee_generation_check(p_conv);
    PERFORM app_e2ee_gate(p_conv, p_device, false);
    IF EXISTS (SELECT 1 FROM e2ee_generation_heads WHERE conversation_id=p_conv AND generation>0) THEN RAISE EXCEPTION 'no group' USING ERRCODE='P0E05'; END IF;
    v_hash := app_e2ee_audience_hash(p_conv);
    SELECT s.e2ee_audience_groups INTO v_share FROM server_settings s;
    IF v_share AND v_hash IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(hashtextextended(
            'tinyserver.e2ee.audience.' || encode(v_hash, 'hex'), 0));
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.e2ee.' || p_conv::text, 0));
    IF EXISTS (SELECT 1 FROM e2ee_groups g WHERE g.conversation_id = p_conv) THEN
        RAISE EXCEPTION 'group exists' USING ERRCODE = 'P0E06';
    END IF;
    IF v_share AND v_hash IS NOT NULL THEN
        SELECT g.conversation_id INTO v_existing
        FROM e2ee_groups g
        WHERE g.shared_from IS NULL
          AND g.audience_hash = v_hash
          AND g.conversation_id <> p_conv
          AND NOT EXISTS(SELECT 1 FROM e2ee_generation_heads h WHERE h.conversation_id=g.conversation_id AND h.generation>0)
        LIMIT 1;
    END IF;
    v_group := coalesce(v_existing, p_conv);
    IF p_context IS NOT NULL AND (
        octet_length(p_context) <> 32
        OR substring(p_context FROM 1 FOR 16) IS DISTINCT FROM uuid_send(v_group)
        OR substring(p_context FROM 17 FOR 16) IS DISTINCT FROM uuid_send(p_conv)
    ) THEN
        RAISE EXCEPTION 'bad context' USING ERRCODE = 'P0E15';
    END IF;
    DELETE FROM e2ee_handshake WHERE conversation_id=p_conv AND generation=0;
    DELETE FROM e2ee_trees WHERE conversation_id=p_conv AND generation=0;
    DELETE FROM e2ee_generation_members WHERE conversation_id=p_conv AND generation=0;
    IF v_existing IS NOT NULL THEN
        INSERT INTO e2ee_groups (conversation_id, shared_from, audience_hash, context)
        VALUES (p_conv, v_existing, v_hash, p_context);
        PERFORM app_e2ee_reconcile(v_existing);
        RETURN;
    END IF;
    INSERT INTO e2ee_groups (conversation_id, audience_hash, context)
    VALUES (p_conv, v_hash, p_context);
    INSERT INTO e2ee_leaves (conversation_id, leaf_index, user_id, device_id, joined_epoch)
    VALUES (p_conv, 0, app_uid(), p_device, 0);
    IF NOT app_e2ee_reconcile(p_conv) THEN
        PERFORM app_e2ee_hint(p_conv);
    END IF;
END;
$$;

-- Restore `app_e2ee_audience_hash` from 0025_e2ee_remaining.sql.
CREATE OR REPLACE FUNCTION app_e2ee_audience_hash(p_conv uuid)
RETURNS bytea
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_kind text;
    v_ids text;
BEGIN
    IF EXISTS (SELECT 1 FROM channels c WHERE c.id = p_conv AND c.e2ee) THEN
        v_kind := 'channel';
        SELECT coalesce(string_agg(m.user_id::text, ',' ORDER BY m.user_id::text), '')
        INTO v_ids
        FROM memberships m
        WHERE NOT app_banned(m.user_id)
          AND (app_channel_perms_of(p_conv, m.user_id) & 1) = 1;
    ELSIF EXISTS (SELECT 1 FROM directs d WHERE d.id = p_conv AND d.e2ee) THEN
        v_kind := 'direct';
        SELECT d.low_user_id::text || ',' || d.high_user_id::text INTO v_ids
        FROM directs d WHERE d.id = p_conv;
    ELSE
        RETURN NULL;
    END IF;
    RETURN sha256(convert_to(v_kind || ':' || v_ids, 'UTF8'));
END;
$$;

-- Restore `app_e2ee_desired` from 0041_send_path_locks.sql.
CREATE OR REPLACE FUNCTION app_e2ee_desired(p_conv uuid)
RETURNS TABLE (d_user uuid, d_device uuid)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_low uuid;
    v_high uuid;
BEGIN
    IF EXISTS (SELECT 1 FROM channels c WHERE c.id = p_conv AND c.e2ee) THEN
        RETURN QUERY
        WITH holders AS (
            SELECT DISTINCT d.user_id
            FROM e2ee_devices d
            WHERE d.revoked_at IS NULL
              AND EXISTS (SELECT 1 FROM memberships m WHERE m.user_id = d.user_id)
        ),
        viewers AS MATERIALIZED (
            SELECT h.user_id FROM holders h
            WHERE (app_channel_perms_of(p_conv, h.user_id) & 1) = 1
        )
        SELECT d.user_id, d.device_id
        FROM e2ee_devices d
        JOIN viewers v ON v.user_id = d.user_id
        WHERE d.revoked_at IS NULL;
        RETURN;
    END IF;
    SELECT x.low_user_id, x.high_user_id INTO v_low, v_high
    FROM directs x WHERE x.id = p_conv AND x.e2ee;
    IF FOUND THEN
        RETURN QUERY
        SELECT d.user_id, d.device_id
        FROM e2ee_devices d
        WHERE d.user_id IN (v_low, v_high)
          AND d.revoked_at IS NULL
          AND EXISTS (SELECT 1 FROM memberships m WHERE m.user_id = d.user_id)
          AND NOT app_banned(d.user_id);
    END IF;
END;
$$;

-- Restore `app_open_conversation` from 0057_group_reachability.sql.
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

DELETE FROM _sqlx_migrations WHERE version = 59;

COMMIT;
