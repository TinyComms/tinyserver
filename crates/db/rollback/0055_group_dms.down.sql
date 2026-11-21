-- Undoes migrations/0055_group_dms.sql. Run as the owner role, in one transaction, then
-- start the previous build.

BEGIN;

-- Restore `app_audience` first so restored functions can reference it.
CREATE FUNCTION app_audience(p_kind text, p_low uuid, p_high uuid)
RETURNS uuid[]
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT CASE WHEN p_kind = 'direct' THEN ARRAY[p_low, p_high] ELSE NULL END;
$$;

REVOKE EXECUTE ON FUNCTION app_audience(text, uuid, uuid) FROM PUBLIC, app_runtime;

-- Restore `app_open_conversation` (5-column version from 0048_blocks.sql).
DROP FUNCTION IF EXISTS app_open_conversation(uuid, boolean);
CREATE FUNCTION app_open_conversation(p_id uuid, p_need_speak boolean)
RETURNS TABLE (kind text, channel_id uuid, direct_id uuid, low_user_id uuid, high_user_id uuid)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_channel uuid;
    v_low uuid;
    v_high uuid;
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
        RETURN NEXT;
        RETURN;
    END IF;
    SELECT d.id, d.low_user_id, d.high_user_id INTO v_channel, v_low, v_high
    FROM directs d
    WHERE d.id = p_id AND app_uid() IN (d.low_user_id, d.high_user_id);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
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
    RETURN NEXT;
END;
$$;

REVOKE EXECUTE ON FUNCTION app_open_conversation(uuid, boolean) FROM PUBLIC, app_runtime;

-- Restore 2-argument `app_last_message` from 0025_e2ee_remaining.sql.
DROP FUNCTION IF EXISTS app_last_message(uuid, uuid, uuid);
CREATE FUNCTION app_last_message(p_channel uuid, p_direct uuid)
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
      AND (m.channel_id = p_channel OR m.direct_id = p_direct)
    ORDER BY m.seq DESC
    LIMIT 1;
$$;

REVOKE EXECUTE ON FUNCTION app_last_message(uuid, uuid) FROM PUBLIC, app_runtime;

CREATE OR REPLACE FUNCTION app_outbox_append(p_topic text, p_payload jsonb, p_audience uuid[])
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    c_key CONSTANT bigint := hashtext('tinyserver.outbox');
    v_scoped boolean := p_audience IS NULL;
    v_seen bigint := 0;
    v_audience uuid[] := p_audience;
    v_stale boolean := false;
    v_id bigint;
BEGIN
    IF p_topic !~ '^[a-z][a-z0-9]*\.[a-z_]+$' THEN
        RAISE EXCEPTION 'invalid topic' USING ERRCODE = '22023';
    END IF;
    IF v_scoped THEN
        SELECT coalesce(max(o.id), 0) INTO v_seen FROM outbox o;
        v_audience := app_scope_audience(p_payload, NULL);
    END IF;
    PERFORM pg_advisory_xact_lock(c_key);
    IF v_scoped THEN
        v_stale := EXISTS (
            SELECT 1 FROM outbox o
            WHERE o.id > v_seen
              AND o.topic NOT IN ('message.created', 'message.edited', 'message.deleted',
                                  'reaction.updated', 'e2ee.reaction', 'read.updated')
        );
    END IF;
    IF v_stale THEN
        v_audience := app_scope_audience(p_payload, NULL);
    END IF;
    INSERT INTO outbox (topic, payload, audience)
    VALUES (p_topic, p_payload, v_audience)
    RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;

CREATE OR REPLACE FUNCTION app_conv_e2ee(p_conv uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT coalesce(
        (SELECT c.e2ee FROM channels c WHERE c.id = p_conv),
        (SELECT d.e2ee FROM directs d WHERE d.id = p_conv),
        false
    );
$$;

CREATE OR REPLACE FUNCTION app_e2ee_has_plaintext(p_id uuid)
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

CREATE OR REPLACE FUNCTION app_e2ee_establish_audience()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_conv uuid;
    v_group uuid;
BEGIN
    IF TG_TABLE_NAME = 'messages' THEN
        v_conv := coalesce(NEW.channel_id, NEW.direct_id);
    ELSE
        v_conv := NEW.conversation_id;
    END IF;
    v_group := app_e2ee_resolve(v_conv);
    UPDATE e2ee_groups SET audience_established = true
    WHERE conversation_id = v_group AND shared_from IS NULL AND NOT audience_established;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION app_e2ee_generation_stamp()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_conv uuid;
    v_group uuid;
BEGIN
    IF TG_OP = 'DELETE' THEN
        INSERT INTO e2ee_generation_members
        SELECT OLD.conversation_id, OLD.generation, l.device_id, l.joined_epoch
        FROM e2ee_leaves l
        WHERE l.conversation_id = OLD.conversation_id
        ON CONFLICT DO NOTHING;
        RETURN OLD;
    END IF;
    IF TG_TABLE_NAME = 'e2ee_groups' THEN
        NEW.group_id := coalesce(NEW.group_id, NEW.conversation_id);
        IF TG_OP = 'INSERT' AND NEW.generation = 0 THEN
            PERFORM pg_advisory_xact_lock(
                hashtextextended('tinyserver.e2ee.uuid.' || NEW.conversation_id::text, 0)
            );
            INSERT INTO e2ee_reserved_group_ids VALUES (NEW.conversation_id) ON CONFLICT DO NOTHING;
        END IF;
        IF NEW.shared_from IS NOT NULL THEN
            PERFORM pg_advisory_xact_lock(
                hashtextextended('tinyserver.e2ee.' || NEW.shared_from::text, 0)
            );
            IF EXISTS (
                SELECT 1 FROM e2ee_generation_heads
                WHERE conversation_id IN (NEW.conversation_id, NEW.shared_from) AND generation > 0
            ) THEN
                RAISE EXCEPTION 'repair unavailable' USING ERRCODE = 'P0E22';
            END IF;
        END IF;
        RETURN NEW;
    END IF;
    IF TG_TABLE_NAME = 'messages' THEN
        v_conv := coalesce(NEW.channel_id, NEW.direct_id);
    ELSE
        v_conv := NEW.conversation_id;
    END IF;
    v_group := app_e2ee_resolve(v_conv);
    SELECT g.generation INTO NEW.generation FROM e2ee_groups g WHERE g.conversation_id = v_group;
    NEW.generation := coalesce(NEW.generation, 0);
    IF TG_TABLE_NAME IN ('messages', 'e2ee_reaction_blobs') THEN
        SELECT g.group_id INTO NEW.group_id FROM e2ee_groups g WHERE g.conversation_id = v_group;
    END IF;
    RETURN NEW;
END;
$$;

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

CREATE OR REPLACE FUNCTION app_unread(p_kind text, p_conversation uuid)
RETURNS integer
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT count(*)::integer
    FROM messages m
    WHERE m.deleted_at IS NULL
      AND m.msg_kind = 'message'
      AND m.author_id <> app_uid()
      AND NOT EXISTS (
          SELECT 1 FROM blocks b
          WHERE b.blocker_id = app_uid() AND b.blocked_id = m.author_id
      )
      AND ((p_kind = 'channel' AND m.channel_id = p_conversation AND m.thread_id IS NULL)
           OR (p_kind = 'direct' AND m.direct_id = p_conversation))
      AND NOT EXISTS (
          SELECT 1
          FROM reads r
          JOIN messages cursor_message ON cursor_message.id = r.message_id
          WHERE r.user_id = app_uid()
            AND r.kind = p_kind
            AND r.conversation_id = p_conversation
            AND m.seq <= cursor_message.seq
      );
$$;

CREATE OR REPLACE FUNCTION app_unread_mentions(p_kind text, p_conversation uuid)
RETURNS integer
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT count(*)::integer
    FROM messages m
    WHERE m.deleted_at IS NULL
      AND NOT m.e2ee
      AND m.msg_kind = 'message'
      AND m.author_id <> app_uid()
      AND NOT EXISTS (
          SELECT 1 FROM blocks b
          WHERE b.blocker_id = app_uid() AND b.blocked_id = m.author_id
      )
      AND ((p_kind = 'channel' AND m.channel_id = p_conversation AND m.thread_id IS NULL)
           OR (p_kind = 'direct' AND m.direct_id = p_conversation))
      AND NOT EXISTS (
          SELECT 1
          FROM reads r
          JOIN messages cursor_message ON cursor_message.id = r.message_id
          WHERE r.user_id = app_uid()
            AND r.kind = p_kind
            AND r.conversation_id = p_conversation
            AND m.seq <= cursor_message.seq
      )
      AND EXISTS (
          SELECT 1
          FROM message_mentions mm
          WHERE mm.message_id = m.id
            AND (
                (mm.kind = 'user' AND mm.target_id = app_uid())
                OR mm.kind = 'everyone'
                OR (mm.kind = 'role' AND EXISTS (
                    SELECT 1 FROM member_roles mr
                    WHERE mr.user_id = app_uid() AND mr.role_id = mm.target_id
                ))
            )
      );
$$;

CREATE OR REPLACE FUNCTION app_store_mentions(
    p_message uuid,
    p_kind text,
    p_channel uuid,
    p_low uuid,
    p_high uuid,
    p_body text,
    p_mentions jsonb
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_elem jsonb;
    v_mkind text;
    v_start integer;
    v_end integer;
    v_target_text text;
    v_target uuid;
    v_body_len integer := octet_length(coalesce(p_body, ''));
    v_mentionable boolean;
BEGIN
    DELETE FROM message_mentions WHERE message_id = p_message;
    IF p_mentions IS NULL THEN
        RETURN;
    END IF;
    IF jsonb_typeof(p_mentions) <> 'array' THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF jsonb_array_length(p_mentions) > 50 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    FOR v_elem IN SELECT value FROM jsonb_array_elements(p_mentions) LOOP
        IF jsonb_typeof(v_elem) <> 'object' THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
        v_mkind := v_elem->>'kind';
        IF v_mkind IS NULL OR v_mkind NOT IN ('user', 'role', 'everyone') THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
        BEGIN
            v_start := (v_elem->>'start')::integer;
            v_end := (v_elem->>'end')::integer;
        EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
            CONTINUE;
        END;
        IF v_start IS NULL OR v_end IS NULL OR v_start < 0 OR v_end <= v_start OR v_end > v_body_len THEN
            CONTINUE;
        END IF;
        IF v_mkind = 'everyone' THEN
            IF p_kind = 'channel' AND p_channel IS NOT NULL AND app_channel_has(p_channel, 4194304) THEN
                INSERT INTO message_mentions (message_id, kind, target_id, start_at, end_at)
                VALUES (p_message, 'everyone', NULL, v_start, v_end);
            END IF;
        ELSIF v_mkind = 'user' THEN
            v_target_text := v_elem->>'id';
            IF v_target_text IS NULL THEN
                CONTINUE;
            END IF;
            BEGIN
                v_target := v_target_text::uuid;
            EXCEPTION WHEN invalid_text_representation THEN
                CONTINUE;
            END;
            IF NOT EXISTS (SELECT 1 FROM users u WHERE u.id = v_target AND u.deleted_at IS NULL) THEN
                CONTINUE;
            END IF;
            IF NOT EXISTS (SELECT 1 FROM memberships m WHERE m.user_id = v_target)
               OR app_banned(v_target) THEN
                CONTINUE;
            END IF;
            IF p_kind = 'channel' THEN
                IF p_channel IS NULL OR app_channel_perms_of(p_channel, v_target) & 1 <> 1 THEN
                    CONTINUE;
                END IF;
            ELSE
                IF v_target NOT IN (p_low, p_high) THEN
                    CONTINUE;
                END IF;
            END IF;
            INSERT INTO message_mentions (message_id, kind, target_id, start_at, end_at)
            VALUES (p_message, 'user', v_target, v_start, v_end);
        ELSIF v_mkind = 'role' THEN
            IF p_kind <> 'channel' OR p_channel IS NULL THEN
                CONTINUE;
            END IF;
            v_target_text := v_elem->>'id';
            IF v_target_text IS NULL THEN
                CONTINUE;
            END IF;
            BEGIN
                v_target := v_target_text::uuid;
            EXCEPTION WHEN invalid_text_representation THEN
                CONTINUE;
            END;
            SELECT r.mentionable INTO v_mentionable
            FROM roles r WHERE r.id = v_target AND NOT r.is_default;
            IF NOT FOUND THEN
                CONTINUE;
            END IF;
            IF v_mentionable OR app_channel_has(p_channel, 4194304) THEN
                INSERT INTO message_mentions (message_id, kind, target_id, start_at, end_at)
                VALUES (p_message, 'role', v_target, v_start, v_end);
            END IF;
        END IF;
    END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION app_list_messages(p_conversation uuid, p_before uuid, p_limit integer)
RETURNS jsonb
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
BEGIN
    SELECT kind, channel_id, direct_id, low_user_id, high_user_id
    INTO v_kind, v_channel, v_direct, v_low, v_high
    FROM app_open_conversation(p_conversation, false);
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF p_before IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM messages m
        WHERE m.id = p_before
          AND (m.channel_id = v_channel OR m.direct_id = v_direct)
    ) THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    RETURN coalesce((
        SELECT jsonb_agg(app_message_json(page.id, app_uid()) ORDER BY page.seq)
        FROM (
            SELECT m.id, m.seq
            FROM messages m
            WHERE (m.channel_id = v_channel OR m.direct_id = v_direct)
              AND (
                  p_before IS NULL OR m.seq < (
                      SELECT b.seq FROM messages b WHERE b.id = p_before
                  )
              )
            ORDER BY m.seq DESC
            LIMIT p_limit
        ) page
    ), '[]'::jsonb);
END;
$$;

CREATE OR REPLACE FUNCTION app_list_messages_filtered(
    p_conversation uuid,
    p_before uuid,
    p_limit integer,
    p_threads boolean
)
RETURNS jsonb
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
BEGIN
    SELECT kind, channel_id, direct_id, low_user_id, high_user_id
    INTO v_kind, v_channel, v_direct, v_low, v_high
    FROM app_open_conversation(p_conversation, false);
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF p_before IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM messages m
        WHERE m.id = p_before
          AND (m.channel_id = v_channel OR m.direct_id = v_direct)
    ) THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    RETURN coalesce((
        SELECT jsonb_agg(app_message_json(page.id, app_uid()) ORDER BY page.seq)
        FROM (
            SELECT m.id, m.seq
            FROM messages m
            WHERE (m.channel_id = v_channel OR m.direct_id = v_direct)
              AND (NOT p_threads OR m.thread_id IS NULL)
              AND (
                  p_before IS NULL OR m.seq < (
                      SELECT b.seq FROM messages b WHERE b.id = p_before
                  )
              )
            ORDER BY m.seq DESC
            LIMIT p_limit
        ) page
    ), '[]'::jsonb);
END;
$$;

CREATE OR REPLACE FUNCTION app_post_message(
    p_conversation uuid,
    p_body text,
    p_reply uuid,
    p_client text,
    p_attachments uuid[],
    p_mentions jsonb DEFAULT NULL,
    p_previews jsonb DEFAULT NULL
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
    IF app_conv_e2ee(p_conversation) THEN
        RAISE EXCEPTION 'e2ee required' USING ERRCODE = 'P0E01';
    END IF;
    PERFORM app_e2ee_plaintext_allowed();
    IF v_client IS NOT NULL AND (
        char_length(v_client) > 64 OR v_client ~ E'[\\x00-\\x1F\\x7F]'
    ) THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF v_client IS NOT NULL THEN
        SELECT id INTO v_existing
        FROM messages
        WHERE author_id = app_uid() AND client_id = v_client AND NOT e2ee;
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
              AND a.kind <> 'sealed'
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
            WHERE author_id = app_uid() AND client_id = v_client AND NOT e2ee;
            RETURN app_message_json(v_existing, app_uid());
    END;
    IF coalesce(cardinality(p_attachments), 0) > 0 THEN
        UPDATE attachments a
        SET message_id = v_id, sort = s.ord::integer
        FROM unnest(p_attachments) WITH ORDINALITY AS s(id, ord)
        WHERE a.id = s.id
          AND a.uploader_id = app_uid()
          AND a.message_id IS NULL
          AND a.scan_status = 'clean'
          AND a.kind <> 'sealed';
        GET DIAGNOSTICS v_linked = ROW_COUNT;
        IF v_linked <> cardinality(p_attachments) THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
    END IF;
    PERFORM app_store_mentions(v_id, v_kind, v_channel, v_low, v_high, v_body, p_mentions);
    IF p_previews IS NOT NULL THEN
        PERFORM app_store_previews(v_id, v_body, p_previews);
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

CREATE OR REPLACE FUNCTION app_post_message_ext(
    p_conversation uuid,
    p_body text,
    p_reply uuid,
    p_client text,
    p_attachments uuid[],
    p_emoji jsonb,
    p_sticker uuid
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
    v_body text := btrim(coalesce(p_body, ''));
    v_client text := nullif(p_client, '');
    v_emoji jsonb := coalesce(p_emoji, '[]'::jsonb);
    v_existing uuid;
    v_id uuid;
    v_linked integer;
    v_payload jsonb;
    v_span jsonb;
    v_span_id uuid;
    v_start integer;
    v_end integer;
    v_body_len integer;
BEGIN
    SELECT kind, channel_id, direct_id, low_user_id, high_user_id
    INTO v_kind, v_channel, v_direct, v_low, v_high
    FROM app_open_conversation(p_conversation, true);
    IF app_conv_e2ee(p_conversation) THEN
        RAISE EXCEPTION 'e2ee required' USING ERRCODE = 'P0E01';
    END IF;
    PERFORM app_e2ee_plaintext_allowed();
    IF v_client IS NOT NULL AND (
        char_length(v_client) > 64 OR v_client ~ E'[\\x00-\\x1F\\x7F]'
    ) THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF v_client IS NOT NULL THEN
        SELECT id INTO v_existing
        FROM messages
        WHERE author_id = app_uid() AND client_id = v_client AND NOT e2ee;
        IF FOUND THEN
            RETURN app_message_json(v_existing, app_uid());
        END IF;
    END IF;
    IF char_length(v_body) > 4000 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF p_sticker IS NOT NULL THEN
        IF NOT EXISTS (SELECT 1 FROM emoji WHERE id = p_sticker AND kind = 'sticker') THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
    END IF;
    IF v_body = '' AND coalesce(cardinality(p_attachments), 0) = 0 AND p_sticker IS NULL THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF jsonb_typeof(v_emoji) <> 'array' OR jsonb_array_length(v_emoji) > 64 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    v_body_len := char_length(v_body);
    FOR v_span IN SELECT value FROM jsonb_array_elements(v_emoji) LOOP
        BEGIN
            v_span_id := (v_span->>'id')::uuid;
            v_start := (v_span->>'start')::integer;
            v_end := (v_span->>'end')::integer;
        EXCEPTION WHEN others THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END;
        IF v_span_id IS NULL OR v_start IS NULL OR v_end IS NULL
           OR v_start < 0 OR v_end <= v_start OR v_end > v_body_len THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM emoji WHERE id = v_span_id AND kind = 'emoji') THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
    END LOOP;
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
              AND a.kind <> 'sealed'
        ) <> cardinality(p_attachments) THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
    END IF;
    BEGIN
        INSERT INTO messages (
            channel_id, direct_id, author_id, body, reply_to, client_id, emoji_spans, sticker_id
        )
        VALUES (
            v_channel, v_direct, app_uid(), v_body, p_reply, v_client, v_emoji, p_sticker
        )
        RETURNING id INTO v_id;
    EXCEPTION
        WHEN unique_violation THEN
            SELECT id INTO v_existing
            FROM messages
            WHERE author_id = app_uid() AND client_id = v_client AND NOT e2ee;
            RETURN app_message_json(v_existing, app_uid());
    END;
    IF coalesce(cardinality(p_attachments), 0) > 0 THEN
        UPDATE attachments a
        SET message_id = v_id, sort = s.ord::integer
        FROM unnest(p_attachments) WITH ORDINALITY AS s(id, ord)
        WHERE a.id = s.id
          AND a.uploader_id = app_uid()
          AND a.message_id IS NULL
          AND a.scan_status = 'clean'
          AND a.kind <> 'sealed';
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

CREATE OR REPLACE FUNCTION app_post_message_thread(
    p_conversation uuid,
    p_body text,
    p_reply uuid,
    p_client text,
    p_attachments uuid[],
    p_emoji jsonb,
    p_sticker uuid,
    p_thread uuid,
    p_mentions jsonb DEFAULT NULL,
    p_previews jsonb DEFAULT NULL
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
    v_body text := btrim(coalesce(p_body, ''));
    v_client text := nullif(p_client, '');
    v_emoji jsonb := coalesce(p_emoji, '[]'::jsonb);
    v_existing uuid;
    v_id uuid;
    v_linked integer;
    v_payload jsonb;
    v_span jsonb;
    v_span_id uuid;
    v_start integer;
    v_end integer;
    v_body_len integer;
    v_root_channel uuid;
    v_root_thread uuid;
    v_root_author uuid;
BEGIN
    SELECT kind, channel_id, direct_id, low_user_id, high_user_id
    INTO v_kind, v_channel, v_direct, v_low, v_high
    FROM app_open_conversation(p_conversation, true);
    IF app_conv_e2ee(p_conversation) THEN
        RAISE EXCEPTION 'e2ee required' USING ERRCODE = 'P0E01';
    END IF;
    PERFORM app_e2ee_plaintext_allowed();
    IF v_client IS NOT NULL AND (
        char_length(v_client) > 64 OR v_client ~ E'[\\x00-\\x1F\\x7F]'
    ) THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF v_client IS NOT NULL THEN
        SELECT id INTO v_existing
        FROM messages
        WHERE author_id = app_uid() AND client_id = v_client AND NOT e2ee;
        IF FOUND THEN
            RETURN app_message_json(v_existing, app_uid());
        END IF;
    END IF;
    IF char_length(v_body) > 4000 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF p_sticker IS NOT NULL THEN
        IF NOT EXISTS (SELECT 1 FROM emoji WHERE id = p_sticker AND kind = 'sticker') THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
    END IF;
    IF v_body = '' AND coalesce(cardinality(p_attachments), 0) = 0 AND p_sticker IS NULL THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF jsonb_typeof(v_emoji) <> 'array' OR jsonb_array_length(v_emoji) > 64 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    v_body_len := char_length(v_body);
    FOR v_span IN SELECT value FROM jsonb_array_elements(v_emoji) LOOP
        BEGIN
            v_span_id := (v_span->>'id')::uuid;
            v_start := (v_span->>'start')::integer;
            v_end := (v_span->>'end')::integer;
        EXCEPTION WHEN others THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END;
        IF v_span_id IS NULL OR v_start IS NULL OR v_end IS NULL
           OR v_start < 0 OR v_end <= v_start OR v_end > v_body_len THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM emoji WHERE id = v_span_id AND kind = 'emoji') THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
    END LOOP;
    IF p_thread IS NOT NULL THEN
        IF v_kind <> 'channel' THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
        SELECT channel_id, thread_id, author_id
        INTO v_root_channel, v_root_thread, v_root_author
        FROM messages WHERE id = p_thread;
        IF NOT FOUND OR v_root_channel IS DISTINCT FROM v_channel THEN
            RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
        END IF;
        IF v_root_thread IS NOT NULL THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
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
              AND a.kind <> 'sealed'
        ) <> cardinality(p_attachments) THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
    END IF;
    BEGIN
        INSERT INTO messages (
            channel_id, direct_id, author_id, body, reply_to, client_id,
            emoji_spans, sticker_id, thread_id
        )
        VALUES (
            v_channel, v_direct, app_uid(), v_body, p_reply, v_client,
            v_emoji, p_sticker, p_thread
        )
        RETURNING id INTO v_id;
    EXCEPTION
        WHEN unique_violation THEN
            SELECT id INTO v_existing
            FROM messages
            WHERE author_id = app_uid() AND client_id = v_client AND NOT e2ee;
            RETURN app_message_json(v_existing, app_uid());
    END;
    IF coalesce(cardinality(p_attachments), 0) > 0 THEN
        UPDATE attachments a
        SET message_id = v_id, sort = s.ord::integer
        FROM unnest(p_attachments) WITH ORDINALITY AS s(id, ord)
        WHERE a.id = s.id
          AND a.uploader_id = app_uid()
          AND a.message_id IS NULL
          AND a.scan_status = 'clean'
          AND a.kind <> 'sealed';
        GET DIAGNOSTICS v_linked = ROW_COUNT;
        IF v_linked <> cardinality(p_attachments) THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
    END IF;
    IF p_thread IS NOT NULL THEN
        INSERT INTO thread_follows (thread_id, user_id)
        VALUES (p_thread, app_uid()), (p_thread, v_root_author)
        ON CONFLICT (thread_id, user_id) DO NOTHING;
    END IF;
    PERFORM app_store_mentions(v_id, v_kind, v_channel, v_low, v_high, v_body, p_mentions);
    IF p_previews IS NOT NULL THEN
        PERFORM app_store_previews(v_id, v_body, p_previews);
    END IF;
    v_payload := jsonb_build_object(
        'conversation_id', p_conversation::text,
        'kind', v_kind,
        'message', app_message_json(v_id, app_uid())
    );
    PERFORM app_emit_to('message.created', v_payload, app_audience(v_kind, v_low, v_high));
    IF p_thread IS NOT NULL THEN
        PERFORM app_emit_to(
            'thread.updated',
            jsonb_build_object(
                'conversation_id', p_conversation::text,
                'kind', 'channel',
                'message_id', p_thread::text,
                'thread', app_thread_summary(p_thread, NULL)
            ),
            app_audience(v_kind, v_low, v_high)
        );
    END IF;
    RETURN v_payload->'message';
END;
$$;

CREATE OR REPLACE FUNCTION app_post_e2ee_message(
    p_conversation uuid,
    p_ciphertext bytea,
    p_epoch bigint,
    p_device uuid,
    p_client text,
    p_kind text,
    p_target uuid,
    p_attachments uuid[],
    p_has_body boolean
)
RETURNS TABLE (r_message jsonb, r_created boolean)
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
    v_client text := nullif(btrim(p_client), '');
    v_id uuid;
    v_existing uuid;
    v_group uuid;
    v_epoch bigint;
    v_linked integer;
    v_payload jsonb;
    v_author uuid;
BEGIN
    PERFORM app_e2ee_generation_check(p_conversation);
    SELECT kind, channel_id, direct_id, low_user_id, high_user_id
    INTO v_kind, v_channel, v_direct, v_low, v_high
    FROM app_open_conversation(p_conversation, true);
    IF NOT app_conv_e2ee(p_conversation) THEN
        RAISE EXCEPTION 'not e2ee' USING ERRCODE = 'P0E02';
    END IF;
    IF p_has_body THEN
        RAISE EXCEPTION 'e2ee required' USING ERRCODE = 'P0E01';
    END IF;
    PERFORM app_e2ee_gate(p_conversation, p_device, true);
    IF p_kind IS NULL OR p_kind NOT IN ('message', 'edit')
       OR (p_kind = 'edit') <> (p_target IS NOT NULL) THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF v_client IS NOT NULL AND (
        char_length(v_client) > 64 OR v_client ~ E'[\\x00-\\x1F\\x7F]'
    ) THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF v_client IS NOT NULL THEN
        SELECT m.id INTO v_existing FROM messages m
        WHERE m.e2ee AND m.device_id = p_device AND m.client_id = v_client
          AND coalesce(m.channel_id, m.direct_id) = p_conversation;
        IF FOUND THEN
            RETURN QUERY SELECT app_message_json(v_existing, app_uid()), false;
            RETURN;
        END IF;
    END IF;
    IF p_ciphertext IS NULL OR octet_length(p_ciphertext) < 1 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF octet_length(p_ciphertext) > 20480 THEN
        RAISE EXCEPTION 'too large' USING ERRCODE = '22023';
    END IF;
    IF coalesce(cardinality(p_attachments), 0) > 10 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    v_group := app_e2ee_resolve(p_conversation);
    PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.e2ee.' || v_group::text, 0));
    IF v_group IS DISTINCT FROM app_e2ee_resolve(p_conversation) THEN
        RAISE EXCEPTION 'stale epoch' USING ERRCODE = 'P0E03';
    END IF;
    SELECT g.epoch INTO v_epoch FROM e2ee_groups g
    WHERE g.conversation_id = v_group AND g.shared_from IS NULL
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no group' USING ERRCODE = 'P0E05';
    END IF;
    IF v_epoch <> p_epoch THEN
        RAISE EXCEPTION 'stale epoch' USING ERRCODE = 'P0E03';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM e2ee_leaves l
                   WHERE l.conversation_id = v_group AND l.device_id = p_device)
       OR EXISTS (SELECT 1 FROM e2ee_pending p
                  WHERE p.conversation_id = v_group AND p.device_id = p_device
                    AND p.op = 'remove') THEN
        RAISE EXCEPTION 'not in group' USING ERRCODE = 'P0E07';
    END IF;
    PERFORM app_e2ee_require_current_audience(v_group);
    IF p_kind = 'edit' THEN
        SELECT m.author_id INTO v_author FROM messages m
        WHERE m.id = p_target AND m.e2ee AND m.msg_kind = 'message' AND m.deleted_at IS NULL
          AND (m.channel_id IS NOT DISTINCT FROM v_channel)
          AND (m.direct_id IS NOT DISTINCT FROM v_direct);
        IF NOT FOUND THEN
            RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
        END IF;
        IF v_author <> app_uid() THEN
            RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
        END IF;
    END IF;
    IF coalesce(cardinality(p_attachments), 0) > 0 THEN
        IF (
            SELECT count(*) FROM attachments a
            WHERE a.id = ANY (p_attachments)
              AND a.uploader_id = app_uid()
              AND a.message_id IS NULL
              AND a.created_at > now() - interval '1 hour'
              AND a.kind = 'sealed'
        ) <> cardinality(p_attachments) THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
    END IF;
    BEGIN
        INSERT INTO messages (channel_id, direct_id, author_id, body, client_id,
                              e2ee, ciphertext, epoch, device_id, msg_kind, target_id)
        VALUES (v_channel, v_direct, app_uid(), '', v_client,
                true, p_ciphertext, p_epoch, p_device, p_kind, p_target)
        RETURNING id INTO v_id;
    EXCEPTION
        WHEN unique_violation THEN
            SELECT m.id INTO v_existing FROM messages m
            WHERE m.e2ee AND m.device_id = p_device AND m.client_id = v_client
              AND coalesce(m.channel_id, m.direct_id) = p_conversation;
            RETURN QUERY SELECT app_message_json(v_existing, app_uid()), false;
            RETURN;
    END;
    IF coalesce(cardinality(p_attachments), 0) > 0 THEN
        UPDATE attachments a
        SET message_id = v_id, sort = s.ord::integer
        FROM unnest(p_attachments) WITH ORDINALITY AS s(id, ord)
        WHERE a.id = s.id
          AND a.uploader_id = app_uid()
          AND a.message_id IS NULL
          AND a.kind = 'sealed';
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
    RETURN QUERY SELECT v_payload->'message', true;
END;
$$;

CREATE OR REPLACE FUNCTION app_edit_message(
    p_id uuid,
    p_body text,
    p_mentions jsonb DEFAULT NULL,
    p_previews jsonb DEFAULT NULL
)
RETURNS TABLE (r_message jsonb, r_removed_files text[])
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_author uuid;
    v_channel uuid;
    v_direct uuid;
    v_deleted timestamptz;
    v_e2ee boolean;
    v_old_body text;
    v_body text;
    v_mine boolean;
    v_mod_strip boolean;
    v_kind text;
    v_low uuid;
    v_high uuid;
    v_conv uuid;
    v_files integer;
    v_removed text[];
BEGIN
    PERFORM app_msg_voice();
    SELECT author_id, channel_id, direct_id, deleted_at, e2ee, body
    INTO v_author, v_channel, v_direct, v_deleted, v_e2ee, v_old_body
    FROM messages WHERE id = p_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    v_mine := v_author = app_uid();
    v_mod_strip := NOT v_mine
        AND p_body IS NULL
        AND p_mentions IS NULL
        AND p_previews IS NOT NULL
        AND jsonb_typeof(p_previews) = 'array'
        AND jsonb_array_length(p_previews) = 0;
    v_conv := coalesce(v_channel, v_direct);
    SELECT kind, low_user_id, high_user_id INTO v_kind, v_low, v_high
    FROM app_open_conversation(v_conv, v_mine);
    IF v_e2ee THEN
        RAISE EXCEPTION 'e2ee required' USING ERRCODE = 'P0E01';
    END IF;
    PERFORM app_e2ee_plaintext_allowed();
    IF NOT v_mine AND NOT (
        v_mod_strip AND v_channel IS NOT NULL AND app_channel_has(v_channel, 2097152)
    ) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    IF v_deleted IS NOT NULL THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF p_body IS NULL AND p_previews IS NULL THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF p_body IS NOT NULL THEN
        v_body := coalesce(btrim(p_body), '');
        IF char_length(v_body) > 4000 THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
        SELECT count(*) INTO v_files
        FROM attachments WHERE message_id = p_id AND NOT is_preview;
        IF v_body = '' AND v_files = 0 THEN
            RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
        END IF;
        UPDATE messages SET body = v_body, edited_at = now() WHERE id = p_id;
        PERFORM app_store_mentions(p_id, v_kind, v_channel, v_low, v_high, v_body, p_mentions);
    ELSE
        v_body := v_old_body;
    END IF;
    v_removed := app_store_previews(p_id, v_body, p_previews);
    PERFORM app_emit_to(
        'message.edited',
        jsonb_build_object(
            'conversation_id', v_conv::text,
            'kind', v_kind,
            'message', app_message_json(p_id, app_uid())
        ),
        app_audience(v_kind, v_low, v_high)
    );
    RETURN QUERY SELECT app_message_json(p_id, app_uid()), v_removed;
END;
$$;

CREATE OR REPLACE FUNCTION app_delete_message(p_id uuid)
RETURNS text[]
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_author uuid;
    v_channel uuid;
    v_direct uuid;
    v_deleted timestamptz;
    v_thread uuid;
    v_mine boolean;
    v_kind text;
    v_low uuid;
    v_high uuid;
    v_conv uuid;
    v_files text[];
    v_all uuid[];
BEGIN
    PERFORM app_msg_voice();
    SELECT author_id, channel_id, direct_id, deleted_at, thread_id
    INTO v_author, v_channel, v_direct, v_deleted, v_thread
    FROM messages WHERE id = p_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    v_mine := v_author = app_uid();
    v_conv := coalesce(v_channel, v_direct);
    SELECT kind, low_user_id, high_user_id INTO v_kind, v_low, v_high
    FROM app_open_conversation(v_conv, v_mine);
    IF NOT v_mine AND NOT (v_channel IS NOT NULL AND app_channel_has(v_channel, 2097152)) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    IF v_deleted IS NOT NULL THEN
        RETURN '{}'::text[];
    END IF;
    SELECT p_id || coalesce(array_agg(m.id), '{}') INTO v_all
    FROM messages m WHERE m.target_id = p_id;
    SELECT coalesce(array_agg(id::text), '{}') INTO v_files
    FROM attachments WHERE message_id = ANY (v_all);
    DELETE FROM message_previews WHERE message_id = ANY (v_all);
    DELETE FROM attachments WHERE message_id = ANY (v_all);
    DELETE FROM reactions WHERE message_id = ANY (v_all);
    DELETE FROM channel_pins WHERE message_id = ANY (v_all);
    DELETE FROM message_mentions WHERE message_id = ANY (v_all);
    UPDATE messages SET body = '', deleted_at = now(),
        deleted_by = CASE WHEN v_mine THEN NULL ELSE app_uid() END
    WHERE id = ANY (v_all) AND deleted_at IS NULL;
    IF NOT v_mine THEN
        PERFORM app_audit('message.delete', 'message',
                          jsonb_build_object('message_id', p_id, 'channel_id', v_channel),
                          v_author, NULL);
    END IF;
    PERFORM app_emit_to(
        'message.deleted',
        jsonb_build_object(
            'conversation_id', v_conv::text,
            'kind', v_kind,
            'message', app_message_json(p_id, app_uid())
        ),
        app_audience(v_kind, v_low, v_high)
    );
    IF v_thread IS NOT NULL THEN
        PERFORM app_emit_to(
            'thread.updated',
            jsonb_build_object(
                'conversation_id', v_conv::text,
                'kind', 'channel',
                'message_id', v_thread::text,
                'thread', app_thread_summary(v_thread, NULL)
            ),
            app_audience(v_kind, v_low, v_high)
        );
    END IF;
    RETURN v_files;
END;
$$;

CREATE OR REPLACE FUNCTION app_reaction(p_message uuid, p_emoji text, p_on boolean)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_channel uuid;
    v_direct uuid;
    v_deleted timestamptz;
    v_e2ee boolean;
    v_kind text;
    v_low uuid;
    v_high uuid;
    v_conv uuid;
    v_count integer;
    v_me boolean;
BEGIN
    PERFORM app_emoji_ok(p_emoji);
    PERFORM app_msg_voice();
    SELECT channel_id, direct_id, deleted_at, e2ee
    INTO v_channel, v_direct, v_deleted, v_e2ee
    FROM messages WHERE id = p_message;
    IF NOT FOUND OR v_deleted IS NOT NULL THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    IF v_e2ee THEN
        RAISE EXCEPTION 'e2ee required' USING ERRCODE = 'P0E01';
    END IF;
    v_conv := coalesce(v_channel, v_direct);
    SELECT kind, low_user_id, high_user_id INTO v_kind, v_low, v_high
    FROM app_open_conversation(v_conv, true);
    IF p_on THEN
        INSERT INTO reactions (message_id, user_id, emoji, emoji_id)
        VALUES (p_message, app_uid(), p_emoji, NULL)
        ON CONFLICT (message_id, user_id, emoji) WHERE emoji_id IS NULL DO NOTHING;
    ELSE
        DELETE FROM reactions
        WHERE message_id = p_message AND user_id = app_uid()
          AND emoji = p_emoji AND emoji_id IS NULL;
    END IF;
    SELECT count(*)::integer, coalesce(bool_or(user_id = app_uid()), false)
    INTO v_count, v_me
    FROM reactions
    WHERE message_id = p_message AND emoji = p_emoji AND emoji_id IS NULL;
    PERFORM app_emit_to(
        'reaction.updated',
        jsonb_build_object(
            'message_id', p_message::text,
            'conversation_id', v_conv::text,
            'kind', v_kind,
            'emoji', p_emoji,
            'on', p_on,
            'user_id', app_uid()::text,
            'count', v_count
        ),
        app_audience(v_kind, v_low, v_high)
    );
    RETURN jsonb_build_object('emoji', p_emoji, 'count', v_count, 'me', v_me);
END;
$$;

CREATE OR REPLACE FUNCTION app_custom_reaction(p_message uuid, p_emoji_id uuid, p_on boolean)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_channel uuid;
    v_direct uuid;
    v_deleted timestamptz;
    v_kind text;
    v_low uuid;
    v_high uuid;
    v_conv uuid;
    v_name text;
    v_label text;
    v_count integer;
    v_me boolean;
BEGIN
    PERFORM app_msg_voice();
    SELECT name INTO v_name FROM emoji WHERE id = p_emoji_id AND kind = 'emoji';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    v_label := ':' || v_name || ':';
    SELECT channel_id, direct_id, deleted_at INTO v_channel, v_direct, v_deleted
    FROM messages WHERE id = p_message;
    IF NOT FOUND OR v_deleted IS NOT NULL THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    v_conv := coalesce(v_channel, v_direct);
    SELECT kind, low_user_id, high_user_id INTO v_kind, v_low, v_high
    FROM app_open_conversation(v_conv, true);
    IF p_on THEN
        INSERT INTO reactions (message_id, user_id, emoji, emoji_id)
        VALUES (p_message, app_uid(), v_label, p_emoji_id)
        ON CONFLICT (message_id, user_id, emoji_id) WHERE emoji_id IS NOT NULL DO NOTHING;
    ELSE
        DELETE FROM reactions
        WHERE message_id = p_message AND user_id = app_uid() AND emoji_id = p_emoji_id;
    END IF;
    SELECT count(*)::integer, coalesce(bool_or(user_id = app_uid()), false)
    INTO v_count, v_me
    FROM reactions
    WHERE message_id = p_message AND emoji_id = p_emoji_id;
    PERFORM app_emit_to(
        'reaction.updated',
        jsonb_build_object(
            'message_id', p_message::text,
            'conversation_id', v_conv::text,
            'kind', v_kind,
            'emoji', v_label,
            'emoji_id', p_emoji_id::text,
            'name', v_name,
            'on', p_on,
            'user_id', app_uid()::text,
            'count', v_count
        ),
        app_audience(v_kind, v_low, v_high)
    );
    RETURN jsonb_build_object(
        'emoji', v_label,
        'emoji_id', p_emoji_id::text,
        'name', v_name,
        'count', v_count,
        'me', v_me
    );
END;
$$;

CREATE OR REPLACE FUNCTION app_pin_message(p_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_channel uuid;
    v_direct uuid;
    v_deleted timestamptz;
    v_kind text;
    v_low uuid;
    v_high uuid;
    v_conv uuid;
BEGIN
    PERFORM app_msg_voice();
    SELECT channel_id, direct_id, deleted_at INTO v_channel, v_direct, v_deleted
    FROM messages WHERE id = p_id;
    IF NOT FOUND OR v_deleted IS NOT NULL THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    v_conv := coalesce(v_channel, v_direct);
    SELECT kind, low_user_id, high_user_id INTO v_kind, v_low, v_high
    FROM app_open_conversation(v_conv, false);
    IF v_kind = 'channel' AND NOT app_channel_has(v_channel, 512) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    IF EXISTS (SELECT 1 FROM channel_pins WHERE message_id = p_id) THEN
        RETURN;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.pins'));
    IF EXISTS (SELECT 1 FROM channel_pins WHERE message_id = p_id) THEN
        RETURN;
    END IF;
    IF (SELECT count(*) FROM channel_pins WHERE channel_id = v_conv) >= 50 THEN
        RAISE EXCEPTION 'pin limit' USING ERRCODE = 'P0E23';
    END IF;
    INSERT INTO channel_pins (channel_id, message_id, pinned_by)
    VALUES (v_conv, p_id, app_uid())
    ON CONFLICT (message_id) DO NOTHING;
    IF v_kind = 'channel' THEN
        PERFORM app_audit(
            'message.pin', 'message',
            jsonb_build_object('message_id', p_id, 'channel_id', v_channel),
            NULL, NULL
        );
    END IF;
    PERFORM app_emit_to(
        'pin.added',
        jsonb_build_object(
            'conversation_id', v_conv::text,
            'kind', v_kind,
            'message_id', p_id::text,
            'pinned_by', app_uid()::text
        ),
        app_audience(v_kind, v_low, v_high)
    );
END;
$$;

CREATE OR REPLACE FUNCTION app_unpin_message(p_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_channel uuid;
    v_direct uuid;
    v_deleted timestamptz;
    v_kind text;
    v_low uuid;
    v_high uuid;
    v_conv uuid;
BEGIN
    PERFORM app_msg_voice();
    SELECT channel_id, direct_id, deleted_at INTO v_channel, v_direct, v_deleted
    FROM messages WHERE id = p_id;
    IF NOT FOUND OR v_deleted IS NOT NULL THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    v_conv := coalesce(v_channel, v_direct);
    SELECT kind, low_user_id, high_user_id INTO v_kind, v_low, v_high
    FROM app_open_conversation(v_conv, false);
    IF v_kind = 'channel' AND NOT app_channel_has(v_channel, 512) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    DELETE FROM channel_pins WHERE message_id = p_id;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    IF v_kind = 'channel' THEN
        PERFORM app_audit(
            'message.unpin', 'message',
            jsonb_build_object('message_id', p_id, 'channel_id', v_channel),
            NULL, NULL
        );
    END IF;
    PERFORM app_emit_to(
        'pin.removed',
        jsonb_build_object(
            'conversation_id', v_conv::text,
            'kind', v_kind,
            'message_id', p_id::text,
            'pinned_by', app_uid()::text
        ),
        app_audience(v_kind, v_low, v_high)
    );
END;
$$;

CREATE OR REPLACE FUNCTION app_mark_read(p_conversation uuid, p_message uuid)
RETURNS void
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
    v_at timestamptz;
    v_old uuid;
    v_old_at timestamptz;
    v_old_id uuid;
BEGIN
    SELECT kind, channel_id, direct_id, low_user_id, high_user_id
    INTO v_kind, v_channel, v_direct, v_low, v_high
    FROM app_open_conversation(p_conversation, false);
    SELECT created_at INTO v_at
    FROM messages
    WHERE id = p_message
      AND (channel_id IS NOT DISTINCT FROM v_channel)
      AND (direct_id IS NOT DISTINCT FROM v_direct);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    SELECT message_id INTO v_old
    FROM reads
    WHERE user_id = app_uid() AND kind = v_kind AND conversation_id = p_conversation;
    IF v_old IS NOT NULL THEN
        SELECT created_at, id INTO v_old_at, v_old_id FROM messages WHERE id = v_old;
        IF v_old_at IS NOT NULL AND (v_at, p_message) <= (v_old_at, v_old_id) THEN
            RETURN;
        END IF;
    END IF;
    INSERT INTO reads (user_id, kind, conversation_id, message_id)
    VALUES (app_uid(), v_kind, p_conversation, p_message)
    ON CONFLICT (user_id, kind, conversation_id) DO UPDATE
    SET message_id = EXCLUDED.message_id, read_at = now();
    IF v_kind = 'direct' THEN
        PERFORM app_emit_to(
            'read.updated',
            jsonb_build_object(
                'conversation_id', p_conversation::text,
                'kind', 'direct',
                'user_id', app_uid()::text,
                'message_id', p_message::text
            ),
            ARRAY[v_low, v_high]
        );
    ELSIF v_kind = 'channel' THEN
        PERFORM app_emit_to(
            'read.updated',
            jsonb_build_object(
                'conversation_id', p_conversation::text,
                'kind', 'channel',
                'user_id', app_uid()::text,
                'message_id', p_message::text
            ),
            ARRAY[app_uid()]
        );
    END IF;
END;
$$;

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
BEGIN
    SELECT kind, channel_id, direct_id, low_user_id, high_user_id
    INTO v_kind, v_channel, v_direct, v_low, v_high
    FROM app_open_conversation(p_conversation, true);
    IF v_kind = 'direct' THEN
        RETURN ARRAY[
            CASE WHEN v_low = app_uid() THEN v_high ELSE v_low END::text
        ];
    END IF;
    RETURN coalesce((
        SELECT array_agg(m.user_id::text)
        FROM memberships m
        WHERE m.user_id <> app_uid()
          AND app_channel_perms_of(v_channel, m.user_id) & 1 = 1
    ), '{}'::text[]);
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

CREATE OR REPLACE FUNCTION app_search_messages(
    p_query text,
    p_conversation uuid,
    p_author uuid,
    p_before uuid,
    p_limit integer
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_uid uuid := app_uid();
    v_query text := btrim(coalesce(p_query, ''));
    v_limit integer := coalesce(p_limit, 25);
    v_kind text;
    v_channel uuid;
    v_direct uuid;
    v_skipped boolean := false;
    v_before_seq bigint;
    v_tsquery tsquery;
    v_hits jsonb;
    v_more boolean := false;
    v_count integer;
BEGIN
    PERFORM app_msg_gate();
    IF char_length(v_query) < 2 OR char_length(v_query) > 200
       OR v_query ~ E'[\\x00-\\x1F\\x7F]' THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF v_limit < 1 OR v_limit > 50 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.search.' || v_uid::text));
    DELETE FROM search_rate_log
    WHERE user_id = v_uid AND created_at <= now() - interval '1 minute';
    IF (
        SELECT count(*) FROM search_rate_log
        WHERE user_id = v_uid AND created_at > now() - interval '1 minute'
    ) >= 30 THEN
        RAISE EXCEPTION 'slow down' USING ERRCODE = 'P0E11';
    END IF;
    INSERT INTO search_rate_log (user_id, created_at) VALUES (v_uid, now());
    IF p_conversation IS NOT NULL THEN
        SELECT kind, channel_id, direct_id
        INTO v_kind, v_channel, v_direct
        FROM app_open_conversation(p_conversation, false);
        v_skipped := app_conv_e2ee(p_conversation);
    ELSE
        v_skipped := EXISTS (
            SELECT 1 FROM channels c
            WHERE c.e2ee AND app_channel_perms_of(c.id, v_uid) & 1 = 1
        ) OR EXISTS (
            SELECT 1 FROM directs d
            WHERE d.e2ee AND NOT d.is_self
              AND v_uid IN (d.low_user_id, d.high_user_id)
        );
    END IF;
    IF p_before IS NOT NULL THEN
        SELECT m.seq INTO v_before_seq FROM messages m WHERE m.id = p_before;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
        END IF;
    END IF;
    v_tsquery := plainto_tsquery('simple', v_query);
    IF v_tsquery = ''::tsquery THEN
        RETURN jsonb_build_object(
            'hits', '[]'::jsonb,
            'more', false,
            'skipped_encrypted', v_skipped
        );
    END IF;
    WITH matched AS (
        SELECT m.id,
               coalesce(m.channel_id, m.direct_id) AS conversation_id,
               CASE WHEN m.channel_id IS NOT NULL THEN 'channel' ELSE 'direct' END AS kind,
               m.seq
        FROM messages m
        WHERE m.deleted_at IS NULL
          AND NOT m.e2ee
          AND m.msg_kind = 'message'
          AND to_tsvector('simple', m.body) @@ v_tsquery
          AND (p_author IS NULL OR m.author_id = p_author)
          AND (v_before_seq IS NULL OR (m.seq, m.id) < (v_before_seq, p_before))
          AND (
              (p_conversation IS NOT NULL AND (
                  (v_channel IS NOT NULL AND m.channel_id = v_channel)
                  OR (v_direct IS NOT NULL AND m.direct_id = v_direct)
              ))
              OR (p_conversation IS NULL AND (
                  (m.channel_id IS NOT NULL AND app_channel_perms_of(m.channel_id, v_uid) & 1 = 1)
                  OR (m.direct_id IS NOT NULL AND EXISTS (
                      SELECT 1 FROM directs d
                      WHERE d.id = m.direct_id
                        AND NOT d.is_self
                        AND v_uid IN (d.low_user_id, d.high_user_id)
                  ))
              ))
          )
        ORDER BY m.seq DESC, m.id DESC
        LIMIT v_limit + 1
    ),
    counted AS (
        SELECT count(*)::integer AS total FROM matched
    ),
    page AS (
        SELECT id, conversation_id, kind, seq
        FROM matched
        ORDER BY seq DESC, id DESC
        LIMIT v_limit
    )
    SELECT coalesce(
               (SELECT jsonb_agg(
                    jsonb_build_object(
                        'conversation_id', p.conversation_id::text,
                        'kind', p.kind,
                        'message', app_message_json(p.id, v_uid)
                    )
                    ORDER BY p.seq DESC, p.id DESC
                ) FROM page p),
               '[]'::jsonb
           ),
           (SELECT total FROM counted)
    INTO v_hits, v_count;
    v_more := coalesce(v_count, 0) > v_limit;
    RETURN jsonb_build_object(
        'hits', v_hits,
        'more', v_more,
        'skipped_encrypted', v_skipped
    );
END;
$$;

-- Restore policies, indexes, constraints, and drop group tables and helpers.
DROP POLICY messages_select ON messages;
CREATE POLICY messages_select ON messages
    FOR SELECT USING (
        (channel_id IS NOT NULL AND app_channel_has(channel_id, 1))
        OR (direct_id IS NOT NULL AND EXISTS (
            SELECT 1 FROM directs d
            WHERE d.id = direct_id AND app_uid() IN (d.low_user_id, d.high_user_id)
        ))
    );

DELETE FROM messages WHERE group_dm_id IS NOT NULL;
DELETE FROM reads WHERE kind = 'group';
ALTER TABLE reads DROP CONSTRAINT IF EXISTS reads_kind_check;
ALTER TABLE reads ADD CONSTRAINT reads_kind_check
    CHECK (kind IN ('channel', 'direct', 'thread'));

DROP INDEX IF EXISTS messages_e2ee_client;
CREATE UNIQUE INDEX messages_e2ee_client
    ON messages (device_id, (coalesce(channel_id, direct_id)), client_id)
    WHERE client_id IS NOT NULL AND e2ee;

DROP INDEX IF EXISTS messages_group_dm_seq;
ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_parent_check;
ALTER TABLE messages DROP COLUMN IF EXISTS group_dm_id;
ALTER TABLE messages ADD CHECK ((channel_id IS NULL) <> (direct_id IS NULL));

DROP TRIGGER IF EXISTS group_dm_members_sync ON group_dm_members;
DROP FUNCTION IF EXISTS app_group_members_sync();
DROP FUNCTION IF EXISTS app_group_sweep();
DROP FUNCTION IF EXISTS app_group_audience(uuid, uuid);
DROP TABLE IF EXISTS group_dm_members;
DROP TABLE IF EXISTS group_dms;
DROP FUNCTION IF EXISTS app_is_group_member(uuid);
DROP FUNCTION IF EXISTS app_group_member_key(uuid[]);

DELETE FROM _sqlx_migrations WHERE version = 55;

COMMIT;
