-- Close device-link receive gaps and the post-revoke encryption window.
-- Eligibility is urgent for removals, verified siblings, and the initial audience;
-- ordinary additions of new people still use the configured batching interval.
-- The server does not make an MLS commit: clients verify and commit as before.

CREATE OR REPLACE FUNCTION app_e2ee_begin_issue(p_conv uuid)
RETURNS TABLE (
    r_epoch bigint,
    r_id bigint,
    r_op text,
    r_device uuid,
    r_leaf integer,
    r_package bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_group uuid;
    v_epoch bigint;
    v_secs integer;
    v_oldest timestamptz;
    v_urgent_only boolean := false;
BEGIN
    PERFORM app_e2ee_gate(p_conv, NULL, false);
    v_group := app_e2ee_resolve(p_conv);
    PERFORM app_e2ee_reconcile(v_group);
    v_group := app_e2ee_resolve(p_conv);
    SELECT g.epoch INTO v_epoch FROM e2ee_groups g
    WHERE g.conversation_id = v_group AND g.shared_from IS NULL;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    SELECT s.e2ee_commit_batch_secs INTO v_secs FROM server_settings s;
    IF coalesce(v_secs, 0) > 0 THEN
        IF EXISTS (SELECT 1 FROM e2ee_pending p
                   WHERE p.conversation_id = v_group AND p.proposal IS NOT NULL) THEN
            RETURN;
        END IF;
        SELECT min(p.created_at) INTO v_oldest FROM e2ee_pending p
        WHERE p.conversation_id = v_group AND p.proposal IS NULL;
        -- The initial audience is established before messages may be accepted. Later,
        -- an approved sibling introduces no new person/identity; removals protect future
        -- secrecy. Neither should wait for churn batching. One signed batch at a time
        -- still applies above, including when urgent work arrives during a batch.
        v_urgent_only := v_epoch <> 0 AND v_oldest IS NOT NULL
                        AND v_oldest > now() - make_interval(secs => v_secs);
    END IF;
    RETURN QUERY
    SELECT v_epoch, p.id, p.op, p.device_id, p.leaf_index, p.key_package
    FROM e2ee_pending p
    JOIN e2ee_devices d ON d.device_id = p.device_id
    WHERE p.conversation_id = v_group AND p.proposal IS NULL
      AND (NOT v_urgent_only OR p.op = 'remove' OR (
          p.op = 'add' AND d.cross_signature IS NOT NULL
          AND EXISTS (SELECT 1 FROM e2ee_leaves l
                      WHERE l.conversation_id = v_group AND l.user_id = d.user_id)
      ))
    ORDER BY (p.op = 'add'), p.id;
END;
$$;

-- A new ciphertext must be decryptable by the current intended audience, and by no
-- removed leaf. Check the desired set, not just pending proposals: key packages may
-- not have arrived yet, or an Add may be waiting for a later bounded commit.
-- Call only while holding reconciliation's transaction advisory lock. This orders
-- sends with device registration/revocation (whose deferred triggers take that lock
-- before their transaction commits), permission changes, and MLS commits.
CREATE FUNCTION app_e2ee_require_current_audience(p_group uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    IF (SELECT count(*) FROM app_e2ee_desired(p_group)) > app_e2ee_group_devices_max() THEN
        RAISE EXCEPTION 'group too large' USING ERRCODE = 'P0E16';
    END IF;
    IF EXISTS (
        (SELECT d.d_device FROM app_e2ee_desired(p_group) d
         EXCEPT SELECT l.device_id FROM e2ee_leaves l WHERE l.conversation_id = p_group)
        UNION ALL
        (SELECT l.device_id FROM e2ee_leaves l WHERE l.conversation_id = p_group
         EXCEPT SELECT d.d_device FROM app_e2ee_desired(p_group) d)
    ) THEN
        RAISE EXCEPTION 'proposals changed' USING ERRCODE = 'P0E04';
    END IF;
END;
$$;

REVOKE EXECUTE ON FUNCTION app_e2ee_require_current_audience(uuid) FROM PUBLIC, app_runtime;


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
    -- Reconciliation can detach a shared conversation while this call waits.
    -- The ciphertext was sealed for the old group; require a fresh client sync.
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

CREATE OR REPLACE FUNCTION app_post_e2ee_reaction(
    p_conv uuid,
    p_ciphertext bytea,
    p_epoch bigint,
    p_device uuid,
    p_client text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_client text := nullif(btrim(p_client), '');
    v_group uuid;
    v_epoch bigint;
    v_id uuid;
    v_at timestamptz;
    v_seq bigint;
    v_existing record;
BEGIN
    PERFORM app_e2ee_gate(p_conv, p_device, true);
    IF NOT app_conv_e2ee(p_conv) THEN
        RAISE EXCEPTION 'not e2ee' USING ERRCODE = 'P0E02';
    END IF;
    IF v_client IS NULL OR char_length(v_client) > 64 OR v_client ~ E'[\\x00-\\x1F\\x7F]' THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF p_ciphertext IS NULL OR octet_length(p_ciphertext) < 1
       OR octet_length(p_ciphertext) > 20480 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    SELECT id, ciphertext, epoch, created_at, seq
    INTO v_existing
    FROM e2ee_reaction_blobs
    WHERE device_id = p_device AND client_id = v_client;
    IF FOUND THEN
        RETURN jsonb_build_object(
            'id', v_existing.id::text,
            'ciphertext', translate(encode(v_existing.ciphertext, 'base64'), E'\n', ''),
            'epoch', v_existing.epoch,
            'created_at', app_stamp(v_existing.created_at),
            'seq', v_existing.seq,
            'created', false
        );
    END IF;
    v_group := app_e2ee_resolve(p_conv);
    PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.e2ee.' || v_group::text, 0));
    IF v_group IS DISTINCT FROM app_e2ee_resolve(p_conv) THEN
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
    v_at := date_trunc('minute', clock_timestamp());
    INSERT INTO e2ee_reaction_blobs (conversation_id, ciphertext, epoch, device_id, client_id, created_at)
    VALUES (p_conv, p_ciphertext, p_epoch, p_device, v_client, v_at)
    RETURNING id, seq INTO v_id, v_seq;
    PERFORM app_emit_to(
        'e2ee.reaction',
        jsonb_build_object(
            'conversation_id', p_conv::text,
            'id', v_id::text,
            'ciphertext', translate(encode(p_ciphertext, 'base64'), E'\n', ''),
            'epoch', p_epoch,
            'created_at', app_stamp(v_at)
        ),
        app_e2ee_audience(p_conv)
    );
    RETURN jsonb_build_object(
        'id', v_id::text,
        'ciphertext', translate(encode(p_ciphertext, 'base64'), E'\n', ''),
        'epoch', p_epoch,
        'created_at', app_stamp(v_at),
        'seq', v_seq,
        'created', true
    );
END;
$$;
