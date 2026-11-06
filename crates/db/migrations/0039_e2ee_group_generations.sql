-- Durable public generation heads are independent of mutable MLS membership.
-- Opaque UUID tombstones prevent retired groups becoming another conversation.
-- They intentionally retain no user, membership or binding data after deletion.
CREATE TABLE e2ee_reserved_group_ids (group_id uuid PRIMARY KEY);
REVOKE ALL ON e2ee_reserved_group_ids FROM app_runtime;
ALTER TABLE e2ee_reserved_group_ids ENABLE ROW LEVEL SECURITY;
ALTER TABLE e2ee_reserved_group_ids FORCE ROW LEVEL SECURITY;
CREATE TABLE e2ee_generation_heads (
 conversation_id uuid PRIMARY KEY, generation bigint NOT NULL CHECK(generation >= 0),
 group_id uuid NOT NULL UNIQUE, head_hash bytea NOT NULL CHECK(octet_length(head_hash)=32)
);
CREATE TABLE e2ee_generation_bindings (
 conversation_id uuid NOT NULL, generation bigint NOT NULL CHECK(generation>0),
 group_id uuid NOT NULL UNIQUE, binding_hash bytea NOT NULL CHECK(octet_length(binding_hash)=32),
 binding jsonb NOT NULL CHECK(jsonb_typeof(binding)='object' AND octet_length(binding::text)<=4096), PRIMARY KEY(conversation_id,generation), UNIQUE(conversation_id,binding_hash)
);
CREATE TABLE e2ee_generation_members (
 conversation_id uuid NOT NULL, generation bigint NOT NULL, device_id uuid NOT NULL,
 joined_epoch bigint NOT NULL, PRIMARY KEY(conversation_id,generation,device_id)
);
ALTER TABLE e2ee_groups ADD COLUMN generation bigint NOT NULL DEFAULT 0;
ALTER TABLE e2ee_groups ADD COLUMN group_id uuid;
UPDATE e2ee_groups SET group_id=conversation_id;
ALTER TABLE e2ee_groups ALTER COLUMN group_id SET NOT NULL;
INSERT INTO e2ee_reserved_group_ids SELECT DISTINCT group_id FROM e2ee_groups ON CONFLICT DO NOTHING;
ALTER TABLE e2ee_handshake DROP CONSTRAINT e2ee_handshake_conversation_id_fkey;
ALTER TABLE e2ee_trees DROP CONSTRAINT e2ee_trees_conversation_id_fkey;
ALTER TABLE e2ee_handshake ADD COLUMN generation bigint NOT NULL DEFAULT 0;
ALTER TABLE e2ee_trees ADD COLUMN generation bigint NOT NULL DEFAULT 0;
ALTER TABLE e2ee_trees DROP CONSTRAINT e2ee_trees_pkey;
ALTER TABLE e2ee_trees ADD PRIMARY KEY(conversation_id,generation,epoch,part);
ALTER TABLE messages ADD COLUMN generation bigint NOT NULL DEFAULT 0;
ALTER TABLE messages ADD COLUMN group_id uuid;
UPDATE messages SET group_id=app_e2ee_resolve(coalesce(channel_id,direct_id)) WHERE e2ee;
ALTER TABLE e2ee_reaction_blobs ADD COLUMN generation bigint NOT NULL DEFAULT 0;
ALTER TABLE e2ee_reaction_blobs ADD COLUMN group_id uuid;
UPDATE e2ee_reaction_blobs SET group_id=app_e2ee_resolve(conversation_id);
CREATE INDEX e2ee_handshake_generation ON e2ee_handshake(conversation_id,generation,seq);
REVOKE ALL ON e2ee_generation_heads,e2ee_generation_bindings,e2ee_generation_members FROM app_runtime;
ALTER TABLE e2ee_generation_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE e2ee_generation_heads FORCE ROW LEVEL SECURITY;
ALTER TABLE e2ee_generation_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE e2ee_generation_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE e2ee_generation_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE e2ee_generation_members FORCE ROW LEVEL SECURITY;

CREATE FUNCTION app_e2ee_generation_check(p_conv uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_group uuid; v_expected bigint; v_actual bigint;
BEGIN
 PERFORM app_open_conversation(p_conv,false);
 v_group:=app_e2ee_resolve(p_conv);
 PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.e2ee.' || v_group::text,0));
 IF v_group IS DISTINCT FROM app_e2ee_resolve(p_conv) THEN
  RAISE EXCEPTION 'stale epoch' USING ERRCODE='P0E03';
 END IF;
 v_expected:=coalesce(nullif(current_setting('tiny.e2ee_generation',true),''),'0')::bigint;
 SELECT generation INTO v_actual FROM e2ee_generation_heads WHERE conversation_id=p_conv;
 IF v_expected<0 OR v_expected<>coalesce(v_actual,0) THEN
  RAISE EXCEPTION 'generation changed' USING ERRCODE='P0E21';
 END IF;
END;
$$;

CREATE FUNCTION app_e2ee_generation_head(p_conv uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_key bytea; v_group uuid; v_head e2ee_generation_heads;
BEGIN
 PERFORM app_e2ee_gate(p_conv,NULL,false);
 v_group:=app_e2ee_resolve(p_conv);
 PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.e2ee.' || v_group::text,0));
 SELECT signature_key INTO v_key FROM e2ee_server_key;
 IF v_key IS NULL THEN RAISE EXCEPTION 'server key unavailable' USING ERRCODE='P0E15'; END IF;
 INSERT INTO e2ee_generation_heads(conversation_id,generation,group_id,head_hash)
 VALUES(p_conv,0,p_conv,sha256(convert_to('tiny-e2ee-v1 group-genesis','UTF8') || decode('00','hex') || uuid_send(p_conv) || sha256(v_key)))
 ON CONFLICT(conversation_id) DO NOTHING;
 INSERT INTO e2ee_reserved_group_ids VALUES(p_conv) ON CONFLICT DO NOTHING;
 SELECT * INTO v_head FROM e2ee_generation_heads WHERE conversation_id=p_conv;
 RETURN jsonb_build_object('generation',v_head.generation,'group_id',v_head.group_id::text,'head_hash',translate(encode(v_head.head_hash,'base64'),E'\n',''));
END;
$$;

CREATE FUNCTION app_e2ee_generations(p_conv uuid,p_after bigint,p_limit integer)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_head jsonb;
BEGIN
 IF p_after IS NULL OR p_after<0 OR p_limit IS NULL OR p_limit<1 OR p_limit>100 THEN RAISE EXCEPTION 'invalid' USING ERRCODE='22023'; END IF;
 v_head:=app_e2ee_generation_head(p_conv);
 RETURN v_head || jsonb_build_object('bindings',coalesce((SELECT jsonb_agg(x.binding ORDER BY x.generation)
  FROM (SELECT binding,generation FROM e2ee_generation_bindings WHERE conversation_id=p_conv AND generation>p_after ORDER BY generation LIMIT p_limit) x),'[]'::jsonb));
END;
$$;

-- Stamp retained public data and archive membership before a mutable group disappears.
CREATE FUNCTION app_e2ee_generation_stamp() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_conv uuid; v_group uuid;
BEGIN
 IF TG_OP='DELETE' THEN
  INSERT INTO e2ee_generation_members SELECT OLD.conversation_id,OLD.generation,l.device_id,l.joined_epoch FROM e2ee_leaves l WHERE l.conversation_id=OLD.conversation_id ON CONFLICT DO NOTHING;
  RETURN OLD;
 END IF;
 IF TG_TABLE_NAME='e2ee_groups' THEN
  NEW.group_id:=coalesce(NEW.group_id,NEW.conversation_id);
  IF TG_OP='INSERT' AND NEW.generation=0 THEN
   -- Creation and UUID reservation commit together, even if the process stops
   -- before its separate group-info read initializes the generation head.
   PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.e2ee.uuid.' || NEW.conversation_id::text,0));
   INSERT INTO e2ee_reserved_group_ids VALUES(NEW.conversation_id) ON CONFLICT DO NOTHING;
  END IF;
  IF NEW.shared_from IS NOT NULL THEN
   PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.e2ee.' || NEW.shared_from::text,0));
   IF EXISTS(SELECT 1 FROM e2ee_generation_heads WHERE conversation_id IN(NEW.conversation_id,NEW.shared_from) AND generation>0) THEN
    RAISE EXCEPTION 'repair unavailable' USING ERRCODE='P0E22';
   END IF;
  END IF;
  RETURN NEW;
 END IF;
 IF TG_TABLE_NAME='messages' THEN v_conv:=coalesce(NEW.channel_id,NEW.direct_id); ELSE v_conv:=NEW.conversation_id; END IF;
 v_group:=app_e2ee_resolve(v_conv);
 SELECT g.generation INTO NEW.generation FROM e2ee_groups g WHERE g.conversation_id=v_group;
 NEW.generation:=coalesce(NEW.generation,0);
 IF TG_TABLE_NAME IN ('messages','e2ee_reaction_blobs') THEN
  SELECT g.group_id INTO NEW.group_id FROM e2ee_groups g WHERE g.conversation_id=v_group;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER generation_group_insert BEFORE INSERT ON e2ee_groups FOR EACH ROW EXECUTE FUNCTION app_e2ee_generation_stamp();
CREATE TRIGGER generation_group_alias_update BEFORE UPDATE OF shared_from ON e2ee_groups FOR EACH ROW EXECUTE FUNCTION app_e2ee_generation_stamp();
CREATE TRIGGER generation_group_delete BEFORE DELETE ON e2ee_groups FOR EACH ROW EXECUTE FUNCTION app_e2ee_generation_stamp();
CREATE TRIGGER generation_handshake BEFORE INSERT ON e2ee_handshake FOR EACH ROW EXECUTE FUNCTION app_e2ee_generation_stamp();
CREATE TRIGGER generation_tree BEFORE INSERT ON e2ee_trees FOR EACH ROW EXECUTE FUNCTION app_e2ee_generation_stamp();
CREATE TRIGGER generation_message BEFORE INSERT ON messages FOR EACH ROW WHEN(NEW.e2ee) EXECUTE FUNCTION app_e2ee_generation_stamp();
CREATE TRIGGER generation_reaction BEFORE INSERT ON e2ee_reaction_blobs FOR EACH ROW EXECUTE FUNCTION app_e2ee_generation_stamp();

-- Availability is a preflight hint; repair rechecks the same permission under lock.
CREATE FUNCTION app_e2ee_can_repair(p_conv uuid)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=public AS $$
BEGIN
 PERFORM app_e2ee_gate(p_conv,NULL,true);
 RETURN true;
EXCEPTION WHEN insufficient_privilege OR no_data_found THEN
 RETURN false;
END;
$$;
REVOKE EXECUTE ON FUNCTION app_e2ee_can_repair(uuid) FROM PUBLIC,app_runtime;

CREATE OR REPLACE FUNCTION app_e2ee_info(p_conv uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_group uuid;
    v_epoch bigint;
    v_committer uuid;
    v_path boolean;
    v_proposals timestamptz;
    v_context bytea;
BEGIN
    PERFORM app_e2ee_generation_check(p_conv);
    PERFORM app_open_conversation(p_conv, false);
    IF NOT app_conv_e2ee(p_conv) THEN
        RETURN jsonb_build_object('e2ee', false);
    END IF;
    v_group := app_e2ee_resolve(p_conv);
    PERFORM app_e2ee_reconcile(v_group);
    v_group := app_e2ee_resolve(p_conv);
    SELECT g.context INTO v_context FROM e2ee_groups g WHERE g.conversation_id = p_conv;
    SELECT g.epoch, g.last_committer, g.last_commit_path, g.last_commit_at
    INTO v_epoch, v_committer, v_path, v_proposals
    FROM e2ee_groups g
    WHERE g.conversation_id = v_group AND g.shared_from IS NULL;
    IF NOT FOUND THEN
        RETURN app_e2ee_generation_head(p_conv) || jsonb_build_object(
            'e2ee', true, 'repair_available',false, 'epoch', NULL, 'group_id', coalesce((SELECT group_id FROM e2ee_generation_heads WHERE conversation_id=p_conv),p_conv)::text,
            'members', '[]'::jsonb, 'pending', '[]'::jsonb,
            'device_cap', app_e2ee_group_devices_max(), 'waiting', 0, 'trees', '[]'::jsonb,
            'preferred_committer', NULL, 'context', NULL
        );
    END IF;
    RETURN app_e2ee_generation_head(p_conv) || jsonb_build_object(
        'e2ee', true,
        'repair_available', v_group=p_conv AND NOT (SELECT e2ee_audience_groups FROM server_settings) AND NOT EXISTS(SELECT 1 FROM e2ee_groups WHERE shared_from=p_conv) AND app_e2ee_can_repair(p_conv),
        'epoch', v_epoch,
        'group_id', coalesce((SELECT group_id FROM e2ee_generation_heads WHERE conversation_id=p_conv AND generation>0),v_group)::text,
        'device_cap', app_e2ee_group_devices_max(),
        'preferred_committer', CASE
            WHEN v_path AND v_committer IS NOT NULL
                 AND v_proposals > now() - interval '10 seconds'
                 AND EXISTS (SELECT 1 FROM e2ee_pending p
                             WHERE p.conversation_id = v_group AND p.proposal IS NOT NULL)
                 AND EXISTS (SELECT 1 FROM e2ee_leaves l
                             WHERE l.conversation_id = v_group AND l.device_id = v_committer)
                 AND NOT EXISTS (SELECT 1 FROM e2ee_pending p
                                 WHERE p.conversation_id = v_group AND p.device_id = v_committer
                                   AND p.op = 'remove')
            THEN v_committer::text
        END,
        'context', CASE WHEN v_context IS NULL THEN NULL
            ELSE translate(encode(v_context, 'base64'), E'\n', '') END,
        'waiting', (
            SELECT count(*) FROM app_e2ee_desired(p_conv) x
            WHERE NOT EXISTS (SELECT 1 FROM e2ee_leaves l
                              WHERE l.conversation_id = v_group AND l.device_id = x.d_device)
              AND NOT EXISTS (SELECT 1 FROM e2ee_pending p
                              WHERE p.conversation_id = v_group AND p.device_id = x.d_device
                                AND p.op = 'add')
        ),
        'trees', coalesce((
            SELECT jsonb_agg(DISTINCT t.epoch ORDER BY t.epoch)
            FROM e2ee_trees t WHERE t.conversation_id = v_group AND t.generation=coalesce((SELECT generation FROM e2ee_generation_heads WHERE conversation_id=p_conv),0)
        ), '[]'::jsonb),
        'members', coalesce((
            SELECT jsonb_agg(jsonb_build_object(
                'user_id', l.user_id::text,
                'device_id', l.device_id::text,
                'leaf_index', l.leaf_index
            ) ORDER BY l.leaf_index)
            FROM e2ee_leaves l WHERE l.conversation_id = v_group
        ), '[]'::jsonb),
        'pending', coalesce((
            SELECT jsonb_agg(jsonb_build_object(
                'op', p.op,
                'user_id', d.user_id::text,
                'device_id', p.device_id::text,
                'issued', p.proposal IS NOT NULL
            ) ORDER BY p.id)
            FROM e2ee_pending p JOIN e2ee_devices d ON d.device_id = p.device_id
            WHERE p.conversation_id = v_group
        ), '[]'::jsonb)
    );
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
    -- Legacy generation-zero recreation reuses this conversation UUID. These
    -- public protocol rows previously cascaded with mutable group deletion;
    -- stale commits and tree epochs cannot enter the rebuilt group. The
    -- positive-head guard above makes this unreachable for repaired history.
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
    v_established boolean;
    v_secs integer;
    v_oldest timestamptz;
    v_urgent_only boolean := false;
BEGIN
    PERFORM app_e2ee_generation_check(p_conv);
    PERFORM app_e2ee_gate(p_conv, NULL, false);
    v_group := app_e2ee_resolve(p_conv);
    PERFORM app_e2ee_reconcile(v_group);
    v_group := app_e2ee_resolve(p_conv);
    SELECT g.epoch, g.audience_established INTO v_epoch, v_established FROM e2ee_groups g
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
        v_urgent_only := v_established AND v_oldest IS NOT NULL
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

CREATE OR REPLACE FUNCTION app_e2ee_issue(
    p_conv uuid,
    p_epoch bigint,
    p_ids bigint[],
    p_proposals bytea[],
    p_batch bytea
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_group uuid;
    v_i integer;
    v_made integer := 0;
BEGIN
    PERFORM app_e2ee_generation_check(p_conv);
    PERFORM app_e2ee_gate(p_conv, NULL, false);
    v_group := app_e2ee_resolve(p_conv);
    PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.e2ee.' || v_group::text, 0));
    IF NOT EXISTS (SELECT 1 FROM e2ee_groups g
                   WHERE g.conversation_id = v_group AND g.shared_from IS NULL
                     AND g.epoch = p_epoch) THEN
        RAISE EXCEPTION 'stale epoch' USING ERRCODE = 'P0E03';
    END IF;
    FOR v_i IN 1..coalesce(cardinality(p_ids), 0) LOOP
        IF p_proposals[v_i] IS NULL THEN
            DELETE FROM e2ee_pending p
            WHERE p.id = p_ids[v_i] AND p.conversation_id = v_group AND p.proposal IS NULL;
        ELSE
            UPDATE e2ee_pending p
            SET proposal = p_proposals[v_i], proposal_epoch = p_epoch
            WHERE p.id = p_ids[v_i] AND p.conversation_id = v_group AND p.proposal IS NULL;
            IF FOUND THEN
                v_made := v_made + 1;
            END IF;
        END IF;
    END LOOP;
    IF v_made > 0 THEN
        INSERT INTO e2ee_handshake (conversation_id, kind, epoch, data)
        VALUES (v_group, 'proposals', p_epoch, p_batch);
        UPDATE e2ee_groups SET proposals_at = now() WHERE conversation_id = v_group;
        PERFORM app_e2ee_hint(v_group);
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app_e2ee_commit_snapshot(p_conv uuid, p_device uuid, p_epoch bigint)
RETURNS TABLE (
    r_leaf integer,
    r_id bigint,
    r_op text,
    r_device uuid,
    r_proposal bytea,
    r_package bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_group uuid;
    v_epoch bigint;
    v_leaf integer;
BEGIN
    PERFORM app_e2ee_generation_check(p_conv);
    PERFORM app_e2ee_gate(p_conv, p_device, false);
    v_group := app_e2ee_resolve(p_conv);
    SELECT g.epoch INTO v_epoch FROM e2ee_groups g
    WHERE g.conversation_id = v_group AND g.shared_from IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no group' USING ERRCODE = 'P0E05';
    END IF;
    IF v_epoch <> p_epoch THEN
        RAISE EXCEPTION 'stale epoch' USING ERRCODE = 'P0E03';
    END IF;
    SELECT l.leaf_index INTO v_leaf FROM e2ee_leaves l
    WHERE l.conversation_id = v_group AND l.device_id = p_device;
    IF NOT FOUND OR EXISTS (SELECT 1 FROM e2ee_pending p
                            WHERE p.conversation_id = v_group AND p.device_id = p_device
                              AND p.op = 'remove') THEN
        RAISE EXCEPTION 'not in group' USING ERRCODE = 'P0E07';
    END IF;
    RETURN QUERY
    SELECT v_leaf, p.id, p.op, p.device_id, p.proposal, p.key_package
    FROM e2ee_pending p
    WHERE p.conversation_id = v_group AND p.proposal IS NOT NULL AND p.proposal_epoch = v_epoch
    ORDER BY p.id;
END;
$$;

CREATE OR REPLACE FUNCTION app_e2ee_apply_commit(
    p_conv uuid,
    p_device uuid,
    p_epoch bigint,
    p_commit bytea,
    p_ids bigint[],
    p_welcome_devices uuid[],
    p_welcomes bytea[],
    p_tree bytea[],
    p_path boolean
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_group uuid;
    v_epoch bigint;
    v_issued bigint[];
    v_row record;
    v_added uuid[] := '{}';
    v_seq bigint;
    v_i integer;
BEGIN
    PERFORM app_e2ee_generation_check(p_conv);
    PERFORM app_e2ee_gate(p_conv, p_device, false);
    v_group := app_e2ee_resolve(p_conv);
    PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.e2ee.' || v_group::text, 0));
    SELECT g.epoch INTO v_epoch FROM e2ee_groups g
    WHERE g.conversation_id = v_group AND g.shared_from IS NULL FOR UPDATE;
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
    SELECT coalesce(array_agg(p.id ORDER BY p.id), '{}') INTO v_issued
    FROM e2ee_pending p
    WHERE p.conversation_id = v_group AND p.proposal IS NOT NULL AND p.proposal_epoch = v_epoch;
    IF cardinality(v_issued) = 0
       OR v_issued IS DISTINCT FROM (SELECT coalesce(array_agg(x ORDER BY x), '{}')
                                     FROM unnest(p_ids) AS u (x)) THEN
        RAISE EXCEPTION 'proposals changed' USING ERRCODE = 'P0E04';
    END IF;

    FOR v_row IN
        SELECT p.id, p.device_id, p.leaf_index FROM e2ee_pending p
        WHERE p.id = ANY (p_ids) AND p.op = 'remove'
    LOOP
        DELETE FROM e2ee_leaves l
        WHERE l.conversation_id = v_group AND l.leaf_index = v_row.leaf_index
          AND l.device_id = v_row.device_id;
        DELETE FROM e2ee_handshake h
        WHERE h.conversation_id = v_group AND h.generation=(SELECT generation FROM e2ee_groups WHERE conversation_id=v_group) AND h.for_device = v_row.device_id;
    END LOOP;
    FOR v_row IN
        SELECT p.id, p.device_id, d.user_id
        FROM unnest(p_ids) WITH ORDINALITY AS o (id, ord)
        JOIN e2ee_pending p ON p.id = o.id
        JOIN e2ee_devices d ON d.device_id = p.device_id
        WHERE p.op = 'add'
        ORDER BY o.ord
    LOOP
        INSERT INTO e2ee_leaves (conversation_id, leaf_index, user_id, device_id, joined_epoch)
        VALUES (v_group, app_e2ee_free_leaf(v_group), v_row.user_id, v_row.device_id, p_epoch + 1);
        v_added := v_added || v_row.device_id;
    END LOOP;
    DELETE FROM e2ee_pending p WHERE p.id = ANY (p_ids);

    IF coalesce(cardinality(p_welcome_devices), 0) <> cardinality(v_added)
       OR coalesce(cardinality(p_welcomes), 0) <> cardinality(v_added)
       OR EXISTS (SELECT 1 FROM unnest(p_welcome_devices) AS w (x) WHERE x <> ALL (v_added)) THEN
        RAISE EXCEPTION 'welcomes do not match the adds' USING ERRCODE = 'P0E15';
    END IF;

    INSERT INTO e2ee_handshake (conversation_id, kind, epoch, data)
    VALUES (v_group, 'commit', p_epoch, p_commit)
    RETURNING seq INTO v_seq;
    FOR v_i IN 1..coalesce(cardinality(p_welcome_devices), 0) LOOP
        INSERT INTO e2ee_handshake (conversation_id, kind, epoch, data, for_device)
        VALUES (v_group, 'welcome', p_epoch + 1, p_welcomes[v_i], p_welcome_devices[v_i]);
    END LOOP;
    UPDATE e2ee_groups
    SET epoch = p_epoch + 1,
        updated_at = now(),
        last_committer = p_device,
        last_commit_at = now(),
        last_commit_path = coalesce(p_path, false)
    WHERE conversation_id = v_group;

    IF coalesce(cardinality(p_tree), 0) > 16 THEN
        RAISE EXCEPTION 'tree too large' USING ERRCODE = 'P0E15';
    END IF;
    FOR v_i IN 1..coalesce(cardinality(p_tree), 0) LOOP
        INSERT INTO e2ee_trees (conversation_id, epoch, part, data)
        VALUES (v_group, p_epoch + 1, v_i - 1, p_tree[v_i]);
    END LOOP;
    DELETE FROM e2ee_trees t WHERE t.conversation_id = v_group AND t.generation=(SELECT generation FROM e2ee_groups WHERE conversation_id=v_group) AND t.epoch <= p_epoch + 1 - 8;

    PERFORM app_e2ee_reconcile(v_group, false);
    IF EXISTS (SELECT 1 FROM e2ee_groups g WHERE g.conversation_id = v_group) THEN
        PERFORM app_e2ee_hint(v_group);
    END IF;
    RETURN v_seq;
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
    PERFORM app_e2ee_generation_check(p_conv);
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
    SELECT id, ciphertext, epoch, created_at, seq, generation, group_id
    INTO v_existing
    FROM e2ee_reaction_blobs
    WHERE device_id = p_device AND client_id = v_client;
    IF FOUND THEN
        RETURN jsonb_build_object(
            'id', v_existing.id::text,
            'ciphertext', translate(encode(v_existing.ciphertext, 'base64'), E'\n', ''),
            'epoch', v_existing.epoch, 'generation',v_existing.generation,'group_id',v_existing.group_id::text,
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
            'epoch', p_epoch,'generation',(SELECT generation FROM e2ee_groups WHERE conversation_id=v_group),'group_id',(SELECT group_id::text FROM e2ee_groups WHERE conversation_id=v_group),
            'created_at', app_stamp(v_at)
        ),
        app_e2ee_audience(p_conv)
    );
    RETURN jsonb_build_object(
        'id', v_id::text,
        'ciphertext', translate(encode(p_ciphertext, 'base64'), E'\n', ''),
        'epoch', p_epoch,'generation',(SELECT generation FROM e2ee_groups WHERE conversation_id=v_group),'group_id',(SELECT group_id::text FROM e2ee_groups WHERE conversation_id=v_group),
        'created_at', app_stamp(v_at),
        'seq', v_seq,
        'created', true
    );
END;
$$;

CREATE OR REPLACE FUNCTION app_e2ee_mls_target(p_conv uuid)
RETURNS TABLE (r_group uuid, r_audience boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    PERFORM app_e2ee_gate(p_conv, NULL, false);
    PERFORM app_e2ee_generation_check(p_conv);
    r_group := coalesce((SELECT group_id FROM e2ee_generation_heads WHERE conversation_id=p_conv AND generation>0),app_e2ee_resolve(p_conv));
    SELECT s.e2ee_audience_groups INTO r_audience FROM server_settings s;
    RETURN NEXT;
END;
$$;

CREATE OR REPLACE FUNCTION app_message_json(p_id uuid, p_viewer uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT jsonb_build_object(
        'id', m.id::text,
        'author_id', m.author_id::text,
        'body', CASE WHEN m.deleted_at IS NULL THEN m.body ELSE '' END,
        'reply_to', m.reply_to::text,
        'client_id', m.client_id,
        'created_at', app_stamp(m.created_at),
        'edited_at', CASE WHEN m.edited_at IS NULL THEN NULL ELSE app_stamp(m.edited_at) END,
        'deleted_at', CASE WHEN m.deleted_at IS NULL THEN NULL ELSE app_stamp(m.deleted_at) END,
        'e2ee', m.e2ee,
        'attachments', coalesce((
            SELECT jsonb_agg(jsonb_build_object(
                'id', a.id::text,
                'name', a.name,
                'mime', a.mime,
                'kind', a.kind,
                'bytes', a.bytes,
                'width', a.width,
                'height', a.height,
                'duration', a.duration
            ) ORDER BY a.sort, a.created_at, a.id)
            FROM attachments a
            WHERE a.message_id = m.id AND m.deleted_at IS NULL
        ), '[]'::jsonb),
        'reactions', coalesce((
            SELECT jsonb_agg(jsonb_build_object(
                'emoji', r.emoji,
                'count', r.count,
                'me', r.me
            ) ORDER BY r.emoji)
            FROM (
                SELECT emoji, count(*) AS count, bool_or(user_id = p_viewer) AS me
                FROM reactions
                WHERE message_id = m.id AND m.deleted_at IS NULL
                GROUP BY emoji
            ) r
        ), '[]'::jsonb)
    ) || CASE WHEN m.e2ee THEN jsonb_build_object(
        'kind', m.msg_kind,
        'ciphertext', CASE WHEN m.deleted_at IS NULL
            THEN translate(encode(m.ciphertext, 'base64'), E'\n', '') END,
        'epoch', m.epoch, 'generation',m.generation,'group_id',m.group_id::text,
        'device_id', m.device_id::text,
        'target_id', m.target_id::text,
        'seq', m.seq
    ) ELSE '{}'::jsonb END
    FROM messages m
    WHERE m.id = p_id;
$$;

CREATE FUNCTION app_e2ee_repair(p_conv uuid,p_binding jsonb,p_hash bytea)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE h e2ee_generation_heads; g e2ee_groups; v_device uuid; v_key bytea; v_new uuid; v_from bigint; v_to bigint; v_epoch bigint; v_existing jsonb;
BEGIN
 PERFORM app_e2ee_gate(p_conv,NULL,true);
 PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.e2ee.' || p_conv::text,0));
 -- A permission-only change can leave the old leaf in place while this waits.
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

-- Explicit historic reads do not reconcile or issue proposals for the active generation.
CREATE FUNCTION app_e2ee_handshake_at(p_conv uuid,p_device uuid,p_after bigint,p_limit integer,p_generation bigint)
RETURNS TABLE(r_seq bigint,r_kind text,r_epoch bigint,r_data bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_group uuid; v_joined bigint;
BEGIN
 PERFORM app_e2ee_gate(p_conv,p_device,false);
 IF p_after IS NULL OR p_after<0 OR p_limit IS NULL OR p_limit<1 OR p_limit>200 OR p_generation IS NULL OR p_generation<0 THEN RAISE EXCEPTION 'invalid' USING ERRCODE='22023'; END IF;
 v_group:=app_e2ee_resolve(p_conv);
 IF p_generation>coalesce((SELECT generation FROM e2ee_generation_heads WHERE conversation_id=p_conv),0) THEN RAISE EXCEPTION 'generation changed' USING ERRCODE='P0E21'; END IF;
 SELECT joined_epoch INTO v_joined FROM e2ee_leaves WHERE conversation_id=v_group AND device_id=p_device AND p_generation=coalesce((SELECT generation FROM e2ee_groups WHERE conversation_id=v_group),0);
 IF v_joined IS NULL THEN SELECT joined_epoch INTO v_joined FROM e2ee_generation_members WHERE conversation_id=v_group AND device_id=p_device AND generation=p_generation; END IF;
 RETURN QUERY SELECT h.seq,h.kind,h.epoch,h.data FROM e2ee_handshake h WHERE h.conversation_id=v_group AND h.generation=p_generation AND h.seq>p_after
 AND ((h.kind='welcome' AND h.for_device=p_device) OR (h.kind IN('commit','proposals') AND v_joined IS NOT NULL AND h.epoch>=v_joined)) ORDER BY h.seq LIMIT p_limit;
END;
$$;
CREATE OR REPLACE FUNCTION app_e2ee_handshake(p_conv uuid,p_device uuid,p_after bigint,p_limit integer)
RETURNS TABLE(r_seq bigint,r_kind text,r_epoch bigint,r_data bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
BEGIN RETURN QUERY SELECT * FROM app_e2ee_handshake_at(p_conv,p_device,p_after,p_limit,0); END;
$$;
CREATE FUNCTION app_e2ee_tree_at(p_conv uuid,p_device uuid,p_epoch bigint,p_generation bigint)
RETURNS SETOF bytea LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE v_group uuid; v_joined bigint;
BEGIN
 PERFORM app_e2ee_gate(p_conv,p_device,false);
 IF p_generation IS NULL OR p_generation<0 THEN RAISE EXCEPTION 'invalid' USING ERRCODE='22023'; END IF;
 v_group:=app_e2ee_resolve(p_conv);
 SELECT joined_epoch INTO v_joined FROM e2ee_leaves WHERE conversation_id=v_group AND device_id=p_device AND p_generation=coalesce((SELECT generation FROM e2ee_groups WHERE conversation_id=v_group),0);
 IF v_joined IS NULL THEN SELECT joined_epoch INTO v_joined FROM e2ee_generation_members WHERE conversation_id=v_group AND device_id=p_device AND generation=p_generation; END IF;
 IF v_joined IS NULL THEN RAISE EXCEPTION 'not in group' USING ERRCODE='P0E07'; END IF;
 IF p_epoch IS NULL OR p_epoch<v_joined THEN RAISE EXCEPTION 'not found' USING ERRCODE='P0002'; END IF;
 RETURN QUERY SELECT data FROM e2ee_trees WHERE conversation_id=v_group AND generation=p_generation AND epoch=p_epoch ORDER BY part;
END;
$$;
CREATE OR REPLACE FUNCTION app_e2ee_tree(p_conv uuid,p_device uuid,p_epoch bigint)
RETURNS SETOF bytea LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
BEGIN RETURN QUERY SELECT * FROM app_e2ee_tree_at(p_conv,p_device,p_epoch,0); END;
$$;
REVOKE EXECUTE ON FUNCTION app_e2ee_generation_check(uuid),app_e2ee_generation_stamp(),app_e2ee_generation_head(uuid) FROM PUBLIC,app_runtime;
REVOKE EXECUTE ON FUNCTION app_e2ee_repair(uuid,jsonb,bytea),app_e2ee_generations(uuid,bigint,integer),app_e2ee_handshake_at(uuid,uuid,bigint,integer,bigint),app_e2ee_tree_at(uuid,uuid,bigint,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_e2ee_repair(uuid,jsonb,bytea),app_e2ee_generations(uuid,bigint,integer),app_e2ee_handshake_at(uuid,uuid,bigint,integer,bigint),app_e2ee_tree_at(uuid,uuid,bigint,bigint) TO app_runtime;

CREATE OR REPLACE FUNCTION app_e2ee_reconcile(p_conv uuid, p_emit boolean DEFAULT true)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_group uuid;
    v_desired uuid[];
    v_changed boolean := false;
    v_room integer;
    v_row record;
    v_package record;
    v_left integer;
    v_leaves integer;
    v_removing integer;
    v_adding integer;
BEGIN
    v_group := app_e2ee_resolve(p_conv);
    PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.e2ee.' || v_group::text, 0));
    IF NOT EXISTS (SELECT 1 FROM e2ee_groups g
                   WHERE g.conversation_id = v_group AND g.shared_from IS NULL) THEN
        RETURN false;
    END IF;
    DELETE FROM e2ee_groups s
    WHERE s.shared_from = v_group
      AND app_e2ee_audience_hash(s.conversation_id)
          IS DISTINCT FROM app_e2ee_audience_hash(v_group);
    UPDATE e2ee_groups g
    SET audience_hash = CASE WHEN g.generation>0 THEN NULL ELSE app_e2ee_audience_hash(g.conversation_id) END
    WHERE g.conversation_id = v_group AND g.shared_from IS NULL;

    SELECT coalesce(array_agg(DISTINCT x.d_device), '{}'::uuid[]) INTO v_desired
    FROM (
        SELECT d.d_device FROM app_e2ee_desired(v_group) d
        UNION
        SELECT d.d_device
        FROM e2ee_groups s
        CROSS JOIN LATERAL app_e2ee_desired(s.conversation_id) AS d
        WHERE s.shared_from = v_group
    ) x;

    IF EXISTS (SELECT 1 FROM e2ee_leaves l WHERE l.conversation_id = v_group)
       AND NOT EXISTS (SELECT 1 FROM e2ee_leaves l
                       WHERE l.conversation_id = v_group AND l.device_id = ANY (v_desired)) THEN
        DELETE FROM e2ee_groups WHERE conversation_id = v_group;
        RETURN true;
    END IF;

    DELETE FROM e2ee_pending p
    WHERE p.conversation_id = v_group AND p.proposal IS NULL AND (
        (p.op = 'add' AND (
            p.device_id <> ALL (v_desired)
            OR EXISTS (SELECT 1 FROM e2ee_leaves l
                       WHERE l.conversation_id = v_group AND l.device_id = p.device_id)))
        OR (p.op = 'remove' AND (
            p.device_id = ANY (v_desired)
            OR NOT EXISTS (SELECT 1 FROM e2ee_leaves l
                           WHERE l.conversation_id = v_group AND l.device_id = p.device_id)))
    );

    FOR v_row IN
        SELECT l.leaf_index, l.device_id
        FROM e2ee_leaves l
        WHERE l.conversation_id = v_group
          AND l.device_id <> ALL (v_desired)
          AND NOT EXISTS (SELECT 1 FROM e2ee_pending p
                          WHERE p.conversation_id = v_group AND p.device_id = l.device_id
                            AND p.op = 'remove')
        ORDER BY l.leaf_index
    LOOP
        INSERT INTO e2ee_pending (conversation_id, op, device_id, leaf_index)
        VALUES (v_group, 'remove', v_row.device_id, v_row.leaf_index);
        v_changed := true;
    END LOOP;

    SELECT count(*) INTO v_leaves FROM e2ee_leaves l WHERE l.conversation_id = v_group;
    SELECT count(*) FILTER (WHERE p.op = 'remove'), count(*) FILTER (WHERE p.op = 'add')
    INTO v_removing, v_adding
    FROM e2ee_pending p WHERE p.conversation_id = v_group;
    v_room := greatest(0, least(
        app_e2ee_adds_per_commit(v_leaves) - v_adding,
        app_e2ee_group_devices_max() - (v_leaves - v_removing + v_adding)
    ));
    FOR v_row IN
        SELECT w.d_device
        FROM unnest(v_desired) AS w (d_device)
        WHERE NOT EXISTS (SELECT 1 FROM e2ee_leaves l
                          WHERE l.conversation_id = v_group AND l.device_id = w.d_device)
          AND NOT EXISTS (SELECT 1 FROM e2ee_pending p
                          WHERE p.conversation_id = v_group AND p.device_id = w.d_device
                            AND p.op = 'add')
        ORDER BY w.d_device
        LIMIT v_room
    LOOP
        SELECT k.id, k.data, k.last_resort INTO v_package
        FROM e2ee_key_packages k
        WHERE k.device_id = v_row.d_device AND k.expires_at > now()
        ORDER BY k.last_resort, k.id
        LIMIT 1
        FOR UPDATE SKIP LOCKED;
        IF NOT FOUND THEN
            CONTINUE;
        END IF;
        INSERT INTO e2ee_pending (conversation_id, op, device_id, key_package)
        VALUES (v_group, 'add', v_row.d_device, v_package.data);
        v_changed := true;
        IF NOT v_package.last_resort THEN
            DELETE FROM e2ee_key_packages WHERE id = v_package.id;
        END IF;
        SELECT count(*) INTO v_left
        FROM e2ee_key_packages k
        WHERE k.device_id = v_row.d_device AND NOT k.last_resort AND k.expires_at > now();
        IF v_left < 5 THEN
            UPDATE e2ee_devices SET low_keys = true
            WHERE device_id = v_row.d_device AND NOT low_keys;
            IF FOUND THEN
                PERFORM app_emit_to(
                    'e2ee.keys_low',
                    jsonb_build_object('device_id', v_row.d_device::text, 'remaining', v_left),
                    ARRAY[(SELECT d.user_id FROM e2ee_devices d WHERE d.device_id = v_row.d_device)]
                );
            END IF;
        END IF;
    END LOOP;

    IF v_changed AND p_emit THEN
        PERFORM app_e2ee_hint(v_group);
    END IF;
    RETURN v_changed;
END;
$$;

CREATE OR REPLACE FUNCTION app_list_e2ee_reactions(p_conv uuid, p_after bigint, p_limit integer)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    PERFORM app_e2ee_gate(p_conv, NULL, false);
    IF NOT app_conv_e2ee(p_conv) THEN
        RAISE EXCEPTION 'not e2ee' USING ERRCODE = 'P0E02';
    END IF;
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    RETURN coalesce((
        SELECT jsonb_agg(jsonb_build_object(
            'id', r.id::text,
            'ciphertext', translate(encode(r.ciphertext, 'base64'), E'\n', ''),
            'epoch', r.epoch,'generation',r.generation,'group_id',r.group_id::text,
            'created_at', app_stamp(r.created_at),
            'seq', r.seq
        ) ORDER BY r.seq)
        FROM (
            SELECT id, ciphertext, epoch, created_at, seq, generation, group_id
            FROM e2ee_reaction_blobs
            WHERE conversation_id = p_conv
              AND (p_after IS NULL OR seq > p_after)
            ORDER BY seq
            LIMIT p_limit
        ) r
    ), '[]'::jsonb);
END;
$$;

-- New conversations and repair CAS serialize UUID reservation checks together.
CREATE FUNCTION app_e2ee_conversation_uuid_check() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.e2ee.uuid.' || NEW.id::text,0));
 IF EXISTS(SELECT 1 FROM e2ee_reserved_group_ids WHERE group_id=NEW.id) THEN
  RAISE EXCEPTION 'group exists' USING ERRCODE='P0E06';
 END IF;
 RETURN NEW;
END;
$$;
REVOKE EXECUTE ON FUNCTION app_e2ee_conversation_uuid_check() FROM PUBLIC,app_runtime;
CREATE TRIGGER channels_e2ee_uuid BEFORE INSERT ON channels FOR EACH ROW EXECUTE FUNCTION app_e2ee_conversation_uuid_check();
CREATE TRIGGER directs_e2ee_uuid BEFORE INSERT ON directs FOR EACH ROW EXECUTE FUNCTION app_e2ee_conversation_uuid_check();

-- Deleting a conversation keeps only opaque UUID reservations. Deleting mutable
-- MLS rows alone keeps its durable head, ledger and readable public history.
CREATE OR REPLACE FUNCTION app_e2ee_forget_channel() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
BEGIN
 DELETE FROM e2ee_groups WHERE conversation_id=OLD.id;
 DELETE FROM e2ee_generation_heads WHERE conversation_id=OLD.id;
 DELETE FROM e2ee_generation_bindings WHERE conversation_id=OLD.id;
 DELETE FROM e2ee_generation_members WHERE conversation_id=OLD.id;
 DELETE FROM e2ee_handshake WHERE conversation_id=OLD.id;
 DELETE FROM e2ee_trees WHERE conversation_id=OLD.id;
 RETURN NULL;
END;
$$;
CREATE TRIGGER directs_e2ee_forget AFTER DELETE ON directs FOR EACH ROW EXECUTE FUNCTION app_e2ee_forget_channel();
