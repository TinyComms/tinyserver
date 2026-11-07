-- Initial audiences may require several bounded Add commits. An epoch greater
-- than zero does not mean the initial audience is ready. Keep initial additions
-- urgent until the canonical group accepts its first application ciphertext.
-- Existing groups are conservatively established: retention may have erased all
-- evidence of earlier ciphertext. New groups start unestablished, independently
-- of epochs; neither retention nor creation of shared aliases can reset the bit.
ALTER TABLE e2ee_groups
    ADD COLUMN audience_established boolean NOT NULL DEFAULT true;
ALTER TABLE e2ee_groups ALTER COLUMN audience_established SET DEFAULT false;

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

-- The post functions already hold the canonical group's advisory lock and check
-- its exact audience. AFTER INSERT makes this transition part of the same write:
-- rejected posts and rolled-back transactions cannot establish an audience.
CREATE FUNCTION app_e2ee_establish_audience()
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

REVOKE EXECUTE ON FUNCTION app_e2ee_establish_audience() FROM PUBLIC, app_runtime;

CREATE TRIGGER messages_establish_e2ee_audience
    AFTER INSERT ON messages
    FOR EACH ROW WHEN (NEW.e2ee)
    EXECUTE FUNCTION app_e2ee_establish_audience();

CREATE TRIGGER reactions_establish_e2ee_audience
    AFTER INSERT ON e2ee_reaction_blobs
    FOR EACH ROW EXECUTE FUNCTION app_e2ee_establish_audience();
