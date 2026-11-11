-- Undoes migrations/0041_send_path_locks.sql. Run as the owner role, in one transaction, then
-- start the previous image. It restores the bodies from 0020, 0021 and 0037 as they were and
-- removes the migration's record, so the previous image's migration check passes.

BEGIN;

CREATE OR REPLACE FUNCTION app_emit_to(p_topic text, p_payload jsonb, p_audience uuid[])
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_id bigint;
BEGIN
    IF p_topic !~ '^[a-z][a-z0-9]*\.[a-z_]+$' THEN
        RAISE EXCEPTION 'invalid topic' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.outbox'));
    INSERT INTO outbox (topic, payload, audience)
    VALUES (p_topic, p_payload, app_scope_audience(p_payload, p_audience))
    RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;

CREATE OR REPLACE FUNCTION app_emit(p_topic text, p_payload jsonb)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_id bigint;
BEGIN
    IF p_topic !~ '^[a-z][a-z0-9]*\.[a-z_]+$' THEN
        RAISE EXCEPTION 'invalid topic' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.outbox'));
    INSERT INTO outbox (topic, payload, audience)
    VALUES (p_topic, p_payload, app_scope_audience(p_payload, NULL))
    RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;

DROP FUNCTION app_outbox_append(text, jsonb, uuid[]);

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
        SELECT d.user_id, d.device_id
        FROM e2ee_devices d
        WHERE d.revoked_at IS NULL
          AND EXISTS (SELECT 1 FROM memberships m WHERE m.user_id = d.user_id)
          AND (app_channel_perms_of(p_conv, d.user_id) & 1) = 1;
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

CREATE OR REPLACE FUNCTION app_e2ee_require_current_audience(p_group uuid)
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

DELETE FROM _sqlx_migrations WHERE version = 41;

COMMIT;
