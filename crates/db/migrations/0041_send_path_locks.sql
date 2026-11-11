-- Shorter lock holds on the send path. No table, column, topic, payload or API changes.
--
-- 1. The outbox lock. app_emit and app_emit_to take one transaction advisory lock before they
--    insert, so outbox ids are handed out in commit order: a reader that has seen id N has seen
--    every committed id below N, which is what lets the live dispatcher keep a single cursor.
--    The lock is held from the emit to COMMIT. Until now the audience of an event (for a
--    channel: its viewers, one permission lookup per member when the channel is restricted) was
--    worked out after the lock was taken, so every other write in the community waited for it.
--    It is now worked out first, and only the id assignment and the insert are under the lock.
--
--    The lock also made the audience fresh: an emit that waited behind a permission change
--    computed its audience after that change had committed. That is kept. Once the lock is
--    held, the audience is worked out again, under the lock, if the outbox gained a committed
--    row since the audience was first read whose topic is not a plain message or reaction
--    event. Every role, override, membership and channel change emits such a row, in the
--    transaction that made the change, and a transaction that held the lock before this one
--    has committed by the time this one has it. A message that races a message sees no such
--    row and keeps the audience it already has.
--    An explicit audience (a direct, a user's own events, the encrypted topics) is never
--    recomputed: the caller has already built it, before the call, as before.
--
-- 2. The encrypted group barrier. app_e2ee_require_current_audience, run on every encrypted
--    send under the group's advisory lock, called app_e2ee_desired three times. It now calls it
--    once and compares the devices it returned against the group's leaves in both directions,
--    as before, so a removed member's device is still refused ('proposals changed') and so is a
--    device that should be in the group and is not. app_e2ee_desired itself looks a person's
--    permissions up once per person that has a device, not once per device.

CREATE FUNCTION app_outbox_append(p_topic text, p_payload jsonb, p_audience uuid[])
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
        -- Read before the audience, so a change that commits after this is seen below.
        SELECT coalesce(max(o.id), 0) INTO v_seen FROM outbox o;
        v_audience := app_scope_audience(p_payload, NULL);
    END IF;
    PERFORM pg_advisory_xact_lock(c_key);
    IF v_scoped THEN
        -- A new statement, so a transaction that held the lock and has since committed is seen.
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

REVOKE EXECUTE ON FUNCTION app_outbox_append(text, jsonb, uuid[]) FROM PUBLIC, app_runtime;

CREATE OR REPLACE FUNCTION app_emit_to(p_topic text, p_payload jsonb, p_audience uuid[])
RETURNS bigint
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT app_outbox_append(p_topic, p_payload, p_audience);
$$;

CREATE OR REPLACE FUNCTION app_emit(p_topic text, p_payload jsonb)
RETURNS bigint
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT app_outbox_append(p_topic, p_payload, NULL);
$$;

-- The devices that should be in the group: every active device of every person who can view
-- the conversation now. Same rows as before; the permission lookup runs once per person.
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

-- A new ciphertext must be decryptable by the current intended audience, and by no
-- removed leaf. Call only while holding reconciliation's transaction advisory lock.
CREATE OR REPLACE FUNCTION app_e2ee_require_current_audience(p_group uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_want uuid[];
BEGIN
    SELECT coalesce(array_agg(d.d_device), '{}'::uuid[]) INTO v_want
    FROM app_e2ee_desired(p_group) d;
    IF cardinality(v_want) > app_e2ee_group_devices_max() THEN
        RAISE EXCEPTION 'group too large' USING ERRCODE = 'P0E16';
    END IF;
    IF EXISTS (
        (SELECT w.device FROM unnest(v_want) AS w(device)
         EXCEPT SELECT l.device_id FROM e2ee_leaves l WHERE l.conversation_id = p_group)
        UNION ALL
        (SELECT l.device_id FROM e2ee_leaves l WHERE l.conversation_id = p_group
         EXCEPT SELECT w.device FROM unnest(v_want) AS w(device))
    ) THEN
        RAISE EXCEPTION 'proposals changed' USING ERRCODE = 'P0E04';
    END IF;
END;
$$;

-- Rollback: crates/db/rollback/0041_send_path_locks.down.sql puts the previous bodies back and
-- removes this migration's record. Nothing here changes data.
