-- Live events. Every room, member, invite, and session change writes one outbox row in the
-- transaction that made it, through app_emit. The row id is the event seq that /v1/live sends.
--
-- app_emit takes one transaction lock before it inserts, so ids are handed out in commit order:
-- a reader that has seen id N has seen every committed id below N. The lock is held from the
-- emit to the commit, which is the end of each write.

CREATE OR REPLACE FUNCTION app_emit(p_topic text, p_payload jsonb)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_id bigint;
BEGIN
    IF p_topic !~ '^[a-z]+\.[a-z_]+$' THEN
        RAISE EXCEPTION 'invalid topic' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.outbox'));
    INSERT INTO outbox (topic, payload) VALUES (p_topic, p_payload) RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION app_emit(text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_emit(text, jsonb) TO app_runtime;

-- The runtime reads the outbox and writes it only through app_emit and app_sweep.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON outbox FROM app_runtime;
GRANT SELECT ON outbox TO app_runtime;

-- The highest seq the sweep has deleted. A client resuming from below it gets resync.
CREATE TABLE outbox_pruned (
    only_row boolean PRIMARY KEY DEFAULT true CHECK (only_row),
    through bigint NOT NULL
);

INSERT INTO outbox_pruned (through) VALUES (0);

REVOKE ALL ON outbox_pruned FROM app_runtime;
GRANT SELECT ON outbox_pruned TO app_runtime;

-- Accepting an invite now emits member.joined to everyone and invite.accepted to managers.
-- The invite row is behind RLS for the person accepting, so the definer builds both payloads.

CREATE OR REPLACE FUNCTION app_accept_invite(p_token_hash bytea, p_user_id uuid)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_invite invites%ROWTYPE;
    v_name text;
    v_stamp constant text := 'YYYY-MM-DD"T"HH24:MI:SS"Z"';
BEGIN
    IF EXISTS (SELECT 1 FROM memberships WHERE user_id = p_user_id) THEN
        RAISE EXCEPTION 'already a member' USING ERRCODE = '23505';
    END IF;

    SELECT * INTO v_invite
    FROM invites
    WHERE token_hash = p_token_hash
      AND accepted_at IS NULL
      AND expires_at > now()
    FOR UPDATE;
    IF v_invite.id IS NULL THEN
        RAISE EXCEPTION 'invite not found' USING ERRCODE = 'P0002';
    END IF;

    INSERT INTO memberships (user_id, role) VALUES (p_user_id, v_invite.role);
    UPDATE invites
    SET accepted_at = now(), accepted_by = p_user_id
    WHERE id = v_invite.id
    RETURNING * INTO v_invite;
    INSERT INTO audit_log (actor_id, action, subject, detail)
    VALUES (p_user_id, 'invite.accept', 'membership', jsonb_build_object('role', v_invite.role));

    SELECT display_name INTO v_name FROM users WHERE id = p_user_id;
    PERFORM app_emit('invite.accepted', jsonb_build_object('invite', jsonb_build_object(
        'id', v_invite.id,
        'role', v_invite.role,
        'created_by', v_invite.created_by,
        'expires_at', to_char(v_invite.expires_at AT TIME ZONE 'UTC', v_stamp),
        'accepted_at', to_char(v_invite.accepted_at AT TIME ZONE 'UTC', v_stamp),
        'accepted_by', v_invite.accepted_by
    )));
    PERFORM app_emit('member.joined', jsonb_build_object('member', jsonb_build_object(
        'user_id', p_user_id,
        'display_name', v_name,
        'role', v_invite.role
    )));
    RETURN v_invite.role;
END;
$$;

-- The sweep now also deletes outbox rows older than 24 hours. It deletes every id up to the
-- newest old row, so the kept rows are one unbroken run and outbox_pruned is exact.

DROP FUNCTION app_sweep();

CREATE FUNCTION app_sweep(
    OUT expired_sessions bigint,
    OUT expired_invites bigint,
    OUT expired_keys bigint,
    OUT expired_events bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_through bigint;
BEGIN
    DELETE FROM sessions WHERE expires_at <= now();
    GET DIAGNOSTICS expired_sessions = ROW_COUNT;
    DELETE FROM invites WHERE accepted_at IS NULL AND expires_at <= now();
    GET DIAGNOSTICS expired_invites = ROW_COUNT;
    DELETE FROM idempotency_keys WHERE expires_at <= now();
    GET DIAGNOSTICS expired_keys = ROW_COUNT;

    expired_events := 0;
    SELECT max(id) INTO v_through FROM outbox WHERE created_at <= now() - interval '24 hours';
    IF v_through IS NOT NULL THEN
        DELETE FROM outbox WHERE id <= v_through;
        GET DIAGNOSTICS expired_events = ROW_COUNT;
        UPDATE outbox_pruned SET through = greatest(through, v_through);
    END IF;
END;
$$;

REVOKE EXECUTE ON FUNCTION app_sweep() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_sweep() TO app_runtime;
