-- A direct call's history. The ring itself is memory and dies with the process. A row is written
-- only when the call reaches an end: missed, declined, cancelled, or ended. No media, no SDP,
-- no keys. The runtime role has no grant. Row level security is forced with no policy, so a
-- grant added later still shows nothing. The functions below are the only door.

CREATE TABLE direct_call_log (
    id uuid PRIMARY KEY,
    direct_id uuid NOT NULL REFERENCES directs (id) ON DELETE CASCADE,
    caller_id uuid NOT NULL,
    callee_id uuid NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('missed', 'declined', 'cancelled', 'ended')),
    accepted_at timestamptz,
    ended_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX direct_call_log_direct ON direct_call_log (direct_id, ended_at DESC);

ALTER TABLE direct_call_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE direct_call_log FORCE ROW LEVEL SECURITY;

REVOKE ALL ON direct_call_log FROM app_runtime;

-- The two parties of a direct the caller is in, and whether either is timed out. Empty when
-- the id is not a direct, the caller is not a party, either person is banned, or either is
-- no longer a member. A timeout is reported rather than hidden, so the socket can say
-- `timed_out` instead of pretending the conversation is not there.
CREATE FUNCTION app_direct_parties(p_direct uuid, p_user uuid)
RETURNS TABLE (
    low_user_id uuid,
    high_user_id uuid,
    low_timed_out boolean,
    high_timed_out boolean
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT d.low_user_id,
           d.high_user_id,
           coalesce(mlow.timeout_until > now(), false),
           coalesce(mhigh.timeout_until > now(), false)
    FROM directs d
    JOIN memberships mlow ON mlow.user_id = d.low_user_id
    JOIN memberships mhigh ON mhigh.user_id = d.high_user_id
    WHERE d.id = p_direct
      AND p_user IN (d.low_user_id, d.high_user_id)
      AND NOT app_banned(d.low_user_id)
      AND NOT app_banned(d.high_user_id);
$$;

-- Records one finished direct call and tells the two parties. A second write of the same ring
-- does nothing, so a timer and a leave cannot announce it twice.
CREATE FUNCTION app_record_direct_call(
    p_id uuid,
    p_direct uuid,
    p_caller uuid,
    p_callee uuid,
    p_outcome text,
    p_accepted double precision
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    IF p_outcome NOT IN ('missed', 'declined', 'cancelled', 'ended') THEN
        RAISE EXCEPTION 'invalid outcome' USING ERRCODE = '22023';
    END IF;
    IF p_caller = p_callee OR NOT EXISTS (
        SELECT 1 FROM directs d
        WHERE d.id = p_direct
          AND p_caller IN (d.low_user_id, d.high_user_id)
          AND p_callee IN (d.low_user_id, d.high_user_id)
    ) THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    INSERT INTO direct_call_log (id, direct_id, caller_id, callee_id, outcome, accepted_at)
    VALUES (
        p_id,
        p_direct,
        p_caller,
        p_callee,
        p_outcome,
        CASE WHEN p_accepted IS NULL THEN NULL ELSE to_timestamp(p_accepted) END
    )
    ON CONFLICT (id) DO NOTHING;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    PERFORM app_emit_to(
        'direct.call',
        jsonb_build_object(
            'direct_id', p_direct::text,
            'ring_id', p_id::text,
            'caller_id', p_caller::text,
            'callee_id', p_callee::text,
            'outcome', p_outcome,
            'accepted_at', app_stamp(CASE WHEN p_accepted IS NULL THEN NULL ELSE to_timestamp(p_accepted) END),
            'ended_at', app_stamp(now())
        ),
        ARRAY[p_caller, p_callee]
    );
END;
$$;

CREATE OR REPLACE FUNCTION app_direct_json(p_id uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT jsonb_build_object(
        'id', d.id::text,
        'created_at', app_stamp(d.created_at),
        'e2ee', d.e2ee,
        'plaintext_history', d.e2ee AND app_e2ee_has_plaintext(d.id),
        'peer', jsonb_build_object(
            'user_id', peer.id::text,
            'display_name', peer.display_name
        ),
        'unread', app_unread('direct', d.id),
        'last_read', (
            SELECT r.message_id::text FROM reads r
            WHERE r.user_id = app_uid() AND r.kind = 'direct' AND r.conversation_id = d.id
        ),
        'peer_read', (
            SELECT r.message_id::text FROM reads r
            WHERE r.user_id = CASE WHEN d.low_user_id = app_uid() THEN d.high_user_id ELSE d.low_user_id END
              AND r.kind = 'direct' AND r.conversation_id = d.id
        ),
        'last_message', app_last_message(NULL, d.id),
        'last_call', (
            SELECT jsonb_build_object(
                'id', c.id::text,
                'outcome', c.outcome,
                'caller_id', c.caller_id::text,
                'accepted_at', app_stamp(c.accepted_at),
                'ended_at', app_stamp(c.ended_at)
            )
            FROM direct_call_log c
            WHERE c.direct_id = d.id
            ORDER BY c.ended_at DESC, c.id DESC
            LIMIT 1
        )
    )
    FROM directs d
    JOIN users peer ON peer.id = CASE
        WHEN d.low_user_id = app_uid() THEN d.high_user_id ELSE d.low_user_id END
    WHERE d.id = p_id AND app_uid() IN (d.low_user_id, d.high_user_id);
$$;

GRANT EXECUTE ON FUNCTION app_direct_parties(uuid, uuid) TO app_runtime;
GRANT EXECUTE ON FUNCTION app_record_direct_call(uuid, uuid, uuid, uuid, text, double precision) TO app_runtime;
