-- Group call history and call access checks (issue #63).
--
-- Mirrors `0040_direct_calls.sql`: the live call and its rings live in memory and die with the
-- process. Rows are written only when a call ends (`ended`, `missed`, or `cancelled`). No media,
-- no SDP, no keys, and no display names are stored. Both tables have forced RLS with no policies
-- and no runtime grant; the SECURITY DEFINER functions below are the only door.
--
-- Rollback: crates/db/rollback/0060_group_calls.down.sql.

CREATE TABLE group_call_log (
    id uuid PRIMARY KEY,
    group_id uuid NOT NULL REFERENCES group_dms (id) ON DELETE CASCADE,
    started_by uuid NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('ended', 'missed', 'cancelled')),
    started_at timestamptz NOT NULL,
    ended_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX group_call_log_group ON group_call_log (group_id, ended_at DESC, id DESC);

CREATE TABLE group_call_log_people (
    call_id uuid NOT NULL REFERENCES group_call_log (id) ON DELETE CASCADE,
    user_id uuid NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('joined', 'declined', 'missed', 'busy', 'not_rung')),
    PRIMARY KEY (call_id, user_id)
);

ALTER TABLE group_call_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_call_log FORCE ROW LEVEL SECURITY;
REVOKE ALL ON group_call_log FROM PUBLIC, app_runtime;

ALTER TABLE group_call_log_people ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_call_log_people FORCE ROW LEVEL SECURITY;
REVOKE ALL ON group_call_log_people FROM PUBLIC, app_runtime;

-- Current unbanned members of `p_group` (in join order) and whether each is timed out, only when
-- `p_user` is itself a current unbanned member of `p_group`. Empty otherwise, so the socket maps
-- an absent or inaccessible group to `not_found` and a timed-out caller to `timed_out`.
CREATE FUNCTION app_group_call_access(p_group uuid, p_user uuid)
RETURNS TABLE (
    user_id uuid,
    timed_out boolean
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT gm.user_id,
           coalesce(m.timeout_until > now(), false)
    FROM group_dm_members gm
    JOIN memberships m ON m.user_id = gm.user_id
    WHERE gm.group_dm_id = p_group
      AND NOT app_banned(gm.user_id)
      AND EXISTS (
          SELECT 1
          FROM group_dm_members self_gm
          JOIN memberships self_m ON self_m.user_id = self_gm.user_id
          WHERE self_gm.group_dm_id = p_group
            AND self_gm.user_id = p_user
            AND NOT app_banned(p_user)
      )
    ORDER BY gm.joined_at, gm.seq;
$$;

REVOKE EXECUTE ON FUNCTION app_group_call_access(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_group_call_access(uuid, uuid) TO app_runtime;

-- Records one finished group call once (`ON CONFLICT DO NOTHING`) and emits one durable
-- `group.call` event to the group's current members. If the group was deleted before the write
-- landed, returns quietly.
CREATE FUNCTION app_record_group_call(
    p_id uuid,
    p_group uuid,
    p_started_by uuid,
    p_outcome text,
    p_started_at double precision,
    p_people uuid[],
    p_people_outcomes text[]
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_started timestamptz;
    v_ended timestamptz;
    v_joined jsonb;
    v_outcomes jsonb;
BEGIN
    IF p_outcome NOT IN ('ended', 'missed', 'cancelled') THEN
        RAISE EXCEPTION 'invalid outcome' USING ERRCODE = '22023';
    END IF;
    IF coalesce(cardinality(p_people), 0) <> coalesce(cardinality(p_people_outcomes), 0) THEN
        RAISE EXCEPTION 'invalid people outcomes' USING ERRCODE = '22023';
    END IF;
    PERFORM 1 FROM group_dms WHERE id = p_group FOR KEY SHARE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    v_started := to_timestamp(p_started_at);
    v_ended := now();

    INSERT INTO group_call_log (id, group_id, started_by, outcome, started_at, ended_at)
    VALUES (p_id, p_group, p_started_by, p_outcome, v_started, v_ended)
    ON CONFLICT (id) DO NOTHING;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    INSERT INTO group_call_log_people (call_id, user_id, outcome)
    SELECT p_id, u.uid, u.out
    FROM unnest(
        coalesce(p_people, '{}'::uuid[]),
        coalesce(p_people_outcomes, '{}'::text[])
    ) AS u(uid, out)
    WHERE u.uid IS NOT NULL
    ON CONFLICT (call_id, user_id) DO NOTHING;

    SELECT coalesce(jsonb_agg(p.user_id::text ORDER BY p.user_id), '[]'::jsonb)
    INTO v_joined
    FROM group_call_log_people p
    WHERE p.call_id = p_id AND p.outcome = 'joined';

    SELECT coalesce(jsonb_object_agg(p.user_id::text, p.outcome), '{}'::jsonb)
    INTO v_outcomes
    FROM group_call_log_people p
    WHERE p.call_id = p_id;

    PERFORM app_emit_to(
        'group.call',
        jsonb_build_object(
            'group_id', p_group::text,
            'call_id', p_id::text,
            'started_by', p_started_by::text,
            'outcome', p_outcome,
            'started_at', app_stamp(v_started),
            'ended_at', app_stamp(v_ended),
            'joined', v_joined,
            'outcomes', v_outcomes
        ),
        app_group_audience(p_group, NULL)
    );
END;
$$;

REVOKE EXECUTE ON FUNCTION app_record_group_call(uuid, uuid, uuid, text, double precision, uuid[], text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_record_group_call(uuid, uuid, uuid, text, double precision, uuid[], text[]) TO app_runtime;

-- Extend `app_group_json` with `last_call`, mirroring `app_direct_json` in `0040_direct_calls.sql`.
CREATE OR REPLACE FUNCTION app_group_json(p_id uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
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
        'last_message', app_last_message(NULL, NULL, g.id),
        'last_call', (
            SELECT jsonb_build_object(
                'id', c.id::text,
                'call_id', c.id::text,
                'started_by', c.started_by::text,
                'outcome', c.outcome,
                'started_at', app_stamp(c.started_at),
                'ended_at', app_stamp(c.ended_at),
                'joined', coalesce((
                    SELECT jsonb_agg(p.user_id::text ORDER BY p.user_id)
                    FROM group_call_log_people p
                    WHERE p.call_id = c.id AND p.outcome = 'joined'
                ), '[]'::jsonb),
                'mine', (
                    SELECT p.outcome
                    FROM group_call_log_people p
                    WHERE p.call_id = c.id AND p.user_id = app_uid()
                )
            )
            FROM group_call_log c
            WHERE c.group_id = g.id
            ORDER BY c.ended_at DESC, c.id DESC
            LIMIT 1
        )
    )
    FROM group_dms g
    WHERE g.id = p_id
      AND EXISTS (
          SELECT 1 FROM group_dm_members gm
          WHERE gm.group_dm_id = g.id AND gm.user_id = app_uid()
      );
$$;

REVOKE EXECUTE ON FUNCTION app_group_json(uuid) FROM PUBLIC, app_runtime;
