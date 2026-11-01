-- The operator's switches for the whole community: suspend it read-only or offline with a
-- notice members see, and a legal hold that stops the community from being deleted and stops
-- resolved reports from expiring.
--
-- Only the owner role writes these, through `tinyserver operator`. That role's password is in
-- the init container and nowhere else, so nothing a member or a moderator can reach through the
-- serving process can lift a suspension or a hold. The serving process reads the state to obey
-- it, and nothing more.

CREATE TABLE operator_state (
    -- One row. A second one cannot be inserted.
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    mode text NOT NULL DEFAULT 'normal' CHECK (mode IN ('normal', 'read_only', 'offline')),
    -- What members see while suspended. Never a reason for a legal hold.
    notice text CHECK (char_length(notice) BETWEEN 1 AND 500),
    since timestamptz NOT NULL DEFAULT now(),
    legal_hold boolean NOT NULL DEFAULT false,
    legal_hold_since timestamptz,
    CHECK (mode <> 'normal' OR notice IS NULL),
    CHECK (legal_hold = (legal_hold_since IS NOT NULL))
);

INSERT INTO operator_state DEFAULT VALUES;

-- Every change, for the operator's own record. The reason for a hold is kept here, never in the
-- row the serving process reads.
CREATE TABLE operator_events (
    id bigserial PRIMARY KEY,
    at timestamptz NOT NULL DEFAULT now(),
    action text NOT NULL CHECK (action IN ('suspend', 'resume', 'hold', 'release')),
    mode text CHECK (mode IN ('normal', 'read_only', 'offline')),
    reason text CHECK (char_length(reason) <= 500)
);

REVOKE ALL ON operator_state FROM app_runtime;
GRANT SELECT ON operator_state TO app_runtime;
REVOKE ALL ON operator_events FROM app_runtime;
REVOKE ALL ON SEQUENCE operator_events_id_seq FROM app_runtime;

-- A legal hold keeps resolved reports too. Same function as 0015 with the hold checked first.
CREATE OR REPLACE FUNCTION app_reports_sweep(p_days integer)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_deleted bigint;
BEGIN
    IF p_days IS NULL OR p_days < 7 OR p_days > 3650 THEN
        RAISE EXCEPTION 'retention out of range' USING ERRCODE = '22023';
    END IF;
    IF EXISTS (SELECT 1 FROM operator_state WHERE legal_hold) THEN
        RETURN 0;
    END IF;
    DELETE FROM reports
    WHERE NOT preserve
      AND status IN ('actioned', 'dismissed')
      AND resolved_at <= now() - make_interval(days => p_days);
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    IF v_deleted > 0 THEN
        INSERT INTO audit_log (actor_id, action, subject, detail)
        VALUES (NULL, 'report.expire', 'report',
                jsonb_build_object('count', v_deleted, 'retention_days', p_days));
    END IF;
    RETURN v_deleted;
END;
$$;
