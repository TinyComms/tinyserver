-- In-community abuse reports, and the permission that lets moderators work them.
--
-- What this is, and what it is not. A member can report a message, a member or a channel. A
-- report holds what the reporter chose to write, and, when the reporter chooses to send it,
-- evidence: text the reporter's own client disclosed. The server cannot check that evidence is
-- genuine (it may be a message nobody sent, in a conversation the server cannot read at all),
-- so every report that carries evidence is stored with `evidence_unverified = true` and the API
-- says so. Nothing here reads, copies or decrypts a conversation: a report about a message
-- stores the message's id, where it was posted and who posted it, and never its body.
--
-- Who sees a report. Only people with the new `manage_reports` permission, and never the person
-- the report is about: a moderator who is the subject of a report cannot list it, read it, or
-- see its audit rows, and asking for it by id answers "not found". The reported member never
-- sees a report about them at all. A moderator does see who reported, because a moderator has
-- to be able to deal with a reporter who is abusing the report button.
--
-- Permission bit 20, `manage_reports`, is 1 << 20 = 1048576. All bits are now 2097151. It is
-- NOT part of @everyone (63) or of the room override mask (246399). Existing roles: every owner
-- has it through the owner flag, as owners have every bit; every role other than @everyone that
-- already held manage_server (524288) gets it, which includes the "Admin" role every server
-- upgraded from the three fixed roles has. @everyone is excluded on purpose even when someone
-- gave it manage_server: that would hand every member everyone's reports.
--
-- Writes. `app_runtime` can read `reports` and `report_notes` through row level security and
-- cannot write them. Creating, triaging, annotating, linking, preserving and expiring all go
-- through the SECURITY DEFINER functions below, which check permission and write the audit row.
-- Audit rows for reports carry the report id and kind, never report text. They are invisible to
-- anyone without manage_reports, and the row written when a report is filed has no actor.

-- 1. The permission bit.

ALTER TABLE roles DROP CONSTRAINT roles_permissions_check;
ALTER TABLE roles
    ADD CONSTRAINT roles_permissions_check
    CHECK (permissions >= 0 AND permissions <= 2097151);

UPDATE roles SET permissions = permissions | 1048576
WHERE NOT is_default AND permissions & 524288 <> 0;

-- Owners hold every bit. These three functions spelled "every bit" as 1048575.

CREATE OR REPLACE FUNCTION app_perms_of(p_user uuid)
RETURNS bigint
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT CASE
        WHEN m.user_id IS NULL THEN 0::bigint
        WHEN m.owner THEN 2097151::bigint
        ELSE coalesce((SELECT permissions FROM roles WHERE is_default), 0)
             | coalesce((SELECT bit_or(r.permissions)
                         FROM member_roles mr JOIN roles r ON r.id = mr.role_id
                         WHERE mr.user_id = p_user), 0)
    END
    FROM (SELECT p_user AS u) x
    LEFT JOIN memberships m ON m.user_id = x.u;
$$;

CREATE OR REPLACE FUNCTION app_room_perms_of(p_room uuid, p_user uuid)
RETURNS bigint
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_owner boolean;
    v_perms bigint;
    v_allow bigint;
    v_deny bigint;
BEGIN
    SELECT owner INTO v_owner FROM memberships WHERE user_id = p_user;
    IF v_owner IS NULL THEN
        RETURN 0;
    END IF;
    IF v_owner THEN
        RETURN 2097151;
    END IF;
    v_perms := app_perms_of(p_user);
    SELECT o.allow, o.deny INTO v_allow, v_deny
    FROM room_overrides o JOIN roles r ON r.id = o.role_id
    WHERE o.room_id = p_room AND r.is_default;
    IF FOUND THEN
        v_perms := (v_perms & ~v_deny) | v_allow;
    END IF;
    SELECT coalesce(bit_or(o.allow), 0), coalesce(bit_or(o.deny), 0) INTO v_allow, v_deny
    FROM room_overrides o JOIN member_roles mr ON mr.role_id = o.role_id
    WHERE o.room_id = p_room AND mr.user_id = p_user;
    RETURN (v_perms & ~v_deny) | v_allow;
END;
$$;

CREATE OR REPLACE FUNCTION app_channel_perms_of(p_channel uuid, p_user uuid)
RETURNS bigint
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_owner boolean;
    v_perms bigint;
    v_allow bigint;
    v_deny bigint;
BEGIN
    SELECT owner INTO v_owner FROM memberships WHERE user_id = p_user;
    IF v_owner IS NULL THEN
        RETURN 0;
    END IF;
    IF v_owner THEN
        RETURN 2097151;
    END IF;
    v_perms := app_perms_of(p_user);
    SELECT o.allow, o.deny INTO v_allow, v_deny
    FROM channel_overrides o JOIN roles r ON r.id = o.role_id
    WHERE o.channel_id = p_channel AND r.is_default;
    IF FOUND THEN
        v_perms := (v_perms & ~v_deny) | v_allow;
    END IF;
    SELECT coalesce(bit_or(o.allow), 0), coalesce(bit_or(o.deny), 0) INTO v_allow, v_deny
    FROM channel_overrides o JOIN member_roles mr ON mr.role_id = o.role_id
    WHERE o.channel_id = p_channel AND mr.user_id = p_user;
    RETURN (v_perms & ~v_deny) | v_allow;
END;
$$;

-- 2. Tables.

CREATE TABLE reports (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind text NOT NULL CHECK (kind IN ('message', 'member', 'channel')),
    category text NOT NULL CHECK (category IN (
        'spam', 'harassment', 'hate', 'violence', 'sexual', 'illegal', 'impersonation', 'other'
    )),
    -- NULL once the reporter deletes their account.
    reporter_id uuid REFERENCES users (id) ON DELETE SET NULL,
    -- The member reported, or the author of the message reported. NULL for a channel.
    reported_user_id uuid REFERENCES users (id) ON DELETE SET NULL,
    -- Where it was. Ids only, never content. These go NULL if the message or channel is deleted.
    message_id uuid REFERENCES messages (id) ON DELETE SET NULL,
    channel_id uuid REFERENCES channels (id) ON DELETE SET NULL,
    direct_id uuid REFERENCES directs (id) ON DELETE SET NULL,
    -- What the reporter wrote, and what the reporter's client chose to disclose.
    note text CHECK (char_length(note) <= 2000),
    evidence text CHECK (octet_length(evidence) <= 32768),
    -- The server cannot verify evidence. A report with evidence is always stored with this set.
    evidence_unverified boolean NOT NULL DEFAULT true,
    status text NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'reviewing', 'actioned', 'dismissed')),
    -- Legal hold. Only an owner sets or clears it. Suspends deletion and survives account
    -- deletion.
    preserve boolean NOT NULL DEFAULT false,
    preserved_by uuid REFERENCES users (id) ON DELETE SET NULL,
    preserved_at timestamptz,
    -- audit_log ids of the kick, ban or timeout this report led to.
    linked_audit_ids bigint[] NOT NULL DEFAULT '{}'
        CHECK (cardinality(linked_audit_ids) <= 20),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    -- When the report became actioned or dismissed; retention counts from here.
    resolved_at timestamptz,
    CHECK (evidence IS NULL OR evidence_unverified),
    CHECK (preserve = (preserved_at IS NOT NULL)),
    CHECK ((status IN ('actioned', 'dismissed')) = (resolved_at IS NOT NULL))
);

CREATE INDEX reports_queue ON reports (created_at DESC, id DESC);
CREATE INDEX reports_status ON reports (status, created_at DESC);
CREATE INDEX reports_reporter ON reports (reporter_id, created_at) WHERE reporter_id IS NOT NULL;
CREATE INDEX reports_reported ON reports (reported_user_id) WHERE reported_user_id IS NOT NULL;
CREATE INDEX reports_expiry ON reports (resolved_at)
    WHERE resolved_at IS NOT NULL AND NOT preserve;

CREATE TABLE report_notes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id uuid NOT NULL REFERENCES reports (id) ON DELETE CASCADE,
    author_id uuid REFERENCES users (id) ON DELETE SET NULL,
    body text NOT NULL CHECK (char_length(body) BETWEEN 1 AND 2000),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX report_notes_report ON report_notes (report_id, created_at, id);

-- 3. Row level security: read only, and never your own.

ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports FORCE ROW LEVEL SECURITY;
CREATE POLICY reports_select ON reports
    FOR SELECT
    USING (app_has(1048576) AND reported_user_id IS DISTINCT FROM app_uid());

ALTER TABLE report_notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE report_notes FORCE ROW LEVEL SECURITY;
-- The subquery runs under the policy above, so a note is as visible as its report.
CREATE POLICY report_notes_select ON report_notes
    FOR SELECT
    USING (EXISTS (SELECT 1 FROM reports r WHERE r.id = report_id));

-- Default privileges give the runtime role every verb on a new table. It gets one.
REVOKE ALL ON reports, report_notes FROM app_runtime;
GRANT SELECT ON reports, report_notes TO app_runtime;

-- Audit rows about reports are for moderators only, and not for the person reported. A row
-- about a report names that person as its subject, so the person it is about is shut out here.
DROP POLICY audit_select ON audit_log;
CREATE POLICY audit_select ON audit_log
    FOR SELECT
    USING (
        app_has(262144)
        AND (action NOT LIKE 'report.%'
             OR (app_has(1048576) AND subject_user_id IS DISTINCT FROM app_uid()))
    );

-- 4. Filing a report. Any member who is not banned; a timeout does not stop it. Returns what
-- the reporter may see, which is none of the people involved.
--
-- Limits, enforced here so they hold across restarts and across server instances: 10 reports
-- an hour and 50 a day per reporter. Reporting the same thing twice while the first is still
-- open returns the first and counts for nothing.

CREATE FUNCTION app_report_create(
    p_kind text,
    p_target uuid,
    p_category text,
    p_note text,
    p_evidence text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_me uuid := app_uid();
    v_note text := nullif(btrim(p_note), '');
    v_evidence text := nullif(p_evidence, '');
    v_reported uuid;
    v_message uuid;
    v_channel uuid;
    v_direct uuid;
    v_msg_channel uuid;
    v_msg_direct uuid;
    v_existing reports%ROWTYPE;
    v_row reports%ROWTYPE;
BEGIN
    PERFORM app_msg_gate();
    IF p_kind IS NULL OR p_kind NOT IN ('message', 'member', 'channel')
       OR p_target IS NULL
       OR p_category IS NULL
       OR p_category NOT IN ('spam', 'harassment', 'hate', 'violence', 'sexual', 'illegal',
                             'impersonation', 'other')
       OR (v_note IS NOT NULL AND char_length(v_note) > 2000)
       OR (v_evidence IS NOT NULL AND octet_length(v_evidence) > 32768)
    THEN
        RAISE EXCEPTION 'invalid report' USING ERRCODE = '22023';
    END IF;

    IF p_kind = 'member' THEN
        IF p_target = v_me THEN
            RAISE EXCEPTION 'cannot report yourself' USING ERRCODE = '22023';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM memberships WHERE user_id = p_target) THEN
            RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
        END IF;
        v_reported := p_target;
    ELSIF p_kind = 'channel' THEN
        IF NOT EXISTS (SELECT 1 FROM channels WHERE id = p_target)
           OR NOT app_channel_has(p_target, 1) THEN
            RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
        END IF;
        v_channel := p_target;
    ELSE
        SELECT m.channel_id, m.direct_id, m.author_id
        INTO v_msg_channel, v_msg_direct, v_reported
        FROM messages m WHERE m.id = p_target;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
        END IF;
        -- Only someone who can already read the message can report it, so a report is not a
        -- way to learn that a message exists.
        IF v_msg_channel IS NOT NULL THEN
            IF NOT app_channel_has(v_msg_channel, 1) THEN
                RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
            END IF;
        ELSIF NOT EXISTS (
            SELECT 1 FROM directs d
            WHERE d.id = v_msg_direct AND v_me IN (d.low_user_id, d.high_user_id)
        ) THEN
            RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
        END IF;
        IF v_reported = v_me THEN
            RAISE EXCEPTION 'cannot report yourself' USING ERRCODE = '22023';
        END IF;
        v_message := p_target;
        v_channel := v_msg_channel;
        v_direct := v_msg_direct;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.reports.' || v_me::text));

    SELECT * INTO v_existing
    FROM reports r
    WHERE r.reporter_id = v_me
      AND r.kind = p_kind
      AND r.status IN ('open', 'reviewing')
      AND ((p_kind = 'message' AND r.message_id = p_target)
           OR (p_kind = 'member' AND r.reported_user_id = p_target)
           OR (p_kind = 'channel' AND r.channel_id = p_target))
    ORDER BY r.created_at
    LIMIT 1;
    IF FOUND THEN
        RETURN jsonb_build_object(
            'id', v_existing.id, 'kind', v_existing.kind, 'category', v_existing.category,
            'status', v_existing.status, 'created_at', app_stamp(v_existing.created_at),
            'evidence_unverified', v_existing.evidence IS NOT NULL, 'duplicate', true);
    END IF;

    IF (SELECT count(*) FROM reports
        WHERE reporter_id = v_me AND created_at > now() - interval '1 hour') >= 10
       OR (SELECT count(*) FROM reports
           WHERE reporter_id = v_me AND created_at > now() - interval '1 day') >= 50
    THEN
        RAISE EXCEPTION 'rate limited' USING ERRCODE = 'TC429';
    END IF;

    INSERT INTO reports (kind, category, reporter_id, reported_user_id, message_id, channel_id,
                         direct_id, note, evidence, evidence_unverified)
    VALUES (p_kind, p_category, v_me, v_reported, v_message, v_channel, v_direct,
            v_note, v_evidence, true)
    RETURNING * INTO v_row;

    -- No actor: the audit log does not say who reported. The subject is the person reported, so
    -- the policy can keep this row from them.
    INSERT INTO audit_log (actor_id, action, subject, detail, subject_user_id)
    VALUES (NULL, 'report.create', 'report',
            jsonb_build_object('report_id', v_row.id, 'kind', v_row.kind,
                               'category', v_row.category),
            v_reported);

    RETURN jsonb_build_object(
        'id', v_row.id, 'kind', v_row.kind, 'category', v_row.category,
        'status', v_row.status, 'created_at', app_stamp(v_row.created_at),
        'evidence_unverified', v_row.evidence IS NOT NULL, 'duplicate', false);
END;
$$;

-- 5. Working a report: triage, annotate, link an enforcement action, hold. Any of the four,
-- together or alone, in one transaction; each change writes its own audit row.

CREATE FUNCTION app_report_update(
    p_id uuid,
    p_status text,
    p_note text,
    p_link_audit bigint,
    p_preserve boolean
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_me uuid := app_uid();
    v_report reports%ROWTYPE;
    v_note text := nullif(btrim(p_note), '');
    v_note_id uuid;
    v_action text;
    v_subject uuid;
BEGIN
    PERFORM app_require(1048576);
    SELECT * INTO v_report FROM reports WHERE id = p_id FOR UPDATE;
    -- A report about the caller does not exist as far as the caller can tell.
    IF NOT FOUND OR v_report.reported_user_id = v_me THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    IF p_status IS NULL AND v_note IS NULL AND p_link_audit IS NULL AND p_preserve IS NULL THEN
        RAISE EXCEPTION 'nothing to change' USING ERRCODE = '22023';
    END IF;
    IF p_status IS NOT NULL AND p_status NOT IN ('open', 'reviewing', 'actioned', 'dismissed') THEN
        RAISE EXCEPTION 'invalid status' USING ERRCODE = '22023';
    END IF;
    IF v_note IS NOT NULL AND char_length(v_note) > 2000 THEN
        RAISE EXCEPTION 'note too long' USING ERRCODE = '22023';
    END IF;
    -- Only an owner may set or clear a legal hold. Checked before anything is written.
    IF p_preserve IS NOT NULL AND p_preserve <> v_report.preserve AND NOT app_owner_of(v_me) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;

    IF p_status IS NOT NULL AND p_status <> v_report.status THEN
        UPDATE reports
        SET status = p_status,
            resolved_at = CASE WHEN p_status IN ('actioned', 'dismissed') THEN now() END
        WHERE id = p_id;
        PERFORM app_audit('report.triage', 'report',
                          jsonb_build_object('report_id', p_id, 'from', v_report.status,
                                             'to', p_status),
                          v_report.reported_user_id, NULL);
    END IF;

    IF v_note IS NOT NULL THEN
        INSERT INTO report_notes (report_id, author_id, body)
        VALUES (p_id, v_me, v_note)
        RETURNING id INTO v_note_id;
        PERFORM app_audit('report.annotate', 'report',
                          jsonb_build_object('report_id', p_id, 'note_id', v_note_id),
                          v_report.reported_user_id, NULL);
    END IF;

    IF p_link_audit IS NOT NULL THEN
        SELECT a.action, a.subject_user_id INTO v_action, v_subject
        FROM audit_log a WHERE a.id = p_link_audit;
        IF NOT FOUND OR v_action NOT IN ('member.remove', 'member.ban', 'member.timeout') THEN
            RAISE EXCEPTION 'not an enforcement action' USING ERRCODE = '22023';
        END IF;
        -- An action against someone else is not this report's outcome.
        IF v_report.reported_user_id IS NOT NULL AND v_subject IS DISTINCT FROM v_report.reported_user_id
        THEN
            RAISE EXCEPTION 'action is about someone else' USING ERRCODE = '22023';
        END IF;
        IF NOT p_link_audit = ANY (v_report.linked_audit_ids) THEN
            IF cardinality(v_report.linked_audit_ids) >= 20 THEN
                RAISE EXCEPTION 'too many links' USING ERRCODE = '22023';
            END IF;
            UPDATE reports
            SET linked_audit_ids = array_append(linked_audit_ids, p_link_audit)
            WHERE id = p_id;
            PERFORM app_audit('report.link', 'report',
                              jsonb_build_object('report_id', p_id, 'audit_id', p_link_audit,
                                                 'action', v_action),
                              v_report.reported_user_id, NULL);
        END IF;
    END IF;

    IF p_preserve IS NOT NULL AND p_preserve <> v_report.preserve THEN
        UPDATE reports
        SET preserve = p_preserve,
            preserved_by = CASE WHEN p_preserve THEN v_me END,
            preserved_at = CASE WHEN p_preserve THEN now() END
        WHERE id = p_id;
        PERFORM app_audit(CASE WHEN p_preserve THEN 'report.preserve' ELSE 'report.unpreserve' END,
                          'report',
                          jsonb_build_object('report_id', p_id),
                          v_report.reported_user_id, NULL);
    END IF;

    UPDATE reports SET updated_at = now() WHERE id = p_id;
END;
$$;

-- 6. Retention. Dismissed and actioned reports go p_days after they were resolved, with their
-- notes. A report on legal hold stays, and so does one still open or under review. The sweep
-- passes the operator's setting (TINYSERVER_REPORT_RETENTION_DAYS, default 90).

CREATE FUNCTION app_reports_sweep(p_days integer)
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

-- 7. Account deletion (0014). A trigger, so this does not touch app_delete_account.
--
-- A person who deletes their account:
--   * as a REPORTER: loses their identity link on every report they made, preserved or not
--     (reporter_id becomes NULL). On reports that are not on legal hold their own words go too:
--     the note and the evidence. The report itself stays, with its kind, target, category and
--     status, so a moderator can still act on it.
--   * as the PERSON REPORTED: on reports that are not on legal hold the evidence, the
--     reporter's note and the moderators' notes are deleted. The report row stays, as a record
--     that a report was made and what became of it.
--   * A report on legal hold is never changed except for the reporter link, because a hold
--     exists to keep it.
-- The users row is already a tombstone with no name, email or picture, so ids that remain
-- identify no one.

CREATE FUNCTION app_reports_forget_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    UPDATE reports
    SET reporter_id = NULL,
        note = CASE WHEN preserve THEN note END,
        evidence = CASE WHEN preserve THEN evidence END
    WHERE reporter_id = NEW.id;
    DELETE FROM report_notes
    WHERE report_id IN (SELECT id FROM reports
                        WHERE reported_user_id = NEW.id AND NOT preserve);
    UPDATE reports
    SET note = NULL, evidence = NULL
    WHERE reported_user_id = NEW.id AND NOT preserve;
    RETURN NULL;
END;
$$;

REVOKE EXECUTE ON FUNCTION app_reports_forget_user() FROM PUBLIC;

CREATE TRIGGER users_forget_reports
    AFTER UPDATE OF deleted_at ON users
    FOR EACH ROW
    WHEN (OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL)
    EXECUTE FUNCTION app_reports_forget_user();

-- 8. Grants.

REVOKE EXECUTE ON FUNCTION app_report_create(text, uuid, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_report_create(text, uuid, text, text, text) TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_report_update(uuid, text, text, bigint, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_report_update(uuid, text, text, bigint, boolean) TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_reports_sweep(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_reports_sweep(integer) TO app_runtime;
