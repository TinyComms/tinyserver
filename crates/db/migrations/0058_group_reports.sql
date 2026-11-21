-- Abuse reports for messages in group conversations (issue #59).
--
-- Extends `reports` with `group_dm_id` (`ON DELETE SET NULL`, no member-list column) and teaches
-- `app_report_create` to admit `kind = 'message'` reports for group messages when the reporter
-- is a current member of that group. Non-members (including owners outside the group) get 404.
-- Handling the report never adds a moderator to the group or exposes its messages or members.
-- Evidence stays unverified, mirroring direct messages and channels.
--
-- Rollback: crates/db/rollback/0058_group_reports.down.sql.

ALTER TABLE reports ADD COLUMN group_dm_id uuid REFERENCES group_dms (id) ON DELETE SET NULL;

CREATE OR REPLACE FUNCTION app_report_create(
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
    v_group uuid;
    v_msg_channel uuid;
    v_msg_direct uuid;
    v_msg_group uuid;
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
        SELECT m.channel_id, m.direct_id, m.group_dm_id, m.author_id
        INTO v_msg_channel, v_msg_direct, v_msg_group, v_reported
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
        ELSIF v_msg_direct IS NOT NULL THEN
            IF NOT EXISTS (
                SELECT 1 FROM directs d
                WHERE d.id = v_msg_direct AND v_me IN (d.low_user_id, d.high_user_id)
            ) THEN
                RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
            END IF;
        ELSIF v_msg_group IS NOT NULL THEN
            IF NOT EXISTS (
                SELECT 1 FROM group_dm_members gm
                WHERE gm.group_dm_id = v_msg_group AND gm.user_id = v_me
            ) THEN
                RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
            END IF;
        ELSE
            RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
        END IF;
        IF v_reported = v_me THEN
            RAISE EXCEPTION 'cannot report yourself' USING ERRCODE = '22023';
        END IF;
        v_message := p_target;
        v_channel := v_msg_channel;
        v_direct := v_msg_direct;
        v_group := v_msg_group;
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
                         direct_id, group_dm_id, note, evidence, evidence_unverified)
    VALUES (p_kind, p_category, v_me, v_reported, v_message, v_channel, v_direct, v_group,
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
