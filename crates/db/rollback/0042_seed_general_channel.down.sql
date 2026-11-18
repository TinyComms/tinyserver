-- Undoes migrations/0042_seed_general_channel.sql. Run as the owner role, in one transaction,
-- then start the previous image. It restores app_accept_invite's body from 0005_server.sql as
-- it was and drops app_seed_defaults, so the previous image's migration check passes. Channels
-- already seeded stay: they may hold messages by then.

BEGIN;

CREATE OR REPLACE FUNCTION app_accept_invite(p_token_hash bytea, p_user_id uuid)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_invite invites%ROWTYPE;
    v_stamp constant text := 'YYYY-MM-DD"T"HH24:MI:SS"Z"';
BEGIN
    IF app_banned(p_user_id) THEN
        RAISE EXCEPTION 'banned' USING ERRCODE = '42501';
    END IF;
    IF EXISTS (SELECT 1 FROM memberships WHERE user_id = p_user_id) THEN
        RAISE EXCEPTION 'already a member' USING ERRCODE = '23505';
    END IF;

    SELECT * INTO v_invite
    FROM invites
    WHERE token_hash = p_token_hash
      AND (expires_at IS NULL OR expires_at > now())
      AND (max_uses IS NULL OR uses < max_uses)
    FOR UPDATE;
    IF v_invite.id IS NULL THEN
        RAISE EXCEPTION 'invite not found' USING ERRCODE = 'P0002';
    END IF;

    INSERT INTO memberships (user_id, owner, joined_via)
    VALUES (p_user_id, v_invite.role = 'owner', 'invite');
    INSERT INTO member_roles (user_id, role_id)
    SELECT p_user_id, r.id FROM roles r
    WHERE r.id = ANY (v_invite.role_ids) AND NOT r.is_default;
    UPDATE invites
    SET accepted_at = now(), accepted_by = p_user_id, uses = uses + 1
    WHERE id = v_invite.id
    RETURNING * INTO v_invite;
    INSERT INTO audit_log (actor_id, action, subject, detail, subject_user_id)
    VALUES (p_user_id, 'invite.accept', 'membership',
            jsonb_build_object('role', v_invite.role, 'invite_id', v_invite.id,
                               'label', v_invite.label),
            p_user_id);

    PERFORM app_emit('invite.accepted', jsonb_build_object('invite', jsonb_build_object(
        'id', v_invite.id,
        'role', v_invite.role,
        'created_by', v_invite.created_by,
        'expires_at', to_char(v_invite.expires_at AT TIME ZONE 'UTC', v_stamp),
        'accepted_at', to_char(v_invite.accepted_at AT TIME ZONE 'UTC', v_stamp),
        'accepted_by', v_invite.accepted_by,
        'label', v_invite.label,
        'max_uses', v_invite.max_uses,
        'uses', v_invite.uses,
        'role_ids', to_jsonb(v_invite.role_ids)
    )));
    PERFORM app_emit('member.joined', jsonb_build_object('member', app_member_json(p_user_id)));
    RETURN app_member_role(p_user_id);
END;
$$;

DROP FUNCTION app_seed_defaults(uuid);

DELETE FROM _sqlx_migrations WHERE version = 42;

COMMIT;
