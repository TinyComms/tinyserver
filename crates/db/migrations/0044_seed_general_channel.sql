-- A new community starts with a #general text channel. No table, column, topic, payload or
-- API changes.
--
-- A community comes into being when its first owner signs in with the owner invite that
-- `tinyserver bootstrap` issued: app_accept_invite makes the first membership. From this
-- migration that same transaction also makes the community's first channel: one text channel
-- named general, in no category, at position 0, created by that owner. It follows the
-- e2ee_text setting like any new conversation (the rule app_e2ee_may_create applies). At the
-- first sign-in no device can be enrolled yet, so an encrypted seed starts over an empty
-- audience; growth past the device cap afterwards is what the waiting mechanism
-- (app_e2ee_info) already handles. The seed
-- writes the channel.create audit row a created channel writes, with no actor, because during
-- the first sign-in nobody is scoped yet, exactly as bootstrap writes its own row, and emits
-- the same channel.created event, so every client learns of the channel the way it already
-- learns of any other.
--
-- The seed runs once, ever: only for an owner invite, and only while the community has no
-- channel and no other member. An owner who deletes general does not get it back, and a
-- recovery owner joining a community that still has people does not seed either. Communities
-- whose owner signed in before this migration are untouched; the one-time backfill the issue
-- asks for them needs its own seeded-once stamp and is a separate change, so it cannot fire
-- twice.

-- Called only from app_accept_invite. Skips quietly when there is nothing to do, so a
-- community that arranged its own channels keeps them and a retried sign-in seeds nothing
-- twice.
CREATE FUNCTION app_seed_defaults(p_owner uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_id uuid;
    v_e2ee boolean;
BEGIN
    IF EXISTS (SELECT 1 FROM channels)
       OR EXISTS (SELECT 1 FROM memberships WHERE user_id <> p_owner) THEN
        RETURN;
    END IF;
    -- A new conversation follows the server's e2ee_text setting, as app_create_channel does.
    v_e2ee := (SELECT s.e2ee_text FROM server_settings s) IN ('new_required', 'required');
    INSERT INTO channels (category_id, name, topic, position, created_by, e2ee)
    VALUES (NULL, 'general', '', 0, p_owner, v_e2ee)
    RETURNING id INTO v_id;
    PERFORM app_audit(
        'channel.create', 'channel',
        jsonb_build_object('id', v_id, 'name', 'general', 'e2ee', v_e2ee, 'seeded', true),
        NULL, NULL
    );
    PERFORM app_emit('channel.created', jsonb_build_object('channel', app_channel_json(v_id)));
END;
$$;

-- Nobody at runtime calls it; only the first owner's sign-in does, from inside
-- app_accept_invite.
REVOKE EXECUTE ON FUNCTION app_seed_defaults(uuid) FROM PUBLIC, app_runtime;

-- The body from 0005_server.sql, with the seed called where the first membership is made.
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
    -- The community's first channel, when this membership is the community's first. One
    -- transaction: the channel, its audit row and its event commit with the owner, or not at
    -- all. No network call inside it; the event is an outbox row the dispatcher delivers.
    IF v_invite.role = 'owner' THEN
        PERFORM app_seed_defaults(p_user_id);
    END IF;
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
