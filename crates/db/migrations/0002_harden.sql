-- Two owners demoting or removing each other at once could both see two owners and leave none.
-- Both functions now take one transaction lock before they read a role. Under read committed
-- the second caller waits, then counts what the first one committed. CREATE OR REPLACE keeps
-- the function owner and the grants from 0001.

CREATE OR REPLACE FUNCTION app_set_member_role(p_user_id uuid, p_role text)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_caller text;
    v_current text;
    v_owners integer;
BEGIN
    v_caller := current_setting('app.role', true);
    IF v_caller NOT IN ('owner', 'admin') THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    IF p_role NOT IN ('owner', 'admin', 'member') THEN
        RAISE EXCEPTION 'invalid role' USING ERRCODE = '22023';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.owners'));

    SELECT role INTO v_current FROM memberships WHERE user_id = p_user_id;
    IF v_current IS NULL THEN
        RAISE EXCEPTION 'member not found' USING ERRCODE = 'P0002';
    END IF;

    IF v_caller <> 'owner' AND (v_current = 'owner' OR p_role = 'owner') THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;

    SELECT count(*) INTO v_owners FROM memberships WHERE role = 'owner';
    IF v_current = 'owner' AND p_role <> 'owner' AND v_owners <= 1 THEN
        RAISE EXCEPTION 'last owner' USING ERRCODE = '42501';
    END IF;

    UPDATE memberships SET role = p_role WHERE user_id = p_user_id;
    INSERT INTO audit_log (actor_id, action, subject, detail)
    VALUES (
        nullif(current_setting('app.user_id', true), '')::uuid,
        'member.role',
        'membership',
        jsonb_build_object('user_id', p_user_id, 'role', p_role)
    );
    RETURN p_role;
END;
$$;

CREATE OR REPLACE FUNCTION app_remove_member(p_user_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_caller text;
    v_current text;
    v_owners integer;
BEGIN
    v_caller := current_setting('app.role', true);
    IF v_caller NOT IN ('owner', 'admin') THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.owners'));

    SELECT role INTO v_current FROM memberships WHERE user_id = p_user_id;
    IF v_current IS NULL THEN
        RAISE EXCEPTION 'member not found' USING ERRCODE = 'P0002';
    END IF;
    IF v_caller <> 'owner' AND v_current = 'owner' THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;

    SELECT count(*) INTO v_owners FROM memberships WHERE role = 'owner';
    IF v_current = 'owner' AND v_owners <= 1 THEN
        RAISE EXCEPTION 'last owner' USING ERRCODE = '42501';
    END IF;

    DELETE FROM memberships WHERE user_id = p_user_id;
    INSERT INTO audit_log (actor_id, action, subject, detail)
    VALUES (
        nullif(current_setting('app.user_id', true), '')::uuid,
        'member.remove',
        'membership',
        jsonb_build_object('user_id', p_user_id)
    );
END;
$$;
