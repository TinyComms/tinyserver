-- Identity has no RLS. Authorization is memberships, and the API connects as
-- app_runtime (NOBYPASSRLS). app_owner runs migrations and SECURITY DEFINER
-- functions; that role has BYPASSRLS, so those functions must check the caller.

CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email text NOT NULL,
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 80),
    password_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX users_email_lower ON users (lower(email));

CREATE TABLE sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX sessions_user ON sessions (user_id);

CREATE TABLE memberships (
    user_id uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE rooms (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
    created_by uuid NOT NULL REFERENCES users (id),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE invites (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    role text NOT NULL CHECK (role IN ('admin', 'member')),
    token_hash bytea NOT NULL UNIQUE,
    created_by uuid NOT NULL REFERENCES users (id),
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz,
    accepted_by uuid REFERENCES users (id),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_log (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id uuid,
    action text NOT NULL,
    subject text NOT NULL,
    detail jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE idempotency_keys (
    key text PRIMARY KEY,
    request_hash text NOT NULL,
    status_code integer,
    response jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

CREATE TABLE outbox (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    topic text NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    sent_at timestamptz
);

CREATE OR REPLACE FUNCTION notify_app_wake()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_notify('app_wake', NEW.topic);
    RETURN NEW;
END;
$$;

CREATE TRIGGER outbox_wake
    AFTER INSERT ON outbox
    FOR EACH ROW
    EXECUTE FUNCTION notify_app_wake();

ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE rooms ENABLE ROW LEVEL SECURITY;
ALTER TABLE rooms FORCE ROW LEVEL SECURITY;
ALTER TABLE invites ENABLE ROW LEVEL SECURITY;
ALTER TABLE invites FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;

CREATE POLICY memberships_select ON memberships
    FOR SELECT
    USING (current_setting('app.role', true) IN ('owner', 'admin', 'member'));

CREATE POLICY rooms_select ON rooms
    FOR SELECT
    USING (current_setting('app.role', true) IN ('owner', 'admin', 'member'));

CREATE POLICY rooms_write ON rooms
    FOR ALL
    USING (current_setting('app.role', true) IN ('owner', 'admin'))
    WITH CHECK (current_setting('app.role', true) IN ('owner', 'admin'));

CREATE POLICY invites_all ON invites
    FOR ALL
    USING (current_setting('app.role', true) IN ('owner', 'admin'))
    WITH CHECK (current_setting('app.role', true) IN ('owner', 'admin'));

CREATE POLICY audit_select ON audit_log
    FOR SELECT
    USING (current_setting('app.role', true) IN ('owner', 'admin'));

CREATE POLICY audit_insert ON audit_log
    FOR INSERT
    WITH CHECK (nullif(current_setting('app.user_id', true), '') IS NOT NULL);

-- Direct membership writes are denied. Role changes go through the functions below.
-- app_owner bypasses RLS, so the functions re-check app.role themselves.

CREATE OR REPLACE FUNCTION app_member_role(p_user_id uuid)
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT role FROM memberships WHERE user_id = p_user_id;
$$;

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

CREATE OR REPLACE FUNCTION app_accept_invite(p_token_hash bytea, p_user_id uuid)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_invite uuid;
    v_role text;
BEGIN
    IF EXISTS (SELECT 1 FROM memberships WHERE user_id = p_user_id) THEN
        RAISE EXCEPTION 'already a member' USING ERRCODE = '23505';
    END IF;

    SELECT id, role INTO v_invite, v_role
    FROM invites
    WHERE token_hash = p_token_hash
      AND accepted_at IS NULL
      AND expires_at > now()
    FOR UPDATE;
    IF v_invite IS NULL THEN
        RAISE EXCEPTION 'invite not found' USING ERRCODE = 'P0002';
    END IF;

    INSERT INTO memberships (user_id, role) VALUES (p_user_id, v_role);
    UPDATE invites
    SET accepted_at = now(), accepted_by = p_user_id
    WHERE id = v_invite;
    INSERT INTO audit_log (actor_id, action, subject, detail)
    VALUES (p_user_id, 'invite.accept', 'membership', jsonb_build_object('role', v_role));
    RETURN v_role;
END;
$$;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_runtime;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO app_runtime;

-- Audit rows are append-only for the runtime role. Owners read them through RLS.
REVOKE UPDATE, DELETE ON audit_log FROM app_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON memberships FROM app_runtime;
REVOKE INSERT ON memberships FROM app_runtime;
