-- Sign-in moves to an OpenID Connect provider. tinyserver keeps no passwords.
--
-- A person is (issuer, subject) from a verified ID token. Email is profile only: it may be
-- missing, two people may share one, and it never links accounts. People who signed in with a
-- password before this have no identity and cannot sign in; `tinyserver bootstrap
-- --owner-invite` gives the owner a way back in.

ALTER TABLE users DROP COLUMN password_hash;
ALTER TABLE users ALTER COLUMN email DROP NOT NULL;
ALTER TABLE users ADD CONSTRAINT users_email_length CHECK (char_length(email) <= 254);
DROP INDEX users_email_lower;

CREATE TABLE user_identities (
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    issuer text NOT NULL CHECK (char_length(issuer) BETWEEN 1 AND 2048),
    subject text NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 255),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (issuer, subject)
);

CREATE INDEX user_identities_user ON user_identities (user_id);

-- A sign-in between POST /v1/auth/start and the provider's callback. Keyed by the SHA-256 of the
-- state sent to the provider. The verifier and nonce are the server's own, for the provider leg;
-- the client's redirect, challenge, and state are for the leg back to tinyclient.
CREATE TABLE auth_pending (
    state_hash bytea PRIMARY KEY,
    provider text NOT NULL,
    verifier text NOT NULL,
    nonce text NOT NULL,
    client_redirect text NOT NULL,
    client_challenge text NOT NULL,
    client_state text NOT NULL,
    invite_hash bytea,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- The one-time code tinyclient trades for a session at POST /v1/auth/token. Keyed by its SHA-256.
-- The issuer and the provider's session id (`sid`) pass on to the session it opens.
CREATE TABLE auth_codes (
    code_hash bytea PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_challenge text NOT NULL,
    issuer text NOT NULL,
    sid text CHECK (char_length(sid) BETWEEN 1 AND 255),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX auth_codes_user ON auth_codes (user_id);

-- A session opened by sign-in remembers which provider, and the provider's session id when the
-- ID token had one, so back-channel logout can end it. Sessions from before have neither.
ALTER TABLE sessions ADD COLUMN issuer text;
ALTER TABLE sessions ADD COLUMN sid text CHECK (char_length(sid) BETWEEN 1 AND 255);
CREATE INDEX sessions_provider_sid ON sessions (issuer, sid) WHERE sid IS NOT NULL;

-- Default privileges gave app_runtime everything on new tables. Narrow it to what sign-in does.
REVOKE ALL ON user_identities, auth_pending, auth_codes FROM app_runtime;
GRANT SELECT, INSERT ON user_identities TO app_runtime;
GRANT SELECT, INSERT, DELETE ON auth_pending TO app_runtime;
GRANT SELECT, INSERT, DELETE ON auth_codes TO app_runtime;

-- An owner invite is made only by `tinyserver bootstrap`, as app_owner, so it has no creator.
-- The runtime still cannot make one: the policy below refuses role 'owner' on insert or update.
ALTER TABLE invites DROP CONSTRAINT invites_role_check;
ALTER TABLE invites ADD CONSTRAINT invites_role_check CHECK (role IN ('owner', 'admin', 'member'));
ALTER TABLE invites ALTER COLUMN created_by DROP NOT NULL;

DROP POLICY invites_all ON invites;

CREATE POLICY invites_all ON invites
    FOR ALL
    USING (current_setting('app.role', true) IN ('owner', 'admin'))
    WITH CHECK (current_setting('app.role', true) IN ('owner', 'admin') AND role <> 'owner');

-- Membership from the provider's groups claim, when the owner configured it. Never owner.
-- tinyserver checks the groups; these only make the row, audit it, and tell live sockets.

CREATE OR REPLACE FUNCTION app_join_by_groups(p_user_id uuid, p_role text, p_issuer text)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_name text;
BEGIN
    IF p_role NOT IN ('admin', 'member') THEN
        RAISE EXCEPTION 'invalid role' USING ERRCODE = '22023';
    END IF;
    IF EXISTS (SELECT 1 FROM memberships WHERE user_id = p_user_id) THEN
        RAISE EXCEPTION 'already a member' USING ERRCODE = '23505';
    END IF;
    INSERT INTO memberships (user_id, role) VALUES (p_user_id, p_role);
    INSERT INTO audit_log (actor_id, action, subject, detail)
    VALUES (p_user_id, 'member.join', 'membership',
            jsonb_build_object('role', p_role, 'via', 'groups', 'issuer', p_issuer));
    SELECT display_name INTO v_name FROM users WHERE id = p_user_id;
    PERFORM app_emit('member.joined', jsonb_build_object('member', jsonb_build_object(
        'user_id', p_user_id,
        'display_name', v_name,
        'role', p_role
    )));
    RETURN p_role;
END;
$$;

-- A member in an admin group becomes admin when they sign in. Admins and owners are left alone.
CREATE OR REPLACE FUNCTION app_promote_by_groups(p_user_id uuid, p_issuer text)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_role text;
    v_name text;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.owners'));
    SELECT role INTO v_role FROM memberships WHERE user_id = p_user_id;
    IF v_role IS DISTINCT FROM 'member' THEN
        RETURN v_role;
    END IF;
    UPDATE memberships SET role = 'admin' WHERE user_id = p_user_id;
    INSERT INTO audit_log (actor_id, action, subject, detail)
    VALUES (p_user_id, 'member.role', 'membership',
            jsonb_build_object('user_id', p_user_id, 'role', 'admin', 'via', 'groups',
                               'issuer', p_issuer));
    SELECT display_name INTO v_name FROM users WHERE id = p_user_id;
    PERFORM app_emit('member.role', jsonb_build_object('member', jsonb_build_object(
        'user_id', p_user_id,
        'display_name', v_name,
        'role', 'admin'
    )));
    RETURN 'admin';
END;
$$;

REVOKE EXECUTE ON FUNCTION app_join_by_groups(uuid, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_join_by_groups(uuid, text, text) TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_promote_by_groups(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_promote_by_groups(uuid, text) TO app_runtime;

-- The sweep also deletes sign-ins that were never finished and codes nobody redeemed.

DROP FUNCTION app_sweep();

CREATE FUNCTION app_sweep(
    OUT expired_sessions bigint,
    OUT expired_invites bigint,
    OUT expired_keys bigint,
    OUT expired_events bigint,
    OUT expired_logins bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_through bigint;
    v_codes bigint;
BEGIN
    DELETE FROM sessions WHERE expires_at <= now();
    GET DIAGNOSTICS expired_sessions = ROW_COUNT;
    DELETE FROM invites WHERE accepted_at IS NULL AND expires_at <= now();
    GET DIAGNOSTICS expired_invites = ROW_COUNT;
    DELETE FROM idempotency_keys WHERE expires_at <= now();
    GET DIAGNOSTICS expired_keys = ROW_COUNT;
    DELETE FROM auth_pending WHERE expires_at <= now();
    GET DIAGNOSTICS expired_logins = ROW_COUNT;
    DELETE FROM auth_codes WHERE expires_at <= now();
    GET DIAGNOSTICS v_codes = ROW_COUNT;
    expired_logins := expired_logins + v_codes;

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
