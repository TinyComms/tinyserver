-- Built-in passkey sign-in (WebAuthn). A new source of (issuer, subject), not a second login
-- stack: the issuer is 'tinyserver:passkey' and the subject is a random 128-bit account id
-- chosen here. Everything downstream (invites, bans, roles, sessions, the owner bootstrap,
-- account deletion) is the machinery OIDC sign-in already uses.
--
-- What is stored about a person, and nothing else:
--   passkey_credentials     credential id, the public key (inside `passkey`), the sign counter,
--                           the backup flags, a label the person chose, created_at, last_used_at.
--                           `flagged_at` is set when the sign counter went backwards.
--   passkey_recovery_codes  the SHA-256 of each unused recovery code. Never the code.
--   passkey_claims          the SHA-256 of an owner-issued claim link token, and when it expires.
--   passkey_ceremonies      a registration or sign-in in progress: the library's state, which
--                           holds the challenge, for at most a few minutes.
-- No IP address, no user agent, no email, no phone number, no attestation statement. A
-- ceremony's `display_name` is the name the person typed at sign-up, kept until they finish.
--
-- Every table is reached only through the SECURITY DEFINER functions below. The runtime role has
-- no grant on any of them, and row level security is forced with no policy, so even a grant
-- added by mistake shows nothing.

CREATE TABLE passkey_credentials (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id bytea NOT NULL UNIQUE CHECK (octet_length(credential_id) BETWEEN 16 AND 1024),
    -- The library's own serialisation of the credential: COSE public key, counter, flags. It is
    -- what the next assertion is checked against. Pinned with the library version.
    passkey jsonb NOT NULL,
    sign_count bigint NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    backup_eligible boolean NOT NULL,
    backup_state boolean NOT NULL,
    label text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 60),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    -- The counter went backwards after a valid signature: possibly a cloned authenticator.
    -- The credential is refused until the person removes it.
    flagged_at timestamptz
);

CREATE INDEX passkey_credentials_user ON passkey_credentials (user_id);

CREATE TABLE passkey_recovery_codes (
    code_hash bytea PRIMARY KEY CHECK (octet_length(code_hash) = 32),
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX passkey_recovery_codes_user ON passkey_recovery_codes (user_id);

-- An owner-issued, single-use link that lets an existing member enrol a passkey on their
-- existing account. Only the hash of the token is kept.
CREATE TABLE passkey_claims (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

CREATE INDEX passkey_claims_user ON passkey_claims (user_id);

-- A ceremony in progress. Found by the SHA-256 of a random 256-bit id the page holds, and
-- deleted when it is used, so a challenge works once. `continue` rows are the short step between
-- "the passkey is made" and "tinyclient gets its one-time code", so a person can read their
-- recovery codes first.
CREATE TABLE passkey_ceremonies (
    id_hash bytea PRIMARY KEY CHECK (octet_length(id_hash) = 32),
    kind text NOT NULL CHECK (kind IN
        ('signup', 'login', 'recover', 'claim', 'continue')),
    state jsonb,
    user_id uuid REFERENCES users (id) ON DELETE CASCADE,
    subject text,
    pending_hash bytea,
    display_name text,
    secret_hash bytea,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

CREATE INDEX passkey_ceremonies_expires ON passkey_ceremonies (expires_at);

ALTER TABLE passkey_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE passkey_credentials FORCE ROW LEVEL SECURITY;
ALTER TABLE passkey_recovery_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE passkey_recovery_codes FORCE ROW LEVEL SECURITY;
ALTER TABLE passkey_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE passkey_claims FORCE ROW LEVEL SECURITY;
ALTER TABLE passkey_ceremonies ENABLE ROW LEVEL SECURITY;
ALTER TABLE passkey_ceremonies FORCE ROW LEVEL SECURITY;

-- Default privileges gave app_runtime everything on new tables. It gets nothing on these.
REVOKE ALL ON passkey_credentials, passkey_recovery_codes, passkey_claims, passkey_ceremonies
    FROM app_runtime;

-- Ceremonies. The caller picks the id; only its hash is stored.

CREATE FUNCTION app_passkey_ceremony_begin(
    p_kind text, p_id_hash bytea, p_state jsonb, p_user uuid, p_subject text, p_pending bytea,
    p_name text, p_secret bytea, p_ttl_secs integer
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    IF p_ttl_secs NOT BETWEEN 10 AND 3600 THEN
        RAISE EXCEPTION 'bad lifetime' USING ERRCODE = '22023';
    END IF;
    DELETE FROM passkey_ceremonies WHERE expires_at <= now();
    DELETE FROM passkey_claims WHERE expires_at <= now();
    -- A person who retries replaces their earlier challenge rather than adding another.
    IF p_pending IS NOT NULL THEN
        DELETE FROM passkey_ceremonies WHERE kind = p_kind AND pending_hash = p_pending;
    END IF;
    IF p_secret IS NOT NULL THEN
        DELETE FROM passkey_ceremonies WHERE kind = p_kind AND secret_hash = p_secret;
    END IF;
    -- Unauthenticated callers can start ceremonies; this bounds the table, and the per-address
    -- limiter in front of the route keeps one client from using it all.
    IF (SELECT count(*) FROM passkey_ceremonies) >= 20000 THEN
        RAISE EXCEPTION 'too many ceremonies' USING ERRCODE = '53400';
    END IF;
    INSERT INTO passkey_ceremonies
        (id_hash, kind, state, user_id, subject, pending_hash, display_name, secret_hash,
         expires_at)
    VALUES
        (p_id_hash, p_kind, p_state, p_user, p_subject, p_pending, p_name, p_secret,
         now() + make_interval(secs => p_ttl_secs));
END;
$$;

-- Spends a ceremony: it is deleted whether or not what follows succeeds. Nothing comes back for
-- an unknown id, the wrong kind, or an expired ceremony.
CREATE FUNCTION app_passkey_ceremony_take(p_kind text, p_id_hash bytea)
RETURNS TABLE (
    state jsonb, user_id uuid, subject text, pending_hash bytea, display_name text,
    secret_hash bytea
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
    DELETE FROM passkey_ceremonies c
    WHERE c.id_hash = p_id_hash AND c.kind = p_kind AND c.expires_at > now()
    RETURNING c.state, c.user_id, c.subject, c.pending_hash, c.display_name, c.secret_hash;
$$;

-- After a passkey is made and before tinyclient gets its code: a `continue` ceremony, and the
-- pending sign-in kept alive for 15 minutes so there is time to save recovery codes.
CREATE FUNCTION app_passkey_continue(
    p_user uuid, p_subject text, p_pending bytea, p_id_hash bytea, p_ttl_secs integer
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    IF p_ttl_secs NOT BETWEEN 10 AND 3600 THEN
        RAISE EXCEPTION 'bad lifetime' USING ERRCODE = '22023';
    END IF;
    INSERT INTO passkey_ceremonies (id_hash, kind, user_id, subject, pending_hash, expires_at)
    VALUES (p_id_hash, 'continue', p_user, p_subject, p_pending,
            now() + make_interval(secs => p_ttl_secs));
    UPDATE auth_pending
    SET expires_at = greatest(expires_at, now() + interval '15 minutes')
    WHERE state_hash = p_pending;
END;
$$;

-- Credentials.

-- The passkey subject the person already has, if any.
CREATE FUNCTION app_passkey_subject_of(p_user uuid)
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT subject FROM user_identities
    WHERE user_id = p_user AND issuer = 'tinyserver:passkey'
    ORDER BY created_at
    LIMIT 1;
$$;

-- Gives an existing account a passkey identity, or confirms the one it has. A banned account
-- gets none. Returns false when the account already has a different passkey subject.
CREATE FUNCTION app_passkey_attach(p_user uuid, p_subject text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_have text;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.passkey' || p_user::text, 0));
    IF app_banned(p_user) THEN
        RAISE EXCEPTION 'banned' USING ERRCODE = '42501';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM users WHERE id = p_user AND deleted_at IS NULL) THEN
        RAISE EXCEPTION 'user not found' USING ERRCODE = 'P0002';
    END IF;
    v_have := app_passkey_subject_of(p_user);
    IF v_have IS NOT NULL THEN
        RETURN v_have = p_subject;
    END IF;
    INSERT INTO user_identities (user_id, issuer, subject)
    VALUES (p_user, 'tinyserver:passkey', p_subject);
    RETURN true;
END;
$$;

-- Stores a verified credential for an account that has this passkey subject. A credential id
-- another account already has is refused (23505). At most 10 passkeys per account.
CREATE FUNCTION app_passkey_insert(
    p_user uuid, p_subject text, p_credential_id bytea, p_passkey jsonb, p_sign_count bigint,
    p_backup_eligible boolean, p_backup_state boolean, p_label text
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_id uuid;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM user_identities
        WHERE user_id = p_user AND issuer = 'tinyserver:passkey' AND subject = p_subject
    ) THEN
        RAISE EXCEPTION 'no passkey identity' USING ERRCODE = 'P0002';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.passkey' || p_user::text, 0));
    IF (SELECT count(*) FROM passkey_credentials WHERE user_id = p_user) >= 10 THEN
        RAISE EXCEPTION 'too many passkeys' USING ERRCODE = '22023';
    END IF;
    INSERT INTO passkey_credentials
        (user_id, credential_id, passkey, sign_count, backup_eligible, backup_state, label)
    VALUES
        (p_user, p_credential_id, p_passkey, p_sign_count, p_backup_eligible, p_backup_state,
         p_label)
    RETURNING id INTO v_id;
    INSERT INTO audit_log (actor_id, action, subject, detail, subject_user_id)
    VALUES (p_user, 'passkey.add', 'user', jsonb_build_object('credential', v_id), p_user);
    RETURN v_id;
END;
$$;

-- The credential for a sign-in, with the passkey subject its account signs in as.
CREATE FUNCTION app_passkey_find(p_credential_id bytea)
RETURNS TABLE (id uuid, user_id uuid, subject text, passkey jsonb, flagged boolean)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT c.id, c.user_id, i.subject, c.passkey, c.flagged_at IS NOT NULL
    FROM passkey_credentials c
    JOIN user_identities i ON i.user_id = c.user_id AND i.issuer = 'tinyserver:passkey'
    WHERE c.credential_id = p_credential_id
    ORDER BY i.created_at
    LIMIT 1;
$$;

-- Every credential an account has: to exclude from a new registration, and to ask for a
-- re-check by the account's own passkeys.
CREATE FUNCTION app_passkey_credentials_of(p_user uuid)
RETURNS TABLE (id uuid, credential_id bytea, passkey jsonb, flagged boolean)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT c.id, c.credential_id, c.passkey, c.flagged_at IS NOT NULL
    FROM passkey_credentials c
    WHERE c.user_id = p_user
    ORDER BY c.created_at;
$$;

-- After a good assertion: the new counter and flags, and when it was used.
CREATE FUNCTION app_passkey_record_use(
    p_id uuid, p_passkey jsonb, p_sign_count bigint, p_backup_eligible boolean,
    p_backup_state boolean
)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
    UPDATE passkey_credentials
    SET passkey = p_passkey,
        sign_count = greatest(sign_count, p_sign_count),
        backup_eligible = p_backup_eligible,
        backup_state = p_backup_state,
        last_used_at = now()
    WHERE id = p_id;
$$;

-- A valid signature with a counter that did not go up. Refuse this credential from now on.
CREATE FUNCTION app_passkey_flag(p_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_user uuid;
BEGIN
    UPDATE passkey_credentials SET flagged_at = coalesce(flagged_at, now())
    WHERE id = p_id
    RETURNING user_id INTO v_user;
    IF v_user IS NOT NULL THEN
        INSERT INTO audit_log (actor_id, action, subject, detail, subject_user_id)
        VALUES (v_user, 'passkey.flag', 'user', jsonb_build_object('credential', p_id), v_user);
    END IF;
END;
$$;

-- The caller's own passkeys. Never the key material.
CREATE FUNCTION app_passkey_list()
RETURNS TABLE (
    id uuid, label text, created_at timestamptz, last_used_at timestamptz,
    backup_eligible boolean, backup_state boolean, flagged boolean
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT c.id, c.label, c.created_at, c.last_used_at, c.backup_eligible, c.backup_state,
           c.flagged_at IS NOT NULL
    FROM passkey_credentials c
    WHERE c.user_id = app_uid()
    ORDER BY c.created_at;
$$;

CREATE FUNCTION app_passkey_rename(p_id uuid, p_label text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    UPDATE passkey_credentials SET label = p_label WHERE id = p_id AND user_id = app_uid();
    IF NOT FOUND THEN
        RAISE EXCEPTION 'passkey not found' USING ERRCODE = 'P0002';
    END IF;
END;
$$;

-- Removes one of the caller's passkeys. The last one goes only if an unused recovery code is
-- left, since without either the account could never be signed in to again.
CREATE FUNCTION app_passkey_remove(p_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_user uuid := app_uid();
BEGIN
    IF v_user IS NULL THEN
        RAISE EXCEPTION 'passkey not found' USING ERRCODE = 'P0002';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.passkey' || v_user::text, 0));
    IF NOT EXISTS (SELECT 1 FROM passkey_credentials WHERE id = p_id AND user_id = v_user) THEN
        RAISE EXCEPTION 'passkey not found' USING ERRCODE = 'P0002';
    END IF;
    IF (SELECT count(*) FROM passkey_credentials WHERE user_id = v_user) <= 1
       AND NOT EXISTS (SELECT 1 FROM passkey_recovery_codes WHERE user_id = v_user) THEN
        RAISE EXCEPTION 'last credential' USING ERRCODE = '42501';
    END IF;
    DELETE FROM passkey_credentials WHERE id = p_id AND user_id = v_user;
    INSERT INTO audit_log (actor_id, action, subject, detail, subject_user_id)
    VALUES (v_user, 'passkey.remove', 'user', jsonb_build_object('credential', p_id), v_user);
END;
$$;

-- Recovery codes. Only hashes arrive here.

CREATE FUNCTION app_passkey_codes_left()
RETURNS integer
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT count(*)::integer FROM passkey_recovery_codes WHERE user_id = app_uid();
$$;

-- A new set for the caller. Every code from the old set stops working.
CREATE FUNCTION app_passkey_regenerate(p_hashes bytea[])
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_user uuid := app_uid();
BEGIN
    IF v_user IS NULL THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    IF cardinality(p_hashes) NOT BETWEEN 1 AND 20 THEN
        RAISE EXCEPTION 'bad count' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.passkey' || v_user::text, 0));
    DELETE FROM passkey_recovery_codes WHERE user_id = v_user;
    INSERT INTO passkey_recovery_codes (code_hash, user_id)
    SELECT h, v_user FROM unnest(p_hashes) AS h;
    INSERT INTO audit_log (actor_id, action, subject, detail, subject_user_id)
    VALUES (v_user, 'recovery.regenerate', 'user', jsonb_build_object('codes', cardinality(p_hashes)),
            v_user);
END;
$$;

-- A first set, when the account has none: sign-up, or a claim by someone who never had a
-- passkey. Returns false, and stores nothing, when they already have codes.
CREATE FUNCTION app_passkey_seed_recovery(p_user uuid, p_hashes bytea[])
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    IF cardinality(p_hashes) NOT BETWEEN 1 AND 20 THEN
        RAISE EXCEPTION 'bad count' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.passkey' || p_user::text, 0));
    IF EXISTS (SELECT 1 FROM passkey_recovery_codes WHERE user_id = p_user) THEN
        RETURN false;
    END IF;
    INSERT INTO passkey_recovery_codes (code_hash, user_id)
    SELECT h, p_user FROM unnest(p_hashes) AS h;
    RETURN true;
END;
$$;

-- The account an unused recovery code belongs to, or nothing.
CREATE FUNCTION app_passkey_recovery_lookup(p_hash bytea)
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT user_id FROM passkey_recovery_codes WHERE code_hash = p_hash;
$$;

-- Spends a code, once, for the account it belongs to. Returns the codes left. Raises when the
-- code is gone, so two tries at once cannot both win.
CREATE FUNCTION app_passkey_recovery_consume(p_hash bytea, p_user uuid)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_left integer;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.passkey' || p_user::text, 0));
    DELETE FROM passkey_recovery_codes WHERE code_hash = p_hash AND user_id = p_user;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'recovery code not found' USING ERRCODE = 'P0002';
    END IF;
    SELECT count(*)::integer INTO v_left FROM passkey_recovery_codes WHERE user_id = p_user;
    INSERT INTO audit_log (actor_id, action, subject, detail, subject_user_id)
    VALUES (p_user, 'passkey.recover', 'user', jsonb_build_object('codes_left', v_left), p_user);
    RETURN v_left;
END;
$$;

-- Claim links.

-- The member a live claim link is for, or nothing: unknown, expired, or for someone who is
-- banned or gone.
CREATE FUNCTION app_passkey_claim_peek(p_hash bytea)
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT c.user_id FROM passkey_claims c
    WHERE c.token_hash = p_hash AND c.expires_at > now()
      AND NOT app_banned(c.user_id)
      AND EXISTS (SELECT 1 FROM users u WHERE u.id = c.user_id AND u.deleted_at IS NULL);
$$;

-- Spends a claim link, once. Raises when it is gone or expired.
CREATE FUNCTION app_passkey_claim_consume(p_hash bytea, p_user uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    DELETE FROM passkey_claims
    WHERE token_hash = p_hash AND user_id = p_user AND expires_at > now();
    IF NOT FOUND THEN
        RAISE EXCEPTION 'claim not found' USING ERRCODE = 'P0002';
    END IF;
    INSERT INTO audit_log (actor_id, action, subject, detail, subject_user_id)
    VALUES (p_user, 'passkey.claim', 'user', '{}'::jsonb, p_user);
END;
$$;

-- A claim link a signed-in person makes for themself, to put a passkey on another device. It
-- replaces any link they had. The caller checks the session is recent before asking.
CREATE FUNCTION app_passkey_claim_self(p_hash bytea, p_ttl_secs integer)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_user uuid := app_uid();
BEGIN
    IF v_user IS NULL OR NOT EXISTS (
        SELECT 1 FROM users WHERE id = v_user AND deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    IF p_ttl_secs NOT BETWEEN 60 AND 86400 THEN
        RAISE EXCEPTION 'bad lifetime' USING ERRCODE = '22023';
    END IF;
    DELETE FROM passkey_claims WHERE user_id = v_user;
    INSERT INTO passkey_claims (token_hash, user_id, expires_at)
    VALUES (p_hash, v_user, now() + make_interval(secs => p_ttl_secs));
    INSERT INTO audit_log (actor_id, action, subject, detail, subject_user_id)
    VALUES (v_user, 'passkey.link', 'user', '{}'::jsonb, v_user);
END;
$$;

DO $$
DECLARE
    v_function text;
BEGIN
    FOREACH v_function IN ARRAY ARRAY[
        'app_passkey_ceremony_begin(text, bytea, jsonb, uuid, text, bytea, text, bytea, integer)',
        'app_passkey_ceremony_take(text, bytea)',
        'app_passkey_continue(uuid, text, bytea, bytea, integer)',
        'app_passkey_subject_of(uuid)', 'app_passkey_attach(uuid, text)',
        'app_passkey_insert(uuid, text, bytea, jsonb, bigint, boolean, boolean, text)',
        'app_passkey_find(bytea)', 'app_passkey_credentials_of(uuid)',
        'app_passkey_record_use(uuid, jsonb, bigint, boolean, boolean)',
        'app_passkey_flag(uuid)', 'app_passkey_list()', 'app_passkey_rename(uuid, text)',
        'app_passkey_remove(uuid)', 'app_passkey_codes_left()',
        'app_passkey_regenerate(bytea[])', 'app_passkey_seed_recovery(uuid, bytea[])',
        'app_passkey_recovery_lookup(bytea)', 'app_passkey_recovery_consume(bytea, uuid)',
        'app_passkey_claim_peek(bytea)', 'app_passkey_claim_consume(bytea, uuid)',
        'app_passkey_claim_self(bytea, integer)'
    ] LOOP
        EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', v_function);
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO app_runtime', v_function);
    END LOOP;
END;
$$;

-- Deleting an account (`app_delete_account`, 0014) tombstones the user row and leaves it in
-- place, so the foreign keys above do not fire. This does what they would: a person who deletes
-- their account takes their passkeys, recovery codes, claim links and any ceremony with them.
-- A trigger, not a new body for `app_delete_account`, so later changes to that function keep
-- working alongside it.
CREATE FUNCTION app_passkey_forget_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    DELETE FROM passkey_credentials WHERE user_id = NEW.id;
    DELETE FROM passkey_recovery_codes WHERE user_id = NEW.id;
    DELETE FROM passkey_claims WHERE user_id = NEW.id;
    DELETE FROM passkey_ceremonies WHERE user_id = NEW.id;
    RETURN NULL;
END;
$$;

REVOKE EXECUTE ON FUNCTION app_passkey_forget_user() FROM PUBLIC;

CREATE TRIGGER users_forget_passkeys
    AFTER UPDATE OF deleted_at ON users
    FOR EACH ROW
    WHEN (OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL)
    EXECUTE FUNCTION app_passkey_forget_user();
