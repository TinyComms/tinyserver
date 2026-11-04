-- Sign-in as one switch the owner holds. `sign_in_methods` now says which kind of sign-in the
-- server accepts from people who are not yet members:
--
--   'provider'  an identity provider. The default.
--   'any'       a provider or a passkey.
--   'passkey'   a passkey only.
--
-- 0031 had 'any' and 'passkey'. Today 'any' on a server with no passkeys was provider-only, so
-- moving those rows to 'provider' changes nothing anyone sees.

-- 0031's check is unnamed, so find the name it was given.
DO $$
DECLARE
    v_name text;
BEGIN
    SELECT conname INTO v_name
    FROM pg_constraint
    WHERE conrelid = 'server_settings'::regclass
      AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%sign_in_methods%';
    IF v_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE server_settings DROP CONSTRAINT %I', v_name);
    END IF;
END;
$$;

ALTER TABLE server_settings
    ADD CHECK (sign_in_methods IN ('provider', 'any', 'passkey')),
    ALTER COLUMN sign_in_methods SET DEFAULT 'provider';

UPDATE server_settings SET sign_in_methods = 'provider' WHERE sign_in_methods = 'any';

-- What the setup page needs to say. As in 0031, plus the people who have no identity-provider
-- sign-in (`members_without_provider`) and whether the owner has one (`owner_has_provider`).
-- A passkey's own identity has the issuer 'tinyserver:passkey' and does not count as a
-- provider. Both `members_without_*` counts leave out banned members, who cannot sign in
-- anyway; that also changes `members_without_passkey` from 0031.
-- The result columns differ from 0031, so the old function goes first.
DROP FUNCTION app_setup_state();
CREATE FUNCTION app_setup_state()
RETURNS TABLE (
    completed_at timestamptz,
    provider_profile text,
    activity_visibility text,
    sign_in_methods text,
    members integer,
    members_without_passkey integer,
    members_without_provider integer,
    emails_stored integer,
    owner_has_passkey boolean,
    owner_has_provider boolean
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    IF NOT app_owner_of(app_uid()) THEN
        RAISE EXCEPTION 'forbidden' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY
    SELECT s.setup_completed_at, s.provider_profile, s.activity_visibility, s.sign_in_methods,
           (SELECT count(*)::integer FROM memberships),
           (SELECT count(*)::integer FROM memberships m
             WHERE NOT app_banned(m.user_id)
               AND NOT EXISTS (SELECT 1 FROM passkey_credentials c WHERE c.user_id = m.user_id)),
           (SELECT count(*)::integer FROM memberships m
             WHERE NOT app_banned(m.user_id)
               AND NOT EXISTS (SELECT 1 FROM user_identities i
                                WHERE i.user_id = m.user_id AND i.issuer <> 'tinyserver:passkey')),
           (SELECT count(*)::integer FROM users u
             WHERE u.email IS NOT NULL
               AND EXISTS (SELECT 1 FROM memberships m WHERE m.user_id = u.id)),
           EXISTS (SELECT 1 FROM passkey_credentials c WHERE c.user_id = app_uid()),
           EXISTS (SELECT 1 FROM user_identities i
                    WHERE i.user_id = app_uid() AND i.issuer <> 'tinyserver:passkey')
    FROM server_settings s;
END;
$$;

-- Applies the owner's choices and marks setup done. All or nothing.
--
-- Refuses, with a message the API maps:
--   'forbidden'                      not an owner.
--   'owner_needs_passkey'            to 'passkey' while the owner has none, which would lock the
--                                    owner out at the next sign-in.
--   'members_without_passkey:<n>'    to 'passkey' while n members have none, unless p_allow_lockout.
--   'owner_needs_provider'           to 'provider' while the owner has no provider sign-in.
--   'members_without_provider:<n>'   to 'provider' while n members have none, unless p_allow_lockout.
--
-- Banned members are not counted. Each argument is the new value, or null to leave a choice as
-- it is. Erasing emails and clearing last-seen are one-way, and only happen when asked for
-- (emails) or when the choice itself says so ('nobody').
DROP FUNCTION app_setup_apply(text, text, text, boolean, boolean, boolean);
CREATE FUNCTION app_setup_apply(
    p_provider_profile text,
    p_activity_visibility text,
    p_sign_in_methods text,
    p_erase_emails boolean,
    p_allow_lockout boolean
)
RETURNS TABLE (emails_erased integer, last_seen_cleared integer)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_user uuid := app_uid();
    v_erased integer := 0;
    v_cleared integer := 0;
    v_lacking integer;
    v_sign_in text;
    v_activity text;
BEGIN
    IF v_user IS NULL OR NOT app_owner_of(v_user) THEN
        RAISE EXCEPTION 'forbidden' USING ERRCODE = '42501';
    END IF;
    -- One setup at a time, and not alongside a change of owners.
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.owners'));

    v_sign_in := coalesce(p_sign_in_methods, (SELECT sign_in_methods FROM server_settings));
    v_activity := coalesce(p_activity_visibility, (SELECT activity_visibility FROM server_settings));

    IF v_sign_in = 'passkey'
       AND p_sign_in_methods IS NOT NULL
       AND (SELECT sign_in_methods FROM server_settings) <> 'passkey' THEN
        IF NOT EXISTS (SELECT 1 FROM passkey_credentials WHERE user_id = v_user) THEN
            RAISE EXCEPTION 'owner_needs_passkey' USING ERRCODE = '22023';
        END IF;
        SELECT count(*)::integer INTO v_lacking
        FROM memberships m
        WHERE NOT app_banned(m.user_id)
          AND NOT EXISTS (SELECT 1 FROM passkey_credentials c WHERE c.user_id = m.user_id);
        IF v_lacking > 0 AND NOT p_allow_lockout THEN
            RAISE EXCEPTION 'members_without_passkey:%', v_lacking USING ERRCODE = '22023';
        END IF;
    END IF;

    IF v_sign_in = 'provider'
       AND p_sign_in_methods IS NOT NULL
       AND (SELECT sign_in_methods FROM server_settings) <> 'provider' THEN
        IF NOT EXISTS (SELECT 1 FROM user_identities i
                        WHERE i.user_id = v_user AND i.issuer <> 'tinyserver:passkey') THEN
            RAISE EXCEPTION 'owner_needs_provider' USING ERRCODE = '22023';
        END IF;
        SELECT count(*)::integer INTO v_lacking
        FROM memberships m
        WHERE NOT app_banned(m.user_id)
          AND NOT EXISTS (SELECT 1 FROM user_identities i
                           WHERE i.user_id = m.user_id AND i.issuer <> 'tinyserver:passkey');
        IF v_lacking > 0 AND NOT p_allow_lockout THEN
            RAISE EXCEPTION 'members_without_provider:%', v_lacking USING ERRCODE = '22023';
        END IF;
    END IF;

    UPDATE server_settings
    SET provider_profile = coalesce(p_provider_profile, provider_profile),
        activity_visibility = v_activity,
        sign_in_methods = v_sign_in,
        setup_completed_at = coalesce(setup_completed_at, now()),
        setup_completed_by = coalesce(setup_completed_by, v_user);

    IF p_erase_emails THEN
        UPDATE users u SET email = NULL
        WHERE u.email IS NOT NULL
          AND EXISTS (SELECT 1 FROM memberships m WHERE m.user_id = u.id);
        GET DIAGNOSTICS v_erased = ROW_COUNT;
    END IF;
    IF v_activity = 'nobody' THEN
        UPDATE memberships SET last_seen_at = NULL WHERE last_seen_at IS NOT NULL;
        GET DIAGNOSTICS v_cleared = ROW_COUNT;
    END IF;
    RETURN QUERY SELECT v_erased, v_cleared;
END;
$$;

DO $$
DECLARE
    v_function text;
BEGIN
    FOREACH v_function IN ARRAY ARRAY[
        'app_setup_state()',
        'app_setup_apply(text, text, text, boolean, boolean)'
    ] LOOP
        EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', v_function);
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO app_runtime', v_function);
    END LOOP;
END;
$$;
