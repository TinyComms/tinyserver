-- First-run setup: what this community collects about its members, chosen once by the owner and
-- changeable by the owner afterwards.
--
-- Three choices, each of which the server enforces, not just records:
--
--   provider_profile    what is kept from an identity provider (SSO) when someone first signs
--                       in with it. 'full' is the name and the email address, as before. 'name'
--                       keeps the name and never an email address. 'none' keeps neither: the
--                       account starts as "Member" and the person picks a name. Accounts made
--                       with a passkey are not touched by this: they have no provider, and the
--                       name is the one the person typed.
--   activity_visibility who may see when a member was last connected and how they
--                       joined (by invite or through a group). 'everyone' is as before. 'admins' is holders of manage_server.
--                       'nobody' stops the server recording last-seen at all, and clears what
--                       was recorded.
--   sign_in_methods     'any' is every method this deployment offers. 'passkey' refuses a new
--                       sign-in through an identity provider; sessions already open, and the
--                       passkeys people have, are untouched.
--
-- The defaults are what the server did before this migration, so an upgrade changes nothing
-- until the owner chooses. `setup_completed_at` is null until they have, which is how a client
-- knows to offer the choice.

ALTER TABLE server_settings
    ADD COLUMN provider_profile text NOT NULL DEFAULT 'full'
        CHECK (provider_profile IN ('full', 'name', 'none')),
    ADD COLUMN activity_visibility text NOT NULL DEFAULT 'everyone'
        CHECK (activity_visibility IN ('everyone', 'admins', 'nobody')),
    ADD COLUMN sign_in_methods text NOT NULL DEFAULT 'any'
        CHECK (sign_in_methods IN ('any', 'passkey')),
    ADD COLUMN setup_completed_at timestamptz,
    ADD COLUMN setup_completed_by uuid REFERENCES users (id) ON DELETE SET NULL;

-- The three choices, for sign-in, which has no member yet and so cannot read server_settings.
CREATE FUNCTION app_posture()
RETURNS TABLE (provider_profile text, activity_visibility text, sign_in_methods text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT s.provider_profile, s.activity_visibility, s.sign_in_methods FROM server_settings s;
$$;

CREATE FUNCTION app_activity_visibility()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT activity_visibility FROM server_settings;
$$;

-- Nothing is recorded when the owner chose 'nobody'. `app_seen` is what the live hub calls.
CREATE OR REPLACE FUNCTION app_seen(p_users uuid[])
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
    UPDATE memberships SET last_seen_at = now()
    WHERE user_id = ANY (p_users)
      AND (SELECT activity_visibility FROM server_settings) <> 'nobody';
$$;

-- What the setup page needs to say: whether it has been done, and what the choices would touch.
-- Owners only. `members_without_passkey` counts the people who could not sign in under
-- 'passkey' until they add one.
CREATE FUNCTION app_setup_state()
RETURNS TABLE (
    completed_at timestamptz,
    provider_profile text,
    activity_visibility text,
    sign_in_methods text,
    members integer,
    members_without_passkey integer,
    emails_stored integer,
    owner_has_passkey boolean
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
             WHERE NOT EXISTS (SELECT 1 FROM passkey_credentials c WHERE c.user_id = m.user_id)),
           (SELECT count(*)::integer FROM users u
             WHERE u.email IS NOT NULL
               AND EXISTS (SELECT 1 FROM memberships m WHERE m.user_id = u.id)),
           EXISTS (SELECT 1 FROM passkey_credentials c WHERE c.user_id = app_uid())
    FROM server_settings s;
END;
$$;

-- Applies the owner's choices and marks setup done. All or nothing.
--
-- Refuses, with a message the API maps:
--   'forbidden'                      not an owner.
--   'passkeys_unavailable'           'passkey' on a deployment with no passkey sign-in.
--   'owner_needs_passkey'            'passkey' while the owner has none, which would lock the
--                                    owner out at the next sign-in.
--   'members_without_passkey:<n>'    'passkey' while n members have none, unless p_allow_lockout.
--
-- Each argument is the new value, or null to leave a choice as it is. Erasing emails and
-- clearing last-seen are one-way, and only happen when asked for (emails) or when the choice
-- itself says so ('nobody').
CREATE FUNCTION app_setup_apply(
    p_provider_profile text,
    p_activity_visibility text,
    p_sign_in_methods text,
    p_erase_emails boolean,
    p_allow_lockout boolean,
    p_passkeys_available boolean
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
        IF NOT p_passkeys_available THEN
            RAISE EXCEPTION 'passkeys_unavailable' USING ERRCODE = '22023';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM passkey_credentials WHERE user_id = v_user) THEN
            RAISE EXCEPTION 'owner_needs_passkey' USING ERRCODE = '22023';
        END IF;
        SELECT count(*)::integer INTO v_lacking
        FROM memberships m
        WHERE NOT EXISTS (SELECT 1 FROM passkey_credentials c WHERE c.user_id = m.user_id);
        IF v_lacking > 0 AND NOT p_allow_lockout THEN
            RAISE EXCEPTION 'members_without_passkey:%', v_lacking USING ERRCODE = '22023';
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
        'app_posture()', 'app_activity_visibility()', 'app_setup_state()',
        'app_setup_apply(text, text, text, boolean, boolean, boolean)'
    ] LOOP
        EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', v_function);
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO app_runtime', v_function);
    END LOOP;
END;
$$;
