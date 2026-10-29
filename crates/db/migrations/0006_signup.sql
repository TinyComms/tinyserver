-- An invite can make the person's account at the provider. When the provider can make sign-up
-- links (Pocket ID), a sign-in that carries an invite offers "I'm new here", and tinyserver asks
-- the provider for a single-use sign-up link. One per pending sign-in, and only while the invite
-- could still be accepted.

-- When this pending sign-in asked the provider for a sign-up link. At most once.
ALTER TABLE auth_pending ADD COLUMN signup_at timestamptz;
GRANT UPDATE (signup_at) ON auth_pending TO app_runtime;

-- Whether the invite with this hash could be accepted now: known, not expired, not used up.
-- The runtime cannot read invites without a signed-in caller, so this looks past RLS and says
-- nothing but yes or no.
CREATE FUNCTION app_invite_usable(p_token_hash bytea)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT EXISTS (
        SELECT 1 FROM invites
        WHERE token_hash = p_token_hash
          AND (expires_at IS NULL OR expires_at > now())
          AND (max_uses IS NULL OR uses < max_uses)
    );
$$;

REVOKE EXECUTE ON FUNCTION app_invite_usable(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_invite_usable(bytea) TO app_runtime;
