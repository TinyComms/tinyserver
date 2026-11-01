-- The server's name and icon, for the sign-in pages.
--
-- Someone signing in is not a member yet, so `server_settings` (visible to members only) is
-- closed to them. The passkey pages show the server's name and icon so a person can see which
-- community they are signing in to. This is the only way they are read before sign-in, and the
-- pages call it only for someone who holds a live sign-in or a claim link the owner made:
-- someone who merely knows the address is shown nothing.
CREATE FUNCTION app_server_face()
RETURNS TABLE (name text, icon bytea, icon_type text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT s.name, s.icon, s.icon_type FROM server_settings s;
$$;

REVOKE EXECUTE ON FUNCTION app_server_face() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_server_face() TO app_runtime;
