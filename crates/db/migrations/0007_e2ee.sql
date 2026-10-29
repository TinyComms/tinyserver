-- End-to-end encrypted calls. The keys live in the apps and the MLS state in memory; nothing of
-- either is ever stored. What is stored is one room setting: only apps that encrypt end to end
-- may join this room's call.
ALTER TABLE rooms ADD COLUMN e2ee_required boolean NOT NULL DEFAULT false;

-- The call check reads the setting with the rest. Its result changes shape, so it is made again.
DROP FUNCTION app_call_access(uuid, uuid);

CREATE FUNCTION app_call_access(p_room uuid, p_user uuid)
RETURNS TABLE (perms bigint, user_limit integer, timed_out boolean, e2ee_required boolean)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT app_room_perms_of(r.id, p_user),
           r.user_limit,
           coalesce((SELECT m.timeout_until > now() FROM memberships m WHERE m.user_id = p_user),
                    false),
           r.e2ee_required
    FROM rooms r
    WHERE r.id = p_room;
$$;

REVOKE EXECUTE ON FUNCTION app_call_access(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_call_access(uuid, uuid) TO app_runtime;
