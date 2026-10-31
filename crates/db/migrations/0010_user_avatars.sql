-- A member's own picture. PNG, JPEG, or WebP, at most 256 KiB, same ceiling as the server icon.
-- The three columns are set and cleared together. `avatar_sha` is what the member list sends;
-- the bytes are fetched from GET /v1/users/{id}/avatar.

ALTER TABLE users
    ADD COLUMN avatar bytea,
    ADD COLUMN avatar_sha text,
    ADD COLUMN avatar_type text;

ALTER TABLE users
    ADD CONSTRAINT users_avatar_bytes CHECK (avatar IS NULL OR octet_length(avatar) <= 262144),
    ADD CONSTRAINT users_avatar_sha CHECK (avatar_sha IS NULL OR avatar_sha ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT users_avatar_type CHECK (avatar_type IS NULL OR avatar_type IN ('image/png', 'image/jpeg', 'image/webp')),
    ADD CONSTRAINT users_avatar_together CHECK (
        (avatar IS NULL) = (avatar_sha IS NULL)
        AND (avatar IS NULL) = (avatar_type IS NULL)
    );

-- Live events that already send app_member_json now include the picture's hash, or null.
CREATE OR REPLACE FUNCTION app_member_json(p_user uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT jsonb_build_object(
        'user_id', u.id,
        'display_name', u.display_name,
        'role', app_member_role(u.id),
        'owner', app_owner_of(u.id),
        'roles', to_jsonb(app_roles_of(u.id)),
        'avatar', u.avatar_sha
    )
    FROM users u WHERE u.id = p_user;
$$;
