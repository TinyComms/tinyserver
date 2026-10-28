-- Server management: settings, roles with permissions, an owner flag, categories, room settings
-- and per-room overrides, bans, timeouts, multi-use invites, and audit rows with a subject and a
-- reason.
--
-- Authorization moves from the `app.role` setting to permissions read from the database for
-- `app.user_id`. Permission bits are in docs/calls.md; every function below that writes a role,
-- a member's roles, the owner flag, a ban, a timeout, or an override checks the caller's
-- permission and the hierarchy itself, because app_owner bypasses RLS.
--
-- Bits: 0 view_channel, 1 connect, 2 speak, 3 video, 4 share_screen, 5 voice_activity,
-- 6 priority_speaker, 7 create_invites, 8 manage_invites, 9 manage_channels, 10 manage_roles,
-- 11 kick_members, 12 ban_members, 13 timeout_members, 14 mute_members, 15 deafen_members,
-- 16 move_members, 17 disconnect_members, 18 view_audit_log, 19 manage_server.
-- All bits: 1048575. Channel-scoped bits: 246399. @everyone by default: 63.

-- Server settings, one row.

CREATE TABLE server_settings (
    only_row boolean PRIMARY KEY DEFAULT true CHECK (only_row),
    name text NOT NULL DEFAULT 'Tiny server' CHECK (char_length(name) BETWEEN 1 AND 80),
    description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 500),
    welcome text NOT NULL DEFAULT '' CHECK (char_length(welcome) <= 2000),
    icon bytea CHECK (octet_length(icon) <= 262144),
    icon_sha text CHECK (icon_sha ~ '^[0-9a-f]{64}$'),
    icon_type text CHECK (icon_type IN ('image/png', 'image/jpeg', 'image/webp')),
    default_room_id uuid REFERENCES rooms (id) ON DELETE SET NULL,
    afk_room_id uuid REFERENCES rooms (id) ON DELETE SET NULL,
    afk_timeout_secs integer NOT NULL DEFAULT 0 CHECK (afk_timeout_secs BETWEEN 0 AND 86400),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((icon IS NULL) = (icon_sha IS NULL) AND (icon IS NULL) = (icon_type IS NULL))
);

INSERT INTO server_settings (created_at)
SELECT coalesce((SELECT min(created_at) FROM memberships), now());

-- Roles. @everyone is the one default role at position 0; every member has it without a row in
-- member_roles. A higher position is more senior. Positions are unique once a write commits.

CREATE TABLE roles (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
    color text CHECK (color ~ '^#[0-9A-F]{6}$'),
    position integer NOT NULL CHECK (position >= 0),
    permissions bigint NOT NULL DEFAULT 0 CHECK (permissions >= 0 AND permissions <= 1048575),
    hoist boolean NOT NULL DEFAULT false,
    is_default boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT roles_position_unique UNIQUE (position) DEFERRABLE INITIALLY DEFERRED,
    CHECK (is_default = (position = 0))
);

CREATE UNIQUE INDEX roles_one_default ON roles (is_default) WHERE is_default;

INSERT INTO roles (name, position, permissions, is_default) VALUES ('@everyone', 0, 63, true);
INSERT INTO roles (name, color, position, permissions, hoist)
VALUES ('Admin', '#3B82F6', 1, 1048575, true);

-- The owner flag replaces the owner role. Owners have every permission everywhere.
ALTER TABLE memberships ADD COLUMN owner boolean NOT NULL DEFAULT false;
ALTER TABLE memberships ADD COLUMN last_seen_at timestamptz;
ALTER TABLE memberships ADD COLUMN joined_via text CHECK (joined_via IN ('invite', 'groups'));
ALTER TABLE memberships ADD COLUMN timeout_until timestamptz;

UPDATE memberships SET owner = (role = 'owner');

CREATE TABLE member_roles (
    user_id uuid NOT NULL REFERENCES memberships (user_id) ON DELETE CASCADE,
    role_id uuid NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX member_roles_role ON member_roles (role_id);

INSERT INTO member_roles (user_id, role_id)
SELECT m.user_id, r.id FROM memberships m CROSS JOIN roles r
WHERE m.role = 'admin' AND r.name = 'Admin' AND NOT r.is_default;

UPDATE memberships m SET joined_via = 'groups'
WHERE EXISTS (SELECT 1 FROM audit_log a
              WHERE a.actor_id = m.user_id AND a.action = 'member.join'
                AND a.detail->>'via' = 'groups');
UPDATE memberships m SET joined_via = 'invite'
WHERE joined_via IS NULL
  AND EXISTS (SELECT 1 FROM audit_log a WHERE a.actor_id = m.user_id AND a.action = 'invite.accept');

DROP POLICY memberships_select ON memberships;
ALTER TABLE memberships DROP COLUMN role;

-- Categories and room settings.

CREATE TABLE categories (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
    position integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE rooms ADD COLUMN category_id uuid REFERENCES categories (id) ON DELETE SET NULL;
ALTER TABLE rooms ADD COLUMN position integer NOT NULL DEFAULT 0;
ALTER TABLE rooms ADD COLUMN topic text NOT NULL DEFAULT '' CHECK (char_length(topic) <= 1024);
ALTER TABLE rooms ADD COLUMN user_limit integer NOT NULL DEFAULT 0
    CHECK (user_limit BETWEEN 0 AND 99);
ALTER TABLE rooms ADD COLUMN bitrate_kbps integer NOT NULL DEFAULT 64
    CHECK (bitrate_kbps BETWEEN 16 AND 128);
ALTER TABLE rooms ADD COLUMN ptt_only boolean NOT NULL DEFAULT false;
ALTER TABLE rooms ADD COLUMN video_enabled boolean NOT NULL DEFAULT true;

UPDATE rooms r SET position = o.n
FROM (SELECT id, (row_number() OVER (ORDER BY created_at, id) - 1)::integer AS n FROM rooms) o
WHERE o.id = r.id;

CREATE TABLE room_overrides (
    room_id uuid NOT NULL REFERENCES rooms (id) ON DELETE CASCADE,
    role_id uuid NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    allow bigint NOT NULL DEFAULT 0 CHECK (allow >= 0 AND allow & ~246399::bigint = 0),
    deny bigint NOT NULL DEFAULT 0 CHECK (deny >= 0 AND deny & ~246399::bigint = 0),
    PRIMARY KEY (room_id, role_id),
    CHECK (allow & deny = 0)
);

CREATE INDEX room_overrides_role ON room_overrides (role_id);

-- Bans. One row per person, and one per (issuer, subject) they signed in with, so neither an
-- invite nor a joining group nor a fresh sign-in lets them back.

CREATE TABLE bans (
    user_id uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    reason text CHECK (char_length(reason) BETWEEN 1 AND 512),
    banned_by uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz
);

CREATE TABLE ban_identities (
    issuer text NOT NULL,
    subject text NOT NULL,
    user_id uuid NOT NULL REFERENCES bans (user_id) ON DELETE CASCADE,
    PRIMARY KEY (issuer, subject)
);

CREATE INDEX ban_identities_user ON ban_identities (user_id);

-- Invites: a label, several uses, roles to give, and optionally no expiry.

ALTER TABLE invites ADD COLUMN label text CHECK (char_length(label) BETWEEN 1 AND 80);
ALTER TABLE invites ADD COLUMN max_uses integer CHECK (max_uses BETWEEN 1 AND 1000);
ALTER TABLE invites ADD COLUMN uses integer NOT NULL DEFAULT 0 CHECK (uses >= 0);
ALTER TABLE invites ADD COLUMN role_ids uuid[] NOT NULL DEFAULT '{}';
ALTER TABLE invites ALTER COLUMN expires_at DROP NOT NULL;

UPDATE invites SET max_uses = 1, uses = CASE WHEN accepted_at IS NULL THEN 0 ELSE 1 END;
UPDATE invites SET role_ids = ARRAY[(SELECT id FROM roles WHERE name = 'Admin' AND NOT is_default)]
WHERE role = 'admin';

-- Audit rows name the person acted on and the reason given.

ALTER TABLE audit_log ADD COLUMN subject_user_id uuid;
ALTER TABLE audit_log ADD COLUMN reason text CHECK (char_length(reason) <= 512);

UPDATE audit_log SET subject_user_id = (detail->>'user_id')::uuid
WHERE detail->>'user_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';

CREATE INDEX audit_log_actor ON audit_log (actor_id, id);

-- Who is asking, and what they may do.

CREATE FUNCTION app_uid()
RETURNS uuid
LANGUAGE sql
STABLE
AS $$
    SELECT nullif(current_setting('app.user_id', true), '')::uuid;
$$;

CREATE FUNCTION app_is_member_of(p_user uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT EXISTS (SELECT 1 FROM memberships WHERE user_id = p_user);
$$;

CREATE FUNCTION app_owner_of(p_user uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT coalesce((SELECT owner FROM memberships WHERE user_id = p_user), false);
$$;

-- Base permissions: @everyone OR the member's roles. Every bit for an owner, none for a
-- non-member.
CREATE FUNCTION app_perms_of(p_user uuid)
RETURNS bigint
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT CASE
        WHEN m.user_id IS NULL THEN 0::bigint
        WHEN m.owner THEN 1048575::bigint
        ELSE coalesce((SELECT permissions FROM roles WHERE is_default), 0)
             | coalesce((SELECT bit_or(r.permissions)
                         FROM member_roles mr JOIN roles r ON r.id = mr.role_id
                         WHERE mr.user_id = p_user), 0)
    END
    FROM (SELECT p_user AS u) x
    LEFT JOIN memberships m ON m.user_id = x.u;
$$;

-- Permissions in one room: the base, then the @everyone override (deny, then allow), then the
-- OR of the member's other roles' overrides (deny, then allow).
CREATE FUNCTION app_room_perms_of(p_room uuid, p_user uuid)
RETURNS bigint
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_owner boolean;
    v_perms bigint;
    v_allow bigint;
    v_deny bigint;
BEGIN
    SELECT owner INTO v_owner FROM memberships WHERE user_id = p_user;
    IF v_owner IS NULL THEN
        RETURN 0;
    END IF;
    IF v_owner THEN
        RETURN 1048575;
    END IF;
    v_perms := app_perms_of(p_user);
    SELECT o.allow, o.deny INTO v_allow, v_deny
    FROM room_overrides o JOIN roles r ON r.id = o.role_id
    WHERE o.room_id = p_room AND r.is_default;
    IF FOUND THEN
        v_perms := (v_perms & ~v_deny) | v_allow;
    END IF;
    SELECT coalesce(bit_or(o.allow), 0), coalesce(bit_or(o.deny), 0) INTO v_allow, v_deny
    FROM room_overrides o JOIN member_roles mr ON mr.role_id = o.role_id
    WHERE o.room_id = p_room AND mr.user_id = p_user;
    RETURN (v_perms & ~v_deny) | v_allow;
END;
$$;

-- The highest position among a member's roles, 0 with only @everyone. Owners rank above
-- everyone; a non-member is -1.
CREATE FUNCTION app_rank_of(p_user uuid)
RETURNS integer
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT CASE
        WHEN m.user_id IS NULL THEN -1
        WHEN m.owner THEN 2147483647
        ELSE coalesce((SELECT max(r.position)
                       FROM member_roles mr JOIN roles r ON r.id = mr.role_id
                       WHERE mr.user_id = p_user), 0)
    END
    FROM (SELECT p_user AS u) x
    LEFT JOIN memberships m ON m.user_id = x.u;
$$;

CREATE FUNCTION app_roles_of(p_user uuid)
RETURNS text[]
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT coalesce(array_agg(mr.role_id::text ORDER BY r.position DESC), '{}')
    FROM member_roles mr JOIN roles r ON r.id = mr.role_id
    WHERE mr.user_id = p_user;
$$;

CREATE FUNCTION app_perms()
RETURNS bigint
LANGUAGE sql
STABLE
AS $$
    SELECT app_perms_of(app_uid());
$$;

CREATE FUNCTION app_has(p_bits bigint)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT app_perms() & p_bits = p_bits;
$$;

CREATE FUNCTION app_room_has(p_room uuid, p_bits bigint)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT app_room_perms_of(p_room, app_uid()) & p_bits = p_bits;
$$;

CREATE FUNCTION app_is_member()
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT app_is_member_of(app_uid());
$$;

CREATE FUNCTION app_require(p_bits bigint)
RETURNS void
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    IF NOT app_has(p_bits) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
END;
$$;

-- The legacy role string: owner, admin when any of the member's roles manages the server or its
-- roles, else member. NULL for a non-member.
CREATE OR REPLACE FUNCTION app_member_role(p_user_id uuid)
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT CASE
        WHEN m.user_id IS NULL THEN NULL
        WHEN m.owner THEN 'owner'
        WHEN app_perms_of(p_user_id) & (524288 | 1024) <> 0 THEN 'admin'
        ELSE 'member'
    END
    FROM (SELECT p_user_id AS u) x
    LEFT JOIN memberships m ON m.user_id = x.u;
$$;

-- The role a legacy "admin" means: the most senior role that manages the server or its roles.
CREATE FUNCTION app_admin_role()
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT id FROM roles
    WHERE NOT is_default AND permissions & (524288 | 1024) <> 0
    ORDER BY position DESC
    LIMIT 1;
$$;

CREATE FUNCTION app_banned(p_user uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT EXISTS (
        SELECT 1 FROM bans b
        WHERE (b.expires_at IS NULL OR b.expires_at > now())
          AND (b.user_id = p_user
               OR b.user_id IN (SELECT bi.user_id
                                FROM ban_identities bi
                                JOIN user_identities ui
                                  ON ui.issuer = bi.issuer AND ui.subject = bi.subject
                                WHERE ui.user_id = p_user))
    );
$$;

-- Raises unless the caller may act on p_target: owners may act on anyone, anyone else only on
-- a non-owner whose rank is below theirs.
CREATE FUNCTION app_check_target(p_target uuid)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_actor uuid := app_uid();
    v_actor_owner boolean;
    v_target_owner boolean;
BEGIN
    SELECT owner INTO v_target_owner FROM memberships WHERE user_id = p_target;
    IF v_target_owner IS NULL THEN
        RAISE EXCEPTION 'member not found' USING ERRCODE = 'P0002';
    END IF;
    SELECT owner INTO v_actor_owner FROM memberships WHERE user_id = v_actor;
    IF v_actor_owner IS NULL THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    IF v_actor_owner THEN
        RETURN;
    END IF;
    IF v_target_owner OR app_rank_of(p_target) >= app_rank_of(v_actor) THEN
        RAISE EXCEPTION 'hierarchy' USING ERRCODE = '42501';
    END IF;
END;
$$;

-- What live events and the member list say about one person.
CREATE FUNCTION app_member_json(p_user uuid)
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
        'roles', to_jsonb(app_roles_of(u.id))
    )
    FROM users u WHERE u.id = p_user;
$$;

CREATE FUNCTION app_audit(
    p_action text,
    p_subject text,
    p_detail jsonb,
    p_subject_user uuid,
    p_reason text
)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
    INSERT INTO audit_log (actor_id, action, subject, detail, subject_user_id, reason)
    VALUES (app_uid(), p_action, p_subject, p_detail, p_subject_user, nullif(btrim(p_reason), ''));
$$;

-- Roles. Only the role functions write roles and member_roles.

CREATE FUNCTION app_role_create(p_name text, p_color text, p_perms bigint, p_hoist boolean)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_actor uuid := app_uid();
    v_rank integer;
    v_position integer;
    v_id uuid;
BEGIN
    PERFORM app_require(1024);
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.owners'));
    IF NOT app_owner_of(v_actor) AND p_perms & ~app_perms_of(v_actor) <> 0 THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    v_rank := app_rank_of(v_actor);
    IF app_owner_of(v_actor) THEN
        SELECT coalesce(max(position), 0) + 1 INTO v_position FROM roles;
    ELSE
        v_position := greatest(v_rank, 1);
        UPDATE roles SET position = position + 1 WHERE position >= v_position;
    END IF;
    INSERT INTO roles (name, color, position, permissions, hoist)
    VALUES (p_name, p_color, v_position, p_perms, coalesce(p_hoist, false))
    RETURNING id INTO v_id;
    PERFORM app_audit('role.create', 'role',
                      jsonb_build_object('id', v_id, 'name', p_name, 'permissions', p_perms),
                      NULL, NULL);
    RETURN v_id;
END;
$$;

CREATE FUNCTION app_role_update(
    p_id uuid,
    p_name text,
    p_color text,
    p_perms bigint,
    p_hoist boolean
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_actor uuid := app_uid();
    v_role roles%ROWTYPE;
BEGIN
    PERFORM app_require(1024);
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.owners'));
    SELECT * INTO v_role FROM roles WHERE id = p_id FOR UPDATE;
    IF v_role.id IS NULL THEN
        RAISE EXCEPTION 'role not found' USING ERRCODE = 'P0002';
    END IF;
    IF NOT app_owner_of(v_actor) THEN
        IF v_role.position >= app_rank_of(v_actor) THEN
            RAISE EXCEPTION 'hierarchy' USING ERRCODE = '42501';
        END IF;
        IF (p_perms # v_role.permissions) & ~app_perms_of(v_actor) <> 0 THEN
            RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
        END IF;
    END IF;
    IF v_role.is_default AND p_name <> v_role.name THEN
        RAISE EXCEPTION 'default role' USING ERRCODE = '22023';
    END IF;
    UPDATE roles
    SET name = p_name, color = p_color, permissions = p_perms, hoist = p_hoist
    WHERE id = p_id;
    PERFORM app_audit('role.update', 'role',
                      jsonb_build_object('id', p_id, 'name', p_name, 'color', p_color,
                                         'permissions', p_perms, 'hoist', p_hoist,
                                         'was', jsonb_build_object(
                                             'name', v_role.name, 'color', v_role.color,
                                             'permissions', v_role.permissions,
                                             'hoist', v_role.hoist)),
                      NULL, NULL);
END;
$$;

CREATE FUNCTION app_role_delete(p_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_actor uuid := app_uid();
    v_role roles%ROWTYPE;
BEGIN
    PERFORM app_require(1024);
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.owners'));
    SELECT * INTO v_role FROM roles WHERE id = p_id FOR UPDATE;
    IF v_role.id IS NULL THEN
        RAISE EXCEPTION 'role not found' USING ERRCODE = 'P0002';
    END IF;
    IF v_role.is_default THEN
        RAISE EXCEPTION 'default role' USING ERRCODE = '22023';
    END IF;
    IF NOT app_owner_of(v_actor) AND v_role.position >= app_rank_of(v_actor) THEN
        RAISE EXCEPTION 'hierarchy' USING ERRCODE = '42501';
    END IF;
    DELETE FROM roles WHERE id = p_id;
    UPDATE invites SET role_ids = array_remove(role_ids, p_id) WHERE p_id = ANY (role_ids);
    PERFORM app_audit('role.delete', 'role',
                      jsonb_build_object('id', p_id, 'name', v_role.name), NULL, NULL);
END;
$$;

-- p_ids is every role but @everyone, most senior first. Positions keep their values and move
-- between roles; a non-owner cannot move a role at or above their own rank.
CREATE FUNCTION app_role_order(p_ids uuid[])
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_actor uuid := app_uid();
    v_rank integer;
    v_count integer;
    v_positions integer[];
BEGIN
    PERFORM app_require(1024);
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.owners'));
    SELECT count(*) INTO v_count FROM roles WHERE NOT is_default;
    IF coalesce(array_length(p_ids, 1), 0) <> v_count
       OR (SELECT count(DISTINCT x.v) FROM unnest(p_ids) AS x(v)) <> v_count
       OR EXISTS (SELECT 1 FROM unnest(p_ids) AS x(v)
                  WHERE NOT EXISTS (SELECT 1 FROM roles r WHERE r.id = x.v AND NOT r.is_default))
    THEN
        RAISE EXCEPTION 'invalid order' USING ERRCODE = '22023';
    END IF;
    SELECT array_agg(position ORDER BY position DESC) INTO v_positions
    FROM roles WHERE NOT is_default;
    IF NOT app_owner_of(v_actor) THEN
        v_rank := app_rank_of(v_actor);
        IF EXISTS (
            SELECT 1
            FROM roles r
            JOIN (SELECT p_ids[i] AS id, v_positions[i] AS position
                  FROM generate_subscripts(p_ids, 1) AS i) n ON n.id = r.id
            WHERE n.position <> r.position AND (r.position >= v_rank OR n.position >= v_rank)
        ) THEN
            RAISE EXCEPTION 'hierarchy' USING ERRCODE = '42501';
        END IF;
    END IF;
    UPDATE roles r SET position = n.position
    FROM (SELECT p_ids[i] AS id, v_positions[i] AS position
          FROM generate_subscripts(p_ids, 1) AS i) n
    WHERE n.id = r.id;
    PERFORM app_audit('role.order', 'role', jsonb_build_object('ids', to_jsonb(p_ids)),
                      NULL, NULL);
END;
$$;

-- Replaces a member's roles. Every role added or removed must be below the caller's rank.
CREATE FUNCTION app_set_member_roles(p_user uuid, p_role_ids uuid[])
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_actor uuid := app_uid();
    v_wanted uuid[];
    v_added uuid[];
    v_removed uuid[];
BEGIN
    PERFORM app_require(1024);
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.owners'));
    PERFORM app_check_target(p_user);
    IF EXISTS (SELECT 1 FROM unnest(coalesce(p_role_ids, '{}')) AS x(v)
               WHERE NOT EXISTS (SELECT 1 FROM roles r WHERE r.id = x.v)) THEN
        RAISE EXCEPTION 'role not found' USING ERRCODE = '22023';
    END IF;
    SELECT coalesce(array_agg(DISTINCT r.id), '{}') INTO v_wanted
    FROM roles r WHERE r.id = ANY (coalesce(p_role_ids, '{}')) AND NOT r.is_default;
    SELECT coalesce(array_agg(x.v), '{}') INTO v_added
    FROM unnest(v_wanted) AS x(v)
    WHERE NOT EXISTS (SELECT 1 FROM member_roles mr WHERE mr.user_id = p_user AND mr.role_id = x.v);
    SELECT coalesce(array_agg(role_id), '{}') INTO v_removed
    FROM member_roles WHERE user_id = p_user AND NOT (role_id = ANY (v_wanted));
    IF NOT app_owner_of(v_actor) AND EXISTS (
        SELECT 1 FROM roles WHERE id = ANY (v_added || v_removed)
          AND position >= app_rank_of(v_actor)) THEN
        RAISE EXCEPTION 'hierarchy' USING ERRCODE = '42501';
    END IF;
    DELETE FROM member_roles WHERE user_id = p_user AND role_id = ANY (v_removed);
    INSERT INTO member_roles (user_id, role_id) SELECT p_user, x.v FROM unnest(v_added) AS x(v);
    PERFORM app_audit('member.roles', 'membership',
                      jsonb_build_object('user_id', p_user, 'added', to_jsonb(v_added),
                                         'removed', to_jsonb(v_removed)),
                      p_user, NULL);
    RETURN app_member_role(p_user);
END;
$$;

-- Owners grant and revoke owner, the last owner stays.
CREATE FUNCTION app_set_owner(p_user uuid, p_owner boolean)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_current boolean;
BEGIN
    IF NOT app_owner_of(app_uid()) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.owners'));
    SELECT owner INTO v_current FROM memberships WHERE user_id = p_user;
    IF v_current IS NULL THEN
        RAISE EXCEPTION 'member not found' USING ERRCODE = 'P0002';
    END IF;
    IF v_current AND NOT p_owner AND (SELECT count(*) FROM memberships WHERE owner) <= 1 THEN
        RAISE EXCEPTION 'last owner' USING ERRCODE = '42501';
    END IF;
    UPDATE memberships SET owner = p_owner WHERE user_id = p_user;
    PERFORM app_audit('member.owner', 'membership',
                      jsonb_build_object('user_id', p_user, 'owner', p_owner), p_user, NULL);
    RETURN app_member_role(p_user);
END;
$$;

-- The legacy role change: owner is the owner flag, admin adds the admin role, member takes away
-- every role that manages the server or its roles.
CREATE OR REPLACE FUNCTION app_set_member_role(p_user_id uuid, p_role text)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_actor uuid := app_uid();
    v_actor_owner boolean;
    v_owner boolean;
    v_admin uuid;
BEGIN
    IF p_role NOT IN ('owner', 'admin', 'member') THEN
        RAISE EXCEPTION 'invalid role' USING ERRCODE = '22023';
    END IF;
    IF NOT app_is_member_of(v_actor) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    v_actor_owner := app_owner_of(v_actor);
    IF NOT v_actor_owner THEN
        PERFORM app_require(1024);
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.owners'));
    SELECT owner INTO v_owner FROM memberships WHERE user_id = p_user_id;
    IF v_owner IS NULL THEN
        RAISE EXCEPTION 'member not found' USING ERRCODE = 'P0002';
    END IF;
    IF (v_owner OR p_role = 'owner') AND NOT v_actor_owner THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    IF p_role <> 'owner' AND NOT v_actor_owner THEN
        PERFORM app_require(1024);
        PERFORM app_check_target(p_user_id);
    END IF;
    IF v_owner AND p_role <> 'owner' AND (SELECT count(*) FROM memberships WHERE owner) <= 1 THEN
        RAISE EXCEPTION 'last owner' USING ERRCODE = '42501';
    END IF;

    IF p_role = 'owner' THEN
        UPDATE memberships SET owner = true WHERE user_id = p_user_id;
    ELSIF p_role = 'admin' THEN
        v_admin := app_admin_role();
        IF v_admin IS NULL THEN
            RAISE EXCEPTION 'no admin role' USING ERRCODE = '22023';
        END IF;
        IF NOT v_actor_owner
           AND (SELECT position FROM roles WHERE id = v_admin) >= app_rank_of(v_actor) THEN
            RAISE EXCEPTION 'hierarchy' USING ERRCODE = '42501';
        END IF;
        UPDATE memberships SET owner = false WHERE user_id = p_user_id;
        INSERT INTO member_roles (user_id, role_id) VALUES (p_user_id, v_admin)
        ON CONFLICT DO NOTHING;
    ELSE
        IF NOT v_actor_owner AND EXISTS (
            SELECT 1 FROM member_roles mr JOIN roles r ON r.id = mr.role_id
            WHERE mr.user_id = p_user_id AND r.permissions & (524288 | 1024) <> 0
              AND r.position >= app_rank_of(v_actor)) THEN
            RAISE EXCEPTION 'hierarchy' USING ERRCODE = '42501';
        END IF;
        UPDATE memberships SET owner = false WHERE user_id = p_user_id;
        DELETE FROM member_roles mr USING roles r
        WHERE r.id = mr.role_id AND mr.user_id = p_user_id
          AND r.permissions & (524288 | 1024) <> 0;
    END IF;
    PERFORM app_audit('member.role', 'membership',
                      jsonb_build_object('user_id', p_user_id, 'role', p_role), p_user_id, NULL);
    RETURN app_member_role(p_user_id);
END;
$$;

-- Kick. Owners may remove owners; the last owner stays.
DROP FUNCTION app_remove_member(uuid);

CREATE FUNCTION app_remove_member(p_user_id uuid, p_reason text DEFAULT NULL)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_owner boolean;
BEGIN
    PERFORM app_require(2048);
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.owners'));
    PERFORM app_check_target(p_user_id);
    SELECT owner INTO v_owner FROM memberships WHERE user_id = p_user_id;
    IF v_owner AND (SELECT count(*) FROM memberships WHERE owner) <= 1 THEN
        RAISE EXCEPTION 'last owner' USING ERRCODE = '42501';
    END IF;
    DELETE FROM memberships WHERE user_id = p_user_id;
    PERFORM app_audit('member.remove', 'membership', jsonb_build_object('user_id', p_user_id),
                      p_user_id, p_reason);
END;
$$;

-- Ban. Removes the membership and every session; the caller emits the events.
CREATE FUNCTION app_ban(p_user uuid, p_reason text, p_expires timestamptz)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_member boolean;
    v_owner boolean;
BEGIN
    PERFORM app_require(4096);
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.owners'));
    IF NOT EXISTS (SELECT 1 FROM users WHERE id = p_user) THEN
        RAISE EXCEPTION 'user not found' USING ERRCODE = 'P0002';
    END IF;
    IF p_user = app_uid() THEN
        RAISE EXCEPTION 'hierarchy' USING ERRCODE = '42501';
    END IF;
    IF p_expires IS NOT NULL AND p_expires <= now() THEN
        RAISE EXCEPTION 'expiry in the past' USING ERRCODE = '22023';
    END IF;
    SELECT owner INTO v_owner FROM memberships WHERE user_id = p_user;
    v_member := v_owner IS NOT NULL;
    IF v_member THEN
        PERFORM app_check_target(p_user);
        IF v_owner AND (SELECT count(*) FROM memberships WHERE owner) <= 1 THEN
            RAISE EXCEPTION 'last owner' USING ERRCODE = '42501';
        END IF;
    END IF;
    INSERT INTO bans (user_id, reason, banned_by, expires_at)
    VALUES (p_user, nullif(btrim(p_reason), ''), app_uid(), p_expires)
    ON CONFLICT (user_id) DO UPDATE
    SET reason = EXCLUDED.reason, banned_by = EXCLUDED.banned_by, created_at = now(),
        expires_at = EXCLUDED.expires_at;
    INSERT INTO ban_identities (issuer, subject, user_id)
    SELECT issuer, subject, user_id FROM user_identities WHERE user_id = p_user
    ON CONFLICT (issuer, subject) DO UPDATE SET user_id = EXCLUDED.user_id;
    DELETE FROM memberships WHERE user_id = p_user;
    DELETE FROM sessions WHERE user_id = p_user;
    PERFORM app_audit('member.ban', 'membership',
                      jsonb_build_object('user_id', p_user, 'expires_at', p_expires),
                      p_user, p_reason);
    RETURN v_member;
END;
$$;

CREATE FUNCTION app_unban(p_user uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    PERFORM app_require(4096);
    DELETE FROM bans WHERE user_id = p_user;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'ban not found' USING ERRCODE = 'P0002';
    END IF;
    PERFORM app_audit('member.unban', 'membership', jsonb_build_object('user_id', p_user),
                      p_user, NULL);
END;
$$;

-- Timeout until p_until, at most 28 days; NULL ends it.
CREATE FUNCTION app_timeout(p_user uuid, p_until timestamptz, p_reason text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    PERFORM app_require(8192);
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.owners'));
    PERFORM app_check_target(p_user);
    IF p_until IS NOT NULL AND (p_until <= now() OR p_until > now() + interval '28 days 1 minute')
    THEN
        RAISE EXCEPTION 'timeout out of range' USING ERRCODE = '22023';
    END IF;
    UPDATE memberships SET timeout_until = p_until WHERE user_id = p_user;
    PERFORM app_audit('member.timeout', 'membership',
                      jsonb_build_object('user_id', p_user, 'until', p_until), p_user, p_reason);
END;
$$;

-- Room overrides: manage_roles and manage_channels in that room, for a role below the caller.
CREATE FUNCTION app_set_override(p_room uuid, p_role uuid, p_allow bigint, p_deny bigint)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_actor uuid := app_uid();
    v_position integer;
BEGIN
    PERFORM app_require(1024);
    IF NOT app_room_has(p_room, 512) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM rooms WHERE id = p_room) THEN
        RAISE EXCEPTION 'room not found' USING ERRCODE = 'P0002';
    END IF;
    SELECT position INTO v_position FROM roles WHERE id = p_role;
    IF v_position IS NULL THEN
        RAISE EXCEPTION 'role not found' USING ERRCODE = 'P0002';
    END IF;
    IF NOT app_owner_of(v_actor) AND v_position >= app_rank_of(v_actor) THEN
        RAISE EXCEPTION 'hierarchy' USING ERRCODE = '42501';
    END IF;
    IF p_allow IS NULL THEN
        DELETE FROM room_overrides WHERE room_id = p_room AND role_id = p_role;
    ELSE
        INSERT INTO room_overrides (room_id, role_id, allow, deny)
        VALUES (p_room, p_role, p_allow & 246399, p_deny & 246399 & ~p_allow)
        ON CONFLICT (room_id, role_id) DO UPDATE
        SET allow = EXCLUDED.allow, deny = EXCLUDED.deny;
    END IF;
    PERFORM app_audit('room.override', 'room',
                      jsonb_build_object('id', p_room, 'role_id', p_role,
                                         'allow', p_allow & 246399,
                                         'deny', p_deny & 246399 & ~coalesce(p_allow, 0)),
                      NULL, NULL);
END;
$$;

-- What a person may do in a room's call, read by the live socket without a scope.
CREATE FUNCTION app_call_access(p_room uuid, p_user uuid)
RETURNS TABLE (perms bigint, user_limit integer, timed_out boolean)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT app_room_perms_of(r.id, p_user),
           r.user_limit,
           coalesce((SELECT m.timeout_until > now() FROM memberships m WHERE m.user_id = p_user),
                    false)
    FROM rooms r
    WHERE r.id = p_room;
$$;

-- When people were last connected. The live socket hub calls it in batches.
CREATE FUNCTION app_seen(p_users uuid[])
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
    UPDATE memberships SET last_seen_at = now() WHERE user_id = ANY (p_users);
$$;

-- Invites: several uses, roles, bans honoured.
CREATE OR REPLACE FUNCTION app_accept_invite(p_token_hash bytea, p_user_id uuid)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_invite invites%ROWTYPE;
    v_stamp constant text := 'YYYY-MM-DD"T"HH24:MI:SS"Z"';
BEGIN
    IF app_banned(p_user_id) THEN
        RAISE EXCEPTION 'banned' USING ERRCODE = '42501';
    END IF;
    IF EXISTS (SELECT 1 FROM memberships WHERE user_id = p_user_id) THEN
        RAISE EXCEPTION 'already a member' USING ERRCODE = '23505';
    END IF;

    SELECT * INTO v_invite
    FROM invites
    WHERE token_hash = p_token_hash
      AND (expires_at IS NULL OR expires_at > now())
      AND (max_uses IS NULL OR uses < max_uses)
    FOR UPDATE;
    IF v_invite.id IS NULL THEN
        RAISE EXCEPTION 'invite not found' USING ERRCODE = 'P0002';
    END IF;

    INSERT INTO memberships (user_id, owner, joined_via)
    VALUES (p_user_id, v_invite.role = 'owner', 'invite');
    INSERT INTO member_roles (user_id, role_id)
    SELECT p_user_id, r.id FROM roles r
    WHERE r.id = ANY (v_invite.role_ids) AND NOT r.is_default;
    UPDATE invites
    SET accepted_at = now(), accepted_by = p_user_id, uses = uses + 1
    WHERE id = v_invite.id
    RETURNING * INTO v_invite;
    INSERT INTO audit_log (actor_id, action, subject, detail, subject_user_id)
    VALUES (p_user_id, 'invite.accept', 'membership',
            jsonb_build_object('role', v_invite.role, 'invite_id', v_invite.id,
                               'label', v_invite.label),
            p_user_id);

    PERFORM app_emit('invite.accepted', jsonb_build_object('invite', jsonb_build_object(
        'id', v_invite.id,
        'role', v_invite.role,
        'created_by', v_invite.created_by,
        'expires_at', to_char(v_invite.expires_at AT TIME ZONE 'UTC', v_stamp),
        'accepted_at', to_char(v_invite.accepted_at AT TIME ZONE 'UTC', v_stamp),
        'accepted_by', v_invite.accepted_by,
        'label', v_invite.label,
        'max_uses', v_invite.max_uses,
        'uses', v_invite.uses,
        'role_ids', to_jsonb(v_invite.role_ids)
    )));
    PERFORM app_emit('member.joined', jsonb_build_object('member', app_member_json(p_user_id)));
    RETURN app_member_role(p_user_id);
END;
$$;

CREATE OR REPLACE FUNCTION app_join_by_groups(p_user_id uuid, p_role text, p_issuer text)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_admin uuid;
BEGIN
    IF p_role NOT IN ('admin', 'member') THEN
        RAISE EXCEPTION 'invalid role' USING ERRCODE = '22023';
    END IF;
    IF app_banned(p_user_id) THEN
        RAISE EXCEPTION 'banned' USING ERRCODE = '42501';
    END IF;
    IF EXISTS (SELECT 1 FROM memberships WHERE user_id = p_user_id) THEN
        RAISE EXCEPTION 'already a member' USING ERRCODE = '23505';
    END IF;
    INSERT INTO memberships (user_id, joined_via) VALUES (p_user_id, 'groups');
    IF p_role = 'admin' THEN
        v_admin := app_admin_role();
        IF v_admin IS NOT NULL THEN
            INSERT INTO member_roles (user_id, role_id) VALUES (p_user_id, v_admin);
        END IF;
    END IF;
    INSERT INTO audit_log (actor_id, action, subject, detail, subject_user_id)
    VALUES (p_user_id, 'member.join', 'membership',
            jsonb_build_object('role', p_role, 'via', 'groups', 'issuer', p_issuer), p_user_id);
    PERFORM app_emit('member.joined', jsonb_build_object('member', app_member_json(p_user_id)));
    RETURN app_member_role(p_user_id);
END;
$$;

-- A member in an admin group gets the admin role when they sign in.
CREATE OR REPLACE FUNCTION app_promote_by_groups(p_user_id uuid, p_issuer text)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_role text;
    v_admin uuid;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.owners'));
    v_role := app_member_role(p_user_id);
    IF v_role IS DISTINCT FROM 'member' THEN
        RETURN v_role;
    END IF;
    v_admin := app_admin_role();
    IF v_admin IS NULL THEN
        RETURN v_role;
    END IF;
    INSERT INTO member_roles (user_id, role_id) VALUES (p_user_id, v_admin)
    ON CONFLICT DO NOTHING;
    INSERT INTO audit_log (actor_id, action, subject, detail, subject_user_id)
    VALUES (p_user_id, 'member.role', 'membership',
            jsonb_build_object('user_id', p_user_id, 'role', 'admin', 'via', 'groups',
                               'issuer', p_issuer), p_user_id);
    PERFORM app_emit('member.role', jsonb_build_object('member', app_member_json(p_user_id)));
    RETURN app_member_role(p_user_id);
END;
$$;

-- The sweep also deletes expired bans. Its result is the same as 0004's.
CREATE OR REPLACE FUNCTION app_sweep(
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
    DELETE FROM bans WHERE expires_at <= now();

    expired_events := 0;
    SELECT max(id) INTO v_through FROM outbox WHERE created_at <= now() - interval '24 hours';
    IF v_through IS NOT NULL THEN
        DELETE FROM outbox WHERE id <= v_through;
        GET DIAGNOSTICS expired_events = ROW_COUNT;
        UPDATE outbox_pruned SET through = greatest(through, v_through);
    END IF;
END;
$$;

-- Row level security from permissions.

DROP POLICY rooms_select ON rooms;
DROP POLICY rooms_write ON rooms;
DROP POLICY invites_all ON invites;
DROP POLICY audit_select ON audit_log;

CREATE POLICY memberships_select ON memberships
    FOR SELECT USING (app_is_member());

CREATE POLICY rooms_select ON rooms
    FOR SELECT USING (app_room_has(id, 1));
CREATE POLICY rooms_insert ON rooms
    FOR INSERT WITH CHECK (app_has(512));
CREATE POLICY rooms_update ON rooms
    FOR UPDATE USING (app_room_has(id, 512)) WITH CHECK (app_room_has(id, 512));
CREATE POLICY rooms_delete ON rooms
    FOR DELETE USING (app_room_has(id, 512));

CREATE POLICY invites_select ON invites
    FOR SELECT USING (app_perms() & (128 | 256) <> 0);
-- Roles on an invite need manage_roles and must be below the caller; an invite that never
-- expires needs an owner or manage_server.
CREATE POLICY invites_insert ON invites
    FOR INSERT WITH CHECK (
        app_has(128)
        AND role <> 'owner'
        AND (expires_at IS NOT NULL OR app_owner_of(app_uid()) OR app_has(524288))
        AND (role_ids = '{}' OR (
            app_has(1024)
            AND NOT EXISTS (
                SELECT 1 FROM unnest(role_ids) AS x(v)
                WHERE NOT EXISTS (
                    SELECT 1 FROM roles r
                    WHERE r.id = x.v AND NOT r.is_default
                      AND (app_owner_of(app_uid()) OR r.position < app_rank_of(app_uid())))))));
CREATE POLICY invites_delete ON invites
    FOR DELETE USING (app_has(256) OR (app_has(128) AND created_by = app_uid()));

CREATE POLICY audit_select ON audit_log
    FOR SELECT USING (app_has(262144));

ALTER TABLE server_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE server_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY server_select ON server_settings FOR SELECT USING (app_is_member());
CREATE POLICY server_update ON server_settings
    FOR UPDATE USING (app_has(524288)) WITH CHECK (app_has(524288));

ALTER TABLE roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE roles FORCE ROW LEVEL SECURITY;
CREATE POLICY roles_select ON roles FOR SELECT USING (app_is_member());

ALTER TABLE member_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE member_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY member_roles_select ON member_roles FOR SELECT USING (app_is_member());

ALTER TABLE categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE categories FORCE ROW LEVEL SECURITY;
CREATE POLICY categories_select ON categories FOR SELECT USING (app_is_member());
CREATE POLICY categories_write ON categories
    FOR ALL USING (app_has(512)) WITH CHECK (app_has(512));

ALTER TABLE room_overrides ENABLE ROW LEVEL SECURITY;
ALTER TABLE room_overrides FORCE ROW LEVEL SECURITY;
CREATE POLICY room_overrides_select ON room_overrides FOR SELECT USING (app_is_member());

ALTER TABLE bans ENABLE ROW LEVEL SECURITY;
ALTER TABLE bans FORCE ROW LEVEL SECURITY;
CREATE POLICY bans_select ON bans FOR SELECT USING (app_has(4096));

ALTER TABLE ban_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE ban_identities FORCE ROW LEVEL SECURITY;

-- Grants. Roles, member roles, overrides, and bans change only through the functions above.
-- Default privileges are per database, so every grant the runtime needs is spelled out.

REVOKE ALL ON roles, member_roles, room_overrides, bans, ban_identities FROM app_runtime;
GRANT SELECT ON roles, member_roles, room_overrides, bans TO app_runtime;
REVOKE ALL ON server_settings FROM app_runtime;
GRANT SELECT, UPDATE ON server_settings TO app_runtime;
REVOKE UPDATE ON invites FROM app_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON categories TO app_runtime;

DO $$
DECLARE
    v_function text;
BEGIN
    FOREACH v_function IN ARRAY ARRAY[
        'app_uid()', 'app_is_member_of(uuid)', 'app_owner_of(uuid)', 'app_perms_of(uuid)',
        'app_room_perms_of(uuid, uuid)', 'app_rank_of(uuid)', 'app_roles_of(uuid)',
        'app_perms()', 'app_has(bigint)', 'app_room_has(uuid, bigint)', 'app_is_member()',
        'app_require(bigint)', 'app_member_role(uuid)', 'app_admin_role()', 'app_banned(uuid)',
        'app_check_target(uuid)', 'app_member_json(uuid)',
        'app_audit(text, text, jsonb, uuid, text)',
        'app_role_create(text, text, bigint, boolean)',
        'app_role_update(uuid, text, text, bigint, boolean)', 'app_role_delete(uuid)',
        'app_role_order(uuid[])', 'app_set_member_roles(uuid, uuid[])',
        'app_set_owner(uuid, boolean)', 'app_set_member_role(uuid, text)',
        'app_remove_member(uuid, text)', 'app_ban(uuid, text, timestamptz)', 'app_unban(uuid)',
        'app_timeout(uuid, timestamptz, text)',
        'app_set_override(uuid, uuid, bigint, bigint)', 'app_call_access(uuid, uuid)',
        'app_seen(uuid[])', 'app_accept_invite(bytea, uuid)',
        'app_join_by_groups(uuid, text, text)', 'app_promote_by_groups(uuid, text)',
        'app_sweep()'
    ] LOOP
        EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', v_function);
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO app_runtime', v_function);
    END LOOP;
END;
$$;
