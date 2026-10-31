-- A bot is an application the owner adds to this one community. It is not a person and
-- not a membership. The token is returned once; Postgres stores its SHA-256.
--
-- Scopes are the grant, the way a Discord guild install grants permissions. The same
-- bits as migrations/0005_server.sql: 0 view_channel, 9 manage_channels.
--   1<<0  VIEW_CHANNEL     rooms.read
--   1<<9  MANAGE_CHANNELS  rooms.write
-- members.read is a scope only. It is not a bit.
-- A bot with no scope can sign its own calls and do nothing else.
-- A bot is not a user, so a room it creates stores the bot id in created_by.

CREATE TABLE bots (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
    token_hash bytea NOT NULL UNIQUE,
    scopes text[] NOT NULL,
    permissions bigint NOT NULL CHECK (permissions >= 0),
    created_by uuid NOT NULL REFERENCES users (id),
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);

CREATE INDEX bots_token ON bots (token_hash) WHERE revoked_at IS NULL;

ALTER TABLE bots ENABLE ROW LEVEL SECURITY;
ALTER TABLE bots FORCE ROW LEVEL SECURITY;

-- Managers see and change bots. Token lookup does not: it goes through the
-- definer function below, which does not need app.role.
CREATE POLICY bots_managers ON bots
    FOR ALL
    USING (app_has(524288))
    WITH CHECK (app_has(524288));

-- app.scopes is ",rooms.read,rooms.write,members.read," when those were granted, or empty.
CREATE POLICY rooms_bot ON rooms
    FOR SELECT
    USING (
        current_setting('app.role', true) = 'bot'
        AND strpos(current_setting('app.scopes', true), ',rooms.read,') > 0
    );

-- rooms.write may create, rename, and delete. FOR ALL so RETURNING can read the row.
CREATE POLICY rooms_bot_write ON rooms
    FOR ALL
    USING (
        current_setting('app.role', true) = 'bot'
        AND strpos(current_setting('app.scopes', true), ',rooms.write,') > 0
    )
    WITH CHECK (
        current_setting('app.role', true) = 'bot'
        AND strpos(current_setting('app.scopes', true), ',rooms.write,') > 0
    );

CREATE POLICY memberships_bot ON memberships
    FOR SELECT
    USING (
        current_setting('app.role', true) = 'bot'
        AND strpos(current_setting('app.scopes', true), ',members.read,') > 0
    );

ALTER TABLE rooms DROP CONSTRAINT rooms_created_by_fkey;

CREATE OR REPLACE FUNCTION app_bot_identity(p_hash bytea)
RETURNS TABLE (id uuid, name text, scopes text[])
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT id, name, scopes
    FROM bots
    WHERE token_hash = p_hash
      AND revoked_at IS NULL;
$$;

REVOKE ALL ON FUNCTION app_bot_identity(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_bot_identity(bytea) TO app_runtime;

REVOKE ALL ON bots FROM app_runtime;
GRANT SELECT, INSERT, UPDATE ON bots TO app_runtime;
