-- The external sender's private half leaves Postgres. A dump of the database must not be
-- enough to sign Add or Remove proposals. The column stays, nullable, so the process can copy
-- an old row into the key file and then clear it. This migration does not clear it: the copy
-- happens when the server starts, after migrate.
--
-- The key file is `{TINYSERVER_DATA_DIR}/e2ee-server-key`, or `TINYSERVER_E2EE_KEY_FILE`.
-- In deploy/compose.yml that file is on the `tinyserver_keys` volume, because the data dir
-- there is a tmpfs.

DO $$
DECLARE
    v_name text;
BEGIN
    FOR v_name IN
        SELECT c.conname
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY (c.conkey)
        WHERE n.nspname = 'public'
          AND t.relname = 'e2ee_server_key'
          AND c.contype = 'c'
          AND a.attname = 'private_key'
    LOOP
        EXECUTE format('ALTER TABLE e2ee_server_key DROP CONSTRAINT %I', v_name);
    END LOOP;
END;
$$;

ALTER TABLE e2ee_server_key ALTER COLUMN private_key DROP NOT NULL;

ALTER TABLE e2ee_server_key
    ADD CONSTRAINT e2ee_server_key_private_key_check
    CHECK (private_key IS NULL OR octet_length(private_key) BETWEEN 16 AND 128);

-- The row, if there is one. r_private is set only until the process has copied it out.
-- plpgsql, not sql: a sql function can be inlined and then run as the caller, who cannot
-- read this table.
CREATE FUNCTION app_e2ee_server_key_state()
RETURNS TABLE (r_public bytea, r_private bytea)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    RETURN QUERY SELECT k.signature_key, k.private_key FROM e2ee_server_key k;
END;
$$;

-- The public half only. A race returns the public key that won. The private half is never
-- written here.
CREATE FUNCTION app_e2ee_remember_server_public(p_public bytea)
RETURNS bytea
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    INSERT INTO e2ee_server_key (signature_key, private_key)
    VALUES (p_public, NULL)
    ON CONFLICT DO NOTHING;
    RETURN (SELECT k.signature_key FROM e2ee_server_key k);
END;
$$;

-- Drops the private half after the process has it in the key file.
CREATE FUNCTION app_e2ee_clear_server_private()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    UPDATE e2ee_server_key SET private_key = NULL WHERE private_key IS NOT NULL;
END;
$$;

-- The old shape, so a caller from before this migration cannot put the secret back.
-- p_private is ignored. The returned private half is always null.
CREATE OR REPLACE FUNCTION app_e2ee_server_key(p_public bytea, p_private bytea)
RETURNS TABLE (r_public bytea, r_private bytea)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    INSERT INTO e2ee_server_key (signature_key, private_key)
    VALUES (p_public, NULL)
    ON CONFLICT DO NOTHING;
    RETURN QUERY SELECT k.signature_key, NULL::bytea FROM e2ee_server_key k;
END;
$$;

REVOKE EXECUTE ON FUNCTION app_e2ee_server_key_state() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_e2ee_server_key_state() TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_e2ee_remember_server_public(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_e2ee_remember_server_public(bytea) TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_e2ee_clear_server_private() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_e2ee_clear_server_private() TO app_runtime;
