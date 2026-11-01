-- End-to-end encrypted text, part 4: the community's root key and the encryption policy it signs.
--
-- The root key is a P-256 key that the owner's device makes and keeps; the server never sees its
-- private half. The server publishes the public half and one policy document signed by it, both
-- opaque to the server beyond the signature check. Members pin the root key the first time they
-- see it, and a client in a community whose signed policy says "encrypted only" refuses to post
-- in plaintext even if the server's own e2ee_text setting is lowered. A changed root is shown to
-- every member as "this community's identity changed". This is the server half of
-- design/security.md section 2.8 items 5 and 8 in tinycloud; the invite capability keys that the
-- root will certify (item 6) are not in this version.
--
-- The signature is ECDSA P-256 (DER) over SHA-256 of "tiny-e2ee-v1 community-policy" || policy,
-- checked by the API before it calls app_e2ee_set_root. The policy's own format is the clients'.

CREATE TABLE e2ee_community_root (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    root_key bytea NOT NULL CHECK (octet_length(root_key) = 65),
    policy bytea NOT NULL CHECK (octet_length(policy) BETWEEN 1 AND 4096),
    policy_signature bytea NOT NULL CHECK (octet_length(policy_signature) BETWEEN 8 AND 128),
    -- Goes up by one at every change, so a client can tell an old policy from a new one.
    version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
    updated_at timestamptz NOT NULL DEFAULT now()
);

REVOKE ALL ON e2ee_community_root FROM app_runtime;
ALTER TABLE e2ee_community_root ENABLE ROW LEVEL SECURITY;
ALTER TABLE e2ee_community_root FORCE ROW LEVEL SECURITY;

-- The root key and policy, for any member. Every field is null when no root was set.
CREATE FUNCTION app_e2ee_root()
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_row e2ee_community_root%ROWTYPE;
BEGIN
    PERFORM app_msg_gate();
    SELECT * INTO v_row FROM e2ee_community_root r WHERE r.id;
    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'root_key', NULL, 'policy', NULL, 'policy_signature', NULL, 'version', 0,
            'updated_at', NULL
        );
    END IF;
    RETURN jsonb_build_object(
        'root_key', translate(encode(v_row.root_key, 'base64'), E'\n', ''),
        'policy', translate(encode(v_row.policy, 'base64'), E'\n', ''),
        'policy_signature', translate(encode(v_row.policy_signature, 'base64'), E'\n', ''),
        'version', v_row.version,
        'updated_at', app_stamp(v_row.updated_at)
    );
END;
$$;

-- Sets the root key and its signed policy. Needs manage_server. A new policy under the same root
-- is a plain update; a different root replaces the community's identity, which only happens when
-- `p_replace` says so (P0E18 otherwise). Every member hears of it, with no key material, and the
-- audit log records who did it.
CREATE FUNCTION app_e2ee_set_root(p_key bytea, p_policy bytea, p_signature bytea, p_replace boolean)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_old bytea;
    v_changed boolean;
BEGIN
    PERFORM app_msg_gate();
    IF NOT app_has(524288) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    IF p_key IS NULL OR octet_length(p_key) <> 65 OR p_policy IS NULL
       OR octet_length(p_policy) NOT BETWEEN 1 AND 4096 OR p_signature IS NULL
       OR octet_length(p_signature) NOT BETWEEN 8 AND 128 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.e2ee.root', 0));
    SELECT r.root_key INTO v_old FROM e2ee_community_root r WHERE r.id;
    v_changed := FOUND AND v_old <> p_key;
    IF v_changed AND NOT coalesce(p_replace, false) THEN
        RAISE EXCEPTION 'root exists' USING ERRCODE = 'P0E18';
    END IF;
    INSERT INTO e2ee_community_root (id, root_key, policy, policy_signature)
    VALUES (true, p_key, p_policy, p_signature)
    ON CONFLICT (id) DO UPDATE
    SET root_key = EXCLUDED.root_key,
        policy = EXCLUDED.policy,
        policy_signature = EXCLUDED.policy_signature,
        version = e2ee_community_root.version + 1,
        updated_at = now();
    PERFORM app_audit(
        'e2ee.root', 'server',
        jsonb_build_object('root_changed', v_changed, 'first', v_old IS NULL),
        NULL, NULL
    );
    PERFORM app_emit(
        'e2ee.community',
        jsonb_build_object(
            'version', (SELECT r.version FROM e2ee_community_root r WHERE r.id),
            'root_changed', v_changed
        )
    );
    RETURN app_e2ee_root();
END;
$$;

REVOKE EXECUTE ON FUNCTION app_e2ee_root() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_e2ee_root() TO app_runtime;
REVOKE EXECUTE ON FUNCTION app_e2ee_set_root(bytea, bytea, bytea, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_e2ee_set_root(bytea, bytea, bytea, boolean) TO app_runtime;
