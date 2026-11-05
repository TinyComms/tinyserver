-- A person's own devices may form one private MLS group: a device that cannot open a message asks
-- its siblings for it, and they carry verified marks and settings between them. Every MLS group
-- here hangs off a conversation (the handshake log, the external sender's Add and Remove
-- proposals, the message store), and a direct with yourself is refused, so this is that
-- conversation: a direct whose two sides are the same person, marked self. The protocol is
-- docs/e2ee-text.md section 5.
--
-- It is always encrypted. The devices that should be in its group are that person's active
-- devices, as for any direct, so a new cross-signed device is proposed for Add and a revoked one
-- for Remove. Only that person can open it. It is not listed with the directs, is not audited,
-- and announces nothing; its events go to that person's sessions only. Its messages are deleted
-- once older than e2ee_self_ttl_secs (7 days by default), and the whole conversation goes with
-- the account.

ALTER TABLE server_settings
    -- How long a message in a self conversation is kept. A request and its answer are short-lived.
    ADD COLUMN e2ee_self_ttl_secs integer NOT NULL DEFAULT 604800
        CHECK (e2ee_self_ttl_secs BETWEEN 3600 AND 2592000);

ALTER TABLE directs ADD COLUMN is_self boolean NOT NULL DEFAULT false;

-- The pair check of 0008 becomes: two people in order, or one person and the self mark, always
-- encrypted. The unique pair key of 0020 still holds, so a person has at most one.
DO $$
DECLARE
    v_name text;
BEGIN
    FOR v_name IN
        SELECT c.conname
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'public'
          AND t.relname = 'directs'
          AND c.contype = 'c'
          AND pg_get_constraintdef(c.oid) LIKE '%low_user_id < high_user_id%'
    LOOP
        EXECUTE format('ALTER TABLE directs DROP CONSTRAINT %I', v_name);
    END LOOP;
END;
$$;

ALTER TABLE directs ADD CONSTRAINT directs_pair_check CHECK (
    (NOT is_self AND low_user_id < high_user_id)
    OR (is_self AND low_user_id = high_user_id AND e2ee)
);

-- The directs a person sees in their list. Their self conversation is not one of them.
CREATE OR REPLACE FUNCTION app_list_directs()
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT coalesce(
        jsonb_agg(app_direct_json(d.id) ORDER BY d.created_at, d.id),
        '[]'::jsonb
    )
    FROM directs d
    WHERE app_uid() IN (d.low_user_id, d.high_user_id)
      AND NOT d.is_self
      AND app_is_member()
      AND NOT app_banned(app_uid());
$$;

-- Get or make the caller's self conversation. Making one is refused while e2ee_text is off; one
-- that exists is returned whatever the setting.
CREATE FUNCTION app_e2ee_self(OUT body jsonb, OUT created boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_me uuid := app_uid();
    v_id uuid;
BEGIN
    PERFORM app_msg_gate();
    created := false;
    SELECT d.id INTO v_id FROM directs d
    WHERE d.low_user_id = v_me AND d.high_user_id = v_me AND d.is_self;
    IF NOT FOUND THEN
        PERFORM app_e2ee_may_create(true);
        INSERT INTO directs (low_user_id, high_user_id, e2ee, is_self)
        VALUES (v_me, v_me, true, true)
        ON CONFLICT (low_user_id, high_user_id, e2ee) DO NOTHING
        RETURNING id INTO v_id;
        IF v_id IS NULL THEN
            SELECT d.id INTO v_id FROM directs d
            WHERE d.low_user_id = v_me AND d.high_user_id = v_me AND d.is_self;
        ELSE
            created := true;
        END IF;
    END IF;
    body := jsonb_build_object(
        'conversation_id', v_id::text,
        'ttl_secs', (SELECT s.e2ee_self_ttl_secs FROM server_settings s)
    );
END;
$$;

-- What GET /v1/capabilities says of this feature. Nothing a member cannot learn by trying.
CREATE FUNCTION app_e2ee_self_ttl_secs()
RETURNS integer
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT s.e2ee_self_ttl_secs FROM server_settings s;
$$;

-- The periodic sweep: messages and encrypted reactions of self conversations older than the
-- setting. Edits of a deleted message go with it. Returns the ids of the sealed files attached to
-- the messages that went, for the caller to delete.
CREATE FUNCTION app_e2ee_self_sweep()
RETURNS text[]
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_before timestamptz;
    v_ids text[];
BEGIN
    SELECT now() - make_interval(secs => s.e2ee_self_ttl_secs) INTO v_before
    FROM server_settings s;
    SELECT coalesce(array_agg(a.id::text), '{}') INTO v_ids
    FROM attachments a
    JOIN messages m ON m.id = a.message_id
    JOIN directs d ON d.id = m.direct_id
    WHERE d.is_self AND m.created_at <= v_before;
    DELETE FROM messages m
    USING directs d
    WHERE m.direct_id = d.id AND d.is_self AND m.created_at <= v_before;
    DELETE FROM e2ee_reaction_blobs r
    USING directs d
    WHERE r.conversation_id = d.id AND d.is_self AND r.created_at <= v_before;
    RETURN v_ids;
END;
$$;

DO $$
DECLARE
    v_function text;
BEGIN
    FOREACH v_function IN ARRAY ARRAY[
        'app_e2ee_self()',
        'app_e2ee_self_ttl_secs()',
        'app_e2ee_self_sweep()'
    ]
    LOOP
        EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', v_function);
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO app_runtime', v_function);
    END LOOP;
END;
$$;

-- Deleting an account tombstones the user row, so no foreign key fires. This deletes their self
-- conversation: its group and handshake log, its reactions, and its messages with it. Their
-- sealed files are already gone with their uploads (app_delete_account).
CREATE FUNCTION app_e2ee_self_forget_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_id uuid;
BEGIN
    FOR v_id IN
        SELECT d.id FROM directs d
        WHERE d.low_user_id = NEW.id AND d.high_user_id = NEW.id AND d.is_self
    LOOP
        DELETE FROM e2ee_groups WHERE conversation_id = v_id;
        DELETE FROM e2ee_reaction_blobs WHERE conversation_id = v_id;
        DELETE FROM reads WHERE kind = 'direct' AND conversation_id = v_id;
        DELETE FROM directs WHERE id = v_id;
    END LOOP;
    RETURN NULL;
END;
$$;

REVOKE EXECUTE ON FUNCTION app_e2ee_self_forget_user() FROM PUBLIC;

CREATE TRIGGER users_forget_e2ee_self
    AFTER UPDATE OF deleted_at ON users
    FOR EACH ROW
    WHEN (OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL)
    EXECUTE FUNCTION app_e2ee_self_forget_user();
