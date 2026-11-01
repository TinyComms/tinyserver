-- End-to-end encrypted text, part 2: devices, key packages, and the MLS group of each encrypted
-- conversation, with the server as delivery service and external sender.
--
-- Who is in a group is decided by permission, not by who asks. The desired device set of a
-- conversation is every active device of every person who can view it (view_channel for a
-- channel, the two people of a direct). Whenever it can have changed, app_e2ee_reconcile
-- compares it with the leaves of the group and records what the group must do about it: a
-- pending Remove for a leaf no longer wanted, a pending Add (with the device's key package,
-- claimed once) for a device wanted and not in. The server signs those as external proposals
-- when a member next asks (crates/api/src/e2ee_text); a member commits them; the commit is
-- applied here by compare-and-swap on the epoch. The server never sees a group secret, so it
-- cannot read a message, and it has no key that opens one.
--
-- Reconcile runs from deferred constraint triggers, once per transaction at commit, on every
-- table that can change who views a conversation: so no code path that kicks, bans, deletes
-- an account, edits a role or an override, or revokes a device can forget it, as in 0013. No
-- background worker is needed.

-- The most devices one person may have at once.
CREATE FUNCTION app_e2ee_max_devices()
RETURNS integer
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT 20;
$$;

CREATE TABLE e2ee_groups (
    conversation_id uuid PRIMARY KEY,
    epoch bigint NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- The leaves of the tree, as the commits that were accepted left them. A removed leaf is blank:
-- its row is gone, and the next Add takes the lowest free index, as openmls does.
CREATE TABLE e2ee_leaves (
    conversation_id uuid NOT NULL REFERENCES e2ee_groups (conversation_id) ON DELETE CASCADE,
    leaf_index integer NOT NULL CHECK (leaf_index >= 0),
    user_id uuid NOT NULL REFERENCES users (id),
    device_id uuid NOT NULL REFERENCES e2ee_devices (device_id),
    -- The epoch the group was at when this device joined: it reads no handshake before it.
    joined_epoch bigint NOT NULL CHECK (joined_epoch >= 0),
    PRIMARY KEY (conversation_id, leaf_index),
    UNIQUE (conversation_id, device_id)
);

-- What the group has yet to do. A row is "issued" once the server has signed its proposal for
-- the current epoch; an issued row is never withdrawn, so a commit has one well defined set of
-- proposals to apply. A row not yet issued may be dropped when it no longer applies.
CREATE TABLE e2ee_pending (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    conversation_id uuid NOT NULL REFERENCES e2ee_groups (conversation_id) ON DELETE CASCADE,
    op text NOT NULL CHECK (op IN ('add', 'remove')),
    device_id uuid NOT NULL REFERENCES e2ee_devices (device_id),
    leaf_index integer CHECK (leaf_index IS NULL OR leaf_index >= 0),
    key_package bytea CHECK (key_package IS NULL OR octet_length(key_package) <= 8192),
    proposal bytea CHECK (proposal IS NULL OR octet_length(proposal) <= 16384),
    proposal_epoch bigint,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (conversation_id, device_id, op),
    CHECK ((op = 'remove') = (leaf_index IS NOT NULL)),
    CHECK ((op = 'add') = (key_package IS NOT NULL)),
    CHECK ((proposal IS NULL) = (proposal_epoch IS NULL))
);

-- The public handshake log. Proposals and commits are MLS public messages; a welcome is only
-- returned to the device it is for. No row holds a secret.
CREATE TABLE e2ee_handshake (
    seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    conversation_id uuid NOT NULL REFERENCES e2ee_groups (conversation_id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('proposals', 'commit', 'welcome')),
    epoch bigint NOT NULL CHECK (epoch >= 0),
    data bytea NOT NULL CHECK (octet_length(data) BETWEEN 1 AND 1048576),
    for_device uuid REFERENCES e2ee_devices (device_id),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((kind = 'welcome') = (for_device IS NOT NULL))
);

CREATE INDEX e2ee_handshake_conversation ON e2ee_handshake (conversation_id, seq);
CREATE INDEX e2ee_handshake_welcome ON e2ee_handshake (for_device, seq) WHERE kind = 'welcome';

REVOKE ALL ON e2ee_groups, e2ee_leaves, e2ee_pending, e2ee_handshake FROM app_runtime;

ALTER TABLE e2ee_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE e2ee_groups FORCE ROW LEVEL SECURITY;
ALTER TABLE e2ee_leaves ENABLE ROW LEVEL SECURITY;
ALTER TABLE e2ee_leaves FORCE ROW LEVEL SECURITY;
ALTER TABLE e2ee_pending ENABLE ROW LEVEL SECURITY;
ALTER TABLE e2ee_pending FORCE ROW LEVEL SECURITY;
ALTER TABLE e2ee_handshake ENABLE ROW LEVEL SECURITY;
ALTER TABLE e2ee_handshake FORCE ROW LEVEL SECURITY;

-- A deleted channel takes its group, leaves, pending proposals and handshake log with it.
CREATE FUNCTION app_e2ee_forget_channel()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    DELETE FROM e2ee_groups WHERE conversation_id = OLD.id;
    RETURN NULL;
END;
$$;

CREATE TRIGGER channels_e2ee_forget
    AFTER DELETE ON channels
    FOR EACH ROW
    EXECUTE FUNCTION app_e2ee_forget_channel();

-- The caller may use this encrypted conversation, and `p_device`, if given, is theirs and active.
-- p_speak also needs a voice that is not timed out and the speak permission.
CREATE FUNCTION app_e2ee_gate(p_conv uuid, p_device uuid, p_speak boolean)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_user uuid;
    v_revoked timestamptz;
BEGIN
    PERFORM app_open_conversation(p_conv, p_speak);
    IF NOT app_conv_e2ee(p_conv) THEN
        RAISE EXCEPTION 'not e2ee' USING ERRCODE = 'P0E02';
    END IF;
    IF p_device IS NOT NULL THEN
        SELECT d.user_id, d.revoked_at INTO v_user, v_revoked
        FROM e2ee_devices d WHERE d.device_id = p_device;
        IF NOT FOUND OR v_user <> app_uid() OR v_revoked IS NOT NULL THEN
            RAISE EXCEPTION 'bad device' USING ERRCODE = 'P0E13';
        END IF;
    END IF;
END;
$$;

-- The devices that should be in the group: every active device of every person who can view
-- the conversation now.
CREATE FUNCTION app_e2ee_desired(p_conv uuid)
RETURNS TABLE (d_user uuid, d_device uuid)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_low uuid;
    v_high uuid;
BEGIN
    IF EXISTS (SELECT 1 FROM channels c WHERE c.id = p_conv AND c.e2ee) THEN
        RETURN QUERY
        SELECT d.user_id, d.device_id
        FROM e2ee_devices d
        WHERE d.revoked_at IS NULL
          AND EXISTS (SELECT 1 FROM memberships m WHERE m.user_id = d.user_id)
          AND (app_channel_perms_of(p_conv, d.user_id) & 1) = 1;
        RETURN;
    END IF;
    SELECT x.low_user_id, x.high_user_id INTO v_low, v_high
    FROM directs x WHERE x.id = p_conv AND x.e2ee;
    IF FOUND THEN
        RETURN QUERY
        SELECT d.user_id, d.device_id
        FROM e2ee_devices d
        WHERE d.user_id IN (v_low, v_high)
          AND d.revoked_at IS NULL
          AND EXISTS (SELECT 1 FROM memberships m WHERE m.user_id = d.user_id)
          AND NOT app_banned(d.user_id);
    END IF;
END;
$$;

-- Who hears of a handshake change: the people who can use the conversation now. An empty
-- list would read as everyone to the socket, so it is the nil uuid instead.
CREATE FUNCTION app_e2ee_audience(p_conv uuid)
RETURNS uuid[]
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT CASE WHEN cardinality(a.users) = 0
                THEN ARRAY['00000000-0000-0000-0000-000000000000'::uuid]
                ELSE a.users END
    FROM (SELECT coalesce(array_agg(DISTINCT x.d_user), '{}'::uuid[]) AS users
          FROM app_e2ee_desired(p_conv) x) a;
$$;

-- Hints the members to read the handshake log. The seq is the newest there is; a client reads
-- the log after any hint, whatever the seq says.
CREATE FUNCTION app_e2ee_hint(p_conv uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    PERFORM app_emit_to(
        'e2ee.handshake',
        jsonb_build_object(
            'conversation_id', p_conv::text,
            'seq', coalesce((SELECT max(h.seq) FROM e2ee_handshake h
                             WHERE h.conversation_id = p_conv), 0)
        ),
        app_e2ee_audience(p_conv)
    );
END;
$$;

-- The lowest leaf index not in use: the leftmost blank leaf, else one past the last.
CREATE FUNCTION app_e2ee_free_leaf(p_conv uuid)
RETURNS integer
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT coalesce(
        (SELECT min(s.i)
         FROM generate_series(
                  0, coalesce((SELECT max(l.leaf_index) FROM e2ee_leaves l
                               WHERE l.conversation_id = p_conv), -1)) AS s (i)
         WHERE NOT EXISTS (SELECT 1 FROM e2ee_leaves l
                           WHERE l.conversation_id = p_conv AND l.leaf_index = s.i)),
        coalesce((SELECT max(l.leaf_index) FROM e2ee_leaves l
                  WHERE l.conversation_id = p_conv), -1) + 1
    );
$$;

-- Brings the pending Add and Remove proposals of one group in line with who can use the
-- conversation now. True when it changed what is pending. It does not need a caller.
CREATE FUNCTION app_e2ee_reconcile(p_conv uuid, p_emit boolean DEFAULT true)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_desired uuid[];
    v_changed boolean := false;
    v_room integer;
    v_row record;
    v_package record;
    v_left integer;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.e2ee.' || p_conv::text, 0));
    IF NOT EXISTS (SELECT 1 FROM e2ee_groups g WHERE g.conversation_id = p_conv) THEN
        RETURN false;
    END IF;
    SELECT coalesce(array_agg(x.d_device), '{}'::uuid[]) INTO v_desired
    FROM app_e2ee_desired(p_conv) x;

    -- No leaf is wanted any more: nobody can commit, so the group is over. The next device to
    -- ask starts a new one. Messages already sent stay ciphertext nobody new can read.
    IF EXISTS (SELECT 1 FROM e2ee_leaves l WHERE l.conversation_id = p_conv)
       AND NOT EXISTS (SELECT 1 FROM e2ee_leaves l
                       WHERE l.conversation_id = p_conv AND l.device_id = ANY (v_desired)) THEN
        DELETE FROM e2ee_groups WHERE conversation_id = p_conv;
        RETURN true;
    END IF;

    -- Proposals not yet signed that no longer apply are dropped. Signed ones stay: a commit
    -- must have one set of proposals to apply.
    DELETE FROM e2ee_pending p
    WHERE p.conversation_id = p_conv AND p.proposal IS NULL AND (
        (p.op = 'add' AND (
            p.device_id <> ALL (v_desired)
            OR EXISTS (SELECT 1 FROM e2ee_leaves l
                       WHERE l.conversation_id = p_conv AND l.device_id = p.device_id)))
        OR (p.op = 'remove' AND (
            p.device_id = ANY (v_desired)
            OR NOT EXISTS (SELECT 1 FROM e2ee_leaves l
                           WHERE l.conversation_id = p_conv AND l.device_id = p.device_id)))
    );

    FOR v_row IN
        SELECT l.leaf_index, l.device_id
        FROM e2ee_leaves l
        WHERE l.conversation_id = p_conv
          AND l.device_id <> ALL (v_desired)
          AND NOT EXISTS (SELECT 1 FROM e2ee_pending p
                          WHERE p.conversation_id = p_conv AND p.device_id = l.device_id
                            AND p.op = 'remove')
        ORDER BY l.leaf_index
    LOOP
        INSERT INTO e2ee_pending (conversation_id, op, device_id, leaf_index)
        VALUES (p_conv, 'remove', v_row.device_id, v_row.leaf_index);
        v_changed := true;
    END LOOP;

    -- At most 100 Adds wait at once; the rest follow in a later epoch.
    SELECT greatest(0, 100 - count(*)) INTO v_room
    FROM e2ee_pending p WHERE p.conversation_id = p_conv AND p.op = 'add';
    FOR v_row IN
        SELECT w.d_device
        FROM unnest(v_desired) AS w (d_device)
        WHERE NOT EXISTS (SELECT 1 FROM e2ee_leaves l
                          WHERE l.conversation_id = p_conv AND l.device_id = w.d_device)
          AND NOT EXISTS (SELECT 1 FROM e2ee_pending p
                          WHERE p.conversation_id = p_conv AND p.device_id = w.d_device
                            AND p.op = 'add')
        ORDER BY w.d_device
        LIMIT v_room
    LOOP
        -- The device's own key packages first, its last resort only when none is left.
        SELECT k.id, k.data, k.last_resort INTO v_package
        FROM e2ee_key_packages k
        WHERE k.device_id = v_row.d_device AND k.expires_at > now()
        ORDER BY k.last_resort, k.id
        LIMIT 1
        FOR UPDATE SKIP LOCKED;
        IF NOT FOUND THEN
            -- Waits for the device to upload one: the upload reconciles again.
            CONTINUE;
        END IF;
        INSERT INTO e2ee_pending (conversation_id, op, device_id, key_package)
        VALUES (p_conv, 'add', v_row.d_device, v_package.data);
        v_changed := true;
        IF NOT v_package.last_resort THEN
            DELETE FROM e2ee_key_packages WHERE id = v_package.id;
        END IF;
        SELECT count(*) INTO v_left
        FROM e2ee_key_packages k
        WHERE k.device_id = v_row.d_device AND NOT k.last_resort AND k.expires_at > now();
        IF v_left < 5 THEN
            UPDATE e2ee_devices SET low_keys = true
            WHERE device_id = v_row.d_device AND NOT low_keys;
            IF FOUND THEN
                PERFORM app_emit_to(
                    'e2ee.keys_low',
                    jsonb_build_object('device_id', v_row.d_device::text, 'remaining', v_left),
                    ARRAY[(SELECT d.user_id FROM e2ee_devices d WHERE d.device_id = v_row.d_device)]
                );
            END IF;
        END IF;
    END LOOP;

    IF v_changed AND p_emit THEN
        PERFORM app_e2ee_hint(p_conv);
    END IF;
    RETURN v_changed;
END;
$$;

CREATE FUNCTION app_e2ee_reconcile_all()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_conv uuid;
BEGIN
    FOR v_conv IN SELECT g.conversation_id FROM e2ee_groups g ORDER BY g.conversation_id LOOP
        PERFORM app_e2ee_reconcile(v_conv);
    END LOOP;
END;
$$;

-- Once per transaction, after its last statement: the people who can view a conversation have
-- settled, so compare them with the groups.
CREATE FUNCTION app_e2ee_reconcile_trigger()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    IF coalesce(current_setting('app.e2ee_reconciled', true), '') = pg_current_xact_id()::text THEN
        RETURN NULL;
    END IF;
    PERFORM set_config('app.e2ee_reconciled', pg_current_xact_id()::text, true);
    PERFORM app_e2ee_reconcile_all();
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER e2ee_reconcile_memberships
    AFTER INSERT OR DELETE OR UPDATE OF owner ON memberships
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION app_e2ee_reconcile_trigger();
CREATE CONSTRAINT TRIGGER e2ee_reconcile_member_roles
    AFTER INSERT OR DELETE OR UPDATE ON member_roles
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION app_e2ee_reconcile_trigger();
CREATE CONSTRAINT TRIGGER e2ee_reconcile_roles
    AFTER DELETE OR UPDATE OF permissions ON roles
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION app_e2ee_reconcile_trigger();
CREATE CONSTRAINT TRIGGER e2ee_reconcile_overrides
    AFTER INSERT OR DELETE OR UPDATE ON channel_overrides
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION app_e2ee_reconcile_trigger();
CREATE CONSTRAINT TRIGGER e2ee_reconcile_devices
    AFTER INSERT OR UPDATE OF revoked_at ON e2ee_devices
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION app_e2ee_reconcile_trigger();

-- Registers a device. The person's first is trusted on first use; every later one needs a
-- cross signature, which the API has already checked against their active devices.
CREATE FUNCTION app_e2ee_put_device(p_device uuid, p_key bytea, p_cross bytea, p_label text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_user uuid := app_uid();
    v_label text := coalesce(btrim(p_label), '');
    v_active integer;
    v_at timestamptz;
BEGIN
    PERFORM app_msg_gate();
    IF p_device IS NULL OR p_key IS NULL OR octet_length(p_key) <> 65 OR char_length(v_label) > 80 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.e2ee.user.' || v_user::text, 0));
    IF EXISTS (SELECT 1 FROM e2ee_devices d WHERE d.device_id = p_device) THEN
        RAISE EXCEPTION 'device exists' USING ERRCODE = 'P0E08';
    END IF;
    SELECT count(*) INTO v_active FROM e2ee_devices d
    WHERE d.user_id = v_user AND d.revoked_at IS NULL;
    IF v_active >= app_e2ee_max_devices() THEN
        RAISE EXCEPTION 'too many devices' USING ERRCODE = 'P0E14';
    END IF;
    IF v_active > 0 AND p_cross IS NULL THEN
        RAISE EXCEPTION 'cross signature required' USING ERRCODE = 'P0E09';
    END IF;
    INSERT INTO e2ee_devices (device_id, user_id, signature_key, cross_signature, label)
    VALUES (p_device, v_user, p_key, CASE WHEN v_active > 0 THEN p_cross END, v_label)
    RETURNING created_at INTO v_at;
    PERFORM app_emit(
        'e2ee.device',
        jsonb_build_object('user_id', v_user::text, 'device_id', p_device::text, 'op', 'added')
    );
    RETURN jsonb_build_object(
        'device_id', p_device::text,
        'signature_key', translate(encode(p_key, 'base64'), E'\n', ''),
        'cross_signature', CASE WHEN v_active > 0
            THEN translate(encode(p_cross, 'base64'), E'\n', '') END,
        'label', v_label,
        'created_at', app_stamp(v_at)
    );
END;
$$;

-- The signature keys of the caller's active devices, for checking a cross signature.
CREATE FUNCTION app_e2ee_active_keys()
RETURNS SETOF bytea
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    PERFORM app_msg_gate();
    RETURN QUERY
    SELECT d.signature_key FROM e2ee_devices d
    WHERE d.user_id = app_uid() AND d.revoked_at IS NULL
    ORDER BY d.created_at, d.device_id;
END;
$$;

-- The signature key of one of the caller's active devices.
CREATE FUNCTION app_e2ee_my_device_key(p_device uuid)
RETURNS bytea
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_key bytea;
BEGIN
    PERFORM app_msg_gate();
    SELECT d.signature_key INTO v_key FROM e2ee_devices d
    WHERE d.device_id = p_device AND d.user_id = app_uid() AND d.revoked_at IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'bad device' USING ERRCODE = 'P0E13';
    END IF;
    RETURN v_key;
END;
$$;

-- Revokes one of the caller's own devices. A revoked one is idempotent; another person's is
-- not found. Its Remove is queued in every group it is in by the trigger.
CREATE FUNCTION app_e2ee_revoke_device(p_device uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_user uuid;
    v_revoked timestamptz;
BEGIN
    PERFORM app_msg_gate();
    SELECT d.user_id, d.revoked_at INTO v_user, v_revoked
    FROM e2ee_devices d WHERE d.device_id = p_device FOR UPDATE;
    IF NOT FOUND OR v_user <> app_uid() THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    IF v_revoked IS NOT NULL THEN
        RETURN;
    END IF;
    UPDATE e2ee_devices SET revoked_at = now(), low_keys = false WHERE device_id = p_device;
    DELETE FROM e2ee_key_packages WHERE device_id = p_device;
    DELETE FROM e2ee_handshake WHERE for_device = p_device;
    PERFORM app_emit(
        'e2ee.device',
        jsonb_build_object('user_id', v_user::text, 'device_id', p_device::text, 'op', 'revoked')
    );
END;
$$;

-- A member's active devices. Another member sees the key and the cross signature, which a client
-- checks itself; only the person themselves sees the label.
CREATE FUNCTION app_e2ee_user_devices(p_user uuid)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    PERFORM app_msg_gate();
    IF NOT app_is_member_of(p_user) THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    RETURN coalesce((
        SELECT jsonb_agg(
            jsonb_build_object(
                'device_id', d.device_id::text,
                'signature_key', translate(encode(d.signature_key, 'base64'), E'\n', ''),
                'cross_signature', CASE WHEN d.cross_signature IS NULL THEN NULL
                    ELSE translate(encode(d.cross_signature, 'base64'), E'\n', '') END,
                'created_at', app_stamp(d.created_at)
            ) || CASE WHEN d.user_id = app_uid()
                      THEN jsonb_build_object('label', d.label) ELSE '{}'::jsonb END
            ORDER BY d.created_at, d.device_id)
        FROM e2ee_devices d
        WHERE d.user_id = p_user AND d.revoked_at IS NULL
    ), '[]'::jsonb);
END;
$$;

-- Adds public key packages to one of the caller's devices. At most 50 in a call and 100 waiting
-- at once; one that was ever uploaded before is refused, because its init key is gone.
-- `p_expires` is each one's not_after, in seconds since the epoch.
CREATE FUNCTION app_e2ee_put_key_packages(
    p_device uuid,
    p_data bytea[],
    p_expires bigint[],
    p_last bytea,
    p_last_expires bigint
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_user uuid;
    v_n integer := coalesce(cardinality(p_data), 0);
    v_i integer;
    v_waiting integer;
    v_remaining integer;
BEGIN
    PERFORM app_msg_gate();
    SELECT d.user_id INTO v_user FROM e2ee_devices d
    WHERE d.device_id = p_device AND d.revoked_at IS NULL FOR UPDATE;
    IF NOT FOUND OR v_user <> app_uid() THEN
        RAISE EXCEPTION 'bad device' USING ERRCODE = 'P0E13';
    END IF;
    IF v_n > 50 OR v_n <> coalesce(cardinality(p_expires), 0) THEN
        RAISE EXCEPTION 'too many key packages' USING ERRCODE = 'P0E10';
    END IF;
    DELETE FROM e2ee_key_packages k
    WHERE k.device_id = p_device AND NOT k.last_resort AND k.expires_at <= now();
    SELECT count(*) INTO v_waiting FROM e2ee_key_packages k
    WHERE k.device_id = p_device AND NOT k.last_resort;
    IF v_waiting + v_n > 100 THEN
        RAISE EXCEPTION 'too many key packages' USING ERRCODE = 'P0E10';
    END IF;
    FOR v_i IN 1..v_n LOOP
        INSERT INTO e2ee_key_package_hashes (device_id, hash)
        VALUES (p_device, sha256(p_data[v_i]))
        ON CONFLICT DO NOTHING;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'key package already used' USING ERRCODE = 'P0E15';
        END IF;
        INSERT INTO e2ee_key_packages (device_id, data, expires_at)
        VALUES (p_device, p_data[v_i], to_timestamp(p_expires[v_i]));
    END LOOP;
    IF p_last IS NOT NULL THEN
        INSERT INTO e2ee_key_package_hashes (device_id, hash)
        VALUES (p_device, sha256(p_last))
        ON CONFLICT DO NOTHING;
        DELETE FROM e2ee_key_packages k WHERE k.device_id = p_device AND k.last_resort;
        INSERT INTO e2ee_key_packages (device_id, data, last_resort, expires_at)
        VALUES (p_device, p_last, true, to_timestamp(p_last_expires));
    END IF;
    SELECT count(*) INTO v_remaining FROM e2ee_key_packages k
    WHERE k.device_id = p_device AND NOT k.last_resort AND k.expires_at > now();
    UPDATE e2ee_devices SET low_keys = (v_remaining < 5) WHERE device_id = p_device;
    -- A key package may be what a waiting Add needed.
    PERFORM app_e2ee_reconcile_all();
    RETURN jsonb_build_object('remaining', v_remaining);
END;
$$;

CREATE FUNCTION app_e2ee_key_package_count(p_device uuid)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    PERFORM app_msg_gate();
    IF NOT EXISTS (SELECT 1 FROM e2ee_devices d
                   WHERE d.device_id = p_device AND d.user_id = app_uid()
                     AND d.revoked_at IS NULL) THEN
        RAISE EXCEPTION 'bad device' USING ERRCODE = 'P0E13';
    END IF;
    RETURN jsonb_build_object(
        'remaining', (SELECT count(*) FROM e2ee_key_packages k
                      WHERE k.device_id = p_device AND NOT k.last_resort AND k.expires_at > now()),
        'last_resort', EXISTS (SELECT 1 FROM e2ee_key_packages k
                               WHERE k.device_id = p_device AND k.last_resort
                                 AND k.expires_at > now())
    );
END;
$$;

-- The server's external sender key, made on first use. A second caller racing the first gets
-- the key that won.
CREATE FUNCTION app_e2ee_server_key(p_public bytea, p_private bytea)
RETURNS TABLE (r_public bytea, r_private bytea)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    INSERT INTO e2ee_server_key (signature_key, private_key)
    VALUES (p_public, p_private)
    ON CONFLICT DO NOTHING;
    RETURN QUERY SELECT k.signature_key, k.private_key FROM e2ee_server_key k;
END;
$$;

-- What the caller may know of an encrypted conversation's group. After this the API signs any
-- proposals that are due and reads it again.
CREATE FUNCTION app_e2ee_info(p_conv uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_epoch bigint;
BEGIN
    PERFORM app_open_conversation(p_conv, false);
    IF NOT app_conv_e2ee(p_conv) THEN
        RETURN jsonb_build_object('e2ee', false);
    END IF;
    PERFORM app_e2ee_reconcile(p_conv);
    SELECT g.epoch INTO v_epoch FROM e2ee_groups g WHERE g.conversation_id = p_conv;
    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'e2ee', true, 'epoch', NULL, 'members', '[]'::jsonb, 'pending', '[]'::jsonb
        );
    END IF;
    RETURN jsonb_build_object(
        'e2ee', true,
        'epoch', v_epoch,
        'members', coalesce((
            SELECT jsonb_agg(jsonb_build_object(
                'user_id', l.user_id::text,
                'device_id', l.device_id::text,
                'leaf_index', l.leaf_index
            ) ORDER BY l.leaf_index)
            FROM e2ee_leaves l WHERE l.conversation_id = p_conv
        ), '[]'::jsonb),
        'pending', coalesce((
            SELECT jsonb_agg(jsonb_build_object(
                'op', p.op,
                'user_id', d.user_id::text,
                'device_id', p.device_id::text,
                'issued', p.proposal IS NOT NULL
            ) ORDER BY p.id)
            FROM e2ee_pending p JOIN e2ee_devices d ON d.device_id = p.device_id
            WHERE p.conversation_id = p_conv
        ), '[]'::jsonb)
    );
END;
$$;

-- The first member device starts the group, at epoch 0, with itself in leaf 0. Everyone else
-- who can use the conversation is then pending as an Add.
CREATE FUNCTION app_e2ee_create_group(p_conv uuid, p_device uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    PERFORM app_e2ee_gate(p_conv, p_device, false);
    PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.e2ee.' || p_conv::text, 0));
    IF EXISTS (SELECT 1 FROM e2ee_groups g WHERE g.conversation_id = p_conv) THEN
        RAISE EXCEPTION 'group exists' USING ERRCODE = 'P0E06';
    END IF;
    INSERT INTO e2ee_groups (conversation_id) VALUES (p_conv);
    INSERT INTO e2ee_leaves (conversation_id, leaf_index, user_id, device_id, joined_epoch)
    VALUES (p_conv, 0, app_uid(), p_device, 0);
    IF NOT app_e2ee_reconcile(p_conv) THEN
        PERFORM app_e2ee_hint(p_conv);
    END IF;
END;
$$;

-- The proposals not yet signed, and the epoch to sign them for. Holds the group's lock until
-- the transaction ends, so what is signed is what is issued.
CREATE FUNCTION app_e2ee_begin_issue(p_conv uuid)
RETURNS TABLE (
    r_epoch bigint,
    r_id bigint,
    r_op text,
    r_device uuid,
    r_leaf integer,
    r_package bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_epoch bigint;
BEGIN
    PERFORM app_e2ee_gate(p_conv, NULL, false);
    PERFORM app_e2ee_reconcile(p_conv);
    SELECT g.epoch INTO v_epoch FROM e2ee_groups g WHERE g.conversation_id = p_conv;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    RETURN QUERY
    SELECT v_epoch, p.id, p.op, p.device_id, p.leaf_index, p.key_package
    FROM e2ee_pending p
    WHERE p.conversation_id = p_conv AND p.proposal IS NULL
    ORDER BY (p.op = 'add'), p.id;
END;
$$;

-- Stores the signed proposals for the epoch. A NULL proposal is one that could not be made;
-- its row is dropped. `p_batch` is what a member reads from the log.
CREATE FUNCTION app_e2ee_issue(
    p_conv uuid,
    p_epoch bigint,
    p_ids bigint[],
    p_proposals bytea[],
    p_batch bytea
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_i integer;
    v_made integer := 0;
BEGIN
    PERFORM app_e2ee_gate(p_conv, NULL, false);
    PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.e2ee.' || p_conv::text, 0));
    IF NOT EXISTS (SELECT 1 FROM e2ee_groups g
                   WHERE g.conversation_id = p_conv AND g.epoch = p_epoch) THEN
        RAISE EXCEPTION 'stale epoch' USING ERRCODE = 'P0E03';
    END IF;
    FOR v_i IN 1..coalesce(cardinality(p_ids), 0) LOOP
        IF p_proposals[v_i] IS NULL THEN
            DELETE FROM e2ee_pending p
            WHERE p.id = p_ids[v_i] AND p.conversation_id = p_conv AND p.proposal IS NULL;
        ELSE
            UPDATE e2ee_pending p
            SET proposal = p_proposals[v_i], proposal_epoch = p_epoch
            WHERE p.id = p_ids[v_i] AND p.conversation_id = p_conv AND p.proposal IS NULL;
            IF FOUND THEN
                v_made := v_made + 1;
            END IF;
        END IF;
    END LOOP;
    IF v_made > 0 THEN
        INSERT INTO e2ee_handshake (conversation_id, kind, epoch, data)
        VALUES (p_conv, 'proposals', p_epoch, p_batch);
        PERFORM app_e2ee_hint(p_conv);
    END IF;
END;
$$;

-- The handshake log after `p_after`, for one of the caller's devices: the proposals and commits
-- from the epoch it joined at, and the welcomes made for it. Nothing from before it joined.
CREATE FUNCTION app_e2ee_handshake(p_conv uuid, p_device uuid, p_after bigint, p_limit integer)
RETURNS TABLE (r_seq bigint, r_kind text, r_epoch bigint, r_data bytea)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_joined bigint;
BEGIN
    PERFORM app_e2ee_gate(p_conv, p_device, false);
    IF p_after IS NULL OR p_after < 0 OR p_limit IS NULL OR p_limit < 1 OR p_limit > 200 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    SELECT l.joined_epoch INTO v_joined FROM e2ee_leaves l
    WHERE l.conversation_id = p_conv AND l.device_id = p_device;
    RETURN QUERY
    SELECT h.seq, h.kind, h.epoch, h.data
    FROM e2ee_handshake h
    WHERE h.conversation_id = p_conv AND h.seq > p_after
      AND ((h.kind = 'welcome' AND h.for_device = p_device)
           OR (h.kind IN ('proposals', 'commit') AND v_joined IS NOT NULL AND h.epoch >= v_joined))
    ORDER BY h.seq
    LIMIT p_limit;
END;
$$;

-- What a commit is checked against, read in one snapshot: the epoch, the leaf the committing
-- device sits in (as r_leaf on every row), and each signed proposal of this epoch with the
-- device it is for. An epoch that has moved on is stale. A device not in the group, or one that
-- is itself being removed, cannot commit.
CREATE FUNCTION app_e2ee_commit_snapshot(p_conv uuid, p_device uuid, p_epoch bigint)
RETURNS TABLE (
    r_leaf integer,
    r_id bigint,
    r_op text,
    r_device uuid,
    r_proposal bytea,
    r_package bytea
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_epoch bigint;
    v_leaf integer;
BEGIN
    PERFORM app_e2ee_gate(p_conv, p_device, false);
    SELECT g.epoch INTO v_epoch FROM e2ee_groups g WHERE g.conversation_id = p_conv;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no group' USING ERRCODE = 'P0E05';
    END IF;
    IF v_epoch <> p_epoch THEN
        RAISE EXCEPTION 'stale epoch' USING ERRCODE = 'P0E03';
    END IF;
    SELECT l.leaf_index INTO v_leaf FROM e2ee_leaves l
    WHERE l.conversation_id = p_conv AND l.device_id = p_device;
    IF NOT FOUND OR EXISTS (SELECT 1 FROM e2ee_pending p
                            WHERE p.conversation_id = p_conv AND p.device_id = p_device
                              AND p.op = 'remove') THEN
        RAISE EXCEPTION 'not in group' USING ERRCODE = 'P0E07';
    END IF;
    RETURN QUERY
    SELECT v_leaf, p.id, p.op, p.device_id, p.proposal, p.key_package
    FROM e2ee_pending p
    WHERE p.conversation_id = p_conv AND p.proposal IS NOT NULL AND p.proposal_epoch = v_epoch
    ORDER BY p.id;
END;
$$;

-- Applies a commit the API has checked. The compare-and-swap is here: the epoch must still be
-- `p_epoch` and the signed proposals must still be exactly `p_ids`, which the commit applies in
-- the order it names them. A commit that lost the race is stale; one that missed a proposal
-- signed meanwhile must be made again from the log.
CREATE FUNCTION app_e2ee_apply_commit(
    p_conv uuid,
    p_device uuid,
    p_epoch bigint,
    p_commit bytea,
    p_ids bigint[],
    p_welcome_devices uuid[],
    p_welcomes bytea[]
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_epoch bigint;
    v_issued bigint[];
    v_row record;
    v_added uuid[] := '{}';
    v_seq bigint;
    v_i integer;
BEGIN
    PERFORM app_e2ee_gate(p_conv, p_device, false);
    PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.e2ee.' || p_conv::text, 0));
    SELECT g.epoch INTO v_epoch FROM e2ee_groups g
    WHERE g.conversation_id = p_conv FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no group' USING ERRCODE = 'P0E05';
    END IF;
    IF v_epoch <> p_epoch THEN
        RAISE EXCEPTION 'stale epoch' USING ERRCODE = 'P0E03';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM e2ee_leaves l
                   WHERE l.conversation_id = p_conv AND l.device_id = p_device)
       OR EXISTS (SELECT 1 FROM e2ee_pending p
                  WHERE p.conversation_id = p_conv AND p.device_id = p_device
                    AND p.op = 'remove') THEN
        RAISE EXCEPTION 'not in group' USING ERRCODE = 'P0E07';
    END IF;
    SELECT coalesce(array_agg(p.id ORDER BY p.id), '{}') INTO v_issued
    FROM e2ee_pending p
    WHERE p.conversation_id = p_conv AND p.proposal IS NOT NULL AND p.proposal_epoch = v_epoch;
    IF cardinality(v_issued) = 0
       OR v_issued IS DISTINCT FROM (SELECT coalesce(array_agg(x ORDER BY x), '{}')
                                     FROM unnest(p_ids) AS u (x)) THEN
        RAISE EXCEPTION 'proposals changed' USING ERRCODE = 'P0E04';
    END IF;

    -- Removes first, then Adds in the order the commit lists them.
    FOR v_row IN
        SELECT p.id, p.device_id, p.leaf_index FROM e2ee_pending p
        WHERE p.id = ANY (p_ids) AND p.op = 'remove'
    LOOP
        DELETE FROM e2ee_leaves l
        WHERE l.conversation_id = p_conv AND l.leaf_index = v_row.leaf_index
          AND l.device_id = v_row.device_id;
        DELETE FROM e2ee_handshake h WHERE h.conversation_id = p_conv AND h.for_device = v_row.device_id;
    END LOOP;
    FOR v_row IN
        SELECT p.id, p.device_id, d.user_id
        FROM unnest(p_ids) WITH ORDINALITY AS o (id, ord)
        JOIN e2ee_pending p ON p.id = o.id
        JOIN e2ee_devices d ON d.device_id = p.device_id
        WHERE p.op = 'add'
        ORDER BY o.ord
    LOOP
        INSERT INTO e2ee_leaves (conversation_id, leaf_index, user_id, device_id, joined_epoch)
        VALUES (p_conv, app_e2ee_free_leaf(p_conv), v_row.user_id, v_row.device_id, p_epoch + 1);
        v_added := v_added || v_row.device_id;
    END LOOP;
    DELETE FROM e2ee_pending p WHERE p.id = ANY (p_ids);

    IF coalesce(cardinality(p_welcome_devices), 0) <> cardinality(v_added)
       OR coalesce(cardinality(p_welcomes), 0) <> cardinality(v_added)
       OR EXISTS (SELECT 1 FROM unnest(p_welcome_devices) AS w (x) WHERE x <> ALL (v_added)) THEN
        RAISE EXCEPTION 'welcomes do not match the adds' USING ERRCODE = 'P0E15';
    END IF;

    -- The proposals of this epoch stay in the log: a member that has not read them yet needs them
    -- to apply the commit, which names them by reference.
    INSERT INTO e2ee_handshake (conversation_id, kind, epoch, data)
    VALUES (p_conv, 'commit', p_epoch, p_commit)
    RETURNING seq INTO v_seq;
    FOR v_i IN 1..coalesce(cardinality(p_welcome_devices), 0) LOOP
        INSERT INTO e2ee_handshake (conversation_id, kind, epoch, data, for_device)
        VALUES (p_conv, 'welcome', p_epoch + 1, p_welcomes[v_i], p_welcome_devices[v_i]);
    END LOOP;
    UPDATE e2ee_groups SET epoch = p_epoch + 1, updated_at = now() WHERE conversation_id = p_conv;

    -- Who can use the conversation may have changed while the commit was made.
    PERFORM app_e2ee_reconcile(p_conv, false);
    IF EXISTS (SELECT 1 FROM e2ee_groups g WHERE g.conversation_id = p_conv) THEN
        PERFORM app_e2ee_hint(p_conv);
    END IF;
    RETURN v_seq;
END;
$$;

DO $$
DECLARE
    v_function text;
BEGIN
    FOREACH v_function IN ARRAY ARRAY[
        'app_e2ee_put_device(uuid, bytea, bytea, text)',
        'app_e2ee_active_keys()',
        'app_e2ee_my_device_key(uuid)',
        'app_e2ee_revoke_device(uuid)',
        'app_e2ee_user_devices(uuid)',
        'app_e2ee_put_key_packages(uuid, bytea[], bigint[], bytea, bigint)',
        'app_e2ee_key_package_count(uuid)',
        'app_e2ee_server_key(bytea, bytea)',
        'app_e2ee_info(uuid)',
        'app_e2ee_create_group(uuid, uuid)',
        'app_e2ee_begin_issue(uuid)',
        'app_e2ee_issue(uuid, bigint, bigint[], bytea[], bytea)',
        'app_e2ee_handshake(uuid, uuid, bigint, integer)',
        'app_e2ee_commit_snapshot(uuid, uuid, bigint)',
        'app_e2ee_apply_commit(uuid, uuid, bigint, bytea, bigint[], uuid[], bytea[])'
    ]
    LOOP
        EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', v_function);
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO app_runtime', v_function);
    END LOOP;
    -- Internals: only other definer functions and the triggers call these.
    FOREACH v_function IN ARRAY ARRAY[
        'app_e2ee_max_devices()',
        'app_e2ee_forget_channel()',
        'app_e2ee_gate(uuid, uuid, boolean)',
        'app_e2ee_desired(uuid)',
        'app_e2ee_audience(uuid)',
        'app_e2ee_hint(uuid)',
        'app_e2ee_free_leaf(uuid)',
        'app_e2ee_reconcile(uuid, boolean)',
        'app_e2ee_reconcile_all()',
        'app_e2ee_reconcile_trigger()'
    ]
    LOOP
        EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC, app_runtime', v_function);
    END LOOP;
END $$;
