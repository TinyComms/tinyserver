-- End-to-end encrypted text and sealed attachments, part 1: what a conversation is, who a
-- device is, and the key packages waiting to add it. The protocol is docs/e2ee-text.md.
--
-- The server never holds a key that opens a message. Everything below is either a public MLS
-- object (a key package, a signature key) or a setting. app_runtime reads and writes the new
-- tables only through the SECURITY DEFINER functions of 0021 and 0022; it has no grant on them.
--
-- SQLSTATEs of class P0E are this feature's own, mapped in crates/db/src/messages.rs:
--   P0E01 e2ee_required      P0E02 not_e2ee            P0E03 stale_epoch
--   P0E04 proposals_changed  P0E05 no_group            P0E06 group_exists
--   P0E07 not_in_group       P0E08 device_exists       P0E09 cross_signature_required
--   P0E10 too_many_keys      P0E11 slow_down           P0E12 e2ee_off
--   P0E13 bad_device         P0E14 too_many_devices    P0E15 bad_e2ee
--   P0E16 group_too_large    P0E17 id_taken

-- off: no new encrypted conversations. optional: either, the default. new_required: a new
-- conversation must be encrypted. required: as new_required, and no plaintext text is accepted
-- anywhere any more: an old plaintext conversation is read-only, and plaintext uploads are
-- refused. Existing conversations are never converted either way.
ALTER TABLE server_settings
    ADD COLUMN e2ee_text text NOT NULL DEFAULT 'optional'
        CHECK (e2ee_text IN ('off', 'optional', 'new_required', 'required')),
    -- The most devices one encrypted group may hold. Past it, the server refuses to make an
    -- encrypted channel and stops adding devices to a group: a Welcome carries the whole ratchet
    -- tree unless the committer uploads the tree, and a joiner checks every leaf, so a bigger
    -- group is slow on a phone and near the size limits (docs/e2ee-text.md section 10).
    ADD COLUMN e2ee_group_devices_max integer NOT NULL DEFAULT 2000
        CHECK (e2ee_group_devices_max BETWEEN 2 AND 20000),
    -- Sealed uploads are opaque to the server, so size and rate are all it can limit.
    ADD COLUMN sealed_files_per_hour integer NOT NULL DEFAULT 60
        CHECK (sealed_files_per_hour BETWEEN 1 AND 100000),
    ADD COLUMN sealed_bytes_per_day bigint NOT NULL DEFAULT 2147483648
        CHECK (sealed_bytes_per_day >= 1);

-- Fixed at creation, never cleared.
ALTER TABLE channels ADD COLUMN e2ee boolean NOT NULL DEFAULT false;
ALTER TABLE directs ADD COLUMN e2ee boolean NOT NULL DEFAULT false;

-- A pair of people may have one plaintext direct and one encrypted one. An existing plaintext
-- direct is never converted, so a pair that already talks must still be able to start an
-- encrypted conversation.
ALTER TABLE directs DROP CONSTRAINT directs_low_user_id_high_user_id_key;
ALTER TABLE directs ADD CONSTRAINT directs_pair_kind_key UNIQUE (low_user_id, high_user_id, e2ee);

-- A device is one install signed in to one account. Its signing key is made on the device.
CREATE TABLE e2ee_devices (
    device_id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id),
    signature_key bytea NOT NULL CHECK (octet_length(signature_key) = 65),
    cross_signature bytea CHECK (cross_signature IS NULL OR octet_length(cross_signature) BETWEEN 8 AND 128),
    label text NOT NULL DEFAULT '' CHECK (char_length(label) <= 80),
    low_keys boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);

CREATE INDEX e2ee_devices_user ON e2ee_devices (user_id) WHERE revoked_at IS NULL;

-- Public MLS key packages. One is claimed when the server builds an Add proposal and is then
-- deleted. A last resort package is never deleted.
CREATE TABLE e2ee_key_packages (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id uuid NOT NULL REFERENCES e2ee_devices (device_id) ON DELETE CASCADE,
    data bytea NOT NULL CHECK (octet_length(data) BETWEEN 1 AND 8192),
    last_resort boolean NOT NULL DEFAULT false,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX e2ee_key_packages_claim ON e2ee_key_packages (device_id, last_resort, id);
CREATE UNIQUE INDEX e2ee_key_packages_last_resort ON e2ee_key_packages (device_id) WHERE last_resort;

-- Every key package a device ever uploaded, by hash, so one cannot be used twice: its init key
-- is gone from the device once it has been used.
CREATE TABLE e2ee_key_package_hashes (
    device_id uuid NOT NULL REFERENCES e2ee_devices (device_id) ON DELETE CASCADE,
    hash bytea NOT NULL CHECK (octet_length(hash) = 32),
    PRIMARY KEY (device_id, hash)
);

-- The server's external sender key. It signs Add and Remove proposals and nothing else; it
-- cannot decrypt, commit or send an application message.
CREATE TABLE e2ee_server_key (
    only_row boolean PRIMARY KEY DEFAULT true CHECK (only_row),
    signature_key bytea NOT NULL CHECK (octet_length(signature_key) = 65),
    private_key bytea NOT NULL CHECK (octet_length(private_key) BETWEEN 16 AND 128),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- What the sealed uploads of a person add up to. Rows older than two days are swept.
CREATE TABLE e2ee_upload_ledger (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id),
    bytes bigint NOT NULL CHECK (bytes > 0),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX e2ee_upload_ledger_user ON e2ee_upload_ledger (user_id, created_at);

-- A message may be ciphertext. Then body is empty and the rest says where it goes.
ALTER TABLE messages
    ADD COLUMN e2ee boolean NOT NULL DEFAULT false,
    ADD COLUMN ciphertext bytea CHECK (ciphertext IS NULL OR octet_length(ciphertext) <= 32768),
    ADD COLUMN epoch bigint CHECK (epoch IS NULL OR epoch >= 0),
    ADD COLUMN device_id uuid REFERENCES e2ee_devices (device_id),
    ADD COLUMN msg_kind text NOT NULL DEFAULT 'message' CHECK (msg_kind IN ('message', 'edit')),
    ADD COLUMN target_id uuid REFERENCES messages (id) ON DELETE CASCADE;

ALTER TABLE messages ADD CONSTRAINT messages_e2ee_shape CHECK (
    (e2ee AND body = '' AND reply_to IS NULL AND device_id IS NOT NULL AND epoch IS NOT NULL
        AND (ciphertext IS NOT NULL OR deleted_at IS NOT NULL)
        AND ((msg_kind = 'edit') = (target_id IS NOT NULL)))
    OR (NOT e2ee AND ciphertext IS NULL AND epoch IS NULL AND device_id IS NULL
        AND msg_kind = 'message' AND target_id IS NULL)
);

-- A deleted ciphertext message keeps its row and loses its ciphertext, whoever deleted it.
CREATE FUNCTION app_e2ee_tombstone()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.ciphertext := NULL;
    RETURN NEW;
END;
$$;

CREATE TRIGGER messages_e2ee_tombstone
    BEFORE UPDATE OF deleted_at ON messages
    FOR EACH ROW
    WHEN (NEW.deleted_at IS NOT NULL AND OLD.ciphertext IS NOT NULL)
    EXECUTE FUNCTION app_e2ee_tombstone();

-- The replay key of a plaintext message is the author and client id, as before. A ciphertext
-- message is unique per sending device and conversation.
DROP INDEX messages_client;
CREATE UNIQUE INDEX messages_client
    ON messages (author_id, client_id)
    WHERE client_id IS NOT NULL AND NOT e2ee;
CREATE UNIQUE INDEX messages_e2ee_client
    ON messages (device_id, (coalesce(channel_id, direct_id)), client_id)
    WHERE client_id IS NOT NULL AND e2ee;
CREATE INDEX messages_e2ee_target ON messages (target_id) WHERE target_id IS NOT NULL;

-- A sealed upload is opaque: the server does not sniff, decode or scan it, and says so.
ALTER TABLE attachments DROP CONSTRAINT attachments_kind_check;
ALTER TABLE attachments ADD CONSTRAINT attachments_kind_check
    CHECK (kind IN ('image', 'gif', 'video', 'file', 'sealed'));
ALTER TABLE attachments DROP CONSTRAINT attachments_scan_status_check;
ALTER TABLE attachments ADD CONSTRAINT attachments_scan_status_check
    CHECK (scan_status IN ('uploaded', 'scanning', 'clean', 'blocked', 'error', 'sealed'));
ALTER TABLE attachments ADD CONSTRAINT attachments_sealed_shape CHECK (
    (kind = 'sealed') = (scan_status = 'sealed')
);

-- Topics may now carry a digit: e2ee.handshake, e2ee.device, e2ee.keys_low.
CREATE OR REPLACE FUNCTION app_emit_to(p_topic text, p_payload jsonb, p_audience uuid[])
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_id bigint;
BEGIN
    IF p_topic !~ '^[a-z][a-z0-9]*\.[a-z_]+$' THEN
        RAISE EXCEPTION 'invalid topic' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.outbox'));
    INSERT INTO outbox (topic, payload, audience)
    VALUES (p_topic, p_payload, app_scope_audience(p_payload, p_audience))
    RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;

CREATE OR REPLACE FUNCTION app_emit(p_topic text, p_payload jsonb)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_id bigint;
BEGIN
    IF p_topic !~ '^[a-z][a-z0-9]*\.[a-z_]+$' THEN
        RAISE EXCEPTION 'invalid topic' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.outbox'));
    INSERT INTO outbox (topic, payload, audience)
    VALUES (p_topic, p_payload, app_scope_audience(p_payload, NULL))
    RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;

-- Whether a conversation (a channel or a direct) is end-to-end encrypted. A missing one is not.
CREATE FUNCTION app_conv_e2ee(p_conv uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT coalesce(
        (SELECT c.e2ee FROM channels c WHERE c.id = p_conv),
        (SELECT d.e2ee FROM directs d WHERE d.id = p_conv),
        false
    );
$$;

REVOKE EXECUTE ON FUNCTION app_conv_e2ee(uuid) FROM PUBLIC, app_runtime;

-- app_runtime may not touch these tables. Every read and write goes through a function.
REVOKE ALL ON e2ee_devices, e2ee_key_packages, e2ee_key_package_hashes, e2ee_server_key,
    e2ee_upload_ledger FROM app_runtime;

ALTER TABLE e2ee_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE e2ee_devices FORCE ROW LEVEL SECURITY;
ALTER TABLE e2ee_key_packages ENABLE ROW LEVEL SECURITY;
ALTER TABLE e2ee_key_packages FORCE ROW LEVEL SECURITY;
ALTER TABLE e2ee_key_package_hashes ENABLE ROW LEVEL SECURITY;
ALTER TABLE e2ee_key_package_hashes FORCE ROW LEVEL SECURITY;
ALTER TABLE e2ee_server_key ENABLE ROW LEVEL SECURITY;
ALTER TABLE e2ee_server_key FORCE ROW LEVEL SECURITY;
ALTER TABLE e2ee_upload_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE e2ee_upload_ledger FORCE ROW LEVEL SECURITY;
