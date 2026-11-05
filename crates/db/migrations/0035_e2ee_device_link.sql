-- Device linking: a person's new device and a device they already have talk through the server for
-- a few minutes, and the old one hands the new one an archive of their history. Everything the
-- server holds here is opaque: the messages are sealed device to device under keys the server
-- never sees (except the first, a public key), and the archive is sealed under a key that only
-- travels inside those messages. The protocol is docs/e2ee-text.md section 5.
--
-- Only sessions of the person who made a link can touch it. A link lasts e2ee_link_ttl_secs (5
-- minutes by default); its messages go when it expires, and its archive an hour after that, or at
-- once when either device deletes the link. The archive is a file in the upload directory, under
-- links/, named by 32 random bytes that are not the link id. No public media route reads it.
--
-- New SQLSTATE of class P0E, mapped in crates/db/src/messages.rs:
--   P0E20 archive_exists

ALTER TABLE server_settings
    -- The largest archive one link may carry. 512 MiB by default.
    ADD COLUMN e2ee_link_archive_max bigint NOT NULL DEFAULT 536870912
        CHECK (e2ee_link_archive_max BETWEEN 1048576 AND 17179869184),
    -- How long a link may be used for messages, and may start an archive upload.
    ADD COLUMN e2ee_link_ttl_secs integer NOT NULL DEFAULT 300
        CHECK (e2ee_link_ttl_secs BETWEEN 60 AND 3600);

CREATE TABLE e2ee_links (
    -- 16 random bytes, made by the server.
    id bytea PRIMARY KEY CHECK (octet_length(id) = 16),
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    -- The archive's file name: 64 hex characters, random, never derived from the id.
    archive_name text UNIQUE CHECK (archive_name ~ '^[0-9a-f]{64}$'),
    archive_state text NOT NULL DEFAULT 'none'
        CHECK (archive_state IN ('none', 'uploading', 'ready')),
    archive_bytes bigint CHECK (archive_bytes >= 1),
    CHECK ((archive_state = 'none') = (archive_name IS NULL)),
    CHECK ((archive_state = 'none') = (archive_bytes IS NULL))
);

CREATE INDEX e2ee_links_user ON e2ee_links (user_id);
CREATE INDEX e2ee_links_expiry ON e2ee_links (expires_at);

-- At most 16 per link, numbered from 1. `sender` is the label the client sent, `new` or `old`.
CREATE TABLE e2ee_link_messages (
    link_id bytea NOT NULL REFERENCES e2ee_links (id) ON DELETE CASCADE,
    seq integer NOT NULL CHECK (seq BETWEEN 1 AND 16),
    sender text NOT NULL CHECK (sender IN ('new', 'old')),
    data bytea NOT NULL CHECK (octet_length(data) BETWEEN 1 AND 8192),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (link_id, seq)
);

-- app_runtime may not touch these tables. Every read and write goes through a function.
REVOKE ALL ON e2ee_links, e2ee_link_messages FROM app_runtime;

ALTER TABLE e2ee_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE e2ee_links FORCE ROW LEVEL SECURITY;
ALTER TABLE e2ee_link_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE e2ee_link_messages FORCE ROW LEVEL SECURITY;

-- The caller's own link, locked, while messages may still be posted and read. Anyone else's
-- link, an expired one, and one that does not exist are all the same `not found`.
CREATE FUNCTION app_e2ee_link_open(p_id bytea)
RETURNS e2ee_links
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_link e2ee_links;
BEGIN
    PERFORM app_msg_gate();
    SELECT * INTO v_link FROM e2ee_links l
    WHERE l.id = p_id AND l.user_id = app_uid() AND l.expires_at > now()
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    RETURN v_link;
END;
$$;

REVOKE EXECUTE ON FUNCTION app_e2ee_link_open(bytea) FROM PUBLIC, app_runtime;

-- A new link. At most 5 unexpired links per person (`slow_down`). Returns when it expires.
CREATE FUNCTION app_e2ee_link_create(p_id bytea)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_user uuid := app_uid();
    v_expires timestamptz;
BEGIN
    PERFORM app_msg_gate();
    IF p_id IS NULL OR octet_length(p_id) <> 16 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.e2ee.link.' || v_user::text, 0));
    IF (SELECT count(*) FROM e2ee_links l WHERE l.user_id = v_user AND l.expires_at > now()) >= 5 THEN
        RAISE EXCEPTION 'too many links' USING ERRCODE = 'P0E11';
    END IF;
    INSERT INTO e2ee_links (id, user_id, expires_at)
    SELECT p_id, v_user, now() + make_interval(secs => s.e2ee_link_ttl_secs)
    FROM server_settings s
    RETURNING expires_at INTO v_expires;
    RETURN app_stamp(v_expires);
END;
$$;

-- One message. The 17th is `slow_down`. Returns its number.
CREATE FUNCTION app_e2ee_link_post(p_id bytea, p_sender text, p_data bytea)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_seq integer;
BEGIN
    PERFORM app_e2ee_link_open(p_id);
    IF p_sender IS NULL OR p_sender NOT IN ('new', 'old') THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF p_data IS NULL OR octet_length(p_data) < 1 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF octet_length(p_data) > 8192 THEN
        RAISE EXCEPTION 'too large' USING ERRCODE = '22023';
    END IF;
    SELECT coalesce(max(m.seq), 0) + 1 INTO v_seq FROM e2ee_link_messages m WHERE m.link_id = p_id;
    IF v_seq > 16 THEN
        RAISE EXCEPTION 'too many messages' USING ERRCODE = 'P0E11';
    END IF;
    INSERT INTO e2ee_link_messages (link_id, seq, sender, data) VALUES (p_id, v_seq, p_sender, p_data);
    RETURN v_seq;
END;
$$;

-- The messages after `p_after`, in order.
CREATE FUNCTION app_e2ee_link_messages(p_id bytea, p_after integer)
RETURNS TABLE (r_seq integer, r_sender text, r_data bytea)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    PERFORM app_e2ee_link_open(p_id);
    RETURN QUERY
        SELECT m.seq, m.sender, m.data
        FROM e2ee_link_messages m
        WHERE m.link_id = p_id AND m.seq > coalesce(p_after, 0)
        ORDER BY m.seq;
END;
$$;

-- Deletes the caller's link and its messages, expired or not. Returns the archive's file name, for
-- the caller to delete, or NULL. Someone else's link is left alone and looks the same as none.
CREATE FUNCTION app_e2ee_link_delete(p_id bytea)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_name text;
BEGIN
    PERFORM app_msg_gate();
    DELETE FROM e2ee_links l
    WHERE l.id = p_id AND l.user_id = app_uid()
    RETURNING l.archive_name INTO v_name;
    RETURN v_name;
END;
$$;

-- Starts the link's one archive. The link must not have expired, must not have one, and the
-- person may have one archive in flight or stored at a time (`slow_down`). `p_bytes` is the
-- declared length; past the server's setting it is `too large`.
CREATE FUNCTION app_e2ee_link_archive_begin(p_id bytea, p_name text, p_bytes bigint)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_user uuid := app_uid();
    v_link e2ee_links;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('tinyserver.e2ee.link.' || v_user::text, 0));
    v_link := app_e2ee_link_open(p_id);
    IF p_name IS NULL OR p_name !~ '^[0-9a-f]{64}$' OR p_bytes IS NULL OR p_bytes < 1 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF p_bytes > (SELECT s.e2ee_link_archive_max FROM server_settings s) THEN
        RAISE EXCEPTION 'too large' USING ERRCODE = '22023';
    END IF;
    IF v_link.archive_state <> 'none' THEN
        RAISE EXCEPTION 'archive exists' USING ERRCODE = 'P0E20';
    END IF;
    IF EXISTS (
        SELECT 1 FROM e2ee_links l
        WHERE l.user_id = v_user AND l.archive_state <> 'none'
    ) THEN
        RAISE EXCEPTION 'archive in flight' USING ERRCODE = 'P0E11';
    END IF;
    UPDATE e2ee_links
    SET archive_name = p_name, archive_state = 'uploading', archive_bytes = p_bytes
    WHERE id = p_id;
END;
$$;

-- An upload that failed: the link may take another. Nothing when the upload is not this one.
CREATE FUNCTION app_e2ee_link_archive_abort(p_id bytea, p_name text)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
    UPDATE e2ee_links
    SET archive_name = NULL, archive_state = 'none', archive_bytes = NULL
    WHERE id = p_id AND user_id = app_uid() AND archive_name = p_name
      AND archive_state = 'uploading';
$$;

-- An upload that finished with every byte it declared. False when the link went meanwhile: the
-- caller then deletes the file.
CREATE FUNCTION app_e2ee_link_archive_done(p_id bytea, p_name text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    UPDATE e2ee_links
    SET archive_state = 'ready'
    WHERE id = p_id AND user_id = app_uid() AND archive_name = p_name
      AND archive_state = 'uploading';
    RETURN FOUND;
END;
$$;

-- The caller's stored archive: its file name and length. It stays readable for an hour past the
-- link's expiry, so a large download that started in time can finish or resume.
CREATE FUNCTION app_e2ee_link_archive(p_id bytea)
RETURNS TABLE (r_name text, r_bytes bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    PERFORM app_msg_gate();
    RETURN QUERY
        SELECT l.archive_name, l.archive_bytes
        FROM e2ee_links l
        WHERE l.id = p_id AND l.user_id = app_uid() AND l.archive_state = 'ready'
          AND l.expires_at + interval '1 hour' > now();
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
END;
$$;

-- The periodic sweep: messages of expired links, links that expired with no archive, and links
-- whose archive is an hour past expiry. Returns the archive file names whose rows went, for the
-- caller to delete.
CREATE FUNCTION app_e2ee_link_sweep()
RETURNS SETOF text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    DELETE FROM e2ee_link_messages m
    USING e2ee_links l
    WHERE m.link_id = l.id AND l.expires_at <= now();
    DELETE FROM e2ee_links l WHERE l.expires_at <= now() AND l.archive_state = 'none';
    RETURN QUERY
        DELETE FROM e2ee_links l
        WHERE l.expires_at + interval '1 hour' <= now()
        RETURNING l.archive_name;
END;
$$;

-- Every archive file name a row still has, so the sweep can delete files no row names: one left
-- by a crash, or by a deleted account.
CREATE FUNCTION app_e2ee_link_archive_names()
RETURNS SETOF text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT l.archive_name FROM e2ee_links l WHERE l.archive_name IS NOT NULL;
$$;

-- What GET /v1/capabilities says of this feature. Nothing a member cannot learn by trying.
CREATE FUNCTION app_e2ee_link_archive_max()
RETURNS bigint
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT s.e2ee_link_archive_max FROM server_settings s;
$$;

DO $$
DECLARE
    v_function text;
BEGIN
    FOREACH v_function IN ARRAY ARRAY[
        'app_e2ee_link_create(bytea)',
        'app_e2ee_link_post(bytea, text, bytea)',
        'app_e2ee_link_messages(bytea, integer)',
        'app_e2ee_link_delete(bytea)',
        'app_e2ee_link_archive_begin(bytea, text, bigint)',
        'app_e2ee_link_archive_abort(bytea, text)',
        'app_e2ee_link_archive_done(bytea, text)',
        'app_e2ee_link_archive(bytea)',
        'app_e2ee_link_sweep()',
        'app_e2ee_link_archive_names()',
        'app_e2ee_link_archive_max()'
    ]
    LOOP
        EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', v_function);
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO app_runtime', v_function);
    END LOOP;
END;
$$;

-- Deleting an account tombstones the user row, so the foreign key above does not fire. This does
-- what it would. The sweep deletes the archive file, which no row names any more.
CREATE FUNCTION app_e2ee_link_forget_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    DELETE FROM e2ee_links WHERE user_id = NEW.id;
    RETURN NULL;
END;
$$;

REVOKE EXECUTE ON FUNCTION app_e2ee_link_forget_user() FROM PUBLIC;

CREATE TRIGGER users_forget_e2ee_links
    AFTER UPDATE OF deleted_at ON users
    FOR EACH ROW
    WHEN (OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL)
    EXECUTE FUNCTION app_e2ee_link_forget_user();
