-- Server-side search over plaintext messages (issue #69).
--
-- Index choice: partial GIN expression index using `to_tsvector('simple', body)` where
-- `NOT e2ee AND deleted_at IS NULL AND msg_kind = 'message'`.
-- Why `to_tsvector('simple', body)` instead of `pg_trgm`:
--   1. `app_owner` is NOSUPERUSER (see docker/postgres/init/01-roles.sh), so creating the
--      `pg_trgm` extension is not available to migrations without superuser privileges.
--   2. The `'simple'` text search configuration is built in, language-neutral (avoids English
--      stemming surprises in multilingual communities), and fast on GIN.
--   3. As a partial expression index over `NOT e2ee AND deleted_at IS NULL AND msg_kind = 'message'`,
--      encrypted messages are never indexed, and edited/deleted text leaves the index automatically.

CREATE INDEX messages_body_search
    ON messages USING gin (to_tsvector('simple', body))
    WHERE NOT e2ee AND deleted_at IS NULL AND msg_kind = 'message';

-- Per-user rate limit log for search (30 searches per minute). Stores only user_id and
-- timestamp — never the query string.
CREATE TABLE search_rate_log (
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX search_rate_log_user ON search_rate_log (user_id, created_at DESC);

ALTER TABLE search_rate_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE search_rate_log FORCE ROW LEVEL SECURITY;

REVOKE ALL ON search_rate_log FROM app_runtime;

CREATE FUNCTION app_search_forget_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    DELETE FROM search_rate_log WHERE user_id = NEW.id;
    RETURN NULL;
END;
$$;

REVOKE EXECUTE ON FUNCTION app_search_forget_user() FROM PUBLIC;

CREATE TRIGGER users_forget_search_rate_log
    AFTER UPDATE OF deleted_at ON users
    FOR EACH ROW
    WHEN (OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL)
    EXECUTE FUNCTION app_search_forget_user();

-- Searches plaintext messages visible to the caller, newest first.
-- Returns {hits: [{conversation_id, kind, message}], more: bool, skipped_encrypted: bool}.
CREATE FUNCTION app_search_messages(
    p_query text,
    p_conversation uuid,
    p_author uuid,
    p_before uuid,
    p_limit integer
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_uid uuid := app_uid();
    v_query text := btrim(coalesce(p_query, ''));
    v_limit integer := coalesce(p_limit, 25);
    v_kind text;
    v_channel uuid;
    v_direct uuid;
    v_skipped boolean := false;
    v_before_seq bigint;
    v_tsquery tsquery;
    v_hits jsonb;
    v_more boolean := false;
    v_count integer;
BEGIN
    PERFORM app_msg_gate();
    IF char_length(v_query) < 2 OR char_length(v_query) > 200
       OR v_query ~ E'[\\x00-\\x1F\\x7F]' THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;
    IF v_limit < 1 OR v_limit > 50 THEN
        RAISE EXCEPTION 'invalid' USING ERRCODE = '22023';
    END IF;

    -- Rate limit: 30 searches per minute per user.
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.search.' || v_uid::text));
    DELETE FROM search_rate_log
    WHERE user_id = v_uid AND created_at <= now() - interval '1 minute';
    IF (
        SELECT count(*) FROM search_rate_log
        WHERE user_id = v_uid AND created_at > now() - interval '1 minute'
    ) >= 30 THEN
        RAISE EXCEPTION 'slow down' USING ERRCODE = 'P0E11';
    END IF;
    INSERT INTO search_rate_log (user_id, created_at) VALUES (v_uid, now());

    IF p_conversation IS NOT NULL THEN
        SELECT kind, channel_id, direct_id
        INTO v_kind, v_channel, v_direct
        FROM app_open_conversation(p_conversation, false);
        v_skipped := app_conv_e2ee(p_conversation);
    ELSE
        v_skipped := EXISTS (
            SELECT 1 FROM channels c
            WHERE c.e2ee AND app_channel_perms_of(c.id, v_uid) & 1 = 1
        ) OR EXISTS (
            SELECT 1 FROM directs d
            WHERE d.e2ee AND NOT d.is_self
              AND v_uid IN (d.low_user_id, d.high_user_id)
        );
    END IF;

    IF p_before IS NOT NULL THEN
        SELECT m.seq INTO v_before_seq FROM messages m WHERE m.id = p_before;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
        END IF;
    END IF;

    v_tsquery := plainto_tsquery('simple', v_query);
    IF v_tsquery = ''::tsquery THEN
        RETURN jsonb_build_object(
            'hits', '[]'::jsonb,
            'more', false,
            'skipped_encrypted', v_skipped
        );
    END IF;

    WITH matched AS (
        SELECT m.id,
               coalesce(m.channel_id, m.direct_id) AS conversation_id,
               CASE WHEN m.channel_id IS NOT NULL THEN 'channel' ELSE 'direct' END AS kind,
               m.seq
        FROM messages m
        WHERE m.deleted_at IS NULL
          AND NOT m.e2ee
          AND m.msg_kind = 'message'
          AND to_tsvector('simple', m.body) @@ v_tsquery
          AND (p_author IS NULL OR m.author_id = p_author)
          AND (v_before_seq IS NULL OR (m.seq, m.id) < (v_before_seq, p_before))
          AND (
              (p_conversation IS NOT NULL AND (
                  (v_channel IS NOT NULL AND m.channel_id = v_channel)
                  OR (v_direct IS NOT NULL AND m.direct_id = v_direct)
              ))
              OR (p_conversation IS NULL AND (
                  (m.channel_id IS NOT NULL AND app_channel_perms_of(m.channel_id, v_uid) & 1 = 1)
                  OR (m.direct_id IS NOT NULL AND EXISTS (
                      SELECT 1 FROM directs d
                      WHERE d.id = m.direct_id
                        AND NOT d.is_self
                        AND v_uid IN (d.low_user_id, d.high_user_id)
                  ))
              ))
          )
        ORDER BY m.seq DESC, m.id DESC
        LIMIT v_limit + 1
    ),
    counted AS (
        SELECT count(*)::integer AS total FROM matched
    ),
    page AS (
        SELECT id, conversation_id, kind, seq
        FROM matched
        ORDER BY seq DESC, id DESC
        LIMIT v_limit
    )
    SELECT coalesce(
               (SELECT jsonb_agg(
                    jsonb_build_object(
                        'conversation_id', p.conversation_id::text,
                        'kind', p.kind,
                        'message', app_message_json(p.id, v_uid)
                    )
                    ORDER BY p.seq DESC, p.id DESC
                ) FROM page p),
               '[]'::jsonb
           ),
           (SELECT total FROM counted)
    INTO v_hits, v_count;

    v_more := coalesce(v_count, 0) > v_limit;

    RETURN jsonb_build_object(
        'hits', v_hits,
        'more', v_more,
        'skipped_encrypted', v_skipped
    );
END;
$$;

REVOKE EXECUTE ON FUNCTION app_search_messages(text, uuid, uuid, uuid, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_search_messages(text, uuid, uuid, uuid, integer) TO app_runtime;

-- Rollback: crates/db/rollback/0051_message_search.down.sql drops app_search_messages,
-- the trigger, search_rate_log, and the messages_body_search index.
