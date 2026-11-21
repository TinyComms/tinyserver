-- Undoes migrations/0054_channel_threads.sql. Run as the owner role, in one transaction, then
-- start the previous build.

BEGIN;

DROP FUNCTION IF EXISTS app_post_message_thread(uuid, text, uuid, text, uuid[], jsonb, uuid, uuid, jsonb, jsonb);
DROP FUNCTION IF EXISTS app_list_followed_threads();
DROP FUNCTION IF EXISTS app_unfollow_thread(uuid);
DROP FUNCTION IF EXISTS app_follow_thread(uuid);
DROP FUNCTION IF EXISTS app_mark_thread_read(uuid, uuid);
DROP FUNCTION IF EXISTS app_list_thread_messages(uuid, uuid, integer);
DROP FUNCTION IF EXISTS app_list_messages_filtered(uuid, uuid, integer, boolean);
DROP FUNCTION IF EXISTS app_thread_summary(uuid, uuid);
DROP FUNCTION IF EXISTS app_thread_unread(uuid, uuid);

DROP TABLE IF EXISTS thread_follows;
DELETE FROM reads WHERE kind = 'thread';
ALTER TABLE reads DROP CONSTRAINT IF EXISTS reads_kind_check;
ALTER TABLE reads ADD CONSTRAINT reads_kind_check CHECK (kind IN ('channel', 'direct'));

DROP INDEX IF EXISTS messages_thread_order;
ALTER TABLE messages DROP COLUMN IF EXISTS thread_id;

CREATE OR REPLACE FUNCTION app_unread(p_kind text, p_conversation uuid)
RETURNS integer
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT count(*)::integer
    FROM messages m
    WHERE m.deleted_at IS NULL
      AND m.msg_kind = 'message'
      AND m.author_id <> app_uid()
      AND NOT EXISTS (
          SELECT 1 FROM blocks b
          WHERE b.blocker_id = app_uid() AND b.blocked_id = m.author_id
      )
      AND ((p_kind = 'channel' AND m.channel_id = p_conversation)
           OR (p_kind = 'direct' AND m.direct_id = p_conversation))
      AND NOT EXISTS (
          SELECT 1
          FROM reads r
          JOIN messages cursor_message ON cursor_message.id = r.message_id
          WHERE r.user_id = app_uid()
            AND r.kind = p_kind
            AND r.conversation_id = p_conversation
            AND m.seq <= cursor_message.seq
      );
$$;

CREATE OR REPLACE FUNCTION app_unread_mentions(p_kind text, p_conversation uuid)
RETURNS integer
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT count(*)::integer
    FROM messages m
    WHERE m.deleted_at IS NULL
      AND NOT m.e2ee
      AND m.msg_kind = 'message'
      AND m.author_id <> app_uid()
      AND NOT EXISTS (
          SELECT 1 FROM blocks b
          WHERE b.blocker_id = app_uid() AND b.blocked_id = m.author_id
      )
      AND ((p_kind = 'channel' AND m.channel_id = p_conversation)
           OR (p_kind = 'direct' AND m.direct_id = p_conversation))
      AND NOT EXISTS (
          SELECT 1
          FROM reads r
          JOIN messages cursor_message ON cursor_message.id = r.message_id
          WHERE r.user_id = app_uid()
            AND r.kind = p_kind
            AND r.conversation_id = p_conversation
            AND m.seq <= cursor_message.seq
      )
      AND EXISTS (
          SELECT 1
          FROM message_mentions mm
          WHERE mm.message_id = m.id
            AND (
                (mm.kind = 'user' AND mm.target_id = app_uid())
                OR mm.kind = 'everyone'
                OR (mm.kind = 'role' AND EXISTS (
                    SELECT 1 FROM member_roles mr
                    WHERE mr.user_id = app_uid() AND mr.role_id = mm.target_id
                ))
            )
      );
$$;

CREATE OR REPLACE FUNCTION app_message_json(p_id uuid, p_viewer uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT jsonb_build_object(
        'id', m.id::text,
        'author_id', m.author_id::text,
        'body', CASE WHEN m.deleted_at IS NULL THEN m.body ELSE '' END,
        'reply_to', m.reply_to::text,
        'client_id', m.client_id,
        'created_at', app_stamp(m.created_at),
        'edited_at', CASE WHEN m.edited_at IS NULL THEN NULL ELSE app_stamp(m.edited_at) END,
        'deleted_at', CASE WHEN m.deleted_at IS NULL THEN NULL ELSE app_stamp(m.deleted_at) END,
        'deleted_by', CASE WHEN m.deleted_by <> m.author_id THEN m.deleted_by::text END,
        'e2ee', m.e2ee,
        'emoji', CASE WHEN m.deleted_at IS NULL THEN m.emoji_spans ELSE '[]'::jsonb END,
        'sticker_id', CASE WHEN m.deleted_at IS NULL THEN m.sticker_id::text END,
        'attachments', coalesce((
            SELECT jsonb_agg(jsonb_build_object(
                'id', a.id::text,
                'name', a.name,
                'mime', a.mime,
                'kind', a.kind,
                'bytes', a.bytes,
                'width', a.width,
                'height', a.height,
                'duration', a.duration
            ) ORDER BY a.sort, a.created_at, a.id)
            FROM attachments a
            WHERE a.message_id = m.id AND NOT a.is_preview AND m.deleted_at IS NULL
        ), '[]'::jsonb),
        'reactions', coalesce((
            SELECT jsonb_agg(
                CASE WHEN r.emoji_id IS NULL THEN
                    jsonb_build_object(
                        'emoji', r.emoji,
                        'count', r.count,
                        'me', r.me
                    )
                ELSE
                    jsonb_build_object(
                        'emoji', r.emoji,
                        'emoji_id', r.emoji_id::text,
                        'name', r.name,
                        'count', r.count,
                        'me', r.me
                    )
                END
                ORDER BY r.emoji, r.emoji_id NULLS FIRST
            )
            FROM (
                SELECT
                    coalesce(':' || e.name || ':', rx.emoji) AS emoji,
                    rx.emoji_id,
                    e.name,
                    count(*) AS count,
                    bool_or(rx.user_id = p_viewer) AS me
                FROM reactions rx
                LEFT JOIN emoji e ON e.id = rx.emoji_id
                WHERE rx.message_id = m.id AND m.deleted_at IS NULL
                GROUP BY rx.emoji_id, coalesce(':' || e.name || ':', rx.emoji), e.name
            ) r
        ), '[]'::jsonb)
    ) || CASE WHEN m.e2ee THEN jsonb_build_object(
        'kind', m.msg_kind,
        'ciphertext', CASE WHEN m.deleted_at IS NULL
            THEN translate(encode(m.ciphertext, 'base64'), E'\n', '') END,
        'epoch', m.epoch,
        'generation', m.generation,
        'group_id', m.group_id::text,
        'device_id', m.device_id::text,
        'target_id', m.target_id::text,
        'seq', m.seq
    ) ELSE jsonb_build_object(
        'mentions', coalesce((
            SELECT jsonb_agg(
                CASE WHEN mm.target_id IS NULL THEN
                    jsonb_build_object('kind', mm.kind, 'start', mm.start_at, 'end', mm.end_at)
                ELSE
                    jsonb_build_object('kind', mm.kind, 'id', mm.target_id::text, 'start', mm.start_at, 'end', mm.end_at)
                END
                ORDER BY mm.start_at, mm.end_at, mm.kind, mm.target_id
            )
            FROM message_mentions mm
            WHERE mm.message_id = m.id AND m.deleted_at IS NULL
        ), '[]'::jsonb),
        'previews', coalesce((
            SELECT jsonb_agg(
                jsonb_strip_nulls(jsonb_build_object(
                    'url', mp.url,
                    'site', mp.site,
                    'title', mp.title,
                    'description', mp.description,
                    'image_attachment_id', mp.image_attachment_id::text
                ))
                ORDER BY mp.sort
            )
            FROM message_previews mp
            WHERE mp.message_id = m.id AND m.deleted_at IS NULL
        ), '[]'::jsonb)
    ) END
    FROM messages m
    WHERE m.id = p_id;
$$;

CREATE OR REPLACE FUNCTION app_delete_message(p_id uuid)
RETURNS text[]
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_author uuid;
    v_channel uuid;
    v_direct uuid;
    v_deleted timestamptz;
    v_mine boolean;
    v_kind text;
    v_low uuid;
    v_high uuid;
    v_conv uuid;
    v_files text[];
    v_all uuid[];
BEGIN
    PERFORM app_msg_voice();
    SELECT author_id, channel_id, direct_id, deleted_at
    INTO v_author, v_channel, v_direct, v_deleted
    FROM messages WHERE id = p_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    v_mine := v_author = app_uid();
    v_conv := coalesce(v_channel, v_direct);
    SELECT kind, low_user_id, high_user_id INTO v_kind, v_low, v_high
    FROM app_open_conversation(v_conv, v_mine);
    IF NOT v_mine AND NOT (v_channel IS NOT NULL AND app_channel_has(v_channel, 2097152)) THEN
        RAISE EXCEPTION 'not allowed' USING ERRCODE = '42501';
    END IF;
    IF v_deleted IS NOT NULL THEN
        RETURN '{}'::text[];
    END IF;
    SELECT p_id || coalesce(array_agg(m.id), '{}') INTO v_all
    FROM messages m WHERE m.target_id = p_id;
    SELECT coalesce(array_agg(id::text), '{}') INTO v_files
    FROM attachments WHERE message_id = ANY (v_all);
    DELETE FROM message_previews WHERE message_id = ANY (v_all);
    DELETE FROM attachments WHERE message_id = ANY (v_all);
    DELETE FROM reactions WHERE message_id = ANY (v_all);
    DELETE FROM channel_pins WHERE message_id = ANY (v_all);
    DELETE FROM message_mentions WHERE message_id = ANY (v_all);
    UPDATE messages SET body = '', deleted_at = now(),
        deleted_by = CASE WHEN v_mine THEN NULL ELSE app_uid() END
    WHERE id = ANY (v_all) AND deleted_at IS NULL;
    IF NOT v_mine THEN
        PERFORM app_audit('message.delete', 'message',
                          jsonb_build_object('message_id', p_id, 'channel_id', v_channel),
                          v_author, NULL);
    END IF;
    PERFORM app_emit_to(
        'message.deleted',
        jsonb_build_object(
            'conversation_id', v_conv::text,
            'kind', v_kind,
            'message', app_message_json(p_id, app_uid())
        ),
        app_audience(v_kind, v_low, v_high)
    );
    RETURN v_files;
END;
$$;

DELETE FROM _sqlx_migrations WHERE version = 54;

COMMIT;
