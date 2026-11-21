-- Undoes migrations/0053_custom_emoji.sql. Run as the owner role, in one transaction, then
-- start the previous build.

BEGIN;

DROP FUNCTION IF EXISTS app_post_message_ext(uuid, text, uuid, text, uuid[], jsonb, uuid);
DROP FUNCTION IF EXISTS app_clear_custom_reaction(uuid, uuid);
DROP FUNCTION IF EXISTS app_toggle_custom_reaction(uuid, uuid);
DROP FUNCTION IF EXISTS app_custom_reaction(uuid, uuid, boolean);
DROP FUNCTION IF EXISTS app_delete_emoji(uuid);
DROP FUNCTION IF EXISTS app_rename_emoji(uuid, text);
DROP FUNCTION IF EXISTS app_create_emoji(text, text, text, bytea, text, boolean);
DROP FUNCTION IF EXISTS app_get_emoji(uuid);
DROP FUNCTION IF EXISTS app_list_emoji(text);
DROP FUNCTION IF EXISTS app_emoji_list_json(text);

DELETE FROM reactions WHERE emoji_id IS NOT NULL;
DROP INDEX IF EXISTS reactions_custom_uniq;
DROP INDEX IF EXISTS reactions_unicode_uniq;
ALTER TABLE reactions DROP COLUMN IF EXISTS emoji_id;
ALTER TABLE reactions DROP CONSTRAINT IF EXISTS reactions_emoji_check;
ALTER TABLE reactions ADD CONSTRAINT reactions_emoji_check
    CHECK (char_length(emoji) BETWEEN 1 AND 16);
ALTER TABLE reactions ADD PRIMARY KEY (message_id, user_id, emoji);

ALTER TABLE messages DROP COLUMN IF EXISTS sticker_id;
ALTER TABLE messages DROP COLUMN IF EXISTS emoji_spans;
DROP TABLE IF EXISTS emoji;

CREATE OR REPLACE FUNCTION app_reaction(p_message uuid, p_emoji text, p_on boolean)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_channel uuid;
    v_direct uuid;
    v_deleted timestamptz;
    v_kind text;
    v_low uuid;
    v_high uuid;
    v_conv uuid;
    v_count integer;
    v_me boolean;
BEGIN
    PERFORM app_emoji_ok(p_emoji);
    PERFORM app_msg_voice();
    SELECT channel_id, direct_id, deleted_at INTO v_channel, v_direct, v_deleted
    FROM messages WHERE id = p_message;
    IF NOT FOUND OR v_deleted IS NOT NULL THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    v_conv := coalesce(v_channel, v_direct);
    SELECT kind, low_user_id, high_user_id INTO v_kind, v_low, v_high
    FROM app_open_conversation(v_conv, true);
    IF p_on THEN
        INSERT INTO reactions (message_id, user_id, emoji)
        VALUES (p_message, app_uid(), p_emoji)
        ON CONFLICT DO NOTHING;
    ELSE
        DELETE FROM reactions
        WHERE message_id = p_message AND user_id = app_uid() AND emoji = p_emoji;
    END IF;
    SELECT count(*)::integer, coalesce(bool_or(user_id = app_uid()), false)
    INTO v_count, v_me
    FROM reactions
    WHERE message_id = p_message AND emoji = p_emoji;
    PERFORM app_emit_to(
        'reaction.updated',
        jsonb_build_object(
            'message_id', p_message::text,
            'conversation_id', v_conv::text,
            'kind', v_kind,
            'emoji', p_emoji,
            'on', p_on,
            'user_id', app_uid()::text,
            'count', v_count
        ),
        app_audience(v_kind, v_low, v_high)
    );
    RETURN jsonb_build_object('emoji', p_emoji, 'count', v_count, 'me', v_me);
END;
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
            WHERE a.message_id = m.id AND m.deleted_at IS NULL
        ), '[]'::jsonb),
        'reactions', coalesce((
            SELECT jsonb_agg(jsonb_build_object(
                'emoji', r.emoji,
                'count', r.count,
                'me', r.me
            ) ORDER BY r.emoji)
            FROM (
                SELECT emoji, count(*) AS count, bool_or(user_id = p_viewer) AS me
                FROM reactions
                WHERE message_id = m.id AND m.deleted_at IS NULL
                GROUP BY emoji
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
    ) ELSE '{}'::jsonb END
    FROM messages m
    WHERE m.id = p_id;
$$;

DELETE FROM _sqlx_migrations WHERE version = 53;

COMMIT;
