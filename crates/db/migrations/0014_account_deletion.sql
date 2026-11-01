-- A person can delete their own account, and an edited or deleted message stops being readable
-- in the live event history.
--
-- Until now nothing deleted a user. A removed or banned member kept an email address, a
-- display name, a provider identity, every message, and the display names in the audit log,
-- for ever. A person who asks to be gone could not be.
--
-- Deleting an account here means:
--   * The row in `users` stays, as a tombstone with no email, no name, no picture and no
--     provider identity. Messages, channels and invites point at it, and a message with no
--     author would be worse for the people still in the conversation.
--   * Every message they wrote is emptied the way deleting a message empties it, and its
--     attachments are deleted. Their files are unlinked by the caller after the commit.
--   * Their sessions, identities, memberships, reactions, read marks, bots, unused invites
--     and idempotency keys are deleted.
--   * Their display name is taken out of audit log rows. The rows stay, as a record that
--     something happened, with the person's id and without who they were.
--   * A ban survives. `ban_identities` keeps the provider identity of a banned person so that
--     deleting an account cannot undo a ban. This is the one place an identity outlives its
--     account, and it is only ever there because a moderator banned it.
--
-- What this does not do: it does not reach Postgres write-ahead logs, dead rows before the
-- next vacuum, backups, or anything a person's own client has already stored. A message
-- someone else already read stays read.

ALTER TABLE users ADD COLUMN deleted_at timestamptz;

-- An edited or deleted message is still in the outbox as it was first sent, for the 24 hours
-- the outbox keeps events for a socket that reconnects. Anyone who reconnects in that window
-- would be replayed the text the author just took back. Rewrite those rows to what the
-- message says now.
CREATE FUNCTION app_scrub_outbox()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    UPDATE outbox
    SET payload = CASE
        WHEN NEW.deleted_at IS NULL THEN
            jsonb_set(payload, '{message,body}', to_jsonb(NEW.body))
        ELSE
            jsonb_set(jsonb_set(payload, '{message,body}', '""'::jsonb),
                      '{message,attachments}', '[]'::jsonb)
        END
    WHERE topic IN ('message.created', 'message.edited')
      AND payload #>> '{message,id}' = NEW.id::text;
    IF NEW.deleted_at IS NOT NULL THEN
        -- The 200 character preview of a channel's last message.
        UPDATE outbox
        SET payload = jsonb_set(payload, '{channel,last_message,body}', '""'::jsonb)
        WHERE topic IN ('channel.created', 'channel.updated')
          AND payload #>> '{channel,last_message,id}' = NEW.id::text;
    END IF;
    RETURN NULL;
END;
$$;

REVOKE EXECUTE ON FUNCTION app_scrub_outbox() FROM PUBLIC;

CREATE TRIGGER messages_scrub_outbox
    AFTER UPDATE OF body, deleted_at ON messages
    FOR EACH ROW
    WHEN (OLD.body IS DISTINCT FROM NEW.body OR OLD.deleted_at IS DISTINCT FROM NEW.deleted_at)
    EXECUTE FUNCTION app_scrub_outbox();

-- Deletes the caller's account. Returns the attachment ids whose files the caller removes
-- after the commit. A sole owner cannot delete: the community would have none.
CREATE FUNCTION app_delete_account()
RETURNS text[]
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_user uuid := app_uid();
    v_owner boolean;
    v_files text[];
BEGIN
    IF v_user IS NULL OR NOT EXISTS (
        SELECT 1 FROM users WHERE id = v_user AND deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'not found' USING ERRCODE = 'P0002';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('tinyserver.owners'));
    SELECT owner INTO v_owner FROM memberships WHERE user_id = v_user;
    IF v_owner AND (SELECT count(*) FROM memberships WHERE owner) <= 1 THEN
        RAISE EXCEPTION 'last owner' USING ERRCODE = '42501';
    END IF;

    SELECT coalesce(array_agg(a.id::text), '{}') INTO v_files
    FROM attachments a
    WHERE a.uploader_id = v_user
       OR a.message_id IN (SELECT m.id FROM messages m WHERE m.author_id = v_user);
    DELETE FROM attachments
    WHERE uploader_id = v_user
       OR message_id IN (SELECT m.id FROM messages m WHERE m.author_id = v_user);
    DELETE FROM reactions
    WHERE user_id = v_user
       OR message_id IN (SELECT m.id FROM messages m WHERE m.author_id = v_user);
    UPDATE messages SET body = '', deleted_at = now()
    WHERE author_id = v_user AND deleted_at IS NULL;
    DELETE FROM reads WHERE user_id = v_user;

    DELETE FROM bots WHERE created_by = v_user;
    DELETE FROM invites WHERE created_by = v_user AND accepted_at IS NULL;
    DELETE FROM idempotency_keys WHERE key LIKE v_user::text || E'\n%';
    DELETE FROM sessions WHERE user_id = v_user;
    DELETE FROM user_identities WHERE user_id = v_user;
    DELETE FROM memberships WHERE user_id = v_user;

    -- Their join, rename and profile events, with the name and email they carry.
    DELETE FROM outbox WHERE payload #>> '{member,user_id}' = v_user::text;

    UPDATE audit_log
    SET detail = detail - 'display_name' - 'name' - 'email'
    WHERE (actor_id = v_user OR subject_user_id = v_user) AND detail IS NOT NULL;

    UPDATE users
    SET email = NULL,
        display_name = 'Deleted user',
        avatar = NULL,
        avatar_type = NULL,
        avatar_sha = NULL,
        deleted_at = now()
    WHERE id = v_user;

    INSERT INTO audit_log (actor_id, action, subject, detail, subject_user_id)
    VALUES (v_user, 'account.delete', 'user', jsonb_build_object('user_id', v_user), v_user);
    RETURN v_files;
END;
$$;

REVOKE EXECUTE ON FUNCTION app_delete_account() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_delete_account() TO app_runtime;
