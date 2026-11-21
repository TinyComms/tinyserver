-- Rollback of 0049_message_mentions.sql.

DROP TRIGGER IF EXISTS roles_forget_message_mentions ON roles;
DROP FUNCTION IF EXISTS app_mentions_forget_role();
DROP TRIGGER IF EXISTS users_forget_message_mentions ON users;
DROP FUNCTION IF EXISTS app_mentions_forget_user();

DROP FUNCTION IF EXISTS app_post_message(uuid, text, uuid, text, uuid[], jsonb);
DROP FUNCTION IF EXISTS app_edit_message(uuid, text, jsonb);
DROP FUNCTION IF EXISTS app_store_mentions(uuid, text, uuid, uuid, uuid, text, jsonb);
DROP FUNCTION IF EXISTS app_unread_mentions(text, uuid);
DROP TABLE IF EXISTS message_mentions;

DROP FUNCTION IF EXISTS app_role_create(text, text, bigint, boolean, boolean);
DROP FUNCTION IF EXISTS app_role_update(uuid, text, text, bigint, boolean, boolean);
ALTER TABLE roles DROP COLUMN IF EXISTS mentionable;

UPDATE roles SET permissions = permissions & 4194303;
UPDATE room_overrides SET allow = allow & 2343551, deny = deny & 2343551;
UPDATE channel_overrides SET allow = allow & 2343551, deny = deny & 2343551;

ALTER TABLE roles DROP CONSTRAINT roles_permissions_check;
ALTER TABLE roles
    ADD CONSTRAINT roles_permissions_check
    CHECK (permissions >= 0 AND permissions <= 4194303);

ALTER TABLE room_overrides DROP CONSTRAINT room_overrides_allow_check;
ALTER TABLE room_overrides DROP CONSTRAINT room_overrides_deny_check;
ALTER TABLE room_overrides
    ADD CONSTRAINT room_overrides_allow_check
        CHECK (allow >= 0 AND allow & ~2343551::bigint = 0),
    ADD CONSTRAINT room_overrides_deny_check
        CHECK (deny >= 0 AND deny & ~2343551::bigint = 0);

ALTER TABLE channel_overrides DROP CONSTRAINT channel_overrides_allow_check;
ALTER TABLE channel_overrides DROP CONSTRAINT channel_overrides_deny_check;
ALTER TABLE channel_overrides
    ADD CONSTRAINT channel_overrides_allow_check
        CHECK (allow >= 0 AND allow & ~2343551::bigint = 0),
    ADD CONSTRAINT channel_overrides_deny_check
        CHECK (deny >= 0 AND deny & ~2343551::bigint = 0);
