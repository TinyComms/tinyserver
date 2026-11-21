-- Rollback of 0051_message_previews.sql.

DROP TRIGGER IF EXISTS users_forget_message_previews ON users;
DROP FUNCTION IF EXISTS app_previews_forget_user();
DROP FUNCTION IF EXISTS app_post_message(uuid, text, uuid, text, uuid[], jsonb, jsonb);
DROP FUNCTION IF EXISTS app_edit_message(uuid, text, jsonb, jsonb);
DROP FUNCTION IF EXISTS app_store_previews(uuid, text, jsonb);
DROP TABLE IF EXISTS message_previews;
ALTER TABLE attachments DROP COLUMN IF EXISTS is_preview;
