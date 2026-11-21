-- Rollback of 0050_message_search.sql.

DROP FUNCTION IF EXISTS app_search_messages(text, uuid, uuid, uuid, integer);
DROP TRIGGER IF EXISTS users_forget_search_rate_log ON users;
DROP FUNCTION IF EXISTS app_search_forget_user();
DROP TABLE IF EXISTS search_rate_log;
DROP INDEX IF EXISTS messages_body_search;
