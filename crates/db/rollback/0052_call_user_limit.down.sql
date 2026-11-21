-- Undoes migrations/0052_call_user_limit.sql. Run as the owner role, in one transaction, then
-- start the previous build.
UPDATE rooms SET user_limit = 99 WHERE user_limit > 99;
ALTER TABLE rooms DROP CONSTRAINT IF EXISTS rooms_user_limit_check;
ALTER TABLE rooms ADD CONSTRAINT rooms_user_limit_check CHECK (user_limit BETWEEN 0 AND 99);
DELETE FROM _sqlx_migrations WHERE version = 52;
