-- Issue #74: lift the 0-99 check on rooms.user_limit so an owner can set any non-negative room
-- cap (0 remains unlimited).
ALTER TABLE rooms DROP CONSTRAINT IF EXISTS rooms_user_limit_check;
ALTER TABLE rooms ADD CONSTRAINT rooms_user_limit_check CHECK (user_limit >= 0);

-- Rollback: crates/db/rollback/0052_call_user_limit.down.sql restores CHECK (user_limit BETWEEN 0 AND 99).
