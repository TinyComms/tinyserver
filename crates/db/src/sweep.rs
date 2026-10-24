//! Deletes rows that can no longer be used. Accepted invites are kept for the invite list.

use sqlx::PgPool;

use crate::DbError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Swept {
    pub sessions: i64,
    pub invites: i64,
    pub idempotency_keys: i64,
}

impl Swept {
    pub fn total(&self) -> i64 {
        self.sessions + self.invites + self.idempotency_keys
    }
}

/// Runs as `app_runtime`. The database function deletes past RLS on invites.
pub async fn sweep(pool: &PgPool) -> Result<Swept, DbError> {
    let (sessions, invites, idempotency_keys): (i64, i64, i64) =
        sqlx::query_as("SELECT expired_sessions, expired_invites, expired_keys FROM app_sweep()")
            .fetch_one(pool)
            .await?;
    Ok(Swept {
        sessions,
        invites,
        idempotency_keys,
    })
}
