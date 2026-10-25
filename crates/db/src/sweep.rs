//! Deletes rows that can no longer be used. Accepted invites are kept for the invite list.
//! Outbox rows are kept 24 hours, which is how far back a live socket can resume.

use sqlx::PgPool;

use crate::DbError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Swept {
    pub sessions: i64,
    pub invites: i64,
    pub idempotency_keys: i64,
    /// Outbox rows older than 24 hours.
    pub events: i64,
}

impl Swept {
    pub fn total(&self) -> i64 {
        self.sessions + self.invites + self.idempotency_keys + self.events
    }
}

/// Runs as `app_runtime`. The database function deletes past RLS on invites.
pub async fn sweep(pool: &PgPool) -> Result<Swept, DbError> {
    let (sessions, invites, idempotency_keys, events): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT expired_sessions, expired_invites, expired_keys, expired_events FROM app_sweep()",
    )
    .fetch_one(pool)
    .await?;
    Ok(Swept {
        sessions,
        invites,
        idempotency_keys,
        events,
    })
}
