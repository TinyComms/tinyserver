//! Deletes rows that can no longer be used. Accepted invites are kept for the invite list.
//! Unfinished sign-ins and unredeemed one-time codes go once they expire.
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
    /// Sign-ins never finished and one-time codes never redeemed.
    pub logins: i64,
    /// Uploads nobody attached within an hour.
    pub attachments: i64,
}

impl Swept {
    pub fn total(&self) -> i64 {
        self.sessions
            + self.invites
            + self.idempotency_keys
            + self.events
            + self.logins
            + self.attachments
    }
}

/// Runs as `app_runtime`. The database function deletes past RLS on invites.
pub async fn sweep(pool: &PgPool) -> Result<Swept, DbError> {
    let (sessions, invites, idempotency_keys, events, logins): (i64, i64, i64, i64, i64) =
        sqlx::query_as(
            "SELECT expired_sessions, expired_invites, expired_keys, expired_events, expired_logins
             FROM app_sweep()",
        )
        .fetch_one(pool)
        .await?;
    let orphans = crate::messages::expire_orphans(pool).await?;
    crate::messages::remove_files(&orphans);
    let attachments = i64::try_from(orphans.len()).unwrap_or(i64::MAX);
    Ok(Swept {
        sessions,
        invites,
        idempotency_keys,
        events,
        logins,
        attachments,
    })
}
