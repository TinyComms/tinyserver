//! Deletes rows that can no longer be used. Accepted invites are kept for the invite list.
//! Unfinished sign-ins and unredeemed one-time codes go once they expire.
//! Outbox rows are kept 24 hours, which is how far back a live socket can resume.
//! Resolved abuse reports go after `TINYSERVER_REPORT_RETENTION_DAYS` (90), unless on hold.
//! Device links go when they expire; their archive files an hour later, and any archive file no
//! row names (a crash mid-upload, a deleted account) on the next sweep, the first of which runs
//! at start.
//! Messages in a self conversation go once older than `e2ee_self_ttl_secs` (7 days), with the
//! sealed files attached to them.

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
    /// Resolved abuse reports past their retention. Reports on legal hold are never counted.
    pub reports: i64,
    /// Device link archive files deleted: expired, or named by no row.
    pub link_archives: i64,
}

impl Swept {
    pub fn total(&self) -> i64 {
        self.sessions
            + self.invites
            + self.idempotency_keys
            + self.events
            + self.logins
            + self.attachments
            + self.reports
            + self.link_archives
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
    let reports = crate::reports::expire_reports(pool).await?;
    // Expired key packages, old welcomes and old sealed-upload ledger rows. Not counted above:
    // none of it is a row a person made.
    sqlx::query("SELECT app_e2ee_sweep()").execute(pool).await?;
    // Not counted either: a self conversation is one person's devices talking to each other.
    crate::e2ee::sweep_self(pool).await?;
    let link_archives = crate::link::sweep_links(pool).await?;
    Ok(Swept {
        sessions,
        invites,
        idempotency_keys,
        events,
        logins,
        attachments,
        reports,
        link_archives,
    })
}
