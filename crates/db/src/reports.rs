//! Abuse reports inside one community: filing, listing, reading and working them.
//!
//! A report names a message, a member or a channel. It holds what the reporter wrote and, if the
//! reporter chose to send it, evidence: text the reporter's client disclosed, which the server
//! cannot check (`evidence_unverified`). The server stores a message's id and author, never its
//! body, and never reads a conversation to make a report.
//!
//! Filing needs only membership. Everything else needs `manage_reports`, and a moderator never
//! sees a report about themselves. Writes go through `app_report_create` and `app_report_update`
//! (`migrations/0015_abuse_reports.sql`); `app_runtime` can read `reports` through row level
//! security and cannot write it. Nothing here logs a note, evidence or a moderator's note, and
//! no error carries one: lengths and shapes are checked before the database is asked.

use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row};
use thiserror::Error;

use crate::community::{from_sql, require, scope, uuid, STAMP};
use crate::perm;
use crate::{Caller, CommunityError};

/// Evidence is at most this many bytes of UTF-8.
pub const EVIDENCE_MAX: usize = 32 * 1024;
/// A reporter's or a moderator's note is at most this many characters.
pub const NOTE_MAX: usize = 2000;
/// Reports older than this many days after they were resolved are deleted, unless on hold.
pub const RETENTION_DEFAULT_DAYS: i32 = 90;
/// The shortest retention an operator may set. It has to outlast the 24 hour filing limit.
pub const RETENTION_MIN_DAYS: i32 = 7;
pub const RETENTION_MAX_DAYS: i32 = 3650;

pub const KINDS: &[&str] = &["message", "member", "channel"];
pub const CATEGORIES: &[&str] = &[
    "spam",
    "harassment",
    "hate",
    "violence",
    "sexual",
    "illegal",
    "impersonation",
    "other",
];
pub const STATUSES: &[&str] = &["open", "reviewing", "actioned", "dismissed"];

#[derive(Debug, Error)]
pub enum ReportError {
    /// The reporter is over the limit: 10 an hour, 50 a day.
    #[error("rate limited")]
    RateLimited,
    /// Evidence over [`EVIDENCE_MAX`].
    #[error("too large")]
    TooLarge,
    #[error(transparent)]
    Community(#[from] CommunityError),
}

fn lift(error: sqlx::Error) -> ReportError {
    if error
        .as_database_error()
        .and_then(|database| database.code())
        .is_some_and(|code| code == "TC429")
    {
        return ReportError::RateLimited;
    }
    ReportError::Community(from_sql(error))
}

/// The `RETENTION_DAYS` environment value, or the default. `None` when it is set and is not a
/// whole number from 7 to 3650, so the server can refuse to start rather than guess.
pub fn retention_days_from(value: Option<&str>) -> Option<i32> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        None => Some(RETENTION_DEFAULT_DAYS),
        Some(value) => value
            .parse::<i32>()
            .ok()
            .filter(|days| (RETENTION_MIN_DAYS..=RETENTION_MAX_DAYS).contains(days)),
    }
}

/// `TINYSERVER_REPORT_RETENTION_DAYS`. A bad value is the default here; `serve` checks it at
/// start and refuses it.
pub fn retention_days() -> i32 {
    retention_days_from(
        std::env::var("TINYSERVER_REPORT_RETENTION_DAYS")
            .ok()
            .as_deref(),
    )
    .unwrap_or(RETENTION_DEFAULT_DAYS)
}

#[derive(Debug, Clone, Default)]
pub struct NewReport {
    pub kind: String,
    pub target_id: String,
    pub category: String,
    pub note: Option<String>,
    pub evidence: Option<String>,
}

/// What the reporter gets back: nothing about anyone involved.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Filed {
    pub id: String,
    pub kind: String,
    pub category: String,
    pub status: String,
    pub created_at: String,
    /// True whenever the report carries evidence: the server cannot verify it.
    pub evidence_unverified: bool,
    /// The reporter already had an unresolved report about this; nothing new was stored.
    pub duplicate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Person {
    pub user_id: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportSummary {
    pub id: String,
    pub kind: String,
    pub category: String,
    pub status: String,
    pub preserve: bool,
    /// The member reported, or the author of the message reported. `None` for a channel.
    pub reported: Option<Person>,
    /// `None` once the reporter has deleted their account.
    pub reporter: Option<Person>,
    pub message_id: Option<String>,
    pub channel_id: Option<String>,
    pub direct_id: Option<String>,
    pub has_evidence: bool,
    pub evidence_unverified: bool,
    pub linked_audit_ids: Vec<i64>,
    pub created_at: String,
    pub updated_at: String,
    pub resolved_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportNote {
    pub id: String,
    pub author: Option<Person>,
    pub body: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportDetail {
    #[serde(flatten)]
    pub summary: ReportSummary,
    /// What the reporter wrote.
    pub note: Option<String>,
    /// What the reporter's client chose to disclose. Unverified.
    pub evidence: Option<String>,
    pub preserved_by: Option<Person>,
    pub preserved_at: Option<String>,
    pub notes: Vec<ReportNote>,
}

#[derive(Debug, Clone, Default)]
pub struct ReportPatch {
    pub status: Option<String>,
    pub note: Option<String>,
    pub link_audit_id: Option<i64>,
    pub preserve: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct ReportQuery {
    pub status: Option<String>,
    pub kind: Option<String>,
    /// A report id; the page starts after it.
    pub before: Option<String>,
    pub limit: i64,
}

/// Text from a person: no NUL or other control characters but newline, return and tab.
fn clean_text(text: &str) -> bool {
    !text
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
}

fn check_note(note: Option<&str>) -> Result<Option<String>, CommunityError> {
    let Some(note) = note.map(str::trim).filter(|note| !note.is_empty()) else {
        return Ok(None);
    };
    if note.chars().count() > NOTE_MAX || !clean_text(note) {
        return Err(CommunityError::Invalid);
    }
    Ok(Some(note.to_string()))
}

/// Files a report. Any member who is not banned. Nothing is read from the conversation.
pub async fn file_report(
    pool: &PgPool,
    caller: &Caller,
    input: &NewReport,
) -> Result<Filed, ReportError> {
    if !KINDS.contains(&input.kind.as_str()) || !CATEGORIES.contains(&input.category.as_str()) {
        return Err(CommunityError::Invalid.into());
    }
    let target = uuid(&input.target_id)?;
    let note = check_note(input.note.as_deref())?;
    let evidence = input.evidence.as_deref().filter(|text| !text.is_empty());
    if let Some(evidence) = evidence {
        if evidence.len() > EVIDENCE_MAX {
            return Err(ReportError::TooLarge);
        }
        if !clean_text(evidence) {
            return Err(CommunityError::Invalid.into());
        }
    }
    let mut tx = scope(pool, caller).await?;
    let filed: serde_json::Value =
        sqlx::query_scalar("SELECT app_report_create($1, $2::uuid, $3, $4, $5)")
            .bind(&input.kind)
            .bind(&target)
            .bind(&input.category)
            .bind(note.as_deref())
            .bind(evidence)
            .fetch_one(&mut *tx)
            .await
            .map_err(lift)?;
    tx.commit().await.map_err(from_sql)?;
    serde_json::from_value(filed).map_err(|_| CommunityError::Invalid.into())
}

const SUMMARY_COLUMNS: &str = "r.id::text, r.kind, r.category, r.status, r.preserve,
        r.reported_user_id::text, ru.display_name, r.reporter_id::text, rp.display_name,
        r.message_id::text, r.channel_id::text, r.direct_id::text,
        r.evidence IS NOT NULL, r.evidence_unverified, r.linked_audit_ids";

fn stamps(column: &str) -> String {
    format!("to_char(r.{column} AT TIME ZONE 'UTC', '{STAMP}')")
}

fn person(id: Option<String>, name: Option<String>) -> Option<Person> {
    id.map(|user_id| Person {
        user_id,
        display_name: name.unwrap_or_default(),
    })
}

fn summary_from(row: &PgRow) -> Result<ReportSummary, CommunityError> {
    let get = from_sql;
    Ok(ReportSummary {
        id: row.try_get(0).map_err(get)?,
        kind: row.try_get(1).map_err(get)?,
        category: row.try_get(2).map_err(get)?,
        status: row.try_get(3).map_err(get)?,
        preserve: row.try_get(4).map_err(get)?,
        reported: person(row.try_get(5).map_err(get)?, row.try_get(6).map_err(get)?),
        reporter: person(row.try_get(7).map_err(get)?, row.try_get(8).map_err(get)?),
        message_id: row.try_get(9).map_err(get)?,
        channel_id: row.try_get(10).map_err(get)?,
        direct_id: row.try_get(11).map_err(get)?,
        has_evidence: row.try_get(12).map_err(get)?,
        evidence_unverified: row.try_get(13).map_err(get)?,
        linked_audit_ids: row.try_get(14).map_err(get)?,
        created_at: row.try_get(15).map_err(get)?,
        updated_at: row.try_get(16).map_err(get)?,
        resolved_at: row.try_get(17).map_err(get)?,
    })
}

fn summary_sql(filter: &str, tail: &str) -> String {
    format!(
        "SELECT {SUMMARY_COLUMNS}, {created}, {updated}, {resolved}
         FROM reports r
         LEFT JOIN users ru ON ru.id = r.reported_user_id
         LEFT JOIN users rp ON rp.id = r.reporter_id
         {filter} {tail}",
        created = stamps("created_at"),
        updated = stamps("updated_at"),
        resolved = stamps("resolved_at"),
    )
}

/// Newest first. Needs manage_reports; reports about the caller are not listed.
pub async fn list_reports(
    pool: &PgPool,
    caller: &Caller,
    query: &ReportQuery,
) -> Result<Vec<ReportSummary>, CommunityError> {
    let status = match query.status.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(status) if STATUSES.contains(&status) => Some(status.to_string()),
        Some(_) => return Err(CommunityError::Invalid),
    };
    let kind = match query.kind.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(kind) if KINDS.contains(&kind) => Some(kind.to_string()),
        Some(_) => return Err(CommunityError::Invalid),
    };
    let before = match &query.before {
        Some(before) => Some(uuid(before)?),
        None => None,
    };
    let mut tx = scope(pool, caller).await?;
    require(&mut tx, perm::MANAGE_REPORTS).await?;
    let sql = summary_sql(
        "WHERE ($2::text IS NULL OR r.status = $2)
           AND ($3::text IS NULL OR r.kind = $3)
           AND ($4::uuid IS NULL OR (r.created_at, r.id) <
                (SELECT b.created_at, b.id FROM reports b WHERE b.id = $4::uuid))",
        "ORDER BY r.created_at DESC, r.id DESC LIMIT $1",
    );
    let rows = sqlx::query(&sql)
        .bind(query.limit.clamp(1, 200))
        .bind(status)
        .bind(kind)
        .bind(before)
        .fetch_all(&mut *tx)
        .await
        .map_err(from_sql)?;
    let reports = rows
        .iter()
        .map(summary_from)
        .collect::<Result<Vec<_>, _>>()?;
    tx.commit().await.map_err(from_sql)?;
    Ok(reports)
}

async fn detail(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: &str,
) -> Result<ReportDetail, CommunityError> {
    let sql = format!(
        "SELECT {SUMMARY_COLUMNS}, {created}, {updated}, {resolved},
                r.note, r.evidence, r.preserved_by::text, pb.display_name,
                to_char(r.preserved_at AT TIME ZONE 'UTC', '{STAMP}')
         FROM reports r
         LEFT JOIN users ru ON ru.id = r.reported_user_id
         LEFT JOIN users rp ON rp.id = r.reporter_id
         LEFT JOIN users pb ON pb.id = r.preserved_by
         WHERE r.id = $1::uuid",
        created = stamps("created_at"),
        updated = stamps("updated_at"),
        resolved = stamps("resolved_at"),
    );
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(from_sql)?
        .ok_or(CommunityError::NotFound)?;
    let summary = summary_from(&row)?;
    let get = from_sql;
    let note = row.try_get(18).map_err(get)?;
    let evidence = row.try_get(19).map_err(get)?;
    let preserved_by = person(row.try_get(20).map_err(get)?, row.try_get(21).map_err(get)?);
    let preserved_at = row.try_get(22).map_err(get)?;
    let rows = sqlx::query(&format!(
        "SELECT n.id::text, n.author_id::text, u.display_name, n.body,
                to_char(n.created_at AT TIME ZONE 'UTC', '{STAMP}')
         FROM report_notes n LEFT JOIN users u ON u.id = n.author_id
         WHERE n.report_id = $1::uuid
         ORDER BY n.created_at, n.id"
    ))
    .bind(id)
    .fetch_all(&mut **tx)
    .await
    .map_err(from_sql)?;
    let mut notes = Vec::with_capacity(rows.len());
    for row in &rows {
        notes.push(ReportNote {
            id: row.try_get(0).map_err(get)?,
            author: person(row.try_get(1).map_err(get)?, row.try_get(2).map_err(get)?),
            body: row.try_get(3).map_err(get)?,
            created_at: row.try_get(4).map_err(get)?,
        });
    }
    Ok(ReportDetail {
        summary,
        note,
        evidence,
        preserved_by,
        preserved_at,
        notes,
    })
}

/// One report in full. Needs manage_reports. A report about the caller, or that does not
/// exist, is `NotFound`.
pub async fn get_report(
    pool: &PgPool,
    caller: &Caller,
    id: &str,
) -> Result<ReportDetail, CommunityError> {
    let id = uuid(id).map_err(|_| CommunityError::NotFound)?;
    let mut tx = scope(pool, caller).await?;
    require(&mut tx, perm::MANAGE_REPORTS).await?;
    let found = detail(&mut tx, &id).await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(found)
}

/// Triage, annotate, link an enforcement action, or set the legal hold. Any of them, together,
/// in one transaction. Each is audited with the report id and never the text.
pub async fn update_report(
    pool: &PgPool,
    caller: &Caller,
    id: &str,
    patch: &ReportPatch,
) -> Result<ReportDetail, ReportError> {
    let id = uuid(id).map_err(|_| CommunityError::NotFound)?;
    if let Some(status) = &patch.status {
        if !STATUSES.contains(&status.as_str()) {
            return Err(CommunityError::Invalid.into());
        }
    }
    let note = check_note(patch.note.as_deref())?;
    if patch.status.is_none()
        && note.is_none()
        && patch.link_audit_id.is_none()
        && patch.preserve.is_none()
    {
        return Err(CommunityError::Invalid.into());
    }
    let mut tx = scope(pool, caller).await?;
    sqlx::query("SELECT app_report_update($1::uuid, $2, $3, $4, $5)")
        .bind(&id)
        .bind(patch.status.as_deref())
        .bind(note.as_deref())
        .bind(patch.link_audit_id)
        .bind(patch.preserve)
        .execute(&mut *tx)
        .await
        .map_err(lift)?;
    let updated = detail(&mut tx, &id).await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(updated)
}

/// Deletes resolved reports past the retention window. Returns how many. Reports on hold, and
/// reports still open or under review, stay.
pub(crate) async fn expire_reports(pool: &PgPool) -> Result<i64, crate::DbError> {
    let deleted: i64 = sqlx::query_scalar("SELECT app_reports_sweep($1)")
        .bind(retention_days())
        .fetch_one(pool)
        .await?;
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_is_a_whole_number_of_days_with_a_floor() {
        assert_eq!(retention_days_from(None), Some(90));
        assert_eq!(retention_days_from(Some("")), Some(90));
        assert_eq!(retention_days_from(Some("30")), Some(30));
        assert_eq!(retention_days_from(Some("7")), Some(7));
        // Below a week the 24 hour filing limit could be counted against deleted reports.
        assert_eq!(retention_days_from(Some("6")), None);
        assert_eq!(retention_days_from(Some("0")), None);
        assert_eq!(retention_days_from(Some("-1")), None);
        assert_eq!(retention_days_from(Some("3651")), None);
        assert_eq!(retention_days_from(Some("ninety")), None);
    }

    #[test]
    fn notes_are_trimmed_bounded_and_free_of_control_characters() {
        assert_eq!(check_note(None).ok(), Some(None));
        assert_eq!(check_note(Some("  \n ")).ok(), Some(None));
        assert_eq!(
            check_note(Some(" a\nb ")).ok(),
            Some(Some("a\nb".to_string()))
        );
        assert!(check_note(Some(&"x".repeat(NOTE_MAX + 1))).is_err());
        assert!(check_note(Some(&"x".repeat(NOTE_MAX))).is_ok());
        assert!(check_note(Some("nul\u{0}")).is_err());
        assert!(check_note(Some("bell\u{7}")).is_err());
    }
}
