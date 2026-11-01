//! The operator's switches for the whole community (`migrations/0016_operator.sql`).
//!
//! A suspension is `read_only` (members read, nothing new is written) or `offline` (only the
//! notice and the health check answer), with a notice members see. A legal hold stops the
//! community's deletion and the expiry of resolved reports. The serving process reads the state
//! with [`operator_state`]; only the owner role, from `tinyserver operator`, changes it.

use sqlx::PgPool;

use crate::DbError;

/// What members may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    /// Sign in, read, download, report, sign out and delete an account. Nothing else is written.
    ReadOnly,
    /// Only the health check and `GET /v1/status`, which carries the notice.
    Offline,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::ReadOnly => "read_only",
            Self::Offline => "offline",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "normal" => Some(Self::Normal),
            "read_only" | "read-only" => Some(Self::ReadOnly),
            "offline" => Some(Self::Offline),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorState {
    pub mode: Mode,
    pub notice: Option<String>,
    /// When the mode last changed, RFC 3339 in UTC.
    pub since: String,
    pub legal_hold: bool,
}

impl OperatorState {
    /// What a server without the table, or before it was read, behaves as.
    pub fn normal() -> Self {
        Self {
            mode: Mode::Normal,
            notice: None,
            since: String::new(),
            legal_hold: false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OperatorError {
    #[error(
        "the notice must be 1 to {NOTICE_MAX} characters, with no control characters but new lines"
    )]
    BadNotice,
    #[error("a suspension needs a notice for members")]
    NeedsNotice,
    #[error("the reason must be at most {NOTICE_MAX} characters")]
    BadReason,
    #[error(transparent)]
    Db(#[from] DbError),
}

impl From<sqlx::Error> for OperatorError {
    fn from(error: sqlx::Error) -> Self {
        Self::Db(DbError::Sql(error))
    }
}

pub const NOTICE_MAX: usize = 500;

const STATE: &str = "SELECT mode, notice,
            to_char(since AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
            legal_hold
     FROM operator_state";

type Row = (String, Option<String>, String, bool);

fn from_row((mode, notice, since, legal_hold): Row) -> OperatorState {
    OperatorState {
        // The CHECK constraint allows only the three; anything else would be a newer schema,
        // and the strictest reading is the safe one.
        mode: Mode::parse(&mode).unwrap_or(Mode::Offline),
        notice,
        since,
        legal_hold,
    }
}

/// The state now. The runtime role may read it; it is one row.
pub async fn operator_state(pool: &PgPool) -> Result<OperatorState, DbError> {
    let row: Row = sqlx::query_as(STATE).fetch_one(pool).await?;
    Ok(from_row(row))
}

/// Suspends (`ReadOnly`, `Offline`, with a notice) or resumes (`Normal`, no notice). Needs the
/// owner role. A hold is not touched.
pub async fn set_operator_mode(
    owner: &PgPool,
    mode: Mode,
    notice: Option<&str>,
) -> Result<OperatorState, OperatorError> {
    let notice = match (mode, notice) {
        (Mode::Normal, _) => None,
        (_, None) => return Err(OperatorError::NeedsNotice),
        (_, Some(notice)) => Some(clean_notice(notice)?),
    };
    let mut tx = owner.begin().await?;
    sqlx::query("UPDATE operator_state SET mode = $1, notice = $2, since = now()")
        .bind(mode.as_str())
        .bind(&notice)
        .execute(&mut *tx)
        .await?;
    let action = if mode == Mode::Normal {
        "resume"
    } else {
        "suspend"
    };
    sqlx::query("INSERT INTO operator_events (action, mode) VALUES ($1, $2)")
        .bind(action)
        .bind(mode.as_str())
        .execute(&mut *tx)
        .await?;
    let row: Row = sqlx::query_as(STATE).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(from_row(row))
}

/// Places or releases the legal hold. Needs the owner role. The reason goes to the operator's
/// own record, `operator_events`, which the serving process cannot read.
pub async fn set_legal_hold(
    owner: &PgPool,
    hold: bool,
    reason: Option<&str>,
) -> Result<OperatorState, OperatorError> {
    let reason = reason.map(str::trim).filter(|reason| !reason.is_empty());
    if reason.is_some_and(|reason| reason.chars().count() > NOTICE_MAX) {
        return Err(OperatorError::BadReason);
    }
    let mut tx = owner.begin().await?;
    sqlx::query(
        "UPDATE operator_state
         SET legal_hold = $1,
             legal_hold_since = CASE WHEN $1 THEN COALESCE(legal_hold_since, now()) END",
    )
    .bind(hold)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO operator_events (action, reason) VALUES ($1, $2)")
        .bind(if hold { "hold" } else { "release" })
        .bind(reason)
        .execute(&mut *tx)
        .await?;
    let row: Row = sqlx::query_as(STATE).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(from_row(row))
}

/// Reports an owner has put on hold inside the community. Needs the owner role, which reads
/// past row level security. A community with any is not deleted either.
pub async fn held_reports(owner: &PgPool) -> Result<i64, DbError> {
    Ok(
        sqlx::query_scalar("SELECT count(*) FROM reports WHERE preserve")
            .fetch_one(owner)
            .await?,
    )
}

/// Trimmed, 1 to [`NOTICE_MAX`] characters, no control characters but `\n`.
pub fn clean_notice(notice: &str) -> Result<String, OperatorError> {
    let notice = notice.trim();
    let count = notice.chars().count();
    if !(1..=NOTICE_MAX).contains(&count) || notice.chars().any(|c| c.is_control() && c != '\n') {
        return Err(OperatorError::BadNotice);
    }
    Ok(notice.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_round_trip_and_unknown_is_none() {
        for mode in [Mode::Normal, Mode::ReadOnly, Mode::Offline] {
            assert_eq!(Mode::parse(mode.as_str()), Some(mode));
        }
        assert_eq!(Mode::parse("read-only"), Some(Mode::ReadOnly));
        assert_eq!(Mode::parse("paused"), None);
    }

    #[test]
    fn a_notice_is_short_plain_text() {
        assert_eq!(
            clean_notice("  Back soon.  ").expect("notice"),
            "Back soon."
        );
        assert_eq!(
            clean_notice("Line one\nline two").expect("notice"),
            "Line one\nline two"
        );
        assert!(clean_notice("   ").is_err());
        assert!(clean_notice("bell\u{7}").is_err());
        assert!(clean_notice("esc\u{1b}[31m").is_err());
        assert!(clean_notice(&"x".repeat(NOTICE_MAX)).is_ok());
        assert!(clean_notice(&"x".repeat(NOTICE_MAX + 1)).is_err());
    }

    #[test]
    fn an_unknown_mode_in_the_table_reads_as_offline() {
        let state = from_row(("later".into(), None, String::new(), false));
        assert_eq!(state.mode, Mode::Offline);
    }
}
