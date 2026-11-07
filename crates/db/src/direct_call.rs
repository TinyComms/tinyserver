//! Who may ring a direct, and the row written when that call ends.

use sqlx::PgPool;

use crate::error::DbError;
use crate::messages::is_uuid;

/// The two parties of a direct, and whether each is timed out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectParties {
    pub low_user_id: String,
    pub high_user_id: String,
    pub low_timed_out: bool,
    pub high_timed_out: bool,
}

impl DirectParties {
    /// `user_id` is one of two distinct people, and neither is timed out.
    pub fn open_to(&self, user_id: &str) -> Result<(), &'static str> {
        if self.low_user_id == self.high_user_id
            || (user_id != self.low_user_id && user_id != self.high_user_id)
        {
            return Err("not_found");
        }
        if self.low_timed_out || self.high_timed_out {
            return Err("timed_out");
        }
        Ok(())
    }

    pub fn peer_of(&self, user_id: &str) -> Option<&str> {
        if user_id == self.low_user_id {
            Some(&self.high_user_id)
        } else if user_id == self.high_user_id {
            Some(&self.low_user_id)
        } else {
            None
        }
    }
}

/// Empty when the direct does not exist, the user is not a party, either person is banned,
/// or either is no longer a member.
pub async fn direct_parties(
    pool: &PgPool,
    direct_id: &str,
    user_id: &str,
) -> Result<Option<DirectParties>, DbError> {
    if !is_uuid(direct_id) || !is_uuid(user_id) {
        return Ok(None);
    }
    let row: Option<(String, String, bool, bool)> = sqlx::query_as(
        "SELECT low_user_id::text, high_user_id::text, low_timed_out, high_timed_out
         FROM app_direct_parties($1::uuid, $2::uuid)",
    )
    .bind(direct_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(low_user_id, high_user_id, low_timed_out, high_timed_out)| DirectParties {
            low_user_id,
            high_user_id,
            low_timed_out,
            high_timed_out,
        },
    ))
}

/// One finished direct call. `accepted_at` is seconds since the unix epoch, when they accepted.
#[derive(Debug, Clone, PartialEq)]
pub struct DirectCallRecord {
    pub ring_id: String,
    pub direct_id: String,
    pub caller_id: String,
    pub callee_id: String,
    pub outcome: &'static str,
    pub accepted_at: Option<f64>,
}

pub async fn record_direct_call(pool: &PgPool, call: &DirectCallRecord) -> Result<(), DbError> {
    sqlx::query("SELECT app_record_direct_call($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6)")
        .bind(&call.ring_id)
        .bind(&call.direct_id)
        .bind(&call.caller_id)
        .bind(&call.callee_id)
        .bind(call.outcome)
        .bind(call.accepted_at)
        .execute(pool)
        .await?;
    Ok(())
}
