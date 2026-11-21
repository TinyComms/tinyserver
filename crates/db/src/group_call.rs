//! Who may start or join a group call, and the row written when that call ends.

use sqlx::PgPool;

use crate::error::DbError;
use crate::messages::is_uuid;

/// The current unbanned members of a group conversation, plus which members are timed out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupCallMembers {
    pub members: Vec<String>,
    pub timed_out: Vec<String>,
    pub caller_timed_out: bool,
}

impl GroupCallMembers {
    /// `Ok(())` when the caller is allowed to start or join a call; `Err("timed_out")` when the
    /// caller is in a timeout.
    pub fn check_caller(&self) -> Result<(), &'static str> {
        if self.caller_timed_out {
            Err("timed_out")
        } else {
            Ok(())
        }
    }
}

/// Returns `Ok(None)` when the group does not exist, the caller is not a current member, or the
/// caller is banned.
pub async fn group_call_access(
    pool: &PgPool,
    group_id: &str,
    user_id: &str,
) -> Result<Option<GroupCallMembers>, DbError> {
    if !is_uuid(group_id) || !is_uuid(user_id) {
        return Ok(None);
    }
    let rows: Vec<(String, bool)> = sqlx::query_as(
        "SELECT user_id::text, timed_out
         FROM app_group_call_access($1::uuid, $2::uuid)",
    )
    .bind(group_id)
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    if rows.is_empty() {
        return Ok(None);
    }
    let caller_timed_out = rows
        .iter()
        .find(|(uid, _)| uid == user_id)
        .is_some_and(|(_, timed_out)| *timed_out);
    let timed_out = rows
        .iter()
        .filter(|(_, is_timed_out)| *is_timed_out)
        .map(|(uid, _)| uid.clone())
        .collect();
    let members = rows.into_iter().map(|(uid, _)| uid).collect();
    Ok(Some(GroupCallMembers {
        members,
        timed_out,
        caller_timed_out,
    }))
}

/// One finished group call. `started_at` is seconds since the unix epoch.
#[derive(Debug, Clone, PartialEq)]
pub struct GroupCallRecord {
    pub call_id: String,
    pub group_id: String,
    pub started_by: String,
    pub outcome: &'static str,
    pub started_at: f64,
    pub people: Vec<(String, &'static str)>,
}

pub async fn record_group_call(pool: &PgPool, call: &GroupCallRecord) -> Result<(), DbError> {
    let people_ids: Vec<&str> = call.people.iter().map(|(id, _)| id.as_str()).collect();
    let people_outcomes: Vec<&str> = call.people.iter().map(|(_, out)| *out).collect();
    sqlx::query(
        "SELECT app_record_group_call(
            $1::uuid, $2::uuid, $3::uuid, $4, $5, $6::uuid[], $7::text[]
         )",
    )
    .bind(&call.call_id)
    .bind(&call.group_id)
    .bind(&call.started_by)
    .bind(call.outcome)
    .bind(call.started_at)
    .bind(&people_ids)
    .bind(&people_outcomes)
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::GroupCallMembers;

    #[test]
    fn check_caller_refuses_timed_out_and_allows_active() {
        let active = GroupCallMembers {
            members: vec!["a".into(), "b".into()],
            timed_out: vec![],
            caller_timed_out: false,
        };
        assert_eq!(active.check_caller(), Ok(()));

        let timed_out = GroupCallMembers {
            members: vec!["a".into(), "b".into()],
            timed_out: vec!["a".into()],
            caller_timed_out: true,
        };
        assert_eq!(timed_out.check_caller(), Err("timed_out"));
    }
}
