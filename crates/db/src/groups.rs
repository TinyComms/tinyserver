//! Group conversations: find-or-create, list, get, rename, add a person, leave.
//!
//! All calls go through `messages::scoped` so bots are refused with `403 forbidden` before SQL.

use std::collections::HashSet;

use serde_json::Value;
use sqlx::PgPool;

use crate::community::Caller;
use crate::messages::{commit, is_uuid, json_in, message_sql, remove_files, scoped, MessageError};

/// Maximum characters for a group conversation name after trimming. Empty is allowed.
pub const GROUP_NAME_MAX: usize = 80;
/// Minimum number of other members required in `POST /v1/groups` (two people are a direct).
pub const GROUP_CREATE_USERS_MIN: usize = 2;
/// Maximum number of other members accepted in one `POST /v1/groups` call.
pub const GROUP_CREATE_USERS_MAX: usize = 100;

/// Lists all group conversations the caller is currently in, ordered by `created_at, id`.
pub async fn list_groups(pool: &PgPool, caller: &Caller) -> Result<Value, MessageError> {
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(&mut tx, "SELECT app_group_list()", |query| query).await?;
    commit(tx, value).await
}

/// Fetches one group conversation the caller is currently in, else `NotFound`.
pub async fn get_group(pool: &PgPool, caller: &Caller, id: &str) -> Result<Value, MessageError> {
    if !is_uuid(id) {
        return Err(MessageError::NotFound);
    }
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(&mut tx, "SELECT app_group_get($1::uuid)", |query| {
        query.bind(id)
    })
    .await?;
    commit(tx, value).await
}

/// Find-or-create a group conversation for `caller` + `user_ids` with the given `e2ee` flag.
/// Returns `(group_json, created)`.
pub async fn open_group(
    pool: &PgPool,
    caller: &Caller,
    user_ids: &[String],
    name: Option<&str>,
    e2ee: bool,
) -> Result<(Value, bool), MessageError> {
    if e2ee {
        return Err(MessageError::E2eeOff);
    }
    let users = validate_group_create_users(&caller.user_id, user_ids)?;
    let name = validate_group_name(name.unwrap_or(""))?;
    let mut tx = scoped(pool, caller).await?;
    let row: (Value, bool) = sqlx::query_as(
        "SELECT body, created FROM app_group_open(
            (SELECT array_agg(u::uuid ORDER BY ord)
             FROM unnest($1::text[]) WITH ORDINALITY AS t(u, ord)),
            $2,
            $3
        )",
    )
    .bind(&users)
    .bind(&name)
    .bind(e2ee)
    .fetch_one(&mut *tx)
    .await
    .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(row)
}

/// Renames a group conversation. Empty string clears the name.
pub async fn rename_group(
    pool: &PgPool,
    caller: &Caller,
    id: &str,
    name: &str,
) -> Result<Value, MessageError> {
    if !is_uuid(id) {
        return Err(MessageError::NotFound);
    }
    let name = validate_group_name(name)?;
    let mut tx = scoped(pool, caller).await?;
    let value = json_in(&mut tx, "SELECT app_group_rename($1::uuid, $2)", |query| {
        query.bind(id).bind(&name)
    })
    .await?;
    commit(tx, value).await
}

/// Adds one member to a group conversation. Returns `(group_json, added)`.
/// If the user is already a member, returns `(group_json, false)`.
pub async fn add_group_member(
    pool: &PgPool,
    caller: &Caller,
    id: &str,
    user_id: &str,
) -> Result<(Value, bool), MessageError> {
    if !is_uuid(id) {
        return Err(MessageError::NotFound);
    }
    if !is_uuid(user_id) {
        return Err(MessageError::Invalid);
    }
    let mut tx = scoped(pool, caller).await?;
    let row: (Value, bool) =
        sqlx::query_as("SELECT body, added FROM app_group_add($1::uuid, $2::uuid)")
            .bind(id)
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    Ok(row)
}

/// Leaves a group conversation. If the caller was the last member, deletes the group and removes
/// its attachment files after commit.
pub async fn leave_group(
    pool: &PgPool,
    caller: &Caller,
    id: &str,
) -> Result<Vec<String>, MessageError> {
    if !is_uuid(id) {
        return Err(MessageError::NotFound);
    }
    let mut tx = scoped(pool, caller).await?;
    let ids: Vec<String> = sqlx::query_scalar("SELECT app_group_leave($1::uuid)")
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(message_sql)?;
    tx.commit().await.map_err(message_sql)?;
    remove_files(&ids);
    Ok(ids)
}

/// Validates and trims a group name: 0 to 80 characters, no ASCII control characters.
pub fn validate_group_name(name: &str) -> Result<String, MessageError> {
    let trimmed = name.trim();
    if trimmed.chars().count() > GROUP_NAME_MAX || trimmed.chars().any(|c| c.is_ascii_control()) {
        return Err(MessageError::Invalid);
    }
    Ok(trimmed.to_string())
}

/// Validates `user_ids` for `POST /v1/groups`: 2 to 100 distinct valid UUIDs, none equal to
/// `caller_id`. Preserves the input order.
pub fn validate_group_create_users(
    caller_id: &str,
    user_ids: &[String],
) -> Result<Vec<String>, MessageError> {
    if !(GROUP_CREATE_USERS_MIN..=GROUP_CREATE_USERS_MAX).contains(&user_ids.len()) {
        return Err(MessageError::Invalid);
    }
    let caller_norm = caller_id.trim().to_ascii_lowercase();
    let mut seen = HashSet::with_capacity(user_ids.len());
    let mut out = Vec::with_capacity(user_ids.len());
    for raw in user_ids {
        let id = raw.trim().to_ascii_lowercase();
        if !is_uuid(&id) || id == caller_norm || !seen.insert(id.clone()) {
            return Err(MessageError::Invalid);
        }
        out.push(id);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const U1: &str = "11111111-1111-4111-8111-111111111111";
    const U2: &str = "22222222-2222-4222-8222-222222222222";
    const U3: &str = "33333333-3333-4333-8333-333333333333";

    #[test]
    fn group_name_allows_empty_up_to_80_and_rejects_controls() {
        assert_eq!(validate_group_name("").expect("empty"), "");
        assert_eq!(validate_group_name("   ").expect("blank"), "");
        assert_eq!(
            validate_group_name("  Design Crew  ").expect("trim"),
            "Design Crew"
        );
        assert_eq!(validate_group_name(&"a".repeat(80)).expect("80").len(), 80);
        assert!(matches!(
            validate_group_name(&"a".repeat(81)),
            Err(MessageError::Invalid)
        ));
        assert!(matches!(
            validate_group_name("bad\nname"),
            Err(MessageError::Invalid)
        ));
        assert!(matches!(
            validate_group_name("bad\u{0}name"),
            Err(MessageError::Invalid)
        ));
    }

    #[test]
    fn group_create_users_requires_two_to_hundred_distinct_non_self_uuids() {
        let ok = validate_group_create_users(U1, &[U3.into(), U2.into()]).expect("valid");
        assert_eq!(ok, vec![U3, U2]);

        // Fewer than two -> Invalid.
        assert!(matches!(
            validate_group_create_users(U1, &[U2.into()]),
            Err(MessageError::Invalid)
        ));
        // Self -> Invalid.
        assert!(matches!(
            validate_group_create_users(U1, &[U1.into(), U2.into()]),
            Err(MessageError::Invalid)
        ));
        // Duplicate (case-insensitive) -> Invalid.
        assert!(matches!(
            validate_group_create_users(U1, &[U2.into(), U2.to_uppercase()]),
            Err(MessageError::Invalid)
        ));
        // Bad UUID -> Invalid.
        assert!(matches!(
            validate_group_create_users(U1, &["not-a-uuid".into(), U2.into()]),
            Err(MessageError::Invalid)
        ));
        // Over 100 -> Invalid.
        let over: Vec<String> = (1..=101)
            .map(|n| format!("00000000-0000-4000-8000-{n:012}"))
            .collect();
        assert!(matches!(
            validate_group_create_users(U1, &over),
            Err(MessageError::Invalid)
        ));
    }
}
