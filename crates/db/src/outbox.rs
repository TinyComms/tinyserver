//! Durable live events. A change writes its event with `emit` in its own transaction, and the
//! commit wakes `LISTEN app_wake`. The row id is the event seq, handed out in commit order.

use serde_json::Value;
use sqlx::{PgPool, Postgres, Transaction};

use crate::community::from_sql;
use crate::{CommunityError, DbError};

/// The `NOTIFY` channel an outbox insert fires.
pub const WAKE_CHANNEL: &str = "app_wake";

#[derive(Debug, Clone, PartialEq)]
pub struct OutboxRow {
    pub seq: i64,
    pub topic: String,
    pub payload: Value,
    /// Empty means every member socket. Otherwise only these user ids.
    pub users: Vec<String>,
}

/// The newest seq, and the highest seq the sweep has deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboxBounds {
    pub head: i64,
    pub pruned_through: i64,
}

pub(crate) async fn emit(
    tx: &mut Transaction<'_, Postgres>,
    topic: &str,
    payload: Value,
) -> Result<(), CommunityError> {
    sqlx::query("SELECT app_emit($1, $2)")
        .bind(topic)
        .bind(payload)
        .execute(&mut **tx)
        .await
        .map_err(from_sql)?;
    Ok(())
}

/// Like `emit`, for an event only `users` should see. An empty list is nobody, not everyone.
#[allow(dead_code)] // Message writes call `app_emit_to` in SQL. This is the same function.
pub(crate) async fn emit_to(
    tx: &mut Transaction<'_, Postgres>,
    topic: &str,
    payload: Value,
    users: &[String],
) -> Result<(), CommunityError> {
    sqlx::query(
        "SELECT app_emit_to($1, $2, (
            SELECT coalesce(array_agg(item::uuid), '{}') FROM unnest($3::text[]) AS item
        ))",
    )
    .bind(topic)
    .bind(payload)
    .bind(users)
    .execute(&mut **tx)
    .await
    .map_err(from_sql)?;
    Ok(())
}

/// Events with a seq above `after`, oldest first, at most `limit`.
pub async fn outbox_after(
    pool: &PgPool,
    after: i64,
    limit: i64,
) -> Result<Vec<OutboxRow>, DbError> {
    let rows: Vec<(i64, String, Value, Vec<String>)> = sqlx::query_as(
        "SELECT id, topic, payload, coalesce(audience::text[], '{}')
         FROM outbox WHERE id > $1 ORDER BY id LIMIT $2",
    )
    .bind(after)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(seq, topic, payload, users)| OutboxRow {
            seq,
            topic,
            payload,
            users,
        })
        .collect())
}

pub async fn outbox_bounds(pool: &PgPool) -> Result<OutboxBounds, DbError> {
    let (head, pruned_through): (i64, i64) = sqlx::query_as(
        "SELECT greatest(coalesce((SELECT max(id) FROM outbox), 0), through), through
         FROM outbox_pruned",
    )
    .fetch_one(pool)
    .await?;
    Ok(OutboxBounds {
        head,
        pruned_through,
    })
}
