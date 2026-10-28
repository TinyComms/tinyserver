//! Roles. Every write goes through a `SECURITY DEFINER` function that checks manage_roles and
//! the hierarchy; see `migrations/0005_server.sql`.

use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::bootstrap::normalize_name;
use crate::community::{from_sql, scope, uuids};
use crate::outbox::emit;
use crate::perm;
use crate::{Caller, CommunityError};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Role {
    pub id: String,
    pub name: String,
    /// `#RRGGBB`.
    pub color: Option<String>,
    pub position: i32,
    pub permissions: i64,
    pub hoist: bool,
    /// @everyone.
    pub default: bool,
    pub member_count: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NewRole {
    pub name: String,
    pub color: Option<String>,
    pub permissions: Option<i64>,
    pub hoist: Option<bool>,
}

/// `None` leaves a field as it is; `color: Some(None)` clears the colour.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RolePatch {
    pub name: Option<String>,
    pub color: Option<Option<String>>,
    pub permissions: Option<i64>,
    pub hoist: Option<bool>,
}

const ROLE_SELECT: &str = "SELECT r.id::text, r.name, r.color, r.position, r.permissions, r.hoist,
                                  r.is_default,
                                  CASE WHEN r.is_default
                                       THEN (SELECT count(*) FROM memberships)
                                       ELSE (SELECT count(*) FROM member_roles mr
                                             WHERE mr.role_id = r.id) END
                           FROM roles r";

/// Every role, most senior first. Any member may read them.
pub async fn list_roles(pool: &PgPool, caller: &Caller) -> Result<Vec<Role>, CommunityError> {
    let mut tx = scope(pool, caller).await?;
    let roles = roles_in(&mut tx).await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(roles)
}

async fn roles_in(tx: &mut Transaction<'_, Postgres>) -> Result<Vec<Role>, CommunityError> {
    let rows = sqlx::query(&format!("{ROLE_SELECT} ORDER BY r.position DESC"))
        .fetch_all(&mut **tx)
        .await
        .map_err(from_sql)?;
    rows.iter().map(role_from).collect()
}

async fn role_in(tx: &mut Transaction<'_, Postgres>, id: &str) -> Result<Role, CommunityError> {
    let row = sqlx::query(&format!("{ROLE_SELECT} WHERE r.id = $1::uuid"))
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(from_sql)?;
    let Some(row) = row else {
        return Err(CommunityError::NotFound);
    };
    role_from(&row)
}

/// Placed just below the caller's rank, or at the top for an owner.
pub async fn create_role(
    pool: &PgPool,
    caller: &Caller,
    input: &NewRole,
) -> Result<Role, CommunityError> {
    let name = normalize_name(&input.name).map_err(|_| CommunityError::Invalid)?;
    let color = match &input.color {
        Some(color) => Some(clean_color(color)?),
        None => None,
    };
    let permissions = input.permissions.unwrap_or(0) & perm::ALL;
    let mut tx = scope(pool, caller).await?;
    let id: String = sqlx::query_scalar("SELECT app_role_create($1, $2, $3, $4)::text")
        .bind(&name)
        .bind(color.as_deref())
        .bind(permissions)
        .bind(input.hoist.unwrap_or(false))
        .fetch_one(&mut *tx)
        .await
        .map_err(from_sql)?;
    let role = role_in(&mut tx, &id).await?;
    emit(&mut tx, "role.created", serde_json::json!({ "role": role })).await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(role)
}

pub async fn update_role(
    pool: &PgPool,
    caller: &Caller,
    id: &str,
    patch: &RolePatch,
) -> Result<Role, CommunityError> {
    let mut tx = scope(pool, caller).await?;
    let current = role_in(&mut tx, id).await?;
    let name = match &patch.name {
        Some(name) => normalize_name(name).map_err(|_| CommunityError::Invalid)?,
        None => current.name.clone(),
    };
    let color = match &patch.color {
        Some(Some(color)) => Some(clean_color(color)?),
        Some(None) => None,
        None => current.color.clone(),
    };
    let permissions = patch
        .permissions
        .map_or(current.permissions, |bits| bits & perm::ALL);
    let hoist = patch.hoist.unwrap_or(current.hoist);
    sqlx::query("SELECT app_role_update($1::uuid, $2, $3, $4, $5)")
        .bind(id)
        .bind(&name)
        .bind(color.as_deref())
        .bind(permissions)
        .bind(hoist)
        .execute(&mut *tx)
        .await
        .map_err(from_sql)?;
    let role = role_in(&mut tx, id).await?;
    emit(&mut tx, "role.updated", serde_json::json!({ "role": role })).await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(role)
}

pub async fn delete_role(pool: &PgPool, caller: &Caller, id: &str) -> Result<(), CommunityError> {
    let mut tx = scope(pool, caller).await?;
    sqlx::query("SELECT app_role_delete($1::uuid)")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(from_sql)?;
    emit(
        &mut tx,
        "role.deleted",
        serde_json::json!({ "role_id": id }),
    )
    .await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(())
}

/// `ids` is every role but @everyone, most senior first. Including @everyone is `default_role`.
pub async fn order_roles(
    pool: &PgPool,
    caller: &Caller,
    ids: &[String],
) -> Result<Vec<Role>, CommunityError> {
    let ids = uuids(ids)?;
    let mut tx = scope(pool, caller).await?;
    let default_listed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM roles WHERE is_default AND id = ANY ($1::uuid[]))",
    )
    .bind(&ids)
    .fetch_one(&mut *tx)
    .await
    .map_err(from_sql)?;
    if default_listed {
        return Err(CommunityError::DefaultRole);
    }
    sqlx::query("SELECT app_role_order($1::uuid[])")
        .bind(&ids)
        .execute(&mut *tx)
        .await
        .map_err(from_sql)?;
    let roles = roles_in(&mut tx).await?;
    emit(
        &mut tx,
        "roles.reordered",
        serde_json::json!({ "role_ids": ids }),
    )
    .await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(roles)
}

/// `#rgb` or `#rrggbb`, any case, as `#RRGGBB`.
fn clean_color(color: &str) -> Result<String, CommunityError> {
    let hex = color
        .trim()
        .strip_prefix('#')
        .ok_or(CommunityError::Invalid)?;
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CommunityError::Invalid);
    }
    let full = match hex.len() {
        6 => hex.to_string(),
        3 => hex.chars().flat_map(|c| [c, c]).collect(),
        _ => return Err(CommunityError::Invalid),
    };
    Ok(format!("#{}", full.to_ascii_uppercase()))
}

fn role_from(row: &PgRow) -> Result<Role, CommunityError> {
    Ok(Role {
        id: row.try_get(0).map_err(from_sql)?,
        name: row.try_get(1).map_err(from_sql)?,
        color: row.try_get(2).map_err(from_sql)?,
        position: row.try_get(3).map_err(from_sql)?,
        permissions: row.try_get(4).map_err(from_sql)?,
        hoist: row.try_get(5).map_err(from_sql)?,
        default: row.try_get(6).map_err(from_sql)?,
        member_count: row.try_get(7).map_err(from_sql)?,
    })
}

#[cfg(test)]
mod tests {
    use super::clean_color;

    #[test]
    fn colours_are_six_upper_hex_digits() {
        assert_eq!(clean_color("#3b82f6").expect("ok"), "#3B82F6");
        assert_eq!(clean_color("#abc").expect("ok"), "#AABBCC");
        assert!(clean_color("3b82f6").is_err());
        assert!(clean_color("#zzzzzz").is_err());
    }
}
