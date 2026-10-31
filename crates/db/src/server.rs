//! The server's own settings and icon, and its categories and channel layout.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::bootstrap::normalize_name;
use crate::community::{audit, from_sql, require, room_event, rooms_in, scope, uuid, Room, STAMP};
use crate::outbox::emit;
use crate::perm;
use crate::{Caller, CommunityError};

/// The largest icon, in bytes.
pub const ICON_MAX: usize = 256 * 1024;
/// Images and GIFs, until an admin changes it.
pub const IMAGE_MAX_DEFAULT: i64 = 8 * 1024 * 1024;
/// Video and every other file, until an admin changes it.
pub const FILE_MAX_DEFAULT: i64 = 25 * 1024 * 1024;
/// The most an admin may allow for either kind of upload.
pub const UPLOAD_MAX: i64 = 100 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerSettings {
    pub name: String,
    pub description: String,
    pub welcome: String,
    /// The SHA-256 of the icon in hex, or `None` without one.
    pub icon: Option<String>,
    pub default_room_id: Option<String>,
    pub afk_room_id: Option<String>,
    /// 0 is off.
    pub afk_timeout_secs: i32,
    /// Images and GIFs, in bytes.
    pub image_max_bytes: i64,
    /// Video and every other file, in bytes.
    pub file_max_bytes: i64,
    /// Zip and other archives may be stored when this is true. Default false.
    pub allow_archives: bool,
    pub created_at: String,
}

/// `None` leaves a field as it is. The room ids take `Some(None)` to clear.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerPatch {
    pub name: Option<String>,
    pub description: Option<String>,
    pub welcome: Option<String>,
    pub default_room_id: Option<Option<String>>,
    pub afk_room_id: Option<Option<String>>,
    pub afk_timeout_secs: Option<i32>,
    pub image_max_bytes: Option<i64>,
    pub file_max_bytes: Option<i64>,
    pub allow_archives: Option<bool>,
}

pub struct Icon {
    pub bytes: Vec<u8>,
    pub content_type: String,
    pub sha: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Category {
    pub id: String,
    pub name: String,
    pub position: i32,
}

/// One bucket of `PUT /v1/layout`: a category, or `None` for the uncategorized rooms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutBucket {
    pub category_id: Option<String>,
    pub room_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Layout {
    pub categories: Vec<Category>,
    pub rooms: Vec<Room>,
}

fn settings_select() -> String {
    format!(
        "SELECT name, description, welcome, icon_sha, default_room_id::text, afk_room_id::text,
                afk_timeout_secs, image_max_bytes, file_max_bytes, allow_archives,
                to_char(created_at AT TIME ZONE 'UTC', '{STAMP}')
         FROM server_settings"
    )
}

pub async fn get_server(pool: &PgPool, caller: &Caller) -> Result<ServerSettings, CommunityError> {
    let mut tx = scope(pool, caller).await?;
    let settings = settings_in(&mut tx).await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(settings)
}

async fn settings_in(tx: &mut Transaction<'_, Postgres>) -> Result<ServerSettings, CommunityError> {
    let row = sqlx::query(&settings_select())
        .fetch_optional(&mut **tx)
        .await
        .map_err(from_sql)?;
    // Hidden by RLS from anyone who is not a member.
    let Some(row) = row else {
        return Err(CommunityError::Forbidden);
    };
    settings_from(&row)
}

/// Needs manage_server. Name 1 to 80 characters, description up to 500, welcome up to 2000.
pub async fn update_server(
    pool: &PgPool,
    caller: &Caller,
    patch: &ServerPatch,
) -> Result<ServerSettings, CommunityError> {
    let name = match &patch.name {
        Some(name) => Some(normalize_name(name).map_err(|_| CommunityError::Invalid)?),
        None => None,
    };
    let description = bounded(patch.description.as_deref(), 500)?;
    let welcome = bounded(patch.welcome.as_deref(), 2000)?;
    if patch
        .afk_timeout_secs
        .is_some_and(|secs| !(0..=86_400).contains(&secs))
    {
        return Err(CommunityError::Invalid);
    }
    let default_room = room_choice(&patch.default_room_id)?;
    let afk_room = room_choice(&patch.afk_room_id)?;
    let image_max = upload_limit(patch.image_max_bytes)?;
    let file_max = upload_limit(patch.file_max_bytes)?;
    let mut tx = scope(pool, caller).await?;
    require(&mut tx, perm::MANAGE_SERVER).await?;
    sqlx::query(
        "UPDATE server_settings
         SET name = coalesce($1, name),
             description = coalesce($2, description),
             welcome = coalesce($3, welcome),
             default_room_id = CASE WHEN $4 THEN $5::uuid ELSE default_room_id END,
             afk_room_id = CASE WHEN $6 THEN $7::uuid ELSE afk_room_id END,
             afk_timeout_secs = coalesce($8, afk_timeout_secs),
             image_max_bytes = coalesce($9, image_max_bytes),
             file_max_bytes = coalesce($10, file_max_bytes),
             allow_archives = coalesce($11, allow_archives)",
    )
    .bind(name.as_deref())
    .bind(description.as_deref())
    .bind(welcome.as_deref())
    .bind(default_room.0)
    .bind(default_room.1.as_deref())
    .bind(afk_room.0)
    .bind(afk_room.1.as_deref())
    .bind(patch.afk_timeout_secs)
    .bind(image_max)
    .bind(file_max)
    .bind(patch.allow_archives)
    .execute(&mut *tx)
    .await
    .map_err(from_sql)?;
    let settings = settings_in(&mut tx).await?;
    let mut changed = serde_json::Map::new();
    if name.is_some() {
        changed.insert("name".into(), Value::from(settings.name.clone()));
    }
    for (key, set) in [
        ("description", description.is_some()),
        ("welcome", welcome.is_some()),
        ("default_room_id", default_room.0),
        ("afk_room_id", afk_room.0),
        ("afk_timeout_secs", patch.afk_timeout_secs.is_some()),
        ("image_max_bytes", image_max.is_some()),
        ("file_max_bytes", file_max.is_some()),
        ("allow_archives", patch.allow_archives.is_some()),
    ] {
        if set {
            changed.insert(key.into(), Value::Bool(true));
        }
    }
    audit(&mut tx, "server.update", "server", Value::Object(changed)).await?;
    emit(
        &mut tx,
        "server.updated",
        serde_json::json!({ "server": settings }),
    )
    .await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(settings)
}

fn upload_limit(value: Option<i64>) -> Result<Option<i64>, CommunityError> {
    match value {
        None => Ok(None),
        Some(value) if (1..=UPLOAD_MAX).contains(&value) => Ok(Some(value)),
        Some(_) => Err(CommunityError::Invalid),
    }
}

fn bounded(text: Option<&str>, max: usize) -> Result<Option<String>, CommunityError> {
    let Some(text) = text else {
        return Ok(None);
    };
    let text = text.trim();
    if text.chars().count() > max {
        return Err(CommunityError::Invalid);
    }
    Ok(Some(text.to_string()))
}

fn room_choice(choice: &Option<Option<String>>) -> Result<(bool, Option<String>), CommunityError> {
    match choice {
        None => Ok((false, None)),
        Some(None) => Ok((true, None)),
        Some(Some(id)) => Ok((true, Some(uuid(id)?))),
    }
}

/// Any member. `None` without an icon.
pub async fn get_icon(pool: &PgPool, caller: &Caller) -> Result<Option<Icon>, CommunityError> {
    let mut tx = scope(pool, caller).await?;
    type IconRow = (Option<Vec<u8>>, Option<String>, Option<String>);
    let row: Option<IconRow> =
        sqlx::query_as("SELECT icon, icon_type, icon_sha FROM server_settings")
            .fetch_optional(&mut *tx)
            .await
            .map_err(from_sql)?;
    tx.commit().await.map_err(from_sql)?;
    let Some(row) = row else {
        return Err(CommunityError::Forbidden);
    };
    Ok(match row {
        (Some(bytes), Some(content_type), Some(sha)) => Some(Icon {
            bytes,
            content_type,
            sha,
        }),
        _ => None,
    })
}

/// The image type from its first bytes: PNG, JPEG, or WebP.
pub fn sniff_image(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

/// Needs manage_server. Checked before the icon is decoded, so someone who may not change it
/// gets forbidden rather than a media error.
pub async fn ensure_manage_server(pool: &PgPool, caller: &Caller) -> Result<(), CommunityError> {
    let mut tx = scope(pool, caller).await?;
    require(&mut tx, perm::MANAGE_SERVER).await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(())
}

/// Needs manage_server. Returns the new icon's SHA-256 in hex. The caller checks the type and
/// the size first.
pub async fn set_icon(
    pool: &PgPool,
    caller: &Caller,
    bytes: &[u8],
    content_type: &str,
) -> Result<String, CommunityError> {
    if bytes.is_empty() || bytes.len() > ICON_MAX {
        return Err(CommunityError::Invalid);
    }
    let sha: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let mut tx = scope(pool, caller).await?;
    require(&mut tx, perm::MANAGE_SERVER).await?;
    sqlx::query("UPDATE server_settings SET icon = $1, icon_type = $2, icon_sha = $3")
        .bind(bytes)
        .bind(content_type)
        .bind(&sha)
        .execute(&mut *tx)
        .await
        .map_err(from_sql)?;
    audit(
        &mut tx,
        "server.icon",
        "server",
        serde_json::json!({ "icon": sha, "bytes": bytes.len(), "type": content_type }),
    )
    .await?;
    let settings = settings_in(&mut tx).await?;
    emit(
        &mut tx,
        "server.updated",
        serde_json::json!({ "server": settings }),
    )
    .await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(sha)
}

pub async fn delete_icon(pool: &PgPool, caller: &Caller) -> Result<(), CommunityError> {
    let mut tx = scope(pool, caller).await?;
    require(&mut tx, perm::MANAGE_SERVER).await?;
    sqlx::query("UPDATE server_settings SET icon = NULL, icon_type = NULL, icon_sha = NULL")
        .execute(&mut *tx)
        .await
        .map_err(from_sql)?;
    audit(
        &mut tx,
        "server.icon",
        "server",
        serde_json::json!({ "icon": null }),
    )
    .await?;
    let settings = settings_in(&mut tx).await?;
    emit(
        &mut tx,
        "server.updated",
        serde_json::json!({ "server": settings }),
    )
    .await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(())
}

// Categories.

pub async fn list_categories(
    pool: &PgPool,
    caller: &Caller,
) -> Result<Vec<Category>, CommunityError> {
    let mut tx = scope(pool, caller).await?;
    let categories = categories_in(&mut tx).await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(categories)
}

async fn categories_in(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<Vec<Category>, CommunityError> {
    let rows: Vec<(String, String, i32)> = sqlx::query_as(
        "SELECT id::text, name, position FROM categories ORDER BY position, created_at, id",
    )
    .fetch_all(&mut **tx)
    .await
    .map_err(from_sql)?;
    Ok(rows
        .into_iter()
        .map(|(id, name, position)| Category { id, name, position })
        .collect())
}

/// Needs manage_channels. A new category goes last.
pub async fn create_category(
    pool: &PgPool,
    caller: &Caller,
    name: &str,
) -> Result<Category, CommunityError> {
    let name = normalize_name(name).map_err(|_| CommunityError::Invalid)?;
    let mut tx = scope(pool, caller).await?;
    require(&mut tx, perm::MANAGE_CHANNELS).await?;
    let (id, position): (String, i32) = sqlx::query_as(
        "INSERT INTO categories (name, position)
         VALUES ($1, (SELECT coalesce(max(position) + 1, 0) FROM categories))
         RETURNING id::text, position",
    )
    .bind(&name)
    .fetch_one(&mut *tx)
    .await
    .map_err(from_sql)?;
    let category = Category { id, name, position };
    audit(
        &mut tx,
        "category.create",
        "category",
        serde_json::json!({ "id": category.id, "name": category.name }),
    )
    .await?;
    emit(
        &mut tx,
        "category.created",
        serde_json::json!({ "category": category }),
    )
    .await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(category)
}

pub async fn rename_category(
    pool: &PgPool,
    caller: &Caller,
    id: &str,
    name: &str,
) -> Result<Category, CommunityError> {
    let name = normalize_name(name).map_err(|_| CommunityError::Invalid)?;
    let mut tx = scope(pool, caller).await?;
    require(&mut tx, perm::MANAGE_CHANNELS).await?;
    let row: Option<(String, String, i32)> = sqlx::query_as(
        "UPDATE categories SET name = $2 WHERE id = $1::uuid RETURNING id::text, name, position",
    )
    .bind(id)
    .bind(&name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(from_sql)?;
    let Some((id, name, position)) = row else {
        return Err(CommunityError::NotFound);
    };
    let category = Category { id, name, position };
    audit(
        &mut tx,
        "category.update",
        "category",
        serde_json::json!({ "id": category.id, "name": category.name }),
    )
    .await?;
    emit(
        &mut tx,
        "category.updated",
        serde_json::json!({ "category": category }),
    )
    .await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(category)
}

/// Its rooms become uncategorized.
pub async fn delete_category(
    pool: &PgPool,
    caller: &Caller,
    id: &str,
) -> Result<(), CommunityError> {
    let mut tx = scope(pool, caller).await?;
    require(&mut tx, perm::MANAGE_CHANNELS).await?;
    let gone: Option<(String, String)> =
        sqlx::query_as("DELETE FROM categories WHERE id = $1::uuid RETURNING id::text, name")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(from_sql)?;
    let Some((id, name)) = gone else {
        return Err(CommunityError::NotFound);
    };
    audit(
        &mut tx,
        "category.delete",
        "category",
        serde_json::json!({ "id": id, "name": name }),
    )
    .await?;
    emit(
        &mut tx,
        "category.deleted",
        serde_json::json!({ "category_id": id }),
    )
    .await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(())
}

/// Orders categories by their place in `buckets` and puts each listed room in its bucket's
/// category at its place there. Rooms and categories not listed keep where they are. Needs
/// manage_channels, and manage_channels in every room moved.
pub async fn set_layout(
    pool: &PgPool,
    caller: &Caller,
    buckets: &[LayoutBucket],
) -> Result<Layout, CommunityError> {
    let mut categories = Vec::new();
    let mut rooms = Vec::new();
    for bucket in buckets {
        if let Some(category) = &bucket.category_id {
            categories.push(uuid(category)?);
        }
        for room in &bucket.room_ids {
            rooms.push(uuid(room)?);
        }
    }
    let unique = |ids: &[String]| {
        let mut sorted = ids.to_vec();
        sorted.sort();
        sorted.dedup();
        sorted.len() == ids.len()
    };
    if !unique(&categories) || !unique(&rooms) || buckets.len() > 500 || rooms.len() > 2000 {
        return Err(CommunityError::Invalid);
    }
    let mut tx = scope(pool, caller).await?;
    require(&mut tx, perm::MANAGE_CHANNELS).await?;
    let mut position = 0;
    for bucket in buckets {
        let category = match &bucket.category_id {
            Some(id) => {
                let id = uuid(id)?;
                let updated =
                    sqlx::query("UPDATE categories SET position = $2 WHERE id = $1::uuid")
                        .bind(&id)
                        .bind(position)
                        .execute(&mut *tx)
                        .await
                        .map_err(from_sql)?;
                if updated.rows_affected() == 0 {
                    return Err(CommunityError::NotFound);
                }
                position += 1;
                Some(id)
            }
            None => None,
        };
        for (index, room) in bucket.room_ids.iter().enumerate() {
            let updated = sqlx::query(
                "UPDATE rooms SET category_id = $2::uuid, position = $3 WHERE id = $1::uuid",
            )
            .bind(uuid(room)?)
            .bind(category.as_deref())
            .bind(i32::try_from(index).map_err(|_| CommunityError::Invalid)?)
            .execute(&mut *tx)
            .await
            .map_err(from_sql)?;
            if updated.rows_affected() == 0 {
                // Missing, hidden, or no manage_channels there.
                return Err(CommunityError::NotFound);
            }
        }
    }
    let layout = Layout {
        categories: categories_in(&mut tx).await?,
        rooms: rooms_in(&mut tx).await?,
    };
    audit(
        &mut tx,
        "layout.update",
        "layout",
        serde_json::json!({ "categories": categories, "rooms": rooms }),
    )
    .await?;
    let rooms: Vec<Value> = layout
        .rooms
        .iter()
        .map(|room| room_event(room)["room"].clone())
        .collect();
    emit(
        &mut tx,
        "layout.updated",
        serde_json::json!({ "categories": layout.categories, "rooms": rooms }),
    )
    .await?;
    tx.commit().await.map_err(from_sql)?;
    Ok(layout)
}

fn settings_from(row: &PgRow) -> Result<ServerSettings, CommunityError> {
    Ok(ServerSettings {
        name: row.try_get(0).map_err(from_sql)?,
        description: row.try_get(1).map_err(from_sql)?,
        welcome: row.try_get(2).map_err(from_sql)?,
        icon: row.try_get(3).map_err(from_sql)?,
        default_room_id: row.try_get(4).map_err(from_sql)?,
        afk_room_id: row.try_get(5).map_err(from_sql)?,
        afk_timeout_secs: row.try_get(6).map_err(from_sql)?,
        image_max_bytes: row.try_get(7).map_err(from_sql)?,
        file_max_bytes: row.try_get(8).map_err(from_sql)?,
        allow_archives: row.try_get(9).map_err(from_sql)?,
        created_at: row.try_get(10).map_err(from_sql)?,
    })
}

#[cfg(test)]
mod tests {
    use super::sniff_image;

    #[test]
    fn icons_are_png_jpeg_or_webp() {
        assert_eq!(sniff_image(b"\x89PNG\r\n\x1a\nrest"), Some("image/png"));
        assert_eq!(sniff_image(&[0xFF, 0xD8, 0xFF, 0xE0]), Some("image/jpeg"));
        assert_eq!(sniff_image(b"RIFF\0\0\0\0WEBPVP8 "), Some("image/webp"));
        assert_eq!(sniff_image(b"GIF89a"), None);
        assert_eq!(sniff_image(b""), None);
    }
}
