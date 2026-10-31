//! Bots on this community. An owner or admin grants scopes and receives a token once.
//! The bot presents `Authorization: Bot <token>`. It is not a member and has no session.

use serde::Serialize;
use sqlx::Row;

use crate::bootstrap::normalize_name;
use crate::community::{self, audit, require, scope, Caller, CommunityError};
use crate::session::{new_token, token_digest, SessionError};
use crate::PgPool;

const SCOPES: &[&str] = &["rooms.read", "members.read", "rooms.write"];

/// `VIEW_CHANNEL` in the server permission mask (`1 << 0`).
const VIEW_CHANNEL: i64 = 1 << 0;
/// `MANAGE_CHANNELS` in the server permission mask (`1 << 9`).
const MANAGE_CHANNELS: i64 = 1 << 9;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Bot {
    pub id: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub permissions: i64,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BotIssued {
    pub id: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub permissions: i64,
    pub token: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BotSession {
    pub id: String,
    pub name: String,
    pub scopes: Vec<String>,
}

/// The scopes a bot may be granted. Empty is allowed: the bot can then only identify itself.
pub fn granted(scopes: &[String]) -> Result<Vec<String>, CommunityError> {
    let mut out = Vec::with_capacity(scopes.len());
    for scope in scopes {
        let scope = scope.trim();
        if !SCOPES.contains(&scope) || out.iter().any(|have: &String| have == scope) {
            return Err(CommunityError::Invalid);
        }
        out.push(scope.to_string());
    }
    Ok(out)
}

/// `permissions`, when sent, replaces `scopes`. The stored scopes are the names that integer
/// implies. `members.read` has no bit, so it stays only when the integer is absent.
pub fn grant(
    scopes: &[String],
    permissions: Option<i64>,
) -> Result<(i64, Vec<String>), CommunityError> {
    if let Some(permissions) = permissions {
        if permissions < 0 {
            return Err(CommunityError::Invalid);
        }
        return Ok((permissions, scopes_from_permissions(permissions)));
    }
    let scopes = granted(scopes)?;
    Ok((permissions_of(&scopes), scopes))
}

fn scopes_from_permissions(permissions: i64) -> Vec<String> {
    let mut scopes = Vec::new();
    if permissions & VIEW_CHANNEL == VIEW_CHANNEL {
        scopes.push("rooms.read".into());
    }
    if permissions & MANAGE_CHANNELS == MANAGE_CHANNELS {
        scopes.push("rooms.write".into());
    }
    scopes
}

fn permissions_of(scopes: &[String]) -> i64 {
    let mut permissions = 0;
    for scope in scopes {
        match scope.as_str() {
            "rooms.read" => permissions |= VIEW_CHANNEL,
            "rooms.write" => permissions |= MANAGE_CHANNELS,
            _ => {}
        }
    }
    permissions
}

pub async fn create_bot(
    pool: &PgPool,
    caller: &Caller,
    name: &str,
    scopes: &[String],
    permissions: Option<i64>,
) -> Result<BotIssued, CommunityError> {
    let name = normalize_name(name).map_err(|_| CommunityError::Invalid)?;
    let (permissions, scopes) = grant(scopes, permissions)?;
    let mut tx = scope(pool, caller).await?;
    require(&mut tx, crate::perm::MANAGE_SERVER).await?;
    let token = new_token();
    let digest = token_digest(&token);
    let row = sqlx::query(&format!(
        "INSERT INTO bots (name, token_hash, scopes, permissions, created_by)
         VALUES ($1, $2, $3, $4, $5::uuid)
         RETURNING id::text, name, scopes, permissions,
                   to_char(created_at AT TIME ZONE 'UTC', '{stamp}') AS created_at",
        stamp = community::STAMP
    ))
    .bind(&name)
    .bind(digest.as_slice())
    .bind(&scopes)
    .bind(permissions)
    .bind(&caller.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(community::from_sql)?;
    let id: String = row.try_get("id").map_err(community::from_sql)?;
    let created_at: String = row.try_get("created_at").map_err(community::from_sql)?;
    let stored: Vec<String> = row.try_get("scopes").map_err(community::from_sql)?;
    let stored_permissions: i64 = row.try_get("permissions").map_err(community::from_sql)?;
    audit(
        &mut tx,
        "bot.create",
        "bot",
        serde_json::json!({"id": id, "name": name, "scopes": stored, "permissions": stored_permissions}),
    )
    .await?;
    tx.commit().await.map_err(community::from_sql)?;
    Ok(BotIssued {
        id,
        name,
        scopes: stored,
        permissions: stored_permissions,
        token,
        created_at,
    })
}

pub async fn list_bots(pool: &PgPool, caller: &Caller) -> Result<Vec<Bot>, CommunityError> {
    let mut tx = scope(pool, caller).await?;
    require(&mut tx, crate::perm::MANAGE_SERVER).await?;
    let rows = sqlx::query(&format!(
        "SELECT id::text, name, scopes, permissions,
                to_char(created_at AT TIME ZONE 'UTC', '{stamp}') AS created_at
         FROM bots
         WHERE revoked_at IS NULL
         ORDER BY created_at, id",
        stamp = community::STAMP
    ))
    .fetch_all(&mut *tx)
    .await
    .map_err(community::from_sql)?;
    let mut bots = Vec::with_capacity(rows.len());
    for row in rows {
        bots.push(Bot {
            id: row.try_get("id").map_err(community::from_sql)?,
            name: row.try_get("name").map_err(community::from_sql)?,
            scopes: row.try_get("scopes").map_err(community::from_sql)?,
            permissions: row.try_get("permissions").map_err(community::from_sql)?,
            created_at: row.try_get("created_at").map_err(community::from_sql)?,
        });
    }
    tx.commit().await.map_err(community::from_sql)?;
    Ok(bots)
}

pub async fn revoke_bot(pool: &PgPool, caller: &Caller, id: &str) -> Result<(), CommunityError> {
    let mut tx = scope(pool, caller).await?;
    require(&mut tx, crate::perm::MANAGE_SERVER).await?;
    let revoked: Option<String> = sqlx::query_scalar(
        "UPDATE bots
         SET revoked_at = now()
         WHERE id = $1::uuid AND revoked_at IS NULL
         RETURNING id::text",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(community::from_sql)?;
    let Some(revoked) = revoked else {
        return Err(CommunityError::NotFound);
    };
    audit(
        &mut tx,
        "bot.revoke",
        "bot",
        serde_json::json!({"id": revoked}),
    )
    .await?;
    tx.commit().await.map_err(community::from_sql)?;
    Ok(())
}

/// The bot a token names, or unauthorized when the token is unknown or revoked.
pub async fn authenticate_bot(pool: &PgPool, token: &str) -> Result<BotSession, SessionError> {
    let digest = token_digest(token);
    let row: Option<(String, String, Vec<String>)> =
        sqlx::query_as("SELECT id::text, name, scopes FROM app_bot_identity($1)")
            .bind(digest.as_slice())
            .fetch_optional(pool)
            .await?;
    let Some((id, name, scopes)) = row else {
        return Err(SessionError::Unauthorized);
    };
    Ok(BotSession { id, name, scopes })
}

#[cfg(test)]
mod tests {
    use super::granted;

    #[test]
    fn scopes_are_the_two_server_grants_without_duplicates() {
        let rooms = vec!["rooms.read".to_string()];
        assert_eq!(granted(&rooms).expect("rooms").as_slice(), ["rooms.read"]);
        let both = vec![" members.read ".to_string(), "rooms.read".to_string()];
        assert_eq!(
            granted(&both).expect("both").as_slice(),
            ["members.read", "rooms.read"]
        );
        assert_eq!(
            granted(&["rooms.write".to_string()])
                .expect("write")
                .as_slice(),
            ["rooms.write"]
        );
        assert!(granted(&["voice.connect".to_string()]).is_err());
        assert!(granted(&["rooms.read".to_string(), "rooms.read".to_string()]).is_err());
        assert!(granted(&[]).expect("none").is_empty());
    }

    #[test]
    fn scopes_are_implied_by_the_permission_bits() {
        use super::grant;

        let (permissions, scopes) =
            grant(&["members.read".to_string()], Some(512)).expect("manage");
        assert_eq!(permissions, 512);
        assert_eq!(scopes, ["rooms.write"]);
        let (permissions, scopes) = grant(&[], Some(1)).expect("view");
        assert_eq!(permissions, 1);
        assert_eq!(scopes, ["rooms.read"]);
        let (permissions, scopes) = grant(&[], Some(513)).expect("both bits");
        assert_eq!(permissions, 513);
        assert_eq!(scopes, ["rooms.read", "rooms.write"]);
        let (permissions, scopes) = grant(&[], Some(2)).expect("connect");
        assert_eq!(permissions, 2);
        assert!(scopes.is_empty());
        assert!(grant(&[], Some(-1)).is_err());
        let (permissions, scopes) = grant(
            &["rooms.read".to_string(), "members.read".to_string()],
            None,
        )
        .expect("scopes");
        assert_eq!(permissions, 1);
        assert_eq!(scopes, ["rooms.read", "members.read"]);
    }
}
