use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{delete, patch};
use axum::{Json, Router};
use db::{close_all_sessions, rename_me, PgPool};
use serde::Deserialize;

use crate::community::{caller, lift, ApiError};
use crate::session::Current;

pub fn routes() -> Router<PgPool> {
    Router::new()
        .route("/v1/me", patch(rename))
        .route("/v1/sessions", delete(sign_out_everywhere))
}

#[derive(Deserialize)]
struct NameBody {
    display_name: String,
}

async fn rename(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(body): Json<NameBody>,
) -> Result<Json<Current>, ApiError> {
    let caller = caller(&pool, &headers).await?;
    let identity = rename_me(&pool, &caller, &body.display_name)
        .await
        .map_err(lift)?;
    tracing::info!(user_id = %caller.user_id, "display name changed");
    Ok(Json(Current::from(identity)))
}

async fn sign_out_everywhere(
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let caller = caller(&pool, &headers).await?;
    let ended = close_all_sessions(&pool, &caller).await.map_err(lift)?;
    tracing::info!(user_id = %caller.user_id, ended, "sessions closed");
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn account_routes_share_paths_without_overlap() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://nobody@127.0.0.1:1/none")
            .expect("lazy pool");
        let _ = crate::router(pool, None);
    }
}
