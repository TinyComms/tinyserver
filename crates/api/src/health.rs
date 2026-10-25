use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Extension, Json, Router};
use db::PgPool;
use serde::Serialize;

use crate::Live;

#[derive(Serialize)]
struct Health {
    ok: bool,
    db_role: String,
    schema: &'static str,
    /// `off` without an SFU, `up` while it runs, `down` once it stopped.
    media: &'static str,
}

pub fn routes(live: Option<Live>) -> Router<PgPool> {
    Router::new()
        .route("/health", get(health))
        .layer(Extension(live))
}

async fn health(
    State(pool): State<PgPool>,
    Extension(live): Extension<Option<Live>>,
) -> (StatusCode, Json<Health>) {
    let media = live.as_ref().map_or("off", Live::media);
    match probe(&pool).await {
        Ok(mut body) => {
            body.media = media;
            body.ok = body.ok && media != "down";
            let status = if body.ok {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            (status, Json(body))
        }
        Err(error) => {
            tracing::warn!(%error, "database health check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(Health {
                    ok: false,
                    db_role: String::new(),
                    schema: "unreachable",
                    media,
                }),
            )
        }
    }
}

async fn probe(pool: &PgPool) -> Result<Health, sqlx::Error> {
    let (db_role, ready): (String, bool) =
        sqlx::query_as("SELECT current_user, to_regclass('public.memberships') IS NOT NULL")
            .fetch_one(pool)
            .await?;
    let schema = if ready { "ready" } else { "missing" };
    Ok(Health {
        ok: ready,
        db_role,
        schema,
        media: "off",
    })
}
