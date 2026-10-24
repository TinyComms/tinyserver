use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use db::PgPool;
use serde::Serialize;

#[derive(Serialize)]
struct Health {
    ok: bool,
    db_role: String,
    schema: &'static str,
}

pub fn routes() -> Router<PgPool> {
    Router::new().route("/health", get(health))
}

async fn health(State(pool): State<PgPool>) -> (StatusCode, Json<Health>) {
    match probe(&pool).await {
        Ok(body) => {
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
    })
}
