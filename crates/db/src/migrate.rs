use crate::DbError;
use sqlx::PgPool;

pub async fn migrate(pool: &PgPool) -> Result<(), DbError> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}
