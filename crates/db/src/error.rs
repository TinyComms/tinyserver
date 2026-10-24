use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
    #[error("migrate failed: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("an owner already exists")]
    OwnerExists,
    #[error("password must be 12 to 128 characters")]
    PasswordTooShort,
    #[error("email is not usable")]
    BadEmail,
    #[error("display name must be 1 to 80 characters")]
    BadName,
    #[error("could not hash the password")]
    Hash,
}
