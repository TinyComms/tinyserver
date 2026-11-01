use std::borrow::Cow;

use sha2::{Digest, Sha384};
use sqlx::migrate::Migrator;
use sqlx::PgPool;

use crate::DbError;

pub async fn migrate(pool: &PgPool) -> Result<(), DbError> {
    let mut migrator = sqlx::migrate!("./migrations");
    accept_other_line_endings(pool, &mut migrator).await?;
    migrator.run(pool).await?;
    Ok(())
}

/// sqlx refuses to continue when a migration it applied earlier has a different checksum, which
/// is its guard against a file being edited after it ran. The checksum is of the file's bytes, so
/// the same file read with Windows line endings (an image built from a checkout that converts
/// them) has another checksum, and a database migrated by that build then refuses the same
/// migrations from a Unix one.
///
/// Nothing is written to the database. For each migration applied with the checksum of its text
/// in the other line-ending form, this run is told that checksum, so the only difference it can
/// see is the one that does not matter. Any other difference is still an error.
async fn accept_other_line_endings(pool: &PgPool, migrator: &mut Migrator) -> Result<(), DbError> {
    let has_table: bool = sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations') IS NOT NULL")
        .fetch_one(pool)
        .await?;
    if !has_table {
        return Ok(());
    }
    let applied: Vec<(i64, Vec<u8>)> =
        sqlx::query_as("SELECT version, checksum FROM _sqlx_migrations")
            .fetch_all(pool)
            .await?;
    for migration in migrator.migrations.to_mut().iter_mut() {
        let Some((_, was)) = applied
            .iter()
            .find(|(version, _)| *version == migration.version)
        else {
            continue;
        };
        if let Some(checksum) = other_line_endings(&migration.sql, &migration.checksum, was) {
            tracing::info!(
                version = migration.version,
                "migration was applied with the other line endings; its text is the same"
            );
            migration.checksum = Cow::Owned(checksum);
        }
    }
    Ok(())
}

/// The checksum `was` recorded, if it is the checksum of `sql` with the other line endings and
/// not `current`'s.
fn other_line_endings(sql: &str, current: &[u8], was: &[u8]) -> Option<Vec<u8>> {
    if current == was {
        return None;
    }
    let unix = sql.replace("\r\n", "\n");
    let windows = unix.replace('\n', "\r\n");
    [unix, windows]
        .iter()
        .map(|text| Sha384::digest(text.as_bytes()).to_vec())
        .find(|checksum| checksum.as_slice() == was)
}

#[cfg(test)]
mod tests {
    use super::other_line_endings;
    use sha2::{Digest, Sha384};

    fn sum(text: &str) -> Vec<u8> {
        Sha384::digest(text.as_bytes()).to_vec()
    }

    #[test]
    fn a_checksum_taken_with_the_other_line_endings_is_the_same_text() {
        let unix = "CREATE TABLE a (\n    id int\n);\n";
        let windows = "CREATE TABLE a (\r\n    id int\r\n);\r\n";
        // Applied from a Windows checkout, read now from a Unix one.
        assert_eq!(
            other_line_endings(unix, &sum(unix), &sum(windows)),
            Some(sum(windows))
        );
        // And the other way round.
        assert_eq!(
            other_line_endings(windows, &sum(windows), &sum(unix)),
            Some(sum(unix))
        );
    }

    #[test]
    fn an_unchanged_or_edited_migration_is_left_to_sqlx() {
        let sql = "CREATE TABLE a (\n    id int\n);\n";
        // Unchanged: nothing to say.
        assert_eq!(other_line_endings(sql, &sum(sql), &sum(sql)), None);
        // Edited since it ran, however the lines end.
        let edited = "CREATE TABLE a (\n    id bigint\n);\n";
        assert_eq!(other_line_endings(sql, &sum(sql), &sum(edited)), None);
        let edited_windows = edited.replace('\n', "\r\n");
        assert_eq!(
            other_line_endings(sql, &sum(sql), &sum(&edited_windows)),
            None
        );
        assert_eq!(other_line_endings(sql, &sum(sql), b"not a checksum"), None);
    }
}
