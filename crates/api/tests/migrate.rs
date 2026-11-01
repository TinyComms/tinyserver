//! A database migrated by a build whose checkout converted line endings still migrates with a
//! build whose checkout did not, and a migration that was really edited is still refused.

mod common;

use common::run;
use sha2::{Digest, Sha384};

fn checksum(text: &str) -> Vec<u8> {
    Sha384::digest(text.as_bytes()).to_vec()
}

#[tokio::test]
async fn a_database_migrated_with_windows_line_endings_migrates_again() {
    run(|db| async move {
        // Pretend migrations 8 to 10 were applied from copies with Windows line endings: the
        // checksum recorded is that of the same text with them.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../db/migrations");
        for (version, name) in [
            (8_i64, "0008_messages.sql"),
            (9, "0009_upload_limits.sql"),
            (10, "0010_user_avatars.sql"),
        ] {
            let text = std::fs::read_to_string(dir.join(name))
                .expect("migration")
                .replace("\r\n", "\n");
            let windows = checksum(&text.replace('\n', "\r\n"));
            assert_ne!(windows, checksum(&text), "{name} has no line breaks");
            sqlx::query("UPDATE _sqlx_migrations SET checksum = $2 WHERE version = $1")
                .bind(version)
                .bind(windows)
                .execute(&db.owner)
                .await
                .expect("record");
        }
        db::migrate(&db.owner).await.expect("migrates again");

        // The database was not rewritten to say otherwise: what was recorded is still recorded.
        let recorded: Vec<u8> =
            sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version = 8")
                .fetch_one(&db.owner)
                .await
                .expect("checksum");
        let text = std::fs::read_to_string(dir.join("0008_messages.sql"))
            .expect("migration")
            .replace("\r\n", "\n");
        assert_eq!(recorded, checksum(&text.replace('\n', "\r\n")));

        // A migration that was really changed after it ran is still refused.
        sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = 9")
            .bind(checksum("something else entirely"))
            .execute(&db.owner)
            .await
            .expect("tamper");
        let refused = db::migrate(&db.owner).await;
        assert!(refused.is_err(), "an edited migration was accepted");
    })
    .await;
}
