//! `tinyserver auth`: the operator's side of moving a community from an identity provider to
//! passkeys. Everything here runs as the database owner through `DATABASE_URL_MIGRATE`, like
//! `identities` and `relink-identity`, and none of it needs the provider to be running.
//!
//! Files that hold claim links or member emails are made with mode 0600 where the system has
//! modes, are never overwritten, and are the only place a link is written: the log gets counts.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use clap::Subcommand;

#[derive(Subcommand)]
pub enum AuthCommand {
    /// Write every member to a file: who they are, what they can sign in with, and whether
    /// they have a passkey yet. Run it before an identity provider is removed, so there is a
    /// roster to hand claim links out against afterwards.
    ExportMembers {
        /// Where to write it. An existing file is not overwritten.
        #[arg(long)]
        out: PathBuf,
    },
    /// Make a one-time link for each chosen member that lets them set up a passkey on their
    /// existing account. They keep their id, roles, messages and device keys. The links go into
    /// a file; hand each person only their own.
    ClaimLinks {
        /// A member's id, from `auth status` or `auth export-members`. Repeat for several.
        #[arg(long = "user")]
        users: Vec<String>,
        /// Every member who has no passkey yet.
        #[arg(long)]
        all_unclaimed: bool,
        /// How long a link works, 1 to 90 days.
        #[arg(long, default_value_t = 14)]
        days: i32,
        /// Where to write the links. An existing file is not overwritten.
        #[arg(long)]
        out: PathBuf,
    },
    /// Say how many members have a passkey, and who does not. Changes nothing.
    Status,
    /// Remove the identity-provider identities of members who have a working passkey and a
    /// recovery code, so the provider can no longer sign them in. Says what it would do unless
    /// told to apply. Members without a passkey keep their identities.
    RetireOidcIdentities {
        /// Do it. Without this nothing is changed.
        #[arg(long)]
        apply: bool,
    },
}

pub async fn run(command: AuthCommand) -> anyhow::Result<()> {
    let url = std::env::var("DATABASE_URL_MIGRATE")
        .ok()
        .filter(|value| !value.is_empty())
        .context("DATABASE_URL_MIGRATE is not set")?;
    let pool = db::owner_pool(&url).await?;
    match command {
        AuthCommand::ExportMembers { out } => export_members(&pool, &out).await,
        AuthCommand::ClaimLinks {
            users,
            all_unclaimed,
            days,
            out,
        } => claim_links(&pool, &users, all_unclaimed, days, &out).await,
        AuthCommand::Status => status(&pool).await,
        AuthCommand::RetireOidcIdentities { apply } => retire(&pool, apply).await,
    }
}

/// One tab-separated field: no tab or line break, so a row stays one row.
fn field(text: &str) -> String {
    text.chars()
        .map(|c| if c == '\t' || c.is_control() { ' ' } else { c })
        .collect()
}

fn row(fields: &[&str]) -> String {
    let mut line = fields
        .iter()
        .map(|f| field(f))
        .collect::<Vec<_>>()
        .join("\t");
    line.push('\n');
    line
}

/// A new file only the owner can read. It is not overwritten: an old file may hold links that
/// are still live.
fn write_private(path: &Path, contents: &str) -> anyhow::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("{} exists or cannot be created", path.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("write {}", path.display()))?;
    file.sync_all().ok();
    #[cfg(not(unix))]
    println!(
        "This system has no file modes: make sure only you can read {}.",
        path.display()
    );
    Ok(())
}

async fn export_members(pool: &db::PgPool, out: &Path) -> anyhow::Result<()> {
    let members = db::roster(pool).await?;
    let mut text = row(&[
        "user_id",
        "name",
        "email",
        "role",
        "joined",
        "last_seen",
        "passkeys",
        "banned",
        "signs_in_with",
        "identities",
    ]);
    for member in &members {
        text.push_str(&row(&[
            &member.user_id,
            &member.display_name,
            member.email.as_deref().unwrap_or(""),
            member.role.as_deref().unwrap_or(""),
            &member.joined_at,
            member.last_seen_at.as_deref().unwrap_or(""),
            &member.passkeys.to_string(),
            if member.banned { "yes" } else { "no" },
            &member.issuers.join(","),
            &member.identities.join(";"),
        ]));
    }
    write_private(out, &text)?;
    tracing::info!(members = members.len(), "members exported");
    println!("Wrote {} members to {}.", members.len(), out.display());
    Ok(())
}

async fn claim_links(
    pool: &db::PgPool,
    users: &[String],
    all_unclaimed: bool,
    days: i32,
    out: &Path,
) -> anyhow::Result<()> {
    if users.is_empty() == !all_unclaimed {
        bail!("pass --all-unclaimed, or one or more --user <id>, and not both");
    }
    if !(1..=90).contains(&days) {
        bail!("--days is 1 to 90");
    }
    let public = std::env::var("TINYSERVER_PUBLIC_URL")
        .ok()
        .filter(|value| !value.is_empty())
        .context("TINYSERVER_PUBLIC_URL is not set")?;
    let public = public.trim_end_matches('/');
    let members = db::roster(pool).await?;
    let chosen: Vec<&db::RosterRow> = if all_unclaimed {
        members
            .iter()
            .filter(|member| member.passkeys == 0 && !member.banned && member.role.is_some())
            .collect()
    } else {
        let mut found = Vec::new();
        for id in users {
            match members.iter().find(|member| &member.user_id == id) {
                Some(member) if member.banned => bail!("{id} is banned and gets no link"),
                Some(member) => found.push(member),
                None => bail!("no member {id}"),
            }
        }
        found
    };
    if chosen.is_empty() {
        println!("Everyone already has a passkey. No links made.");
        return Ok(());
    }
    let mut text = row(&["user_id", "name", "email", "link"]);
    for member in &chosen {
        let token = db::mint_claim(pool, &member.user_id, days).await?;
        text.push_str(&row(&[
            &member.user_id,
            &member.display_name,
            member.email.as_deref().unwrap_or(""),
            &api::claim_url(public, &token),
        ]));
    }
    write_private(out, &text)?;
    // Counts only: a link is written to the file and nowhere else.
    tracing::info!(links = chosen.len(), days, "claim links made");
    println!(
        "Made {} claim links, good for {days} days, in {}.\n\
         Each works once and only for its member. Hand each person only their own, \
         by a way you trust. Delete the file when you are done.",
        chosen.len(),
        out.display()
    );
    Ok(())
}

async fn status(pool: &db::PgPool) -> anyhow::Result<()> {
    let members = db::roster(pool).await?;
    let banned = members.iter().filter(|member| member.banned).count();
    let with = members
        .iter()
        .filter(|member| !member.banned && member.passkeys > 0)
        .count();
    let without: Vec<&db::RosterRow> = members
        .iter()
        .filter(|member| !member.banned && member.passkeys == 0)
        .collect();
    println!("Members: {}", members.len());
    println!("  with a passkey: {with}");
    println!("  without one:    {}", without.len());
    println!("  banned:         {banned}");
    for member in without {
        println!(
            "  - {}  {}  (signs in with: {})",
            member.user_id,
            member.display_name,
            if member.issuers.is_empty() {
                "nothing".to_string()
            } else {
                member.issuers.join(", ")
            }
        );
    }
    Ok(())
}

async fn retire(pool: &db::PgPool, apply: bool) -> anyhow::Result<()> {
    let retired = db::retire_identities(pool, !apply).await?;
    if retired.is_empty() {
        println!("Nothing to retire.");
        return Ok(());
    }
    for item in &retired {
        println!(
            "{} {}  {} {}",
            if apply { "removed" } else { "would remove" },
            item.user_id,
            item.issuer,
            item.subject
        );
    }
    if apply {
        tracing::info!(identities = retired.len(), "identities retired");
    } else {
        println!(
            "\n{} identities would be removed. Nothing was changed. Add --apply to do it.",
            retired.len()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{field, row, write_private};

    #[test]
    fn a_field_cannot_break_its_row() {
        assert_eq!(field("a\tb\nc\rd"), "a b c d");
        assert_eq!(row(&["x", "a\tb", ""]), "x\ta b\t\n");
    }

    #[test]
    fn a_file_of_links_is_never_overwritten() {
        let dir = std::env::temp_dir().join(format!("tinyserver-auth-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("links.tsv");
        write_private(&path, "first\n").expect("first write");
        assert!(write_private(&path, "second\n").is_err());
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "first\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
