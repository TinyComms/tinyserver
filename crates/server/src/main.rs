use std::net::SocketAddr;

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use db::DbError;

#[derive(Parser)]
#[command(name = "tinyserver", about = "Self-hosted voice and video server")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Apply SQL migrations as the database owner.
    Migrate,
    /// Create the first owner. Refuses when one already exists.
    Bootstrap,
    /// Serve HTTP. Media is not started.
    Serve,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match Cli::parse().command {
        Command::Migrate => migrate().await?,
        Command::Bootstrap => bootstrap().await?,
        Command::Serve => serve().await?,
    }
    Ok(())
}

async fn migrate() -> anyhow::Result<()> {
    let url = env_var("DATABASE_URL_MIGRATE")?;
    let pool = db::owner_pool(&url).await?;
    db::migrate(&pool).await?;
    tracing::info!("migrations applied");
    Ok(())
}

async fn bootstrap() -> anyhow::Result<()> {
    let url = env_var("DATABASE_URL_MIGRATE")?;
    let email = env_var("TINYSERVER_OWNER_EMAIL")?;
    let name = env_var("TINYSERVER_OWNER_NAME")?;
    let password = env_var("TINYSERVER_OWNER_PASSWORD")?;
    let pool = db::owner_pool(&url).await?;
    match db::bootstrap_owner(&pool, &email, &name, &password).await {
        Ok(()) => {
            tracing::info!(email = %email.trim(), "owner created");
            Ok(())
        }
        Err(DbError::OwnerExists) => bail!("an owner already exists"),
        Err(error) => Err(error).context("bootstrap failed"),
    }
}

async fn serve() -> anyhow::Result<()> {
    if sfu::running() {
        bail!("media plane was not supposed to start in this build");
    }
    let url = env_var("DATABASE_URL")?;
    let bind: SocketAddr = env_var("BIND")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()
        .context("BIND is not a socket address")?;
    let pool = db::runtime_pool(&url).await?;
    let app = api::router(pool);
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind {bind}"))?;
    tracing::info!(%bind, "listening");
    axum_serve(listener, app).await
}

async fn axum_serve(listener: tokio::net::TcpListener, app: axum::Router) -> anyhow::Result<()> {
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await
        .context("server stopped")?;
    Ok(())
}

/// Resolves on SIGINT or SIGTERM. `docker stop` sends SIGTERM to PID 1.
async fn shutdown() {
    let interrupt = async {
        if tokio::signal::ctrl_c().await.is_err() {
            tracing::warn!("failed to listen for ctrl-c");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(error) => {
                tracing::warn!(%error, "failed to listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => tracing::info!("interrupt received"),
        () = terminate => tracing::info!("terminate received"),
    }
}

fn env_var(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("{name} is not set"))
}
