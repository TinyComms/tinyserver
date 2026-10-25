use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use db::{DbError, PgPool};

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
    /// Serve HTTP and the live socket, and media when `TINYSERVER_PUBLIC_IP` is set.
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
    let pool = db::owner_pool(&url).await?;
    // Checked first, so a later start needs none of the owner variables.
    if db::owner_exists(&pool).await? {
        bail!("an owner already exists");
    }
    let email = env_var("TINYSERVER_OWNER_EMAIL")?;
    let name = env_var("TINYSERVER_OWNER_NAME")?;
    let password = env_var("TINYSERVER_OWNER_PASSWORD")?;
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
    let media = media_config()?;
    let url = env_var("DATABASE_URL")?;
    let bind: SocketAddr = env_var("BIND")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()
        .context("BIND is not a socket address")?;
    let pool = db::runtime_pool(&url).await?;
    let defaults = api::Limits::default();
    let limits = api::Limits {
        call_room_max: env_count("TINYSERVER_CALL_ROOM_MAX", defaults.call_room_max)?,
        call_server_max: env_count("TINYSERVER_CALL_SERVER_MAX", defaults.call_server_max)?,
        ..defaults
    };
    let live = match media {
        Some(config) => {
            let (media, events) = sfu::start(config).context("start media")?;
            tracing::info!(addr = %media.addr(), "media advertised");
            api::Live::with_media(pool.clone(), limits, media, events)
        }
        None => {
            tracing::warn!("TINYSERVER_PUBLIC_IP is not set; calls have no media");
            api::Live::start(pool.clone(), limits)
        }
    };
    let app = api::app(pool.clone(), live.clone());
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind {bind}"))?;
    tracing::info!(%bind, "listening");
    let sweeper = tokio::spawn(sweep_every(pool, SWEEP_EVERY));
    let served = axum_serve(listener, app, live.clone()).await;
    sweeper.abort();
    live.close();
    if !live.closed(DRAIN).await {
        tracing::warn!(sockets = live.sockets(), "live sockets still open at exit");
    }
    served
}

/// Media binds every interface on `TINYSERVER_MEDIA_PORT` and advertises
/// `TINYSERVER_PUBLIC_IP` with the same port. No public address means no media.
fn media_config() -> anyhow::Result<Option<sfu::Config>> {
    let Ok(public) = env_var("TINYSERVER_PUBLIC_IP") else {
        return Ok(None);
    };
    let public_ip: IpAddr = public
        .parse()
        .context("TINYSERVER_PUBLIC_IP is not an IP address")?;
    if !public_ip.is_ipv4() {
        bail!("TINYSERVER_PUBLIC_IP must be IPv4 for now");
    }
    let port = match env_var("TINYSERVER_MEDIA_PORT") {
        Err(_) => DEFAULT_MEDIA_PORT,
        Ok(value) => value
            .parse::<u16>()
            .ok()
            .filter(|port| *port > 0)
            .context("TINYSERVER_MEDIA_PORT is not a port number")?,
    };
    let bind = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
    Ok(Some(sfu::Config::new(bind, public_ip)))
}

const DEFAULT_MEDIA_PORT: u16 = 50000;

/// How long live sockets get to take their close frame on shutdown.
const DRAIN: Duration = Duration::from_secs(5);

const SWEEP_EVERY: Duration = Duration::from_secs(10 * 60);

/// Deletes expired sessions, invites, idempotency keys, and old outbox rows. The first sweep
/// runs at start.
async fn sweep_every(pool: PgPool, period: Duration) {
    let mut ticks = tokio::time::interval(period);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticks.tick().await;
        match db::sweep(&pool).await {
            Ok(swept) if swept.total() > 0 => tracing::info!(
                sessions = swept.sessions,
                invites = swept.invites,
                idempotency_keys = swept.idempotency_keys,
                events = swept.events,
                "expired rows deleted"
            ),
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "sweep failed"),
        }
    }
}

/// On a signal, live sockets get `1012 restart` first, so graceful shutdown is not held open
/// by them.
async fn axum_serve(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    live: api::Live,
) -> anyhow::Result<()> {
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown().await;
            live.close();
        })
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

/// An empty value counts as unset. Compose passes `${NAME:-}` through as empty.
/// A positive count from the environment, or `default` when unset.
fn env_count(name: &str, default: usize) -> anyhow::Result<usize> {
    match env_var(name) {
        Err(_) => Ok(default),
        Ok(value) => value
            .parse::<usize>()
            .ok()
            .filter(|count| *count > 0)
            .with_context(|| format!("{name} is not a positive whole number")),
    }
}

fn env_var(name: &str) -> anyhow::Result<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .with_context(|| format!("{name} is not set"))
}
