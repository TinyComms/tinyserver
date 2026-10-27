use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use db::PgPool;

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
    /// Print a single-use owner invite, good for 24 hours, when there is no owner yet.
    /// Does nothing when an owner exists.
    Bootstrap {
        /// Make the owner invite even though an owner exists. For an owner who signed in with a
        /// password before sign-in moved to an OIDC provider.
        #[arg(long)]
        owner_invite: bool,
    },
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
        Command::Bootstrap { owner_invite } => bootstrap(owner_invite).await?,
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

async fn bootstrap(force: bool) -> anyhow::Result<()> {
    let url = env_var("DATABASE_URL_MIGRATE")?;
    let pool = db::owner_pool(&url).await?;
    let Some(issued) = db::owner_invite(&pool, force)
        .await
        .context("bootstrap failed")?
    else {
        tracing::info!("an owner already exists");
        return Ok(());
    };
    tracing::info!(invite_id = %issued.id, expires_at = %issued.expires_at, "owner invite created");
    // Printed once, to the operator. The database keeps only its hash.
    let code = env_var("TINYSERVER_PUBLIC_URL")
        .ok()
        .and_then(|origin| join_code(&origin, &issued.token));
    println!();
    println!("Owner invite, single use, until {}:", issued.expires_at);
    match code {
        Some(code) => println!("  {code}"),
        None => println!("  {}", issued.token),
    }
    println!(
        "Paste it into tinyclient's \"Join a server\" and sign in. That person becomes the owner."
    );
    println!();
    Ok(())
}

/// tinyclient's invite code: `tc1.`, the server origin in hex, `.`, the invite token.
fn join_code(origin: &str, token: &str) -> Option<String> {
    let origin = origin.trim().trim_end_matches('/');
    if origin.is_empty() || origin.chars().any(char::is_whitespace) {
        return None;
    }
    let hex: String = origin.bytes().map(|byte| format!("{byte:02x}")).collect();
    Some(format!("tc1.{hex}.{token}"))
}

async fn serve() -> anyhow::Result<()> {
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
    let sign_in = sign_in().await?;
    let media = media_config(limits.call_room_max)?;
    let live = match media {
        Some(config) => {
            let (media, events) = sfu::start(config).context("start media")?;
            tracing::info!(addr = %media.addr(), transports = ?media.transports(), "media advertised");
            api::Live::with_media(pool.clone(), limits, media, events)
        }
        None => {
            tracing::warn!("TINYSERVER_PUBLIC_IP is not set; calls have no media");
            api::Live::start(pool.clone(), limits)
        }
    };
    let app = api::app(pool.clone(), live.clone(), Some(sign_in));
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

/// The OIDC providers from the environment, discovered. A provider that cannot be reached is
/// tried again for about a minute, since it may be starting next to this server; a wrong issuer
/// or setting stops the start at once.
async fn sign_in() -> anyhow::Result<api::SignIn> {
    let session_days = match env_var("TINYSERVER_SESSION_MAX_DAYS") {
        Err(_) => 30,
        Ok(value) => value
            .parse::<u32>()
            .ok()
            .filter(|days| (1..=365).contains(days))
            .context("TINYSERVER_SESSION_MAX_DAYS is not a whole number from 1 to 365")?,
    };
    let config = api::SignInConfig {
        public_url: env_var("TINYSERVER_PUBLIC_URL")?,
        session_days,
        providers: providers_from_env()?,
    };
    let mut tries = 0;
    loop {
        match api::SignIn::discover(config.clone()).await {
            Ok(sign_in) => {
                tracing::info!(
                    providers = config.providers.len(),
                    default = %sign_in.provider_name(),
                    "sign-in providers ready"
                );
                return Ok(sign_in);
            }
            Err(error) if error.transient && tries < DISCOVERY_TRIES => {
                tries += 1;
                tracing::warn!(%error, tries, "sign-in provider not ready; trying again");
                tokio::time::sleep(DISCOVERY_PAUSE).await;
            }
            Err(error) => bail!("sign-in: {error}"),
        }
    }
}

const DISCOVERY_TRIES: u32 = 12;
const DISCOVERY_PAUSE: Duration = Duration::from_secs(5);

/// `TINYSERVER_OIDC_PROVIDERS=tinyauth,google` reads `TINYSERVER_OIDC_TINYAUTH_*` and
/// `TINYSERVER_OIDC_GOOGLE_*`, first one the default. Without it, the single provider in
/// `TINYSERVER_OIDC_*` has the id `default`.
fn providers_from_env() -> anyhow::Result<Vec<api::ProviderConfig>> {
    let Ok(list) = env_var("TINYSERVER_OIDC_PROVIDERS") else {
        return Ok(vec![provider_from_env(
            "default",
            "TINYSERVER_OIDC_",
            "TINYSERVER_OIDC_PROVIDER_NAME",
        )?]);
    };
    list.split(',')
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(|id| {
            let id = id.to_ascii_lowercase();
            let prefix = format!(
                "TINYSERVER_OIDC_{}_",
                id.to_ascii_uppercase().replace('-', "_")
            );
            let name = format!("{prefix}NAME");
            provider_from_env(&id, &prefix, &name)
        })
        .collect()
}

fn provider_from_env(
    id: &str,
    prefix: &str,
    name_key: &str,
) -> anyhow::Result<api::ProviderConfig> {
    let key = |suffix: &str| format!("{prefix}{suffix}");
    let list = |suffix: &str| -> Vec<String> {
        env_var(&key(suffix))
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    Ok(api::ProviderConfig {
        id: id.to_string(),
        issuer: env_var(&key("ISSUER"))?,
        client_id: env_var(&key("CLIENT_ID"))?,
        client_secret: secret_from_env(&key("CLIENT_SECRET"))?,
        private_key_pem: match env_var(&key("PRIVATE_KEY_FILE")) {
            Err(_) => None,
            Ok(path) => Some(
                std::fs::read_to_string(&path)
                    .with_context(|| format!("read {} {path}", key("PRIVATE_KEY_FILE")))?,
            ),
        },
        private_key_id: env_var(&key("PRIVATE_KEY_ID")).ok(),
        scopes: env_var(&key("SCOPES"))
            .unwrap_or_else(|_| "openid profile email".to_string())
            .split_whitespace()
            .map(str::to_string)
            .collect(),
        name: env_var(name_key).ok(),
        internal_url: env_var(&key("INTERNAL_URL")).ok(),
        groups_claim: env_var(&key("GROUPS_CLAIM")).ok(),
        admin_groups: list("ADMIN_GROUPS"),
        member_groups: list("MEMBER_GROUPS"),
    })
}

/// `<name>_FILE`, preferred, or `<name>`. Not both. `None` when neither is set.
fn secret_from_env(name: &str) -> anyhow::Result<Option<String>> {
    let file_name = format!("{name}_FILE");
    match (env_var(name).ok(), env_var(&file_name).ok()) {
        (Some(_), Some(_)) => bail!("set {name} or {file_name}, not both"),
        (Some(secret), None) => Ok(Some(secret)),
        (None, Some(path)) => {
            let secret = std::fs::read_to_string(&path)
                .with_context(|| format!("read {file_name} {path}"))?;
            let secret = secret.trim_end().to_string();
            if secret.is_empty() {
                bail!("{file_name} {path} is empty");
            }
            Ok(Some(secret))
        }
        (None, None) => Ok(None),
    }
}

/// Media binds every interface on `TINYSERVER_MEDIA_PORT`, UDP and TCP, and advertises
/// `TINYSERVER_PUBLIC_IP` with the same port, and `TINYSERVER_LAN_IP` too when set. No public
/// address means no media. An offer may have one audio m-line per seat in a room.
/// `TINYSERVER_MEDIA_EGRESS_KBPS` caps what media uploads to everyone, in kb/s.
fn media_config(room_max: usize) -> anyhow::Result<Option<sfu::Config>> {
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
    let lan_ip = match env_var("TINYSERVER_LAN_IP") {
        Err(_) => None,
        Ok(value) => {
            let lan_ip: IpAddr = value
                .parse()
                .context("TINYSERVER_LAN_IP is not an IP address")?;
            if !lan_ip.is_ipv4() {
                bail!("TINYSERVER_LAN_IP must be IPv4 for now");
            }
            Some(lan_ip).filter(|lan_ip| *lan_ip != public_ip)
        }
    };
    let bind = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
    let mut config = sfu::Config::new(bind, public_ip);
    config.lan_ip = lan_ip;
    config.offer_audio = room_max;
    config.egress_kbps = match env_var("TINYSERVER_MEDIA_EGRESS_KBPS") {
        Err(_) => None,
        Ok(value) => Some(
            value
                .parse::<u32>()
                .ok()
                .filter(|kbps| *kbps > 0)
                .context("TINYSERVER_MEDIA_EGRESS_KBPS is not a positive whole number")?,
        ),
    };
    Ok(Some(config))
}

const DEFAULT_MEDIA_PORT: u16 = 50000;

/// How long live sockets get to take their close frame on shutdown.
const DRAIN: Duration = Duration::from_secs(5);

const SWEEP_EVERY: Duration = Duration::from_secs(10 * 60);

/// Deletes expired sessions, invites, idempotency keys, sign-ins, one-time codes, and old
/// outbox rows. The first sweep
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
                logins = swept.logins,
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

#[cfg(test)]
mod tests {
    use super::join_code;

    #[test]
    fn an_owner_invite_prints_as_a_tinyclient_code() {
        // The same as tinyclient's `pack_join`: tc1, the origin in hex, the token.
        assert_eq!(
            join_code("https://a.b/", "tok-en_1").as_deref(),
            Some("tc1.68747470733a2f2f612e62.tok-en_1")
        );
        assert_eq!(join_code("  ", "t"), None);
    }
}
