//! Local logs. One render path in front of stderr and the in-memory ring, so a field name or a
//! secret in a message cannot reach a sink the redactor would have dropped.
//!
//! `RUST_LOG` is not read. The ceiling is [`LogPolicy`], from `TINYSERVER_LOG_*`.

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use tracing::Level;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;

const REDACTED: &str = "[redacted]";
const VALUE_LIMIT: usize = 300;
const RING_LIMIT: usize = 2000;
const RING_TTL: Duration = Duration::from_secs(60 * 60);

const DENY_EXACT: &[&str] = &[
    "body",
    "content",
    "plaintext",
    "text",
    "caption",
    "filename",
    "file_name",
    "media",
    "ciphertext",
    "password",
    "authorization",
    "cookie",
    "token",
    "secret",
    "private_key",
    "invite",
    "oauth_code",
    "code",
    "verifier",
    "nonce",
    "refresh_token",
    "id_token",
    "access_token",
    "key",
    "ice_pwd",
    "fingerprint",
    "sdp",
    "email",
    "display_name",
    "subject",
    "phone",
    "phone_number",
    "vault",
    "sig",
    "detail",
];

const DENY_SUFFIX: &[&str] = &["_token", "_secret", "_password", "_cookie", "_key"];

const PREFIXED: &[&str] = &[
    "xoxc-", "xoxd-", "xoxs-", "xoxp-", "xoxb-", "xoxe-", "xoxe.", "xoxa-", "xoxr-", "xapp-",
    "mfa.",
];
const HEADERS: &[&str] = &[
    "authorization:",
    "proxy-authorization:",
    "x-skypetoken:",
    "authentication:",
    "x-ms-skypetoken:",
];
const PARAMS: &[&str] = &[
    "token=",
    "access_token=",
    "refresh_token=",
    "id_token=",
    "skypetoken=",
    "hm=",
    "tempauth=",
    "sig=",
    "x-amz-signature=",
    "x-amz-credential=",
    "x-amz-security-token=",
    "signature=",
    "code=",
    "password=",
    "pub_key=",
    "a=ice-pwd:",
    "a=fingerprint:",
];
const JSON_FIELDS: &[&str] = &[
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "skypetoken",
    "authorization",
    "password",
    "vault",
];

const FIRST_PARTY: &[&str] = &["tinyserver", "api", "sfu"];
const DEPENDENCIES: &[&str] = &["reqwest", "hyper", "h2", "sqlx", "tower", "str0m"];

#[derive(Clone, Debug)]
pub struct LogPolicy {
    operator: Level,
    ring: bool,
    export: bool,
    peer_ip: bool,
    bundle_hours: u64,
}

impl Default for LogPolicy {
    fn default() -> Self {
        Self {
            operator: Level::INFO,
            ring: true,
            export: true,
            peer_ip: false,
            bundle_hours: 24,
        }
    }
}

impl LogPolicy {
    pub fn from_env() -> Self {
        Self::policy_from_values(
            env_nonempty("TINYSERVER_LOG_LEVEL").as_deref(),
            env_nonempty("TINYSERVER_LOG_RING").as_deref(),
            env_nonempty("TINYSERVER_LOG_EXPORT").as_deref(),
            env_nonempty("TINYSERVER_LOG_PEER_IP").as_deref(),
            env_nonempty("TINYSERVER_LOG_BUNDLE_HOURS").as_deref(),
        )
    }

    /// `None` and unrecognised text are the defaults. `RUST_LOG` is not an input.
    pub fn policy_from_values(
        level: Option<&str>,
        ring: Option<&str>,
        export: Option<&str>,
        peer: Option<&str>,
        hours: Option<&str>,
    ) -> Self {
        let mut policy = Self::default();
        if let Some(level) = level.and_then(parse_level) {
            policy.operator = level;
        }
        if let Some(ring) = ring.and_then(parse_switch) {
            policy.ring = ring;
        }
        if let Some(export) = export.and_then(parse_switch) {
            policy.export = export;
        }
        if let Some(peer) = peer.and_then(parse_switch) {
            policy.peer_ip = peer;
        }
        if let Some(hours) = hours.and_then(|value| value.parse::<u64>().ok()) {
            policy.bundle_hours = hours;
        }
        policy
    }

    #[allow(dead_code)]
    pub fn operator_level(&self) -> Level {
        self.operator
    }

    #[allow(dead_code)]
    pub fn ring_enabled(&self) -> bool {
        self.ring
    }

    #[allow(dead_code)]
    pub fn export_enabled(&self) -> bool {
        self.export
    }

    pub fn peer_ip(&self) -> bool {
        self.peer_ip
    }

    pub fn bundle_ttl(&self) -> Duration {
        Duration::from_secs(self.bundle_hours.saturating_mul(60 * 60))
    }

    #[allow(dead_code)]
    pub fn set_operator_level(&mut self, level: Level) {
        self.operator = level;
    }

    #[allow(dead_code)]
    pub fn set_peer_ip(&mut self, on: bool) {
        self.peer_ip = on;
    }
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn parse_level(value: &str) -> Option<Level> {
    Some(match value.trim().to_ascii_lowercase().as_str() {
        "error" => Level::ERROR,
        "warn" => Level::WARN,
        "info" => Level::INFO,
        "debug" => Level::DEBUG,
        "trace" => Level::TRACE,
        _ => return None,
    })
}

fn parse_switch(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "on" | "1" | "true" => Some(true),
        "off" | "0" | "false" => Some(false),
        _ => None,
    }
}

fn level_name(level: Level) -> &'static str {
    match level {
        Level::ERROR => "error",
        Level::WARN => "warn",
        Level::INFO => "info",
        Level::DEBUG => "debug",
        Level::TRACE => "trace",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sink {
    Operator,
    Ring,
}

pub struct EventParts<'a> {
    pub target: &'a str,
    pub level: Level,
    pub message: &'a str,
    pub fields: &'a [(&'a str, &'a str)],
}

pub fn target_ceiling(policy: &LogPolicy, sink: Sink, target: &str) -> Level {
    if is_target(target, DEPENDENCIES) {
        return Level::WARN;
    }
    if is_target(target, FIRST_PARTY) {
        return match sink {
            Sink::Operator => policy.operator,
            Sink::Ring if policy.ring => Level::DEBUG,
            Sink::Ring => policy.operator,
        };
    }
    Level::WARN
}

fn is_target(target: &str, names: &[&str]) -> bool {
    names
        .iter()
        .any(|name| target == *name || target.starts_with(&format!("{name}::")))
}

pub fn render(policy: &LogPolicy, sink: Sink, event: &EventParts<'_>) -> Option<String> {
    let ceiling = target_ceiling(policy, sink, event.target);
    if event.level > ceiling {
        return None;
    }
    let mut line = format!(
        "{} {} {}",
        level_name(event.level),
        event.target,
        cut(&redact_value(event.message))
    );
    for (name, value) in event.fields {
        if drop_field(policy, sink, name) {
            continue;
        }
        line.push(' ');
        line.push_str(&name.to_ascii_lowercase());
        line.push('=');
        line.push_str(cut(&redact_value(value)));
    }
    Some(line)
}

fn drop_field(policy: &LogPolicy, sink: Sink, name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    if name == "peer" {
        return sink == Sink::Operator || !policy.peer_ip;
    }
    if DENY_EXACT.contains(&name.as_str()) {
        return true;
    }
    DENY_SUFFIX.iter().any(|suffix| name.ends_with(suffix))
}

fn cut(text: &str) -> &str {
    if text.len() <= VALUE_LIMIT {
        return text;
    }
    let mut end = VALUE_LIMIT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

pub fn redact_value(text: &str) -> String {
    scan_secrets(&strip_userinfo(&strip_pem(text)))
}

fn strip_pem(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN ") {
        out.push_str(&rest[..start]);
        let after = &rest[start..];
        if let Some(end_at) = after.find("-----END ") {
            let tail = &after[end_at + "-----END ".len()..];
            if let Some(close) = tail.find("-----") {
                out.push_str(REDACTED);
                rest = &tail[close + 5..];
                continue;
            }
        }
        out.push_str("-----BEGIN ");
        rest = &after["-----BEGIN ".len()..];
    }
    out.push_str(rest);
    out
}

fn strip_userinfo(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while let Some(rel) = text[at..].find("://") {
        let scheme_end = at + rel;
        out.push_str(&text[at..scheme_end + 3]);
        let auth = scheme_end + 3;
        let rest = &text[auth..];
        if let Some(at_sign) = rest.find('@') {
            let userinfo = &rest[..at_sign];
            if userinfo.contains(':')
                && !userinfo.contains('/')
                && !userinfo.contains(char::is_whitespace)
            {
                out.push_str(REDACTED);
                out.push('@');
                at = auth + at_sign + 1;
                continue;
            }
        }
        at = auth;
    }
    out.push_str(&text[at..]);
    out
}

fn scan_secrets(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while at < text.len() {
        let boundary = text[..at]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '-' && c != '.');
        if boundary {
            if let Some((keep, skip)) = secret_at(&text[at..]) {
                out.push_str(&text[at..at + keep]);
                out.push_str(REDACTED);
                at += skip;
                continue;
            }
        }
        let c = text[at..].chars().next().unwrap_or(' ');
        out.push(c);
        at += c.len_utf8();
    }
    out
}

fn secret_at(text: &str) -> Option<(usize, usize)> {
    if let Some(prefix) = PREFIXED.iter().find(|prefix| text.starts_with(**prefix)) {
        let end = value_end(text, prefix.len());
        return (end > prefix.len()).then_some((0, end));
    }
    if let Some(header) = HEADERS
        .iter()
        .find(|header| starts_with_ignore_case(text, header))
    {
        let keep = header.len() + text[header.len()..].len()
            - text[header.len()..].trim_start_matches([' ', '\t']).len();
        let mut from = keep;
        let word = value_end(text, from);
        if word < text.len()
            && text[word..].starts_with(' ')
            && text[from..word].chars().all(|c| c.is_ascii_alphabetic())
        {
            from = word + 1;
        }
        let end = value_end(text, from);
        return (end > keep).then_some((keep, end));
    }
    if starts_with_ignore_case(text, "bearer ") {
        let end = value_end(text, "bearer ".len());
        return (end > "bearer ".len()).then_some((0, end));
    }
    if let Some(param) = PARAMS
        .iter()
        .find(|param| starts_with_ignore_case(text, param))
    {
        let end = value_end(text, param.len());
        return (end > param.len()).then_some((param.len(), end));
    }
    if let Some(rest) = text.strip_prefix('"') {
        for field in JSON_FIELDS {
            if !starts_with_ignore_case(rest, field) || !rest[field.len()..].starts_with('"') {
                continue;
            }
            let after = &rest[field.len() + 1..];
            let value = after
                .trim_start()
                .strip_prefix(':')?
                .trim_start()
                .strip_prefix('"')?;
            let keep = text.len() - value.len();
            let mut escaped = false;
            let close = value.find(|c: char| {
                let close = c == '"' && !escaped;
                escaped = c == '\\' && !escaped;
                close
            })?;
            return (close > 0).then_some((keep, keep + close));
        }
    }
    jwt_at(text)
        .or_else(|| dotted_token(text))
        .map(|end| (0, end))
}

fn jwt_at(text: &str) -> Option<usize> {
    if !text.starts_with("eyJ") {
        return None;
    }
    dotted_parts(text, 10, 4, 4)
}

fn dotted_token(text: &str) -> Option<usize> {
    dotted_parts(text, 18, 5, 20)
}

fn dotted_parts(text: &str, a: usize, b: usize, c: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut at = 0;
    let mut parts = [0usize; 3];
    for (ix, part) in parts.iter_mut().enumerate() {
        let start = at;
        while at < bytes.len() && base64url(bytes[at]) {
            at += 1;
        }
        *part = at - start;
        if ix < 2 {
            if bytes.get(at) != Some(&b'.') {
                return None;
            }
            at += 1;
        }
    }
    let ends_clean = bytes
        .get(at)
        .is_none_or(|ch| !base64url(*ch) && *ch != b'.');
    (parts[0] >= a && parts[1] >= b && parts[2] >= c && ends_clean).then_some(at)
}

fn starts_with_ignore_case(text: &str, prefix: &str) -> bool {
    text.len() >= prefix.len()
        && text.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

fn value_end(text: &str, from: usize) -> usize {
    text[from..]
        .find(|c: char| {
            c.is_whitespace()
                || matches!(
                    c,
                    '&' | '"' | '\'' | ')' | ',' | ';' | '<' | '>' | ']' | '}'
                )
        })
        .map_or(text.len(), |end| from + end)
}

fn base64url(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'-'
}

pub fn data_dir() -> PathBuf {
    if let Some(dir) = env_nonempty("TINYSERVER_DATA_DIR") {
        return PathBuf::from(dir);
    }
    let system = PathBuf::from("/var/lib/tinyserver");
    if system.is_dir() {
        return system;
    }
    PathBuf::from("tinyserver-data")
}

pub fn write_owner_invite(dir: &Path, token_line: &str) -> io::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let path = dir.join("owner-invite");
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)?;
    file.write_all(token_line.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(path)
}

pub fn invite_status(result: &io::Result<PathBuf>) -> String {
    match result {
        Ok(path) => format!("owner invite written to {}", path.display()),
        Err(error) => format!("owner invite was not written: {}", error.kind()),
    }
}

pub fn remove_owner_invite(dir: &Path) {
    let _ = fs::remove_file(dir.join("owner-invite"));
}

#[derive(Default)]
pub struct Ring {
    lines: VecDeque<(SystemTime, String)>,
}

impl Ring {
    pub fn push(&mut self, now: SystemTime, line: String) {
        self.lines
            .retain(|(then, _)| now.duration_since(*then).unwrap_or_default() < RING_TTL);
        self.lines.push_back((now, line));
        while self.lines.len() > RING_LIMIT {
            self.lines.pop_front();
        }
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    pub fn text(&self) -> String {
        let mut out = String::new();
        for (_, line) in &self.lines {
            out.push_str(line);
            out.push('\n');
        }
        out
    }
}

pub fn export_lines(
    dir: &Path,
    lines: &str,
    enabled: bool,
    now: SystemTime,
) -> io::Result<Option<PathBuf>> {
    if !enabled {
        return Ok(None);
    }
    fs::create_dir_all(dir)?;
    let stamp = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let path = dir.join(format!("bundle-{stamp}.log"));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)?;
    file.write_all(lines.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(Some(path))
}

pub fn sweep_dir(dir: &Path, ttl: Duration, now: SystemTime) -> io::Result<usize> {
    if !dir.is_dir() {
        return Ok(0);
    }
    let mut removed = 0;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with("bundle-") || !name.ends_with(".log") {
            continue;
        }
        let age = bundle_age(name, now).or_else(|| {
            let modified = entry.metadata().ok()?.modified().ok()?;
            now.duration_since(modified).ok()
        });
        if age.is_some_and(|age| age > ttl) {
            fs::remove_file(entry.path())?;
            removed += 1;
        }
    }
    Ok(removed)
}

fn bundle_age(name: &str, now: SystemTime) -> Option<Duration> {
    let secs = name
        .strip_prefix("bundle-")?
        .strip_suffix(".log")?
        .parse::<u64>()
        .ok()?;
    now.duration_since(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
        .ok()
}

struct Recorder {
    message: String,
    fields: Vec<(String, String)>,
}

impl Recorder {
    fn new() -> Self {
        Self {
            message: String::new(),
            fields: Vec::new(),
        }
    }
}

impl tracing::field::Visit for Recorder {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let mut text = format!("{value:?}");
        if text.len() >= 2 && text.starts_with('"') && text.ends_with('"') {
            text = text[1..text.len() - 1].to_string();
        }
        if field.name() == "message" {
            self.message = text;
        } else {
            self.fields.push((field.name().to_string(), text));
        }
    }
}

struct RedactLayer {
    policy: LogPolicy,
    sink: Sink,
    ring: Arc<Mutex<Ring>>,
    write: bool,
}

impl<S> Layer<S> for RedactLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut recorder = Recorder::new();
        event.record(&mut recorder);
        let borrowed: Vec<(&str, &str)> = recorder
            .fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let parts = EventParts {
            target: event.metadata().target(),
            level: *event.metadata().level(),
            message: &recorder.message,
            fields: &borrowed,
        };
        let Some(line) = render(&self.policy, self.sink, &parts) else {
            return;
        };
        if self.write {
            let _ = writeln!(io::stderr(), "{line}");
        } else if let Ok(mut ring) = self.ring.lock() {
            ring.push(SystemTime::now(), line);
        }
    }
}

pub struct LogGuard {
    /// Read when a debug bundle is exported. On Unix that is `SIGUSR1`.
    #[cfg_attr(not(unix), allow(dead_code))]
    ring: Arc<Mutex<Ring>>,
    policy: LogPolicy,
}

impl LogGuard {
    /// Writes the ring when export is on. Unix calls this from `SIGUSR1`.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub fn export_bundle(&self) -> io::Result<Option<PathBuf>> {
        if !self.policy.export || !self.policy.ring {
            return Ok(None);
        }
        let text = self.ring.lock().map(|ring| ring.text()).unwrap_or_default();
        export_lines(&data_dir().join("logs"), &text, true, SystemTime::now())
    }

    pub fn sweep_bundles(&self) -> io::Result<usize> {
        sweep_dir(
            &data_dir().join("logs"),
            self.policy.bundle_ttl(),
            SystemTime::now(),
        )
    }
}

fn filter_for(policy: &LogPolicy) -> EnvFilter {
    let enable = if policy.ring && policy.operator < Level::DEBUG {
        Level::DEBUG
    } else {
        policy.operator
    };
    let mut directive = format!(
        "warn,tinyserver={},api={},sfu={}",
        level_name(enable),
        level_name(enable),
        level_name(enable)
    );
    for name in DEPENDENCIES {
        directive.push_str(&format!(",{name}=warn"));
    }
    EnvFilter::new(directive)
}

/// Installs the process subscriber. Call once, before other work. A second call is ignored.
pub fn install(policy: LogPolicy) -> LogGuard {
    let ring = Arc::new(Mutex::new(Ring::default()));
    let operator = RedactLayer {
        policy: policy.clone(),
        sink: Sink::Operator,
        ring: Arc::clone(&ring),
        write: true,
    };
    let memory = RedactLayer {
        policy: policy.clone(),
        sink: Sink::Ring,
        ring: Arc::clone(&ring),
        write: false,
    };
    let rust_log = env_nonempty("RUST_LOG").is_some();
    let _ = tracing_subscriber::registry()
        .with(filter_for(&policy))
        .with(operator)
        .with(memory)
        .try_init();
    if rust_log {
        tracing::info!("RUST_LOG is ignored; set TINYSERVER_LOG_LEVEL");
    }
    sfu::set_peer_ips(policy.peer_ip());
    #[cfg(unix)]
    {
        let ring = Arc::clone(&ring);
        let policy = policy.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let Ok(mut stream) = signal(SignalKind::user_defined1()) else {
                return;
            };
            loop {
                if stream.recv().await.is_none() {
                    return;
                }
                let guard = LogGuard {
                    ring: Arc::clone(&ring),
                    policy: policy.clone(),
                };
                match guard.export_bundle() {
                    Ok(Some(path)) => {
                        tracing::info!(path = %path.display(), "debug bundle written")
                    }
                    Ok(None) => tracing::info!("debug bundle not written"),
                    Err(error) => tracing::warn!(%error, "debug bundle was not written"),
                }
            }
        });
    }
    LogGuard { ring, policy }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line_of(value: Option<String>) -> String {
        match value {
            Some(value) => value,
            None => panic!("expected a log line"),
        }
    }

    fn io_of<T>(value: io::Result<T>) -> T {
        match value {
            Ok(value) => value,
            Err(error) => panic!("io error: {error}"),
        }
    }

    #[test]
    fn drops_body_and_access_token_keeps_user_id() {
        let policy = LogPolicy::default();
        let event = EventParts {
            target: "api::messages",
            level: Level::INFO,
            message: "message failed",
            fields: &[
                ("body", "hello"),
                ("access_token", "z"),
                ("user_id", "018f"),
            ],
        };
        let line = line_of(render(&policy, Sink::Operator, &event));
        assert!(!line.contains("hello"));
        assert!(!line.contains("access_token"));
        assert!(line.contains("user_id=018f"));
    }

    #[test]
    fn redacts_bearer_pem_jwt_ice_and_userinfo() {
        let policy = LogPolicy::default();
        let message = "Bearer abcdef -----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY----- eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaaa.bbbb a=ice-pwd:secret https://user:pass@host/ xoxc-123";
        let event = EventParts {
            target: "api",
            level: Level::WARN,
            message,
            fields: &[("error", "code=abc")],
        };
        let line = line_of(render(&policy, Sink::Operator, &event));
        for raw in [
            "abcdef",
            "-----BEGIN",
            "eyJhbGci",
            "ice-pwd:secret",
            "user:pass",
            "xoxc-123",
            "code=abc",
        ] {
            assert!(!line.contains(raw), "{raw} still in {line}");
        }
        assert!(line.contains("[redacted]"));
    }

    #[test]
    fn default_ceiling_and_dependency_cap() {
        let policy = LogPolicy::default();
        let debug = EventParts {
            target: "api",
            level: Level::DEBUG,
            message: "detail",
            fields: &[],
        };
        assert!(render(&policy, Sink::Operator, &debug).is_none());
        assert!(render(&policy, Sink::Ring, &debug).is_some());
        let mut trace = policy.clone();
        trace.set_operator_level(Level::TRACE);
        let reqwest = EventParts {
            target: "reqwest::connect",
            level: Level::DEBUG,
            message: "body",
            fields: &[],
        };
        let ice = EventParts {
            target: "str0m::ice",
            level: Level::DEBUG,
            message: "addr",
            fields: &[],
        };
        assert!(render(&trace, Sink::Operator, &reqwest).is_none());
        assert!(render(&trace, Sink::Ring, &ice).is_none());
    }

    #[test]
    fn peer_is_operator_blind_and_ring_gated() {
        let event = EventParts {
            target: "sfu",
            level: Level::DEBUG,
            message: "media",
            fields: &[("peer", "203.0.113.5:50000")],
        };
        let off = LogPolicy::default();
        assert!(!line_of(render(&off, Sink::Ring, &event)).contains("peer="));
        let mut on = off.clone();
        on.set_peer_ip(true);
        on.set_operator_level(Level::DEBUG);
        let operator = line_of(render(&on, Sink::Operator, &event));
        assert!(!operator.contains("203.0.113.5"));
        assert!(line_of(render(&on, Sink::Ring, &event)).contains("peer=203.0.113.5:50000"));
    }

    #[test]
    fn key_id_survives_and_long_values_cut_at_300() {
        let policy = LogPolicy::default();
        let long = "a".repeat(500);
        let event = EventParts {
            target: "api",
            level: Level::INFO,
            message: "ok",
            fields: &[("key_id", "kid"), ("error", &long)],
        };
        let line = line_of(render(&policy, Sink::Operator, &event));
        assert!(line.contains("key_id=kid"));
        let error = match line.split("error=").nth(1) {
            Some(error) => error,
            None => panic!("expected an error field"),
        };
        assert_eq!(error.len(), 300);
    }

    #[test]
    fn policy_values_ignore_garbage_and_rust_log() {
        let debug = LogPolicy::policy_from_values(Some("debug"), None, None, None, None);
        assert_eq!(debug.operator_level(), Level::DEBUG);
        let garbage = LogPolicy::policy_from_values(
            Some("nope"),
            Some("nope"),
            Some("nope"),
            Some("nope"),
            Some("nope"),
        );
        assert_eq!(garbage.operator_level(), Level::INFO);
        assert!(garbage.ring_enabled());
        assert!(garbage.export_enabled());
        assert!(!garbage.peer_ip());
        let off = LogPolicy::policy_from_values(
            Some("info"),
            Some("off"),
            Some("off"),
            Some("on"),
            Some("1"),
        );
        assert!(!off.ring_enabled());
        assert!(!off.export_enabled());
        assert!(off.peer_ip());
        assert_eq!(off.bundle_ttl(), Duration::from_secs(3600));
    }

    #[test]
    fn invite_file_holds_the_token_and_the_status_line_does_not() {
        let dir = std::env::temp_dir().join(format!("tiny-invite-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        io_of(fs::create_dir_all(&dir));
        let token = "tc1.example.secret-token";
        let written = write_owner_invite(
            &dir,
            &format!("Link: https://tinyclient.io/invite#{token}\nToken: {token}\n"),
        );
        let status = invite_status(&written);
        assert!(!status.contains(token));
        assert!(io_of(fs::read_to_string(io_of(written))).contains(token));
        let failed: io::Result<PathBuf> =
            Err(io::Error::new(io::ErrorKind::PermissionDenied, token));
        let failure = invite_status(&failed);
        assert!(!failure.contains(token));
        assert!(failure.contains("permission denied"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn export_off_writes_nothing() {
        let dir = std::env::temp_dir().join(format!("tiny-bundle-off-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = io_of(export_lines(
            &dir,
            "info api hello\n",
            false,
            SystemTime::now(),
        ));
        assert!(path.is_none());
        assert!(!dir.exists());
    }

    #[test]
    fn export_then_sweep() {
        let dir = std::env::temp_dir().join(format!("tiny-bundle-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let now = SystemTime::now();
        let old = match now.checked_sub(Duration::from_secs(25 * 60 * 60)) {
            Some(old) => old,
            None => panic!("clock went backwards"),
        };
        let path = match io_of(export_lines(&dir, "info api hello\n", true, old)) {
            Some(path) => path,
            None => panic!("old bundle"),
        };
        let fresh = match io_of(export_lines(&dir, "info api fresh\n", true, now)) {
            Some(path) => path,
            None => panic!("fresh bundle"),
        };
        let removed = io_of(sweep_dir(&dir, Duration::from_secs(24 * 60 * 60), now));
        assert_eq!(removed, 1);
        assert!(!path.exists());
        assert!(fresh.exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
