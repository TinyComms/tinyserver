//! clamd plus three yara-x rules, behind [`db::ScanEngine`].
//!
//! `TINYSERVER_CLAMD_SOCKET` is `host:port` (TCP) or, on Unix, a filesystem path. The rules
//! compile once. A yara hit is blocked before clamd is asked. clamd down, a socket timeout, or
//! any IO error is unavailable, including when yara is clean.

use std::sync::{Arc, OnceLock};

use db::{FakeEngine, ScanEngine, ScanVerdict};

const RULES: &str = r#"
rule lnk_header {
  condition:
    filesize >= 76 and uint32(0) == 0x4C
}

rule html_prefix {
  strings:
    $html = "<html" nocase
  condition:
    $html and @html < 512
}

rule vba_stream {
  strings:
    $vba = "_VBA_PROJECT"
  condition:
    $vba
}
"#;

/// Why the process will not serve.
#[derive(Debug)]
pub enum ScanBootError {
    /// No socket, and the test scanner is not allowed.
    Unconfigured,
    /// A filesystem path where only `host:port` works.
    NeedsTcp(String),
    /// The built-in yara rules did not compile.
    Rules(String),
}

impl std::fmt::Display for ScanBootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unconfigured => f.write_str(
                "TINYSERVER_CLAMD_SOCKET is not set and TINYSERVER_ALLOW_FAKE_SCAN is not 1",
            ),
            Self::NeedsTcp(socket) => write!(
                f,
                "TINYSERVER_CLAMD_SOCKET must be host:port on Windows, not {socket}"
            ),
            Self::Rules(error) => write!(f, "yara rules failed to compile: {error}"),
        }
    }
}

impl std::error::Error for ScanBootError {}

enum Endpoint {
    Tcp(String),
    #[cfg(unix)]
    Unix(String),
}

pub struct ClamdEngine {
    endpoint: Endpoint,
}

impl ClamdEngine {
    fn open(socket: &str) -> Result<Self, ScanBootError> {
        let endpoint = endpoint(socket)?;
        let _ = rules()?;
        Ok(Self { endpoint })
    }

    fn query(&self, bytes: &[u8]) -> std::io::Result<Vec<u8>> {
        match &self.endpoint {
            Endpoint::Tcp(addr) => {
                let tcp = clamav_client::Tcp {
                    host_address: addr.as_str(),
                };
                clamav_client::scan_buffer(bytes, tcp, None)
            }
            #[cfg(unix)]
            Endpoint::Unix(path) => {
                let socket = clamav_client::Socket {
                    socket_path: path.as_str(),
                };
                clamav_client::scan_buffer(bytes, socket, None)
            }
        }
    }
}

impl ScanEngine for ClamdEngine {
    fn scan(&self, bytes: &[u8], _mime: &str, _kind: &str) -> ScanVerdict {
        let compiled = match rules() {
            Ok(compiled) => compiled,
            Err(_) => return ScanVerdict::Unavailable,
        };
        match yara_hit(compiled, bytes) {
            Some(true) => return ScanVerdict::Blocked { reason: "yara" },
            Some(false) => {}
            None => return ScanVerdict::Unavailable,
        }
        clamd_verdict(self.query(bytes))
    }
}

/// No socket and `allow_fake` is an error. No socket and `allow_fake` is [`FakeEngine`].
/// A socket is clamd and yara, including when the fake scanner would also be allowed.
pub fn scan_engine(
    socket: Option<&str>,
    allow_fake: bool,
) -> Result<Arc<dyn ScanEngine>, ScanBootError> {
    let socket = socket.map(str::trim).filter(|value| !value.is_empty());
    let Some(socket) = socket else {
        return if allow_fake {
            Ok(Arc::new(FakeEngine))
        } else {
            Err(ScanBootError::Unconfigured)
        };
    };
    Ok(Arc::new(ClamdEngine::open(socket)?))
}

/// `TINYSERVER_CLAMD_SOCKET` selects clamd. `TINYSERVER_ALLOW_FAKE_SCAN=1` allows [`FakeEngine`]
/// only when that socket is unset.
pub fn engine_from_env() -> Result<Arc<dyn ScanEngine>, ScanBootError> {
    let socket = std::env::var("TINYSERVER_CLAMD_SOCKET").ok();
    let allow_fake = std::env::var("TINYSERVER_ALLOW_FAKE_SCAN")
        .ok()
        .is_some_and(|value| value.trim() == "1");
    scan_engine(socket.as_deref(), allow_fake)
}

fn rules() -> Result<&'static yara_x::Rules, ScanBootError> {
    static COMPILED: OnceLock<yara_x::Rules> = OnceLock::new();
    if let Some(compiled) = COMPILED.get() {
        return Ok(compiled);
    }
    let compiled = compile()?;
    Ok(COMPILED.get_or_init(|| compiled))
}

fn compile() -> Result<yara_x::Rules, ScanBootError> {
    let mut compiler = yara_x::Compiler::new();
    compiler
        .add_source(RULES)
        .map_err(|error| ScanBootError::Rules(error.to_string()))?;
    Ok(compiler.build())
}

fn yara_hit(rules: &yara_x::Rules, bytes: &[u8]) -> Option<bool> {
    let mut scanner = yara_x::Scanner::new(rules);
    match scanner.scan(bytes) {
        Ok(results) => Some(results.matching_rules().next().is_some()),
        Err(_) => None,
    }
}

fn clamd_verdict(response: std::io::Result<Vec<u8>>) -> ScanVerdict {
    let Ok(response) = response else {
        return ScanVerdict::Unavailable;
    };
    let Ok(text) = std::str::from_utf8(&response) else {
        return ScanVerdict::Unavailable;
    };
    // zINSTREAM ends the status word with a NUL: `stream: OK` or `stream: Name FOUND`.
    let text = text.trim_end_matches('\0').trim();
    if text.ends_with("FOUND") {
        ScanVerdict::Blocked { reason: "clamd" }
    } else if text.ends_with("OK") {
        ScanVerdict::Clean
    } else {
        ScanVerdict::Unavailable
    }
}

fn endpoint(socket: &str) -> Result<Endpoint, ScanBootError> {
    if let Some(addr) = tcp_address(socket) {
        return Ok(Endpoint::Tcp(addr));
    }
    #[cfg(unix)]
    {
        Ok(Endpoint::Unix(socket.to_string()))
    }
    #[cfg(not(unix))]
    {
        Err(ScanBootError::NeedsTcp(socket.to_string()))
    }
}

/// `host:port`, or `[ipv6]:port`. Anything else is a filesystem path.
fn tcp_address(value: &str) -> Option<String> {
    if let Some(host) = value.strip_prefix('[') {
        let (host, port) = host.split_once("]:")?;
        let port = tcp_port(port)?;
        if host.is_empty() {
            return None;
        }
        return Some(format!("[{host}]:{port}"));
    }
    let (host, port) = value.rsplit_once(':')?;
    if host.is_empty() || host.contains('/') || host.contains('\\') || host.contains(':') {
        return None;
    }
    let port = tcp_port(port)?;
    Some(format!("{host}:{port}"))
}

fn tcp_port(value: &str) -> Option<u16> {
    let port = value.parse().ok()?;
    (port > 0).then_some(port)
}

#[cfg(test)]
mod tests {
    use super::{clamd_verdict, scan_engine, ScanBootError};
    use db::ScanVerdict;

    #[test]
    fn no_socket_without_the_fake_flag_is_an_error() {
        let Err(error) = scan_engine(None, false) else {
            panic!("expected the boot error");
        };
        assert!(matches!(error, ScanBootError::Unconfigured));
        let message = error.to_string();
        assert!(message.contains("TINYSERVER_CLAMD_SOCKET"), "{message}");
    }

    #[test]
    fn no_socket_with_the_fake_flag_scans_plain_bytes_clean() {
        let engine = scan_engine(None, true).expect("fake engine");
        assert!(matches!(
            engine.scan(b"hello", "text/plain", "file"),
            ScanVerdict::Clean
        ));
    }

    #[test]
    fn yara_blocks_and_a_clean_file_is_unavailable_when_clamd_is_down() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let engine = scan_engine(Some(&format!("127.0.0.1:{port}")), true).expect("clamd engine");

        let mut lnk = vec![0_u8; 76];
        lnk[..4].copy_from_slice(&[0x4c, 0x00, 0x00, 0x00]);
        assert!(matches!(
            engine.scan(&lnk, "application/octet-stream", "file"),
            ScanVerdict::Blocked { reason: "yara" }
        ));

        let mut short = vec![0_u8; 75];
        short[..4].copy_from_slice(&[0x4c, 0x00, 0x00, 0x00]);
        assert!(matches!(
            engine.scan(&short, "application/octet-stream", "file"),
            ScanVerdict::Unavailable
        ));

        assert!(matches!(
            engine.scan(b"<HTML", "text/plain", "file"),
            ScanVerdict::Blocked { reason: "yara" }
        ));

        let mut edge = vec![b'b'; 516];
        edge[511..516].copy_from_slice(b"<html");
        assert!(matches!(
            engine.scan(&edge, "text/plain", "file"),
            ScanVerdict::Blocked { reason: "yara" }
        ));

        let mut late = vec![b'a'; 520];
        late[512..517].copy_from_slice(b"<html");
        assert!(matches!(
            engine.scan(&late, "text/plain", "file"),
            ScanVerdict::Unavailable
        ));

        assert!(matches!(
            engine.scan(
                b"doc _VBA_PROJECT stream",
                "application/octet-stream",
                "file"
            ),
            ScanVerdict::Blocked { reason: "yara" }
        ));
        assert!(matches!(
            engine.scan(
                b"doc _vba_project stream",
                "application/octet-stream",
                "file"
            ),
            ScanVerdict::Unavailable
        ));

        assert!(matches!(
            engine.scan(b"hello", "text/plain", "file"),
            ScanVerdict::Unavailable
        ));
    }

    #[test]
    fn host_port_is_tcp_and_a_path_is_not() {
        assert_eq!(
            super::tcp_address("clamd:3310").as_deref(),
            Some("clamd:3310")
        );
        assert_eq!(
            super::tcp_address("127.0.0.1:3310").as_deref(),
            Some("127.0.0.1:3310")
        );
        assert_eq!(
            super::tcp_address("[::1]:3310").as_deref(),
            Some("[::1]:3310")
        );
        assert_eq!(super::tcp_address("clamd:0"), None);
        assert_eq!(super::tcp_address("/run/clamav/clamd.sock"), None);
        assert_eq!(super::tcp_address(r"C:\clamd.sock"), None);
    }

    #[test]
    fn clamd_words_map_to_verdicts() {
        assert!(matches!(
            clamd_verdict(Ok(b"stream: OK\0".to_vec())),
            ScanVerdict::Clean
        ));
        assert!(matches!(
            clamd_verdict(Ok(b"stream: Win.Test FOUND\0".to_vec())),
            ScanVerdict::Blocked { reason: "clamd" }
        ));
        assert!(matches!(
            clamd_verdict(Ok(b"INSTREAM size limit exceeded. ERROR\0".to_vec())),
            ScanVerdict::Unavailable
        ));
        let refused = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "down");
        assert!(matches!(
            clamd_verdict(Err(refused)),
            ScanVerdict::Unavailable
        ));
        let timed_out = std::io::Error::new(std::io::ErrorKind::TimedOut, "socket");
        assert!(matches!(
            clamd_verdict(Err(timed_out)),
            ScanVerdict::Unavailable
        ));
    }

    #[cfg(not(unix))]
    #[test]
    fn a_filesystem_path_is_rejected_on_windows() {
        match scan_engine(Some(r"C:\clamd.sock"), false) {
            Err(ScanBootError::NeedsTcp(socket)) => {
                assert!(socket.contains("clamd.sock"), "{socket}");
            }
            Err(error) => panic!("{error}"),
            Ok(_) => panic!("expected the boot error"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_filesystem_path_is_a_unix_socket() {
        let engine = scan_engine(Some("/tmp/tinyserver-no-such-clamd.sock"), false)
            .expect("unix socket engine");
        assert!(matches!(
            engine.scan(b"hello", "text/plain", "file"),
            ScanVerdict::Unavailable
        ));
    }
}
