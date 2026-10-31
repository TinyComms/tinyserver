//! Scan verdicts for chat uploads. Tests use FakeEngine; production uses clamd later.

pub enum ScanVerdict {
    Clean,
    Blocked { reason: &'static str },
    Unavailable,
}

pub trait ScanEngine: Send + Sync {
    fn scan(&self, bytes: &[u8], mime: &str, kind: &str) -> ScanVerdict;
}

pub struct FakeEngine;

const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

impl ScanEngine for FakeEngine {
    fn scan(&self, bytes: &[u8], _mime: &str, _kind: &str) -> ScanVerdict {
        if contains_eicar(bytes) {
            ScanVerdict::Blocked { reason: "eicar" }
        } else {
            ScanVerdict::Clean
        }
    }
}

fn contains_eicar(bytes: &[u8]) -> bool {
    bytes.windows(EICAR.len()).any(|window| window == EICAR)
}

#[cfg(test)]
mod tests {
    use super::{FakeEngine, ScanEngine, ScanVerdict};

    #[test]
    fn fake_engine_blocks_eicar() {
        let hit = FakeEngine.scan(
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
            "text/plain",
            "file",
        );
        assert!(matches!(hit, ScanVerdict::Blocked { reason: "eicar" }));
    }

    #[test]
    fn fake_engine_cleans_plain_bytes() {
        assert!(matches!(
            FakeEngine.scan(b"hello", "text/plain", "file"),
            ScanVerdict::Clean
        ));
    }
}
