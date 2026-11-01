//! Where the external sender's private half lives: one file, mode 0600 on Unix.
//!
//! The public half stays in `e2ee_server_key`. This file is the only copy of the secret after
//! the first start. A database dump does not contain it. Nothing here logs the bytes.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// `TINYSERVER_E2EE_KEY_FILE`, or `{TINYSERVER_DATA_DIR}/e2ee-server-key`.
/// The data dir is the same rule as `log_policy::data_dir`: this crate cannot call that one.
pub(crate) fn path() -> PathBuf {
    if let Some(file) = env_nonempty("TINYSERVER_E2EE_KEY_FILE") {
        return PathBuf::from(file);
    }
    data_dir().join("e2ee-server-key")
}

fn data_dir() -> PathBuf {
    if let Some(dir) = env_nonempty("TINYSERVER_DATA_DIR") {
        return PathBuf::from(dir);
    }
    let system = PathBuf::from("/var/lib/tinyserver");
    if system.is_dir() {
        return system;
    }
    PathBuf::from("tinyserver-data")
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

pub(crate) fn read(path: &Path) -> io::Result<Vec<u8>> {
    let bytes = fs::read(path)?;
    if bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "e2ee server key file is empty",
        ));
    }
    Ok(bytes)
}

/// Creates the file only when it is absent. `AlreadyExists` means another process wrote it;
/// the caller reads that file instead of replacing it.
pub(crate) fn create_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "e2ee server key is empty",
        ));
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
