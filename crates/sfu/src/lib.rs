//! Media plane. Not started yet.
//!
//! When calls exist, this crate owns one thread, one UDP socket, and `str0m`.
//! RTP stays in memory. Postgres never stores it.

/// True once the media thread is running. It is not, in this build.
pub fn running() -> bool {
    false
}

#[cfg(test)]
mod tests {
    #[test]
    fn media_plane_is_not_started() {
        assert!(!super::running());
    }
}
