//! An ICE-TCP byte stream through the RFC 4571 framer.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| sfu::fuzz::tcp_frames(data));
