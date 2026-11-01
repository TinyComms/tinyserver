//! The MLS parsers the encrypted-text routes run on bytes a member sent.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| api::fuzz::e2ee_handshake(data));
