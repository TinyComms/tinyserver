//! A live-socket frame, as a client message and as an outbox payload.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| api::fuzz::live_frame(data));
