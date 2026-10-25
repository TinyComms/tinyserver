//! An SDP offer through the caps, str0m's parser, and a participant accepting it.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| sfu::fuzz::offer(data));
