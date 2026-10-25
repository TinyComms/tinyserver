//! Video routing arithmetic: timestamp rebasing, the speaker floor, and layer choice.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| sfu::fuzz::video(data));
