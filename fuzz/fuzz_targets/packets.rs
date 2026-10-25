//! Network packets into a participant with an answer out.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| sfu::fuzz::packets(data));
