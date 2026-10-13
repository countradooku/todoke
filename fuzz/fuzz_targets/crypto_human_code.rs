//! Typed human pairing code: `HumanCode::parse_and_wipe` and
//! `HumanCode::parse` agree, wipe the buffer, and accept exactly ten ASCII
//! digits as given.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    todoke_crypto::pairing::fuzzing::human_code(data);
});
