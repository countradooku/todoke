//! Local storage envelope parsing and authenticated opening. Unauthenticated
//! input must never open.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    assert!(!todoke_crypto::identity::fuzzing::sealed_envelope(data));
});
