//! `FileKeyBody::decode` (PROTOCOL §8): exactly 86 bytes, nonzero transfer
//! and file IDs, suite 1 or 2; accepted bodies re-encode to the input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    todoke_crypto::content::fuzzing::file_key_body(data);
});
