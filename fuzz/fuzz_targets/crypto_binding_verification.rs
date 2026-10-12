//! Ed25519 key validation, ML-KEM key validation, and strict signature
//! verification of a decoded binding under a fuzzer-chosen root.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    todoke_crypto::identity::fuzzing::binding_verification(data);
});
