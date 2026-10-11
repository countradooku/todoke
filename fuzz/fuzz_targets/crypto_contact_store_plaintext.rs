//! Contact store blob plaintext decoder; accepted input must be canonical.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(reencoded) = todoke_crypto::identity::fuzzing::contact_store_plaintext(data) {
        assert_eq!(reencoded.as_slice(), data);
    }
});
