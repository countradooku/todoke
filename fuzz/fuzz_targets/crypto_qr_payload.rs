//! QR pairing payload: the binary layout and the `TODOKE:` + Base45 text,
//! with key validation and expiry; accepted input must be canonical.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(reencoded) = todoke_crypto::pairing::fuzzing::qr_payload(data) {
        assert_eq!(reencoded.as_slice(), data);
    }
    if let Ok(text) = core::str::from_utf8(data) {
        if let Some(reencoded) = todoke_crypto::pairing::fuzzing::qr_text(text) {
            assert_eq!(reencoded.as_str(), text);
        }
    }
});
