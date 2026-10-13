//! `ContentOpener::open_segment` (PROTOCOL §7.4, §8) on arbitrary bytes as
//! the content ciphertext of a segment of a known file: length checks,
//! AEAD authentication, then strict Bao verification. Only the honest
//! ciphertext may open, and only to that segment's bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    todoke_crypto::content::fuzzing::open_segment(data);
});
