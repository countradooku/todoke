//! Strict Bao 0.13.1 slice verification (PROTOCOL §7.4) of arbitrary bytes
//! as the decrypted slice of a segment of a known file: a 3-byte size and a
//! 1-byte index select the file and segment, the rest is the slice. Any
//! accepted slice must yield exactly that segment's bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    todoke_crypto::content::fuzzing::bao_slice(data);
});
