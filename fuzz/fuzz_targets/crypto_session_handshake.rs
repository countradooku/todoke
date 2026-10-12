//! Session prelude and Noise handshake parsing on arbitrary bytes.
//!
//! Drives the real handshake driver (responder or initiator, all three
//! modes) from deterministic public fixture inputs with a stream of
//! fuzzer-supplied prelude records. Must never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    todoke_crypto::session::fuzzing::handshake_records(data);
});
