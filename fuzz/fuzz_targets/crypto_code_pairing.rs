//! Human-code pairing handshake: the `CPace` share exchange and the
//! `XXpsk3` handshake driven by fuzzer-supplied prelude records, with fixed
//! public inputs and scripted randomness.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    todoke_crypto::session::fuzzing::code_pairing_records(data);
});
