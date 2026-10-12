//! Identity confirmation and the PSK ratchet (`Establishment::receive`) on
//! fuzzer-controlled wire operations against an honest peer.
//!
//! Set up deterministically from fixed public test identities and the
//! fixture handshake inputs; see `todoke_crypto::session::fuzzing`. Must
//! never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    todoke_crypto::session::fuzzing::establishment_records(data);
});
