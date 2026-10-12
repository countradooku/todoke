//! Established-session framing, rekey, keepalive, and Error handling
//! (`SessionCore::receive` and its timers) on fuzzer-chosen peer records.
//!
//! Set up deterministically from fixed public test identities and the
//! fixture handshake inputs; see `todoke_crypto::session::fuzzing`. Must
//! never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    todoke_crypto::session::fuzzing::transport_records(data);
});
