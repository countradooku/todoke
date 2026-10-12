//! The async adapter's incremental length-prefixed record reader (prelude
//! and transport framing) on an arbitrary byte stream delivered in short
//! reads; its records must equal a direct split of the same bytes.
//!
//! See `todoke_crypto::session::fuzzing::record_stream`. Must never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    todoke_crypto::session::fuzzing::record_stream(data);
});
