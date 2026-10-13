//! `todoke_crypto::consent::fuzzing::manifest`: see that function for the
//! fixed public inputs and the property asserted (PROTOCOL §7.1–§7.3, §7.7).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    todoke_crypto::consent::fuzzing::manifest(data);
});
