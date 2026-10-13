//! Content-type detection on verified content: bounded signature checks
//! that never panic, and an assessment consistent with the detection.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    todoke_fs::fuzzing::content_type(data);
});
