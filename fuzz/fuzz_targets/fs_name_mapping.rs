//! The receiver's name sanitizer and destination mapping (PROTOCOL §7.1):
//! arbitrary names become safe, stable local components, and a tree of the
//! names the manifest decoder accepts maps onto unique, non-colliding local
//! paths that avoid names the destination already holds.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    todoke_fs::fuzzing::name_mapping(data);
});
