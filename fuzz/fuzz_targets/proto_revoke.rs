//! `Revoke::decode` on arbitrary bytes; accepted input must be canonical.
#![no_main]

use libfuzzer_sys::fuzz_target;
use todoke_proto::identity::Revoke;

fuzz_target!(|data: &[u8]| {
    if let Ok(record) = Revoke::decode(data) {
        assert_eq!(record.encode(), data);
    }
});
