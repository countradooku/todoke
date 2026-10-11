//! `DeviceBinding::decode` on arbitrary bytes; accepted input must be canonical.
#![no_main]

use libfuzzer_sys::fuzz_target;
use todoke_proto::identity::DeviceBinding;

fuzz_target!(|data: &[u8]| {
    if let Ok(binding) = DeviceBinding::decode(data) {
        assert_eq!(binding.encode(), data);
    }
});
