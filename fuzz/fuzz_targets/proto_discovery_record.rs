//! Discovery records (`DiscoveryRecord`), their mDNS TXT strings, and mDNS
//! instance labels on arbitrary bytes; accepted input must be canonical.
#![no_main]

use libfuzzer_sys::fuzz_target;
use todoke_proto::discovery::{DiscoveryRecord, InstanceLabel};

fuzz_target!(|data: &[u8]| {
    if let Ok(record) = DiscoveryRecord::decode(data) {
        assert_eq!(record.encode().as_slice(), data);
        assert_eq!(
            DiscoveryRecord::from_txt(record.to_txt().as_bytes()),
            Ok(record)
        );
    }
    if let Ok(record) = DiscoveryRecord::from_txt(data) {
        assert_eq!(record.to_txt().as_bytes(), data);
    }
    if let Ok(text) = core::str::from_utf8(data)
        && let Ok(label) = InstanceLabel::parse(text)
    {
        assert_eq!(label.as_str(), text);
    }
});
