//! Pointing records (PROTOCOL §10.4) on arbitrary bytes: the first byte
//! picks the record (0 `RangingReady`, 1 `RangingStart`, 2 `RangingAccept`,
//! 3 `RangingStop`), the rest is its body. An accepted body must be
//! canonical, re-encoding to exactly its input, and within the record's
//! limits.
#![no_main]

use libfuzzer_sys::fuzz_target;
use todoke_proto::ranging::{RangingAccept, RangingReady, RangingStart, RangingStop};

fuzz_target!(|data: &[u8]| {
    let Some((&kind, body)) = data.split_first() else {
        return;
    };
    match kind % 4 {
        0 => {
            if let Ok(ready) = RangingReady::decode(body) {
                assert_eq!(ready.encode().as_slice(), body);
                assert_ne!(ready.configs, 0);
            }
        }
        1 => {
            if let Ok(start) = RangingStart::decode(body) {
                assert_eq!(start.encode().as_slice(), body);
                assert!(matches!(start.channel, 5 | 9));
                assert_ne!(start.session_id, 0);
                assert_eq!(start.config.count_ones(), 1);
            }
        }
        2 => {
            if let Ok(accept) = RangingAccept::decode(body) {
                assert_eq!(accept.encode().as_slice(), body);
                assert!(accept.controlee != 0 && accept.controlee != u16::MAX);
                assert_ne!(accept.session_id, 0);
            }
        }
        _ => {
            if let Ok(stop) = RangingStop::decode(body) {
                assert_eq!(stop.encode().as_slice(), body);
            }
        }
    }
});
