//! Capabilities and every transfer record decoder (PROTOCOL §6, §7) on
//! arbitrary bytes; accepted input must re-encode exactly. The first byte
//! selects the record, so each decoder sees the whole remaining input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use todoke_proto::transfer::{
    Accept, Cancel, Capabilities, Chunk, ChunkRequest, Complete, DeliveryReceipt, ManifestPart,
    ManifestStart, Reject, ResumeQuery, ResumeStatus,
};

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    match selector % 12 {
        0 => {
            if let Ok(record) = Capabilities::decode(body) {
                assert_eq!(record.encode().as_slice(), body);
            }
        }
        1 => {
            if let Ok(record) = ManifestStart::decode(body) {
                assert_eq!(record.encode().as_slice(), body);
            }
        }
        2 => {
            if let Ok(record) = ManifestPart::decode(body) {
                assert_eq!(record.encode(), body);
                assert!(!record.data().is_empty() && record.data().len() <= 60_000);
            }
        }
        3 => {
            if let Ok(record) = Accept::decode(body) {
                assert_eq!(record.encode(), body);
                let selection = record.body().selection();
                assert!(selection.windows(2).all(|pair| pair[0] < pair[1]));
            }
        }
        4 => {
            if let Ok(record) = Reject::decode(body) {
                assert_eq!(record.encode().as_slice(), body);
            }
        }
        5 => {
            if let Ok(record) = ChunkRequest::decode(body) {
                assert_eq!(record.encode().as_slice(), body);
            }
        }
        6 => {
            if let Ok(transfer_id) = Chunk::peek_transfer_id(body) {
                assert_eq!(transfer_id.as_slice(), &body[..16]);
            }
            if let Ok(record) = Chunk::decode(body) {
                assert_eq!(record.encode(), body);
                assert!((24..=32_784).contains(&record.content().len()));
            }
        }
        7 => {
            if let Ok(record) = ResumeQuery::decode(body) {
                assert_eq!(record.encode().as_slice(), body);
            }
        }
        8 => {
            if let Ok(record) = ResumeStatus::decode(body) {
                assert_eq!(record.encode(), body);
                for &(start, count) in record.ranges() {
                    assert!(count >= 1 && start >= record.from_index());
                    assert!(u64::from(start) + u64::from(count) <= u64::from(record.next_index()));
                }
            }
        }
        9 => {
            if let Ok(record) = Cancel::decode(body) {
                assert_eq!(record.encode().as_slice(), body);
            }
        }
        10 => {
            if let Ok(record) = Complete::decode(body) {
                assert_eq!(record.encode().as_slice(), body);
            }
        }
        _ => {
            if let Ok(record) = DeliveryReceipt::decode(body) {
                assert_eq!(record.encode().as_slice(), body);
            }
        }
    }
});
