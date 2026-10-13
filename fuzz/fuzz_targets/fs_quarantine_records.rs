//! The quarantine's local record formats: a transfer journal (header and
//! appended entries, cut at the first damaged entry) and the tombstone
//! list. Whatever decodes re-encodes to exactly the bytes it came from, and
//! every name in a journal is a safe local component.
#![no_main]

use libfuzzer_sys::fuzz_target;
use todoke_fs::quarantine::codec::{
    JournalEntry, decode_journal, decode_tombstones, encode_tombstones,
};

fuzz_target!(|data: &[u8]| {
    let Some((&selector, bytes)) = data.split_first() else {
        return;
    };
    if selector & 1 == 0 {
        let Ok((header, entries, valid)) = decode_journal(bytes) else {
            return;
        };
        assert!(valid <= bytes.len());
        let mut encoded = header.encode();
        for entry in &entries {
            encoded.extend_from_slice(&entry.encode());
            if let JournalEntry::TopDirectory { name, .. } | JournalEntry::Published { name, .. } =
                entry
            {
                assert!(!name.contains(['/', '\\', ':']) && name != "." && name != "..");
            }
        }
        assert_eq!(encoded, &bytes[..valid]);
    } else {
        let Ok(list) = decode_tombstones(bytes) else {
            return;
        };
        assert_eq!(encode_tombstones(&list), bytes);
    }
});
