//! `Manifest::decode` (PROTOCOL §7.1) on arbitrary bytes: header, entry
//! tree, names, MIME labels, sizes, depth, path length, and limits. The
//! first byte picks the protocol limits or small receiver limits; accepted
//! manifests re-encode exactly and satisfy the limits.
#![no_main]

use libfuzzer_sys::fuzz_target;
use todoke_proto::transfer::{Manifest, ManifestLimits};

fuzz_target!(|data: &[u8]| {
    let Some((&selector, bytes)) = data.split_first() else {
        return;
    };
    let limits = if selector & 1 == 0 {
        ManifestLimits::SPEC
    } else {
        ManifestLimits::new(u32::from(selector >> 1).max(1), 1 << 20, 1 << 22)
    };
    let Ok(manifest) = Manifest::decode(bytes, &limits) else {
        return;
    };
    assert_eq!(manifest.encode(), bytes);
    let count = u32::try_from(manifest.entries().len()).unwrap_or(u32::MAX);
    assert!(count >= 1 && count <= limits.max_entries());
    assert!(manifest.total_file_bytes() <= limits.max_transfer_bytes());
    for entry in manifest.entries() {
        assert!(entry.size() <= limits.max_file_bytes());
        let path = manifest.path_components(entry.id()).unwrap_or_default();
        assert!(!path.is_empty() && path.len() <= 64);
        let joined = path.iter().map(|name| name.len()).sum::<usize>() + path.len() - 1;
        assert!(joined <= 4096);
    }
});
