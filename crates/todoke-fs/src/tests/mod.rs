//! Crate tests that span modules, and shared fixtures.

mod plan;

use todoke_proto::time::UnixTime;
use todoke_proto::transfer::manifest::{Manifest, ManifestEntry, ManifestHeader, ManifestLimits};

pub(crate) type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;
pub(crate) type TestResult = AnyResult<()>;

/// RFC 8032 test 1 and test 2 public keys: valid Ed25519 points.
pub(crate) const SENDER: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
pub(crate) const RECIPIENT: [u8; 32] = [
    0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
    0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
];
pub(crate) const CREATED: u64 = 1_760_000_000;

/// An entry to build: a directory (`content` is `None`) or a file.
pub(crate) struct Spec {
    pub(crate) name: String,
    pub(crate) parent: u32,
    pub(crate) mime: &'static str,
    pub(crate) content: Option<Vec<u8>>,
}

pub(crate) fn file(name: &str, parent: u32) -> Spec {
    file_with(name, parent, Vec::new())
}

pub(crate) fn file_with(name: &str, parent: u32, content: Vec<u8>) -> Spec {
    Spec {
        name: name.to_owned(),
        parent,
        mime: "application/octet-stream",
        content: Some(content),
    }
}

pub(crate) fn dir(name: &str, parent: u32) -> Spec {
    Spec {
        name: name.to_owned(),
        parent,
        mime: "",
        content: None,
    }
}

/// A manifest with `specs` as entries 1.. in order.
pub(crate) fn manifest(transfer_id: [u8; 16], specs: &[Spec]) -> AnyResult<Manifest> {
    let header = ManifestHeader {
        transfer_id,
        sender_public: SENDER,
        recipient_public: RECIPIENT,
        created_at: UnixTime::new(CREATED).ok_or("time")?,
        expires_at: UnixTime::new(CREATED + 3600).ok_or("time")?,
    };
    let mut entries = Vec::new();
    for (index, spec) in specs.iter().enumerate() {
        let id = u32::try_from(index + 1).unwrap_or(u32::MAX);
        entries.push(match &spec.content {
            None => ManifestEntry::directory(id, spec.parent, spec.name.clone()),
            Some(content) => ManifestEntry::file(
                id,
                spec.parent,
                spec.name.clone(),
                spec.mime.to_owned(),
                u64::try_from(content.len()).unwrap_or(u64::MAX),
                *blake3::hash(content).as_bytes(),
                2,
            ),
        });
    }
    Ok(Manifest::new(header, entries, &ManifestLimits::SPEC)?)
}
