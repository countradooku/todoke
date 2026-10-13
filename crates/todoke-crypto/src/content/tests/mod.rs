//! Content-layer tests: committed fixtures, Wycheproof, Bao reference
//! slices, the seal/open pipeline, resume, and the segment tracker.

mod bao_vectors;
mod cipher;
mod file_key;
mod layout;
mod resume;
mod tracker;
mod vectors;
mod wycheproof;

use std::io::Cursor;
use std::path::Path;

use zeroize::Zeroizing;

use super::{
    AcceptedFile, ContentOpener, ContentSealer, ContentSuite, ContentSuites, FileBinding,
    FileMaster, outboard,
};

pub(super) type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;
pub(super) type TestResult = AnyResult<()>;

pub(super) const TRANSFER_ID: [u8; 16] = [0xa3; 16];
pub(super) const MANIFEST_HASH: [u8; 32] = [0x59; 32];
pub(super) const MASTER: [u8; 32] = [0xa5; 32];

/// Reads a JSON file under `crates/todoke-crypto/testdata`.
pub(super) fn testdata(name: &str) -> AnyResult<serde_json::Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(name);
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

/// The Bao test-vector input: a 4-byte little-endian counter from 1.
pub(super) fn counter_input(len: usize) -> AnyResult<Vec<u8>> {
    let mut out = Vec::with_capacity(len);
    let mut counter: u32 = 1;
    while out.len() < len {
        let take = (len - out.len()).min(4);
        out.extend_from_slice(&counter.to_le_bytes()[..take]);
        counter = counter.checked_add(1).ok_or("counter overflow")?;
    }
    Ok(out)
}

pub(super) fn master() -> FileMaster {
    FileMaster::from_secret(Zeroizing::new(MASTER))
}

/// Whether this device advertises AES, so that AES-only tests can instead
/// check that it is refused where it is not.
pub(super) fn aes_available() -> bool {
    ContentSuites::local().contains(ContentSuite::Aes256GcmStream)
}

/// The suites this device can seal and open.
pub(super) fn local_suites() -> Vec<ContentSuite> {
    [
        ContentSuite::Aes256GcmStream,
        ContentSuite::XChaCha20Poly1305Stream,
    ]
    .into_iter()
    .filter(|&suite| ContentSuites::local().contains(suite))
    .collect()
}

/// A source file with its outboard, root, and binding.
pub(super) struct Source {
    pub(super) content: Vec<u8>,
    pub(super) outboard: Vec<u8>,
    pub(super) binding: FileBinding,
}

impl Source {
    pub(super) fn new(content: Vec<u8>, suite: ContentSuite) -> AnyResult<Self> {
        Self::with_ids(content, suite, TRANSFER_ID, 1)
    }

    pub(super) fn with_ids(
        content: Vec<u8>,
        suite: ContentSuite,
        transfer_id: [u8; 16],
        file_id: u32,
    ) -> AnyResult<Self> {
        let (outboard, root) = outboard(&content);
        let size = u64::try_from(content.len())?;
        let binding = FileBinding::new(transfer_id, MANIFEST_HASH, file_id, suite, size, root)?;
        Ok(Self {
            content,
            outboard,
            binding,
        })
    }

    pub(super) fn accepted(&self) -> AcceptedFile {
        AcceptedFile::assume_accepted_without_verification(self.binding)
    }

    pub(super) fn sealer(&self) -> AnyResult<ContentSealer> {
        Ok(ContentSealer::new(&self.accepted(), &master())?)
    }

    pub(super) fn opener(&self) -> AnyResult<ContentOpener> {
        Ok(ContentOpener::new(&self.accepted(), &master())?)
    }

    pub(super) fn seal(&self, sealer: &ContentSealer, index: u32) -> AnyResult<Vec<u8>> {
        Ok(sealer.seal_segment(
            index,
            Cursor::new(&self.content),
            Cursor::new(&self.outboard),
        )?)
    }

    /// The logical bytes of segment `index`.
    pub(super) fn segment_bytes(&self, index: u32) -> AnyResult<&[u8]> {
        let segment = self.binding.layout().segment(index)?;
        let start = usize::try_from(segment.start())?;
        let len = usize::try_from(segment.len())?;
        Ok(self.content.get(start..start + len).ok_or("range")?)
    }
}
