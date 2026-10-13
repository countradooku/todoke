//! What a content operation is bound to, and the consent gate (§7.2, §8).

use core::fmt;

use super::{ContentError, ContentSuite, SegmentLayout};

/// One regular file's content bindings, all from the accepted canonical
/// manifest (§7.1, §8): transfer ID, manifest hash, the manifest's `u32`
/// file ID, suite, size, and BLAKE3 root. The file ID is the manifest
/// entry ID; the root is a separate manifest field.
///
/// This is public metadata and authorizes nothing; see [`AcceptedFile`].
/// `Debug` shows only the file ID, suite, and size.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FileBinding {
    transfer_id: [u8; 16],
    manifest_hash: [u8; 32],
    file_id: u32,
    suite: ContentSuite,
    layout: SegmentLayout,
    root: [u8; 32],
}

impl FileBinding {
    /// Collects the bindings.
    ///
    /// # Errors
    ///
    /// [`ContentError::InvalidFile`] for an all-zero transfer ID (§1), file
    /// ID 0 (the implicit root, §7.1), or a size above 1 TiB.
    pub fn new(
        transfer_id: [u8; 16],
        manifest_hash: [u8; 32],
        file_id: u32,
        suite: ContentSuite,
        size: u64,
        root: [u8; 32],
    ) -> Result<Self, ContentError> {
        if transfer_id == [0; 16] || file_id == 0 {
            return Err(ContentError::InvalidFile);
        }
        Ok(Self {
            transfer_id,
            manifest_hash,
            file_id,
            suite,
            layout: SegmentLayout::new(size)?,
            root,
        })
    }

    /// The manifest's transfer ID.
    #[must_use]
    pub const fn transfer_id(&self) -> &[u8; 16] {
        &self.transfer_id
    }

    /// The accepted canonical manifest hash.
    #[must_use]
    pub const fn manifest_hash(&self) -> &[u8; 32] {
        &self.manifest_hash
    }

    /// The manifest entry ID of this regular file.
    #[must_use]
    pub const fn file_id(&self) -> u32 {
        self.file_id
    }

    /// The manifest's content suite for this file.
    #[must_use]
    pub const fn suite(&self) -> ContentSuite {
        self.suite
    }

    /// The file size and segments.
    #[must_use]
    pub const fn layout(&self) -> &SegmentLayout {
        &self.layout
    }

    /// The manifest's BLAKE3 plaintext root.
    #[must_use]
    pub const fn root(&self) -> &[u8; 32] {
        &self.root
    }
}

impl fmt::Debug for FileBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileBinding")
            .field("file_id", &self.file_id)
            .field("suite", &self.suite)
            .field("size", &self.layout.size())
            .finish_non_exhaustive()
    }
}

/// A selected regular file of a transfer whose signed Accept (`AcceH`) the
/// core has verified for the current session (§7.2, §7.3). Sealing and
/// opening content require one, so no file key is used and no content is
/// decrypted or verified before consent.
///
/// The transfer layer's verified-Accept path is the only intended
/// constructor: it must check the Accept signature, session, expiry, and
/// that the file is in the selection with exactly this binding, then call
/// the crate-private `AcceptedFile::from_verified_accept`. That path does
/// not exist yet. The other constructor,
/// `assume_accepted_without_verification`,
/// exists only in this crate's unit tests and with the non-default
/// `insecure-content-without-accept` feature, which
/// `scripts/ci/deny-exceptions-dev-only.sh` keeps out of every shipped graph.
///
/// Without the feature, this does not compile:
///
#[cfg_attr(
    not(feature = "insecure-content-without-accept"),
    doc = "```compile_fail"
)]
#[cfg_attr(feature = "insecure-content-without-accept", doc = "```")]
/// use todoke_crypto::content::{AcceptedFile, ContentSuite, FileBinding};
/// let binding = FileBinding::new([1; 16], [2; 32], 1, ContentSuite::XChaCha20Poly1305Stream, 0, [3; 32])?;
/// let _file = AcceptedFile::assume_accepted_without_verification(binding);
/// # Ok::<(), todoke_crypto::content::ContentError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptedFile {
    binding: FileBinding,
}

impl AcceptedFile {
    /// The hook for the transfer layer's verified-Accept path (see the
    /// type documentation).
    #[expect(
        dead_code,
        reason = "the signed Accept is verified by the transfer layer, not built yet"
    )]
    pub(crate) const fn from_verified_accept(binding: FileBinding) -> Self {
        Self { binding }
    }

    /// Treats `binding` as accepted **without** any signed Accept. This
    /// bypasses the PROTOCOL §7.2 consent gate.
    ///
    /// Exists only in this crate's unit tests and with the non-default
    /// `insecure-content-without-accept` feature (benchmarks and the content
    /// fuzzing harnesses), never in a shipped graph.
    #[cfg(any(test, feature = "insecure-content-without-accept"))]
    #[must_use]
    pub const fn assume_accepted_without_verification(binding: FileBinding) -> Self {
        Self { binding }
    }

    /// The accepted file's bindings.
    #[must_use]
    pub const fn binding(&self) -> &FileBinding {
        &self.binding
    }
}
