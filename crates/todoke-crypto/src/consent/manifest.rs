//! The canonical manifest and its hash (§7.1).

use core::fmt;

use todoke_proto::time::UnixTime;
use todoke_proto::transfer::{
    MANIFEST_HASH_DOMAIN, Manifest, ManifestError, ManifestLimits, TransferId,
};

use crate::content::{ContentError, ContentSuite, FileBinding};
use crate::identity::Ed25519PublicKey;

/// `manifest_hash = B3("todoke/v1/manifest\0" || canonical_manifest)` (§7.1).
#[must_use]
pub fn manifest_hash(canonical: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MANIFEST_HASH_DOMAIN);
    hasher.update(canonical);
    *hasher.finalize().as_bytes()
}

/// Why canonical manifest bytes were refused. Carries no names or other
/// peer data; every case is the `MANIFEST` error (§12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestCheckError {
    /// The schema check failed (§7.1).
    Manifest(ManifestError),
    /// The sender key is not a valid Ed25519 public key (§1).
    SenderKey,
    /// The recipient key is not a valid Ed25519 public key (§1).
    RecipientKey,
    /// An empty file does not carry the BLAKE3 root of the empty input
    /// (§7.1: "an empty file is not the zero root").
    EmptyFileRoot,
    /// A file binding is out of range for the content layer.
    Content(ContentError),
}

impl fmt::Display for ManifestCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(error) => write!(f, "{error}"),
            Self::SenderKey => f.write_str("manifest sender key is invalid"),
            Self::RecipientKey => f.write_str("manifest recipient key is invalid"),
            Self::EmptyFileRoot => f.write_str("empty file has the wrong root"),
            Self::Content(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ManifestCheckError {}

impl From<ManifestError> for ManifestCheckError {
    fn from(error: ManifestError) -> Self {
        Self::Manifest(error)
    }
}

/// A canonical manifest: the exact bytes, their §7.1 hash computed here,
/// the validated schema, both device keys validated as Ed25519 keys, and
/// the content binding of every regular file.
///
/// Public metadata: it authorizes nothing until an Accept names its hash.
/// `Debug` prints no names or MIME labels.
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalManifest {
    bytes: Vec<u8>,
    hash: [u8; 32],
    manifest: Manifest,
    sender: Ed25519PublicKey,
    recipient: Ed25519PublicKey,
    /// Regular files in ID order.
    files: Vec<FileBinding>,
}

impl CanonicalManifest {
    /// Checks received bytes against the receiver's `limits` and hashes
    /// them. The bytes are kept exactly as received; nothing is normalized.
    ///
    /// # Errors
    ///
    /// Any [`ManifestCheckError`].
    pub fn parse(bytes: Vec<u8>, limits: &ManifestLimits) -> Result<Self, ManifestCheckError> {
        let manifest = Manifest::decode(&bytes, limits)?;
        // Decoding is canonical; refuse anything that would not re-encode
        // to the same bytes rather than rely on it silently.
        if manifest.encode() != bytes {
            return Err(ManifestCheckError::Manifest(ManifestError::Length));
        }
        Self::build(bytes, manifest)
    }

    /// The canonical form of a manifest the sender assembled.
    ///
    /// # Errors
    ///
    /// Any [`ManifestCheckError`] except a schema error, which
    /// [`Manifest::new`] already reported.
    pub fn from_manifest(manifest: Manifest) -> Result<Self, ManifestCheckError> {
        let bytes = manifest.encode();
        Self::build(bytes, manifest)
    }

    fn build(bytes: Vec<u8>, manifest: Manifest) -> Result<Self, ManifestCheckError> {
        let header = manifest.header();
        let sender = Ed25519PublicKey::from_bytes(&header.sender_public)
            .map_err(|_| ManifestCheckError::SenderKey)?;
        let recipient = Ed25519PublicKey::from_bytes(&header.recipient_public)
            .map_err(|_| ManifestCheckError::RecipientKey)?;
        let hash = manifest_hash(&bytes);
        let empty_root = *blake3::hash(&[]).as_bytes();
        let mut files = Vec::new();
        for entry in manifest.files() {
            if entry.size() == 0 && *entry.root() != empty_root {
                return Err(ManifestCheckError::EmptyFileRoot);
            }
            // The schema check admits only suites 1 and 2 for files.
            let suite = ContentSuite::from_id(entry.content_suite())
                .ok_or(ManifestCheckError::Manifest(ManifestError::Suite))?;
            files.push(
                FileBinding::new(
                    header.transfer_id,
                    hash,
                    entry.id(),
                    suite,
                    entry.size(),
                    *entry.root(),
                )
                .map_err(ManifestCheckError::Content)?,
            );
        }
        Ok(Self {
            bytes,
            hash,
            manifest,
            sender,
            recipient,
            files,
        })
    }

    /// The canonical bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The manifest hash (§7.1).
    #[must_use]
    pub const fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// The validated schema: entries, names, and limits.
    #[must_use]
    pub const fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The transfer ID.
    #[must_use]
    pub const fn transfer_id(&self) -> &TransferId {
        &self.manifest.header().transfer_id
    }

    /// The sender's full device key.
    #[must_use]
    pub const fn sender(&self) -> &Ed25519PublicKey {
        &self.sender
    }

    /// The recipient's full device key.
    #[must_use]
    pub const fn recipient(&self) -> &Ed25519PublicKey {
        &self.recipient
    }

    /// When the manifest was built.
    #[must_use]
    pub const fn created_at(&self) -> UnixTime {
        self.manifest.header().created_at
    }

    /// When the manifest stops being valid.
    #[must_use]
    pub const fn expires_at(&self) -> UnixTime {
        self.manifest.header().expires_at
    }

    /// The content binding of regular file `file_id`, or `None` for a
    /// directory or unknown ID. Public metadata; see
    /// [`VerifiedAccept::file`](super::VerifiedAccept::file) for an
    /// accepted file.
    #[must_use]
    pub fn file(&self, file_id: u32) -> Option<&FileBinding> {
        self.files
            .binary_search_by_key(&file_id, FileBinding::file_id)
            .ok()
            .and_then(|index| self.files.get(index))
    }

    /// Every regular file's binding, in ID order.
    #[must_use]
    pub fn files(&self) -> &[FileBinding] {
        &self.files
    }
}

impl fmt::Debug for CanonicalManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CanonicalManifest")
            .field("hash", &crate::identity::Hex(&self.hash))
            .field("manifest", &self.manifest)
            .finish_non_exhaustive()
    }
}
