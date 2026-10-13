//! The sender's side of an offer: building the manifest as a folder tree
//! (§7.1) and holding each file's fresh master (§8).

use core::fmt;
use std::collections::BTreeMap;

use todoke_crypto::consent::{CanonicalManifest, ManifestCheckError, random_id};
use todoke_crypto::content::{ContentSuite, FileMaster};
use todoke_crypto::identity::Ed25519PublicKey;
use todoke_proto::time::UnixTime;
use todoke_proto::transfer::{
    Manifest, ManifestEntry, ManifestError, ManifestHeader, ManifestLimits, TransferId,
};

/// Why a manifest could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// The entries violate §7.1 (names, tree, sizes, limits).
    Manifest(ManifestError),
    /// The canonical form failed a check (keys, empty-file root).
    Check(ManifestCheckError),
    /// Randomness for the transfer ID or a master was unavailable.
    Random,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(error) => write!(f, "{error}"),
            Self::Check(error) => write!(f, "{error}"),
            Self::Random => f.write_str("randomness unavailable"),
        }
    }
}

impl std::error::Error for BuildError {}

enum Pending {
    Directory {
        parent: u32,
        name: String,
    },
    File {
        parent: u32,
        name: String,
        mime: String,
        size: u64,
        root: [u8; 32],
    },
}

/// Builds a manifest entry by entry, in wire order: folders are entries
/// that later entries name as parent, so a whole tree streams as a list
/// with no archive format (§7.1). Validation happens in [`Self::build`].
pub struct ManifestBuilder {
    transfer_id: TransferId,
    sender: [u8; 32],
    recipient: [u8; 32],
    created_at: UnixTime,
    expires_at: UnixTime,
    entries: Vec<Pending>,
}

impl ManifestBuilder {
    /// A manifest from `sender` to `recipient` (full device keys) with a
    /// fresh random transfer ID, valid from `created_at` until `expires_at`
    /// (at most seven days later).
    ///
    /// # Errors
    ///
    /// [`BuildError::Random`].
    pub fn new(
        sender: &Ed25519PublicKey,
        recipient: &Ed25519PublicKey,
        created_at: UnixTime,
        expires_at: UnixTime,
    ) -> Result<Self, BuildError> {
        let transfer_id = random_id().map_err(|_| BuildError::Random)?;
        Ok(Self::with_transfer_id(
            transfer_id,
            sender,
            recipient,
            created_at,
            expires_at,
        ))
    }

    /// As [`Self::new`] with a given transfer ID, for tests. A live
    /// transfer ID must be fresh and random (§7).
    #[must_use]
    pub fn with_transfer_id(
        transfer_id: TransferId,
        sender: &Ed25519PublicKey,
        recipient: &Ed25519PublicKey,
        created_at: UnixTime,
        expires_at: UnixTime,
    ) -> Self {
        Self {
            transfer_id,
            sender: *sender.as_bytes(),
            recipient: *recipient.as_bytes(),
            created_at,
            expires_at,
            entries: Vec::new(),
        }
    }

    fn next_id(&self) -> u32 {
        u32::try_from(self.entries.len())
            .unwrap_or(u32::MAX)
            .saturating_add(1)
    }

    /// Adds a directory under `parent` (0 for the top level) and returns
    /// its ID.
    pub fn add_directory(&mut self, parent: u32, name: &str) -> u32 {
        let id = self.next_id();
        self.entries.push(Pending::Directory {
            parent,
            name: name.to_owned(),
        });
        id
    }

    /// Adds a regular file under `parent` and returns its ID. `root` is its
    /// BLAKE3 root and `size` its exact length (from the same immutable
    /// snapshot the source will serve). Use `application/octet-stream`
    /// for unknown content.
    pub fn add_file(
        &mut self,
        parent: u32,
        name: &str,
        mime: &str,
        size: u64,
        root: [u8; 32],
    ) -> u32 {
        let id = self.next_id();
        self.entries.push(Pending::File {
            parent,
            name: name.to_owned(),
            mime: mime.to_owned(),
            size,
            root,
        });
        id
    }

    /// Validates the entries against `limits` (the receiver's Capabilities)
    /// and produces the canonical manifest, every file using `suite` (§6).
    ///
    /// # Errors
    ///
    /// [`BuildError::Manifest`] or [`BuildError::Check`].
    pub fn build(
        self,
        suite: ContentSuite,
        limits: &ManifestLimits,
    ) -> Result<CanonicalManifest, BuildError> {
        let header = ManifestHeader {
            transfer_id: self.transfer_id,
            sender_public: self.sender,
            recipient_public: self.recipient,
            created_at: self.created_at,
            expires_at: self.expires_at,
        };
        let mut entries = Vec::with_capacity(self.entries.len());
        for (index, pending) in self.entries.into_iter().enumerate() {
            let id = u32::try_from(index + 1)
                .map_err(|_| BuildError::Manifest(ManifestError::EntryCount))?;
            entries.push(match pending {
                Pending::Directory { parent, name } => ManifestEntry::directory(id, parent, name),
                Pending::File {
                    parent,
                    name,
                    mime,
                    size,
                    root,
                } => ManifestEntry::file(id, parent, name, mime, size, root, suite.id()),
            });
        }
        let manifest = Manifest::new(header, entries, limits).map_err(BuildError::Manifest)?;
        CanonicalManifest::from_manifest(manifest).map_err(BuildError::Check)
    }
}

impl fmt::Debug for ManifestBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManifestBuilder")
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

/// Why the engine refused to send an offer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfferError {
    /// Capabilities have not been exchanged yet, or the session is closed.
    NotReady,
    /// The manifest is not from this device to the session's peer.
    Parties,
    /// A file does not use the negotiated suite (§6).
    Suite,
    /// The manifest exceeds the peer's advertised limits (§6).
    Limits,
    /// The manifest has expired.
    Expired,
    /// The peer already has 2 incoming transfers from this device (§7).
    Busy,
    /// This transfer ID is already in use in this session.
    Duplicate,
}

impl fmt::Display for OfferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotReady => "the session is not ready for transfers",
            Self::Parties => "the manifest is not for this session's devices",
            Self::Suite => "a file does not use the negotiated content suite",
            Self::Limits => "the manifest exceeds the receiver's limits",
            Self::Expired => "the manifest has expired",
            Self::Busy => "the receiver has no free transfer slot",
            Self::Duplicate => "the transfer is already active in this session",
        })
    }
}

impl std::error::Error for OfferError {}

/// A manifest ready to send and each regular file's master (§8). Keep it
/// to resume in a later session: a resumed transfer must reuse the same
/// manifest and masters (§7.5, §8). The masters are zeroized on drop and
/// never leave this crate except inside `FileKey` frames.
pub struct OutgoingOffer {
    manifest: CanonicalManifest,
    masters: BTreeMap<u32, FileMaster>,
    resumed: bool,
}

impl OutgoingOffer {
    /// Draws a fresh master for every regular file.
    ///
    /// # Errors
    ///
    /// [`BuildError::Random`].
    pub fn new(manifest: CanonicalManifest) -> Result<Self, BuildError> {
        let mut masters = BTreeMap::new();
        for file in manifest.files() {
            masters.insert(
                file.file_id(),
                FileMaster::generate().map_err(|_| BuildError::Random)?,
            );
        }
        Ok(Self {
            manifest,
            masters,
            resumed: false,
        })
    }

    /// The canonical manifest.
    #[must_use]
    pub const fn manifest(&self) -> &CanonicalManifest {
        &self.manifest
    }

    /// The transfer ID.
    #[must_use]
    pub const fn transfer_id(&self) -> &TransferId {
        self.manifest.transfer_id()
    }

    /// Whether an earlier session already offered it (then the sender asks
    /// the receiver what it holds, §7.5).
    #[must_use]
    pub const fn is_resumption(&self) -> bool {
        self.resumed
    }

    pub(crate) fn mark_offered(&mut self) {
        self.resumed = true;
    }

    pub(crate) fn take_master(&mut self, file_id: u32) -> Option<FileMaster> {
        self.masters.remove(&file_id)
    }

    pub(crate) fn return_master(&mut self, file_id: u32, master: FileMaster) {
        self.masters.insert(file_id, master);
    }
}

impl fmt::Debug for OutgoingOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutgoingOffer")
            .field("manifest", &self.manifest)
            .field("resumed", &self.resumed)
            .finish_non_exhaustive()
    }
}
