//! Where the sender's content comes from and where the receiver's verified
//! segments go (§7.4, §7.5, §7.7).
//!
//! `todoke-fs` (P08) implements [`SendSource`] and [`ReceiveSink`] for real
//! files: snapshotting sources, Bao outboards on disk, quarantined partial
//! data, collision mapping, and atomic publication. [`MemorySource`] and
//! [`MemorySink`] keep everything in memory for tests and examples.

use core::fmt;
use std::collections::BTreeMap;
use std::io::{Cursor, Read, Seek};

use todoke_crypto::consent::{CanonicalManifest, VerifiedAccept};
use todoke_crypto::content::{SEGMENT_LEN, VerifiedSegment, outboard};
use todoke_crypto::identity::Ed25519PublicKey;
use todoke_proto::time::UnixTime;
use todoke_proto::transfer::TransferId;
use zeroize::Zeroizing;

/// A source file could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceError {
    /// The source has no such file.
    NotFound,
    /// Reading failed.
    Io(std::io::ErrorKind),
}

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("source file not found"),
            Self::Io(kind) => write!(f, "reading the source failed: {kind}"),
        }
    }
}

impl std::error::Error for SourceError {}

/// The sender's files: each selected file's content and its Bao 0.13.1
/// outboard ([`todoke_crypto::content::write_outboard`]).
///
/// Implementations must serve immutable bytes: a snapshot, or a file whose
/// mutation is detected. The content layer re-verifies every slice against
/// the manifest root before sealing and refuses a changed source (§8).
pub trait SendSource {
    /// The file content reader.
    type Content<'a>: Read + Seek
    where
        Self: 'a;
    /// The Bao outboard reader.
    type Outboard<'a>: Read + Seek
    where
        Self: 'a;

    /// Opens file `file_id` of `transfer_id` and its outboard.
    ///
    /// # Errors
    ///
    /// [`SourceError`] if the file is missing or unreadable.
    fn open(
        &mut self,
        transfer_id: &TransferId,
        file_id: u32,
    ) -> Result<(Self::Content<'_>, Self::Outboard<'_>), SourceError>;
}

/// Why the receiver's destination refused an offer before the prompt. The
/// offer is rejected with the matching reason (§7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SinkRefusal {
    /// A local quota would be exceeded (`Reject` reason 2).
    Quota,
    /// The destination cannot represent the manifest, for example names
    /// that collide after case folding with no authorized mapping (`Reject`
    /// reason 3, §7.1).
    UnsupportedDestination,
}

/// Storing or publishing failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SinkError {
    /// Writing, syncing, or publishing failed (`STORAGE`).
    Storage,
    /// A complete file did not have the manifest's exact length or BLAKE3
    /// root at publication (§7.7); nothing was published.
    Integrity,
}

impl fmt::Display for SinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Storage => "storing the file failed",
            Self::Integrity => "the stored file does not match the manifest",
        })
    }
}

impl std::error::Error for SinkError {}

/// What a receiver kept from an earlier session of a transfer (§7.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Retained {
    /// The manifest the earlier Accept named.
    pub manifest_hash: [u8; 32],
    /// The earlier selection; a resumed transfer must repeat it exactly.
    pub selection: Vec<u32>,
}

/// The receiver's destination for one device's incoming transfers. It
/// outlives sessions: retained partial data, accepted selections, and
/// cancel tombstones carry over to the next session (§7.5, §7.6).
///
/// Nothing reaches a sink before consent: the engine calls
/// [`Self::store_segment`] only with a [`VerifiedSegment`], which only
/// exists after the content layer opened a segment with an accepted file's
/// key and verified it against the manifest root.
pub trait ReceiveSink {
    /// Before the consent prompt: whether this destination can hold the
    /// manifest, including filesystem-imposed name collisions (§7.1) and
    /// quota. Must not create files.
    ///
    /// # Errors
    ///
    /// The [`SinkRefusal`] to reject with.
    fn check_offer(&mut self, manifest: &CanonicalManifest) -> Result<(), SinkRefusal>;

    /// Whether `transfer_id` was cancelled or its resumable state revoked
    /// (§7.6, §7.5). A tombstoned ID is never offered again.
    fn is_tombstoned(&self, transfer_id: &TransferId, now: UnixTime) -> bool;

    /// Tombstones `transfer_id` until at least `until` and deletes its
    /// temporary data (§7.6).
    fn tombstone(&mut self, transfer_id: &TransferId, until: UnixTime);

    /// Whether the tombstone store has room for more (it may first drop
    /// tombstones that expired before `now`). While it has none, the engine
    /// takes no new incoming transfer ID: it closes the session with
    /// `LIMIT` at the next `ManifestStart`.
    ///
    /// **Requirement for implementations (P08):** tombstone storage must be
    /// bounded, and the bound is enforced here, never by dropping a
    /// tombstone before its `until` (§7.6 requires it to survive). Every
    /// tombstone belongs to a transfer ID a session admitted, and a session
    /// admits at most [`crate::limits::MAX_INCOMING_TRANSFER_IDS`], so a
    /// store that answers `false` at `N` live tombstones never holds more
    /// than `N` plus that many per session that was already running.
    fn tombstone_room(&mut self, now: UnixTime) -> bool;

    /// What an earlier session retained for `transfer_id`, unless it
    /// expired (§7.5: at most the manifest's expiry).
    fn retained(&self, transfer_id: &TransferId, now: UnixTime) -> Option<Retained>;

    /// Durably records this session's verified Accept, before it is sent
    /// (§7.2).
    ///
    /// # Errors
    ///
    /// [`SinkError::Storage`]; the Accept is then not sent.
    fn record_accept(
        &mut self,
        manifest: &CanonicalManifest,
        accept: &VerifiedAccept,
    ) -> Result<(), SinkError>;

    /// The stored content ciphertext of a retained segment, for
    /// revalidation under this session's key before it counts (§7.5).
    ///
    /// # Errors
    ///
    /// [`SinkError::Storage`].
    fn retained_segment(
        &mut self,
        transfer_id: &TransferId,
        file_id: u32,
        index: u32,
    ) -> Result<Option<Vec<u8>>, SinkError>;

    /// Drops a retained segment that failed revalidation.
    fn drop_segment(&mut self, transfer_id: &TransferId, file_id: u32, index: u32);

    /// Durably stores a verified segment and its content ciphertext (kept
    /// for revalidation on resume). The request retires only after this
    /// succeeds (§7.4).
    ///
    /// # Errors
    ///
    /// [`SinkError::Storage`].
    fn store_segment(
        &mut self,
        segment: &VerifiedSegment,
        ciphertext: &[u8],
    ) -> Result<(), SinkError>;

    /// Checks the complete file's exact length and whole-file BLAKE3 root
    /// against the manifest, then publishes it without path escape,
    /// symlink substitution, or overwrite, atomically where the platform
    /// allows, and durably (§7.7).
    ///
    /// # Errors
    ///
    /// [`SinkError::Integrity`] or [`SinkError::Storage`]; nothing is
    /// published then.
    fn publish(&mut self, manifest: &CanonicalManifest, file_id: u32) -> Result<(), SinkError>;

    /// Whether file `file_id` was already published by an earlier session
    /// of this transfer **and** still matches the manifest: re-hashed now,
    /// exact length and whole-file BLAKE3 root (§7.5: disk metadata alone
    /// is insufficient). A resumed transfer does not fetch such a file
    /// again.
    fn published_intact(&mut self, manifest: &CanonicalManifest, file_id: u32) -> bool;

    /// The transfer completed: its temporary data can go, but its record
    /// (manifest hash and selection) stays until the manifest expires, so
    /// that a re-offer of the same transfer must repeat the selection and
    /// finds its files already published (§7.3: a new selection needs a new
    /// transfer ID; §7.7: no silent retransfer).
    fn finish(&mut self, transfer_id: &TransferId);

    /// `sender` was revoked: every transfer it sent becomes tombstoned
    /// until at least `until` and its temporary data is deleted (§7.5).
    fn revoke_sender(&mut self, sender: &Ed25519PublicKey, until: UnixTime);
}

/// One in-memory source file with its outboard and root.
#[derive(Clone, PartialEq, Eq)]
pub struct MemoryFile {
    content: Vec<u8>,
    outboard: Vec<u8>,
    root: [u8; 32],
}

impl MemoryFile {
    /// Hashes `content` and builds its outboard.
    #[must_use]
    pub fn new(content: Vec<u8>) -> Self {
        let (tree, root) = outboard(&content);
        Self {
            content,
            outboard: tree,
            root,
        }
    }

    /// The BLAKE3 root for the manifest.
    #[must_use]
    pub const fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// The size for the manifest.
    #[must_use]
    pub fn size(&self) -> u64 {
        u64::try_from(self.content.len()).unwrap_or(u64::MAX)
    }

    /// Mutable access to the content, to test source-mutation detection.
    pub fn content_mut(&mut self) -> &mut Vec<u8> {
        &mut self.content
    }
}

impl fmt::Debug for MemoryFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryFile")
            .field("size", &self.content.len())
            .finish_non_exhaustive()
    }
}

/// An in-memory [`SendSource`].
#[derive(Clone, Debug, Default)]
pub struct MemorySource {
    files: BTreeMap<(TransferId, u32), MemoryFile>,
}

impl MemorySource {
    /// An empty source.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds file `file_id` of `transfer_id`.
    pub fn insert(&mut self, transfer_id: TransferId, file_id: u32, file: MemoryFile) {
        self.files.insert((transfer_id, file_id), file);
    }

    /// The stored file, mutably.
    pub fn file_mut(&mut self, transfer_id: &TransferId, file_id: u32) -> Option<&mut MemoryFile> {
        self.files.get_mut(&(*transfer_id, file_id))
    }
}

impl SendSource for MemorySource {
    type Content<'a> = Cursor<&'a [u8]>;
    type Outboard<'a> = Cursor<&'a [u8]>;

    fn open(
        &mut self,
        transfer_id: &TransferId,
        file_id: u32,
    ) -> Result<(Cursor<&[u8]>, Cursor<&[u8]>), SourceError> {
        let file = self
            .files
            .get(&(*transfer_id, file_id))
            .ok_or(SourceError::NotFound)?;
        Ok((
            Cursor::new(file.content.as_slice()),
            Cursor::new(file.outboard.as_slice()),
        ))
    }
}

struct StoredSegment {
    plaintext: Zeroizing<Vec<u8>>,
    ciphertext: Vec<u8>,
}

struct MemoryTransfer {
    sender: Ed25519PublicKey,
    manifest_hash: [u8; 32],
    expires_at: UnixTime,
    selection: Vec<u32>,
    segments: BTreeMap<(u32, u32), StoredSegment>,
}

/// An in-memory [`ReceiveSink`]: retained transfers, tombstones, and
/// published files. It accepts every manifest unless told to refuse, and
/// can be told to fail writes, for tests. It keeps at most
/// [`Self::TOMBSTONE_LIMIT`] unexpired tombstones before reporting no room
/// (adjustable for tests).
#[derive(Default)]
pub struct MemorySink {
    transfers: BTreeMap<TransferId, MemoryTransfer>,
    tombstones: BTreeMap<TransferId, UnixTime>,
    published: BTreeMap<(TransferId, u32), Zeroizing<Vec<u8>>>,
    refusal: Option<SinkRefusal>,
    failing: bool,
    tombstone_limit: Option<usize>,
}

impl MemorySink {
    /// An empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes [`ReceiveSink::check_offer`] refuse with `refusal`.
    pub fn set_refusal(&mut self, refusal: Option<SinkRefusal>) {
        self.refusal = refusal;
    }

    /// Makes every write fail while `failing`.
    pub fn set_failing(&mut self, failing: bool) {
        self.failing = failing;
    }

    /// The default bound on unexpired tombstones: 4096.
    pub const TOMBSTONE_LIMIT: usize = 4096;

    /// Changes the bound on unexpired tombstones.
    pub fn set_tombstone_limit(&mut self, limit: usize) {
        self.tombstone_limit = Some(limit);
    }

    /// How many tombstones are kept, expired or not.
    #[must_use]
    pub fn tombstone_count(&self) -> usize {
        self.tombstones.len()
    }

    /// The published content of `file_id`.
    #[must_use]
    pub fn published(&self, transfer_id: &TransferId, file_id: u32) -> Option<&[u8]> {
        self.published
            .get(&(*transfer_id, file_id))
            .map(|data| data.as_slice())
    }

    /// How many files are published, across transfers.
    #[must_use]
    pub fn published_count(&self) -> usize {
        self.published.len()
    }

    /// How many verified segments are stored, across transfers.
    #[must_use]
    pub fn stored_count(&self) -> usize {
        self.transfers
            .values()
            .map(|transfer| transfer.segments.len())
            .sum()
    }

    /// How many verified segments are stored for `transfer_id`.
    #[must_use]
    pub fn stored_segments(&self, transfer_id: &TransferId) -> usize {
        self.transfers
            .get(transfer_id)
            .map_or(0, |transfer| transfer.segments.len())
    }

    /// Whether segment `index` of `file_id` is stored (not yet published).
    #[must_use]
    pub fn has_segment(&self, transfer_id: &TransferId, file_id: u32, index: u32) -> bool {
        self.transfers
            .get(transfer_id)
            .is_some_and(|transfer| transfer.segments.contains_key(&(file_id, index)))
    }

    /// Changes one stored ciphertext byte, to test revalidation.
    pub fn corrupt_segment(&mut self, transfer_id: &TransferId, file_id: u32, index: u32) {
        if let Some(segment) = self
            .transfers
            .get_mut(transfer_id)
            .and_then(|transfer| transfer.segments.get_mut(&(file_id, index)))
            && let Some(byte) = segment.ciphertext.last_mut()
        {
            *byte ^= 1;
        }
    }
}

impl fmt::Debug for MemorySink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemorySink")
            .field("transfers", &self.transfers.len())
            .field("tombstones", &self.tombstones.len())
            .field("published", &self.published.len())
            .finish_non_exhaustive()
    }
}

impl ReceiveSink for MemorySink {
    fn check_offer(&mut self, _manifest: &CanonicalManifest) -> Result<(), SinkRefusal> {
        self.refusal.map_or(Ok(()), Err)
    }

    fn is_tombstoned(&self, transfer_id: &TransferId, now: UnixTime) -> bool {
        self.tombstones
            .get(transfer_id)
            .is_some_and(|&until| now <= until)
    }

    fn tombstone(&mut self, transfer_id: &TransferId, until: UnixTime) {
        self.transfers.remove(transfer_id);
        let entry = self.tombstones.entry(*transfer_id).or_insert(until);
        *entry = (*entry).max(until);
    }

    fn tombstone_room(&mut self, now: UnixTime) -> bool {
        self.tombstones.retain(|_, until| now <= *until);
        self.tombstones.len() < self.tombstone_limit.unwrap_or(Self::TOMBSTONE_LIMIT)
    }

    fn retained(&self, transfer_id: &TransferId, now: UnixTime) -> Option<Retained> {
        self.transfers
            .get(transfer_id)
            .filter(|transfer| now < transfer.expires_at)
            .map(|transfer| Retained {
                manifest_hash: transfer.manifest_hash,
                selection: transfer.selection.clone(),
            })
    }

    fn record_accept(
        &mut self,
        manifest: &CanonicalManifest,
        accept: &VerifiedAccept,
    ) -> Result<(), SinkError> {
        if self.failing {
            return Err(SinkError::Storage);
        }
        let transfer = self
            .transfers
            .entry(*accept.transfer_id())
            .or_insert_with(|| MemoryTransfer {
                sender: *manifest.sender(),
                manifest_hash: *manifest.hash(),
                expires_at: manifest.expires_at(),
                selection: Vec::new(),
                segments: BTreeMap::new(),
            });
        if transfer.manifest_hash != *manifest.hash() {
            // A different manifest under the same ID: nothing carries over.
            transfer.segments.clear();
            transfer.manifest_hash = *manifest.hash();
        }
        transfer.sender = *manifest.sender();
        transfer.expires_at = manifest.expires_at();
        transfer.selection = accept.selection().to_vec();
        Ok(())
    }

    fn retained_segment(
        &mut self,
        transfer_id: &TransferId,
        file_id: u32,
        index: u32,
    ) -> Result<Option<Vec<u8>>, SinkError> {
        Ok(self
            .transfers
            .get(transfer_id)
            .and_then(|transfer| transfer.segments.get(&(file_id, index)))
            .map(|segment| segment.ciphertext.clone()))
    }

    fn drop_segment(&mut self, transfer_id: &TransferId, file_id: u32, index: u32) {
        if let Some(transfer) = self.transfers.get_mut(transfer_id) {
            transfer.segments.remove(&(file_id, index));
        }
    }

    fn store_segment(
        &mut self,
        segment: &VerifiedSegment,
        ciphertext: &[u8],
    ) -> Result<(), SinkError> {
        if self.failing {
            return Err(SinkError::Storage);
        }
        let transfer = self
            .transfers
            .get_mut(segment.transfer_id())
            .ok_or(SinkError::Storage)?;
        transfer.segments.insert(
            (segment.file_id(), segment.segment().index()),
            StoredSegment {
                plaintext: Zeroizing::new(segment.data().to_vec()),
                ciphertext: ciphertext.to_vec(),
            },
        );
        Ok(())
    }

    fn publish(&mut self, manifest: &CanonicalManifest, file_id: u32) -> Result<(), SinkError> {
        if self.failing {
            return Err(SinkError::Storage);
        }
        let binding = manifest.file(file_id).ok_or(SinkError::Integrity)?;
        let transfer = self
            .transfers
            .get_mut(manifest.transfer_id())
            .ok_or(SinkError::Storage)?;
        let size = binding.layout().size();
        let capacity = usize::try_from(size).map_err(|_| SinkError::Storage)?;
        let mut content = Zeroizing::new(Vec::with_capacity(capacity));
        for index in 0..binding.layout().count() {
            let segment = transfer
                .segments
                .get(&(file_id, index))
                .ok_or(SinkError::Integrity)?;
            content.extend_from_slice(&segment.plaintext);
        }
        // §7.7: exact length and whole-file BLAKE3 before publication.
        if u64::try_from(content.len()) != Ok(size)
            || blake3::hash(&content).as_bytes() != binding.root()
        {
            return Err(SinkError::Integrity);
        }
        for index in 0..binding.layout().count() {
            transfer.segments.remove(&(file_id, index));
        }
        self.published
            .insert((*manifest.transfer_id(), file_id), content);
        Ok(())
    }

    fn published_intact(&mut self, manifest: &CanonicalManifest, file_id: u32) -> bool {
        let Some(binding) = manifest.file(file_id) else {
            return false;
        };
        self.published
            .get(&(*manifest.transfer_id(), file_id))
            .is_some_and(|content| {
                u64::try_from(content.len()) == Ok(binding.layout().size())
                    && blake3::hash(content).as_bytes() == binding.root()
            })
    }

    fn finish(&mut self, transfer_id: &TransferId) {
        if let Some(transfer) = self.transfers.get_mut(transfer_id) {
            transfer.segments.clear();
        }
    }

    fn revoke_sender(&mut self, sender: &Ed25519PublicKey, until: UnixTime) {
        let revoked: Vec<TransferId> = self
            .transfers
            .iter()
            .filter(|(_, transfer)| transfer.sender == *sender)
            .map(|(id, _)| *id)
            .collect();
        for id in revoked {
            self.tombstone(&id, until);
        }
    }
}

/// The logical bytes of a segment: at most [`SEGMENT_LEN`].
pub(crate) fn segment_bytes(size: u64, index: u32) -> u64 {
    let start = u64::from(index) * u64::from(SEGMENT_LEN);
    size.saturating_sub(start).min(u64::from(SEGMENT_LEN))
}
