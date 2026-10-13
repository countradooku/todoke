//! [`FsSink`]: P07's [`ReceiveSink`] on a real filesystem.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{Read as _, Write as _};
use std::path::Path;

use todoke_crypto::consent::{CanonicalManifest, VerifiedAccept};
use todoke_crypto::content::{
    AcceptedFile, ContentOpener, FileMaster, SegmentLayout, VerifiedSegment,
};
use todoke_crypto::identity::{Ed25519PublicKey, Sealer};
use todoke_proto::time::UnixTime;
use todoke_transfer::{ReceiveSink, Retained, SinkError, SinkRefusal, TransferId};
use zeroize::Zeroizing;

use crate::dest::{DestError, Destination};
use crate::detect::{ContentReport, SNIFF_LEN, assess};
use crate::name::TEMP_PREFIX;
use crate::plan::{DestinationPlan, FsProfile};
use crate::quarantine::codec::{
    Corrupt, JournalEntry, JournalHeader, decode_journal, decode_tombstones, encode_tombstones,
};
use crate::quarantine::store::{
    self, Slots, StateDir, StateError, create_transfer_dir, hex, read_bounded, remove, remove_tree,
    unhex16, write_atomic,
};

/// When stored segments reach the disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Durability {
    /// Each segment is synced to the storage device before
    /// [`ReceiveSink::store_segment`] returns (PROTOCOL §7.4: "durably
    /// storing" before the request retires): `fdatasync` on Linux and
    /// Android, `FlushFileBuffers` on Windows, `fsync` on Apple platforms
    /// (whose drive-cache flush, `F_FULLFSYNC`, is kept for publication and
    /// state records). The default.
    EverySegment,
    /// Segments are written at once (they survive a crash of the app) and
    /// synced after every `bytes` of them and before publication; a power
    /// loss can lose the unsynced ones, which a resume then fetches again
    /// (§7.5 revalidates every retained segment either way).
    Periodic {
        /// Bytes of ciphertext between syncs.
        bytes: u64,
    },
}

/// [`FsSink`] settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SinkConfig {
    /// Name rules and path limits of the destination.
    pub profile: FsProfile,
    /// The most bytes of quarantine (ciphertext slots and manifests) all
    /// retained transfers may reserve together.
    pub quota_bytes: u64,
    /// When stored segments are synced.
    pub durability: Durability,
    /// The most unexpired tombstones before no new transfer is taken
    /// ([`ReceiveSink::tombstone_room`]).
    pub tombstone_limit: usize,
}

impl SinkConfig {
    /// The default quarantine quota: 64 GiB.
    pub const DEFAULT_QUOTA_BYTES: u64 = 64 << 30;
    /// The default tombstone bound: 4096.
    pub const DEFAULT_TOMBSTONE_LIMIT: usize = 4096;
}

impl Default for SinkConfig {
    fn default() -> Self {
        Self {
            profile: FsProfile::host(),
            quota_bytes: Self::DEFAULT_QUOTA_BYTES,
            durability: Durability::EverySegment,
            tombstone_limit: Self::DEFAULT_TOMBSTONE_LIMIT,
        }
    }
}

/// Opening an [`FsSink`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// Another sink, in this process or another, holds the state
    /// directory (one writer per directory).
    InUse,
    /// The tombstone list is damaged. The sink fails closed rather than
    /// forget cancelled transfers; the app must ask the user before
    /// resetting the receive state.
    CorruptTombstones,
    /// The state directory could not be used.
    Io(std::io::ErrorKind),
    /// The destination could not be used.
    Destination(DestError),
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InUse => f.write_str("the receive state is in use by another sink"),
            Self::CorruptTombstones => f.write_str("the cancelled-transfer list is damaged"),
            Self::Io(kind) => write!(f, "the receive state is unavailable: {kind}"),
            Self::Destination(error) => write!(f, "the destination is unavailable: {error}"),
        }
    }
}

impl std::error::Error for OpenError {}

/// Plans kept for offers that have not been accepted yet.
const OFFER_PLANS: usize = 16;
/// Bytes reserved per transfer besides its slots (journal, manifest).
const RECORD_OVERHEAD: u64 = 64 << 10;

/// One retained transfer.
struct Transfer {
    header: JournalHeader,
    /// Valid journal bytes; appends start here.
    journal_len: u64,
    top_dirs: BTreeMap<u32, String>,
    published: BTreeMap<u32, String>,
    finished: bool,
    /// This session's consent per keyed file (memory only).
    accepted: BTreeMap<u32, AcceptedFile>,
    /// Files whose sealed master is stored.
    keyed: BTreeSet<u32>,
    /// Open ciphertext slots of files being received.
    slots: BTreeMap<u32, Slots>,
    /// Files known to have no slots file yet (saves a failed open per
    /// requested segment).
    no_slots: BTreeSet<u32>,
    /// The destination plan (computed when first needed).
    plan: Option<DestinationPlan>,
    /// Sizes of the selected files.
    sizes: BTreeMap<u32, u64>,
    /// Quarantine bytes this transfer reserves.
    reserved: u64,
}

/// The receiver's [`ReceiveSink`] on a real filesystem: a private
/// quarantine (verified content ciphertext, sealed file masters, journals,
/// tombstones) in an application state directory, and publication into a
/// [`Destination`]. See the crate documentation for the guarantees.
pub struct FsSink<D: Destination, S: Sealer> {
    state: StateDir,
    destination: D,
    sealer: S,
    config: SinkConfig,
    transfers: BTreeMap<TransferId, Transfer>,
    tombstones: BTreeMap<TransferId, u64>,
    /// The tombstone list on disk is behind memory (a write failed).
    tombstones_dirty: bool,
    offers: VecDeque<(TransferId, DestinationPlan)>,
    reports: BTreeMap<(TransferId, u32), ContentReport>,
    unsynced: u64,
}

impl<D: Destination, S: Sealer> fmt::Debug for FsSink<D, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FsSink")
            .field("transfers", &self.transfers.len())
            .field("tombstones", &self.tombstones.len())
            .finish_non_exhaustive()
    }
}

fn storage<T>(_: T) -> SinkError {
    SinkError::Storage
}

/// The sealing context of a file master: domain, transfer, manifest hash,
/// file ID.
fn master_context(header: &JournalHeader, file_id: u32) -> Vec<u8> {
    let mut context = Vec::with_capacity(26 + 16 + 32 + 4);
    context.extend_from_slice(b"todoke/fs/v1/file-master\0");
    context.extend_from_slice(&header.transfer_id);
    context.extend_from_slice(&header.manifest_hash);
    context.extend_from_slice(&file_id.to_be_bytes());
    context
}

/// The temporary name of file `file_id` while it is published: derived
/// from the transfer's secret salt, so a crash leaves a name the next
/// start can find, and nobody else can predict it.
pub(crate) fn temp_name(header: &JournalHeader, file_id: u32) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"todoke/fs/v1/temp-name\0");
    hasher.update(&header.salt);
    hasher.update(&file_id.to_be_bytes());
    let digest = hasher.finalize();
    format!("{TEMP_PREFIX}{}.part", hex(&digest.as_bytes()[..10]))
}

impl<D: Destination, S: Sealer> FsSink<D, S> {
    /// Opens the quarantine in the private directory `state` (created if
    /// needed) for publication into `destination`, then cleans it up: it
    /// deletes transfers that expired by `now`, damaged ones, and
    /// temporary files a crash left in the destination.
    ///
    /// # Errors
    ///
    /// [`OpenError`].
    pub fn open(
        state: &Path,
        destination: D,
        sealer: S,
        config: SinkConfig,
        now: UnixTime,
    ) -> Result<Self, OpenError> {
        let state = StateDir::open(state).map_err(|error| match error {
            StateError::InUse => OpenError::InUse,
            StateError::Io(kind) => OpenError::Io(kind),
        })?;
        let tombstones = match read_bounded(&state.tombstones()) {
            Ok(bytes) => decode_tombstones(&bytes)
                .map_err(|Corrupt| OpenError::CorruptTombstones)?
                .into_iter()
                .collect(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(OpenError::Io(error.kind())),
        };
        let mut sink = Self {
            state,
            destination,
            sealer,
            config,
            transfers: BTreeMap::new(),
            tombstones,
            tombstones_dirty: false,
            offers: VecDeque::new(),
            reports: BTreeMap::new(),
            unsynced: 0,
        };
        sink.load(now)?;
        Ok(sink)
    }

    /// Loads every retained transfer, deleting expired and damaged ones.
    fn load(&mut self, now: UnixTime) -> Result<(), OpenError> {
        let entries = std::fs::read_dir(self.state.transfers())
            .map_err(|error| OpenError::Io(error.kind()))?;
        for entry in entries {
            let entry = entry.map_err(|error| OpenError::Io(error.kind()))?;
            let path = entry.path();
            let id = entry.file_name().to_str().and_then(unhex16);
            let loaded = id.and_then(|id| self.load_transfer(&id, &path).ok().map(|t| (id, t)));
            match loaded {
                Some((id, transfer))
                    if transfer.header.transfer_id == id
                        && now.seconds() < transfer.header.expires_at
                        && !self.tombstones.contains_key(&id) =>
                {
                    self.transfers.insert(id, transfer);
                    self.clean_temporaries(&id);
                }
                Some((id, transfer)) => {
                    self.transfers.insert(id, transfer);
                    self.discard_transfer(&id);
                }
                None => {
                    let _ = remove_tree(&path);
                }
            }
        }
        Ok(())
    }

    fn load_transfer(&self, id: &[u8; 16], path: &Path) -> Result<Transfer, Corrupt> {
        let bytes = read_bounded(&path.join("journal")).map_err(|_| Corrupt)?;
        let (header, entries, valid) = decode_journal(&bytes)?;
        if header.transfer_id != *id {
            return Err(Corrupt);
        }
        let mut transfer = Transfer {
            journal_len: valid as u64,
            top_dirs: BTreeMap::new(),
            published: BTreeMap::new(),
            finished: false,
            accepted: BTreeMap::new(),
            keyed: BTreeSet::new(),
            slots: BTreeMap::new(),
            no_slots: BTreeSet::new(),
            plan: None,
            sizes: BTreeMap::new(),
            reserved: 0,
            header,
        };
        for entry in entries {
            match entry {
                JournalEntry::TopDirectory { id, name } => {
                    transfer.top_dirs.insert(id, name);
                }
                JournalEntry::Published { id, name } => {
                    if transfer.header.selection.binary_search(&id).is_ok() {
                        transfer.published.insert(id, name);
                    }
                }
                JournalEntry::Finished => transfer.finished = true,
            }
        }
        for &file_id in &transfer.header.selection {
            if path.join(format!("k{file_id}")).exists() {
                transfer.keyed.insert(file_id);
            }
        }
        match self.stored_manifest(&transfer.header) {
            Ok(manifest) => {
                if !transfer.finished {
                    transfer.reserved = reservation(&manifest, &transfer.header.selection);
                }
                transfer.sizes = sizes(&manifest, &transfer.header.selection);
                transfer.plan = Some(self.plan_for(&manifest));
            }
            // A finished transfer needs only its journal (the engine
            // passes the manifest to re-check published files).
            Err(_) if transfer.finished => {}
            Err(error) => return Err(error),
        }
        Ok(transfer)
    }

    /// The canonical manifest stored with a transfer, checked against its
    /// journal.
    fn stored_manifest(&self, header: &JournalHeader) -> Result<CanonicalManifest, Corrupt> {
        let path = self.state.transfer(&header.transfer_id).join("manifest");
        let bytes = read_bounded(&path).map_err(|_| Corrupt)?;
        let manifest =
            CanonicalManifest::parse(bytes, &todoke_proto::transfer::ManifestLimits::SPEC)
                .map_err(|_| Corrupt)?;
        if *manifest.hash() != header.manifest_hash {
            return Err(Corrupt);
        }
        Ok(manifest)
    }

    /// The plan for `manifest` against the destination as it is now.
    fn plan_for(&self, manifest: &CanonicalManifest) -> DestinationPlan {
        let root = self.destination.root().ok();
        let destination = &self.destination;
        DestinationPlan::new(
            manifest.manifest(),
            &self.config.profile,
            self.destination.root_len(),
            // An unreadable name counts as taken.
            &mut |name| {
                root.as_ref()
                    .is_none_or(|root| destination.exists(root, name).unwrap_or(true))
            },
        )
    }

    /// The destination plan shown for an offer (or a retained transfer):
    /// exact local names, renames, warnings, and rejections.
    #[must_use]
    pub fn plan(&self, transfer_id: &TransferId) -> Option<&DestinationPlan> {
        self.transfers
            .get(transfer_id)
            .and_then(|transfer| transfer.plan.as_ref())
            .or_else(|| {
                self.offers
                    .iter()
                    .find(|(id, _)| id == transfer_id)
                    .map(|(_, plan)| plan)
            })
    }

    /// Where file `file_id` was published, from the destination root, if it
    /// was. Local data: never log it.
    #[must_use]
    pub fn published_path(&self, transfer_id: &TransferId, file_id: u32) -> Option<Vec<String>> {
        let transfer = self.transfers.get(transfer_id)?;
        let leaf = transfer.published.get(&file_id)?;
        let plan = transfer.plan.as_ref()?;
        let mut path = Self::directory_names(transfer, plan, file_id)?;
        path.push(leaf.clone());
        Some(path)
    }

    /// What content checking found in published file `file_id` (this
    /// session's publications only).
    #[must_use]
    pub fn content_report(&self, transfer_id: &TransferId, file_id: u32) -> Option<&ContentReport> {
        self.reports.get(&(*transfer_id, file_id))
    }

    /// Bytes of quarantine all retained transfers reserve.
    #[must_use]
    pub fn reserved_bytes(&self) -> u64 {
        self.transfers.values().map(|t| t.reserved).sum()
    }

    /// Deletes every transfer that expired by `now` and every tombstone
    /// that lapsed; [`ReceiveSink::tombstone_room`] does this too.
    pub fn sweep(&mut self, now: UnixTime) {
        let expired: Vec<TransferId> = self
            .transfers
            .iter()
            .filter(|(_, transfer)| now.seconds() >= transfer.header.expires_at)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.discard_transfer(&id);
        }
        let before = self.tombstones.len();
        self.tombstones.retain(|_, until| now.seconds() <= *until);
        if before != self.tombstones.len() {
            self.tombstones_dirty = true;
        }
        self.save_tombstones();
    }

    fn save_tombstones(&mut self) {
        if !self.tombstones_dirty {
            return;
        }
        let list: Vec<([u8; 16], u64)> = self.tombstones.iter().map(|(id, u)| (*id, *u)).collect();
        if write_atomic(&self.state.tombstones(), &encode_tombstones(&list)).is_ok() {
            self.tombstones_dirty = false;
        }
    }

    /// The local names of `file_id`'s directories, from the root.
    fn directory_names(
        transfer: &Transfer,
        plan: &DestinationPlan,
        file_id: u32,
    ) -> Option<Vec<String>> {
        let path = plan.local_path(file_id)?;
        let mut names = Vec::with_capacity(path.len());
        let mut id = plan.entry(file_id)?.parent();
        let mut ids = Vec::new();
        while id != 0 {
            ids.push(id);
            id = plan.entry(id)?.parent();
        }
        ids.reverse();
        for (depth, dir) in ids.iter().enumerate() {
            let name = if depth == 0 {
                transfer.top_dirs.get(dir)?.clone()
            } else {
                plan.entry(*dir)?.local().as_str().to_owned()
            };
            names.push(name);
        }
        Some(names)
    }

    /// Opens (and with `create`, creates) the directories of `file_id`,
    /// keeping every handle from the root down open.
    fn resolve(
        &mut self,
        transfer_id: &TransferId,
        file_id: u32,
        create: bool,
    ) -> Result<Vec<D::Dir>, SinkError> {
        let transfer = self.transfers.get(transfer_id).ok_or(SinkError::Storage)?;
        let plan = transfer.plan.as_ref().ok_or(SinkError::Storage)?;
        let mut ids = Vec::new();
        let mut id = plan.entry(file_id).ok_or(SinkError::Storage)?.parent();
        while id != 0 {
            ids.push(id);
            id = plan.entry(id).ok_or(SinkError::Storage)?.parent();
        }
        ids.reverse();
        let mut chain = vec![self.destination.root().map_err(storage)?];
        let Some((&top, nested)) = ids.split_first() else {
            return Ok(chain);
        };
        let root = chain.first().ok_or(SinkError::Storage)?;
        let existing = transfer.top_dirs.get(&top).cloned();
        let opened = match &existing {
            Some(name) => match self.destination.open_dir(root, name) {
                Ok(dir) => Some(dir),
                // The user removed it: create it again below.
                Err(DestError::NotFound) if create => None,
                Err(_) => return Err(SinkError::Storage),
            },
            None => None,
        };
        let top_dir = match opened {
            Some(dir) => dir,
            None if !create => return Err(SinkError::Storage),
            None => {
                let mut created = None;
                let local = plan
                    .entry(top)
                    .map(|entry| entry.local().as_str().to_owned());
                let candidates = local
                    .into_iter()
                    .chain(plan.candidates(top).map(|(_, name)| name));
                for name in candidates {
                    match self.destination.create_dir(root, &name) {
                        Ok(dir) => {
                            created = Some((dir, name));
                            break;
                        }
                        Err(DestError::Exists) => {}
                        Err(_) => return Err(SinkError::Storage),
                    }
                }
                let (dir, name) = created.ok_or(SinkError::Storage)?;
                self.destination.sync_dir(root).map_err(storage)?;
                self.append(transfer_id, &JournalEntry::TopDirectory { id: top, name })?;
                dir
            }
        };
        chain.push(top_dir);
        let transfer = self.transfers.get(transfer_id).ok_or(SinkError::Storage)?;
        let plan = transfer.plan.as_ref().ok_or(SinkError::Storage)?;
        for dir_id in nested {
            let name = plan
                .entry(*dir_id)
                .ok_or(SinkError::Storage)?
                .local()
                .as_str();
            let parent = chain.last().ok_or(SinkError::Storage)?;
            let next = if create {
                match self.destination.create_dir(parent, name) {
                    Ok(dir) => {
                        self.destination.sync_dir(parent).map_err(storage)?;
                        dir
                    }
                    // Inside this transfer's own directory: an earlier file
                    // made it (or someone put a directory there; links are
                    // refused).
                    Err(DestError::Exists) => {
                        self.destination.open_dir(parent, name).map_err(storage)?
                    }
                    Err(_) => return Err(SinkError::Storage),
                }
            } else {
                self.destination.open_dir(parent, name).map_err(storage)?
            };
            chain.push(next);
        }
        Ok(chain)
    }

    fn append(&mut self, transfer_id: &TransferId, entry: &JournalEntry) -> Result<(), SinkError> {
        let path = self.state.transfer(transfer_id).join("journal");
        let transfer = self
            .transfers
            .get_mut(transfer_id)
            .ok_or(SinkError::Storage)?;
        transfer.journal_len =
            store::append(&path, transfer.journal_len, &entry.encode()).map_err(storage)?;
        match entry {
            JournalEntry::TopDirectory { id, name } => {
                transfer.top_dirs.insert(*id, name.clone());
            }
            JournalEntry::Published { id, name } => {
                transfer.published.insert(*id, name.clone());
            }
            JournalEntry::Finished => transfer.finished = true,
        }
        Ok(())
    }

    /// Removes temporary files a crash left for this transfer's
    /// unpublished files.
    fn clean_temporaries(&mut self, transfer_id: &TransferId) {
        let Some(transfer) = self.transfers.get(transfer_id) else {
            return;
        };
        if transfer.plan.is_none() {
            return;
        }
        let pending: Vec<(u32, String)> = transfer
            .header
            .selection
            .iter()
            .filter(|id| !transfer.published.contains_key(id))
            .map(|&id| (id, temp_name(&transfer.header, id)))
            .collect();
        for (file_id, temp) in pending {
            if let Ok(chain) = self.resolve(transfer_id, file_id, false)
                && let Some(dir) = chain.last()
            {
                let _ = self.destination.discard(dir, &temp);
            }
        }
    }

    /// Deletes a transfer's quarantine: ciphertext, sealed masters,
    /// journal, and leftover temporary files. Published files stay.
    fn discard_transfer(&mut self, transfer_id: &TransferId) {
        self.clean_temporaries(transfer_id);
        self.transfers.remove(transfer_id);
        self.reports.retain(|(id, _), _| id != transfer_id);
        let _ = remove_tree(&self.state.transfer(transfer_id));
    }

    fn slots(
        &mut self,
        transfer_id: &TransferId,
        file_id: u32,
        create: bool,
    ) -> Result<Option<&mut Slots>, SinkError> {
        let path = self.state.transfer(transfer_id).join(format!("s{file_id}"));
        let transfer = self
            .transfers
            .get_mut(transfer_id)
            .ok_or(SinkError::Storage)?;
        if transfer.header.selection.binary_search(&file_id).is_err() {
            return Err(SinkError::Storage);
        }
        if !transfer.slots.contains_key(&file_id) {
            if !create && transfer.no_slots.contains(&file_id) {
                return Ok(None);
            }
            let size = *transfer.sizes.get(&file_id).ok_or(SinkError::Storage)?;
            let layout = SegmentLayout::new(size).map_err(storage)?;
            match Slots::open(&path, &layout, create) {
                Ok(slots) => {
                    transfer.no_slots.remove(&file_id);
                    transfer.slots.insert(file_id, slots);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    transfer.no_slots.insert(file_id);
                    return Ok(None);
                }
                Err(_) => return Err(SinkError::Storage),
            }
        }
        Ok(transfer.slots.get_mut(&file_id))
    }

    /// Publishes one file: see [`ReceiveSink::publish`].
    fn publish_file(
        &mut self,
        manifest: &CanonicalManifest,
        file_id: u32,
    ) -> Result<(), SinkError> {
        let transfer_id = *manifest.transfer_id();
        let binding = *manifest.file(file_id).ok_or(SinkError::Integrity)?;
        let (header, accepted) = {
            let transfer = self.transfers.get(&transfer_id).ok_or(SinkError::Storage)?;
            if transfer.header.manifest_hash != *manifest.hash()
                || transfer.header.selection.binary_search(&file_id).is_err()
            {
                return Err(SinkError::Storage);
            }
            if transfer.published.contains_key(&file_id) {
                return Ok(());
            }
            let accepted = *transfer.accepted.get(&file_id).ok_or(SinkError::Storage)?;
            (transfer.header.clone(), accepted)
        };
        let sealed = read_bounded(
            &self
                .state
                .transfer(&transfer_id)
                .join(format!("k{file_id}")),
        )
        .map_err(storage)?;
        let master =
            FileMaster::open_sealed(&self.sealer, &master_context(&header, file_id), &sealed)
                .map_err(storage)?;
        let opener = ContentOpener::new(&accepted, &master).map_err(storage)?;
        drop(master);
        let chain = self.resolve(&transfer_id, file_id, true)?;
        let dir = chain.last().ok_or(SinkError::Storage)?;
        let temp = temp_name(&header, file_id);
        self.destination.discard(dir, &temp).map_err(storage)?;
        let mut staged = self.destination.stage(dir, &temp).map_err(storage)?;
        let written = self.write_plaintext(&transfer_id, file_id, &opener, &mut staged);
        let (length, root, prefix) = match written {
            Ok(result) => result,
            Err(error) => {
                drop(staged);
                let _ = self.destination.discard(dir, &temp);
                return Err(error);
            }
        };
        // §7.7: exact length and whole-file BLAKE3 before publication.
        if length != binding.layout().size() || root != *binding.root() {
            drop(staged);
            let _ = self.destination.discard(dir, &temp);
            return Err(SinkError::Integrity);
        }
        if self.destination.finish_staged(staged).is_err() {
            let _ = self.destination.discard(dir, &temp);
            return Err(SinkError::Storage);
        }
        let name = match self.commit(&transfer_id, file_id, dir, &temp) {
            Ok(name) => name,
            Err(error) => {
                let _ = self.destination.discard(dir, &temp);
                return Err(error);
            }
        };
        self.destination.sync_dir(dir).map_err(storage)?;
        drop(chain);
        self.append(
            &transfer_id,
            &JournalEntry::Published {
                id: file_id,
                name: name.clone(),
            },
        )?;
        let mime = manifest
            .manifest()
            .entry(file_id)
            .map_or("application/octet-stream", |entry| entry.mime());
        self.reports
            .insert((transfer_id, file_id), assess(&prefix, &name, mime));
        // The file is published: its ciphertext and master can go.
        let base = self.state.transfer(&transfer_id);
        if let Some(transfer) = self.transfers.get_mut(&transfer_id) {
            transfer.slots.remove(&file_id);
            transfer.keyed.remove(&file_id);
            transfer.accepted.remove(&file_id);
        }
        let _ = remove(&base.join(format!("s{file_id}")));
        let _ = remove(&base.join(format!("k{file_id}")));
        Ok(())
    }

    /// Decrypts and verifies every stored segment into `staged`, hashing
    /// as it goes. Returns the length, the BLAKE3 root, and the first
    /// bytes for type detection.
    fn write_plaintext(
        &mut self,
        transfer_id: &TransferId,
        file_id: u32,
        opener: &ContentOpener,
        staged: &mut D::Staged,
    ) -> Result<Written, SinkError> {
        let count = opener.binding().layout().count();
        let slots = self
            .slots(transfer_id, file_id, false)?
            .ok_or(SinkError::Integrity)?;
        let mut hasher = blake3::Hasher::new();
        let mut length = 0_u64;
        let mut prefix = Zeroizing::new(Vec::new());
        for index in 0..count {
            let ciphertext = slots
                .read(index)
                .map_err(storage)?
                .ok_or(SinkError::Integrity)?;
            let segment = opener
                .open_segment(index, &ciphertext)
                .map_err(|_| SinkError::Integrity)?;
            let data = segment.data();
            staged.write_all(data).map_err(storage)?;
            hasher.update(data);
            length = length.saturating_add(data.len() as u64);
            if prefix.len() < SNIFF_LEN {
                let take = (SNIFF_LEN - prefix.len()).min(data.len());
                prefix.extend_from_slice(&data[..take]);
            }
        }
        Ok((length, *hasher.finalize().as_bytes(), prefix))
    }

    /// Publishes the staged file under its planned name, or the next free
    /// candidate; never replaces anything.
    fn commit(
        &self,
        transfer_id: &TransferId,
        file_id: u32,
        dir: &D::Dir,
        temp: &str,
    ) -> Result<String, SinkError> {
        let plan = self
            .transfers
            .get(transfer_id)
            .and_then(|transfer| transfer.plan.as_ref())
            .ok_or(SinkError::Storage)?;
        let entry = plan.entry(file_id).ok_or(SinkError::Storage)?;
        let candidates = core::iter::once(entry.local().as_str().to_owned())
            .chain(plan.candidates(file_id).map(|(_, name)| name));
        for name in candidates {
            match self.destination.publish(dir, temp, &name) {
                Ok(_) => return Ok(name),
                Err(DestError::Exists) => {}
                Err(_) => return Err(SinkError::Storage),
            }
        }
        Err(SinkError::Storage)
    }

    /// Re-hashes published file `file_id` (§7.5).
    fn intact(&mut self, manifest: &CanonicalManifest, file_id: u32) -> Option<bool> {
        let transfer_id = *manifest.transfer_id();
        let binding = *manifest.file(file_id)?;
        let transfer = self.transfers.get_mut(&transfer_id)?;
        if transfer.header.manifest_hash != *manifest.hash() {
            return Some(false);
        }
        let name = transfer.published.get(&file_id)?.clone();
        if transfer.plan.is_none() {
            let plan = DestinationPlan::new(
                manifest.manifest(),
                &self.config.profile,
                self.destination.root_len(),
                &mut |_| false,
            );
            self.transfers.get_mut(&transfer_id)?.plan = Some(plan);
        }
        let chain = self.resolve(&transfer_id, file_id, false).ok()?;
        let mut file = self.destination.open_file(chain.last()?, &name).ok()?;
        let mut hasher = blake3::Hasher::new();
        let mut buffer = Zeroizing::new(vec![0; 1 << 16]);
        let mut length = 0_u64;
        loop {
            let read = file.read(&mut buffer).ok()?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
            length = length.saturating_add(read as u64);
            if length > binding.layout().size() {
                return Some(false);
            }
        }
        Some(length == binding.layout().size() && hasher.finalize().as_bytes() == binding.root())
    }

    /// The quarantine bytes still free.
    fn available(&self) -> u64 {
        self.config
            .quota_bytes
            .saturating_sub(self.reserved_bytes())
    }
}

/// The sizes of `selection`'s files.
fn sizes(manifest: &CanonicalManifest, selection: &[u32]) -> BTreeMap<u32, u64> {
    selection
        .iter()
        .filter_map(|&id| {
            manifest
                .file(id)
                .map(|binding| (id, binding.layout().size()))
        })
        .collect()
}

/// What [`FsSink::write_plaintext`] wrote: the length, the BLAKE3 root,
/// and the first bytes for type detection.
type Written = (u64, [u8; 32], Zeroizing<Vec<u8>>);

/// The quarantine bytes `selection` of `manifest` needs.
fn reservation(manifest: &CanonicalManifest, selection: &[u32]) -> u64 {
    let slots: u64 = selection
        .iter()
        .filter_map(|&id| manifest.file(id))
        .map(|binding| Slots::reservation(binding.layout()))
        .fold(0, u64::saturating_add);
    slots
        .saturating_add(manifest.bytes().len() as u64)
        .saturating_add(RECORD_OVERHEAD)
}

impl<D: Destination, S: Sealer> ReceiveSink for FsSink<D, S> {
    fn check_offer(&mut self, manifest: &CanonicalManifest) -> Result<(), SinkRefusal> {
        let plan = self.plan_for(manifest);
        if !plan.any_file_storable() {
            return Err(SinkRefusal::UnsupportedDestination);
        }
        let transfer_id = *manifest.transfer_id();
        let retained = self
            .transfers
            .get(&transfer_id)
            .is_some_and(|transfer| transfer.header.manifest_hash == *manifest.hash());
        let smallest = manifest
            .files()
            .iter()
            .filter(|binding| {
                plan.entry(binding.file_id())
                    .is_some_and(|entry| entry.rejection().is_none())
            })
            .map(|binding| reservation(manifest, &[binding.file_id()]))
            .min()
            .unwrap_or(u64::MAX);
        if !retained && smallest > self.available() {
            return Err(SinkRefusal::Quota);
        }
        self.offers.retain(|(id, _)| *id != transfer_id);
        if self.offers.len() >= OFFER_PLANS {
            self.offers.pop_front();
        }
        self.offers.push_back((transfer_id, plan));
        Ok(())
    }

    fn is_tombstoned(&self, transfer_id: &TransferId, now: UnixTime) -> bool {
        self.tombstones
            .get(transfer_id)
            .is_some_and(|&until| now.seconds() <= until)
    }

    fn tombstone(&mut self, transfer_id: &TransferId, until: UnixTime) {
        // The tombstone first, so a crash can never forget the cancel.
        let entry = self
            .tombstones
            .entry(*transfer_id)
            .or_insert(until.seconds());
        *entry = (*entry).max(until.seconds());
        self.tombstones_dirty = true;
        self.save_tombstones();
        self.offers.retain(|(id, _)| id != transfer_id);
        self.discard_transfer(transfer_id);
    }

    fn tombstone_room(&mut self, now: UnixTime) -> bool {
        self.sweep(now);
        self.tombstones.len() < self.config.tombstone_limit
    }

    fn retained(&self, transfer_id: &TransferId, now: UnixTime) -> Option<Retained> {
        self.transfers
            .get(transfer_id)
            .filter(|transfer| now.seconds() < transfer.header.expires_at)
            .map(|transfer| Retained {
                manifest_hash: transfer.header.manifest_hash,
                selection: transfer.header.selection.clone(),
            })
    }

    fn record_accept(
        &mut self,
        manifest: &CanonicalManifest,
        accept: &VerifiedAccept,
    ) -> Result<(), SinkError> {
        let transfer_id = *accept.transfer_id();
        if *manifest.transfer_id() != transfer_id || *accept.manifest_hash() != *manifest.hash() {
            return Err(SinkError::Storage);
        }
        if let Some(transfer) = self.transfers.get_mut(&transfer_id)
            && transfer.header.manifest_hash == *manifest.hash()
            && transfer.header.selection == accept.selection()
        {
            // A resumed transfer: the record is already durable. This
            // session's consent replaces the last one's.
            transfer.accepted.clear();
            return Ok(());
        }
        let plan = self
            .offers
            .iter()
            .find(|(id, _)| *id == transfer_id)
            .map_or_else(|| self.plan_for(manifest), |(_, plan)| plan.clone());
        if !plan.accepts(accept.selection()) {
            return Err(SinkError::Storage);
        }
        // A different manifest under this ID: nothing carries over.
        self.discard_transfer(&transfer_id);
        let needed = reservation(manifest, accept.selection());
        if needed > self.available() {
            return Err(SinkError::Storage);
        }
        let mut salt = [0; 32];
        getrandom::fill(&mut salt).map_err(storage)?;
        let header = JournalHeader {
            transfer_id,
            manifest_hash: *manifest.hash(),
            sender: *manifest.sender().as_bytes(),
            expires_at: manifest.expires_at().seconds(),
            salt,
            selection: accept.selection().to_vec(),
        };
        let dir = self.state.transfer(&transfer_id);
        let written = create_transfer_dir(&dir)
            .and_then(|()| write_atomic(&dir.join("manifest"), manifest.bytes()))
            .and_then(|()| write_atomic(&dir.join("journal"), &header.encode()))
            .and_then(|()| store::sync_dir(&self.state.transfers()));
        if written.is_err() {
            let _ = remove_tree(&dir);
            return Err(SinkError::Storage);
        }
        let journal_len = header.encode().len() as u64;
        self.offers.retain(|(id, _)| *id != transfer_id);
        self.transfers.insert(
            transfer_id,
            Transfer {
                header,
                journal_len,
                top_dirs: BTreeMap::new(),
                published: BTreeMap::new(),
                finished: false,
                accepted: BTreeMap::new(),
                keyed: BTreeSet::new(),
                slots: BTreeMap::new(),
                no_slots: BTreeSet::new(),
                plan: Some(plan),
                sizes: sizes(manifest, accept.selection()),
                reserved: needed,
            },
        );
        Ok(())
    }

    fn record_file_key(
        &mut self,
        file: &AcceptedFile,
        master: &FileMaster,
    ) -> Result<(), SinkError> {
        let binding = file.binding();
        let transfer_id = *binding.transfer_id();
        let file_id = binding.file_id();
        let path = self
            .state
            .transfer(&transfer_id)
            .join(format!("k{file_id}"));
        let transfer = self.transfers.get(&transfer_id).ok_or(SinkError::Storage)?;
        if transfer.header.manifest_hash != *binding.manifest_hash()
            || transfer.header.selection.binary_search(&file_id).is_err()
        {
            return Err(SinkError::Storage);
        }
        let context = master_context(&transfer.header, file_id);
        let same = transfer.keyed.contains(&file_id)
            && read_bounded(&path)
                .ok()
                .and_then(|sealed| FileMaster::open_sealed(&self.sealer, &context, &sealed).ok())
                .is_some_and(|stored| stored.ct_eq(master));
        if !same {
            // §8 requires the original master on resume; under any other,
            // retained ciphertext cannot open, so it goes.
            if let Some(transfer) = self.transfers.get_mut(&transfer_id) {
                transfer.slots.remove(&file_id);
            }
            remove(
                &self
                    .state
                    .transfer(&transfer_id)
                    .join(format!("s{file_id}")),
            )
            .map_err(storage)?;
            let sealed = master.seal(&self.sealer, &context).map_err(storage)?;
            write_atomic(&path, &sealed).map_err(storage)?;
        }
        let transfer = self
            .transfers
            .get_mut(&transfer_id)
            .ok_or(SinkError::Storage)?;
        transfer.keyed.insert(file_id);
        transfer.accepted.insert(file_id, *file);
        Ok(())
    }

    fn retained_segment(
        &mut self,
        transfer_id: &TransferId,
        file_id: u32,
        index: u32,
    ) -> Result<Option<Vec<u8>>, SinkError> {
        match self.slots(transfer_id, file_id, false)? {
            Some(slots) => slots.read(index).map_err(storage),
            None => Ok(None),
        }
    }

    fn drop_segment(&mut self, transfer_id: &TransferId, file_id: u32, index: u32) {
        if let Ok(Some(slots)) = self.slots(transfer_id, file_id, false) {
            let _ = slots.clear(index);
        }
    }

    fn store_segment(
        &mut self,
        segment: &VerifiedSegment,
        ciphertext: &[u8],
    ) -> Result<(), SinkError> {
        let transfer_id = *segment.transfer_id();
        let file_id = segment.file_id();
        let keyed = self
            .transfers
            .get(&transfer_id)
            .is_some_and(|transfer| transfer.keyed.contains(&file_id));
        if !keyed {
            return Err(SinkError::Storage);
        }
        let durability = self.config.durability;
        let slots = self
            .slots(&transfer_id, file_id, true)?
            .ok_or(SinkError::Storage)?;
        slots
            .write(segment.segment().index(), ciphertext)
            .map_err(storage)?;
        match durability {
            Durability::EverySegment => slots.sync().map_err(storage)?,
            Durability::Periodic { bytes } => {
                self.unsynced = self.unsynced.saturating_add(ciphertext.len() as u64);
                if self.unsynced >= bytes {
                    self.sync_all_slots()?;
                }
            }
        }
        Ok(())
    }

    fn publish(&mut self, manifest: &CanonicalManifest, file_id: u32) -> Result<(), SinkError> {
        if matches!(self.config.durability, Durability::Periodic { .. }) {
            self.sync_all_slots()?;
        }
        self.publish_file(manifest, file_id)
    }

    fn published_intact(&mut self, manifest: &CanonicalManifest, file_id: u32) -> bool {
        self.intact(manifest, file_id).unwrap_or(false)
    }

    fn finish(&mut self, transfer_id: &TransferId) {
        if self
            .transfers
            .get(transfer_id)
            .is_none_or(|transfer| transfer.finished)
        {
            return;
        }
        let _ = self.append(transfer_id, &JournalEntry::Finished);
        let base = self.state.transfer(transfer_id);
        if let Some(transfer) = self.transfers.get_mut(transfer_id) {
            transfer.slots.clear();
            transfer.accepted.clear();
            transfer.keyed.clear();
            transfer.reserved = 0;
            for &file_id in &transfer.header.selection {
                let _ = remove(&base.join(format!("s{file_id}")));
                let _ = remove(&base.join(format!("k{file_id}")));
            }
        }
    }

    fn revoke_sender(&mut self, sender: &Ed25519PublicKey, until: UnixTime) {
        let revoked: Vec<TransferId> = self
            .transfers
            .iter()
            .filter(|(_, transfer)| transfer.header.sender == *sender.as_bytes())
            .map(|(id, _)| *id)
            .collect();
        for id in revoked {
            self.tombstone(&id, until);
        }
    }
}

impl<D: Destination, S: Sealer> FsSink<D, S> {
    fn sync_all_slots(&mut self) -> Result<(), SinkError> {
        for transfer in self.transfers.values() {
            for slots in transfer.slots.values() {
                slots.sync().map_err(storage)?;
            }
        }
        self.unsynced = 0;
        Ok(())
    }
}
