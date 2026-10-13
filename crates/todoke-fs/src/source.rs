//! [`FsSource`]: P07's [`SendSource`] on real files.

use core::fmt;
use std::collections::BTreeMap;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use todoke_crypto::content::write_outboard;
use todoke_transfer::{SendSource, SourceError, TransferId};

use crate::quarantine::store::{hex, remove, remove_tree};

/// What identifies a file's state: if any of it changes, the content may
/// have changed (§8: the sender must snapshot or detect mutation).
#[derive(Clone, Copy, PartialEq, Eq)]
struct Fingerprint {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    identity: (u64, u64, i64, i64),
    #[cfg(windows)]
    identity: (u64, u64),
}

impl Fingerprint {
    fn of(metadata: &Metadata) -> Self {
        Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            identity: {
                use std::os::unix::fs::MetadataExt as _;
                (
                    metadata.dev(),
                    metadata.ino(),
                    metadata.ctime(),
                    metadata.ctime_nsec(),
                )
            },
            #[cfg(windows)]
            identity: {
                use std::os::windows::fs::MetadataExt as _;
                (metadata.creation_time(), metadata.last_write_time())
            },
        }
    }
}

/// A source file opened and hashed for an offer: its BLAKE3 root and size
/// go into the manifest (§7.1).
pub struct PreparedFile {
    file: File,
    outboard: File,
    outboard_path: PathBuf,
    fingerprint: Fingerprint,
    root: [u8; 32],
    size: u64,
}

impl PreparedFile {
    /// The BLAKE3 root for the manifest.
    #[must_use]
    pub const fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// The size for the manifest.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Whether the file still looks unchanged since it was hashed.
    fn unchanged(&self) -> bool {
        self.file
            .metadata()
            .is_ok_and(|metadata| Fingerprint::of(&metadata) == self.fingerprint)
    }
}

impl fmt::Debug for PreparedFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedFile")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl Drop for PreparedFile {
    fn drop(&mut self) {
        // Best effort; FsSource::new removes leftovers.
        let _ = remove(&self.outboard_path);
    }
}

/// The sender's files: each offered file held open from the moment it
/// was hashed, with its Bao outboard in a private directory.
///
/// Mutation is detected two ways: the file's metadata (size, modification
/// time, and identity: device, inode, and change time on Unix; creation
/// and write times on Windows) is compared with the state it was hashed
/// in before every read, and the content layer re-verifies every slice
/// against the manifest root before sealing it. A changed file fails the
/// transfer with `SOURCE_CHANGED`; a new offer is needed (§8). Holding the
/// file open means renaming or replacing the path does not change what is
/// sent.
pub struct FsSource {
    outboards: PathBuf,
    files: BTreeMap<(TransferId, u32), PreparedFile>,
    counter: u64,
}

impl fmt::Debug for FsSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FsSource")
            .field("files", &self.files.len())
            .finish_non_exhaustive()
    }
}

impl FsSource {
    /// A source keeping outboards in `state/outboards` (private
    /// application storage), which it empties first.
    ///
    /// # Errors
    ///
    /// The I/O error if the directory cannot be prepared.
    pub fn new(state: &Path) -> io::Result<Self> {
        let outboards = state.join("outboards");
        remove_tree(&outboards)?;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(&outboards)?;
        Ok(Self {
            outboards,
            files: BTreeMap::new(),
            counter: 0,
        })
    }

    /// Opens and hashes the file at `path` (chosen by the local user) and
    /// builds its outboard. Fails if the file changes while it is hashed.
    ///
    /// # Errors
    ///
    /// [`SourceError::NotFound`]; [`SourceError::Io`] for a read failure,
    /// a path that is not a regular file (`InvalidInput`), or a file that
    /// changed while it was hashed (`Other`).
    pub fn prepare(&mut self, path: &Path) -> Result<PreparedFile, SourceError> {
        let io = |error: io::Error| match error.kind() {
            io::ErrorKind::NotFound => SourceError::NotFound,
            kind => SourceError::Io(kind),
        };
        let mut file = File::open(path).map_err(io)?;
        let before = file.metadata().map_err(io)?;
        if !before.is_file() {
            return Err(SourceError::Io(io::ErrorKind::InvalidInput));
        }
        self.counter += 1;
        let mut random = [0; 8];
        getrandom::fill(&mut random).map_err(|_| SourceError::Io(io::ErrorKind::Other))?;
        let outboard_path = self
            .outboards
            .join(format!("{}-{}.obao", hex(&random), self.counter));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut outboard = options.open(&outboard_path).map_err(io)?;
        let built = write_outboard(&mut file, &mut outboard);
        let after = file.metadata().map_err(io);
        let (root, size) = match (built, after) {
            (Ok(built), Ok(after))
                if Fingerprint::of(&after) == Fingerprint::of(&before)
                    && built.1 == after.len() =>
            {
                built
            }
            (built, _) => {
                let _ = remove(&outboard_path);
                return Err(match built {
                    Err(error) => io(error),
                    Ok(_) => SourceError::Io(io::ErrorKind::Other),
                });
            }
        };
        file.seek(SeekFrom::Start(0)).map_err(io)?;
        outboard.seek(SeekFrom::Start(0)).map_err(io)?;
        Ok(PreparedFile {
            file,
            outboard,
            outboard_path,
            fingerprint: Fingerprint::of(&before),
            root,
            size,
        })
    }

    /// Serves `prepared` as file `file_id` of `transfer_id`.
    pub fn insert(&mut self, transfer_id: TransferId, file_id: u32, prepared: PreparedFile) {
        self.files.insert((transfer_id, file_id), prepared);
    }

    /// Stops serving every file of `transfer_id` (after delivery,
    /// cancellation, or expiry) and deletes their outboards.
    pub fn remove_transfer(&mut self, transfer_id: &TransferId) {
        self.files.retain(|(id, _), _| id != transfer_id);
    }
}

impl SendSource for FsSource {
    type Content<'a> = &'a File;
    type Outboard<'a> = &'a File;

    fn open(
        &mut self,
        transfer_id: &TransferId,
        file_id: u32,
    ) -> Result<(&File, &File), SourceError> {
        let prepared = self
            .files
            .get(&(*transfer_id, file_id))
            .ok_or(SourceError::NotFound)?;
        if !prepared.unchanged() {
            return Err(SourceError::Io(io::ErrorKind::Other));
        }
        Ok((&prepared.file, &prepared.outboard))
    }
}
