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
        private_empty_dir(&outboards)?;
        Ok(Self {
            outboards,
            files: BTreeMap::new(),
        })
    }

    /// Opens and hashes the file at `path` (chosen by the local user) and
    /// builds its outboard. Fails if the file changes while it is hashed.
    ///
    /// # Errors
    ///
    /// As [`Preparer::prepare`].
    pub fn prepare(&mut self, path: &Path) -> Result<PreparedFile, SourceError> {
        prepare_in(&self.outboards, path, None)
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

/// Hashes files for offers on any thread: a [`PreparedFile`] can be
/// prepared away from the thread that serves it and then
/// [inserted](FsSource::insert) into a source. Outboards are kept in its
/// own private directory.
#[derive(Clone, Debug)]
pub struct Preparer {
    outboards: PathBuf,
}

impl Preparer {
    /// A preparer keeping outboards in `dir` (private application
    /// storage), which it empties first. One preparer per directory.
    ///
    /// # Errors
    ///
    /// The I/O error if the directory cannot be prepared.
    pub fn new(dir: &Path) -> io::Result<Self> {
        private_empty_dir(dir)?;
        Ok(Self {
            outboards: dir.to_owned(),
        })
    }

    /// Opens and hashes the file at `path` and builds its outboard.
    ///
    /// The final component is opened without following a link and without
    /// waiting on a FIFO. With `expected` (what `symlink_metadata` showed
    /// when the caller chose the path), the opened file must be that same
    /// file in the same state: a path swapped since (for a link, a special
    /// file, or another file, anywhere along it) is refused.
    ///
    /// # Errors
    ///
    /// [`SourceError::NotFound`]; [`SourceError::Io`] for a read failure,
    /// a path that is not a regular file or a link (`InvalidInput`), or a
    /// file that changed since `expected` or while it was hashed (`Other`).
    pub fn prepare(
        &self,
        path: &Path,
        expected: Option<&Metadata>,
    ) -> Result<PreparedFile, SourceError> {
        prepare_in(&self.outboards, path, expected)
    }
}

/// Creates `dir` (0700 on Unix), emptied.
fn private_empty_dir(dir: &Path) -> io::Result<()> {
    remove_tree(dir)?;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}

/// Opens a file to send: on Unix without following a final link and
/// without blocking on a FIFO; on Windows without following a reparse
/// point. The caller checks that what it opened is a regular file.
fn open_source(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let flags = (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits();
        options.custom_flags(
            i32::try_from(flags).map_err(|_| io::Error::from(io::ErrorKind::Unsupported))?,
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        /// `FILE_FLAG_OPEN_REPARSE_POINT`: open a link itself.
        const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(OPEN_REPARSE_POINT);
    }
    options.open(path)
}

fn prepare_in(
    outboards: &Path,
    path: &Path,
    expected: Option<&Metadata>,
) -> Result<PreparedFile, SourceError> {
    let io = |error: io::Error| match error.kind() {
        io::ErrorKind::NotFound => SourceError::NotFound,
        kind => SourceError::Io(kind),
    };
    // A refused open of something that is not a regular file (Windows
    // refuses directories, `PermissionDenied`; Unix refuses a final link,
    // `ELOOP`) is reported as such. The check that counts is below, on
    // the opened handle.
    let mut file = open_source(path).map_err(|error| {
        if std::fs::symlink_metadata(path).is_ok_and(|meta| !meta.is_file()) {
            SourceError::Io(io::ErrorKind::InvalidInput)
        } else {
            io(error)
        }
    })?;
    let before = file.metadata().map_err(io)?;
    if !before.is_file() {
        return Err(SourceError::Io(io::ErrorKind::InvalidInput));
    }
    if expected.is_some_and(|expected| Fingerprint::of(expected) != Fingerprint::of(&before)) {
        return Err(SourceError::Io(io::ErrorKind::Other));
    }
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(|_| SourceError::Io(io::ErrorKind::Other))?;
    let outboard_path = outboards.join(format!("{}.obao", hex(&random)));
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut outboard = options.open(&outboard_path).map_err(io)?;
    let built = write_outboard(&mut file, &mut outboard);
    let after = file.metadata().map_err(io);
    let (root, size) = match (built, after) {
        (Ok(built), Ok(after))
            if Fingerprint::of(&after) == Fingerprint::of(&before) && built.1 == after.len() =>
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
        // Readers start at the beginning, like a fresh handle: the slice
        // extractor positions itself relative to where it starts.
        let (mut content, mut outboard) = (&prepared.file, &prepared.outboard);
        content
            .seek(SeekFrom::Start(0))
            .map_err(|error| SourceError::Io(error.kind()))?;
        outboard
            .seek(SeekFrom::Start(0))
            .map_err(|error| SourceError::Io(error.kind()))?;
        Ok((content, outboard))
    }
}
