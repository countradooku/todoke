//! Durable storage for sealed blobs.

use core::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;

/// Whole-blob storage with atomic replacement.
///
/// Rollback resistance (restoring an older blob from a backup) is not provided
/// here and remains a release gate (O3, §14.2).
pub trait BlobStorage {
    /// Reads the blob, or `None` if none was stored. Implementations must
    /// reject blobs longer than `max_len` before reading them fully.
    ///
    /// # Errors
    ///
    /// [`StorageError`] on I/O failure or an oversized blob.
    fn load(&self, max_len: usize) -> Result<Option<Vec<u8>>, StorageError>;

    /// Atomically replaces the blob: after a crash, readers observe either the
    /// old or the new contents, never a mixture.
    ///
    /// # Errors
    ///
    /// [`StorageError`] on I/O failure. The previous blob then remains intact.
    fn store(&mut self, bytes: &[u8]) -> Result<(), StorageError>;
}

/// Storage failure. Carries only an I/O error kind, never a path or contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StorageError {
    /// The stored blob exceeds the caller's limit.
    TooLarge,
    /// An operating-system I/O error.
    Io(io::ErrorKind),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("stored blob is too large"),
            Self::Io(kind) => write!(f, "I/O error: {kind}"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<io::Error> for StorageError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

/// [`BlobStorage`] in one file, replaced via write, sync, and rename.
///
/// Each store removes any stale `.tmp` sibling and creates a fresh one with
/// `create_new` (`O_CREAT | O_EXCL`), which never opens an existing file and,
/// per POSIX, fails rather than following a symlink at that path. Before the
/// rename, the path's `symlink_metadata` must still be the regular file that
/// was opened. On Unix the file is created with mode 0600 and the parent
/// directory is synced after the rename. Windows ACLs and mobile sandbox
/// protection classes are left to platform integration (O9).
///
/// **Single writer required:** there is no locking. At most one
/// `FileStorage` (in one process) may store to a path at a time; a concurrent
/// writer makes `store` fail or lose an update. The directory should be
/// writable only by its owner: anyone who can write to it can replace the
/// blob outright.
#[derive(Debug)]
pub struct FileStorage {
    path: PathBuf,
    temporary: PathBuf,
}

impl FileStorage {
    /// Uses `path` for the blob and a `.tmp` sibling while replacing it.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let mut temporary = path.clone().into_os_string();
        temporary.push(".tmp");
        Self {
            path,
            temporary: temporary.into(),
        }
    }
}

impl BlobStorage for FileStorage {
    fn load(&self, max_len: usize) -> Result<Option<Vec<u8>>, StorageError> {
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let limit = u64::try_from(max_len).map_err(|_| StorageError::TooLarge)?;
        let declared = file.metadata()?.len();
        if declared > limit {
            return Err(StorageError::TooLarge);
        }
        // The file may grow after the metadata check; read at most limit + 1.
        let mut bytes = Vec::with_capacity(usize::try_from(declared).unwrap_or(max_len));
        file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
        if bytes.len() > max_len {
            return Err(StorageError::TooLarge);
        }
        Ok(Some(bytes))
    }

    fn store(&mut self, bytes: &[u8]) -> Result<(), StorageError> {
        // A leftover from a crash, or something planted: never reuse it, since
        // its mode, owner, or link target would carry over. Removing a symlink
        // removes the link, not its target.
        match fs::remove_file(&self.temporary) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        // O_NOFOLLOW would need a libc constant; O_EXCL already refuses an
        // existing path, symlinks included, and the identity check below
        // confirms what is renamed.
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&self.temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        ensure_same_file(&file, &self.temporary)?;
        drop(file);
        fs::rename(&self.temporary, &self.path)?;
        #[cfg(unix)]
        sync_parent(&self.path)?;
        Ok(())
    }
}

/// Fails unless `path` is, without following symlinks, the regular file open
/// as `file` (on Unix, the same device and inode).
fn ensure_same_file(file: &File, path: &std::path::Path) -> Result<(), StorageError> {
    let opened = file.metadata()?;
    let current = fs::symlink_metadata(path)?;
    let same = current.file_type().is_file() && {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            opened.dev() == current.dev() && opened.ino() == current.ino()
        }
        #[cfg(not(unix))]
        {
            opened.is_file()
        }
    };
    if same {
        Ok(())
    } else {
        Err(StorageError::Io(io::ErrorKind::AlreadyExists))
    }
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), StorageError> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// In-memory [`BlobStorage`] for tests and ephemeral stores.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    blob: Option<Vec<u8>>,
}

impl MemoryStorage {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The current sealed blob, if any. Sealed blobs are ciphertext.
    #[must_use]
    pub fn blob(&self) -> Option<&[u8]> {
        self.blob.as_deref()
    }

    /// Replaces the blob directly, for example to simulate tampering in tests.
    pub fn set_blob(&mut self, blob: Option<Vec<u8>>) {
        self.blob = blob;
    }
}

impl BlobStorage for MemoryStorage {
    fn load(&self, max_len: usize) -> Result<Option<Vec<u8>>, StorageError> {
        match &self.blob {
            Some(blob) if blob.len() > max_len => Err(StorageError::TooLarge),
            blob => Ok(blob.clone()),
        }
    }

    fn store(&mut self, bytes: &[u8]) -> Result<(), StorageError> {
        self.blob = Some(bytes.to_vec());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A unique scratch directory under the OS temp dir, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let mut suffix = [0; 8];
            crate::rng::fill(&mut suffix)?;
            let name = hex::encode(suffix);
            let path = std::env::temp_dir().join(format!("todoke-storage-test-{name}"));
            fs::create_dir(&path)?;
            Ok(Self(path))
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn file_storage_round_trip_and_replace() -> TestResult {
        let scratch = Scratch::new()?;
        let mut storage = FileStorage::new(scratch.0.join("blob"));
        assert_eq!(storage.load(64)?, None);
        storage.store(b"first")?;
        assert_eq!(storage.load(64)?.as_deref(), Some(&b"first"[..]));
        storage.store(b"second, longer")?;
        assert_eq!(storage.load(64)?.as_deref(), Some(&b"second, longer"[..]));
        assert!(!scratch.0.join("blob.tmp").exists());
        assert_eq!(storage.load(4), Err(StorageError::TooLarge));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn file_storage_is_owner_only() -> TestResult {
        use std::os::unix::fs::PermissionsExt;
        let scratch = Scratch::new()?;
        let path = scratch.0.join("blob");
        FileStorage::new(&path).store(b"x")?;
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        Ok(())
    }

    /// A leftover or planted `.tmp` with loose permissions must not be
    /// reused: its mode would survive the rename onto the real path.
    #[cfg(unix)]
    #[test]
    fn stale_temporary_file_is_replaced() -> TestResult {
        use std::os::unix::fs::PermissionsExt;
        let scratch = Scratch::new()?;
        let path = scratch.0.join("blob");
        let temporary = scratch.0.join("blob.tmp");
        fs::write(&temporary, b"stale contents, longer than the new blob")?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644))?;
        let mut storage = FileStorage::new(&path);
        storage.store(b"new")?;
        assert_eq!(storage.load(64)?.as_deref(), Some(&b"new"[..]));
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        assert!(!temporary.exists());
        Ok(())
    }

    /// A symlink planted at the `.tmp` path must not be followed: the target
    /// stays untouched and the real path becomes a regular file.
    #[cfg(unix)]
    #[test]
    fn temporary_symlink_is_not_followed() -> TestResult {
        let scratch = Scratch::new()?;
        let path = scratch.0.join("blob");
        let victim = scratch.0.join("victim");
        fs::write(&victim, b"victim")?;
        std::os::unix::fs::symlink(&victim, scratch.0.join("blob.tmp"))?;
        let mut storage = FileStorage::new(&path);
        storage.store(b"secret blob")?;
        assert_eq!(fs::read(&victim)?, b"victim");
        assert!(fs::symlink_metadata(&path)?.file_type().is_file());
        assert_eq!(fs::read(&path)?, b"secret blob");
        // A dangling symlink is not followed either.
        std::os::unix::fs::symlink(scratch.0.join("missing"), scratch.0.join("blob.tmp"))?;
        storage.store(b"again")?;
        assert!(!scratch.0.join("missing").exists());
        assert_eq!(fs::read(&path)?, b"again");
        Ok(())
    }

    /// Only a missing file means "nothing stored"; any other open failure
    /// is an error, never an empty store.
    #[test]
    fn load_reports_errors_other_than_absence() -> TestResult {
        let scratch = Scratch::new()?;
        let file = scratch.0.join("file");
        fs::write(&file, b"not a directory")?;
        let storage = FileStorage::new(file.join("blob"));
        assert!(matches!(storage.load(64), Err(StorageError::Io(_))));
        Ok(())
    }

    #[test]
    fn load_accepts_exactly_max_len() -> TestResult {
        let scratch = Scratch::new()?;
        let mut storage = FileStorage::new(scratch.0.join("blob"));
        storage.store(b"12345")?;
        assert_eq!(storage.load(5)?.as_deref(), Some(&b"12345"[..]));
        assert_eq!(storage.load(4), Err(StorageError::TooLarge));
        assert_eq!(storage.load(0), Err(StorageError::TooLarge));
        Ok(())
    }

    /// A stale `.tmp` that cannot be removed fails the store at the removal
    /// step (not later at `create_new`) and leaves the stored blob intact.
    #[cfg(unix)]
    #[test]
    fn unremovable_temporary_path_fails_store() -> TestResult {
        let scratch = Scratch::new()?;
        let path = scratch.0.join("blob");
        let mut storage = FileStorage::new(&path);
        storage.store(b"kept")?;
        let temporary = scratch.0.join("blob.tmp");
        fs::create_dir(&temporary)?;
        fs::write(temporary.join("inside"), b"x")?;
        let result = storage.store(b"replacement");
        assert!(matches!(result, Err(StorageError::Io(_))));
        assert_ne!(
            result,
            Err(StorageError::Io(io::ErrorKind::AlreadyExists)),
            "failure must come from removing the stale path"
        );
        assert_eq!(storage.load(64)?.as_deref(), Some(&b"kept"[..]));
        assert!(temporary.join("inside").exists());
        Ok(())
    }

    /// The pre-rename check accepts only the very file that was opened.
    #[cfg(unix)]
    #[test]
    fn ensure_same_file_rejects_substitutes() -> TestResult {
        let scratch = Scratch::new()?;
        let opened_path = scratch.0.join("opened");
        let other_path = scratch.0.join("other");
        fs::write(&opened_path, b"a")?;
        fs::write(&other_path, b"b")?;
        let opened = File::open(&opened_path)?;
        assert_eq!(ensure_same_file(&opened, &opened_path), Ok(()));
        let substituted = Err(StorageError::Io(io::ErrorKind::AlreadyExists));
        // Another regular file on the same device.
        assert_eq!(ensure_same_file(&opened, &other_path), substituted);
        // A symlink to the opened file is not the file itself.
        let link = scratch.0.join("link");
        std::os::unix::fs::symlink(&opened_path, &link)?;
        assert_eq!(ensure_same_file(&opened, &link), substituted);
        // A directory is not a regular file.
        assert_eq!(ensure_same_file(&opened, &scratch.0), substituted);
        Ok(())
    }

    /// The parent of a bare file name is the current directory; a missing
    /// parent is an error rather than silently syncing something else.
    #[cfg(unix)]
    #[test]
    fn sync_parent_resolves_the_parent_directory() -> TestResult {
        sync_parent(Path::new("blob"))?;
        let scratch = Scratch::new()?;
        sync_parent(&scratch.0.join("blob"))?;
        assert!(matches!(
            sync_parent(&scratch.0.join("missing").join("blob")),
            Err(StorageError::Io(_))
        ));
        Ok(())
    }

    #[test]
    fn memory_storage_enforces_limit() -> TestResult {
        let mut storage = MemoryStorage::new();
        assert_eq!(storage.load(1)?, None);
        storage.store(b"abc")?;
        assert_eq!(storage.load(3)?.as_deref(), Some(&b"abc"[..]));
        assert_eq!(storage.load(2), Err(StorageError::TooLarge));
        Ok(())
    }
}
