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
/// On Unix the file is created with mode 0600 and the parent directory is
/// synced after the rename. Windows ACLs and mobile sandbox protection classes
/// are left to platform integration (O9).
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
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&self.temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&self.temporary, &self.path)?;
        #[cfg(unix)]
        sync_parent(&self.path)?;
        Ok(())
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
