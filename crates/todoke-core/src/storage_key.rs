//! Where the key that seals this device's state comes from.
//!
//! The platform keeps it where it can (the Keychain wrapped by the Secure
//! Enclave, DPAPI with the TPM, the Secret Service: the `todoke-sys-*`
//! crates, chosen by the daemon, docs/adr/0011-os-integration.md). Where it
//! cannot, [`KeyFile`] keeps the 32-byte key in a file only this user can
//! read, next to the state it seals. That protects the state from other
//! local users and from copies of the state without the key file, **not**
//! from malware running as this user or from a full-disk copy.

use core::fmt;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

/// The source of the 32-byte storage key.
pub trait StorageKeySource {
    /// The key, created on first use.
    ///
    /// # Errors
    ///
    /// The I/O or platform error.
    fn storage_key(&self) -> io::Result<Zeroizing<[u8; 32]>>;

    /// What protects the key.
    fn protection(&self) -> crate::api::KeyProtection {
        crate::api::KeyProtection::File
    }
}

/// A key already fetched: the core asks its source once.
pub(crate) struct Fetched(pub(crate) Zeroizing<[u8; 32]>);

impl StorageKeySource for Fetched {
    fn storage_key(&self) -> io::Result<Zeroizing<[u8; 32]>> {
        Ok(Zeroizing::new(*self.0))
    }
}

/// A key in a file readable only by this user (0600 on Unix).
#[derive(Clone, Debug)]
pub struct KeyFile {
    path: PathBuf,
}

impl KeyFile {
    /// The key file at `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether a key file exists.
    #[must_use]
    pub fn exists(&self) -> bool {
        std::fs::symlink_metadata(&self.path).is_ok()
    }

    /// Overwrites the key file with zeros, syncs, and deletes it (after its
    /// key moved to platform storage). Copy-on-write and journaling file
    /// systems may still hold the old blocks: the platform store is the
    /// protection, not this.
    ///
    /// # Errors
    ///
    /// An I/O error; `NotFound` if there is no key file.
    pub fn remove(&self) -> io::Result<()> {
        let mut file = std::fs::OpenOptions::new().write(true).open(&self.path)?;
        file.write_all(&[0; 32])?;
        file.sync_all()?;
        drop(file);
        std::fs::remove_file(&self.path)
    }
}

impl StorageKeySource for KeyFile {
    fn storage_key(&self) -> io::Result<Zeroizing<[u8; 32]>> {
        let mut key = Zeroizing::new([0; 32]);
        match open_private(&self.path, false) {
            Ok(mut file) => {
                check_private(&file)?;
                let mut read = Zeroizing::new(Vec::with_capacity(33));
                std::io::Read::take(&mut file, 33).read_to_end(&mut read)?;
                if read.len() != 32 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "storage key file",
                    ));
                }
                key.copy_from_slice(&read);
                Ok(key)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                getrandom::fill(key.as_mut_slice()).map_err(|_| io::Error::other("randomness"))?;
                let mut file = open_private(&self.path, true)?;
                file.write_all(key.as_slice())?;
                file.sync_all()?;
                Ok(key)
            }
            Err(error) => Err(error),
        }
    }
}

/// Secret storage the platform provides (the `todoke-sys-*` crates): it
/// only loads and stores; [`Selected`] decides when to use it.
pub trait PlatformKeyStore: Send {
    /// What protects a key stored here.
    fn protection(&self) -> crate::api::KeyProtection;

    /// The stored key, or `None` if none is stored.
    ///
    /// # Errors
    ///
    /// The store is unavailable now (no keyring, locked, refused): never
    /// "no key".
    fn load(&self) -> io::Result<Option<Zeroizing<[u8; 32]>>>;

    /// Stores `key`. Never replaces a stored key.
    ///
    /// # Errors
    ///
    /// `AlreadyExists` if a key is stored; the platform's error.
    fn store(&self, key: &[u8; 32]) -> io::Result<()>;
}

/// Where a profile's key is, recorded beside the state (`storage.backend`)
/// so that a store unavailable for a moment is never taken for an empty
/// one: a new key would orphan the sealed state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Backend {
    File,
    Platform,
}

/// The key source the configuration asks for (§16 O9):
///
/// - a profile whose key is in the platform store uses that store, or
///   does not start;
/// - a key file moves to the platform store when the policy allows and the
///   store is available: stored, read back, recorded, and only then
///   deleted;
/// - a key never moves back to a file by itself, and with
///   [`KeyStorage::Platform`](crate::config::KeyStorage::Platform) nothing
///   falls back to one.
pub struct Selected {
    file: KeyFile,
    platform: Option<Box<dyn PlatformKeyStore>>,
    policy: crate::config::KeyStorage,
    marker: PathBuf,
    used: std::sync::Mutex<Option<crate::api::KeyProtection>>,
}

impl fmt::Debug for Selected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Selected")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl Selected {
    /// The source for the state in `state_dir`, with `platform` if this
    /// build has one.
    #[must_use]
    pub fn new(
        state_dir: &Path,
        platform: Option<Box<dyn PlatformKeyStore>>,
        policy: crate::config::KeyStorage,
    ) -> Self {
        Self {
            file: KeyFile::new(state_dir.join("storage.key")),
            platform,
            policy,
            marker: state_dir.join("storage.backend"),
            used: std::sync::Mutex::new(None),
        }
    }

    fn recorded(&self) -> io::Result<Option<Backend>> {
        match std::fs::read(&self.marker) {
            Ok(text) => match text.trim_ascii() {
                b"file" => Ok(Some(Backend::File)),
                b"platform" => Ok(Some(Backend::Platform)),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "storage.backend names no key store",
                )),
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn record(&self, backend: Backend) -> io::Result<()> {
        let text: &[u8] = match backend {
            Backend::File => b"file\n",
            Backend::Platform => b"platform\n",
        };
        let partial = self.marker.with_extension("backend.tmp");
        let _ = std::fs::remove_file(&partial);
        let mut file = open_private(&partial, true)?;
        file.write_all(text)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&partial, &self.marker)
    }

    fn platform(&self) -> io::Result<&dyn PlatformKeyStore> {
        self.platform.as_deref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "this build has no platform key store",
            )
        })
    }

    /// The key in the platform store; a profile recorded there needs it.
    fn in_platform(&self) -> io::Result<Zeroizing<[u8; 32]>> {
        let platform = self.platform()?;
        let key = platform.load()?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "the storage key is missing from the platform key store",
            )
        })?;
        self.used_now(platform.protection());
        Ok(key)
    }

    /// Stores `key` in the platform store and reads it back.
    fn put(platform: &dyn PlatformKeyStore, key: &[u8; 32]) -> io::Result<()> {
        platform.store(key)?;
        match platform.load()? {
            Some(back) if *back == *key => Ok(()),
            _ => Err(io::Error::other(
                "the platform key store did not keep the storage key",
            )),
        }
    }

    /// Moves the key file's key to the platform store.
    fn migrate(&self, platform: &dyn PlatformKeyStore) -> io::Result<Zeroizing<[u8; 32]>> {
        let key = self.file.storage_key()?;
        match platform.load()? {
            // A key there already that is not this one: never overwrite.
            Some(other) if *other != *key => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "the platform key store holds another storage key for this profile",
                ));
            }
            Some(_) => {}
            None => Self::put(platform, &key)?,
        }
        self.record(Backend::Platform)?;
        self.file.remove()?;
        self.used_now(platform.protection());
        Ok(key)
    }

    fn in_file(&self) -> io::Result<Zeroizing<[u8; 32]>> {
        let key = self.file.storage_key()?;
        self.record(Backend::File)?;
        self.used_now(crate::api::KeyProtection::File);
        Ok(key)
    }

    fn used_now(&self, protection: crate::api::KeyProtection) {
        if let Ok(mut used) = self.used.lock() {
            *used = Some(protection);
        }
    }
}

impl StorageKeySource for Selected {
    fn storage_key(&self) -> io::Result<Zeroizing<[u8; 32]>> {
        use crate::config::KeyStorage;
        let recorded = match self.recorded()? {
            // A key file from before the record existed.
            None if self.file.exists() => Some(Backend::File),
            other => other,
        };
        match (recorded, self.policy) {
            (Some(Backend::Platform), KeyStorage::File) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the storage key is in the platform key store; it is never moved back to a file",
            )),
            (Some(Backend::Platform), _) => self.in_platform(),
            (Some(Backend::File) | None, KeyStorage::File) => self.in_file(),
            (Some(Backend::File), policy) => match self.platform() {
                Ok(platform) => match self.migrate(platform) {
                    Ok(key) => Ok(key),
                    // Unavailable for now: the file still holds the key.
                    Err(_) if policy == KeyStorage::Auto => self.in_file(),
                    Err(error) => Err(error),
                },
                Err(_) if policy == KeyStorage::Auto => self.in_file(),
                Err(error) => Err(error),
            },
            (None, policy) => {
                let created = self.platform().and_then(|platform| {
                    let key = if let Some(key) = platform.load()? {
                        key
                    } else {
                        let mut key = Zeroizing::new([0; 32]);
                        getrandom::fill(key.as_mut_slice())
                            .map_err(|_| io::Error::other("randomness"))?;
                        Self::put(platform, &key)?;
                        key
                    };
                    self.record(Backend::Platform)?;
                    self.used_now(platform.protection());
                    Ok(key)
                });
                match created {
                    Ok(key) => Ok(key),
                    Err(_) if policy == KeyStorage::Auto => self.in_file(),
                    Err(error) => Err(error),
                }
            }
        }
    }

    fn protection(&self) -> crate::api::KeyProtection {
        self.used
            .lock()
            .ok()
            .and_then(|used| *used)
            .unwrap_or(crate::api::KeyProtection::File)
    }
}

fn open_private(path: &Path, create: bool) -> io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    if create {
        options.write(true).create_new(true);
    } else {
        options.read(true);
    }
    // `O_NOFOLLOW`: a link in place of the key file is refused.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let nofollow = rustix::fs::OFlags::NOFOLLOW.bits();
        options
            .mode(0o600)
            .custom_flags(i32::try_from(nofollow).unwrap_or(i32::MAX));
    }
    options.open(path)
}

/// Refuses a key file that others can read or write.
#[cfg(unix)]
fn check_private(file: &std::fs::File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    if file.metadata()?.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the storage key file is readable by others",
        ));
    }
    Ok(())
}

/// On Windows the file inherits the user profile's ACL (only the user and
/// administrators); nothing more is checked here.
#[cfg(not(unix))]
#[expect(clippy::unnecessary_wraps, reason = "the same signature as on Unix")]
fn check_private(_: &std::fs::File) -> io::Result<()> {
    Ok(())
}

/// A fixed key, for tests.
#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct FixedKey(pub(crate) [u8; 32]);

#[cfg(test)]
impl StorageKeySource for FixedKey {
    fn storage_key(&self) -> io::Result<Zeroizing<[u8; 32]>> {
        Ok(Zeroizing::new(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::tests::Scratch;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn the_key_is_created_once_and_kept_private() -> TestResult {
        let scratch = Scratch::new("key-file")?;
        std::fs::create_dir_all(&scratch.0)?;
        let file = KeyFile::new(scratch.0.join("storage.key"));
        let first = file.storage_key()?;
        assert_eq!(file.storage_key()?, first);
        assert_ne!(*first, [0; 32]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(file.path())?.permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn exposed_linked_or_wrong_sized_key_files_are_refused() -> TestResult {
        use std::os::unix::fs::PermissionsExt as _;
        let scratch = Scratch::new("key-file-bad")?;
        std::fs::create_dir_all(&scratch.0)?;
        let path = scratch.0.join("storage.key");
        let file = KeyFile::new(&path);
        file.storage_key()?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        assert_eq!(
            file.storage_key().map(|_| ()).map_err(|e| e.kind()),
            Err(io::ErrorKind::PermissionDenied)
        );
        // A symbolic link in its place is not followed.
        let target = scratch.0.join("elsewhere");
        std::fs::write(&target, [9; 32])?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))?;
        std::fs::remove_file(&path)?;
        std::os::unix::fs::symlink(&target, &path)?;
        assert!(file.storage_key().is_err());
        // A file of the wrong size is not a key.
        std::fs::remove_file(&path)?;
        std::fs::write(&path, [9; 31])?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        assert_eq!(
            file.storage_key().map(|_| ()).map_err(|e| e.kind()),
            Err(io::ErrorKind::InvalidData)
        );
        Ok(())
    }

    /// A platform store in memory that can be made unavailable.
    #[derive(Clone, Default)]
    struct Memory(std::sync::Arc<std::sync::Mutex<(Option<[u8; 32]>, bool)>>);

    impl Memory {
        fn down(&self, down: bool) {
            if let Ok(mut state) = self.0.lock() {
                state.1 = down;
            }
        }

        fn key(&self) -> Option<[u8; 32]> {
            self.0.lock().ok().and_then(|state| state.0)
        }
    }

    impl PlatformKeyStore for Memory {
        fn protection(&self) -> crate::api::KeyProtection {
            crate::api::KeyProtection::Keychain
        }

        fn load(&self) -> io::Result<Option<Zeroizing<[u8; 32]>>> {
            let state = self.0.lock().map_err(|_| io::Error::other("poisoned"))?;
            if state.1 {
                return Err(io::Error::other("locked"));
            }
            Ok(state.0.map(Zeroizing::new))
        }

        fn store(&self, key: &[u8; 32]) -> io::Result<()> {
            let mut state = self.0.lock().map_err(|_| io::Error::other("poisoned"))?;
            if state.1 {
                return Err(io::Error::other("locked"));
            }
            if state.0.is_some() {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            state.0 = Some(*key);
            Ok(())
        }
    }

    fn selected(dir: &Path, memory: &Memory, policy: crate::config::KeyStorage) -> Selected {
        Selected::new(dir, Some(Box::new(memory.clone())), policy)
    }

    /// A new profile keeps its key in the platform store, and stays there.
    #[test]
    fn a_new_key_goes_to_the_platform_store_and_stays() -> TestResult {
        use crate::config::KeyStorage;
        let scratch = Scratch::new("selected-new")?;
        std::fs::create_dir_all(&scratch.0)?;
        let memory = Memory::default();
        let source = selected(&scratch.0, &memory, KeyStorage::Auto);
        let key = source.storage_key()?;
        assert_eq!(memory.key(), Some(*key));
        assert_eq!(source.protection(), crate::api::KeyProtection::Keychain);
        assert!(!scratch.0.join("storage.key").exists());
        // Unavailable later: the profile does not start, and no file key
        // is made in its place.
        memory.down(true);
        let again = selected(&scratch.0, &memory, KeyStorage::Auto);
        assert!(again.storage_key().is_err());
        assert!(!scratch.0.join("storage.key").exists());
        // Nor is it moved back to a file on request.
        memory.down(false);
        let to_file = selected(&scratch.0, &memory, KeyStorage::File);
        assert_eq!(
            to_file.storage_key().map(|_| ()).map_err(|e| e.kind()),
            Err(io::ErrorKind::InvalidInput)
        );
        assert_eq!(
            selected(&scratch.0, &memory, KeyStorage::Auto).storage_key()?,
            key
        );
        Ok(())
    }

    /// A key file moves to the platform store once it is available, and is
    /// deleted only after the store gave the key back.
    #[test]
    fn a_key_file_moves_to_the_platform_store() -> TestResult {
        use crate::config::KeyStorage;
        let scratch = Scratch::new("selected-move")?;
        std::fs::create_dir_all(&scratch.0)?;
        let file = KeyFile::new(scratch.0.join("storage.key"));
        let key = file.storage_key()?;
        let memory = Memory::default();
        // Unavailable at first: the file serves, under Auto only.
        memory.down(true);
        assert_eq!(
            selected(&scratch.0, &memory, KeyStorage::Auto).storage_key()?,
            key
        );
        assert!(file.exists());
        assert!(
            selected(&scratch.0, &memory, KeyStorage::Platform)
                .storage_key()
                .is_err()
        );
        assert!(file.exists());
        memory.down(false);
        let source = selected(&scratch.0, &memory, KeyStorage::Auto);
        assert_eq!(source.storage_key()?, key);
        assert_eq!(memory.key(), Some(*key));
        assert!(!file.exists());
        assert_eq!(source.protection(), crate::api::KeyProtection::Keychain);
        Ok(())
    }

    /// Another key already in the platform store is never overwritten: the
    /// file keeps serving.
    #[test]
    fn a_conflicting_platform_key_is_never_overwritten() -> TestResult {
        use crate::config::KeyStorage;
        let scratch = Scratch::new("selected-conflict")?;
        std::fs::create_dir_all(&scratch.0)?;
        let file = KeyFile::new(scratch.0.join("storage.key"));
        let key = file.storage_key()?;
        let memory = Memory::default();
        memory.store(&[7; 32])?;
        assert_eq!(
            selected(&scratch.0, &memory, KeyStorage::Auto).storage_key()?,
            key
        );
        assert_eq!(memory.key(), Some([7; 32]));
        assert!(file.exists());
        Ok(())
    }

    /// File only: no platform store is touched; no store at all: a file.
    #[test]
    fn file_policy_and_builds_without_a_platform_store_use_a_file() -> TestResult {
        use crate::config::KeyStorage;
        let scratch = Scratch::new("selected-file")?;
        std::fs::create_dir_all(&scratch.0)?;
        let memory = Memory::default();
        let source = selected(&scratch.0, &memory, KeyStorage::File);
        let key = source.storage_key()?;
        assert_eq!(memory.key(), None);
        assert_eq!(source.protection(), crate::api::KeyProtection::File);
        let other = Scratch::new("selected-none")?;
        std::fs::create_dir_all(&other.0)?;
        let none = Selected::new(&other.0, None, KeyStorage::Auto);
        assert_ne!(*none.storage_key()?, *key);
        let required = Scratch::new("selected-required")?;
        std::fs::create_dir_all(&required.0)?;
        assert_eq!(
            Selected::new(&required.0, None, KeyStorage::Platform)
                .storage_key()
                .map(|_| ())
                .map_err(|e| e.kind()),
            Err(io::ErrorKind::Unsupported)
        );
        assert!(!required.0.join("storage.key").exists());
        Ok(())
    }
}
