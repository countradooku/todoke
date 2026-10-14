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
use core::fmt::Write as _;
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
#[cfg(all(not(target_family = "wasm"), feature = "unaudited-dev"))]
pub(crate) struct Fetched(pub(crate) Zeroizing<[u8; 32]>);

#[cfg(all(not(target_family = "wasm"), feature = "unaudited-dev"))]
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

    /// The name the key file is moved to before it is wiped.
    fn retired(&self) -> PathBuf {
        self.path.with_extension("key.retired")
    }

    /// Removes the key file (after its key moved to platform storage): it
    /// is first renamed, so the key file's name never holds a partly wiped
    /// key, then overwritten with zeros, synced, and deleted. A retired
    /// file left by an earlier failure goes the same way. Copy-on-write and
    /// journaling file systems may still hold the old blocks: the platform
    /// store is the protection, not this.
    ///
    /// # Errors
    ///
    /// An I/O error.
    pub fn remove(&self) -> io::Result<()> {
        let retired = self.retired();
        match std::fs::rename(&self.path, &retired) {
            Ok(()) => sync_parent(&self.path)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut file = match std::fs::OpenOptions::new().write(true).open(&retired) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        let length = file.metadata()?.len();
        let zeros = vec![0; usize::try_from(length.min(64)).unwrap_or(64)];
        file.write_all(&zeros)?;
        file.sync_all()?;
        drop(file);
        std::fs::remove_file(&retired)?;
        sync_parent(&retired)
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
                // An all-zero key is a wiped file, never a key.
                if read.len() != 32 || read.iter().all(|&byte| byte == 0) {
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
                sync_parent(&self.path)?;
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

/// A platform store made of a file sealed under a secret the platform
/// keeps for this app (the Flatpak Secret portal): ChaCha20-Poly1305 under
/// the secret's first 32 bytes, with the profile's ID as associated data.
/// The file alone opens nothing; the secret never leaves the platform's
/// keyring except to this app.
pub struct SealedFile {
    path: PathBuf,
    context: Vec<u8>,
    protection: crate::api::KeyProtection,
    secret: Box<dyn Fn() -> io::Result<Zeroizing<Vec<u8>>> + Send>,
}

impl fmt::Debug for SealedFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedFile")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl SealedFile {
    /// The key of profile `profile`, sealed in `path` under the secret
    /// `secret` returns (at least 32 uniformly random bytes).
    #[must_use]
    pub fn new(
        path: PathBuf,
        profile: &str,
        protection: crate::api::KeyProtection,
        secret: Box<dyn Fn() -> io::Result<Zeroizing<Vec<u8>>> + Send>,
    ) -> Self {
        let mut context = b"todoke/v1/storage-key/sealed-file\0".to_vec();
        context.extend_from_slice(profile.as_bytes());
        Self {
            path,
            context,
            protection,
            secret,
        }
    }

    fn sealer(&self) -> io::Result<todoke_crypto::identity::SoftwareSealer> {
        let secret = (self.secret)()?;
        let first: [u8; 32] = secret
            .get(..32)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "the secret is too short"))?;
        Ok(todoke_crypto::identity::SoftwareSealer::new(
            todoke_crypto::identity::StorageKey::from_bytes(Zeroizing::new(first)),
        ))
    }
}

impl PlatformKeyStore for SealedFile {
    fn protection(&self) -> crate::api::KeyProtection {
        self.protection
    }

    fn load(&self) -> io::Result<Option<Zeroizing<[u8; 32]>>> {
        use todoke_crypto::identity::Sealer as _;
        let sealed = match std::fs::read(&self.path) {
            Ok(sealed) => sealed,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let plain = self.sealer()?.open(&self.context, &sealed).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "the sealed key does not open")
        })?;
        let key: [u8; 32] = plain.as_slice().try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the sealed key has the wrong size",
            )
        })?;
        Ok(Some(Zeroizing::new(key)))
    }

    fn store(&self, key: &[u8; 32]) -> io::Result<()> {
        use todoke_crypto::identity::Sealer as _;
        if std::fs::symlink_metadata(&self.path).is_ok() {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        let sealed = self
            .sealer()?
            .seal(&self.context, key)
            .map_err(|_| io::Error::other("sealing the key failed"))?;
        // Written aside, then linked into place: never torn, never replaced.
        let partial = temporary(&self.path)?;
        let mut file = open_private(&partial, true)?;
        let written = file.write_all(&sealed).and_then(|()| file.sync_all());
        drop(file);
        let linked = written.and_then(|()| std::fs::hard_link(&partial, &self.path));
        let _ = std::fs::remove_file(&partial);
        linked?;
        sync_parent(&self.path)
    }
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
        let partial = temporary(&self.marker)?;
        let mut file = open_private(&partial, true)?;
        file.write_all(text)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&partial, &self.marker)?;
        sync_parent(&self.marker)
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
    /// A key file a migration left behind (a crash or an error after the
    /// record) goes now, if it holds this key; a different one stays for
    /// the user to look at, and is never used.
    fn in_platform(&self) -> io::Result<Zeroizing<[u8; 32]>> {
        let platform = self.platform()?;
        let key = platform.load()?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "the storage key is missing from the platform key store",
            )
        })?;
        if self.file.exists() {
            if self.file.storage_key().is_ok_and(|stale| *stale == *key) {
                let _ = self.file.remove();
            }
        } else if self.file.retired().exists() {
            let _ = self.file.remove();
        }
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
        // The move is done: the key file is only a copy now. Failing to
        // remove it must not undo the move (the next start retries).
        let _ = self.file.remove();
        self.used_now(platform.protection());
        Ok(key)
    }

    fn in_file(&self) -> io::Result<Zeroizing<[u8; 32]>> {
        // Never back from the platform store, whatever went wrong.
        if self.recorded()? == Some(Backend::Platform) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the storage key is in the platform key store; it is never moved back to a file",
            ));
        }
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

/// A fresh name beside `path` for a file written before it moves into
/// place: random, so concurrent writers never share (or delete) one.
fn temporary(path: &Path) -> io::Result<PathBuf> {
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|_| io::Error::other("randomness"))?;
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{:016x}.tmp", u64::from_le_bytes(random)));
    Ok(path.with_file_name(name))
}

/// Makes a rename or removal in `path`'s directory durable (Unix: the
/// directory is synced; Windows has no such call, and the file system
/// journals metadata).
fn sync_parent(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// The profile's ID in the platform key stores (`storage.id` beside the
/// state, 32 random hexadecimal digits, created on first use and never
/// changed): the stores name the key by it, so moving or renaming the
/// state directory keeps its key.
///
/// # Errors
///
/// An I/O error; `InvalidData` for a damaged ID file.
pub fn profile_id(state_dir: &Path) -> io::Result<String> {
    crate::profile::private_dir(state_dir).map_err(|error| io::Error::other(error.to_string()))?;
    let path = state_dir.join("storage.id");
    let valid = |text: &str| {
        text.len() == 32
            && text
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    };
    match open_private(&path, false) {
        Ok(mut file) => {
            let mut text = String::new();
            std::io::Read::take(&mut file, 64).read_to_string(&mut text)?;
            let text = text.trim_ascii().to_owned();
            if valid(&text) {
                Ok(text)
            } else {
                Err(io::Error::new(io::ErrorKind::InvalidData, "storage.id"))
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random).map_err(|_| io::Error::other("randomness"))?;
            let id = random
                .iter()
                .fold(String::with_capacity(32), |mut id, byte| {
                    let _ = write!(id, "{byte:02x}");
                    id
                });
            let partial = state_dir.join(format!("storage.id.{id}.tmp"));
            let mut file = open_private(&partial, true)?;
            file.write_all(id.as_bytes())?;
            file.sync_all()?;
            drop(file);
            // Two first starts at once: the first ID wins; read it back.
            match std::fs::hard_link(&partial, &path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    let _ = std::fs::remove_file(&partial);
                    return Err(error);
                }
            }
            let _ = std::fs::remove_file(&partial);
            sync_parent(&path)?;
            profile_id(state_dir)
        }
        Err(error) => Err(error),
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

    /// A migration interrupted after its record (a crash, a key file the
    /// system would not delete): the profile stays in the platform store,
    /// the leftover file goes at the next start, and nothing ever reads a
    /// wiped file as a key.
    #[test]
    fn an_interrupted_migration_finishes_and_never_goes_back() -> TestResult {
        use crate::config::KeyStorage;
        let scratch = Scratch::new("selected-interrupted")?;
        std::fs::create_dir_all(&scratch.0)?;
        let file = KeyFile::new(scratch.0.join("storage.key"));
        let key = file.storage_key()?;
        let memory = Memory::default();
        memory.store(&key)?;
        std::fs::write(scratch.0.join("storage.backend"), b"platform\n")?;
        // The store is down: an error, never the file (even under Auto).
        memory.down(true);
        let down = selected(&scratch.0, &memory, KeyStorage::Auto).storage_key();
        assert!(down.is_err());
        assert_eq!(
            std::fs::read(scratch.0.join("storage.backend"))?,
            b"platform\n"
        );
        // Back: the key comes from the store, and the copy goes.
        memory.down(false);
        assert_eq!(
            selected(&scratch.0, &memory, KeyStorage::Auto).storage_key()?,
            key
        );
        assert!(!file.exists());
        assert!(!scratch.0.join("storage.key.retired").exists());
        Ok(())
    }

    /// Under `Platform`, a different key already in the store fails the
    /// start and changes nothing: the file, the store, and the record stay
    /// as they were.
    #[test]
    fn the_platform_policy_refuses_a_conflicting_key_and_changes_nothing() -> TestResult {
        use crate::config::KeyStorage;
        let scratch = Scratch::new("selected-conflict-platform")?;
        std::fs::create_dir_all(&scratch.0)?;
        let file = KeyFile::new(scratch.0.join("storage.key"));
        let key = file.storage_key()?;
        let before = std::fs::read(file.path())?;
        let memory = Memory::default();
        memory.store(&[7; 32])?;
        for _ in 0..2 {
            assert_eq!(
                selected(&scratch.0, &memory, KeyStorage::Platform)
                    .storage_key()
                    .map(|_| ())
                    .map_err(|e| e.kind()),
                Err(io::ErrorKind::AlreadyExists)
            );
        }
        assert_eq!(memory.key(), Some([7; 32]));
        assert_eq!(std::fs::read(file.path())?, before);
        assert_eq!(file.storage_key()?, key);
        assert!(!scratch.0.join("storage.backend").exists());
        assert!(!scratch.0.join("storage.key.retired").exists());
        Ok(())
    }

    /// A crash after the key went into the store but before the record was
    /// written (the store holds the file's key, no record exists): the next
    /// start completes the migration and nothing is lost.
    #[test]
    fn a_crash_between_the_store_and_the_record_migrates_cleanly() -> TestResult {
        use crate::config::KeyStorage;
        let scratch = Scratch::new("selected-crash-before-record")?;
        std::fs::create_dir_all(&scratch.0)?;
        let file = KeyFile::new(scratch.0.join("storage.key"));
        let key = file.storage_key()?;
        let memory = Memory::default();
        memory.store(&key)?;
        assert!(!scratch.0.join("storage.backend").exists());
        let source = selected(&scratch.0, &memory, KeyStorage::Auto);
        assert_eq!(source.storage_key()?, key);
        assert_eq!(memory.key(), Some(*key));
        assert!(!file.exists());
        assert!(!scratch.0.join("storage.key.retired").exists());
        assert_eq!(
            std::fs::read(scratch.0.join("storage.backend"))?,
            b"platform\n"
        );
        assert_eq!(source.protection(), crate::api::KeyProtection::Keychain);
        // And it stays: the next start reads the store.
        assert_eq!(
            selected(&scratch.0, &memory, KeyStorage::Auto).storage_key()?,
            key
        );
        Ok(())
    }

    /// Removing the key file twice (or when there never was one) is fine.
    #[test]
    fn removing_the_key_file_twice_is_fine() -> TestResult {
        let scratch = Scratch::new("key-file-remove-twice")?;
        std::fs::create_dir_all(&scratch.0)?;
        let file = KeyFile::new(scratch.0.join("storage.key"));
        file.remove()?;
        file.storage_key()?;
        assert!(file.exists());
        file.remove()?;
        assert!(!file.exists());
        file.remove()?;
        assert!(!file.exists());
        assert!(!scratch.0.join("storage.key.retired").exists());
        Ok(())
    }

    /// A wiped (all-zero) key file is refused, never used as a key; a
    /// retired file left behind is cleaned up.
    #[test]
    fn wiped_and_retired_key_files_are_never_keys() -> TestResult {
        use crate::config::KeyStorage;
        let scratch = Scratch::new("selected-wiped")?;
        std::fs::create_dir_all(&scratch.0)?;
        let path = scratch.0.join("storage.key");
        write_private(&path, &[0; 32])?;
        assert_eq!(
            KeyFile::new(&path)
                .storage_key()
                .map(|_| ())
                .map_err(|e| e.kind()),
            Err(io::ErrorKind::InvalidData)
        );
        std::fs::remove_file(&path)?;
        let memory = Memory::default();
        let key = selected(&scratch.0, &memory, KeyStorage::Auto).storage_key()?;
        write_private(&scratch.0.join("storage.key.retired"), &[9; 32])?;
        assert_eq!(
            selected(&scratch.0, &memory, KeyStorage::Auto).storage_key()?,
            key
        );
        assert!(!scratch.0.join("storage.key.retired").exists());
        Ok(())
    }

    /// A key sealed under a platform secret opens only with that secret and
    /// that profile's ID, and is never replaced.
    #[test]
    fn a_sealed_file_needs_its_secret_and_profile() -> TestResult {
        let scratch = Scratch::new("sealed-file")?;
        std::fs::create_dir_all(&scratch.0)?;
        let path = scratch.0.join("storage.key.sealed");
        let secret = |byte: u8| -> Box<dyn Fn() -> io::Result<Zeroizing<Vec<u8>>> + Send> {
            Box::new(move || Ok(Zeroizing::new(vec![byte; 64])))
        };
        let portal = crate::api::KeyProtection::Portal;
        let store = SealedFile::new(path.clone(), "a", portal, secret(1));
        assert!(store.load()?.is_none());
        store.store(&[5; 32])?;
        assert_eq!(store.load()?.map(|key| *key), Some([5; 32]));
        assert_eq!(
            store.store(&[6; 32]).map_err(|e| e.kind()),
            Err(io::ErrorKind::AlreadyExists)
        );
        assert!(!std::fs::read(&path)?.windows(32).any(|w| w == [5; 32]));
        assert!(
            SealedFile::new(path.clone(), "a", portal, secret(2))
                .load()
                .is_err()
        );
        assert!(
            SealedFile::new(path.clone(), "b", portal, secret(1))
                .load()
                .is_err()
        );
        let short: Box<dyn Fn() -> io::Result<Zeroizing<Vec<u8>>> + Send> =
            Box::new(|| Ok(Zeroizing::new(vec![1; 16])));
        assert!(SealedFile::new(path, "a", portal, short).load().is_err());
        Ok(())
    }

    /// The profile ID is made once, kept, and checked.
    #[test]
    fn the_profile_id_is_stable() -> TestResult {
        let scratch = Scratch::new("profile-id")?;
        let id = profile_id(&scratch.0)?;
        assert_eq!(id.len(), 32);
        assert_eq!(profile_id(&scratch.0)?, id);
        let other = Scratch::new("profile-id-other")?;
        assert_ne!(profile_id(&other.0)?, id);
        std::fs::write(scratch.0.join("storage.id"), b"not an id")?;
        assert!(profile_id(&scratch.0).is_err());
        Ok(())
    }

    /// Two first starts at once agree on one profile ID.
    ///
    /// Fails today: both start with the same partial file name
    /// (`storage.id.tmp`, `create_new`), so the loser gets `AlreadyExists`
    /// (or could link the winner's half-written file into place) instead
    /// of reading the first ID. A per-call temporary name fixes it.
    #[test]
    fn concurrent_first_starts_get_one_profile_id() -> TestResult {
        for round in 0..20 {
            let scratch = Scratch::new(&format!("profile-id-race-{round}"))?;
            let barrier = std::sync::Barrier::new(2);
            let ids = std::thread::scope(|scope| {
                let start = || {
                    barrier.wait();
                    profile_id(&scratch.0)
                };
                let first = scope.spawn(start);
                let second = scope.spawn(start);
                let join = |handle: std::thread::ScopedJoinHandle<'_, io::Result<String>>| {
                    handle
                        .join()
                        .map_err(|_| io::Error::other("a thread panicked"))?
                };
                Ok::<_, io::Error>((join(first)?, join(second)?))
            })?;
            assert_eq!(ids.0, ids.1, "round {round}");
            assert_eq!(profile_id(&scratch.0)?, ids.0);
        }
        Ok(())
    }

    fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut file = open_private(path, true)?;
        file.write_all(bytes)
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
