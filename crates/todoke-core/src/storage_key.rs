//! Where the key that seals this device's state comes from.
//!
//! PROTOCOL §16 O9 leaves platform secret storage open: the Secure
//! Enclave, StrongBox/TEE, TPM/DPAPI, the macOS Keychain, and Secret
//! Service adapters come with the platform integration (P13). Until then
//! [`KeyFile`] keeps the 32-byte key in a file only this user can read,
//! next to the state it seals. That protects the state from other local
//! users and from copies of the state without the key file, **not** from
//! malware running as this user or from a full-disk copy; it is recorded as
//! a residual risk (docs/adr/0008-core-daemon-cli.md).

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
}
