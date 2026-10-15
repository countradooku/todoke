//! The storage key's source on each platform, behind the core's policy
//! ([`todoke_core::storage_key::Selected`]: a profile keeps its store, a
//! key file moves to the platform, never back).

use std::io;
use std::path::Path;
use std::sync::Arc;

use todoke_core::config::KeyStorage;
use todoke_core::storage_key::{PlatformKeyStore, Selected};
use zeroize::Zeroizing;

use crate::error::TodokeError;
use crate::hooks::{KeyStore, KeyStoreError};

/// The source for the profile in `state_dir`: the app's key store if it
/// gave one, else the platform's own where Rust reaches it (the macOS
/// Keychain), else none (a private file, as the policy allows).
///
/// # Errors
///
/// [`TodokeError::Profile`] when the profile's ID cannot be made (the
/// state directory cannot be written).
pub(crate) fn source(
    state_dir: &Path,
    key_store: Option<Arc<dyn KeyStore>>,
    policy: KeyStorage,
) -> Result<Selected, TodokeError> {
    let platform: Option<Box<dyn PlatformKeyStore>> = match key_store {
        Some(store) => Some(Box::new(App {
            store,
            profile: profile(state_dir)?,
        })),
        None => native(state_dir)?,
    };
    Ok(Selected::new(state_dir, platform, policy))
}

/// The profile's ID (made on first use), which names its key in a store.
/// Never skipped: a profile without one would fall back to a key file.
fn profile(state_dir: &Path) -> Result<String, TodokeError> {
    todoke_core::storage_key::profile_id(state_dir).map_err(|error| TodokeError::Profile {
        message: format!("the profile cannot be named: {}", error.kind()),
    })
}

#[cfg(target_os = "macos")]
fn native(state_dir: &Path) -> Result<Option<Box<dyn PlatformKeyStore>>, TodokeError> {
    let id = profile(state_dir)?;
    Ok(Some(Box::new(Keychain(
        todoke_sys_macos::keychain::Keychain::for_profile(&id),
    ))))
}

#[cfg(not(target_os = "macos"))]
#[expect(clippy::unnecessary_wraps, reason = "fallible on macOS")]
fn native(_: &Path) -> Result<Option<Box<dyn PlatformKeyStore>>, TodokeError> {
    Ok(None)
}

/// The app's key store, as the core sees it.
struct App {
    store: Arc<dyn KeyStore>,
    profile: String,
}

fn io_error(error: KeyStoreError) -> io::Error {
    match error {
        KeyStoreError::AlreadyExists => io::ErrorKind::AlreadyExists.into(),
        KeyStoreError::Refused { message } => {
            io::Error::new(io::ErrorKind::PermissionDenied, message)
        }
        KeyStoreError::Unavailable { message } => io::Error::other(message),
    }
}

impl PlatformKeyStore for App {
    fn protection(&self) -> todoke_core::api::KeyProtection {
        self.store.protection().into()
    }

    fn load(&self) -> io::Result<Option<Zeroizing<[u8; 32]>>> {
        let Some(bytes) = self.store.load(self.profile.clone()).map_err(io_error)? else {
            return Ok(None);
        };
        let bytes = Zeroizing::new(bytes);
        let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the stored key has the wrong size",
            )
        })?;
        // A wiped or never-written slot (all zeros) is never a key.
        if key.iter().all(|&byte| byte == 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the stored key is all zeros",
            ));
        }
        Ok(Some(Zeroizing::new(key)))
    }

    fn store(&self, key: &[u8; 32]) -> io::Result<()> {
        self.store
            .store(self.profile.clone(), key.to_vec())
            .map_err(io_error)
    }
}

/// The macOS Keychain, as the core sees it.
#[cfg(target_os = "macos")]
struct Keychain(todoke_sys_macos::keychain::Keychain);

#[cfg(target_os = "macos")]
impl PlatformKeyStore for Keychain {
    fn protection(&self) -> todoke_core::api::KeyProtection {
        match self.0.protection() {
            todoke_sys_macos::keychain::KeyProtection::Keychain => {
                todoke_core::api::KeyProtection::Keychain
            }
            todoke_sys_macos::keychain::KeyProtection::SecureEnclave => {
                todoke_core::api::KeyProtection::SecureEnclave
            }
        }
    }

    fn load(&self) -> io::Result<Option<Zeroizing<[u8; 32]>>> {
        self.0.load()
    }

    fn store(&self, key: &[u8; 32]) -> io::Result<()> {
        self.0.store(key)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::types::KeyProtection;

    /// A key store that answers `load` with what it was given and records
    /// what it was asked to store.
    struct Canned {
        load: Result<Option<Vec<u8>>, KeyStoreError>,
        store: Result<(), KeyStoreError>,
        stored: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl KeyStore for Canned {
        fn protection(&self) -> KeyProtection {
            KeyProtection::StrongBox
        }
        fn load(&self, _: String) -> Result<Option<Vec<u8>>, KeyStoreError> {
            self.load.clone()
        }
        fn store(&self, profile: String, key: Vec<u8>) -> Result<(), KeyStoreError> {
            if let Ok(mut stored) = self.stored.lock() {
                stored.push((profile, key));
            }
            self.store.clone()
        }
    }

    fn adapter(
        load: Result<Option<Vec<u8>>, KeyStoreError>,
        store: Result<(), KeyStoreError>,
    ) -> (Arc<Canned>, App) {
        let canned = Arc::new(Canned {
            load,
            store,
            stored: Mutex::new(Vec::new()),
        });
        let app = App {
            store: Arc::clone(&canned) as Arc<dyn KeyStore>,
            profile: "0123456789abcdef0123456789abcdef".to_owned(),
        };
        (canned, app)
    }

    /// Only 32 bytes that are not all zeros are a key; nothing stored is
    /// no key, not an error.
    #[test]
    fn only_a_whole_key_is_a_key() -> io::Result<()> {
        for length in [0, 1, 31, 33, 64] {
            let (_, app) = adapter(Ok(Some(vec![7; length])), Ok(()));
            assert_eq!(
                app.load().map(|_| ()).map_err(|error| error.kind()),
                Err(io::ErrorKind::InvalidData),
                "{length} bytes"
            );
        }
        let (_, app) = adapter(Ok(Some(vec![0; 32])), Ok(()));
        assert_eq!(
            app.load().map(|_| ()).map_err(|error| error.kind()),
            Err(io::ErrorKind::InvalidData)
        );
        // One byte set is enough not to be a wiped slot.
        let mut key = vec![0; 32];
        key[31] = 1;
        let (_, app) = adapter(Ok(Some(key.clone())), Ok(()));
        assert_eq!(app.load()?.map(|key| key.to_vec()), Some(key));
        let (_, app) = adapter(Ok(None), Ok(()));
        assert!(app.load()?.is_none());
        Ok(())
    }

    /// The key store's failures reach the core as the kinds its policy
    /// tells apart (a stored key is never replaced: `AlreadyExists`).
    #[test]
    fn key_store_failures_keep_their_kind() {
        let failures = [
            (KeyStoreError::AlreadyExists, io::ErrorKind::AlreadyExists),
            (
                KeyStoreError::Refused {
                    message: "denied".into(),
                },
                io::ErrorKind::PermissionDenied,
            ),
            (
                KeyStoreError::Unavailable {
                    message: "locked".into(),
                },
                io::ErrorKind::Other,
            ),
        ];
        for (failure, kind) in failures {
            let (_, app) = adapter(Err(failure.clone()), Err(failure));
            assert_eq!(app.load().map(|_| ()).map_err(|e| e.kind()), Err(kind));
            assert_eq!(app.store(&[1; 32]).map_err(|e| e.kind()), Err(kind));
        }
    }

    /// The key is stored whole, under the profile's ID, and the store's
    /// protection is reported as the core's.
    #[test]
    fn the_key_is_stored_under_the_profile() -> io::Result<()> {
        let (canned, app) = adapter(Ok(None), Ok(()));
        app.store(&[9; 32])?;
        let stored = canned
            .stored
            .lock()
            .map(|stored| stored.clone())
            .unwrap_or_default();
        assert_eq!(
            stored,
            [("0123456789abcdef0123456789abcdef".to_owned(), vec![9; 32])]
        );
        assert_eq!(app.protection(), todoke_core::api::KeyProtection::StrongBox);
        Ok(())
    }
}
