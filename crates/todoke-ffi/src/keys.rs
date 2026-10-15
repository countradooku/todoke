//! The storage key's source on each platform, behind the core's policy
//! ([`todoke_core::storage_key::Selected`]: a profile keeps its store, a
//! key file moves to the platform, never back).

use std::io;
use std::path::Path;
use std::sync::Arc;

use todoke_core::config::KeyStorage;
use todoke_core::storage_key::{PlatformKeyStore, Selected};
use zeroize::Zeroizing;

use crate::hooks::{KeyStore, KeyStoreError};

/// The source for the profile in `state_dir`: the app's key store if it
/// gave one, else the platform's own where Rust reaches it (the macOS
/// Keychain), else none (a private file, as the policy allows).
pub(crate) fn source(
    state_dir: &Path,
    key_store: Option<Arc<dyn KeyStore>>,
    policy: KeyStorage,
) -> Selected {
    let platform: Option<Box<dyn PlatformKeyStore>> = match key_store {
        Some(store) => Some(Box::new(App(store))),
        None => native(state_dir),
    };
    Selected::new(state_dir, platform, policy)
}

#[cfg(target_os = "macos")]
fn native(state_dir: &Path) -> Option<Box<dyn PlatformKeyStore>> {
    let id = todoke_core::storage_key::profile_id(state_dir).ok()?;
    Some(Box::new(Keychain(
        todoke_sys_macos::keychain::Keychain::for_profile(&id),
    )))
}

#[cfg(not(target_os = "macos"))]
fn native(_: &Path) -> Option<Box<dyn PlatformKeyStore>> {
    None
}

/// The app's key store, as the core sees it.
struct App(Arc<dyn KeyStore>);

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
        self.0.protection().into()
    }

    fn load(&self) -> io::Result<Option<Zeroizing<[u8; 32]>>> {
        let Some(bytes) = self.0.load().map_err(io_error)? else {
            return Ok(None);
        };
        let bytes = Zeroizing::new(bytes);
        let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the stored key has the wrong size",
            )
        })?;
        Ok(Some(Zeroizing::new(key)))
    }

    fn store(&self, key: &[u8; 32]) -> io::Result<()> {
        self.0.store(key.to_vec()).map_err(io_error)
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
