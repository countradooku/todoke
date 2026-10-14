//! The storage key's source: the platform's secret storage where this
//! build has one (`todoke-sys-*`), behind the core's policy
//! ([`todoke_core::storage_key::Selected`]: a profile keeps its store, a key
//! file moves to the platform, never back).

use std::io;
use std::path::Path;

use todoke_core::api::KeyProtection;
use todoke_core::config::CoreConfig;
use todoke_core::storage_key::{PlatformKeyStore, Selected, profile_id};
use zeroize::Zeroizing;

/// The source for the profile `config` describes. The platform stores
/// name the key by the profile's ID ([`profile_id`]); without one (the
/// state directory cannot be made) there is no platform store, and the
/// policy decides.
#[must_use]
pub fn source(config: &CoreConfig) -> Selected {
    let platform = profile_id(&config.state_dir)
        .ok()
        .and_then(|id| platform(&config.state_dir, &id));
    Selected::new(&config.state_dir, platform, config.key_storage)
}

#[cfg(target_os = "macos")]
#[expect(
    clippy::unnecessary_wraps,
    reason = "builds without a platform store return None"
)]
fn platform(_: &Path, profile: &str) -> Option<Box<dyn PlatformKeyStore>> {
    Some(Box::new(Platform(
        todoke_sys_macos::keychain::Keychain::for_profile(profile),
    )))
}

#[cfg(windows)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "builds without a platform store return None"
)]
fn platform(state_dir: &Path, profile: &str) -> Option<Box<dyn PlatformKeyStore>> {
    Some(Box::new(Platform(todoke_sys_windows::dpapi::Dpapi::new(
        state_dir, profile,
    ))))
}

#[cfg(target_os = "linux")]
#[expect(
    clippy::unnecessary_wraps,
    reason = "builds without a platform store return None"
)]
fn platform(state_dir: &Path, profile: &str) -> Option<Box<dyn PlatformKeyStore>> {
    // Inside Flatpak: sealed under the Secret portal's per-app secret, with
    // no access to the keyring itself.
    if todoke_sys_linux::portal::sandboxed() {
        return Some(Box::new(todoke_core::storage_key::SealedFile::new(
            state_dir.join("storage.key.sealed"),
            profile,
            KeyProtection::Portal,
            Box::new(todoke_sys_linux::secret_portal::retrieve),
        )));
    }
    Some(Box::new(Platform(
        todoke_sys_linux::secret_service::SecretService::for_profile(profile),
    )))
}

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
fn platform(_: &Path, _: &str) -> Option<Box<dyn PlatformKeyStore>> {
    None
}

/// A platform store, as the core sees it.
#[cfg_attr(
    not(any(target_os = "macos", windows, target_os = "linux")),
    expect(dead_code)
)]
struct Platform<T>(T);

#[cfg(target_os = "macos")]
impl PlatformKeyStore for Platform<todoke_sys_macos::keychain::Keychain> {
    fn protection(&self) -> KeyProtection {
        match self.0.protection() {
            todoke_sys_macos::keychain::KeyProtection::Keychain => KeyProtection::Keychain,
            todoke_sys_macos::keychain::KeyProtection::SecureEnclave => {
                KeyProtection::SecureEnclave
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

#[cfg(windows)]
impl PlatformKeyStore for Platform<todoke_sys_windows::dpapi::Dpapi> {
    fn protection(&self) -> KeyProtection {
        match self.0.protection() {
            todoke_sys_windows::dpapi::KeyProtection::Dpapi => KeyProtection::Dpapi,
            todoke_sys_windows::dpapi::KeyProtection::Tpm => KeyProtection::Tpm,
        }
    }
    fn load(&self) -> io::Result<Option<Zeroizing<[u8; 32]>>> {
        self.0.load()
    }
    fn store(&self, key: &[u8; 32]) -> io::Result<()> {
        self.0.store(key)
    }
}

#[cfg(target_os = "linux")]
impl PlatformKeyStore for Platform<todoke_sys_linux::secret_service::SecretService> {
    fn protection(&self) -> KeyProtection {
        KeyProtection::SecretService
    }
    fn load(&self) -> io::Result<Option<Zeroizing<[u8; 32]>>> {
        self.0.load()
    }
    fn store(&self, key: &[u8; 32]) -> io::Result<()> {
        self.0.store(key)
    }
}
