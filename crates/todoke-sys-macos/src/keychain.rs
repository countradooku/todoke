//! The storage key in the Keychain (§16 O9).
//!
//! In a signed build entitled to a Keychain access group, the key lives in
//! the data-protection keychain, readable only while this Mac is unlocked,
//! never synchronised or migrated to another device, and stored wrapped by
//! a P-256 key in the Secure Enclave (ECIES, X9.63 SHA-256, AES-GCM): the
//! stored item alone opens nothing off this machine. Without that
//! entitlement (development builds) it lives in the login keychain, whose
//! access list names the binary that created it.

use std::io;
use std::path::Path;
use std::sync::Mutex;

use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::item::{ItemClass, ItemSearchOptions, Location, Reference, SearchResult};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework::passwords::{
    self, AccessControlOptions, PasswordOptions, generic_password, set_generic_password_options,
};
use zeroize::Zeroizing;

/// The Keychain service of todoke's items.
const SERVICE: &str = "org.todoke.todoke";
/// `errSecItemNotFound`.
const NOT_FOUND: i32 = -25_300;
/// `errSecMissingEntitlement`: not signed for a Keychain access group.
const MISSING_ENTITLEMENT: i32 = -34_018;
/// `errSecDuplicateItem`.
const DUPLICATE: i32 = -25_299;

/// A stored blob: one format byte, then the payload.
const RAW: u8 = 1;
const WRAPPED: u8 = 2;

/// What protects a stored key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyProtection {
    /// The Keychain.
    Keychain,
    /// The data-protection Keychain, the key wrapped by a Secure Enclave key.
    SecureEnclave,
}

/// The storage key of one profile in the Keychain.
pub struct Keychain {
    account: String,
    wrap_label: String,
    protection: Mutex<KeyProtection>,
}

impl core::fmt::Debug for Keychain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Keychain")
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

fn os(error: security_framework::base::Error) -> io::Error {
    io::Error::other(format!("Keychain error {}", error.code()))
}

impl Keychain {
    /// The item for the profile whose state is in `state_dir` (its path
    /// names the item: profiles under different homes are separate).
    #[must_use]
    pub fn for_state(state_dir: &Path) -> Self {
        let account = format!("storage key: {}", state_dir.display());
        Self {
            wrap_label: format!("{SERVICE} wrap: {}", state_dir.display()),
            account,
            protection: Mutex::new(KeyProtection::Keychain),
        }
    }

    fn protected(&self) -> PasswordOptions {
        let mut options = PasswordOptions::new_generic_password(SERVICE, &self.account);
        options.use_protected_keychain();
        options.set_access_synchronized(Some(false));
        options
    }

    fn legacy(&self) -> PasswordOptions {
        PasswordOptions::new_generic_password(SERVICE, &self.account)
    }

    /// The stored blob and whether it came from the data-protection
    /// keychain; `Ok(None)` when there is none.
    fn blob(&self) -> io::Result<(Option<Vec<u8>>, bool)> {
        // Unsigned builds get "not found" or "missing entitlement" here,
        // depending on the macOS version: either way, look in the login
        // keychain too.
        let protected = match generic_password(self.protected()) {
            Ok(blob) => return Ok((Some(blob), true)),
            Err(error) if error.code() == NOT_FOUND => true,
            Err(error) if error.code() == MISSING_ENTITLEMENT => false,
            Err(error) => return Err(os(error)),
        };
        match generic_password(self.legacy()) {
            Ok(blob) => Ok((Some(blob), false)),
            Err(error) if error.code() == NOT_FOUND => Ok((None, protected)),
            Err(error) => Err(os(error)),
        }
    }

    /// The Secure Enclave key that wraps this profile's storage key.
    fn wrapping_key(&self) -> Option<SecKey> {
        let found = ItemSearchOptions::new()
            .class(ItemClass::key())
            .label(&self.wrap_label)
            .ignore_legacy_keychains()
            .load_refs(true)
            .search()
            .ok()?;
        found.into_iter().find_map(|result| match result {
            SearchResult::Ref(Reference::Key(key)) => Some(key),
            _ => None,
        })
    }

    /// Creates the wrapping key in the Secure Enclave, where present.
    fn new_wrapping_key(&self) -> Option<SecKey> {
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            AccessControlOptions::PRIVATE_KEY_USAGE.bits(),
        )
        .ok()?;
        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec_sec_prime_random())
            .set_size_in_bits(256)
            .set_label(self.wrap_label.clone())
            .set_token(Token::SecureEnclave)
            .set_location(Location::DataProtectionKeychain)
            .set_access_control(access);
        SecKey::new(&options).ok()
    }

    fn set_protection(&self, protection: KeyProtection) {
        if let Ok(mut current) = self.protection.lock() {
            *current = protection;
        }
    }

    /// Removes this profile's item and wrapping key (tests; removing a
    /// profile).
    ///
    /// # Errors
    ///
    /// The Keychain's error, other than "not found".
    pub fn delete(&self) -> io::Result<()> {
        for options in [self.protected(), self.legacy()] {
            match passwords::delete_generic_password_options(options) {
                Ok(()) => {}
                Err(error) if error.code() == NOT_FOUND || error.code() == MISSING_ENTITLEMENT => {}
                Err(error) => return Err(os(error)),
            }
        }
        if let Some(key) = self.wrapping_key() {
            key.delete().map_err(os)?;
        }
        Ok(())
    }
}

impl Keychain {
    /// What protects the stored key (after [`Self::load`] or [`Self::store`]).
    #[must_use]
    pub fn protection(&self) -> KeyProtection {
        self.protection
            .lock()
            .map_or(KeyProtection::Keychain, |current| *current)
    }

    /// The stored key, or `None` if none is stored.
    ///
    /// # Errors
    ///
    /// The store is unavailable or refused (never "no key").
    pub fn load(&self) -> io::Result<Option<Zeroizing<[u8; 32]>>> {
        let (Some(blob), _) = self.blob()? else {
            return Ok(None);
        };
        let blob = Zeroizing::new(blob);
        let (&format, payload) = blob
            .split_first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty Keychain item"))?;
        let plain = match format {
            RAW => Zeroizing::new(payload.to_vec()),
            WRAPPED => {
                let key = self.wrapping_key().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "the Secure Enclave key that wraps the storage key is gone",
                    )
                })?;
                let plain = key
                    .decrypt_data(
                        Algorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
                        payload,
                    )
                    .map_err(|_| io::Error::other("the Secure Enclave refused to unwrap"))?;
                Zeroizing::new(plain)
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unknown Keychain item format",
                ));
            }
        };
        let key: [u8; 32] = plain.as_slice().try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the stored key has the wrong size",
            )
        })?;
        self.set_protection(if format == WRAPPED {
            KeyProtection::SecureEnclave
        } else {
            KeyProtection::Keychain
        });
        Ok(Some(Zeroizing::new(key)))
    }

    /// Stores `key`; never replaces a stored one.
    ///
    /// # Errors
    ///
    /// `AlreadyExists` if a key is stored; the platform's error.
    pub fn store(&self, key: &[u8; 32]) -> io::Result<()> {
        let (existing, protected) = self.blob()?;
        if existing.is_some() {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        if protected {
            match self.store_protected(key) {
                Ok(protection) => {
                    self.set_protection(protection);
                    return Ok(());
                }
                // Not entitled after all: the login keychain.
                Err(error) if error.code() == MISSING_ENTITLEMENT => {}
                Err(error) if error.code() == DUPLICATE => {
                    return Err(io::ErrorKind::AlreadyExists.into());
                }
                Err(error) => return Err(os(error)),
            }
        }
        let mut blob = Zeroizing::new(Vec::with_capacity(33));
        blob.push(RAW);
        blob.extend_from_slice(key);
        match set_generic_password_options(&blob, self.legacy()) {
            Ok(()) => {}
            Err(error) if error.code() == DUPLICATE => {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            Err(error) => return Err(os(error)),
        }
        self.set_protection(KeyProtection::Keychain);
        Ok(())
    }
}

impl Keychain {
    /// Stores `key` in the data-protection keychain, wrapped by the Secure
    /// Enclave when it is there.
    fn store_protected(
        &self,
        key: &[u8; 32],
    ) -> Result<KeyProtection, security_framework::base::Error> {
        let mut blob = Zeroizing::new(Vec::with_capacity(160));
        let mut protection = KeyProtection::Keychain;
        // Wrapped by the Secure Enclave when it is there; the raw key
        // otherwise.
        let wrapped = self
            .wrapping_key()
            .or_else(|| self.new_wrapping_key())
            .and_then(|private| private.public_key())
            .and_then(|public| {
                public
                    .encrypt_data(
                        Algorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
                        key,
                    )
                    .ok()
            });
        if let Some(ciphertext) = wrapped {
            blob.push(WRAPPED);
            blob.extend_from_slice(&ciphertext);
            protection = KeyProtection::SecureEnclave;
        } else {
            blob.push(RAW);
            blob.extend_from_slice(key);
        }
        let mut options = self.protected();
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            0,
        )?;
        options.set_access_control(access);
        set_generic_password_options(&blob, options)?;
        Ok(protection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A key stored is the key loaded; a second store is refused; deleting
    /// leaves nothing. Uses an item of its own (a path no profile has).
    #[test]
    fn a_key_round_trips_through_the_keychain() -> TestResult {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random)?;
        let state = std::env::temp_dir().join(format!(
            "todoke-keychain-test-{}",
            u64::from_le_bytes(random)
        ));
        let keychain = Keychain::for_state(&state);
        let cleanup = scopeguard(|| {
            let _ = keychain.delete();
        });
        assert!(keychain.load()?.is_none());
        let key = [0x5a; 32];
        keychain.store(&key)?;
        assert_eq!(keychain.load()?.map(|k| *k), Some(key));
        assert!(matches!(
            keychain.protection(),
            KeyProtection::Keychain | KeyProtection::SecureEnclave
        ));
        assert_eq!(
            keychain.store(&[1; 32]).map_err(|e| e.kind()),
            Err(io::ErrorKind::AlreadyExists)
        );
        keychain.delete()?;
        assert!(keychain.load()?.is_none());
        drop(cleanup);
        Ok(())
    }

    /// Runs `f` when dropped (cleanup after a failed assertion too).
    fn scopeguard(f: impl FnOnce()) -> impl Drop {
        struct Guard<F: FnOnce()>(Option<F>);
        impl<F: FnOnce()> Drop for Guard<F> {
            fn drop(&mut self) {
                if let Some(f) = self.0.take() {
                    f();
                }
            }
        }
        Guard(Some(f))
    }
}
