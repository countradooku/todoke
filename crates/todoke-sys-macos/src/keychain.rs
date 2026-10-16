//! The storage key in the Keychain (§16 O9), on macOS and iOS.
//!
//! In a signed build entitled to a Keychain access group (every iOS app
//! is), the key lives in the data-protection keychain, readable only while
//! the device is unlocked, never synchronised, backed up, or migrated to
//! another device, and stored wrapped by a P-256 key in the Secure Enclave
//! (ECIES, X9.63 SHA-256, AES-GCM): the stored item alone opens nothing off
//! this device. Without that entitlement (macOS development builds) it
//! lives in the login keychain, whose access list names the binary that
//! created it; iOS has no such fallback.
//!
//! With [`Keychain::requiring_presence`], using the key needs the user:
//! Face ID, Touch ID, or the device passcode, asked by the system
//! (`LocalAuthentication`) each time the key is unwrapped. The access control
//! sits on the Secure Enclave key, or on the item where there is no Secure
//! Enclave (an Intel iOS Simulator). A refused or cancelled prompt is
//! [`io::ErrorKind::PermissionDenied`]; a locked-out, unenrolled, or
//! passcode-less device is an error to report.
//!
//! On an iOS device the key is never stored without the Secure Enclave,
//! and never outside the data-protection keychain.

use std::io;
use std::sync::Mutex;

use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::item::{ItemClass, ItemSearchOptions, Location, Reference, SearchResult};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework::passwords::{
    self, AccessControlOptions, PasswordOptions, generic_password,
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
/// `errSecUserCanceled` and `errSecInteractionNotAllowed`: the user did
/// not (or could not, the device being locked) unlock.
#[cfg(target_os = "macos")]
const REFUSED: &[i32] = &[-128, -25_308];
/// The same, and `errSecAuthFailed`: on iOS only the user's failed
/// authentication (on macOS it is also a login keychain item whose access
/// list names another binary, a real failure).
#[cfg(target_os = "ios")]
const REFUSED: &[i32] = &[-128, -25_293, -25_308];
/// `LAError` codes of an unlock the user cancelled or failed:
/// authentication failed, user cancel, user fallback, system cancel, app
/// cancel, not interactive. Lockout, no passcode, no enrolment, and the
/// rest are failures to report, not a prompt to repeat.
const LA_REFUSED: [isize; 6] = [-1, -2, -3, -4, -9, -1004];
/// `errSecNotAvailable`.
const NOT_AVAILABLE: i32 = -25_291;
/// Whether a key may be stored without the Secure Enclave when it cannot
/// be used: on macOS (Macs without one) and the iOS Simulator; never on an
/// iOS device, where every supported model has one and a failure is an
/// error, not a reason to weaken the key.
const ENCLAVE_OPTIONAL: bool = cfg!(any(target_os = "macos", target_abi = "sim"));

/// Whether an unwrap error from `domain` with `code` is the user's refusal.
fn refused_unwrap(domain: &str, code: isize) -> bool {
    if domain.contains("LocalAuthentication") {
        LA_REFUSED.contains(&code)
    } else {
        REFUSED
            .iter()
            .any(|refused| isize::try_from(*refused).is_ok_and(|refused| refused == code))
    }
}

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
    /// Whether a key stored from now on needs the user's presence.
    presence: bool,
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
    if REFUSED.contains(&error.code()) {
        return io::Error::new(io::ErrorKind::PermissionDenied, "the unlock was refused");
    }
    io::Error::other(format!("Keychain error {}", error.code()))
}

/// Adds `blob` as a new item with `options` (`SecItemAdd`): fails with
/// `errSecDuplicateItem` rather than updating an item already there, as
/// security-framework's password helpers would.
fn add(blob: &[u8], options: &PasswordOptions) -> Result<(), security_framework::base::Error> {
    use core_foundation::base::TCFType as _;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    #[allow(
        deprecated,
        reason = "the query is the documented way to read the options"
    )]
    let mut pairs = options.query.clone();
    // kSecValueData.
    pairs.push((
        CFString::from_static_string("v_Data"),
        CFData::from_buffer(blob).into_CFType(),
    ));
    let query = CFDictionary::<CFString, core_foundation::base::CFType>::from_CFType_pairs(&pairs);
    // ItemAddOptions cannot carry the access control the protected item
    // needs; this is the same SecItemAdd.
    #[allow(deprecated, reason = "ItemAddOptions has no access control")]
    security_framework::item::add_item(query.to_untyped())
}

impl Keychain {
    /// The item for the profile with ID `profile` (random, kept beside the
    /// state: moving the state keeps its key).
    #[must_use]
    pub fn for_profile(profile: &str) -> Self {
        Self {
            account: format!("storage key: {profile}"),
            wrap_label: format!("{SERVICE} wrap: {profile}"),
            presence: false,
            protection: Mutex::new(KeyProtection::Keychain),
        }
    }

    /// A key stored from now on needs the user's presence to be used (the
    /// access control is fixed when the key is stored; one stored already
    /// keeps its own).
    #[must_use]
    pub fn requiring_presence(mut self) -> Self {
        self.presence = true;
        self
    }

    /// The access-control flags of what this store creates.
    fn flags(&self, base: AccessControlOptions) -> AccessControlOptions {
        if self.presence {
            base | AccessControlOptions::USER_PRESENCE
        } else {
            base
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
            // iOS apps are always entitled: no weaker item to fall back to.
            #[cfg(target_os = "macos")]
            Err(error) if error.code() == MISSING_ENTITLEMENT => false,
            Err(error) => return Err(os(error)),
        };
        if cfg!(target_os = "ios") {
            return Ok((None, protected));
        }
        match generic_password(self.legacy()) {
            Ok(blob) => Ok((Some(blob), false)),
            Err(error) if error.code() == NOT_FOUND => Ok((None, protected)),
            Err(error) => Err(os(error)),
        }
    }

    /// The Secure Enclave key that wraps this profile's storage key.
    fn wrapping_key(&self) -> Option<SecKey> {
        let mut search = ItemSearchOptions::new();
        search
            .class(ItemClass::key())
            .label(&self.wrap_label)
            .load_refs(true);
        #[cfg(target_os = "macos")]
        search.ignore_legacy_keychains();
        search
            .search()
            .ok()?
            .into_iter()
            .find_map(|result| match result {
                SearchResult::Ref(Reference::Key(key)) => Some(key),
                _ => None,
            })
    }

    /// Creates the wrapping key in the Secure Enclave, where present.
    fn new_wrapping_key(&self) -> Option<SecKey> {
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            self.flags(AccessControlOptions::PRIVATE_KEY_USAGE).bits(),
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
                // With a presence requirement, the system asks the user here.
                let plain = key
                    .decrypt_data(
                        Algorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
                        payload,
                    )
                    .map_err(|error| {
                        // A cancelled or failed prompt: an OSStatus code, or
                        // LocalAuthentication's own domain.
                        let domain = error.domain().to_string();
                        if refused_unwrap(&domain, error.code()) {
                            io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "the unlock was refused",
                            )
                        } else {
                            io::Error::other(format!(
                                "the Secure Enclave refused to unwrap ({domain} {})",
                                error.code()
                            ))
                        }
                    })?;
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
                // Not entitled after all: the login keychain (macOS only).
                #[cfg(target_os = "macos")]
                Err(error) if error.code() == MISSING_ENTITLEMENT => {}
                Err(error) if error.code() == DUPLICATE => {
                    return Err(io::ErrorKind::AlreadyExists.into());
                }
                Err(error) => return Err(os(error)),
            }
        }
        // iOS has no login keychain: an item outside the data-protection
        // keychain would not be "this device only".
        if cfg!(target_os = "ios") {
            return Err(io::Error::other(
                "the data-protection keychain is unavailable",
            ));
        }
        let mut blob = Zeroizing::new(Vec::with_capacity(33));
        blob.push(RAW);
        blob.extend_from_slice(key);
        match add(&blob, &self.legacy()) {
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
        // No item is stored (`store` checked), so a wrapping key still
        // there was left by a store that did not finish: never reused, as
        // its access control may not be what is asked now.
        if let Some(orphan) = self.wrapping_key() {
            orphan.delete()?;
        }
        // Wrapped by the Secure Enclave; the raw key only where the
        // enclave is optional and cannot be used.
        let wrapped = match self.new_wrapping_key() {
            Some(private) => Some(
                private
                    .public_key()
                    .and_then(|public| {
                        public
                            .encrypt_data(
                                Algorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
                                key,
                            )
                            .ok()
                    })
                    .ok_or_else(|| security_framework::base::Error::from_code(NOT_AVAILABLE))?,
            ),
            None if ENCLAVE_OPTIONAL => None,
            None => return Err(security_framework::base::Error::from_code(NOT_AVAILABLE)),
        };
        if let Some(ciphertext) = wrapped {
            blob.push(WRAPPED);
            blob.extend_from_slice(&ciphertext);
            protection = KeyProtection::SecureEnclave;
        } else {
            blob.push(RAW);
            blob.extend_from_slice(key);
        }
        let mut options = self.protected();
        // The wrapped key's presence requirement is on the Secure Enclave
        // key; a raw key (no Secure Enclave) carries it on the item.
        let item_flags = if protection == KeyProtection::SecureEnclave {
            AccessControlOptions::empty()
        } else {
            self.flags(AccessControlOptions::empty())
        };
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            item_flags.bits(),
        )?;
        options.set_access_control(access);
        add(&blob, &options)?;
        Ok(protection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Only a cancelled or failed prompt is a refusal (the app offers to
    /// unlock again); lockout, no passcode, and other errors are failures.
    #[test]
    fn only_a_refused_prompt_is_a_refusal() {
        let la = "com.apple.LocalAuthentication";
        for code in [-1, -2, -3, -4, -9, -1004] {
            assert!(refused_unwrap(la, code), "{code}");
        }
        // Lockout, passcode not set, not enrolled, not available.
        for code in [-5, -6, -7, -8, -1000] {
            assert!(!refused_unwrap(la, code), "{code}");
        }
        assert!(refused_unwrap("NSOSStatusErrorDomain", -128));
        assert!(refused_unwrap("NSOSStatusErrorDomain", -25_308));
        assert_eq!(
            refused_unwrap("NSOSStatusErrorDomain", -25_293),
            cfg!(target_os = "ios")
        );
        assert!(!refused_unwrap("NSOSStatusErrorDomain", -25_300));
        assert!(!refused_unwrap("NSOSStatusErrorDomain", -2));
    }

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
        let keychain = Keychain::for_profile(&state.display().to_string());
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
        // Below the check too, adding never replaces the item.
        let mut blob = vec![RAW];
        blob.extend_from_slice(&[2; 32]);
        assert_eq!(
            add(&blob, &keychain.legacy()).map_err(security_framework::base::Error::code),
            Err(DUPLICATE)
        );
        assert_eq!(keychain.load()?.map(|k| *k), Some(key));
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
