//! Signing-key custody (`KeyStore`) and its backends.
//!
//! Private keys never leave a key store as plaintext: callers receive public
//! keys, signatures, and, for explicitly exportable person roots only, an
//! encrypted [`WrappedKey`].
//!
//! # Backends
//!
//! | Backend | Status |
//! | --- | --- |
//! | [`SoftwareKeyStore`] | Implemented. Seeds sealed with ChaCha20-Poly1305 under a caller-supplied [`StorageKey`]; for tests and Linux without a TPM. |
//! | Apple Secure Enclave–wrapped | Not implemented. Intended hook: a [`Sealer`](super::sealing::Sealer) whose key is held by the Secure Enclave. |
//! | Android `StrongBox` / TEE | Not implemented. Intended hook: a Keystore-backed [`Sealer`](super::sealing::Sealer), or a native [`KeyStore`] where the platform signs Ed25519 itself. |
//! | Windows TPM / DPAPI | Not implemented. Intended hook: a [`Sealer`](super::sealing::Sealer). |
//! | Linux Secret Service / TPM | Not implemented. Intended hook: a [`Sealer`](super::sealing::Sealer). |
//!
//! The platform rows are design intent, not verified API claims. Hardware
//! Ed25519 support differs by platform and OS version, so each adapter must be
//! checked against official platform documentation when it is written (O9).
//! When the platform only wraps a key, the Ed25519 seed is unsealed into
//! zeroizing Rust memory for the duration of one signature.

pub(crate) mod software;

use core::fmt;

use zeroize::Zeroizing;

use super::Hex;
use super::ed25519::{Ed25519PublicKey, Signature, SigningDomain};
use super::sealing::{SealError, StorageKey};
use super::storage::StorageError;
use crate::rng::{self, RandomError};

pub use software::{EncryptedKeyStore, SoftwareKeyStore};

/// Custody of Ed25519 signing keys.
///
/// Implementations must keep private keys out of logs, `Debug` output, errors,
/// and FFI, zeroize them on drop, and enforce [`SigningDomain::permits`].
pub trait KeyStore {
    /// Generates and durably stores a new key. The key is usable only after
    /// this returns `Ok`.
    ///
    /// # Errors
    ///
    /// Randomness, capacity, or persistence failure. On error no key is added.
    fn generate(&mut self, role: KeyRole, export: ExportPolicy) -> Result<KeyId, KeyStoreError>;

    /// The role a key was generated for.
    ///
    /// # Errors
    ///
    /// [`KeyStoreError::UnknownKey`].
    fn role(&self, key: &KeyId) -> Result<KeyRole, KeyStoreError>;

    /// The validated public key for `key`.
    ///
    /// # Errors
    ///
    /// [`KeyStoreError::UnknownKey`].
    fn public_key(&self, key: &KeyId) -> Result<Ed25519PublicKey, KeyStoreError>;

    /// Signs `domain || message` with pure Ed25519.
    ///
    /// # Errors
    ///
    /// [`KeyStoreError::DomainNotPermitted`] if the key's role may not sign in
    /// `domain`, [`KeyStoreError::UnknownKey`], or a backend failure.
    fn sign(
        &self,
        key: &KeyId,
        domain: SigningDomain,
        message: &[u8],
    ) -> Result<Signature, KeyStoreError>;

    /// Encrypts the private key under `wrapping_key` for backup.
    ///
    /// Device keys are never exportable (§2). Person roots are exportable only
    /// when generated with [`ExportPolicy::Exportable`]. Import and root
    /// recovery are not implemented (O4).
    ///
    /// # Errors
    ///
    /// [`KeyStoreError::NotExportable`], [`KeyStoreError::UnknownKey`], or a
    /// backend failure.
    fn export_wrapped(
        &self,
        key: &KeyId,
        wrapping_key: &WrappingKey,
    ) -> Result<WrappedKey, KeyStoreError>;

    /// Durably deletes a key and zeroizes its in-memory copy.
    ///
    /// Erasure from flash, backups, or OS caches is not guaranteed (§14.1).
    ///
    /// # Errors
    ///
    /// [`KeyStoreError::UnknownKey`] or persistence failure. On a persistence
    /// error the key remains present.
    fn delete(&mut self, key: &KeyId) -> Result<(), KeyStoreError>;
}

/// Random, nonzero handle for a stored key. Public; reveals nothing about the key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId([u8; 16]);

impl KeyId {
    pub(crate) fn random() -> Result<Self, RandomError> {
        rng::nonzero_id().map(Self)
    }

    /// Recreates a handle previously obtained from [`Self::to_bytes`].
    /// Returns `None` for the all-zero value.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 16]) -> Option<Self> {
        (bytes != [0; 16]).then_some(Self(bytes))
    }

    /// The handle bytes, for the caller to persist alongside its own state.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({:?})", Hex(&self.0))
    }
}

/// What a key is for. Fixed at generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyRole {
    /// A person's root: signs `DeviceBinding` and `Revoke` only.
    PersonRoot,
    /// A device key: signs possession, identity, Accept, and receipts only.
    Device,
}

impl KeyRole {
    pub(crate) const fn to_u8(self) -> u8 {
        match self {
            Self::PersonRoot => 1,
            Self::Device => 2,
        }
    }

    pub(crate) const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::PersonRoot),
            2 => Some(Self::Device),
            _ => None,
        }
    }
}

/// Whether [`KeyStore::export_wrapped`] may ever release a key. Fixed at generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExportPolicy {
    /// Never exportable.
    NonExportable,
    /// Exportable in wrapped form. Ignored for [`KeyRole::Device`].
    Exportable,
}

impl ExportPolicy {
    pub(crate) const fn to_u8(self) -> u8 {
        match self {
            Self::NonExportable => 0,
            Self::Exportable => 1,
        }
    }

    pub(crate) const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::NonExportable),
            1 => Some(Self::Exportable),
            _ => None,
        }
    }
}

/// A 256-bit key that encrypts an exported private key. Zeroized on drop;
/// `Debug` is redacted. How a user holds or recovers it is open (O4).
pub struct WrappingKey(StorageKey);

impl WrappingKey {
    /// Generates a key from the OS CSPRNG.
    ///
    /// # Errors
    ///
    /// [`RandomError`] if randomness is unavailable.
    pub fn generate() -> Result<Self, RandomError> {
        StorageKey::generate().map(Self)
    }

    /// Wraps caller-held key bytes. Never pass these across FFI.
    #[must_use]
    pub fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(StorageKey::from_bytes(bytes))
    }

    pub(crate) fn as_storage_key(&self) -> &StorageKey {
        &self.0
    }
}

impl fmt::Debug for WrappingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WrappingKey([REDACTED])")
    }
}

/// An exported private key encrypted under a [`WrappingKey`]. Its
/// confidentiality depends entirely on that key.
///
/// Layout: `version:u16 = 1 || role:u8 || public_key[32] || sealed`, where
/// `sealed` is the [`SoftwareSealer`](super::sealing::SoftwareSealer) output
/// over the 32-byte seed, with the preceding 35 bytes as associated data.
#[derive(Clone, PartialEq, Eq)]
pub struct WrappedKey(Vec<u8>);

impl WrappedKey {
    /// The encoded bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for WrappedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WrappedKey([{} encrypted bytes])", self.0.len())
    }
}

/// Key store failure. Variants carry no key material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyStoreError {
    /// No key with this handle.
    UnknownKey,
    /// The key exists but has a different role than required.
    WrongRole,
    /// The key's role may not sign in the requested domain.
    DomainNotPermitted,
    /// The key may not be exported.
    NotExportable,
    /// The store already holds its maximum number of keys.
    Capacity,
    /// The message exceeds the signing backend's length limit.
    MessageTooLong,
    /// OS randomness was unavailable.
    Random,
    /// Sealing or unsealing failed (wrong key, tampering, or backend error).
    Seal,
    /// Stored data is malformed.
    Corrupt,
    /// The storage backend failed.
    Storage(StorageError),
}

impl fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKey => f.write_str("unknown key"),
            Self::WrongRole => f.write_str("key has the wrong role"),
            Self::DomainNotPermitted => f.write_str("key may not sign in this domain"),
            Self::NotExportable => f.write_str("key is not exportable"),
            Self::Capacity => f.write_str("key store is full"),
            Self::MessageTooLong => f.write_str("message too long to sign"),
            Self::Random => f.write_str("randomness unavailable"),
            Self::Seal => f.write_str("key store sealing failed"),
            Self::Corrupt => f.write_str("key store data is malformed"),
            Self::Storage(error) => write!(f, "key store storage failed: {error}"),
        }
    }
}

impl std::error::Error for KeyStoreError {}

impl From<RandomError> for KeyStoreError {
    fn from(_: RandomError) -> Self {
        Self::Random
    }
}

impl From<SealError> for KeyStoreError {
    fn from(_: SealError) -> Self {
        Self::Seal
    }
}

impl From<StorageError> for KeyStoreError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}
