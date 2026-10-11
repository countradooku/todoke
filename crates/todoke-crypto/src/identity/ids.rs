//! Device and person identifiers (PROTOCOL §2).

use core::fmt;

use super::Hex;
use super::ed25519::Ed25519PublicKey;
use super::keystore::{ExportPolicy, KeyId, KeyRole, KeyStore, KeyStoreError};

fn truncated_hash(key: &Ed25519PublicKey) -> [u8; 16] {
    let mut id = [0; 16];
    id.copy_from_slice(&blake3::hash(key.as_bytes()).as_bytes()[..16]);
    id
}

/// `device_id = B3(device_ed25519_public_key)[..16]`.
///
/// A lookup and display aid only. Authorization must compare the full 32-byte
/// key, and a collision must never merge identities.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId([u8; 16]);

impl DeviceId {
    /// Derives the ID of a device key.
    #[must_use]
    pub fn of(device_public: &Ed25519PublicKey) -> Self {
        Self(truncated_hash(device_public))
    }

    /// The 16 ID bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({:?})", Hex(&self.0))
    }
}

/// `person_id = B3(person_root)[..16]`. Same caveats as [`DeviceId`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PersonId([u8; 16]);

impl PersonId {
    /// Derives the ID of a person root key.
    #[must_use]
    pub fn of(person_root: &Ed25519PublicKey) -> Self {
        Self(truncated_hash(person_root))
    }

    /// The 16 ID bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for PersonId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PersonId({:?})", Hex(&self.0))
    }
}

/// This device's Ed25519 signing identity. The private key stays in the
/// [`KeyStore`]; this value holds only its handle and public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceIdentity {
    key: KeyId,
    public: Ed25519PublicKey,
}

impl DeviceIdentity {
    /// Generates a fresh, non-exportable device key (§2: device private keys
    /// are never shared between devices).
    ///
    /// # Errors
    ///
    /// Any [`KeyStoreError`] from generation or persistence.
    pub fn generate<K: KeyStore>(store: &mut K) -> Result<Self, KeyStoreError> {
        let key = store.generate(KeyRole::Device, ExportPolicy::NonExportable)?;
        Self::load(store, key)
    }

    /// Loads an existing device key from `store`.
    ///
    /// # Errors
    ///
    /// [`KeyStoreError::UnknownKey`] or [`KeyStoreError::WrongRole`].
    pub fn load<K: KeyStore>(store: &K, key: KeyId) -> Result<Self, KeyStoreError> {
        if store.role(&key)? != KeyRole::Device {
            return Err(KeyStoreError::WrongRole);
        }
        Ok(Self {
            key,
            public: store.public_key(&key)?,
        })
    }

    /// The key store handle.
    #[must_use]
    pub fn key(&self) -> KeyId {
        self.key
    }

    /// The full device public key.
    #[must_use]
    pub fn public_key(&self) -> &Ed25519PublicKey {
        &self.public
    }

    /// The truncated device ID.
    #[must_use]
    pub fn id(&self) -> DeviceId {
        DeviceId::of(&self.public)
    }
}
