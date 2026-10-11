//! Shared fixtures for identity tests. All values are public test data.

use core::cell::Cell;
use core::num::NonZeroU64;
use std::rc::Rc;

use todoke_proto::identity::KEM_STATIC_LEN;
use todoke_proto::time::UnixTime;
use zeroize::Zeroizing;

use super::storage::StorageError;
use super::{
    BindingRequest, BlobStorage, ExportPolicy, IssueError, KeyId, KeyRole, KeyStore, KeyStoreError,
    MemoryStorage, SoftwareKeyStore, SoftwareSealer, StorageKey, VerifiedDeviceBinding,
    issue_device_binding,
};

pub(crate) type TestResult = Result<(), Box<dyn std::error::Error>>;

pub(crate) const T0: u64 = 1_760_000_000;
pub(crate) const DAY: u64 = 86_400;

pub(crate) fn time(seconds: u64) -> Result<UnixTime, &'static str> {
    UnixTime::new(seconds).ok_or("time out of range")
}

pub(crate) fn nz(value: u64) -> Result<NonZeroU64, &'static str> {
    NonZeroU64::new(value).ok_or("zero")
}

/// A valid ML-KEM-768 encapsulation key from a fixed public seed.
pub(crate) fn kem_static(seed: u8) -> Box<[u8; KEM_STATIC_LEN]> {
    let pair = libcrux_ml_kem::mlkem768::generate_key_pair([seed; 64]);
    Box::new(*pair.public_key().as_slice())
}

pub(crate) fn sealer(byte: u8) -> SoftwareSealer {
    SoftwareSealer::new(StorageKey::from_bytes(Zeroizing::new([byte; 32])))
}

pub(crate) fn memory_keystore() -> Result<SoftwareKeyStore<MemoryStorage>, KeyStoreError> {
    SoftwareKeyStore::open(sealer(1), MemoryStorage::new())
}

pub(crate) fn request(
    noise: u8,
    kem: u8,
    serial: u64,
    not_before: u64,
    not_after: u64,
) -> Result<BindingRequest, &'static str> {
    Ok(BindingRequest {
        noise_static: [noise; 32],
        kem_static: kem_static(kem),
        serial: nz(serial)?,
        not_before: time(not_before)?,
        not_after: time(not_after)?,
    })
}

/// A person root and one device in a single key store.
pub(crate) struct Enrolled {
    pub(crate) store: SoftwareKeyStore<MemoryStorage>,
    pub(crate) root: KeyId,
    pub(crate) device: KeyId,
}

impl Enrolled {
    pub(crate) fn new() -> Result<Self, KeyStoreError> {
        let mut store = memory_keystore()?;
        let root = store.generate(KeyRole::PersonRoot, ExportPolicy::NonExportable)?;
        let device = store.generate(KeyRole::Device, ExportPolicy::NonExportable)?;
        Ok(Self {
            store,
            root,
            device,
        })
    }

    /// Issues a 30-day binding from T0 with fixed Noise/KEM keys.
    pub(crate) fn bind(
        &self,
        serial: u64,
    ) -> Result<VerifiedDeviceBinding, Box<dyn std::error::Error>> {
        self.bind_with(serial, 0x33, 0x44)
    }

    /// Issues a 30-day binding from T0 certifying an actual X25519 key.
    pub(crate) fn bind_noise(
        &self,
        serial: u64,
        noise_static: [u8; 32],
    ) -> Result<VerifiedDeviceBinding, Box<dyn std::error::Error>> {
        let mut request = request(0x33, 0x44, serial, T0, T0 + 30 * DAY)?;
        request.noise_static = noise_static;
        issue_device_binding(&self.store, &self.root, &self.device, request)
            .map_err(|error: IssueError| error.into())
    }

    pub(crate) fn bind_with(
        &self,
        serial: u64,
        noise: u8,
        kem: u8,
    ) -> Result<VerifiedDeviceBinding, Box<dyn std::error::Error>> {
        let request = request(noise, kem, serial, T0, T0 + 30 * DAY)?;
        issue_device_binding(&self.store, &self.root, &self.device, request)
            .map_err(|error: IssueError| error.into())
    }
}

/// In-memory storage whose writes fail while the shared switch is on, for
/// exercising rollback and fail-closed paths. Loads always succeed.
#[derive(Debug, Default)]
pub(crate) struct SwitchableStorage {
    inner: MemoryStorage,
    failing: Rc<Cell<bool>>,
}

impl SwitchableStorage {
    /// The storage and the switch that makes its writes fail.
    pub(crate) fn new() -> (Self, Rc<Cell<bool>>) {
        let storage = Self::default();
        let switch = Rc::clone(&storage.failing);
        (storage, switch)
    }

    /// The last successfully stored blob.
    pub(crate) fn blob(&self) -> Option<&[u8]> {
        self.inner.blob()
    }
}

impl BlobStorage for SwitchableStorage {
    fn load(&self, max_len: usize) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.load(max_len)
    }

    fn store(&mut self, bytes: &[u8]) -> Result<(), StorageError> {
        if self.failing.get() {
            return Err(StorageError::Io(std::io::ErrorKind::Other));
        }
        self.inner.store(bytes)
    }
}

/// Asserts every message is nonempty and differs from every other one.
pub(crate) fn assert_distinct_messages(messages: &[String]) {
    for (index, message) in messages.iter().enumerate() {
        assert_ne!(message, "");
        assert!(!messages[..index].contains(message), "{message}");
    }
}
