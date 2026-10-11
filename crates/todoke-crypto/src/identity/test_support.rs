//! Shared fixtures for identity tests. All values are public test data.

use core::num::NonZeroU64;

use todoke_proto::identity::KEM_STATIC_LEN;
use todoke_proto::time::UnixTime;
use zeroize::Zeroizing;

use super::{
    BindingRequest, ExportPolicy, IssueError, KeyId, KeyRole, KeyStore, KeyStoreError,
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
