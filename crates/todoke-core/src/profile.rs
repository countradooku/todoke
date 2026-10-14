//! This device's persistent identity: its key store, Noise static key,
//! device binding, and contacts, in a private state directory.
//!
//! | File | Contents | Protection |
//! | --- | --- | --- |
//! | `keys.bin` | Person root and device signing keys | Sealed by the key store |
//! | `device.bin` | Key IDs, the X25519 Noise static secret, the binding | Sealed here ([`DEVICE_CONTEXT`]) |
//! | `contacts.bin` | Pinned peers, pair PSKs, revocations | Sealed by the contact store |
//!
//! Everything is sealed under one [`StorageKey`] from a
//! [`StorageKeySource`]. Where that key lives decides how well the state is
//! protected at rest; PROTOCOL §16 O9 leaves platform secret storage open
//! (see [`crate::storage_key`]).
//!
//! The device binding is valid for [`BINDING_LIFETIME`] and renewed with
//! the next serial once less than [`BINDING_RENEWAL`] remains; peers accept
//! the renewal because its serial is higher (§2). The ML-KEM-768 credential
//! in it is a retained public credential that nothing uses (§16 O11): its
//! secret half is never kept.

use core::fmt;
use core::num::NonZeroU64;
use std::path::{Path, PathBuf};

use todoke_crypto::identity::{
    BindingRequest, BlobStorage, ContactStore, ExportPolicy, FileStorage, KeyId, KeyRole, KeyStore,
    PersonIdentity, RevocationSet, Sealer, SoftwareKeyStore, SoftwareSealer, StorageKey,
    VerifiedDeviceBinding, issue_device_binding,
};
use todoke_crypto::session::{LocalIdentity, NoiseStaticKey};
use todoke_proto::identity::{DeviceBinding, KEM_STATIC_LEN};
use todoke_proto::time::UnixTime;
use zeroize::Zeroizing;

use crate::storage_key::StorageKeySource;

/// A binding's validity: one year (§2 allows at most 366 days).
pub const BINDING_LIFETIME: u64 = 365 * 86_400;
/// A binding is renewed once less than this remains: 30 days.
pub const BINDING_RENEWAL: u64 = 30 * 86_400;
/// The sealing context of `device.bin`.
pub const DEVICE_CONTEXT: &[u8] = b"todoke/core/device-record/v1\0";
/// The local format version of `device.bin`.
const DEVICE_VERSION: u8 = 1;
/// The largest `device.bin` read (a binding is under 2 KiB).
const DEVICE_MAX: usize = 8 << 10;
/// Clock tolerance at the start of a new binding (§1: 120 seconds).
const SKEW: u64 = 120;

/// The key store type this crate uses.
pub type Keys = SoftwareKeyStore<FileStorage>;
/// The contact store type this crate uses.
pub type Contacts = ContactStore<SoftwareSealer, FileStorage>;

/// Why the profile could not be opened.
#[derive(Debug)]
pub enum ProfileError {
    /// The state directory or a file in it could not be used.
    Io(std::io::ErrorKind),
    /// The storage key could not be obtained.
    StorageKey,
    /// A stored file failed authentication or did not decode: wrong storage
    /// key, damage, or tampering. Nothing is overwritten.
    Corrupt(&'static str),
    /// The key store, contact store, or binding issuance failed.
    Crypto(String),
    /// OS randomness was unavailable.
    Random,
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(kind) => write!(f, "state directory: {kind}"),
            Self::StorageKey => f.write_str("the storage key is unavailable"),
            Self::Corrupt(what) => write!(f, "{what} is damaged or was sealed with another key"),
            Self::Crypto(what) => write!(f, "{what}"),
            Self::Random => f.write_str("OS randomness is unavailable"),
        }
    }
}

impl std::error::Error for ProfileError {}

impl From<std::io::Error> for ProfileError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.kind())
    }
}

fn crypto(error: impl fmt::Display) -> ProfileError {
    ProfileError::Crypto(error.to_string())
}

/// The sealed device record.
struct DeviceRecord {
    root: KeyId,
    device: KeyId,
    noise_secret: Zeroizing<[u8; 32]>,
    binding: Vec<u8>,
}

impl DeviceRecord {
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ProfileError> {
        let len =
            u16::try_from(self.binding.len()).map_err(|_| ProfileError::Corrupt("binding"))?;
        let mut out = Zeroizing::new(Vec::with_capacity(
            1 + 16 + 16 + 32 + 2 + self.binding.len(),
        ));
        out.push(DEVICE_VERSION);
        out.extend_from_slice(&self.root.to_bytes());
        out.extend_from_slice(&self.device.to_bytes());
        out.extend_from_slice(self.noise_secret.as_slice());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.binding);
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let (&version, rest) = bytes.split_first()?;
        if version != DEVICE_VERSION {
            return None;
        }
        let (root, rest) = rest.split_first_chunk::<16>()?;
        let (device, rest) = rest.split_first_chunk::<16>()?;
        let (noise, rest) = rest.split_first_chunk::<32>()?;
        let (len, binding) = rest.split_first_chunk::<2>()?;
        if binding.len() != usize::from(u16::from_be_bytes(*len)) {
            return None;
        }
        Some(Self {
            root: KeyId::from_bytes(*root)?,
            device: KeyId::from_bytes(*device)?,
            noise_secret: Zeroizing::new(*noise),
            binding: binding.to_vec(),
        })
    }
}

/// This device's identity and contacts, open.
pub struct Profile {
    dir: PathBuf,
    sealer: SoftwareSealer,
    keys: Keys,
    root: KeyId,
    device: KeyId,
    noise: NoiseStaticKey,
    binding: VerifiedDeviceBinding,
    contacts: Contacts,
}

impl fmt::Debug for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Profile").finish_non_exhaustive()
    }
}

impl Profile {
    /// Opens the profile in `dir` (created, private to this user, if
    /// missing), creating a new identity on first use and renewing the
    /// binding when it is close to expiry. `now` must be a trusted clock.
    ///
    /// # Errors
    ///
    /// [`ProfileError`]. A file that does not authenticate is never
    /// replaced: the caller decides what to do (a wrong key, or damage).
    pub fn open(
        dir: &Path,
        source: &dyn StorageKeySource,
        now: UnixTime,
    ) -> Result<Self, ProfileError> {
        private_dir(dir)?;
        let key_bytes = source.storage_key().map_err(|_| ProfileError::StorageKey)?;
        let sealer = || SoftwareSealer::new(StorageKey::from_bytes(Zeroizing::new(*key_bytes)));
        let mut keys = SoftwareKeyStore::open(sealer(), FileStorage::new(dir.join("keys.bin")))
            .map_err(|_| ProfileError::Corrupt("keys.bin"))?;
        let contacts = ContactStore::open(sealer(), FileStorage::new(dir.join("contacts.bin")))
            .map_err(|_| ProfileError::Corrupt("contacts.bin"))?;
        let device_sealer = sealer();
        let mut storage = FileStorage::new(dir.join("device.bin"));
        let record = if let Some(stored) = storage.load(DEVICE_MAX).map_err(crypto)? {
            let plain = device_sealer
                .open(DEVICE_CONTEXT, &stored)
                .map_err(|_| ProfileError::Corrupt("device.bin"))?;
            DeviceRecord::decode(&plain).ok_or(ProfileError::Corrupt("device.bin"))?
        } else {
            let record = create(&mut keys, now)?;
            let new_record = device_sealer
                .seal(DEVICE_CONTEXT, &record.encode()?)
                .map_err(crypto)?;
            storage.store(&new_record).map_err(crypto)?;
            record
        };
        let noise = NoiseStaticKey::from_secret(Zeroizing::new(*record.noise_secret))
            .map_err(|_| ProfileError::Corrupt("device.bin"))?;
        let root_public = keys.public_key(&record.root).map_err(crypto)?;
        let binding = DeviceBinding::decode(&record.binding)
            .map_err(|_| ProfileError::Corrupt("device.bin"))?;
        // Checked at its own start, so that an expired binding (a device that
        // was off for a long time) is still recognised and renewed below.
        let issued = binding.body().not_before();
        let binding = PersonIdentity::new(root_public)
            .verify_binding(&binding, issued, &RevocationSet::new())
            .map_err(|_| ProfileError::Corrupt("device.bin"))?;
        if binding.noise_static() != noise.public_key()
            || keys.public_key(&record.device).map_err(crypto)? != *binding.device_public()
        {
            return Err(ProfileError::Corrupt("device.bin"));
        }
        let mut profile = Self {
            dir: dir.to_owned(),
            sealer: device_sealer,
            keys,
            root: record.root,
            device: record.device,
            noise,
            binding,
            contacts,
        };
        profile.renew_if_due(now, &record.noise_secret)?;
        Ok(profile)
    }

    /// Renews the binding with the next serial if less than
    /// [`BINDING_RENEWAL`] remains (or it already expired).
    fn renew_if_due(&mut self, now: UnixTime, noise_secret: &[u8; 32]) -> Result<(), ProfileError> {
        let not_after = self.binding.binding().body().not_after().seconds();
        if not_after.saturating_sub(now.seconds()) > BINDING_RENEWAL {
            return Ok(());
        }
        let serial = self
            .binding
            .serial()
            .checked_add(1)
            .ok_or(ProfileError::Crypto("binding serial exhausted".into()))?;
        let binding = issue(
            &self.keys,
            &self.root,
            &self.device,
            *self.noise.public_key(),
            Box::new(*self.binding.kem_static()),
            serial,
            now,
        )?;
        let record = DeviceRecord {
            root: self.root,
            device: self.device,
            noise_secret: Zeroizing::new(*noise_secret),
            binding: binding.encode(),
        };
        let sealed = self
            .sealer
            .seal(DEVICE_CONTEXT, &record.encode()?)
            .map_err(crypto)?;
        FileStorage::new(self.dir.join("device.bin"))
            .store(&sealed)
            .map_err(crypto)?;
        self.binding = binding;
        Ok(())
    }

    /// The local identity for sessions, valid at `now`.
    ///
    /// # Errors
    ///
    /// [`ProfileError::Crypto`] if the binding is not valid at `now`.
    pub fn local(&self, now: UnixTime) -> Result<LocalIdentity<'_, Keys>, ProfileError> {
        LocalIdentity::new(&self.keys, self.device, &self.binding, &self.noise, now).map_err(crypto)
    }

    /// The key store.
    #[must_use]
    pub const fn keys(&self) -> &Keys {
        &self.keys
    }

    /// The device signing key.
    #[must_use]
    pub const fn device_key(&self) -> KeyId {
        self.device
    }

    /// The device binding.
    #[must_use]
    pub const fn binding(&self) -> &VerifiedDeviceBinding {
        &self.binding
    }

    /// The Noise static key.
    #[must_use]
    pub const fn noise(&self) -> &NoiseStaticKey {
        &self.noise
    }

    /// The contacts.
    #[must_use]
    pub const fn contacts(&self) -> &Contacts {
        &self.contacts
    }

    /// The contacts, for pairing and sessions.
    pub fn contacts_mut(&mut self) -> &mut Contacts {
        &mut self.contacts
    }

    /// The state directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Splits the profile into what a session needs at once: the local
    /// identity (borrowing the keys) and the contacts (mutably).
    ///
    /// # Errors
    ///
    /// As [`Self::local`].
    pub fn session_parts(
        &mut self,
        now: UnixTime,
    ) -> Result<(LocalIdentity<'_, Keys>, &mut Contacts), ProfileError> {
        let local = LocalIdentity::new(&self.keys, self.device, &self.binding, &self.noise, now)
            .map_err(crypto)?;
        Ok((local, &mut self.contacts))
    }
}

/// A new identity: a person root and device key in the key store, a Noise
/// static key, an unused ML-KEM credential, and the first binding.
fn create(keys: &mut Keys, now: UnixTime) -> Result<DeviceRecord, ProfileError> {
    let root = keys
        .generate(KeyRole::PersonRoot, ExportPolicy::NonExportable)
        .map_err(crypto)?;
    let device = keys
        .generate(KeyRole::Device, ExportPolicy::NonExportable)
        .map_err(crypto)?;
    let mut noise_secret = Zeroizing::new([0; 32]);
    getrandom::fill(noise_secret.as_mut_slice()).map_err(|_| ProfileError::Random)?;
    let noise = NoiseStaticKey::from_secret(Zeroizing::new(*noise_secret))
        .map_err(|_| ProfileError::Random)?;
    let mut seed = Zeroizing::new([0; 64]);
    getrandom::fill(seed.as_mut_slice()).map_err(|_| ProfileError::Random)?;
    // Only the public half is kept (O11: the credential is never used).
    // libcrux's key pair does not wipe its secret half when it goes out of
    // scope; that residue is recorded under O6 with the suite's others.
    let pair = libcrux_ml_kem::mlkem768::generate_key_pair(*seed);
    let kem: Box<[u8; KEM_STATIC_LEN]> = Box::new(*pair.public_key().as_slice());
    let binding = issue(
        keys,
        &root,
        &device,
        *noise.public_key(),
        kem,
        NonZeroU64::MIN,
        now,
    )?;
    Ok(DeviceRecord {
        root,
        device,
        noise_secret,
        binding: binding.encode(),
    })
}

fn issue(
    keys: &Keys,
    root: &KeyId,
    device: &KeyId,
    noise_static: [u8; 32],
    kem_static: Box<[u8; KEM_STATIC_LEN]>,
    serial: NonZeroU64,
    now: UnixTime,
) -> Result<VerifiedDeviceBinding, ProfileError> {
    let start = now.seconds().saturating_sub(SKEW);
    let request = BindingRequest {
        noise_static,
        kem_static,
        serial,
        not_before: UnixTime::new(start).ok_or(ProfileError::Crypto("time".into()))?,
        not_after: UnixTime::new(start.saturating_add(BINDING_LIFETIME))
            .ok_or(ProfileError::Crypto("time".into()))?,
    };
    issue_device_binding(keys, root, device, request).map_err(crypto)
}

/// Creates `dir` if needed, private to this user on Unix (0700), and
/// refuses one that others can read or write.
fn private_dir(dir: &Path) -> Result<(), ProfileError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        let mode = std::fs::metadata(dir)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(ProfileError::Io(std::io::ErrorKind::PermissionDenied));
        }
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
