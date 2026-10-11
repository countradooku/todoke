//! Key store whose state is one sealed blob.

use core::fmt;
use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey};
use zeroize::Zeroizing;

use super::{ExportPolicy, KeyId, KeyRole, KeyStore, KeyStoreError, WrappedKey, WrappingKey};
use crate::identity::codec::{Envelope, LocalFormatError, Reader};
use crate::identity::ed25519::{Ed25519PublicKey, Signature, SigningDomain};
use crate::identity::sealing::{self, Sealer, SoftwareSealer};
use crate::identity::storage::{BlobStorage, FileStorage};
use crate::rng;

/// Most keys one store holds. A device needs one device key and at most a
/// few person roots; the bound keeps the blob small and decoding cheap.
pub const MAX_KEYS: usize = 64;

const SEED_LEN: usize = 32;
/// `key_id[16] || role:u8 || export:u8 || seed[32]`.
const ENTRY_LEN: usize = 16 + 1 + 1 + SEED_LEN;
const MAX_BLOB_LEN: usize = 6 + SoftwareSealer::OVERHEAD + 2 + MAX_KEYS * ENTRY_LEN;

const ENVELOPE: Envelope = Envelope {
    magic: *b"TDKS",
    version: 1,
    context: b"todoke/local/keystore\0",
};

const WRAPPED_KEY_VERSION: u16 = 1;
const WRAPPED_KEY_CONTEXT: &[u8] = b"todoke/local/wrapped-key\0";

pub(crate) struct Entry {
    role: KeyRole,
    export: ExportPolicy,
    public: Ed25519PublicKey,
    seed: Zeroizing<[u8; SEED_LEN]>,
}

impl Entry {
    fn from_seed(
        role: KeyRole,
        export: ExportPolicy,
        seed: Zeroizing<[u8; SEED_LEN]>,
    ) -> Result<Self, LocalFormatError> {
        // `SigningKey` and the `ExpandedSecretKey` it derives are wiped on drop.
        let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let public =
            Ed25519PublicKey::from_bytes(&public).map_err(|_| LocalFormatError::Malformed)?;
        Ok(Self {
            role,
            export,
            public,
            seed,
        })
    }
}

/// A [`KeyStore`] holding Ed25519 seeds in memory and persisting them as a
/// single [`Sealer`]-protected blob in a [`BlobStorage`].
///
/// Every mutation is persisted before it takes effect; on a persistence error
/// the in-memory state is rolled back.
///
/// Blob plaintext (local format v1, not a wire format):
/// `count:u16 || count × (key_id[16] || role:u8 || export:u8 || seed[32])`,
/// sorted by strictly increasing `key_id`. Public keys are re-derived on load.
pub struct EncryptedKeyStore<S: Sealer, B: BlobStorage> {
    sealer: S,
    storage: B,
    keys: BTreeMap<KeyId, Entry>,
}

/// The software backend: a [`SoftwareSealer`] under a caller-supplied
/// [`StorageKey`](crate::identity::StorageKey). Where that key comes from on
/// Linux without a TPM (for example a passphrase KDF) is not decided here.
pub type SoftwareKeyStore<B = FileStorage> = EncryptedKeyStore<SoftwareSealer, B>;

impl<S: Sealer, B: BlobStorage> EncryptedKeyStore<S, B> {
    /// Opens the store in `storage`, or starts empty if nothing is stored yet.
    ///
    /// # Errors
    ///
    /// [`KeyStoreError::Seal`] for a wrong key or tampered blob,
    /// [`KeyStoreError::Corrupt`] for malformed contents, or a storage error.
    pub fn open(sealer: S, storage: B) -> Result<Self, KeyStoreError> {
        let keys = match storage.load(MAX_BLOB_LEN)? {
            None => BTreeMap::new(),
            Some(blob) => {
                let plaintext = ENVELOPE.open(&sealer, &blob).map_err(map_format)?;
                decode(&plaintext).map_err(map_format)?
            }
        };
        Ok(Self {
            sealer,
            storage,
            keys,
        })
    }

    /// Number of stored keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the store holds no keys.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Handles of all stored keys, in handle order.
    pub fn key_ids(&self) -> impl Iterator<Item = KeyId> + '_ {
        self.keys.keys().copied()
    }

    /// The storage backend, for inspection.
    pub fn storage(&self) -> &B {
        &self.storage
    }

    fn persist(&mut self) -> Result<(), KeyStoreError> {
        let plaintext = encode(&self.keys);
        let blob = ENVELOPE
            .seal(&self.sealer, &plaintext)
            .map_err(map_format)?;
        self.storage.store(&blob)?;
        Ok(())
    }

    fn entry(&self, key: &KeyId) -> Result<&Entry, KeyStoreError> {
        self.keys.get(key).ok_or(KeyStoreError::UnknownKey)
    }
}

impl<S: Sealer, B: BlobStorage> KeyStore for EncryptedKeyStore<S, B> {
    fn generate(&mut self, role: KeyRole, export: ExportPolicy) -> Result<KeyId, KeyStoreError> {
        if self.keys.len() >= MAX_KEYS {
            return Err(KeyStoreError::Capacity);
        }
        let export = match role {
            KeyRole::Device => ExportPolicy::NonExportable,
            KeyRole::PersonRoot => export,
        };
        let mut seed = Zeroizing::new([0; SEED_LEN]);
        rng::fill(seed.as_mut())?;
        let entry = Entry::from_seed(role, export, seed).map_err(map_format)?;
        let mut id = KeyId::random()?;
        let mut attempts = 1;
        while self.keys.contains_key(&id) {
            if attempts == 4 {
                return Err(KeyStoreError::Random);
            }
            id = KeyId::random()?;
            attempts += 1;
        }
        self.keys.insert(id, entry);
        if let Err(error) = self.persist() {
            self.keys.remove(&id);
            return Err(error);
        }
        Ok(id)
    }

    fn role(&self, key: &KeyId) -> Result<KeyRole, KeyStoreError> {
        self.entry(key).map(|entry| entry.role)
    }

    fn public_key(&self, key: &KeyId) -> Result<Ed25519PublicKey, KeyStoreError> {
        self.entry(key).map(|entry| entry.public)
    }

    fn sign(
        &self,
        key: &KeyId,
        domain: SigningDomain,
        message: &[u8],
    ) -> Result<Signature, KeyStoreError> {
        let entry = self.entry(key)?;
        if !domain.permits(entry.role) {
            return Err(KeyStoreError::DomainNotPermitted);
        }
        let mut input = Vec::with_capacity(domain.bytes().len() + message.len());
        input.extend_from_slice(domain.bytes());
        input.extend_from_slice(message);
        Ok(sign_input(&entry.seed, &input))
    }

    fn export_wrapped(
        &self,
        key: &KeyId,
        wrapping_key: &WrappingKey,
    ) -> Result<WrappedKey, KeyStoreError> {
        let entry = self.entry(key)?;
        if entry.role != KeyRole::PersonRoot || entry.export != ExportPolicy::Exportable {
            return Err(KeyStoreError::NotExportable);
        }
        let header = wrapped_key_header(entry);
        let sealed = sealing::seal_with(
            wrapping_key.as_storage_key(),
            &wrapped_key_context(&header),
            entry.seed.as_ref(),
        )?;
        let mut out = Vec::with_capacity(header.len() + sealed.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&sealed);
        Ok(WrappedKey(out))
    }

    fn delete(&mut self, key: &KeyId) -> Result<(), KeyStoreError> {
        let entry = self.keys.remove(key).ok_or(KeyStoreError::UnknownKey)?;
        if let Err(error) = self.persist() {
            self.keys.insert(*key, entry);
            return Err(error);
        }
        // `entry.seed` is zeroized when `entry` drops here.
        Ok(())
    }
}

impl<S: Sealer, B: BlobStorage> fmt::Debug for EncryptedKeyStore<S, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedKeyStore")
            .field("keys", &self.keys.len())
            .finish_non_exhaustive()
    }
}

/// Pure Ed25519 (RFC 8032) over `input`, which already carries the domain.
///
/// Uses ed25519-dalek rather than libcrux-ed25519: libcrux 0.0.10 expands the
/// seed into a 96-byte stack array that it never wipes (§14.2), whereas
/// dalek's `SigningKey` and per-signature `ExpandedSecretKey` are
/// `ZeroizeOnDrop` with its default `zeroize` feature. dalek 3.0.0 still
/// leaves unwiped scratch of its own (the SHA-512 output it expands the seed
/// from, hasher states, and the nonce scalar); reviewing that is part of O6.
fn sign_input(seed: &[u8; SEED_LEN], input: &[u8]) -> Signature {
    Signature::from_bytes(SigningKey::from_bytes(seed).sign(input).to_bytes())
}

fn wrapped_key_header(entry: &Entry) -> [u8; 35] {
    let mut header = [0; 35];
    header[..2].copy_from_slice(&WRAPPED_KEY_VERSION.to_be_bytes());
    header[2] = entry.role.to_u8();
    header[3..].copy_from_slice(entry.public.as_bytes());
    header
}

fn wrapped_key_context(header: &[u8; 35]) -> Vec<u8> {
    let mut context = Vec::with_capacity(WRAPPED_KEY_CONTEXT.len() + header.len());
    context.extend_from_slice(WRAPPED_KEY_CONTEXT);
    context.extend_from_slice(header);
    context
}

fn map_format(error: LocalFormatError) -> KeyStoreError {
    match error {
        LocalFormatError::Malformed => KeyStoreError::Corrupt,
        LocalFormatError::Seal => KeyStoreError::Seal,
    }
}

pub(crate) fn encode(keys: &BTreeMap<KeyId, Entry>) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(2 + keys.len() * ENTRY_LEN));
    // `keys.len() <= MAX_KEYS` is enforced on every insertion and decode.
    let count = u16::try_from(keys.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&count.to_be_bytes());
    for (id, entry) in keys {
        out.extend_from_slice(&id.to_bytes());
        out.push(entry.role.to_u8());
        out.push(entry.export.to_u8());
        out.extend_from_slice(entry.seed.as_ref());
    }
    out
}

/// Decodes blob plaintext. Exposed to the fuzz harness via [`crate::identity::fuzzing`].
pub(crate) fn decode(bytes: &[u8]) -> Result<BTreeMap<KeyId, Entry>, LocalFormatError> {
    let mut reader = Reader::new(bytes);
    let count = usize::from(reader.u16()?);
    if count > MAX_KEYS || reader.remaining() != count * ENTRY_LEN {
        return Err(LocalFormatError::Malformed);
    }
    let mut keys = BTreeMap::new();
    let mut previous: Option<KeyId> = None;
    for _ in 0..count {
        let id = KeyId::from_bytes(reader.array()?).ok_or(LocalFormatError::Malformed)?;
        if previous.is_some_and(|previous| previous >= id) {
            return Err(LocalFormatError::Malformed);
        }
        previous = Some(id);
        let role = KeyRole::from_u8(reader.u8()?).ok_or(LocalFormatError::Malformed)?;
        let export = ExportPolicy::from_u8(reader.u8()?).ok_or(LocalFormatError::Malformed)?;
        if role == KeyRole::Device && export != ExportPolicy::NonExportable {
            return Err(LocalFormatError::Malformed);
        }
        let seed = Zeroizing::new(reader.array::<SEED_LEN>()?);
        keys.insert(id, Entry::from_seed(role, export, seed)?);
    }
    reader.finish()?;
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::sealing::StorageKey;
    use crate::identity::storage::{MemoryStorage, StorageError};
    use proptest::prelude::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn sealer(byte: u8) -> SoftwareSealer {
        SoftwareSealer::new(StorageKey::from_bytes(Zeroizing::new([byte; 32])))
    }

    fn memory_store() -> Result<SoftwareKeyStore<MemoryStorage>, KeyStoreError> {
        SoftwareKeyStore::open(sealer(7), MemoryStorage::new())
    }

    /// Storage that fails every write, to exercise rollback.
    struct FailingStorage;

    impl BlobStorage for FailingStorage {
        fn load(&self, _: usize) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(None)
        }

        fn store(&mut self, _: &[u8]) -> Result<(), StorageError> {
            Err(StorageError::Io(std::io::ErrorKind::Other))
        }
    }

    fn unwrap_exported(wrapping_key: &WrappingKey, wrapped: &WrappedKey) -> Option<[u8; 32]> {
        let (header, sealed) = wrapped.as_bytes().split_first_chunk::<35>()?;
        let seed = sealing::open_with(
            wrapping_key.as_storage_key(),
            &wrapped_key_context(header),
            sealed,
        )
        .ok()?;
        seed.as_slice().try_into().ok()
    }

    impl<S: Sealer, B: BlobStorage> EncryptedKeyStore<S, B> {
        /// Inserts a fixed public test seed, for known-answer tests only.
        pub(crate) fn insert_fixed_seed(
            &mut self,
            role: KeyRole,
            seed: [u8; 32],
        ) -> Result<KeyId, KeyStoreError> {
            let entry = Entry::from_seed(role, ExportPolicy::NonExportable, Zeroizing::new(seed))
                .map_err(map_format)?;
            let id = KeyId::random()?;
            self.keys.insert(id, entry);
            self.persist()?;
            Ok(id)
        }
    }

    /// RFC 8032 §7.1 TEST 1–3 through the store's own signing path, and
    /// agreement with the independent libcrux implementation.
    #[test]
    fn signing_path_matches_rfc8032_and_libcrux() -> TestResult {
        let vectors = [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ];
        for (seed, public, message, signature) in vectors {
            let seed: [u8; 32] = hex::decode(seed)?.try_into().map_err(|_| "seed")?;
            let message = hex::decode(message)?;
            let entry = Entry::from_seed(
                KeyRole::Device,
                ExportPolicy::NonExportable,
                Zeroizing::new(seed),
            )
            .map_err(|_| "seed")?;
            assert_eq!(entry.public.as_bytes().as_slice(), hex::decode(public)?);
            let signed = sign_input(&entry.seed, &message).to_bytes();
            assert_eq!(signed.as_slice(), hex::decode(signature)?);
            let reference = libcrux_ed25519::sign(&message, &seed).map_err(|_| "libcrux")?;
            assert_eq!(signed, reference);
        }
        Ok(())
    }

    #[test]
    fn generated_keys_sign_and_verify() -> TestResult {
        let mut store = memory_store()?;
        let device = store.generate(KeyRole::Device, ExportPolicy::NonExportable)?;
        let public = store.public_key(&device)?;
        let signature = store.sign(&device, SigningDomain::Identity, b"transcript")?;
        public.verify(SigningDomain::Identity, b"transcript", &signature)?;
        assert!(
            public
                .verify(SigningDomain::Accept, b"transcript", &signature)
                .is_err()
        );
        assert!(
            public
                .verify(SigningDomain::Identity, b"transcripT", &signature)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn domain_policy_is_enforced_by_role() -> TestResult {
        let mut store = memory_store()?;
        let root = store.generate(KeyRole::PersonRoot, ExportPolicy::NonExportable)?;
        let device = store.generate(KeyRole::Device, ExportPolicy::NonExportable)?;
        for domain in [
            SigningDomain::DevicePossession,
            SigningDomain::Identity,
            SigningDomain::Accept,
            SigningDomain::DeliveryReceipt,
        ] {
            assert_eq!(
                store.sign(&root, domain, b"m"),
                Err(KeyStoreError::DomainNotPermitted)
            );
            assert!(store.sign(&device, domain, b"m").is_ok());
        }
        for domain in [SigningDomain::DeviceBinding, SigningDomain::Revoke] {
            assert!(store.sign(&root, domain, b"m").is_ok());
            assert_eq!(
                store.sign(&device, domain, b"m"),
                Err(KeyStoreError::DomainNotPermitted)
            );
        }
        Ok(())
    }

    #[test]
    fn reopening_restores_identical_keys() -> TestResult {
        let mut store = memory_store()?;
        let root = store.generate(KeyRole::PersonRoot, ExportPolicy::Exportable)?;
        let device = store.generate(KeyRole::Device, ExportPolicy::NonExportable)?;
        let signature = store.sign(&device, SigningDomain::Accept, b"m")?;
        let mut storage = MemoryStorage::new();
        storage.set_blob(store.storage().blob().map(<[u8]>::to_vec));
        let reopened = SoftwareKeyStore::open(sealer(7), storage)?;
        assert_eq!(reopened.len(), 2);
        assert_eq!(reopened.public_key(&root)?, store.public_key(&root)?);
        assert_eq!(reopened.role(&device)?, KeyRole::Device);
        // Ed25519 is deterministic, so the same seed gives the same signature.
        assert_eq!(
            reopened.sign(&device, SigningDomain::Accept, b"m")?,
            signature
        );
        Ok(())
    }

    #[test]
    fn wrong_key_or_tampered_blob_fails_closed() -> TestResult {
        let mut store = memory_store()?;
        store.generate(KeyRole::Device, ExportPolicy::NonExportable)?;
        let blob = store.storage().blob().ok_or("no blob")?.to_vec();

        let mut storage = MemoryStorage::new();
        storage.set_blob(Some(blob.clone()));
        assert_eq!(
            SoftwareKeyStore::open(sealer(8), storage).err(),
            Some(KeyStoreError::Seal)
        );
        for index in 0..blob.len() {
            let mut changed = blob.clone();
            changed[index] ^= 0x01;
            let mut storage = MemoryStorage::new();
            storage.set_blob(Some(changed));
            assert!(SoftwareKeyStore::open(sealer(7), storage).is_err());
        }
        let mut storage = MemoryStorage::new();
        storage.set_blob(Some(vec![0; MAX_BLOB_LEN + 1]));
        assert_eq!(
            SoftwareKeyStore::open(sealer(7), storage).err(),
            Some(KeyStoreError::Storage(StorageError::TooLarge))
        );
        Ok(())
    }

    #[test]
    fn blob_does_not_contain_plaintext_seed() -> TestResult {
        let mut store = memory_store()?;
        let key = store.generate(KeyRole::PersonRoot, ExportPolicy::Exportable)?;
        let wrapping = WrappingKey::generate()?;
        let seed = unwrap_exported(&wrapping, &store.export_wrapped(&key, &wrapping)?)
            .ok_or("unwrap failed")?;
        let blob = store.storage().blob().ok_or("no blob")?;
        assert!(!blob.windows(32).any(|window| window == seed));
        Ok(())
    }

    #[test]
    fn delete_removes_key_durably() -> TestResult {
        let mut store = memory_store()?;
        let key = store.generate(KeyRole::Device, ExportPolicy::NonExportable)?;
        store.delete(&key)?;
        assert_eq!(store.public_key(&key), Err(KeyStoreError::UnknownKey));
        assert_eq!(store.delete(&key), Err(KeyStoreError::UnknownKey));
        let mut storage = MemoryStorage::new();
        storage.set_blob(store.storage().blob().map(<[u8]>::to_vec));
        assert!(SoftwareKeyStore::open(sealer(7), storage)?.is_empty());
        Ok(())
    }

    #[test]
    fn persistence_failure_rolls_back() -> TestResult {
        let mut store = SoftwareKeyStore::open(sealer(7), FailingStorage)?;
        assert!(matches!(
            store.generate(KeyRole::Device, ExportPolicy::NonExportable),
            Err(KeyStoreError::Storage(_))
        ));
        assert!(store.is_empty());
        Ok(())
    }

    #[test]
    fn capacity_is_bounded() -> TestResult {
        let mut store = memory_store()?;
        for _ in 0..MAX_KEYS {
            store.generate(KeyRole::Device, ExportPolicy::NonExportable)?;
        }
        assert_eq!(
            store.generate(KeyRole::Device, ExportPolicy::NonExportable),
            Err(KeyStoreError::Capacity)
        );
        Ok(())
    }

    #[test]
    fn export_policy() -> TestResult {
        let mut store = memory_store()?;
        let wrapping = WrappingKey::generate()?;
        let device = store.generate(KeyRole::Device, ExportPolicy::Exportable)?;
        assert_eq!(
            store.export_wrapped(&device, &wrapping),
            Err(KeyStoreError::NotExportable)
        );
        let locked = store.generate(KeyRole::PersonRoot, ExportPolicy::NonExportable)?;
        assert_eq!(
            store.export_wrapped(&locked, &wrapping),
            Err(KeyStoreError::NotExportable)
        );
        let root = store.generate(KeyRole::PersonRoot, ExportPolicy::Exportable)?;
        let wrapped = store.export_wrapped(&root, &wrapping)?;
        assert_eq!(wrapped.as_bytes().len(), 35 + 12 + 32 + 16);
        assert_eq!(
            &wrapped.as_bytes()[3..35],
            store.public_key(&root)?.as_bytes()
        );
        let seed = unwrap_exported(&wrapping, &wrapped).ok_or("unwrap failed")?;
        let mut public = [0; 32];
        libcrux_ed25519::secret_to_public(&mut public, &seed);
        assert_eq!(&public, store.public_key(&root)?.as_bytes());
        assert!(unwrap_exported(&WrappingKey::generate()?, &wrapped).is_none());
        Ok(())
    }

    #[test]
    fn debug_output_is_redacted() -> TestResult {
        let mut store = memory_store()?;
        let key = store.generate(KeyRole::PersonRoot, ExportPolicy::Exportable)?;
        let wrapping = WrappingKey::from_bytes(Zeroizing::new([0xab; 32]));
        let seed = unwrap_exported(&wrapping, &store.export_wrapped(&key, &wrapping)?)
            .ok_or("unwrap failed")?;
        let seed_hex = hex::encode(seed);
        let rendered = format!("{store:?} {wrapping:?}");
        assert!(!rendered.contains(&seed_hex));
        assert!(!rendered.contains("ab, ab") && !rendered.contains("abab"));
        Ok(())
    }

    #[test]
    fn decode_rejects_noncanonical_plaintext() -> TestResult {
        let entry = |id: u8, role: u8, export: u8| {
            let mut bytes = vec![id; 16];
            bytes.push(role);
            bytes.push(export);
            bytes.extend_from_slice(&[0x11; 32]);
            bytes
        };
        let with = |entries: &[Vec<u8>]| {
            let mut bytes = u16::try_from(entries.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes()
                .to_vec();
            for item in entries {
                bytes.extend_from_slice(item);
            }
            bytes
        };
        assert!(decode(&with(&[entry(1, 1, 1), entry(2, 2, 0)])).is_ok());
        assert!(decode(&with(&[])).is_ok());
        // Order, duplicates, zero ID, enums, device export flag, lengths.
        assert!(decode(&with(&[entry(2, 1, 0), entry(1, 1, 0)])).is_err());
        assert!(decode(&with(&[entry(1, 1, 0), entry(1, 1, 0)])).is_err());
        assert!(decode(&with(&[entry(0, 1, 0)])).is_err());
        assert!(decode(&with(&[entry(1, 0, 0)])).is_err());
        assert!(decode(&with(&[entry(1, 3, 0)])).is_err());
        assert!(decode(&with(&[entry(1, 1, 2)])).is_err());
        assert!(decode(&with(&[entry(1, 2, 1)])).is_err());
        let mut truncated = with(&[entry(1, 1, 0)]);
        truncated.pop();
        assert!(decode(&truncated).is_err());
        let mut trailing = with(&[entry(1, 1, 0)]);
        trailing.push(0);
        assert!(decode(&trailing).is_err());
        let mut over = (u16::try_from(MAX_KEYS + 1)?).to_be_bytes().to_vec();
        over.resize(2 + (MAX_KEYS + 1) * ENTRY_LEN, 1);
        assert!(decode(&over).is_err());
        assert!(decode(&[]).is_err());
        Ok(())
    }

    proptest! {
        #[test]
        fn plaintext_round_trips(
            entries in proptest::collection::btree_map(
                any::<[u8; 16]>().prop_filter("nonzero", |id| *id != [0; 16]),
                (any::<bool>(), any::<bool>(), any::<[u8; 32]>()),
                0..MAX_KEYS,
            )
        ) {
            let mut keys = BTreeMap::new();
            for (id, (root, exportable, seed)) in entries {
                let role = if root { KeyRole::PersonRoot } else { KeyRole::Device };
                let export = if root && exportable {
                    ExportPolicy::Exportable
                } else {
                    ExportPolicy::NonExportable
                };
                let id = KeyId::from_bytes(id).ok_or_else(|| TestCaseError::fail("zero id"))?;
                let entry = Entry::from_seed(role, export, Zeroizing::new(seed))
                    .map_err(|_| TestCaseError::fail("seed"))?;
                keys.insert(id, entry);
            }
            let encoded = encode(&keys);
            let decoded = decode(&encoded).map_err(|_| TestCaseError::fail("decode"))?;
            prop_assert_eq!(decoded.len(), keys.len());
            for ((id_a, a), (id_b, b)) in keys.iter().zip(decoded.iter()) {
                prop_assert_eq!(id_a, id_b);
                prop_assert_eq!(a.role, b.role);
                prop_assert_eq!(a.export, b.export);
                prop_assert_eq!(a.public, b.public);
                prop_assert_eq!(a.seed.as_ref(), b.seed.as_ref());
            }
            let reencoded = encode(&decoded);
            prop_assert_eq!(reencoded.as_slice(), encoded.as_slice());
        }

        #[test]
        fn decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = decode(&bytes);
        }
    }
}
