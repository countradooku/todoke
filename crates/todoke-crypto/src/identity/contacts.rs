//! Paired contacts: pinned keys, pair PSK, verification state, key-change
//! history, and the revocations retained for their roots.

use core::fmt;
use core::num::NonZeroU64;
use std::collections::{BTreeMap, VecDeque};

use todoke_proto::identity::{DeviceBinding, KEM_STATIC_LEN, Revoke};
use todoke_proto::time::UnixTime;
use zeroize::Zeroizing;

use super::Hex;
use super::binding::{BindingError, PersonIdentity, VerifiedDeviceBinding};
use super::codec::{Envelope, LocalFormatError, Reader};
use super::ed25519::Ed25519PublicKey;
use super::ids::DeviceId;
use super::revocation::{ApplyOutcome, RevocationError, RevocationRecord, RevocationSet};
use super::sealing::{Sealer, SoftwareSealer};
use super::storage::{BlobStorage, StorageError};

mod pairing;

pub use pairing::MAX_BURNED_PAIRINGS;
pub(crate) use pairing::PairingJournal;
use pairing::PairingState;

/// Local quota: stored contacts.
pub const MAX_CONTACTS: usize = 1024;
/// Local quota: history events kept per contact; the oldest are dropped first.
pub const MAX_HISTORY: usize = 32;

const PSK_LEN: usize = 32;
/// `pending_state:u8 || generation_next:u64 || handshake_hash[32] ||
/// psk_next[32] || keyset[32]`: the §4.4 ratchet journal, all zero when none.
const PENDING_LEN: usize = 1 + 8 + 32 + PSK_LEN + 32;
/// `person_root || device_public || noise_static || kem_static || serial:u64 ||
/// origin:u8 || state:u8 || generation:u64 || psk[32] || history_count:u8`,
/// plus the trailing pending journal block. History events sit between
/// `history_count` and the journal block.
const CONTACT_FIXED_LEN: usize =
    32 * 3 + KEM_STATIC_LEN + 8 + 1 + 1 + 8 + PSK_LEN + 1 + PENDING_LEN;
/// `at:u64 || kind:u8 || changed:u8 || serial:u64 || keyset[32] || previous[32]`.
const HISTORY_LEN: usize = 8 + 1 + 1 + 8 + 32 + 32;
const MAX_BLOB_LEN: usize = 6
    + SoftwareSealer::OVERHEAD
    + 4
    + MAX_CONTACTS * (CONTACT_FIXED_LEN + MAX_HISTORY * HISTORY_LEN)
    + 4
    + super::revocation::MAX_ROOTS * (32 + 1 + 2 + 2)
    + super::revocation::MAX_TOTAL_RECORDS * todoke_proto::identity::REVOKE_LEN
    + pairing::MAX_SECTION_LEN;

/// Version 2 added retained conflicting revocation records to the revocation
/// set layout; version 3 added the per-contact §4.4 ratchet journal; version
/// 4 added the pending-pairing journal and the burned pairing ledger. Older
/// blobs are rejected; those formats never shipped.
const ENVELOPE: Envelope = Envelope {
    magic: *b"TDKC",
    version: 4,
    context: b"todoke/local/contacts\0",
};
const KEYSET_DOMAIN: &[u8] = b"todoke/local/keyset\0";

/// The current pair PSK. Zeroized on drop; `Debug` is redacted; it has no
/// public constructor or accessor and never leaves this crate. It is produced
/// by pairing and by the §4.4 ratchet in [`crate::session`].
pub struct PairPsk(Zeroizing<[u8; PSK_LEN]>);

impl PairPsk {
    #[cfg(test)]
    pub(crate) fn new(bytes: [u8; PSK_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(crate) fn from_secret(bytes: &[u8; PSK_LEN]) -> Self {
        let mut psk = Zeroizing::new([0; PSK_LEN]);
        psk.copy_from_slice(bytes);
        Self(psk)
    }

    pub(crate) fn expose(&self) -> &[u8; PSK_LEN] {
        &self.0
    }
}

impl fmt::Debug for PairPsk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairPsk([REDACTED])")
    }
}

/// How trust in a contact's keys originated (§2: an authenticated pairing).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TrustOrigin {
    /// QR pairing (`IKpsk2`).
    QrPairing,
    /// Human-code pairing (`CPace` + `XXpsk3`; disabled pending O2).
    CodePairing,
}

impl TrustOrigin {
    const fn to_u8(self) -> u8 {
        match self {
            Self::QrPairing => 1,
            Self::CodePairing => 2,
        }
    }

    const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::QrPairing),
            2 => Some(Self::CodePairing),
            _ => None,
        }
    }
}

/// Persistent verification state. Anything but [`Self::Verified`] blocks the
/// contact until explicit re-pairing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VerificationState {
    /// Keys pinned by an authenticated pairing and unchanged since.
    Verified,
    /// The peer presented a validly signed binding with different keys (§4.3:
    /// unknown identity changes fail closed).
    KeyChanged,
    /// A ratchet transaction was interrupted with a pending journal, or
    /// failed after journaling (§4.4).
    RatchetUncertain,
}

impl VerificationState {
    const fn to_u8(self) -> u8 {
        match self {
            Self::Verified => 1,
            Self::KeyChanged => 2,
            Self::RatchetUncertain => 3,
        }
    }

    const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Verified),
            2 => Some(Self::KeyChanged),
            3 => Some(Self::RatchetUncertain),
            _ => None,
        }
    }
}

/// The full keys pinned for a contact. All authorization compares these, not
/// truncated IDs.
#[derive(Clone, PartialEq, Eq)]
pub struct PinnedKeys {
    person_root: Ed25519PublicKey,
    device_public: Ed25519PublicKey,
    noise_static: [u8; 32],
    kem_static: Box<[u8; KEM_STATIC_LEN]>,
}

impl PinnedKeys {
    fn from_binding(binding: &VerifiedDeviceBinding) -> Self {
        Self {
            person_root: *binding.person_root(),
            device_public: *binding.device_public(),
            noise_static: *binding.noise_static(),
            kem_static: Box::new(*binding.kem_static()),
        }
    }

    /// Pinned person root.
    #[must_use]
    pub fn person_root(&self) -> &Ed25519PublicKey {
        &self.person_root
    }

    /// Pinned device key.
    #[must_use]
    pub fn device_public(&self) -> &Ed25519PublicKey {
        &self.device_public
    }

    /// Pinned X25519 Noise static key.
    #[must_use]
    pub fn noise_static(&self) -> &[u8; 32] {
        &self.noise_static
    }

    /// Pinned ML-KEM-768 credential (compared as data only, §4.3).
    #[must_use]
    pub fn kem_static(&self) -> &[u8; KEM_STATIC_LEN] {
        &self.kem_static
    }

    /// Local digest of all four keys, used in history records.
    #[must_use]
    pub fn digest(&self) -> KeysetDigest {
        let mut hasher = blake3::Hasher::new();
        hasher.update(KEYSET_DOMAIN);
        hasher.update(self.person_root.as_bytes());
        hasher.update(self.device_public.as_bytes());
        hasher.update(&self.noise_static);
        hasher.update(&self.kem_static[..]);
        KeysetDigest(*hasher.finalize().as_bytes())
    }

    fn diff(&self, other: &Self) -> ChangedKeys {
        let mut bits = 0;
        if self.person_root != other.person_root {
            bits |= ChangedKeys::PERSON_ROOT;
        }
        if self.device_public != other.device_public {
            bits |= ChangedKeys::DEVICE_KEY;
        }
        if self.noise_static != other.noise_static {
            bits |= ChangedKeys::NOISE_STATIC;
        }
        if self.kem_static != other.kem_static {
            bits |= ChangedKeys::KEM_STATIC;
        }
        ChangedKeys(bits)
    }
}

impl fmt::Debug for PinnedKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedKeys")
            .field("person_root", &self.person_root)
            .field("device_public", &self.device_public)
            .field("noise_static", &Hex(&self.noise_static))
            .field("kem_static", &format_args!("[{KEM_STATIC_LEN} bytes]"))
            .finish()
    }
}

/// `B3("todoke/local/keyset\0" || person_root || device_public ||
/// noise_static || kem_static)`. A local fingerprint, not a protocol value.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeysetDigest([u8; 32]);

impl KeysetDigest {
    /// The digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for KeysetDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeysetDigest({:?})", Hex(&self.0))
    }
}

/// Which pinned keys differ from a presented binding. Never empty when
/// reported.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChangedKeys(u8);

impl ChangedKeys {
    const PERSON_ROOT: u8 = 1;
    const DEVICE_KEY: u8 = 2;
    const NOISE_STATIC: u8 = 4;
    const KEM_STATIC: u8 = 8;
    const ALL: u8 = 15;

    /// The person root differs.
    #[must_use]
    pub const fn person_root(self) -> bool {
        self.0 & Self::PERSON_ROOT != 0
    }

    /// The device key differs.
    #[must_use]
    pub const fn device_key(self) -> bool {
        self.0 & Self::DEVICE_KEY != 0
    }

    /// The Noise static key differs.
    #[must_use]
    pub const fn noise_static(self) -> bool {
        self.0 & Self::NOISE_STATIC != 0
    }

    /// The ML-KEM credential differs.
    #[must_use]
    pub const fn kem_static(self) -> bool {
        self.0 & Self::KEM_STATIC != 0
    }

    const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Debug for ChangedKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChangedKeys")
            .field("person_root", &self.person_root())
            .field("device_key", &self.device_key())
            .field("noise_static", &self.noise_static())
            .field("kem_static", &self.kem_static())
            .finish()
    }
}

/// One entry in a contact's key history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryEvent {
    /// Local time of the event.
    pub at: UnixTime,
    /// The binding serial involved.
    pub serial: NonZeroU64,
    /// The keyset pinned after the event, or the rejected presented keyset.
    pub keyset: KeysetDigest,
    /// What happened.
    pub kind: HistoryKind,
}

/// Kinds of [`HistoryEvent`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryKind {
    /// First pairing pinned `keyset`.
    Paired,
    /// A binding with the same keys and a higher serial was accepted.
    Renewed,
    /// A validly signed binding with different keys was rejected and the
    /// contact blocked; `keyset` is the presented one.
    KeyChangeRejected(ChangedKeys),
    /// Explicit local re-pairing replaced `previous` with `keyset`.
    RePaired {
        /// The keyset pinned before re-pairing.
        previous: KeysetDigest,
    },
}

/// The durable §4.4 ratchet journal of one contact.
#[derive(Debug)]
enum PendingJournal {
    /// Step 1/2: the next generation and PSK are journaled; the current
    /// PSK is still the old one.
    Journaled {
        generation_next: u64,
        handshake_hash: [u8; 32],
        psk_next: PairPsk,
        keyset: KeysetDigest,
    },
    /// Step 3/4: the new PSK and generation are committed; the marker stays
    /// until the acknowledgment step clears it.
    Committed {
        handshake_hash: [u8; 32],
        keyset: KeysetDigest,
    },
}

/// A paired device.
#[derive(Debug)]
pub struct Contact {
    pinned: PinnedKeys,
    binding_serial: NonZeroU64,
    origin: TrustOrigin,
    state: VerificationState,
    generation: u64,
    psk: PairPsk,
    history: VecDeque<HistoryEvent>,
    pending: Option<PendingJournal>,
}

impl Contact {
    /// The pinned full keys.
    #[must_use]
    pub fn pinned(&self) -> &PinnedKeys {
        &self.pinned
    }

    /// Truncated device ID, for display and lookup only.
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        DeviceId::of(&self.pinned.device_public)
    }

    /// Highest binding serial accepted for these keys.
    #[must_use]
    pub fn binding_serial(&self) -> NonZeroU64 {
        self.binding_serial
    }

    /// How trust originated.
    #[must_use]
    pub fn origin(&self) -> TrustOrigin {
        self.origin
    }

    /// Persistent verification state.
    #[must_use]
    pub fn state(&self) -> VerificationState {
        self.state
    }

    /// Current pair PSK generation (§4.4).
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Key history, oldest first, at most [`MAX_HISTORY`] entries.
    pub fn history(&self) -> impl ExactSizeIterator<Item = &HistoryEvent> {
        self.history.iter()
    }

    /// Whether a §4.4 ratchet transaction is journaled for this contact in
    /// this process. A journal found when opening the store is converted to
    /// [`VerificationState::RatchetUncertain`] instead.
    #[must_use]
    pub fn ratchet_pending(&self) -> bool {
        self.pending.is_some()
    }

    #[cfg(test)]
    pub(crate) fn psk(&self) -> &PairPsk {
        &self.psk
    }

    fn record(&mut self, event: HistoryEvent) {
        if self.history.len() >= MAX_HISTORY {
            self.history.pop_front();
        }
        self.history.push_back(event);
    }
}

/// What a contact session's handshake needs: a copy of the current pair
/// PSK, its generation, and the pinned Noise static key.
pub(crate) struct ContactHandshake {
    pub(crate) psk: Zeroizing<[u8; PSK_LEN]>,
    pub(crate) generation: u64,
    pub(crate) noise_static: [u8; 32],
}

/// Result of [`ContactStore::pair`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairOutcome {
    /// A new contact was created.
    New,
    /// An existing contact for the same device key was explicitly replaced.
    RePaired,
}

/// Why a contact cannot currently be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unavailable {
    /// Blocked after a key change; re-pair explicitly.
    KeyChanged,
    /// Blocked after an interrupted ratchet; re-pair explicitly. Also
    /// reported while a ratchet transaction is journaled in this process,
    /// which keeps a concurrent session from starting (§4.4 step 1).
    RatchetUncertain,
    /// The contact's root is disabled by conflicting revocations or quota.
    RootDisabled,
    /// A retained revocation covers the pinned binding serial.
    Revoked,
    /// The pair generation is `u64::MAX` and cannot be ratcheted again;
    /// re-pair explicitly (§4.4: overflow requires a new pairing). Derived
    /// from the stored generation, so it persists across restarts.
    GenerationExhausted,
}

/// Contact store failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContactError {
    /// No contact with this device key.
    UnknownContact,
    /// The store holds [`MAX_CONTACTS`] contacts.
    Capacity,
    /// The binding's root is disabled or the binding is revoked.
    Binding(BindingError),
    /// A revocation was rejected.
    Revocation(RevocationError),
    /// Sealing or unsealing failed (wrong key or tampering).
    Seal,
    /// Stored data is malformed.
    Corrupt,
    /// The storage backend failed.
    Storage(StorageError),
    /// A §4.4 ratchet step does not match the journaled transaction: wrong
    /// generation, handshake hash, or step order, or generation overflow.
    RatchetMismatch,
}

impl fmt::Display for ContactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownContact => f.write_str("unknown contact"),
            Self::Capacity => f.write_str("contact store is full"),
            Self::Binding(error) => write!(f, "binding rejected: {error}"),
            Self::Revocation(error) => write!(f, "revocation rejected: {error}"),
            Self::Seal => f.write_str("contact store sealing failed"),
            Self::Corrupt => f.write_str("contact store data is malformed"),
            Self::Storage(error) => write!(f, "contact store storage failed: {error}"),
            Self::RatchetMismatch => f.write_str("ratchet step does not match the journal"),
        }
    }
}

impl std::error::Error for ContactError {}

impl From<StorageError> for ContactError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

/// Result of identity confirmation against a pinned contact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityError {
    /// No contact pins this device key.
    UnknownContact,
    /// The contact is blocked.
    Unavailable(Unavailable),
    /// The binding does not match the session's Noise static key, or is not
    /// validly signed by the root it names. The contact is unchanged.
    AuthenticationFailed,
    /// A validly signed binding with different keys was presented. The contact
    /// is now blocked until explicit re-pairing.
    KeyChanged(ChangedKeys),
    /// The binding has the pinned keys but failed time or revocation policy.
    Binding(BindingError),
    /// The binding has the pinned keys but a lower serial than the pinned
    /// one. Serials are unique and increasing (§2), so a superseded binding
    /// must not authenticate. The contact is unchanged.
    SerialRegressed,
    /// Recording the result failed. The in-memory state remains fail-closed.
    Storage(ContactError),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownContact => f.write_str("unknown contact"),
            Self::Unavailable(reason) => write!(f, "contact unavailable: {reason:?}"),
            Self::AuthenticationFailed => f.write_str("identity authentication failed"),
            Self::KeyChanged(_) => f.write_str("contact keys changed"),
            Self::Binding(error) => write!(f, "binding rejected: {error}"),
            Self::SerialRegressed => f.write_str("binding serial is older than the pinned serial"),
            Self::Storage(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for IdentityError {}

/// Paired contacts and the revocations of their roots, persisted as one
/// [`Sealer`]-protected blob. Contacts are keyed by the full device key; IDs
/// are only a lookup aid and a collision never merges contacts.
///
/// Every mutation persists before returning. Mutations that grant or keep
/// access roll back on persistence failure; mutations that block access stay
/// in effect in memory (fail closed) and report the storage error.
pub struct ContactStore<S: Sealer, B: BlobStorage> {
    sealer: S,
    storage: B,
    contacts: BTreeMap<Ed25519PublicKey, Contact>,
    revocations: RevocationSet,
    pairing: PairingState,
}

impl<S: Sealer, B: BlobStorage> ContactStore<S, B> {
    /// Opens the store in `storage`, or starts empty.
    ///
    /// # Errors
    ///
    /// [`ContactError::Seal`], [`ContactError::Corrupt`], or a storage error.
    ///
    /// A ratchet journal found here belongs to a transaction that was
    /// interrupted by a crash or shutdown. Its contact is blocked as
    /// [`VerificationState::RatchetUncertain`] and the journal is dropped
    /// (zeroizing its PSK): neither generation is restored or tried (§4.4).
    /// A journaled new pairing is dropped the same way; it never becomes a
    /// contact, an existing contact for its device is blocked, and its
    /// pairing ID stays burned. The block is persisted with the next
    /// mutation.
    pub fn open(sealer: S, storage: B) -> Result<Self, ContactError> {
        let (mut contacts, revocations, pairing) = match storage.load(MAX_BLOB_LEN)? {
            None => (
                BTreeMap::new(),
                RevocationSet::new(),
                PairingState::default(),
            ),
            Some(blob) => {
                let plaintext = ENVELOPE.open(&sealer, &blob).map_err(map_format)?;
                decode(&plaintext).map_err(map_format)?
            }
        };
        for contact in contacts.values_mut() {
            if contact.pending.take().is_some() {
                contact.state = VerificationState::RatchetUncertain;
            }
        }
        let mut store = Self {
            sealer,
            storage,
            contacts,
            revocations,
            pairing,
        };
        store.discard_interrupted_pairing();
        Ok(store)
    }

    /// The contact pinning `device`, if any.
    #[must_use]
    pub fn contact(&self, device: &Ed25519PublicKey) -> Option<&Contact> {
        self.contacts.get(device)
    }

    /// All contacts in device-key order.
    pub fn contacts(&self) -> impl Iterator<Item = &Contact> {
        self.contacts.values()
    }

    /// Contacts whose truncated device ID is `id`. More than one is possible.
    pub fn find_by_device_id(&self, id: DeviceId) -> impl Iterator<Item = &Contact> {
        self.contacts
            .values()
            .filter(move |contact| contact.device_id() == id)
    }

    /// Retained revocations, for [`PersonIdentity::verify_binding`].
    #[must_use]
    pub fn revocations(&self) -> &RevocationSet {
        &self.revocations
    }

    /// The storage backend, for inspection.
    pub fn storage(&self) -> &B {
        &self.storage
    }

    /// Whether `device` may be used for a new session now.
    ///
    /// The session layer MUST call this before starting a contact handshake
    /// (`KKpsk2` with the stored pair PSK) and refuse on any [`Unavailable`].
    /// Revocation does not by itself rotate, erase, or otherwise invalidate
    /// the pair PSK or its generation: this check is what keeps a revoked
    /// pinned serial from resuming with the existing PSK (§2: revocation MUST
    /// invalidate resumable authorization). [`Self::confirm_identity`] alone
    /// is not enough, because it tolerates [`Unavailable::Revoked`] so that a
    /// renewal can supersede the revoked serial.
    ///
    /// # Errors
    ///
    /// [`ContactError::UnknownContact`], or `Ok(Err(reason))` if blocked.
    pub fn availability(
        &self,
        device: &Ed25519PublicKey,
    ) -> Result<Result<&Contact, Unavailable>, ContactError> {
        let contact = self
            .contacts
            .get(device)
            .ok_or(ContactError::UnknownContact)?;
        Ok(self.check_available(contact).map(|()| contact))
    }

    fn check_available(&self, contact: &Contact) -> Result<(), Unavailable> {
        if contact.pending.is_some() || self.pairing_pending_for(&contact.pinned.device_public) {
            return Err(Unavailable::RatchetUncertain);
        }
        match contact.state {
            VerificationState::Verified => {}
            VerificationState::KeyChanged => return Err(Unavailable::KeyChanged),
            VerificationState::RatchetUncertain => return Err(Unavailable::RatchetUncertain),
        }
        if contact.generation == u64::MAX {
            return Err(Unavailable::GenerationExhausted);
        }
        let root = &contact.pinned.person_root;
        if self.revocations.is_root_disabled(root) {
            return Err(Unavailable::RootDisabled);
        }
        if self
            .revocations
            .is_revoked(root, &contact.pinned.device_public, contact.binding_serial)
        {
            return Err(Unavailable::Revoked);
        }
        Ok(())
    }

    /// Records the result of an authenticated pairing whose ratchet has
    /// committed: pins the binding's keys and stores `psk` at `generation`.
    ///
    /// An existing contact for the same device key is replaced; this is the
    /// explicit local re-pairing that clears a blocked state (§4.3, §4.4).
    /// Pairing a new device of a known person does not inherit any other
    /// device's pairing (§2).
    ///
    /// # Errors
    ///
    /// [`ContactError::Binding`] if the root is disabled or the binding is
    /// revoked, [`ContactError::Capacity`], or a persistence error (the store
    /// is then unchanged).
    pub fn pair(
        &mut self,
        binding: &VerifiedDeviceBinding,
        origin: TrustOrigin,
        psk: PairPsk,
        generation: u64,
        now: UnixTime,
    ) -> Result<PairOutcome, ContactError> {
        let device = *binding.device_public();
        let (outcome, previous) =
            self.insert_paired(binding, origin, psk, generation, now, None)?;
        if let Err(error) = self.persist() {
            match previous {
                Some(previous) => self.contacts.insert(device, previous),
                None => self.contacts.remove(&device),
            };
            return Err(error);
        }
        Ok(outcome)
    }

    /// The in-memory part of [`Self::pair`]: checks the binding against
    /// retained revocations and the quota, then inserts the contact with
    /// `pending` as its ratchet marker. Returns the replaced contact, if
    /// any, so the caller can roll back; nothing is persisted.
    fn insert_paired(
        &mut self,
        binding: &VerifiedDeviceBinding,
        origin: TrustOrigin,
        psk: PairPsk,
        generation: u64,
        now: UnixTime,
        pending: Option<PendingJournal>,
    ) -> Result<(PairOutcome, Option<Contact>), ContactError> {
        let root = binding.person_root();
        if self.revocations.is_root_disabled(root) {
            return Err(ContactError::Binding(BindingError::RootDisabled));
        }
        if self
            .revocations
            .is_revoked(root, binding.device_public(), binding.serial())
        {
            return Err(ContactError::Binding(BindingError::Revoked));
        }
        let device = *binding.device_public();
        let pinned = PinnedKeys::from_binding(binding);
        let keyset = pinned.digest();
        let mut contact = Contact {
            pinned,
            binding_serial: binding.serial(),
            origin,
            state: VerificationState::Verified,
            generation,
            psk,
            history: VecDeque::new(),
            pending,
        };
        let outcome = if let Some(previous) = self.contacts.get(&device) {
            contact.history.clone_from(&previous.history);
            contact.record(HistoryEvent {
                at: now,
                serial: binding.serial(),
                keyset,
                kind: HistoryKind::RePaired {
                    previous: previous.pinned.digest(),
                },
            });
            PairOutcome::RePaired
        } else {
            if self.contacts.len() >= MAX_CONTACTS {
                return Err(ContactError::Capacity);
            }
            contact.record(HistoryEvent {
                at: now,
                serial: binding.serial(),
                keyset,
                kind: HistoryKind::Paired,
            });
            PairOutcome::New
        };
        let previous = self.contacts.insert(device, contact);
        Ok((outcome, previous))
    }

    /// Checks a binding presented in a session's `Identity` message against
    /// the contact pinned for `expected_device` (§4.3).
    ///
    /// `session_noise_static` is the peer static key authenticated by the
    /// Noise handshake; it must equal `binding.noise_static`. A validly
    /// signed binding with any different key blocks the contact and records
    /// the change; a binding that is not validly signed changes nothing.
    /// With matching keys, time and revocation policy apply, a serial below
    /// the pinned one is rejected (§2: serials are unique and increasing),
    /// and a higher serial is recorded as a renewal.
    ///
    /// This does not check the `Identity` signature over the handshake hash;
    /// that belongs to the session layer.
    ///
    /// The session layer MUST also have called [`Self::availability`] before
    /// starting the handshake. This method deliberately accepts a contact
    /// whose pinned serial is revoked when the presented binding has a higher,
    /// unrevoked serial (a renewal), and neither it nor revocation rotates the
    /// pair PSK; only the availability check stops a revoked contact from
    /// resuming with that PSK.
    ///
    /// # Errors
    ///
    /// [`IdentityError`]; see its variants.
    pub fn confirm_identity(
        &mut self,
        expected_device: &Ed25519PublicKey,
        session_noise_static: &[u8; 32],
        presented: &DeviceBinding,
        now: UnixTime,
    ) -> Result<VerifiedDeviceBinding, IdentityError> {
        let contact = self
            .contacts
            .get(expected_device)
            .ok_or(IdentityError::UnknownContact)?;
        self.check_available(contact)
            .or_else(|reason| match reason {
                // A revoked pinned serial may be superseded by a renewal;
                // the presented binding is checked against revocations below.
                Unavailable::Revoked => Ok(()),
                other => Err(other),
            })
            .map_err(IdentityError::Unavailable)?;
        if presented.body().noise_static() != session_noise_static {
            return Err(IdentityError::AuthenticationFailed);
        }
        // Verify under the root the binding names, to distinguish a real key
        // change from garbage. This does not make that root trusted.
        let claimed_root = Ed25519PublicKey::from_bytes(presented.body().person_root())
            .map_err(|_| IdentityError::AuthenticationFailed)?;
        let candidate = PersonIdentity::new(claimed_root)
            .verify_binding_signatures(presented)
            .map_err(|_| IdentityError::AuthenticationFailed)?;
        let presented_keys = PinnedKeys::from_binding(&candidate);
        let changed = contact.pinned.diff(&presented_keys);
        let pinned_root = contact.pinned.person_root;
        let pinned_serial = contact.binding_serial;
        if !changed.is_empty() {
            self.block(
                expected_device,
                VerificationState::KeyChanged,
                Some(HistoryEvent {
                    at: now,
                    serial: candidate.serial(),
                    keyset: presented_keys.digest(),
                    kind: HistoryKind::KeyChangeRejected(changed),
                }),
            )
            .map_err(IdentityError::Storage)?;
            return Err(IdentityError::KeyChanged(changed));
        }
        let verified = PersonIdentity::new(pinned_root)
            .verify_binding(presented, now, &self.revocations)
            .map_err(IdentityError::Binding)?;
        if verified.serial() < pinned_serial {
            return Err(IdentityError::SerialRegressed);
        }
        if verified.serial() > pinned_serial {
            self.renew(expected_device, &verified, now)
                .map_err(IdentityError::Storage)?;
        }
        Ok(verified)
    }

    /// The handshake inputs of an available contact.
    pub(crate) fn handshake_inputs(
        &self,
        device: &Ed25519PublicKey,
    ) -> Result<ContactHandshake, ContactError> {
        let contact = self
            .availability(device)?
            .map_err(|_| ContactError::RatchetMismatch)?;
        let mut psk = Zeroizing::new([0; PSK_LEN]);
        psk.copy_from_slice(contact.psk.expose());
        Ok(ContactHandshake {
            psk,
            generation: contact.generation,
            noise_static: contact.pinned.noise_static,
        })
    }

    /// §4.4 steps 1–2: durably journals `generation_next`, `h`, `psk_next`,
    /// and the pinned keys. The contact must be available and
    /// `generation_next` must be its generation plus one. While journaled,
    /// [`Self::availability`] reports it unavailable, so no concurrent
    /// session starts.
    ///
    /// On a persistence error the journal stays in memory (fail closed):
    /// the contact is unavailable until reopened from what was durably
    /// stored.
    pub(crate) fn journal_ratchet(
        &mut self,
        device: &Ed25519PublicKey,
        generation_next: u64,
        handshake_hash: &[u8; 32],
        psk_next: &[u8; PSK_LEN],
    ) -> Result<(), ContactError> {
        let available = self.availability(device)?.is_ok();
        let contact = self
            .contacts
            .get_mut(device)
            .ok_or(ContactError::UnknownContact)?;
        if !available || contact.generation.checked_add(1) != Some(generation_next) {
            return Err(ContactError::RatchetMismatch);
        }
        contact.pending = Some(PendingJournal::Journaled {
            generation_next,
            handshake_hash: *handshake_hash,
            psk_next: PairPsk::from_secret(psk_next),
            keyset: contact.pinned.digest(),
        });
        self.persist()
    }

    /// §4.4 steps 3–4: atomically replaces the pair PSK and generation with
    /// the journaled ones (dropping, and so zeroizing, the old PSK) and keeps
    /// the marker until [`Self::clear_ratchet`]. On a persistence error the
    /// contact stays blocked in memory.
    pub(crate) fn commit_ratchet(
        &mut self,
        device: &Ed25519PublicKey,
        handshake_hash: &[u8; 32],
    ) -> Result<(), ContactError> {
        let contact = self
            .contacts
            .get_mut(device)
            .ok_or(ContactError::UnknownContact)?;
        match contact.pending.take() {
            Some(PendingJournal::Journaled {
                generation_next,
                handshake_hash: journaled,
                psk_next,
                keyset,
            }) if journaled == *handshake_hash => {
                contact.psk = psk_next;
                contact.generation = generation_next;
                contact.pending = Some(PendingJournal::Committed {
                    handshake_hash: journaled,
                    keyset,
                });
            }
            other => {
                contact.pending = other;
                return Err(ContactError::RatchetMismatch);
            }
        }
        self.persist()
    }

    /// §4.4 steps 4–5: clears the committed marker, which makes the contact
    /// available again. Rolled back on a persistence error, so the contact
    /// stays blocked.
    pub(crate) fn clear_ratchet(
        &mut self,
        device: &Ed25519PublicKey,
        handshake_hash: &[u8; 32],
    ) -> Result<(), ContactError> {
        let contact = self
            .contacts
            .get_mut(device)
            .ok_or(ContactError::UnknownContact)?;
        let pending = match contact.pending.take() {
            Some(PendingJournal::Committed {
                handshake_hash: committed,
                keyset,
            }) if committed == *handshake_hash => PendingJournal::Committed {
                handshake_hash: committed,
                keyset,
            },
            other => {
                contact.pending = other;
                return Err(ContactError::RatchetMismatch);
            }
        };
        if let Err(error) = self.persist() {
            if let Some(contact) = self.contacts.get_mut(device) {
                contact.pending = Some(pending);
            }
            return Err(error);
        }
        Ok(())
    }

    /// A ratchet transaction failed after journaling: blocks the contact as
    /// [`VerificationState::RatchetUncertain`] and drops the journal
    /// (zeroizing any journaled PSK). Neither generation is retried (§4.4).
    /// The block stays in effect in memory even if persisting it fails.
    pub(crate) fn abandon_ratchet(
        &mut self,
        device: &Ed25519PublicKey,
    ) -> Result<(), ContactError> {
        let contact = self
            .contacts
            .get_mut(device)
            .ok_or(ContactError::UnknownContact)?;
        contact.pending = None;
        self.block(device, VerificationState::RatchetUncertain, None)
    }

    /// Blocks `device` after an interrupted ratchet with a pending journal
    /// (§4.4). Only explicit re-pairing clears it.
    ///
    /// # Errors
    ///
    /// [`ContactError::UnknownContact`] or a persistence error; the block
    /// stays in effect in memory either way.
    pub fn mark_ratchet_uncertain(
        &mut self,
        device: &Ed25519PublicKey,
    ) -> Result<(), ContactError> {
        self.block(device, VerificationState::RatchetUncertain, None)
    }

    /// Verifies and retains a revocation from a root that some contact pins.
    ///
    /// # Errors
    ///
    /// [`ContactError::Revocation`] for an untrusted root or invalid record.
    /// On a persistence error, a newly retained record stays in effect in
    /// memory (fail closed).
    pub fn apply_revocation(&mut self, record: Revoke) -> Result<ApplyOutcome, ContactError> {
        let root = Ed25519PublicKey::from_bytes(record.body().person_root())
            .map_err(|_| ContactError::Revocation(RevocationError::UntrustedRoot))?;
        if !self
            .contacts
            .values()
            .any(|contact| contact.pinned.person_root == root)
        {
            return Err(ContactError::Revocation(RevocationError::UntrustedRoot));
        }
        let verified = RevocationRecord::verify(record, &PersonIdentity::new(root))
            .map_err(ContactError::Revocation)?;
        let outcome = self.revocations.apply(verified);
        if outcome != ApplyOutcome::Duplicate {
            self.persist()?;
        }
        Ok(outcome)
    }

    /// Removes a contact. Revocations for its root are dropped only if no
    /// remaining contact pins that root (retention lasts while it is trusted).
    ///
    /// # Errors
    ///
    /// [`ContactError::UnknownContact`] or a persistence error (the store is
    /// then unchanged).
    pub fn remove(&mut self, device: &Ed25519PublicKey) -> Result<(), ContactError> {
        let contact = self
            .contacts
            .remove(device)
            .ok_or(ContactError::UnknownContact)?;
        let snapshot = self.revocations.clone();
        self.retain_trusted_roots();
        if let Err(error) = self.persist() {
            self.contacts.insert(*device, contact);
            self.revocations = snapshot;
            return Err(error);
        }
        Ok(())
    }

    fn retain_trusted_roots(&mut self) {
        let contacts = &self.contacts;
        self.revocations.retain_roots(|root| {
            contacts
                .values()
                .any(|contact| contact.pinned.person_root == *root)
        });
    }

    fn block(
        &mut self,
        device: &Ed25519PublicKey,
        state: VerificationState,
        event: Option<HistoryEvent>,
    ) -> Result<(), ContactError> {
        let contact = self
            .contacts
            .get_mut(device)
            .ok_or(ContactError::UnknownContact)?;
        contact.state = state;
        if let Some(event) = event {
            contact.record(event);
        }
        self.persist()
    }

    fn renew(
        &mut self,
        device: &Ed25519PublicKey,
        binding: &VerifiedDeviceBinding,
        now: UnixTime,
    ) -> Result<(), ContactError> {
        let contact = self
            .contacts
            .get_mut(device)
            .ok_or(ContactError::UnknownContact)?;
        let previous_serial = contact.binding_serial;
        let previous_history = contact.history.clone();
        contact.binding_serial = binding.serial();
        contact.record(HistoryEvent {
            at: now,
            serial: binding.serial(),
            keyset: contact.pinned.digest(),
            kind: HistoryKind::Renewed,
        });
        if let Err(error) = self.persist() {
            if let Some(contact) = self.contacts.get_mut(device) {
                contact.binding_serial = previous_serial;
                contact.history = previous_history;
            }
            return Err(error);
        }
        Ok(())
    }

    fn persist(&mut self) -> Result<(), ContactError> {
        let plaintext = encode_all(&self.contacts, &self.revocations, &self.pairing);
        let blob = ENVELOPE
            .seal(&self.sealer, &plaintext)
            .map_err(map_format)?;
        self.storage.store(&blob)?;
        Ok(())
    }
}

impl<S: Sealer, B: BlobStorage> fmt::Debug for ContactStore<S, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContactStore")
            .field("contacts", &self.contacts.len())
            .field("revocations", &self.revocations.len())
            .field("pairing_pending", &self.pairing.pending.is_some())
            .field("burned_pairings", &self.pairing.burned.len())
            .finish_non_exhaustive()
    }
}

fn map_format(error: LocalFormatError) -> ContactError {
    match error {
        LocalFormatError::Malformed => ContactError::Corrupt,
        LocalFormatError::Seal => ContactError::Seal,
    }
}

/// Local format v4 plaintext with an empty pairing section, for tests of
/// the contact and revocation layouts.
#[cfg(test)]
fn encode(
    contacts: &BTreeMap<Ed25519PublicKey, Contact>,
    revocations: &RevocationSet,
) -> Zeroizing<Vec<u8>> {
    encode_all(contacts, revocations, &PairingState::default())
}

/// Local format v4 plaintext:
/// `count:u32 || count × contact || revocation set || pairing section`,
/// contacts in strictly increasing device-key order. See
/// [`CONTACT_FIXED_LEN`] and [`HISTORY_LEN`] for the record layouts and
/// [`PairingState`] for the pairing section.
fn encode_all(
    contacts: &BTreeMap<Ed25519PublicKey, Contact>,
    revocations: &RevocationSet,
    pairing: &PairingState,
) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::new());
    // Bounded by MAX_CONTACTS and MAX_HISTORY on every insertion and decode.
    let count = u32::try_from(contacts.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&count.to_be_bytes());
    for contact in contacts.values() {
        let pinned = &contact.pinned;
        out.extend_from_slice(pinned.person_root.as_bytes());
        out.extend_from_slice(pinned.device_public.as_bytes());
        out.extend_from_slice(&pinned.noise_static);
        out.extend_from_slice(&pinned.kem_static[..]);
        out.extend_from_slice(&contact.binding_serial.get().to_be_bytes());
        out.push(contact.origin.to_u8());
        out.push(contact.state.to_u8());
        out.extend_from_slice(&contact.generation.to_be_bytes());
        out.extend_from_slice(contact.psk.0.as_ref());
        out.push(u8::try_from(contact.history.len()).unwrap_or(u8::MAX));
        for event in &contact.history {
            encode_event(event, &mut out);
        }
        encode_pending(contact.pending.as_ref(), &mut out);
    }
    revocations.encode_into(&mut out);
    pairing.encode_into(&mut out);
    out
}

fn encode_event(event: &HistoryEvent, out: &mut Vec<u8>) {
    let (kind, changed, previous) = match event.kind {
        HistoryKind::Paired => (1, 0, [0; 32]),
        HistoryKind::Renewed => (2, 0, [0; 32]),
        HistoryKind::KeyChangeRejected(changed) => (3, changed.0, [0; 32]),
        HistoryKind::RePaired { previous } => (4, 0, previous.0),
    };
    out.extend_from_slice(&event.at.seconds().to_be_bytes());
    out.push(kind);
    out.push(changed);
    out.extend_from_slice(&event.serial.get().to_be_bytes());
    out.extend_from_slice(&event.keyset.0);
    out.extend_from_slice(&previous);
}

/// `pending_state:u8 || generation_next:u64 || handshake_hash[32] ||
/// psk_next[32] || keyset[32]`: state 0 is all zero, state 1 (journaled)
/// fills every field, state 2 (committed) leaves `psk_next` zero.
fn encode_pending(pending: Option<&PendingJournal>, out: &mut Vec<u8>) {
    let (state, generation_next, handshake_hash, psk, keyset) = match pending {
        None => (0, 0, [0; 32], None, [0; 32]),
        Some(PendingJournal::Journaled {
            generation_next,
            handshake_hash,
            psk_next,
            keyset,
        }) => (
            1,
            *generation_next,
            *handshake_hash,
            Some(psk_next),
            keyset.0,
        ),
        Some(PendingJournal::Committed {
            handshake_hash,
            keyset,
        }) => (2, 0, *handshake_hash, None, keyset.0),
    };
    out.push(state);
    out.extend_from_slice(&generation_next.to_be_bytes());
    out.extend_from_slice(&handshake_hash);
    match psk {
        Some(psk) => out.extend_from_slice(psk.expose()),
        None => out.extend_from_slice(&[0; PSK_LEN]),
    }
    out.extend_from_slice(&keyset);
}

fn decode_pending(
    reader: &mut Reader<'_>,
    generation: u64,
    keyset: KeysetDigest,
) -> Result<Option<PendingJournal>, LocalFormatError> {
    let state = reader.u8()?;
    let generation_next = reader.u64()?;
    let handshake_hash = reader.array::<32>()?;
    let mut psk_next = PairPsk(Zeroizing::new([0; PSK_LEN]));
    reader.read_into(psk_next.0.as_mut())?;
    let stored_keyset = KeysetDigest(reader.array()?);
    let psk_is_zero = psk_next.0.iter().all(|&byte| byte == 0);
    match state {
        0 if generation_next == 0
            && handshake_hash == [0; 32]
            && psk_is_zero
            && stored_keyset.0 == [0; 32] =>
        {
            Ok(None)
        }
        1 if generation.checked_add(1) == Some(generation_next) && stored_keyset == keyset => {
            Ok(Some(PendingJournal::Journaled {
                generation_next,
                handshake_hash,
                psk_next,
                keyset,
            }))
        }
        2 if generation_next == 0 && psk_is_zero && stored_keyset == keyset => {
            Ok(Some(PendingJournal::Committed {
                handshake_hash,
                keyset,
            }))
        }
        _ => Err(LocalFormatError::Malformed),
    }
}

fn decode_event(reader: &mut Reader<'_>) -> Result<HistoryEvent, LocalFormatError> {
    let at = UnixTime::new(reader.u64()?).ok_or(LocalFormatError::Malformed)?;
    let kind = reader.u8()?;
    let changed = reader.u8()?;
    let serial = NonZeroU64::new(reader.u64()?).ok_or(LocalFormatError::Malformed)?;
    let keyset = KeysetDigest(reader.array()?);
    let previous = reader.array::<32>()?;
    let kind = match (kind, changed, previous == [0; 32]) {
        (1, 0, true) => HistoryKind::Paired,
        (2, 0, true) => HistoryKind::Renewed,
        (3, 1..=ChangedKeys::ALL, true) => HistoryKind::KeyChangeRejected(ChangedKeys(changed)),
        (4, 0, _) => HistoryKind::RePaired {
            previous: KeysetDigest(previous),
        },
        _ => return Err(LocalFormatError::Malformed),
    };
    Ok(HistoryEvent {
        at,
        serial,
        keyset,
        kind,
    })
}

type Decoded = (
    BTreeMap<Ed25519PublicKey, Contact>,
    RevocationSet,
    PairingState,
);

/// Decodes blob plaintext. Exposed to the fuzz harness via
/// [`crate::identity::fuzzing`].
pub(crate) fn decode(bytes: &[u8]) -> Result<Decoded, LocalFormatError> {
    let mut reader = Reader::new(bytes);
    let count = usize::try_from(reader.u32()?).map_err(|_| LocalFormatError::Malformed)?;
    if count > MAX_CONTACTS || reader.remaining() < count * CONTACT_FIXED_LEN {
        return Err(LocalFormatError::Malformed);
    }
    let mut contacts = BTreeMap::new();
    let mut previous_device: Option<Ed25519PublicKey> = None;
    for _ in 0..count {
        let key = |bytes: [u8; 32]| {
            Ed25519PublicKey::from_bytes(&bytes).map_err(|_| LocalFormatError::Malformed)
        };
        let person_root = key(reader.array()?)?;
        let device_public = key(reader.array()?)?;
        if previous_device.is_some_and(|previous| previous >= device_public) {
            return Err(LocalFormatError::Malformed);
        }
        previous_device = Some(device_public);
        let noise_static = reader.array()?;
        let kem_static = Box::new(reader.array::<KEM_STATIC_LEN>()?);
        let binding_serial = NonZeroU64::new(reader.u64()?).ok_or(LocalFormatError::Malformed)?;
        let origin = TrustOrigin::from_u8(reader.u8()?).ok_or(LocalFormatError::Malformed)?;
        let state = VerificationState::from_u8(reader.u8()?).ok_or(LocalFormatError::Malformed)?;
        let generation = reader.u64()?;
        let mut psk = PairPsk(Zeroizing::new([0; PSK_LEN]));
        reader.read_into(psk.0.as_mut())?;
        let history_count = usize::from(reader.u8()?);
        if history_count > MAX_HISTORY
            || reader.remaining() < history_count * HISTORY_LEN + PENDING_LEN
        {
            return Err(LocalFormatError::Malformed);
        }
        let mut history = VecDeque::with_capacity(history_count);
        for _ in 0..history_count {
            history.push_back(decode_event(&mut reader)?);
        }
        let pinned = PinnedKeys {
            person_root,
            device_public,
            noise_static,
            kem_static,
        };
        let pending = decode_pending(&mut reader, generation, pinned.digest())?;
        contacts.insert(
            device_public,
            Contact {
                pinned,
                binding_serial,
                origin,
                state,
                generation,
                psk,
                history,
                pending,
            },
        );
    }
    let revocations = RevocationSet::decode(&mut reader)?;
    let pairing = PairingState::decode(&mut reader)?;
    reader.finish()?;
    // Retained roots must be trusted, i.e. pinned by some contact.
    let all_trusted = revocations.roots().all(|root| {
        contacts
            .values()
            .any(|contact: &Contact| contact.pinned.person_root == *root)
    });
    if !all_trusted {
        return Err(LocalFormatError::Malformed);
    }
    // A device cannot be both mid-ratchet as a contact and mid-pairing.
    if pairing.pending.as_ref().is_some_and(|pending| {
        contacts
            .get(&pending.device)
            .is_some_and(|contact| contact.pending.is_some())
    }) {
        return Err(LocalFormatError::Malformed);
    }
    Ok((contacts, revocations, pairing))
}

/// Re-encodes decoded plaintext, for the fuzz harness's canonicality check.
#[cfg(fuzzing)]
pub(crate) fn reencode(decoded: &Decoded) -> Zeroizing<Vec<u8>> {
    encode_all(&decoded.0, &decoded.1, &decoded.2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::storage::MemoryStorage;
    use crate::identity::test_support::{
        DAY, Enrolled, SwitchableStorage, T0, TestResult, assert_distinct_messages, nz, request,
        sealer, time,
    };
    use crate::identity::{
        ExportPolicy, KeyRole, RevocationRequest, SoftwareSealer, issue_device_binding,
        issue_revocation,
    };
    use proptest::prelude::*;
    use todoke_proto::identity::{RevocationReason, RevokeBody};

    type Store = ContactStore<SoftwareSealer, MemoryStorage>;

    fn empty_store() -> Result<Store, ContactError> {
        ContactStore::open(sealer(9), MemoryStorage::new())
    }

    fn reopen(store: &Store) -> Result<Store, ContactError> {
        let mut storage = MemoryStorage::new();
        storage.set_blob(store.storage().blob().map(<[u8]>::to_vec));
        ContactStore::open(sealer(9), storage)
    }

    fn device(enrolled: &Enrolled) -> Result<Ed25519PublicKey, Box<dyn std::error::Error>> {
        Ok(enrolled.store.public_key(&enrolled.device)?)
    }

    use crate::identity::KeyStore;

    fn paired() -> Result<(Enrolled, Store), Box<dyn std::error::Error>> {
        let enrolled = Enrolled::new()?;
        let mut store = empty_store()?;
        let binding = enrolled.bind(1)?;
        let outcome = store.pair(
            &binding,
            TrustOrigin::QrPairing,
            PairPsk::new([0x77; 32]),
            1,
            time(T0)?,
        )?;
        assert_eq!(outcome, PairOutcome::New);
        Ok((enrolled, store))
    }

    fn revoke_through(
        enrolled: &Enrolled,
        sequence: u64,
        through: u64,
    ) -> Result<Revoke, Box<dyn std::error::Error>> {
        Ok(issue_revocation(
            &enrolled.store,
            &enrolled.root,
            RevocationRequest {
                device_public: device(enrolled)?,
                sequence: nz(sequence)?,
                issued_at: time(T0)?,
                through_serial: nz(through)?,
                reason: RevocationReason::Lost,
            },
        )?
        .record()
        .clone())
    }

    #[test]
    fn pair_then_confirm_and_renew() -> TestResult {
        let (enrolled, mut store) = paired()?;
        let key = device(&enrolled)?;
        let contact = store.contact(&key).ok_or("missing")?;
        assert_eq!(contact.state(), VerificationState::Verified);
        assert_eq!(contact.origin(), TrustOrigin::QrPairing);
        assert_eq!(contact.generation(), 1);
        assert_eq!(contact.pinned().noise_static(), &[0x33; 32]);
        assert_eq!(store.find_by_device_id(DeviceId::of(&key)).count(), 1);

        let same = enrolled.bind(1)?;
        store.confirm_identity(&key, &[0x33; 32], same.binding(), time(T0)?)?;
        let renewed = enrolled.bind(2)?;
        store.confirm_identity(&key, &[0x33; 32], renewed.binding(), time(T0 + DAY)?)?;
        let contact = store.contact(&key).ok_or("missing")?;
        assert_eq!(contact.binding_serial(), nz(2)?);
        let kinds: Vec<_> = contact.history().map(|event| event.kind).collect();
        assert_eq!(kinds, [HistoryKind::Paired, HistoryKind::Renewed]);
        // Presenting the pinned serial again is accepted and changes nothing.
        store.confirm_identity(&key, &[0x33; 32], renewed.binding(), time(T0)?)?;
        assert_eq!(
            store.contact(&key).ok_or("missing")?.binding_serial(),
            nz(2)?
        );
        Ok(())
    }

    /// §2: serials are "unique and increasing for this root/device". Once a
    /// higher serial is pinned, a replayed older binding must not authenticate
    /// even while it is still time-valid.
    #[test]
    fn regressed_serial_is_rejected() -> TestResult {
        let (enrolled, mut store) = paired()?;
        let key = device(&enrolled)?;
        let old = enrolled.bind(1)?;
        store.confirm_identity(&key, &[0x33; 32], enrolled.bind(3)?.binding(), time(T0)?)?;
        assert_eq!(
            store.confirm_identity(&key, &[0x33; 32], old.binding(), time(T0)?),
            Err(IdentityError::SerialRegressed)
        );
        assert_eq!(
            store.confirm_identity(&key, &[0x33; 32], enrolled.bind(2)?.binding(), time(T0)?),
            Err(IdentityError::SerialRegressed)
        );
        let contact = store.contact(&key).ok_or("missing")?;
        assert_eq!(contact.binding_serial(), nz(3)?);
        assert_eq!(contact.state(), VerificationState::Verified);
        assert_eq!(contact.history().len(), 2);
        // The pinned serial itself still authenticates.
        store.confirm_identity(&key, &[0x33; 32], enrolled.bind(3)?.binding(), time(T0)?)?;
        Ok(())
    }

    #[test]
    fn key_change_is_detected_blocked_and_recorded() -> TestResult {
        let (enrolled, mut store) = paired()?;
        let key = device(&enrolled)?;
        let pinned_digest = store.contact(&key).ok_or("missing")?.pinned().digest();
        // Same root and device, different ML-KEM credential.
        let changed = enrolled.bind_with(2, 0x33, 0x55)?;
        let result = store.confirm_identity(&key, &[0x33; 32], changed.binding(), time(T0)?);
        let Err(IdentityError::KeyChanged(which)) = result else {
            return Err(format!("expected key change, got {result:?}").into());
        };
        assert!(which.kem_static() && !which.person_root() && !which.device_key());
        let contact = store.contact(&key).ok_or("missing")?;
        assert_eq!(contact.state(), VerificationState::KeyChanged);
        assert_eq!(contact.pinned().digest(), pinned_digest);
        let last = contact.history().last().ok_or("no history")?;
        assert_eq!(last.kind, HistoryKind::KeyChangeRejected(which));
        assert_eq!(last.serial, nz(2)?);
        assert_ne!(last.keyset, pinned_digest);
        // Fail closed thereafter, even for the originally pinned binding.
        let original = enrolled.bind(1)?;
        assert_eq!(
            store.confirm_identity(&key, &[0x33; 32], original.binding(), time(T0)?),
            Err(IdentityError::Unavailable(Unavailable::KeyChanged))
        );
        assert_eq!(
            store.availability(&key)?.err(),
            Some(Unavailable::KeyChanged)
        );
        // The block survives a restart.
        assert_eq!(
            reopen(&store)?.contact(&key).ok_or("missing")?.state(),
            VerificationState::KeyChanged
        );
        Ok(())
    }

    #[test]
    fn new_root_for_same_device_is_a_key_change() -> TestResult {
        let (enrolled, mut store) = paired()?;
        let key = device(&enrolled)?;
        let other = Enrolled::new()?;
        // Another root certifies this device key; possession is still signed
        // by the real device, so the binding is validly signed.
        let body = todoke_proto::identity::DeviceBindingBody::new(
            *other.store.public_key(&other.root)?.as_bytes(),
            *key.as_bytes(),
            [0x33; 32],
            crate::identity::test_support::kem_static(0x44),
            nz(5)?,
            time(T0)?,
            time(T0 + DAY)?,
        )?;
        let root_signature = other
            .store
            .sign(
                &other.root,
                crate::identity::SigningDomain::DeviceBinding,
                &body.encode(),
            )?
            .to_bytes();
        let possession = enrolled
            .store
            .sign(
                &enrolled.device,
                crate::identity::SigningDomain::DevicePossession,
                &[body.encode(), root_signature.to_vec()].concat(),
            )?
            .to_bytes();
        let binding = DeviceBinding::from_parts(body, root_signature, possession);
        let result = store.confirm_identity(&key, &[0x33; 32], &binding, time(T0)?);
        let Err(IdentityError::KeyChanged(which)) = result else {
            return Err(format!("expected key change, got {result:?}").into());
        };
        assert!(which.person_root() && !which.device_key() && !which.kem_static());
        Ok(())
    }

    #[test]
    fn authentication_failures_leave_contact_unchanged() -> TestResult {
        let (enrolled, mut store) = paired()?;
        let key = device(&enrolled)?;
        let binding = enrolled.bind(2)?;
        assert_eq!(
            store.confirm_identity(&key, &[0x34; 32], binding.binding(), time(T0)?),
            Err(IdentityError::AuthenticationFailed)
        );
        let mut tampered = binding.encode();
        tampered[1400] ^= 1;
        let tampered = DeviceBinding::decode(&tampered)?;
        assert_eq!(
            store.confirm_identity(&key, &[0x33; 32], &tampered, time(T0)?),
            Err(IdentityError::AuthenticationFailed)
        );
        let other = Enrolled::new()?;
        assert_eq!(
            store.confirm_identity(&device(&other)?, &[0x33; 32], binding.binding(), time(T0)?),
            Err(IdentityError::UnknownContact)
        );
        let contact = store.contact(&key).ok_or("missing")?;
        assert_eq!(contact.state(), VerificationState::Verified);
        assert_eq!(contact.history().len(), 1);
        // Expired binding with pinned keys: policy error, still unchanged.
        assert_eq!(
            store.confirm_identity(&key, &[0x33; 32], binding.binding(), time(T0 + 31 * DAY)?),
            Err(IdentityError::Binding(BindingError::Expired))
        );
        assert_eq!(
            store.contact(&key).ok_or("missing")?.state(),
            VerificationState::Verified
        );
        Ok(())
    }

    #[test]
    fn explicit_repairing_clears_block_and_records_history() -> TestResult {
        let (enrolled, mut store) = paired()?;
        let key = device(&enrolled)?;
        store.mark_ratchet_uncertain(&key)?;
        assert_eq!(
            store.availability(&key)?.err(),
            Some(Unavailable::RatchetUncertain)
        );
        let previous = store.contact(&key).ok_or("missing")?.pinned().digest();
        let rebinding = enrolled.bind_with(3, 0x33, 0x55)?;
        let outcome = store.pair(
            &rebinding,
            TrustOrigin::QrPairing,
            PairPsk::new([0x78; 32]),
            1,
            time(T0 + DAY)?,
        )?;
        assert_eq!(outcome, PairOutcome::RePaired);
        let contact = store.contact(&key).ok_or("missing")?;
        assert_eq!(contact.state(), VerificationState::Verified);
        let last = contact.history().last().ok_or("no history")?;
        assert_eq!(last.kind, HistoryKind::RePaired { previous });
        assert_eq!(last.keyset, contact.pinned().digest());
        assert!(store.availability(&key)?.is_ok());
        Ok(())
    }

    #[test]
    fn revocations_flow_through_the_store() -> TestResult {
        let (enrolled, mut store) = paired()?;
        let key = device(&enrolled)?;
        let stranger = Enrolled::new()?;
        assert_eq!(
            store.apply_revocation(revoke_through(&stranger, 1, 1)?),
            Err(ContactError::Revocation(RevocationError::UntrustedRoot))
        );
        assert_eq!(
            store.apply_revocation(revoke_through(&enrolled, 1, 1)?)?,
            ApplyOutcome::Added
        );
        assert_eq!(store.availability(&key)?.err(), Some(Unavailable::Revoked));
        let old = enrolled.bind(1)?;
        assert_eq!(
            store.confirm_identity(&key, &[0x33; 32], old.binding(), time(T0)?),
            Err(IdentityError::Binding(BindingError::Revoked))
        );
        // Pairing a revoked binding is refused.
        assert_eq!(
            store.pair(
                &old,
                TrustOrigin::QrPairing,
                PairPsk::new([1; 32]),
                1,
                time(T0)?
            ),
            Err(ContactError::Binding(BindingError::Revoked))
        );
        // A renewal above through_serial restores availability.
        let renewed = enrolled.bind(2)?;
        store.confirm_identity(&key, &[0x33; 32], renewed.binding(), time(T0)?)?;
        assert!(store.availability(&key)?.is_ok());
        // Revocations persist and are dropped when the root is no longer trusted.
        let reopened = reopen(&store)?;
        assert_eq!(reopened.revocations().len(), 1);
        store.remove(&key)?;
        assert!(store.revocations().is_empty());
        assert!(reopen(&store)?.revocations().is_empty());
        Ok(())
    }

    #[test]
    fn conflicting_revocations_persist_as_evidence() -> TestResult {
        let (enrolled, mut store) = paired()?;
        let key = device(&enrolled)?;
        let root = enrolled.store.public_key(&enrolled.root)?;
        let first = revoke_through(&enrolled, 1, 1)?;
        let conflicting = revoke_through(&enrolled, 1, 2)?;
        assert_eq!(store.apply_revocation(first.clone())?, ApplyOutcome::Added);
        assert_eq!(
            store.apply_revocation(conflicting.clone())?,
            ApplyOutcome::Conflict
        );
        assert_eq!(
            store.availability(&key)?.err(),
            Some(Unavailable::RootDisabled)
        );
        let reopened = reopen(&store)?;
        assert_eq!(reopened.revocations(), store.revocations());
        assert_eq!(
            reopened
                .revocations()
                .records_for(&root)
                .collect::<Vec<_>>(),
            [&first]
        );
        assert_eq!(
            reopened
                .revocations()
                .conflicting_records_for(&root)
                .collect::<Vec<_>>(),
            [&conflicting]
        );
        assert_eq!(
            reopened.availability(&key)?.err(),
            Some(Unavailable::RootDisabled)
        );
        Ok(())
    }

    #[test]
    fn decode_rejects_malformed_conflict_evidence() -> TestResult {
        let (enrolled, _) = paired()?;
        let root = enrolled.store.public_key(&enrolled.root)?;
        let one = revoke_through(&enrolled, 1, 1)?;
        let two = revoke_through(&enrolled, 2, 1)?;
        let mut evidence = [
            revoke_through(&enrolled, 1, 2)?,
            revoke_through(&enrolled, 1, 3)?,
        ];
        evidence.sort_by_key(|record| record.body().encode());
        let [low, high] = evidence;
        let records = [one.clone(), two];
        assert!(
            decode_set(&set_bytes(
                &root,
                true,
                &records,
                &[low.clone(), high.clone()]
            ))
            .is_some()
        );
        // Conflicts require the disabled flag.
        assert!(
            decode_set(&set_bytes(
                &root,
                false,
                &records,
                core::slice::from_ref(&low)
            ))
            .is_none()
        );
        // A conflict must match a retained sequence with a different body.
        let orphan = revoke_through(&enrolled, 3, 1)?;
        assert!(decode_set(&set_bytes(&root, true, &records, &[orphan])).is_none());
        assert!(decode_set(&set_bytes(&root, true, &records, &[one])).is_none());
        // Strictly increasing, so no duplicates or reordering.
        assert!(decode_set(&set_bytes(&root, true, &records, &[high, low.clone()])).is_none());
        assert!(decode_set(&set_bytes(&root, true, &records, &[low.clone(), low])).is_none());
        // Another root's record is not evidence for this one.
        let stranger = Enrolled::new()?;
        let foreign = revoke_through(&stranger, 1, 2)?;
        assert!(decode_set(&set_bytes(&root, true, &records, &[foreign])).is_none());
        Ok(())
    }

    /// The contract the session layer relies on (§2): `availability` blocks a
    /// revoked pinned serial, while `confirm_identity` still accepts a renewal
    /// that supersedes it. Revocation leaves the PSK and generation untouched,
    /// so the availability check is what invalidates resumption.
    #[test]
    fn availability_blocks_revoked_serial_but_renewal_is_accepted() -> TestResult {
        let (enrolled, mut store) = paired()?;
        let key = device(&enrolled)?;
        store.apply_revocation(revoke_through(&enrolled, 1, 1)?)?;
        assert_eq!(store.availability(&key)?.err(), Some(Unavailable::Revoked));
        let contact = store.contact(&key).ok_or("missing")?;
        assert_eq!(contact.generation(), 1);
        assert_eq!(contact.psk.0.as_ref(), &[0x77; 32]);
        let renewal = enrolled.bind(2)?;
        assert_eq!(
            store.confirm_identity(&key, &[0x33; 32], renewal.binding(), time(T0)?),
            Ok(renewal.clone())
        );
        let contact = store.contact(&key).ok_or("missing")?;
        assert_eq!(contact.binding_serial(), nz(2)?);
        assert!(store.availability(&key)?.is_ok());
        Ok(())
    }

    #[test]
    fn persistence_round_trip_and_tamper_detection() -> TestResult {
        let (enrolled, mut store) = paired()?;
        let key = device(&enrolled)?;
        store.confirm_identity(&key, &[0x33; 32], enrolled.bind(2)?.binding(), time(T0)?)?;
        store.apply_revocation(revoke_through(&enrolled, 1, 1)?)?;
        let reopened = reopen(&store)?;
        let a = store.contact(&key).ok_or("missing")?;
        let b = reopened.contact(&key).ok_or("missing")?;
        assert_eq!(a.pinned(), b.pinned());
        assert_eq!(a.psk.0.as_ref(), b.psk.0.as_ref());
        assert_eq!(a.binding_serial(), b.binding_serial());
        assert_eq!(
            a.history().collect::<Vec<_>>(),
            b.history().collect::<Vec<_>>()
        );
        assert_eq!(store.revocations(), reopened.revocations());

        let blob = store.storage().blob().ok_or("no blob")?.to_vec();
        assert!(!blob.windows(32).any(|window| window == [0x77; 32]));
        let mut storage = MemoryStorage::new();
        storage.set_blob(Some(blob.clone()));
        assert_eq!(
            ContactStore::open(sealer(10), storage).err(),
            Some(ContactError::Seal)
        );
        // Every byte: the header (magic, version) is checked first, then the
        // nonce, ciphertext, and tag are authenticated.
        for index in 0..blob.len() {
            let mut changed = blob.clone();
            changed[index] ^= 1;
            let mut storage = MemoryStorage::new();
            storage.set_blob(Some(changed));
            let expected = if index < 6 {
                ContactError::Corrupt
            } else {
                ContactError::Seal
            };
            assert_eq!(
                ContactStore::open(sealer(9), storage).err(),
                Some(expected),
                "byte {index}"
            );
        }
        Ok(())
    }

    /// A revocation for a sibling device under the same root leaves this
    /// contact usable.
    #[test]
    fn sibling_revocation_leaves_contact_available() -> TestResult {
        let (mut enrolled, mut store) = paired()?;
        let key = device(&enrolled)?;
        let sibling = enrolled.store.generate(
            crate::identity::KeyRole::Device,
            crate::identity::ExportPolicy::NonExportable,
        )?;
        let record = issue_revocation(
            &enrolled.store,
            &enrolled.root,
            RevocationRequest {
                device_public: enrolled.store.public_key(&sibling)?,
                sequence: nz(1)?,
                issued_at: time(T0)?,
                through_serial: nz(u64::MAX)?,
                reason: RevocationReason::Lost,
            },
        )?;
        assert_eq!(
            store.apply_revocation(record.record().clone())?,
            ApplyOutcome::Added
        );
        assert!(store.availability(&key)?.is_ok());
        store.confirm_identity(&key, &[0x33; 32], enrolled.bind(2)?.binding(), time(T0)?)?;
        assert!(reopen(&store)?.availability(&key)?.is_ok());
        Ok(())
    }

    /// A disabled root blocks identity confirmation and new pairings for
    /// every device under it, even when no record revokes this device.
    #[test]
    fn disabled_root_blocks_confirmation_and_pairing() -> TestResult {
        let (mut enrolled, mut store) = paired()?;
        let key = device(&enrolled)?;
        let sibling = enrolled.store.generate(
            crate::identity::KeyRole::Device,
            crate::identity::ExportPolicy::NonExportable,
        )?;
        let revoke_sibling = |through: u64| {
            issue_revocation(
                &enrolled.store,
                &enrolled.root,
                RevocationRequest {
                    device_public: enrolled.store.public_key(&sibling)?,
                    sequence: nz(7)?,
                    issued_at: time(T0)?,
                    through_serial: nz(through)?,
                    reason: RevocationReason::Lost,
                },
            )
            .map(|record| record.record().clone())
            .map_err(Box::<dyn std::error::Error>::from)
        };
        store.apply_revocation(revoke_sibling(1)?)?;
        assert_eq!(
            store.apply_revocation(revoke_sibling(2)?)?,
            ApplyOutcome::Conflict
        );
        assert!(!store.revocations().is_revoked(
            &enrolled.store.public_key(&enrolled.root)?,
            &key,
            nz(1)?
        ));
        assert_eq!(
            store.availability(&key)?.err(),
            Some(Unavailable::RootDisabled)
        );
        let renewal = enrolled.bind(2)?;
        assert_eq!(
            store.confirm_identity(&key, &[0x33; 32], renewal.binding(), time(T0)?),
            Err(IdentityError::Unavailable(Unavailable::RootDisabled))
        );
        assert_eq!(
            store.contact(&key).ok_or("missing")?.binding_serial(),
            nz(1)?
        );
        assert_eq!(
            store.pair(
                &renewal,
                TrustOrigin::QrPairing,
                PairPsk::new([2; 32]),
                1,
                time(T0)?
            ),
            Err(ContactError::Binding(BindingError::RootDisabled))
        );
        Ok(())
    }

    #[test]
    fn debug_output_is_redacted() -> TestResult {
        let (enrolled, store) = paired()?;
        let rendered = format!("{store:?} {:?}", store.contact(&device(&enrolled)?));
        assert!(rendered.contains("REDACTED"));
        assert!(!rendered.contains("77, 77") && !rendered.contains("7777"));
        Ok(())
    }

    #[test]
    fn decode_rejects_untrusted_revocation_roots() -> TestResult {
        let (enrolled, store) = paired()?;
        // Re-encode with a revocation for an unpinned root appended.
        let stranger = Enrolled::new()?;
        let mut revocations = RevocationSet::new();
        let record = RevocationRecord::verify(
            revoke_through(&stranger, 1, 1)?,
            &PersonIdentity::new(stranger.store.public_key(&stranger.root)?),
        )?;
        revocations.apply(record);
        let plaintext = encode(&store.contacts, &revocations);
        assert!(decode(&plaintext).is_err());
        let valid = encode(&store.contacts, &RevocationSet::new());
        assert!(decode(&valid).is_ok());
        let _ = enrolled;
        Ok(())
    }

    fn arb_event() -> impl Strategy<Value = HistoryEvent> {
        (
            0..=todoke_proto::time::MAX_UNIX_TIME,
            1..=u64::MAX,
            any::<[u8; 32]>(),
            0..4u8,
            1..=ChangedKeys::ALL,
            any::<[u8; 32]>(),
        )
            .prop_filter_map("event", |(at, serial, keyset, kind, changed, previous)| {
                Some(HistoryEvent {
                    at: UnixTime::new(at)?,
                    serial: NonZeroU64::new(serial)?,
                    keyset: KeysetDigest(keyset),
                    kind: match kind {
                        0 => HistoryKind::Paired,
                        1 => HistoryKind::Renewed,
                        2 => HistoryKind::KeyChangeRejected(ChangedKeys(changed)),
                        _ => HistoryKind::RePaired {
                            previous: KeysetDigest(previous),
                        },
                    },
                })
            })
    }

    fn public_from_seed(seed: [u8; 32]) -> Option<Ed25519PublicKey> {
        let mut public = [0; 32];
        libcrux_ed25519::secret_to_public(&mut public, &seed);
        Ed25519PublicKey::from_bytes(&public).ok()
    }

    fn arb_contact() -> impl Strategy<Value = Contact> {
        (
            (any::<[u8; 32]>(), any::<[u8; 32]>(), any::<[u8; 32]>()),
            (
                any::<u8>(),
                1..=u64::MAX,
                any::<bool>(),
                1..=3u8,
                any::<u64>(),
            ),
            any::<[u8; 32]>(),
            proptest::collection::vec(arb_event(), 0..=MAX_HISTORY),
            (0..3u8, any::<[u8; 32]>(), any::<[u8; 32]>()),
        )
            .prop_filter_map(
                "contact",
                |(
                    (root, device, noise),
                    (kem, serial, code, state, generation),
                    psk,
                    history,
                    (pending_state, pending_hash, pending_psk),
                )| {
                    let pinned = PinnedKeys {
                        person_root: public_from_seed(root)?,
                        device_public: public_from_seed(device)?,
                        noise_static: noise,
                        kem_static: Box::new([kem; KEM_STATIC_LEN]),
                    };
                    let keyset = pinned.digest();
                    let pending = match pending_state {
                        0 => None,
                        1 => Some(PendingJournal::Journaled {
                            generation_next: generation.checked_add(1)?,
                            handshake_hash: pending_hash,
                            psk_next: PairPsk::new(pending_psk),
                            keyset,
                        }),
                        _ => Some(PendingJournal::Committed {
                            handshake_hash: pending_hash,
                            keyset,
                        }),
                    };
                    Some(Contact {
                        pinned,
                        binding_serial: NonZeroU64::new(serial)?,
                        origin: if code {
                            TrustOrigin::CodePairing
                        } else {
                            TrustOrigin::QrPairing
                        },
                        state: VerificationState::from_u8(state)?,
                        generation,
                        psk: PairPsk::new(psk),
                        history: history.into(),
                        pending,
                    })
                },
            )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn plaintext_round_trips(
            contacts in proptest::collection::vec(arb_contact(), 0..6),
            revoked in proptest::collection::vec((any::<[u8; 16]>(), 1..=u64::MAX, any::<[u8; 64]>(), any::<bool>()), 0..4),
        ) {
            let mut map = BTreeMap::new();
            for contact in contacts {
                map.insert(contact.pinned.device_public, contact);
            }
            // Attach structurally valid (unsigned) records to the first root.
            // Optionally add a conflicting record (same sequence, different
            // body) for each, which disables the root.
            let mut revocations = RevocationSet::new();
            if let Some(first) = map.values().next() {
                let root = first.pinned.person_root;
                let device = first.pinned.device_public;
                let record = |id: [u8; 16], sequence: NonZeroU64, through: u64, signature: [u8; 64]| {
                    let body = RevokeBody::new(
                        *root.as_bytes(), id, sequence,
                        UnixTime::new(T0).ok_or_else(|| TestCaseError::fail("time"))?,
                        *device.as_bytes(),
                        NonZeroU64::new(through).ok_or_else(|| TestCaseError::fail("through"))?,
                        RevocationReason::Retired,
                    ).map_err(|_| TestCaseError::fail("body"))?;
                    Ok::<_, TestCaseError>(Revoke::from_parts(body, signature))
                };
                let mut records = Vec::new();
                let mut conflicts = Vec::new();
                for (index, (id, through, signature, conflict)) in revoked.iter().enumerate() {
                    let id = if *id == [0; 16] { [1; 16] } else { *id };
                    let sequence = NonZeroU64::new(u64::try_from(index).unwrap_or(0) + 1)
                        .ok_or_else(|| TestCaseError::fail("sequence"))?;
                    records.push(record(id, sequence, *through, *signature)?);
                    if *conflict {
                        let mut other = id;
                        other[0] ^= 0x80;
                        conflicts.push(record(other, sequence, *through, *signature)?);
                    }
                }
                if !records.is_empty() {
                    revocations = unverified_set(&root, &records, &conflicts)
                        .ok_or_else(|| TestCaseError::fail("set"))?;
                    prop_assert_eq!(revocations.len(), records.len() + conflicts.len());
                    prop_assert_eq!(revocations.is_root_disabled(&root), !conflicts.is_empty());
                }
            }
            let encoded = encode(&map, &revocations);
            let decoded = decode(&encoded).map_err(|_| TestCaseError::fail("decode"))?;
            let reencoded = encode(&decoded.0, &decoded.1);
            prop_assert_eq!(reencoded.as_slice(), encoded.as_slice());
            prop_assert_eq!(decoded.0.len(), map.len());
            prop_assert_eq!(&decoded.1, &revocations);
        }

        #[test]
        fn decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = decode(&bytes);
        }
    }

    /// Builds a one-root set of unsigned records via the local format, the
    /// same path persistence uses (decode does not re-verify signatures).
    /// `records` are in sequence order; `conflicts` (any order) disable the root.
    fn unverified_set(
        root: &Ed25519PublicKey,
        records: &[Revoke],
        conflicts: &[Revoke],
    ) -> Option<RevocationSet> {
        let mut conflicts = conflicts.to_vec();
        conflicts.sort_by_key(|record| (record.body().sequence(), record.body().encode()));
        decode_set(&set_bytes(root, !conflicts.is_empty(), records, &conflicts))
    }

    /// One-root revocation set bytes in the local format, as given.
    fn set_bytes(
        root: &Ed25519PublicKey,
        disabled: bool,
        records: &[Revoke],
        conflicts: &[Revoke],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(root.as_bytes());
        bytes.push(u8::from(disabled));
        for list in [records, conflicts] {
            bytes.extend_from_slice(&u16::try_from(list.len()).unwrap_or(u16::MAX).to_be_bytes());
            for record in list {
                bytes.extend_from_slice(&record.encode());
            }
        }
        bytes
    }

    fn decode_set(bytes: &[u8]) -> Option<RevocationSet> {
        let mut reader = Reader::new(bytes);
        let set = RevocationSet::decode(&mut reader).ok()?;
        reader.finish().ok()?;
        Some(set)
    }

    type SwitchedStore = ContactStore<SoftwareSealer, SwitchableStorage>;

    /// Opens what the switchable store last persisted successfully.
    fn durable(store: &SwitchedStore) -> Result<Store, ContactError> {
        let mut storage = MemoryStorage::new();
        storage.set_blob(store.storage().blob().map(<[u8]>::to_vec));
        ContactStore::open(sealer(9), storage)
    }

    fn storage_failed<T: fmt::Debug>(result: &Result<T, ContactError>) -> bool {
        matches!(result, Err(ContactError::Storage(_)))
    }

    /// The §4.4 journal steps under failing storage: journaling and
    /// committing block in memory even if persisting fails; clearing (which
    /// grants access again) rolls back; a restart never restores an old PSK
    /// as usable while a journal was durable.
    #[test]
    fn ratchet_journal_persistence_is_fail_closed() -> TestResult {
        let enrolled = Enrolled::new()?;
        let key = device(&enrolled)?;
        let (storage, switch) = SwitchableStorage::new();
        let mut store = ContactStore::open(sealer(9), storage)?;
        store.pair(
            &enrolled.bind(1)?,
            TrustOrigin::QrPairing,
            PairPsk::new([0x77; 32]),
            1,
            time(T0)?,
        )?;
        let (hash, next) = ([0x48; 32], [0x99; 32]);
        // Journal write fails: blocked now, old pairing intact on disk.
        switch.set(true);
        assert!(storage_failed(
            &store.journal_ratchet(&key, 2, &hash, &next)
        ));
        assert_eq!(
            store.availability(&key)?.map(|_| ()),
            Err(Unavailable::RatchetUncertain)
        );
        let restarted = durable(&store)?;
        assert_eq!(
            restarted.availability(&key)?.map(Contact::generation),
            Ok(1)
        );
        // A durable journal, then a failing commit: blocked in memory, and a
        // restart finds the journal and blocks too.
        let (storage, switch) = SwitchableStorage::new();
        let mut store = ContactStore::open(sealer(9), storage)?;
        store.pair(
            &enrolled.bind(1)?,
            TrustOrigin::QrPairing,
            PairPsk::new([0x77; 32]),
            1,
            time(T0)?,
        )?;
        store.journal_ratchet(&key, 2, &hash, &next)?;
        switch.set(true);
        assert!(storage_failed(&store.commit_ratchet(&key, &hash)));
        assert!(store.availability(&key)?.is_err());
        let restarted = durable(&store)?;
        let contact = restarted.contact(&key).ok_or("contact")?;
        assert_eq!(contact.state(), VerificationState::RatchetUncertain);
        assert!(!contact.ratchet_pending());
        assert_eq!(
            restarted.availability(&key)?.map(|_| ()),
            Err(Unavailable::RatchetUncertain)
        );
        // Commit persisted, clear fails: the marker is restored in memory.
        let (storage, switch) = SwitchableStorage::new();
        let mut store = ContactStore::open(sealer(9), storage)?;
        store.pair(
            &enrolled.bind(1)?,
            TrustOrigin::QrPairing,
            PairPsk::new([0x77; 32]),
            1,
            time(T0)?,
        )?;
        store.journal_ratchet(&key, 2, &hash, &next)?;
        store.commit_ratchet(&key, &hash)?;
        switch.set(true);
        assert!(storage_failed(&store.clear_ratchet(&key, &hash)));
        assert!(store.contact(&key).ok_or("contact")?.ratchet_pending());
        assert!(store.availability(&key)?.is_err());
        let restarted = durable(&store)?;
        let contact = restarted.contact(&key).ok_or("contact")?;
        assert_eq!(contact.state(), VerificationState::RatchetUncertain);
        assert_eq!(
            contact.generation(),
            2,
            "committed state is what was durable"
        );
        // Abandon blocks in memory even when persisting fails.
        assert!(storage_failed(&store.abandon_ratchet(&key)));
        assert_eq!(
            store.contact(&key).ok_or("contact")?.state(),
            VerificationState::RatchetUncertain
        );
        // Finally a clean run commits and clears.
        let (storage, _switch) = SwitchableStorage::new();
        let mut store = ContactStore::open(sealer(9), storage)?;
        store.pair(
            &enrolled.bind(1)?,
            TrustOrigin::QrPairing,
            PairPsk::new([0x77; 32]),
            1,
            time(T0)?,
        )?;
        store.journal_ratchet(&key, 2, &hash, &next)?;
        store.commit_ratchet(&key, &hash)?;
        store.clear_ratchet(&key, &hash)?;
        let contact = durable(&store)?;
        let contact = contact.availability(&key)?.map_err(|_| "unavailable")?;
        assert_eq!((contact.generation(), contact.psk().expose()), (2, &next));
        Ok(())
    }

    /// Commit and clear act only on the transaction they name: another
    /// handshake hash is refused and leaves the journal, the PSK, and the
    /// generation exactly as they were (§4.4).
    #[test]
    fn ratchet_steps_for_another_handshake_hash_change_nothing() -> TestResult {
        let (enrolled, mut store) = paired()?;
        let key = device(&enrolled)?;
        let (hash, other, next) = ([0x48; 32], [0x49; 32], [0x99; 32]);
        store.journal_ratchet(&key, 2, &hash, &next)?;
        let journaled = store.storage().blob().map(<[u8]>::to_vec);
        assert_eq!(
            store.commit_ratchet(&key, &other),
            Err(ContactError::RatchetMismatch)
        );
        let contact = store.contact(&key).ok_or("contact")?;
        assert!(contact.ratchet_pending());
        assert_eq!(
            (contact.generation(), contact.psk().expose()),
            (1, &[0x77; 32])
        );
        assert_eq!(store.storage().blob().map(<[u8]>::to_vec), journaled);
        // The named transaction still commits.
        store.commit_ratchet(&key, &hash)?;
        let committed = store.storage().blob().map(<[u8]>::to_vec);
        assert_eq!(
            store.clear_ratchet(&key, &other),
            Err(ContactError::RatchetMismatch)
        );
        let contact = store.contact(&key).ok_or("contact")?;
        assert!(contact.ratchet_pending());
        assert_eq!((contact.generation(), contact.psk().expose()), (2, &next));
        assert_eq!(
            store.availability(&key)?.map(|_| ()),
            Err(Unavailable::RatchetUncertain)
        );
        assert_eq!(store.storage().blob().map(<[u8]>::to_vec), committed);
        store.clear_ratchet(&key, &hash)?;
        assert!(store.availability(&key)?.is_ok());
        Ok(())
    }

    /// Re-pairing replaces a journaled contact; journaling refuses overflow.
    #[test]
    fn repairing_clears_a_journal_and_overflow_is_refused() -> TestResult {
        let (enrolled, mut store) = paired()?;
        let key = device(&enrolled)?;
        store.journal_ratchet(&key, 2, &[1; 32], &[2; 32])?;
        assert_eq!(
            store.journal_ratchet(&key, 2, &[1; 32], &[2; 32]),
            Err(ContactError::RatchetMismatch)
        );
        assert_eq!(
            store.clear_ratchet(&key, &[1; 32]),
            Err(ContactError::RatchetMismatch)
        );
        store.pair(
            &enrolled.bind(2)?,
            TrustOrigin::QrPairing,
            PairPsk::new([3; 32]),
            u64::MAX,
            time(T0)?,
        )?;
        assert!(!store.contact(&key).ok_or("contact")?.ratchet_pending());
        assert_eq!(
            store.journal_ratchet(&key, 0, &[1; 32], &[2; 32]),
            Err(ContactError::RatchetMismatch)
        );
        // A contact at u64::MAX is blocked until re-paired (§4.4 overflow).
        assert_eq!(store.contact(&key).map(Contact::generation), Some(u64::MAX));
        assert_eq!(
            store.availability(&key)?.map(Contact::generation),
            Err(Unavailable::GenerationExhausted)
        );
        let unknown = Enrolled::new()?;
        assert_eq!(
            store.journal_ratchet(&device(&unknown)?, 2, &[1; 32], &[2; 32]),
            Err(ContactError::UnknownContact)
        );
        assert_ne!(ContactError::RatchetMismatch.to_string(), "");
        Ok(())
    }

    /// Only the three defined journal encodings decode.
    #[test]
    fn decode_validates_the_journal_block() -> TestResult {
        let device_key = indexed_key(1)?;
        let mut contact = fixed_contact(indexed_key(0)?, device_key, 0)?;
        let keyset = contact.pinned.digest();
        let start = 4 + CONTACT_FIXED_LEN - PENDING_LEN;
        let encode_with = |contact: Contact| {
            let mut map = BTreeMap::new();
            map.insert(device_key, contact);
            encode(&map, &RevocationSet::new()).to_vec()
        };
        let none = encode_with(fixed_contact(indexed_key(0)?, device_key, 0)?);
        assert_eq!(&none[start..start + PENDING_LEN], &[0; PENDING_LEN][..]);
        contact.pending = Some(PendingJournal::Journaled {
            generation_next: 2,
            handshake_hash: [5; 32],
            psk_next: PairPsk::new([6; 32]),
            keyset,
        });
        let journaled = encode_with(contact);
        assert_eq!(journaled[start], 1);
        let mut committed_contact = fixed_contact(indexed_key(0)?, device_key, 0)?;
        committed_contact.pending = Some(PendingJournal::Committed {
            handshake_hash: [5; 32],
            keyset,
        });
        let committed = encode_with(committed_contact);
        for valid in [&none, &journaled, &committed] {
            let decoded = decode(valid).map_err(|_| "decode")?;
            assert_eq!(encode(&decoded.0, &decoded.1).as_slice(), valid.as_slice());
        }
        let malformed = |bytes: &[u8], offset: usize, value: u8| {
            let mut changed = bytes.to_vec();
            changed[start + offset] = value;
            decode(&changed).err() == Some(LocalFormatError::Malformed)
        };
        // Unknown state; nonzero fields when there is no journal.
        assert!(malformed(&none, 0, 3));
        for offset in [1, 9, 41, 73] {
            assert!(malformed(&none, offset, 1), "offset {offset}");
        }
        // A journaled generation that is not generation + 1, or a keyset
        // that is not the pinned one.
        assert!(malformed(&journaled, 8, 3));
        assert!(malformed(&journaled, 73, 0));
        // A committed marker with a PSK or a generation.
        assert!(malformed(&committed, 41, 1));
        assert!(malformed(&committed, 8, 1));
        assert!(malformed(&committed, 73, 0));
        // Truncated block.
        assert!(decode(&none[..none.len() - 5]).is_err());
        Ok(())
    }

    /// Mutations that grant or keep access roll back when persisting fails;
    /// mutations that block access stay in effect in memory (fail closed).
    #[test]
    fn persistence_failures_roll_back_grants_and_keep_blocks() -> TestResult {
        let enrolled = Enrolled::new()?;
        let key = device(&enrolled)?;
        let (storage, failing) = SwitchableStorage::new();
        let mut store = ContactStore::open(sealer(9), storage)?;
        let first = enrolled.bind(1)?;
        let now = time(T0)?;

        failing.set(true);
        let result = store.pair(
            &first,
            TrustOrigin::QrPairing,
            PairPsk::new([1; 32]),
            1,
            now,
        );
        assert!(storage_failed(&result));
        assert!(store.contact(&key).is_none());
        failing.set(false);
        store.pair(
            &first,
            TrustOrigin::QrPairing,
            PairPsk::new([1; 32]),
            1,
            now,
        )?;
        let pinned = store.contact(&key).ok_or("missing")?.pinned().digest();

        // Re-pairing with other keys rolls back to the previous contact.
        failing.set(true);
        let rebinding = enrolled.bind_with(2, 0x33, 0x55)?;
        let result = store.pair(
            &rebinding,
            TrustOrigin::CodePairing,
            PairPsk::new([2; 32]),
            5,
            now,
        );
        assert!(storage_failed(&result));
        let contact = store.contact(&key).ok_or("missing")?;
        assert_eq!(contact.pinned().digest(), pinned);
        assert_eq!(contact.origin(), TrustOrigin::QrPairing);
        assert_eq!(contact.generation(), 1);
        assert_eq!(contact.psk.0.as_ref(), &[1; 32]);
        assert_eq!(contact.history().len(), 1);

        // A renewal rolls back.
        let renewal = enrolled.bind(2)?;
        assert!(matches!(
            store.confirm_identity(&key, &[0x33; 32], renewal.binding(), now),
            Err(IdentityError::Storage(ContactError::Storage(_)))
        ));
        let contact = store.contact(&key).ok_or("missing")?;
        assert_eq!(contact.binding_serial(), nz(1)?);
        assert_eq!(contact.history().len(), 1);

        // A duplicate revocation changes nothing, so nothing is persisted.
        failing.set(false);
        let record = revoke_through(&enrolled, 1, 1)?;
        assert_eq!(store.apply_revocation(record.clone())?, ApplyOutcome::Added);
        failing.set(true);
        assert_eq!(store.apply_revocation(record)?, ApplyOutcome::Duplicate);
        // A new revocation stays in effect although persisting it failed.
        let result = store.apply_revocation(revoke_through(&enrolled, 2, 1)?);
        assert!(storage_failed(&result));
        assert_eq!(store.revocations().len(), 2);

        // Removal rolls back: the contact and its root's revocations remain.
        assert!(storage_failed(&store.remove(&key)));
        assert!(store.contact(&key).is_some());
        assert_eq!(store.revocations().len(), 2);

        // A key change and a ratchet block stay in effect in memory.
        let changed = enrolled.bind_with(3, 0x33, 0x66)?;
        assert!(matches!(
            store.confirm_identity(&key, &[0x33; 32], changed.binding(), now),
            Err(IdentityError::Storage(ContactError::Storage(_)))
        ));
        assert_eq!(
            store.availability(&key)?.err(),
            Some(Unavailable::KeyChanged)
        );
        assert!(storage_failed(&store.mark_ratchet_uncertain(&key)));
        assert_eq!(
            store.availability(&key)?.err(),
            Some(Unavailable::RatchetUncertain)
        );

        // Durable state is the last successful write.
        let durable = durable(&store)?;
        let contact = durable.contact(&key).ok_or("missing")?;
        assert_eq!(contact.state(), VerificationState::Verified);
        assert_eq!(contact.binding_serial(), nz(1)?);
        assert_eq!(durable.revocations().len(), 1);
        Ok(())
    }

    /// The oldest history events are dropped first, at `MAX_HISTORY`.
    #[test]
    fn history_keeps_the_newest_events() -> TestResult {
        let (enrolled, mut store) = paired()?;
        let key = device(&enrolled)?;
        let last = MAX_HISTORY as u64 + 2;
        for serial in 2..=last {
            store.confirm_identity(
                &key,
                &[0x33; 32],
                enrolled.bind(serial)?.binding(),
                time(T0)?,
            )?;
        }
        let contact = store.contact(&key).ok_or("missing")?;
        assert_eq!(contact.history().len(), MAX_HISTORY);
        let serials: Vec<u64> = contact.history().map(|event| event.serial.get()).collect();
        assert_eq!(serials, (3..=last).collect::<Vec<_>>());
        assert!(
            contact
                .history()
                .all(|event| event.kind == HistoryKind::Renewed)
        );
        let reopened = reopen(&store)?;
        assert_eq!(
            reopened
                .contact(&key)
                .ok_or("missing")?
                .history()
                .collect::<Vec<_>>(),
            contact.history().collect::<Vec<_>>()
        );
        Ok(())
    }

    /// Each pinned key is compared separately and reported precisely.
    #[test]
    fn device_and_noise_key_changes_are_reported() -> TestResult {
        let (mut enrolled, mut store) = paired()?;
        let key = device(&enrolled)?;
        let noise = enrolled.bind_with(2, 0x35, 0x44)?;
        let result = store.confirm_identity(&key, &[0x35; 32], noise.binding(), time(T0)?);
        let Err(IdentityError::KeyChanged(which)) = result else {
            return Err(format!("expected key change, got {result:?}").into());
        };
        assert!(which.noise_static());
        assert!(!which.person_root() && !which.device_key() && !which.kem_static());
        assert_eq!(
            format!("{which:?}"),
            "ChangedKeys { person_root: false, device_key: false, noise_static: true, kem_static: false }"
        );

        // Re-pair, then present a sibling device's binding for this contact.
        store.pair(
            &enrolled.bind(3)?,
            TrustOrigin::QrPairing,
            PairPsk::new([3; 32]),
            1,
            time(T0)?,
        )?;
        let sibling = enrolled
            .store
            .generate(KeyRole::Device, ExportPolicy::NonExportable)?;
        let sibling_binding = issue_device_binding(
            &enrolled.store,
            &enrolled.root,
            &sibling,
            request(0x33, 0x44, 4, T0, T0 + DAY)?,
        )?;
        let result =
            store.confirm_identity(&key, &[0x33; 32], sibling_binding.binding(), time(T0)?);
        let Err(IdentityError::KeyChanged(which)) = result else {
            return Err(format!("expected key change, got {result:?}").into());
        };
        assert!(which.device_key());
        assert!(!which.person_root() && !which.noise_static() && !which.kem_static());
        Ok(())
    }

    #[test]
    fn contact_fields_survive_reopening() -> TestResult {
        let enrolled = Enrolled::new()?;
        let key = device(&enrolled)?;
        let mut store = empty_store()?;
        let binding = enrolled.bind(1)?;
        store.pair(
            &binding,
            TrustOrigin::CodePairing,
            PairPsk::new([0x5e; 32]),
            41,
            time(T0)?,
        )?;
        store.mark_ratchet_uncertain(&key)?;
        let reopened = reopen(&store)?;
        assert_eq!(reopened.contacts().count(), 1);
        let contact = reopened.contacts().next().ok_or("missing")?;
        assert_eq!(contact.device_id(), DeviceId::of(&key));
        assert_eq!(contact.origin(), TrustOrigin::CodePairing);
        assert_eq!(contact.state(), VerificationState::RatchetUncertain);
        assert_eq!(contact.generation(), 41);
        assert_eq!(contact.psk.0.as_ref(), &[0x5e; 32]);
        let pinned = contact.pinned();
        assert_eq!(pinned.person_root(), binding.person_root());
        assert_eq!(pinned.device_public(), &key);
        assert_eq!(pinned.noise_static(), binding.noise_static());
        assert_eq!(pinned.kem_static(), binding.kem_static());
        Ok(())
    }

    /// The keyset digest is `B3(domain || root || device || noise || kem)`.
    #[test]
    fn keyset_digest_and_debug_output() -> TestResult {
        let (enrolled, store) = paired()?;
        let pinned = store
            .contact(&device(&enrolled)?)
            .ok_or("missing")?
            .pinned();
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"todoke/local/keyset\0");
        hasher.update(pinned.person_root().as_bytes());
        hasher.update(pinned.device_public().as_bytes());
        hasher.update(pinned.noise_static());
        hasher.update(pinned.kem_static());
        let digest = pinned.digest();
        assert_eq!(digest.as_bytes(), hasher.finalize().as_bytes());
        assert_eq!(
            format!("{digest:?}"),
            format!("KeysetDigest({})", hex::encode(digest.as_bytes()))
        );
        let rendered = format!("{pinned:?}");
        for expected in [
            hex::encode(pinned.person_root().as_bytes()),
            hex::encode(pinned.device_public().as_bytes()),
            hex::encode(pinned.noise_static()),
            format!("[{KEM_STATIC_LEN} bytes]"),
        ] {
            assert!(rendered.contains(&expected), "{rendered} lacks {expected}");
        }
        assert_eq!(
            format!("{store:?}"),
            "ContactStore { contacts: 1, revocations: 0, pairing_pending: false, burned_pairings: 0, .. }"
        );
        Ok(())
    }

    /// Removing one device keeps its root's revocations while another
    /// contact still pins that root.
    #[test]
    fn revocations_are_kept_while_another_contact_pins_the_root() -> TestResult {
        let (mut enrolled, mut store) = paired()?;
        let key = device(&enrolled)?;
        let sibling = enrolled
            .store
            .generate(KeyRole::Device, ExportPolicy::NonExportable)?;
        let sibling_binding = issue_device_binding(
            &enrolled.store,
            &enrolled.root,
            &sibling,
            request(0x35, 0x45, 1, T0, T0 + DAY)?,
        )?;
        store.pair(
            &sibling_binding,
            TrustOrigin::QrPairing,
            PairPsk::new([4; 32]),
            1,
            time(T0)?,
        )?;
        store.apply_revocation(revoke_through(&enrolled, 1, 1)?)?;
        store.remove(&key)?;
        assert_eq!(store.revocations().len(), 1);
        assert_eq!(reopen(&store)?.revocations().len(), 1);
        store.remove(sibling_binding.device_public())?;
        assert!(store.revocations().is_empty());
        Ok(())
    }

    #[test]
    fn error_messages_are_distinct() {
        let contact = [
            ContactError::UnknownContact,
            ContactError::Capacity,
            ContactError::Binding(BindingError::Revoked),
            ContactError::Revocation(RevocationError::InvalidKey),
            ContactError::Seal,
            ContactError::Corrupt,
            ContactError::Storage(StorageError::TooLarge),
        ];
        assert_distinct_messages(&contact.map(|error| error.to_string()));
        assert!(
            ContactError::Binding(BindingError::Revoked)
                .to_string()
                .ends_with(&BindingError::Revoked.to_string())
        );
        let identity = [
            IdentityError::UnknownContact,
            IdentityError::Unavailable(Unavailable::KeyChanged),
            IdentityError::AuthenticationFailed,
            IdentityError::KeyChanged(ChangedKeys(ChangedKeys::NOISE_STATIC)),
            IdentityError::Binding(BindingError::Expired),
            IdentityError::SerialRegressed,
            IdentityError::Storage(ContactError::Seal),
        ];
        assert_distinct_messages(&identity.map(|error| error.to_string()));
        assert_eq!(
            IdentityError::Storage(ContactError::Seal).to_string(),
            ContactError::Seal.to_string()
        );
    }

    /// A distinct valid Ed25519 key per index (public test data).
    fn indexed_key(index: u32) -> Result<Ed25519PublicKey, Box<dyn std::error::Error>> {
        let mut seed = [0x6d; 32];
        seed[..4].copy_from_slice(&index.to_be_bytes());
        public_from_seed(seed).ok_or_else(|| "invalid key".into())
    }

    /// A contact with fixed public test values and `history` events.
    fn fixed_contact(
        root: Ed25519PublicKey,
        device: Ed25519PublicKey,
        history: usize,
    ) -> Result<Contact, &'static str> {
        let event = HistoryEvent {
            at: time(T0)?,
            serial: NonZeroU64::MIN,
            keyset: KeysetDigest([0x2b; 32]),
            kind: HistoryKind::Renewed,
        };
        Ok(Contact {
            pinned: PinnedKeys {
                person_root: root,
                device_public: device,
                noise_static: [0x33; 32],
                kem_static: Box::new([0x44; KEM_STATIC_LEN]),
            },
            binding_serial: NonZeroU64::MIN,
            origin: TrustOrigin::QrPairing,
            state: VerificationState::Verified,
            generation: 1,
            psk: PairPsk::new([0x77; 32]),
            history: core::iter::repeat_n(event, history).collect(),
            pending: None,
        })
    }

    /// An unsigned, structurally valid record (decode does not verify).
    fn unsigned_revoke(
        root: &Ed25519PublicKey,
        sequence: u64,
        through: u64,
    ) -> Result<Revoke, Box<dyn std::error::Error>> {
        let mut record_id = [0x5a; 16];
        record_id[..8].copy_from_slice(&sequence.to_be_bytes());
        record_id[8..].copy_from_slice(&through.to_be_bytes());
        let body = RevokeBody::new(
            *root.as_bytes(),
            record_id,
            nz(sequence)?,
            time(T0)?,
            [0x58; 32],
            nz(through)?,
            RevocationReason::Retired,
        )?;
        Ok(Revoke::from_parts(body, [0; 64]))
    }

    /// One root's entry in the local revocation-set format.
    struct RootEntry {
        root: Ed25519PublicKey,
        disabled: bool,
        records: Vec<Revoke>,
        conflicts: Vec<Revoke>,
    }

    /// Multi-root revocation set bytes, entries written in the given order.
    fn sets_bytes(entries: &[RootEntry]) -> Vec<u8> {
        let mut bytes = u32::try_from(entries.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes()
            .to_vec();
        for entry in entries {
            let one = set_bytes(
                &entry.root,
                entry.disabled,
                &entry.records,
                &entry.conflicts,
            );
            bytes.extend_from_slice(&one[4..]);
        }
        bytes
    }

    fn sorted_keys(
        count: u32,
        offset: u32,
    ) -> Result<Vec<Ed25519PublicKey>, Box<dyn std::error::Error>> {
        let mut keys = (offset..offset + count)
            .map(indexed_key)
            .collect::<Result<Vec<_>, _>>()?;
        keys.sort();
        Ok(keys)
    }

    /// The largest store the quotas allow seals to exactly `MAX_BLOB_LEN` bytes
    /// and opens; one more contact, history event, or trailing byte is
    /// rejected.
    #[test]
    fn maximal_store_fits_the_blob_limit_exactly() -> TestResult {
        let max_contacts = u32::try_from(MAX_CONTACTS)?;
        let roots = sorted_keys(max_contacts, 0)?;
        let devices = sorted_keys(max_contacts + 1, max_contacts)?;
        let mut contacts = BTreeMap::new();
        for (root, device) in roots.iter().zip(&devices) {
            contacts.insert(*device, fixed_contact(*root, *device, MAX_HISTORY)?);
        }
        let per_root = super::super::revocation::MAX_TOTAL_RECORDS / MAX_CONTACTS;
        let mut entries = Vec::new();
        for root in &roots {
            let mut records = Vec::new();
            for sequence in 1..=per_root as u64 {
                records.push(unsigned_revoke(root, sequence, 1)?);
            }
            entries.push(RootEntry {
                root: *root,
                disabled: false,
                records,
                conflicts: Vec::new(),
            });
        }
        let revocations = decode_set(&sets_bytes(&entries)).ok_or("set")?;
        assert_eq!(
            revocations.len(),
            super::super::revocation::MAX_TOTAL_RECORDS
        );
        // A pending pairing for one of the devices and a full ledger.
        let mut pairing = PairingState::default();
        for index in 0..MAX_BURNED_PAIRINGS {
            let mut pairing_id = [0xb0; 16];
            pairing_id[15] = u8::try_from(index)?;
            pairing.burned.insert(pairing_id, time(T0)?);
        }
        let pending_id = *pairing.burned.keys().next().ok_or("ledger")?;
        let pending_device = *devices.first().ok_or("no devices")?;
        pairing.pending = Some(pairing::PendingPairing {
            pairing_id: pending_id,
            expires_at: time(T0)?,
            origin: TrustOrigin::CodePairing,
            device: pending_device,
            keyset: KeysetDigest([1; 32]),
            handshake_hash: [2; 32],
            psk_next: PairPsk::new([3; 32]),
        });
        let plaintext = encode_all(&contacts, &revocations, &pairing);
        let blob = ENVELOPE.seal(&sealer(9), &plaintext).map_err(|_| "seal")?;
        assert_eq!(blob.len(), MAX_BLOB_LEN);
        let mut storage = MemoryStorage::new();
        storage.set_blob(Some(blob.clone()));
        let store = ContactStore::open(sealer(9), storage)?;
        assert_eq!(store.contacts().count(), MAX_CONTACTS);
        assert_eq!(store.revocations(), &revocations);
        let mut storage = MemoryStorage::new();
        storage.set_blob(Some([blob, vec![0]].concat()));
        assert_eq!(
            ContactStore::open(sealer(9), storage).err(),
            Some(ContactError::Storage(StorageError::TooLarge))
        );

        // One contact over the quota.
        let extra = *devices.last().ok_or("no devices")?;
        let first_root = *roots.first().ok_or("no roots")?;
        contacts.insert(extra, fixed_contact(first_root, extra, 0)?);
        assert_eq!(
            decode(&encode(&contacts, &RevocationSet::new())).err(),
            Some(LocalFormatError::Malformed)
        );
        // One history event over the quota.
        let mut over = BTreeMap::new();
        over.insert(extra, fixed_contact(first_root, extra, MAX_HISTORY + 1)?);
        assert_eq!(
            decode(&encode(&over, &RevocationSet::new())).err(),
            Some(LocalFormatError::Malformed)
        );
        Ok(())
    }

    /// Pairing a new device at `MAX_CONTACTS` is refused; re-pairing an
    /// existing contact is still allowed.
    #[test]
    fn pairing_beyond_capacity_is_refused() -> TestResult {
        let (mut enrolled, mut store) = paired()?;
        let key = device(&enrolled)?;
        let root = enrolled.store.public_key(&enrolled.root)?;
        for device in sorted_keys(u32::try_from(MAX_CONTACTS - 1)?, 0)? {
            store
                .contacts
                .insert(device, fixed_contact(root, device, 0)?);
        }
        assert_eq!(store.contacts().count(), MAX_CONTACTS);
        let sibling = enrolled
            .store
            .generate(KeyRole::Device, ExportPolicy::NonExportable)?;
        let sibling_binding = issue_device_binding(
            &enrolled.store,
            &enrolled.root,
            &sibling,
            request(0x35, 0x45, 1, T0, T0 + DAY)?,
        )?;
        assert_eq!(
            store.pair(
                &sibling_binding,
                TrustOrigin::QrPairing,
                PairPsk::new([5; 32]),
                1,
                time(T0)?
            ),
            Err(ContactError::Capacity)
        );
        assert!(store.contact(sibling_binding.device_public()).is_none());
        assert_eq!(
            store.pair(
                &enrolled.bind(2)?,
                TrustOrigin::QrPairing,
                PairPsk::new([6; 32]),
                1,
                time(T0)?
            ),
            Ok(PairOutcome::RePaired)
        );
        assert_eq!(
            store.contact(&key).ok_or("missing")?.binding_serial(),
            nz(2)?
        );
        Ok(())
    }

    /// Contacts must be in strictly increasing device-key order, and the
    /// plaintext must end exactly after the revocation set.
    #[test]
    fn decode_rejects_unordered_contacts_and_trailing_bytes() -> TestResult {
        let root = indexed_key(0)?;
        let devices = sorted_keys(2, 1)?;
        let mut contacts = BTreeMap::new();
        for device in &devices {
            contacts.insert(*device, fixed_contact(root, *device, 0)?);
        }
        let encoded = encode(&contacts, &RevocationSet::new());
        assert!(decode(&encoded).is_ok());
        let first = 4..4 + CONTACT_FIXED_LEN;
        let second = 4 + CONTACT_FIXED_LEN..4 + 2 * CONTACT_FIXED_LEN;
        let mut swapped = encoded.to_vec();
        swapped[first.clone()].copy_from_slice(&encoded[second.clone()]);
        swapped[second.clone()].copy_from_slice(&encoded[first.clone()]);
        assert_eq!(decode(&swapped).err(), Some(LocalFormatError::Malformed));
        let mut duplicated = encoded.to_vec();
        duplicated[second].copy_from_slice(&encoded[first]);
        assert_eq!(decode(&duplicated).err(), Some(LocalFormatError::Malformed));
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert_eq!(decode(&trailing).err(), Some(LocalFormatError::Malformed));
        Ok(())
    }

    /// Every enum byte, range, and history-kind combination in a stored
    /// contact is validated; counts that claim more data than remains are
    /// rejected up front.
    #[test]
    fn decode_rejects_invalid_contact_fields() -> TestResult {
        // Offsets within `count:u32 || contact || revocation set`.
        const SERIAL: usize = 4 + 32 * 3 + KEM_STATIC_LEN;
        const ORIGIN: usize = SERIAL + 8;
        const STATE: usize = ORIGIN + 1;
        const HISTORY_COUNT: usize = STATE + 1 + 8 + PSK_LEN;
        const EVENT: usize = HISTORY_COUNT + 1;
        const KIND: usize = EVENT + 8;
        const CHANGED: usize = KIND + 1;
        const EVENT_SERIAL: usize = CHANGED + 1;
        const PREVIOUS: usize = EVENT_SERIAL + 8 + 32;

        let device = indexed_key(1)?;
        let mut contacts = BTreeMap::new();
        contacts.insert(device, fixed_contact(indexed_key(0)?, device, 1)?);
        let valid = encode(&contacts, &RevocationSet::new()).to_vec();
        assert_eq!(
            valid.len(),
            4 + CONTACT_FIXED_LEN + HISTORY_LEN + 4 + pairing::PENDING_PAIRING_LEN + 1
        );
        assert_eq!(valid[KIND], 2);
        let with = |changes: &[(usize, &[u8])]| {
            let mut bytes = valid.clone();
            for (offset, value) in changes {
                bytes[*offset..*offset + value.len()].copy_from_slice(value);
            }
            decode(&bytes).map(|_| ())
        };
        let malformed = Err(LocalFormatError::Malformed);
        assert_eq!(with(&[]), Ok(()));
        assert_eq!(with(&[(SERIAL, &[0; 8])]), malformed);
        for origin in [0, 3, 0xff] {
            assert_eq!(with(&[(ORIGIN, &[origin])]), malformed);
        }
        assert_eq!(with(&[(ORIGIN, &[2])]), Ok(()));
        for state in [0, 4, 0xff] {
            assert_eq!(with(&[(STATE, &[state])]), malformed);
        }
        assert_eq!(with(&[(STATE, &[3])]), Ok(()));
        let too_late = (todoke_proto::time::MAX_UNIX_TIME + 1).to_be_bytes();
        assert_eq!(with(&[(EVENT, &too_late)]), malformed);
        assert_eq!(with(&[(EVENT_SERIAL, &[0; 8])]), malformed);
        // kind, changed, previous: only the defined combinations decode.
        let nonzero = [0x2c; 32];
        for (kind, changed, previous, accepted) in [
            (1, 0, &[0; 32], true),
            (1, 1, &[0; 32], false),
            (2, 0, &nonzero, false),
            (3, 0, &[0; 32], false),
            (3, 15, &[0; 32], true),
            (3, 16, &[0; 32], false),
            (3, 1, &nonzero, false),
            (4, 0, &nonzero, true),
            (4, 1, &nonzero, false),
            (0, 0, &[0; 32], false),
            (5, 0, &[0; 32], false),
        ] {
            let result = with(&[(KIND, &[kind]), (CHANGED, &[changed]), (PREVIOUS, previous)]);
            assert_eq!(result.is_ok(), accepted, "kind {kind} changed {changed}");
        }
        // Counts that claim more data than remains.
        assert_eq!(decode(&[0, 0, 0, 1]).map(|_| ()), malformed);
        assert_eq!(with(&[(HISTORY_COUNT, &[5])]), malformed);
        Ok(())
    }

    #[test]
    fn revocation_set_decode_rejects_counts_beyond_the_data() -> TestResult {
        let root = indexed_key(0)?;
        let record = unsigned_revoke(&root, 1, 1)?;
        let records = core::slice::from_ref(&record);
        let mut bytes = set_bytes(&root, true, records, &[]);
        assert!(decode_set(&bytes).is_some());
        // The conflict count claims one record that is not there.
        let length = bytes.len();
        bytes[length - 2..].copy_from_slice(&1u16.to_be_bytes());
        assert!(decode_set(&bytes).is_none());
        // The record count claims one record that is not there.
        let mut bytes = set_bytes(&root, true, &[], &[]);
        bytes.truncate(4 + 32 + 1);
        bytes.extend_from_slice(&1u16.to_be_bytes());
        assert!(decode_set(&bytes).is_none());
        Ok(())
    }

    /// Bounds, ordering, and consistency checks of the local revocation-set
    /// format (each case differs from a valid encoding in one respect).
    #[test]
    fn revocation_set_decode_enforces_bounds() -> TestResult {
        use super::super::revocation::{MAX_RECORDS_PER_ROOT, MAX_ROOTS};
        let empty_disabled = |root: Ed25519PublicKey| RootEntry {
            root,
            disabled: true,
            records: Vec::new(),
            conflicts: Vec::new(),
        };
        let records = |root: &Ed25519PublicKey,
                       count: usize|
         -> Result<Vec<Revoke>, Box<dyn std::error::Error>> {
            (1..=count as u64)
                .map(|sequence| unsigned_revoke(root, sequence, 1))
                .collect()
        };

        // Root count: MAX_ROOTS disabled, empty roots decode; one more does not.
        let max_roots = u32::try_from(MAX_ROOTS)?;
        let roots = sorted_keys(max_roots + 1, 5000)?;
        let mut entries: Vec<RootEntry> = roots.iter().copied().map(empty_disabled).collect();
        assert!(decode_set(&sets_bytes(&entries)).is_none());
        entries.pop();
        let set = decode_set(&sets_bytes(&entries)).ok_or("max roots")?;
        assert!(
            entries
                .iter()
                .all(|entry| set.is_root_disabled(&entry.root))
        );
        assert_eq!(set.len(), 0);

        // Roots strictly increasing.
        let (low, high) = (roots[0], roots[1]);
        assert!(decode_set(&sets_bytes(&[empty_disabled(low), empty_disabled(high)])).is_some());
        assert!(decode_set(&sets_bytes(&[empty_disabled(high), empty_disabled(low)])).is_none());
        assert!(decode_set(&sets_bytes(&[empty_disabled(low), empty_disabled(low)])).is_none());

        // An enabled root must retain records; a flag byte other than 0/1 is rejected.
        assert!(decode_set(&set_bytes(&low, false, &[], &[])).is_none());
        let mut flag = set_bytes(&low, true, &[], &[]);
        flag[36] = 2;
        assert!(decode_set(&flag).is_none());

        // Per-root record quota, for records alone and with conflicts.
        let full = records(&low, MAX_RECORDS_PER_ROOT)?;
        assert!(decode_set(&set_bytes(&low, false, &full, &[])).is_some());
        let over = records(&low, MAX_RECORDS_PER_ROOT + 1)?;
        assert!(decode_set(&set_bytes(&low, false, &over, &[])).is_none());
        let partial = &full[..MAX_RECORDS_PER_ROOT - 1];
        let conflict = |sequence: u64| unsigned_revoke(&low, sequence, 2);
        let mut conflicts = vec![conflict(1)?];
        assert!(decode_set(&set_bytes(&low, true, partial, &conflicts)).is_some());
        conflicts.push(conflict(2)?);
        conflicts.sort_by_key(|record| (record.body().sequence(), record.body().encode()));
        assert!(decode_set(&set_bytes(&low, true, partial, &conflicts)).is_none());

        // Records name this root and have strictly increasing sequences.
        let foreign = vec![unsigned_revoke(&low, 1, 1)?, unsigned_revoke(&high, 2, 1)?];
        assert!(decode_set(&set_bytes(&low, false, &foreign, &[])).is_none());
        let unordered = vec![unsigned_revoke(&low, 2, 1)?, unsigned_revoke(&low, 1, 1)?];
        assert!(decode_set(&set_bytes(&low, false, &unordered, &[])).is_none());

        // The per-root quota counts records plus evidence: one record with
        // MAX_RECORDS_PER_ROOT conflicting versions is one too many.
        let one = records(&low, 1)?;
        let mut versions = Vec::new();
        for through in 2..=MAX_RECORDS_PER_ROOT as u64 {
            versions.push(unsigned_revoke(&low, 1, through)?);
        }
        versions.sort_by_key(|record| record.body().encode());
        assert!(decode_set(&set_bytes(&low, true, &one, &versions)).is_some());
        versions.push(unsigned_revoke(&low, 1, MAX_RECORDS_PER_ROOT as u64 + 1)?);
        versions.sort_by_key(|record| record.body().encode());
        assert!(decode_set(&set_bytes(&low, true, &one, &versions)).is_none());
        Ok(())
    }

    /// `MAX_TOTAL_RECORDS` across roots, counting records and evidence.
    #[test]
    fn revocation_set_decode_enforces_total_quota() -> TestResult {
        use super::super::revocation::{MAX_RECORDS_PER_ROOT, MAX_TOTAL_RECORDS};
        let records = |root: &Ed25519PublicKey,
                       count: usize|
         -> Result<Vec<Revoke>, Box<dyn std::error::Error>> {
            (1..=count as u64)
                .map(|sequence| unsigned_revoke(root, sequence, 1))
                .collect()
        };
        let roots = sorted_keys(
            u32::try_from(MAX_TOTAL_RECORDS / MAX_RECORDS_PER_ROOT + 1)?,
            7000,
        )?;
        let mut entries = Vec::new();
        for root in &roots {
            entries.push(RootEntry {
                root: *root,
                disabled: true,
                records: records(root, MAX_RECORDS_PER_ROOT)?,
                conflicts: Vec::new(),
            });
        }
        let last = entries.pop().ok_or("no roots")?;
        assert_eq!(
            decode_set(&sets_bytes(&entries)).ok_or("total")?.len(),
            MAX_TOTAL_RECORDS
        );
        // One more record, for a further root, exceeds the total.
        entries.push(RootEntry {
            root: last.root,
            disabled: true,
            records: records(&last.root, 1)?,
            conflicts: Vec::new(),
        });
        assert!(decode_set(&sets_bytes(&entries)).is_none());
        // Records exactly at the total, conflict evidence exceeding it: free
        // one record slot at the first root so the records alone fit.
        entries.first_mut().ok_or("no roots")?.records.pop();
        assert_eq!(
            decode_set(&sets_bytes(&entries)).ok_or("total")?.len(),
            MAX_TOTAL_RECORDS
        );
        let evidence = unsigned_revoke(&last.root, 1, 2)?;
        entries
            .last_mut()
            .ok_or("no roots")?
            .conflicts
            .push(evidence);
        assert!(decode_set(&sets_bytes(&entries)).is_none());
        // Records plus evidence exactly at the total decode: drop the further
        // root and keep the evidence at the root with the free slot.
        entries.pop();
        let first = entries.first_mut().ok_or("no roots")?;
        let first_root = first.root;
        first.conflicts.push(unsigned_revoke(&first_root, 1, 2)?);
        let set = decode_set(&sets_bytes(&entries)).ok_or("evidence at quota")?;
        assert_eq!(set.len(), MAX_TOTAL_RECORDS);
        assert_eq!(set.conflicting_records_for(&first_root).count(), 1);
        Ok(())
    }

    #[derive(Clone, Copy, Debug)]
    enum Op {
        Pair,
        ConfirmSame,
        /// Present the pinned keys at `pinned serial - delta` (at least 1).
        ConfirmOlder(u64),
        ConfirmChanged,
        ConfirmTampered,
        MarkUncertain,
        Revoke,
        Reopen,
        Remove,
        /// §4.4 journal with the expected next generation.
        Journal,
        /// Journal with a wrong next generation.
        JournalWrongGeneration,
        Commit,
        /// Commit for another transaction's handshake hash.
        CommitWrongHash,
        Clear,
        /// Clear for another transaction's handshake hash.
        ClearWrongHash,
        Abandon,
    }

    fn arb_op() -> impl Strategy<Value = Op> {
        prop_oneof![
            2 => Just(Op::Pair),
            1 => Just(Op::ConfirmSame),
            // Weighted so regressed serials are reached in most cases.
            3 => (0..3u64).prop_map(Op::ConfirmOlder),
            1 => Just(Op::ConfirmChanged),
            1 => Just(Op::ConfirmTampered),
            1 => Just(Op::MarkUncertain),
            1 => Just(Op::Revoke),
            1 => Just(Op::Reopen),
            1 => Just(Op::Remove),
            3 => Just(Op::Journal),
            1 => Just(Op::JournalWrongGeneration),
            3 => Just(Op::Commit),
            1 => Just(Op::CommitWrongHash),
            3 => Just(Op::Clear),
            1 => Just(Op::ClearWrongHash),
            1 => Just(Op::Abandon),
        ]
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ModelJournal {
        Journaled([u8; 32]),
        Committed,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Model {
        state: VerificationState,
        serial: u64,
        generation: u64,
        psk: [u8; 32],
        journal: Option<ModelJournal>,
    }

    impl Model {
        fn paired(serial: u64) -> Self {
            Self {
                state: VerificationState::Verified,
                serial,
                generation: 1,
                psk: [3; 32],
                journal: None,
            }
        }

        fn blocked(&self) -> bool {
            self.state != VerificationState::Verified || self.journal.is_some()
        }
    }

    fn fail(error: impl fmt::Display) -> TestCaseError {
        TestCaseError::fail(error.to_string())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// Model-based state-machine test of the contact verification state,
        /// revocation, and persistence.
        #[test]
        fn contact_state_machine(ops in proptest::collection::vec(arb_op(), 1..24)) {
            let enrolled = Enrolled::new().map_err(fail)?;
            let key = enrolled.store.public_key(&enrolled.device).map_err(fail)?;
            let mut store = empty_store().map_err(fail)?;
            let mut model: Option<Model> = None;
            let mut revoked_through = 0u64;
            let mut next_serial = 1u64;
            let mut next_sequence = 1u64;
            let mut next_psk = 10u8;
            let now = time(T0).map_err(fail)?;
            let hash = [0x48; 32];

            for op in ops {
                match op {
                    Op::Pair => {
                        let binding = enrolled.bind(next_serial).map_err(fail)?;
                        store.pair(&binding, TrustOrigin::QrPairing, PairPsk::new([3; 32]), 1, now)
                            .map_err(fail)?;
                        model = Some(Model::paired(next_serial));
                        next_serial += 1;
                    }
                    Op::ConfirmSame => {
                        let binding = enrolled.bind(next_serial).map_err(fail)?;
                        let result = store.confirm_identity(&key, &[0x33; 32], binding.binding(), now);
                        match model.as_mut() {
                            None => prop_assert_eq!(result, Err(IdentityError::UnknownContact)),
                            Some(m) if m.blocked() => {
                                prop_assert!(matches!(result, Err(IdentityError::Unavailable(_))));
                            }
                            Some(m) => {
                                prop_assert!(result.is_ok());
                                m.serial = m.serial.max(next_serial);
                            }
                        }
                        next_serial += 1;
                    }
                    Op::ConfirmOlder(delta) => {
                        let serial = model.map_or(1, |m| m.serial.saturating_sub(delta).max(1));
                        let binding = enrolled.bind(serial).map_err(fail)?;
                        let result = store.confirm_identity(&key, &[0x33; 32], binding.binding(), now);
                        match model {
                            None => prop_assert_eq!(result, Err(IdentityError::UnknownContact)),
                            Some(m) if m.blocked() => {
                                prop_assert!(matches!(result, Err(IdentityError::Unavailable(_))));
                            }
                            Some(_) if serial <= revoked_through => {
                                prop_assert_eq!(result, Err(IdentityError::Binding(BindingError::Revoked)));
                            }
                            Some(m) if serial < m.serial => {
                                prop_assert_eq!(result, Err(IdentityError::SerialRegressed));
                            }
                            Some(_) => prop_assert!(result.is_ok()),
                        }
                    }
                    Op::ConfirmChanged | Op::ConfirmTampered => {
                        let binding = enrolled.bind_with(next_serial, 0x33, 0x66).map_err(fail)?;
                        let binding = if matches!(op, Op::ConfirmTampered) {
                            let mut bytes = binding.encode();
                            bytes[1437] ^= 1;
                            DeviceBinding::decode(&bytes).map_err(fail)?
                        } else {
                            binding.binding().clone()
                        };
                        let result = store.confirm_identity(&key, &[0x33; 32], &binding, now);
                        match model.as_mut() {
                            None => prop_assert_eq!(result, Err(IdentityError::UnknownContact)),
                            Some(m) if m.blocked() => {
                                prop_assert!(matches!(result, Err(IdentityError::Unavailable(_))));
                            }
                            Some(m) if matches!(op, Op::ConfirmTampered) => {
                                prop_assert_eq!(result, Err(IdentityError::AuthenticationFailed));
                                let _ = m;
                            }
                            Some(m) => {
                                prop_assert!(matches!(result, Err(IdentityError::KeyChanged(_))));
                                m.state = VerificationState::KeyChanged;
                            }
                        }
                        next_serial += 1;
                    }
                    Op::MarkUncertain => {
                        let result = store.mark_ratchet_uncertain(&key);
                        match model.as_mut() {
                            None => prop_assert_eq!(result, Err(ContactError::UnknownContact)),
                            Some(m) => {
                                prop_assert!(result.is_ok());
                                m.state = VerificationState::RatchetUncertain;
                            }
                        }
                    }
                    Op::Revoke => {
                        let through = model.map_or(1, |m| m.serial);
                        let record = revoke_through(&enrolled, next_sequence, through).map_err(fail)?;
                        next_sequence += 1;
                        let result = store.apply_revocation(record);
                        if model.is_some() {
                            prop_assert_eq!(result, Ok(ApplyOutcome::Added));
                            revoked_through = revoked_through.max(through);
                        } else {
                            prop_assert_eq!(
                                result,
                                Err(ContactError::Revocation(RevocationError::UntrustedRoot))
                            );
                        }
                    }
                    Op::Reopen => {
                        store = reopen(&store).map_err(fail)?;
                        // An interrupted journal blocks the pairing (§4.4).
                        if let Some(m) = model.as_mut()
                            && m.journal.take().is_some()
                        {
                            m.state = VerificationState::RatchetUncertain;
                        }
                    }
                    Op::Journal | Op::JournalWrongGeneration => {
                        let psk_next = [next_psk; 32];
                        next_psk = next_psk.wrapping_add(1);
                        let offset = if matches!(op, Op::Journal) { 1 } else { 2 };
                        let generation = model.map_or(1, |m| m.generation + offset);
                        let result = store.journal_ratchet(&key, generation, &hash, &psk_next);
                        match model.as_mut() {
                            None => prop_assert_eq!(result, Err(ContactError::UnknownContact)),
                            Some(m) if m.blocked() || m.serial <= revoked_through || offset == 2 => {
                                prop_assert_eq!(result, Err(ContactError::RatchetMismatch));
                            }
                            Some(m) => {
                                prop_assert_eq!(result, Ok(()));
                                m.journal = Some(ModelJournal::Journaled(psk_next));
                            }
                        }
                    }
                    Op::Commit | Op::CommitWrongHash => {
                        let presented = if matches!(op, Op::Commit) { hash } else { [0x49; 32] };
                        let result = store.commit_ratchet(&key, &presented);
                        match model.as_mut() {
                            None => prop_assert_eq!(result, Err(ContactError::UnknownContact)),
                            Some(m) => match m.journal {
                                Some(ModelJournal::Journaled(psk_next)) if matches!(op, Op::Commit) => {
                                    prop_assert_eq!(result, Ok(()));
                                    m.generation += 1;
                                    m.psk = psk_next;
                                    m.journal = Some(ModelJournal::Committed);
                                }
                                _ => prop_assert_eq!(result, Err(ContactError::RatchetMismatch)),
                            },
                        }
                    }
                    Op::Clear | Op::ClearWrongHash => {
                        let presented = if matches!(op, Op::Clear) { hash } else { [0x49; 32] };
                        let result = store.clear_ratchet(&key, &presented);
                        match model.as_mut() {
                            None => prop_assert_eq!(result, Err(ContactError::UnknownContact)),
                            Some(m)
                                if m.journal == Some(ModelJournal::Committed)
                                    && matches!(op, Op::Clear) =>
                            {
                                prop_assert_eq!(result, Ok(()));
                                m.journal = None;
                            }
                            Some(_) => prop_assert_eq!(result, Err(ContactError::RatchetMismatch)),
                        }
                    }
                    Op::Abandon => {
                        let result = store.abandon_ratchet(&key);
                        match model.as_mut() {
                            None => prop_assert_eq!(result, Err(ContactError::UnknownContact)),
                            Some(m) => {
                                prop_assert_eq!(result, Ok(()));
                                m.journal = None;
                                m.state = VerificationState::RatchetUncertain;
                            }
                        }
                    }
                    Op::Remove => {
                        let result = store.remove(&key);
                        if model.take().is_some() {
                            prop_assert!(result.is_ok());
                            revoked_through = 0;
                        } else {
                            prop_assert_eq!(result, Err(ContactError::UnknownContact));
                        }
                    }
                }

                // Invariants after every operation.
                match model {
                    None => {
                        prop_assert!(store.contact(&key).is_none());
                        prop_assert!(store.revocations().is_empty());
                    }
                    Some(m) => {
                        let contact = store.contact(&key).ok_or_else(|| fail("missing contact"))?;
                        prop_assert_eq!(contact.state(), m.state);
                        prop_assert_eq!(contact.binding_serial().get(), m.serial);
                        prop_assert_eq!(contact.generation(), m.generation);
                        prop_assert_eq!(contact.psk().expose(), &m.psk);
                        prop_assert_eq!(contact.ratchet_pending(), m.journal.is_some());
                        let expected = match m.state {
                            _ if m.journal.is_some() => Err(Unavailable::RatchetUncertain),
                            VerificationState::KeyChanged => Err(Unavailable::KeyChanged),
                            VerificationState::RatchetUncertain => Err(Unavailable::RatchetUncertain),
                            VerificationState::Verified if m.serial <= revoked_through => {
                                Err(Unavailable::Revoked)
                            }
                            VerificationState::Verified => Ok(()),
                        };
                        let actual = store.availability(&key).map_err(fail)?.map(|_| ());
                        prop_assert_eq!(actual, expected);
                        prop_assert!(contact.history().len() <= MAX_HISTORY);
                    }
                }
            }
        }
    }
}
