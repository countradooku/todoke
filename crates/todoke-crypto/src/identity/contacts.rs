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

/// Local quota: stored contacts.
pub const MAX_CONTACTS: usize = 1024;
/// Local quota: history events kept per contact; the oldest are dropped first.
pub const MAX_HISTORY: usize = 32;

const PSK_LEN: usize = 32;
/// `person_root || device_public || noise_static || kem_static || serial:u64 ||
/// origin:u8 || state:u8 || generation:u64 || psk[32] || history_count:u8`.
const CONTACT_FIXED_LEN: usize = 32 * 3 + KEM_STATIC_LEN + 8 + 1 + 1 + 8 + PSK_LEN + 1;
/// `at:u64 || kind:u8 || changed:u8 || serial:u64 || keyset[32] || previous[32]`.
const HISTORY_LEN: usize = 8 + 1 + 1 + 8 + 32 + 32;
const MAX_BLOB_LEN: usize = 6
    + SoftwareSealer::OVERHEAD
    + 4
    + MAX_CONTACTS * (CONTACT_FIXED_LEN + MAX_HISTORY * HISTORY_LEN)
    + 4
    + super::revocation::MAX_ROOTS * (32 + 1 + 2 + 2)
    + super::revocation::MAX_TOTAL_RECORDS * todoke_proto::identity::REVOKE_LEN;

/// Version 2 added retained conflicting revocation records to the revocation
/// set layout. Version 1 blobs are rejected; that format never shipped.
const ENVELOPE: Envelope = Envelope {
    magic: *b"TDKC",
    version: 2,
    context: b"todoke/local/contacts\0",
};
const KEYSET_DOMAIN: &[u8] = b"todoke/local/keyset\0";

/// The current pair PSK. Zeroized on drop; `Debug` is redacted; it has no
/// public constructor or accessor and never leaves this crate. It is produced
/// by pairing and the §4.4 ratchet, neither of which is implemented yet.
pub struct PairPsk(Zeroizing<[u8; PSK_LEN]>);

impl PairPsk {
    #[cfg(test)]
    pub(crate) fn new(bytes: [u8; PSK_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
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
    /// A ratchet transaction was interrupted with a pending journal (§4.4).
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

    fn record(&mut self, event: HistoryEvent) {
        if self.history.len() >= MAX_HISTORY {
            self.history.pop_front();
        }
        self.history.push_back(event);
    }
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
    /// Blocked after an interrupted ratchet; re-pair explicitly.
    RatchetUncertain,
    /// The contact's root is disabled by conflicting revocations or quota.
    RootDisabled,
    /// A retained revocation covers the pinned binding serial.
    Revoked,
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
}

impl<S: Sealer, B: BlobStorage> ContactStore<S, B> {
    /// Opens the store in `storage`, or starts empty.
    ///
    /// # Errors
    ///
    /// [`ContactError::Seal`], [`ContactError::Corrupt`], or a storage error.
    pub fn open(sealer: S, storage: B) -> Result<Self, ContactError> {
        let (contacts, revocations) = match storage.load(MAX_BLOB_LEN)? {
            None => (BTreeMap::new(), RevocationSet::new()),
            Some(blob) => {
                let plaintext = ENVELOPE.open(&sealer, &blob).map_err(map_format)?;
                decode(&plaintext).map_err(map_format)?
            }
        };
        Ok(Self {
            sealer,
            storage,
            contacts,
            revocations,
        })
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
        match contact.state {
            VerificationState::Verified => {}
            VerificationState::KeyChanged => return Err(Unavailable::KeyChanged),
            VerificationState::RatchetUncertain => return Err(Unavailable::RatchetUncertain),
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
        if let Err(error) = self.persist() {
            match previous {
                Some(previous) => self.contacts.insert(device, previous),
                None => self.contacts.remove(&device),
            };
            return Err(error);
        }
        Ok(outcome)
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
        let plaintext = encode(&self.contacts, &self.revocations);
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
            .finish_non_exhaustive()
    }
}

fn map_format(error: LocalFormatError) -> ContactError {
    match error {
        LocalFormatError::Malformed => ContactError::Corrupt,
        LocalFormatError::Seal => ContactError::Seal,
    }
}

/// Local format v2 plaintext:
/// `count:u32 || count × contact || revocation set`, contacts in strictly
/// increasing device-key order. See [`CONTACT_FIXED_LEN`] and
/// [`HISTORY_LEN`] for the record layouts.
fn encode(
    contacts: &BTreeMap<Ed25519PublicKey, Contact>,
    revocations: &RevocationSet,
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
    }
    revocations.encode_into(&mut out);
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

type Decoded = (BTreeMap<Ed25519PublicKey, Contact>, RevocationSet);

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
        let psk = PairPsk(Zeroizing::new(reader.array()?));
        let history_count = usize::from(reader.u8()?);
        if history_count > MAX_HISTORY || reader.remaining() < history_count * HISTORY_LEN {
            return Err(LocalFormatError::Malformed);
        }
        let mut history = VecDeque::with_capacity(history_count);
        for _ in 0..history_count {
            history.push_back(decode_event(&mut reader)?);
        }
        contacts.insert(
            device_public,
            Contact {
                pinned: PinnedKeys {
                    person_root,
                    device_public,
                    noise_static,
                    kem_static,
                },
                binding_serial,
                origin,
                state,
                generation,
                psk,
                history,
            },
        );
    }
    let revocations = RevocationSet::decode(&mut reader)?;
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
    Ok((contacts, revocations))
}

/// Re-encodes decoded plaintext, for the fuzz harness's canonicality check.
#[cfg(fuzzing)]
pub(crate) fn reencode(decoded: &Decoded) -> Zeroizing<Vec<u8>> {
    encode(&decoded.0, &decoded.1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::storage::MemoryStorage;
    use crate::identity::test_support::{DAY, Enrolled, T0, TestResult, nz, sealer, time};
    use crate::identity::{RevocationRequest, SoftwareSealer, issue_revocation};
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
        let mut changed = blob;
        let last = changed.len() - 1;
        changed[last] ^= 1;
        let mut storage = MemoryStorage::new();
        storage.set_blob(Some(changed));
        assert_eq!(
            ContactStore::open(sealer(9), storage).err(),
            Some(ContactError::Seal)
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
        )
            .prop_filter_map(
                "contact",
                |((root, device, noise), (kem, serial, code, state, generation), psk, history)| {
                    Some(Contact {
                        pinned: PinnedKeys {
                            person_root: public_from_seed(root)?,
                            device_public: public_from_seed(device)?,
                            noise_static: noise,
                            kem_static: Box::new([kem; KEM_STATIC_LEN]),
                        },
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
        ]
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Model {
        state: VerificationState,
        serial: u64,
    }

    fn fail(error: impl fmt::Display) -> TestCaseError {
        TestCaseError::fail(error.to_string())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        /// Model-based state-machine test of the contact verification state,
        /// revocation, and persistence.
        #[test]
        fn contact_state_machine(ops in proptest::collection::vec(arb_op(), 1..14)) {
            let enrolled = Enrolled::new().map_err(fail)?;
            let key = enrolled.store.public_key(&enrolled.device).map_err(fail)?;
            let mut store = empty_store().map_err(fail)?;
            let mut model: Option<Model> = None;
            let mut revoked_through = 0u64;
            let mut next_serial = 1u64;
            let mut next_sequence = 1u64;
            let now = time(T0).map_err(fail)?;

            for op in ops {
                match op {
                    Op::Pair => {
                        let binding = enrolled.bind(next_serial).map_err(fail)?;
                        store.pair(&binding, TrustOrigin::QrPairing, PairPsk::new([3; 32]), 1, now)
                            .map_err(fail)?;
                        model = Some(Model { state: VerificationState::Verified, serial: next_serial });
                        next_serial += 1;
                    }
                    Op::ConfirmSame => {
                        let binding = enrolled.bind(next_serial).map_err(fail)?;
                        let result = store.confirm_identity(&key, &[0x33; 32], binding.binding(), now);
                        match model.as_mut() {
                            None => prop_assert_eq!(result, Err(IdentityError::UnknownContact)),
                            Some(m) if m.state != VerificationState::Verified => {
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
                            Some(m) if m.state != VerificationState::Verified => {
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
                            Some(m) if m.state != VerificationState::Verified => {
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
                        let expected = match m.state {
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
