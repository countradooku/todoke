//! The durable side of QR and code pairing (PROTOCOL §3.1, §3.2, §4.4).
//!
//! A new pairing runs the same §4.4 ratchet transaction as a contact
//! session, from generation 0 with the pairing PSK. Because no contact
//! exists yet, its journal lives here instead of in a contact record:
//!
//! 1. **Journal** ([`ContactStore::journal_pairing`]): durably records the
//!    pending pairing `(pairing_id, generation_next = 1, h, psk_next, peer
//!    keyset)` and, in the same write, adds the pairing ID to the burned
//!    ledger. From here on the offer can never be used again, whatever
//!    happens next (§3.1: "uncertain committed QR MUST NOT be replayed
//!    after restart"; §3.2: "an uncertain pending commitment burns the
//!    offer as well").
//! 2. **Commit** ([`ContactStore::commit_pairing`]): atomically creates the
//!    contact through the same path as [`ContactStore::pair`], with
//!    `psk_next` at generation 1 and the committed ratchet marker, and
//!    drops the pending pairing.
//! 3. **Clear**: the existing [`ContactStore::clear_ratchet`] clears the
//!    marker and makes the contact usable.
//!
//! A failure after the journal ([`ContactStore::abandon_pairing`]), or a
//! journal found when the store is opened, never creates a usable contact:
//! the pending pairing is dropped (zeroizing its PSK) and an existing
//! contact for the same device is blocked as
//! [`VerificationState::RatchetUncertain`]. Re-pairing needs a fresh QR or
//! code (§4.4).
//!
//! The ledger keeps each burned pairing ID until its offer can no longer
//! pass an expiry check (its expiry plus twice the §1 skew), at most
//! [`MAX_BURNED_PAIRINGS`] at a time.

use core::fmt;
use std::collections::BTreeMap;

use todoke_proto::time::UnixTime;
use zeroize::Zeroizing;

use super::{
    ContactError, ContactStore, KeysetDigest, PSK_LEN, PairOutcome, PairPsk, PendingJournal,
    PinnedKeys, TrustOrigin, VerificationState,
};
use crate::identity::CLOCK_SKEW_SECONDS;
use crate::identity::binding::VerifiedDeviceBinding;
use crate::identity::codec::{LocalFormatError, Reader};
use crate::identity::ed25519::Ed25519PublicKey;
use crate::identity::sealing::Sealer;
use crate::identity::storage::BlobStorage;

/// Local quota: burned pairing IDs remembered at once.
pub const MAX_BURNED_PAIRINGS: usize = 64;

/// `state:u8 || pairing_id[16] || expires_at:u64 || origin:u8 ||
/// device[32] || keyset[32] || handshake_hash[32] || psk_next[32]`; all
/// zero when no pairing is pending.
pub(super) const PENDING_PAIRING_LEN: usize = 1 + 16 + 8 + 1 + 32 + 32 + 32 + PSK_LEN;
/// `pairing_id[16] || expires_at:u64`.
pub(super) const BURNED_LEN: usize = 16 + 8;
/// The pairing section of the blob: the pending block, a count, and the
/// ledger at its maximum size.
pub(super) const MAX_SECTION_LEN: usize =
    PENDING_PAIRING_LEN + 1 + MAX_BURNED_PAIRINGS * BURNED_LEN;

/// A journaled pairing whose contact does not exist yet (§4.4 steps 1–2).
pub(crate) struct PendingPairing {
    pub(super) pairing_id: [u8; 16],
    pub(super) expires_at: UnixTime,
    pub(super) origin: TrustOrigin,
    pub(super) device: Ed25519PublicKey,
    pub(super) keyset: KeysetDigest,
    pub(super) handshake_hash: [u8; 32],
    pub(super) psk_next: PairPsk,
}

impl fmt::Debug for PendingPairing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingPairing")
            .field("origin", &self.origin)
            .field("device", &self.device)
            .finish_non_exhaustive()
    }
}

/// The pairing state stored alongside the contacts.
#[derive(Debug, Default)]
pub(crate) struct PairingState {
    pub(super) pending: Option<PendingPairing>,
    /// Burned pairing IDs and the expiry of their offers.
    pub(super) burned: BTreeMap<[u8; 16], UnixTime>,
}

/// What [`ContactStore::journal_pairing`] records: the §4.4 pending state of
/// a new pairing, plus the offer it burns.
pub(crate) struct PairingJournal<'a> {
    /// The offer's pairing ID.
    pub(crate) pairing_id: [u8; 16],
    /// The offer's expiry, which bounds how long the ledger keeps the ID.
    pub(crate) expires_at: UnixTime,
    /// QR or code pairing.
    pub(crate) origin: TrustOrigin,
    /// The authenticated peer.
    pub(crate) peer: &'a VerifiedDeviceBinding,
    /// The final handshake hash identifying the transaction.
    pub(crate) handshake_hash: &'a [u8; 32],
    /// `psk_next` for generation 1.
    pub(crate) psk_next: &'a [u8; PSK_LEN],
}

impl<S: Sealer, B: BlobStorage> ContactStore<S, B> {
    /// Whether `pairing_id` was burned by an earlier journaled pairing, on
    /// either side, and is still remembered.
    #[must_use]
    pub fn pairing_burned(&self, pairing_id: &[u8; 16]) -> bool {
        self.pairing.burned.contains_key(pairing_id)
    }

    /// Whether a new pairing is journaled and not yet committed or
    /// abandoned in this process. A journal found when opening the store is
    /// discarded instead (see the module documentation).
    #[must_use]
    pub fn pairing_pending(&self) -> bool {
        self.pairing.pending.is_some()
    }

    /// §4.4 steps 1–2 for a new pairing: durably journals it and burns its
    /// offer in the same write.
    ///
    /// Requires that no other pairing is pending, that the pairing ID is not
    /// burned, and that an existing contact for the same device has no
    /// ratchet in progress. Expired ledger entries are dropped first. While
    /// journaled, [`Self::availability`] reports an existing contact for the
    /// device as unavailable.
    ///
    /// On a persistence error the journal and the burn stay in effect in
    /// memory (fail closed).
    pub(crate) fn journal_pairing(
        &mut self,
        journal: &PairingJournal<'_>,
        now: UnixTime,
    ) -> Result<(), ContactError> {
        let device = *journal.peer.device_public();
        if self.pairing.pending.is_some()
            || self.pairing_burned(&journal.pairing_id)
            || journal.pairing_id == [0; 16]
            || self
                .contacts
                .get(&device)
                .is_some_and(|contact| contact.pending.is_some())
        {
            return Err(ContactError::RatchetMismatch);
        }
        let horizon = now.seconds();
        self.pairing.burned.retain(|_, expires_at| {
            expires_at.seconds().saturating_add(2 * CLOCK_SKEW_SECONDS) > horizon
        });
        if self.pairing.burned.len() >= MAX_BURNED_PAIRINGS {
            return Err(ContactError::Capacity);
        }
        self.pairing
            .burned
            .insert(journal.pairing_id, journal.expires_at);
        self.pairing.pending = Some(PendingPairing {
            pairing_id: journal.pairing_id,
            expires_at: journal.expires_at,
            origin: journal.origin,
            device,
            keyset: PinnedKeys::from_binding(journal.peer).digest(),
            handshake_hash: *journal.handshake_hash,
            psk_next: PairPsk::from_secret(journal.psk_next),
        });
        self.persist()
    }

    /// §4.4 steps 3–4 for a new pairing: creates the contact for `peer`
    /// with the journaled `psk_next` at generation 1 and the committed
    /// marker, and drops the pending pairing, in one durable write.
    ///
    /// `peer` must be the journaled peer and `handshake_hash` the journaled
    /// transaction. The contact goes through the same checks as
    /// [`Self::pair`] (root disabled, binding revoked, capacity). On any
    /// error the store stays fail closed: before the write, nothing is
    /// usable; after a failed write, the new contact exists in memory with
    /// its marker, so it is unavailable.
    pub(crate) fn commit_pairing(
        &mut self,
        peer: &VerifiedDeviceBinding,
        handshake_hash: &[u8; 32],
        now: UnixTime,
    ) -> Result<PairOutcome, ContactError> {
        let pinned = PinnedKeys::from_binding(peer);
        let matches = self.pairing.pending.as_ref().is_some_and(|pending| {
            pending.handshake_hash == *handshake_hash
                && pending.device == *peer.device_public()
                && pending.keyset == pinned.digest()
        });
        if !matches {
            return Err(ContactError::RatchetMismatch);
        }
        let pending = self
            .pairing
            .pending
            .take()
            .ok_or(ContactError::RatchetMismatch)?;
        let marker = PendingJournal::Committed {
            handshake_hash: pending.handshake_hash,
            keyset: pending.keyset,
        };
        let result =
            self.insert_paired(peer, pending.origin, pending.psk_next, 1, now, Some(marker));
        match result {
            Ok((outcome, _previous)) => {
                self.persist()?;
                Ok(outcome)
            }
            Err(error) => Err(error),
        }
    }

    /// The pairing failed after [`Self::journal_pairing`]: drops the pending
    /// pairing (zeroizing its PSK) or, if it already committed, abandons the
    /// new contact's ratchet. Either way an existing contact for `device` is
    /// blocked as [`VerificationState::RatchetUncertain`], and the pairing
    /// ID stays burned. The block stays in effect in memory even if
    /// persisting it fails.
    pub(crate) fn abandon_pairing(
        &mut self,
        pairing_id: &[u8; 16],
        device: &Ed25519PublicKey,
    ) -> Result<(), ContactError> {
        if self
            .pairing
            .pending
            .as_ref()
            .is_some_and(|pending| pending.pairing_id == *pairing_id)
        {
            self.pairing.pending = None;
        }
        match self.contacts.get_mut(device) {
            Some(contact) => {
                contact.pending = None;
                self.block(device, VerificationState::RatchetUncertain, None)
            }
            None => self.persist(),
        }
    }

    /// Opening the store: a pending pairing belongs to a transaction that was
    /// interrupted. It is dropped and an existing contact for its device is
    /// blocked; its pairing ID stays burned (§4.4).
    pub(super) fn discard_interrupted_pairing(&mut self) {
        if let Some(pending) = self.pairing.pending.take()
            && let Some(contact) = self.contacts.get_mut(&pending.device)
        {
            contact.pending = None;
            contact.state = VerificationState::RatchetUncertain;
        }
    }

    /// Whether `device` has a new pairing journaled in this process.
    pub(super) fn pairing_pending_for(&self, device: &Ed25519PublicKey) -> bool {
        self.pairing
            .pending
            .as_ref()
            .is_some_and(|pending| pending.device == *device)
    }
}

impl PairingState {
    pub(super) fn encode_into(&self, out: &mut Vec<u8>) {
        match &self.pending {
            None => out.extend_from_slice(&[0; PENDING_PAIRING_LEN]),
            Some(pending) => {
                out.push(1);
                out.extend_from_slice(&pending.pairing_id);
                out.extend_from_slice(&pending.expires_at.seconds().to_be_bytes());
                out.push(pending.origin.to_u8());
                out.extend_from_slice(pending.device.as_bytes());
                out.extend_from_slice(&pending.keyset.0);
                out.extend_from_slice(&pending.handshake_hash);
                out.extend_from_slice(pending.psk_next.expose());
            }
        }
        // Bounded by MAX_BURNED_PAIRINGS on every insertion and decode.
        out.push(u8::try_from(self.burned.len()).unwrap_or(u8::MAX));
        for (pairing_id, expires_at) in &self.burned {
            out.extend_from_slice(pairing_id);
            out.extend_from_slice(&expires_at.seconds().to_be_bytes());
        }
    }

    pub(super) fn decode(reader: &mut Reader<'_>) -> Result<Self, LocalFormatError> {
        let state = reader.u8()?;
        let pairing_id = reader.array::<16>()?;
        let expires_at = reader.u64()?;
        let origin = reader.u8()?;
        let device = reader.array::<32>()?;
        let keyset = KeysetDigest(reader.array()?);
        let handshake_hash = reader.array::<32>()?;
        let mut psk_next = PairPsk(Zeroizing::new([0; PSK_LEN]));
        reader.read_into(psk_next.0.as_mut())?;
        let pending = match state {
            0 if pairing_id == [0; 16]
                && expires_at == 0
                && origin == 0
                && device == [0; 32]
                && keyset.0 == [0; 32]
                && handshake_hash == [0; 32]
                && psk_next.0.iter().all(|&byte| byte == 0) =>
            {
                None
            }
            1 if pairing_id != [0; 16] => Some(PendingPairing {
                pairing_id,
                expires_at: UnixTime::new(expires_at).ok_or(LocalFormatError::Malformed)?,
                origin: TrustOrigin::from_u8(origin).ok_or(LocalFormatError::Malformed)?,
                device: Ed25519PublicKey::from_bytes(&device)
                    .map_err(|_| LocalFormatError::Malformed)?,
                keyset,
                handshake_hash,
                psk_next,
            }),
            _ => return Err(LocalFormatError::Malformed),
        };
        let count = usize::from(reader.u8()?);
        if count > MAX_BURNED_PAIRINGS || reader.remaining() < count * BURNED_LEN {
            return Err(LocalFormatError::Malformed);
        }
        let mut burned = BTreeMap::new();
        let mut previous: Option<[u8; 16]> = None;
        for _ in 0..count {
            let pairing_id = reader.array::<16>()?;
            let expires_at = UnixTime::new(reader.u64()?).ok_or(LocalFormatError::Malformed)?;
            if pairing_id == [0; 16] || previous.is_some_and(|previous| previous >= pairing_id) {
                return Err(LocalFormatError::Malformed);
            }
            previous = Some(pairing_id);
            burned.insert(pairing_id, expires_at);
        }
        // The journal burns its offer in the same write.
        if let Some(pending) = &pending
            && burned.get(&pending.pairing_id) != Some(&pending.expires_at)
        {
            return Err(LocalFormatError::Malformed);
        }
        Ok(Self { pending, burned })
    }
}

#[cfg(test)]
mod tests;
