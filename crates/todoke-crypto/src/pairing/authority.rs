//! The [`PeerAuthority`] of a new pairing (PROTOCOL §3.1, §3.2, §4.3,
//! §4.4).

use core::fmt;

use todoke_proto::identity::KEM_STATIC_LEN;
use todoke_proto::session::SessionMode;
use todoke_proto::time::UnixTime;
use zeroize::Zeroizing;

use todoke_proto::pairing::{CODE_OFFER_TRANSCRIPT_LEN, CodeOffer, CodeOfferRequest};

use super::code::HumanCode;
use super::offers::{OfferReservation, OfferSecret};
use super::qr::{ExpiryError, QrPayload, check_offer_expiry};
use super::{PairingError, UnauditedCodePairing};
use crate::identity::contacts::{PairOutcome, PairingJournal};
use crate::identity::{
    BlobStorage, ContactError, ContactStore, Ed25519PublicKey, IdentityError, PersonIdentity,
    Sealer, TrustOrigin, VerifiedDeviceBinding,
};
use crate::session::authority::sealed;
use crate::session::{
    InitiatorPlan, PairingPsk, PeerAuthority, PeerPresentation, PendingRatchet, ResponderPlan,
    SessionError,
};

/// The responder keys a QR scanner pins (§3.1).
struct QrPins {
    device: Ed25519PublicKey,
    noise_static: [u8; 32],
    kem_static: Box<[u8; KEM_STATIC_LEN]>,
}

enum Side {
    /// Scanner or code entrant. QR pins the responder's keys; code has no
    /// pretrusted key (§4.2).
    Initiator { pins: Option<QrPins> },
    /// Displayer, holding its offer.
    Responder { reservation: OfferReservation },
}

/// Identity policy and durable state for one new pairing, as initiator or
/// responder.
///
/// It confirms an authenticated peer by verifying its binding under the
/// root the binding names (trust in that root originates in this
/// authenticated pairing, §2) against the store's retained revocations,
/// and, when scanning a QR, by pinning the responder's device, Noise, and
/// ML-KEM keys from the QR. The ratchet transaction journals the pairing
/// and burns the offer, commits by creating the contact, and clears the
/// marker; any failure after the journal blocks the device until a fresh
/// pairing (§4.4).
///
/// It borrows the [`ContactStore`] mutably for the whole establishment.
pub struct PairingAuthority<'s, S: Sealer, B: BlobStorage> {
    store: &'s mut ContactStore<S, B>,
    mode: SessionMode,
    origin: TrustOrigin,
    pairing_id: [u8; 16],
    expires_at: UnixTime,
    side: Side,
    /// Trusted wall-clock time of the peer confirmation, used to prune the
    /// burned ledger at the journal.
    confirmed_at: Option<UnixTime>,
    outcome: Option<PairOutcome>,
}

impl<S: Sealer, B: BlobStorage> ContactStore<S, B> {
    /// Starts pairing from a scanned QR payload (§3.1): the plan for
    /// [`Session::initiate`](crate::session::Session::initiate) and the
    /// authority that pins the QR's keys and creates the contact.
    ///
    /// # Errors
    ///
    /// [`PairingError::Qr`] if the payload expired at `now`,
    /// [`PairingError::Burned`] if this store already journaled this QR
    /// (used, or interrupted after its journal, including before a
    /// restart), or [`PairingError::PairingInProgress`].
    pub fn begin_qr_pairing(
        &mut self,
        payload: &QrPayload,
        now: UnixTime,
    ) -> Result<(InitiatorPlan, PairingAuthority<'_, S, B>), PairingError> {
        payload.check_expiry(now)?;
        self.check_can_pair(payload.pairing_id())?;
        let plan = InitiatorPlan::qr(
            *payload.pairing_id(),
            *payload.noise_static(),
            PairingPsk::from_bytes(payload.psk().clone()),
        );
        let authority = PairingAuthority {
            store: self,
            mode: SessionMode::Qr,
            origin: TrustOrigin::QrPairing,
            pairing_id: *payload.pairing_id(),
            expires_at: payload.expires_at(),
            side: Side::Initiator {
                pins: Some(QrPins {
                    device: *payload.device_public(),
                    noise_static: *payload.noise_static(),
                    kem_static: Box::new(*payload.kem_static()),
                }),
            },
            confirmed_at: None,
            outcome: None,
        };
        Ok((plan, authority))
    }

    /// Starts code pairing as the entrant (§3.2) once the stream's
    /// `CodeOfferRequest`/`CodeOffer` exchange is done: the plan that runs
    /// `CPace` with `code` and the authority that creates the contact.
    pub(crate) fn begin_code_pairing(
        &mut self,
        gate: UnauditedCodePairing,
        request: CodeOfferRequest,
        offer: &CodeOffer,
        code: &HumanCode,
        now: UnixTime,
    ) -> Result<(InitiatorPlan, PairingAuthority<'_, S, B>), PairingError> {
        check_offer_expiry(offer.expires_at(), now).map_err(|error| match error {
            ExpiryError::Expired | ExpiryError::TooFar => PairingError::Expired,
        })?;
        self.check_can_pair(offer.pairing_id())?;
        let mut code_offer = [0; CODE_OFFER_TRANSCRIPT_LEN];
        code_offer[..10].copy_from_slice(&request.encode());
        code_offer[10..].copy_from_slice(&offer.encode());
        let plan = InitiatorPlan::code_pairing(gate, *offer.pairing_id(), code.clone(), code_offer);
        let authority = PairingAuthority {
            store: self,
            mode: SessionMode::Code,
            origin: TrustOrigin::CodePairing,
            pairing_id: *offer.pairing_id(),
            expires_at: offer.expires_at(),
            side: Side::Initiator { pins: None },
            confirmed_at: None,
            outcome: None,
        };
        Ok((plan, authority))
    }

    fn check_can_pair(&self, pairing_id: &[u8; 16]) -> Result<(), PairingError> {
        if self.pairing_burned(pairing_id) {
            return Err(PairingError::Burned);
        }
        if self.pairing_pending() {
            return Err(PairingError::PairingInProgress);
        }
        Ok(())
    }
}

impl OfferReservation {
    /// The responder side of a reserved QR offer: the plan for
    /// [`IncomingSession::respond`](crate::session::IncomingSession::respond)
    /// and the authority that burns the offer and creates the contact.
    ///
    /// Dropping either before the journal frees the offer again.
    ///
    /// # Errors
    ///
    /// [`PairingError::Mode`] for a code offer,
    /// [`PairingError::Burned`], or [`PairingError::PairingInProgress`].
    pub fn into_qr_responder<S: Sealer, B: BlobStorage>(
        self,
        store: &mut ContactStore<S, B>,
    ) -> Result<(ResponderPlan, PairingAuthority<'_, S, B>), PairingError> {
        let OfferSecret::Qr(psk) = self.secret() else {
            return Err(PairingError::Mode);
        };
        store.check_can_pair(self.pairing_id())?;
        let plan = ResponderPlan::qr(PairingPsk::from_bytes(Zeroizing::new(**psk)));
        let authority = PairingAuthority {
            store,
            mode: SessionMode::Qr,
            origin: TrustOrigin::QrPairing,
            pairing_id: *self.pairing_id(),
            expires_at: self.expires_at(),
            side: Side::Responder { reservation: self },
            confirmed_at: None,
            outcome: None,
        };
        Ok((plan, authority))
    }
}

impl OfferReservation {
    /// The responder side of a reserved code offer (§3.2): the plan that
    /// runs `CPace` with the offer's code, and the authority that burns the
    /// offer and creates the contact. The offer records exchanged on the
    /// stream are bound in when the plan is used with the
    /// [`IncomingSession`](crate::session::IncomingSession) that answered
    /// the request.
    ///
    /// Dropping either before the journal records a failed attempt.
    ///
    /// # Errors
    ///
    /// [`PairingError::Mode`] for a QR offer, [`PairingError::Burned`], or
    /// [`PairingError::PairingInProgress`].
    pub fn into_code_responder<S: Sealer, B: BlobStorage>(
        self,
        gate: UnauditedCodePairing,
        store: &mut ContactStore<S, B>,
    ) -> Result<(ResponderPlan, PairingAuthority<'_, S, B>), PairingError> {
        let OfferSecret::Code(code) = self.secret() else {
            return Err(PairingError::Mode);
        };
        store.check_can_pair(self.pairing_id())?;
        let plan = ResponderPlan::code_pairing(gate, code.clone());
        let authority = PairingAuthority {
            store,
            mode: SessionMode::Code,
            origin: TrustOrigin::CodePairing,
            pairing_id: *self.pairing_id(),
            expires_at: self.expires_at(),
            side: Side::Responder { reservation: self },
            confirmed_at: None,
            outcome: None,
        };
        Ok((plan, authority))
    }
}

impl<S: Sealer, B: BlobStorage> PairingAuthority<'_, S, B> {
    /// The result of the commit: a new contact, or an explicit re-pairing
    /// of a known device. `None` until the ratchet committed.
    #[must_use]
    pub fn outcome(&self) -> Option<PairOutcome> {
        self.outcome
    }

    /// The session mode this authority serves.
    #[must_use]
    pub fn mode(&self) -> SessionMode {
        self.mode
    }

    /// §1/§3: the offer must still be valid. The displayer compares its own
    /// clock with no skew; a scanner or code entrant allows the §1 skew.
    /// The displayer's offer must also still be offered: withdrawing or
    /// replacing it stops an attempt in flight.
    fn check_offer(&self, now: UnixTime) -> Result<(), SessionError> {
        if let Side::Responder { reservation } = &self.side
            && !reservation.still_offered()
        {
            return Err(SessionError::Pairing(PairingError::UnknownOffer));
        }
        let valid = match self.side {
            Side::Responder { .. } => now < self.expires_at,
            Side::Initiator { .. } => check_offer_expiry(self.expires_at, now).is_ok(),
        };
        if valid {
            Ok(())
        } else {
            Err(SessionError::Pairing(PairingError::Expired))
        }
    }

    fn device_of(pending: &PendingRatchet) -> Ed25519PublicKey {
        *pending.peer().device_public()
    }
}

fn identity_error(error: IdentityError) -> SessionError {
    match error {
        IdentityError::Storage(error) => SessionError::Storage(error),
        other => SessionError::Identity(other),
    }
}

impl<S: Sealer, B: BlobStorage> sealed::Sealed for PairingAuthority<'_, S, B> {}

impl<S: Sealer, B: BlobStorage> PeerAuthority for PairingAuthority<'_, S, B> {
    fn confirm_peer(
        &mut self,
        presented: &PeerPresentation<'_>,
    ) -> Result<VerifiedDeviceBinding, SessionError> {
        if presented.mode() != self.mode {
            return Err(SessionError::Usage);
        }
        let now = presented.now();
        self.check_offer(now)?;
        let binding = presented.binding();
        let root = Ed25519PublicKey::from_bytes(binding.body().person_root())
            .map_err(|_| identity_error(IdentityError::AuthenticationFailed))?;
        let verified = PersonIdentity::new(root)
            .verify_binding(binding, now, self.store.revocations())
            .map_err(|error| identity_error(IdentityError::Binding(error)))?;
        match &mut self.side {
            Side::Initiator { pins: Some(pins) } => {
                // §3.1: the three full keys from the QR must be exactly the
                // ones the authenticated binding certifies.
                if pins.device != *verified.device_public()
                    || pins.noise_static != *verified.noise_static()
                    || *pins.kem_static != *verified.kem_static()
                {
                    return Err(identity_error(IdentityError::AuthenticationFailed));
                }
            }
            Side::Initiator { pins: None } => {}
            Side::Responder { reservation } => reservation.authenticated(),
        }
        self.confirmed_at = Some(now);
        Ok(verified)
    }

    fn journal(&mut self, pending: &PendingRatchet) -> Result<(), SessionError> {
        let now = self.confirmed_at.ok_or(SessionError::Usage)?;
        // A new pairing ratchets from generation 0 (§4.1, §4.4).
        if pending.generation_next() != 1 {
            return Err(SessionError::RatchetUncertain);
        }
        self.store
            .check_can_pair(&self.pairing_id)
            .map_err(SessionError::Pairing)?;
        // The offer is spent from here on, even if the write fails (§3.2:
        // an uncertain pending commitment burns the offer as well). An offer
        // withdrawn since the peer was confirmed refuses the burn, and
        // nothing is journaled.
        if let Side::Responder { reservation } = &mut self.side {
            reservation.burn().map_err(SessionError::Pairing)?;
        }
        let journal = PairingJournal {
            pairing_id: self.pairing_id,
            expires_at: self.expires_at,
            origin: self.origin,
            peer: pending.peer(),
            handshake_hash: pending.handshake_hash(),
            psk_next: pending.psk_next(),
        };
        match self.store.journal_pairing(&journal, now) {
            Ok(()) => Ok(()),
            Err(ContactError::RatchetMismatch) => {
                Err(SessionError::Pairing(PairingError::PairingInProgress))
            }
            Err(error) => {
                // A failed write leaves the journal in memory and its
                // durability uncertain: undo it there so it does not block
                // later pairings, fail closed for the device, and keep the
                // burn. Refusals before any change (the ledger quota)
                // leave the store as it was.
                if self.store.pairing_pending_with(&self.pairing_id) {
                    let _ = self
                        .store
                        .abandon_pairing(&self.pairing_id, &Self::device_of(pending));
                }
                Err(SessionError::Storage(error))
            }
        }
    }

    fn commit(&mut self, pending: &PendingRatchet) -> Result<(), SessionError> {
        let now = self.confirmed_at.ok_or(SessionError::Usage)?;
        let outcome = self
            .store
            .commit_pairing(pending.peer(), pending.handshake_hash(), now)
            .map_err(|error| match error {
                ContactError::RatchetMismatch => SessionError::RatchetUncertain,
                ContactError::Binding(error) => {
                    SessionError::Identity(IdentityError::Binding(error))
                }
                other => SessionError::Storage(other),
            })?;
        self.outcome = Some(outcome);
        Ok(())
    }

    fn clear(&mut self, pending: &PendingRatchet) -> Result<(), SessionError> {
        self.store
            .clear_ratchet(&Self::device_of(pending), pending.handshake_hash())
            .map_err(|error| match error {
                ContactError::RatchetMismatch => SessionError::RatchetUncertain,
                other => SessionError::Storage(other),
            })
    }

    fn abandon(&mut self, pending: &PendingRatchet) {
        // Already burned at the journal; a withdrawn offer is gone anyway.
        if let Side::Responder { reservation } = &mut self.side {
            let _ = reservation.burn();
        }
        // The block stays in memory even if persisting it fails.
        let _ = self
            .store
            .abandon_pairing(&self.pairing_id, &Self::device_of(pending));
    }
}

impl<S: Sealer, B: BlobStorage> fmt::Debug for PairingAuthority<'_, S, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingAuthority")
            .field("mode", &self.mode)
            .field(
                "role",
                &match self.side {
                    Side::Initiator { .. } => "initiator",
                    Side::Responder { .. } => "responder",
                },
            )
            .field("expires_at", &self.expires_at)
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}
