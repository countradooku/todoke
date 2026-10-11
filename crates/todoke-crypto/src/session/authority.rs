//! Local identity policy and ratchet persistence for one session
//! (PROTOCOL §4.3, §4.4).
//!
//! [`PeerAuthority`] is sealed: only this crate implements it, because its
//! methods handle the next pair PSK. [`ContactAuthority`] serves existing
//! contacts (`KKpsk2`) from a [`ContactStore`]. QR and code pairing create a
//! new contact when their ratchet commits; that authority belongs to the
//! pairing work and is not implemented yet.

use core::fmt;

use todoke_proto::identity::DeviceBinding;
use todoke_proto::session::{Hello, SessionMode};
use todoke_proto::time::UnixTime;
use zeroize::Zeroizing;

use super::handshake::{InitiatorPlan, ResponderPlan};
use super::{Role, SessionError};
use crate::identity::contacts::ContactHandshake;
use crate::identity::{
    BlobStorage, ContactError, ContactStore, Ed25519PublicKey, IdentityError, Sealer,
    VerifiedDeviceBinding,
};

/// A peer's `Identity` after its signature over the handshake hash verified
/// under the binding's device key, and after its binding's Noise static key
/// matched the one the handshake authenticated. Built only by this crate.
pub struct PeerPresentation<'a> {
    pub(crate) mode: SessionMode,
    pub(crate) noise_static: &'a [u8; 32],
    pub(crate) binding: &'a DeviceBinding,
    pub(crate) now: UnixTime,
}

impl PeerPresentation<'_> {
    /// The session mode.
    #[must_use]
    pub fn mode(&self) -> SessionMode {
        self.mode
    }

    /// The presented binding (signatures not yet verified by its root).
    #[must_use]
    pub fn binding(&self) -> &DeviceBinding {
        self.binding
    }
}

impl fmt::Debug for PeerPresentation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerPresentation")
            .field("mode", &self.mode)
            .field("binding", self.binding.body())
            .finish_non_exhaustive()
    }
}

/// A journaled §4.4 transaction: `(generation_next, h, psk_next, peer
/// keys)`. The PSK has no accessor outside this crate.
pub struct PendingRatchet {
    pub(crate) role: Role,
    pub(crate) generation_next: u64,
    pub(crate) handshake_hash: [u8; 32],
    pub(crate) psk_next: Zeroizing<[u8; 32]>,
    pub(crate) peer: VerifiedDeviceBinding,
}

impl PendingRatchet {
    /// This side's handshake role.
    #[must_use]
    pub fn role(&self) -> Role {
        self.role
    }

    /// The generation being committed.
    #[must_use]
    pub fn generation_next(&self) -> u64 {
        self.generation_next
    }

    /// The handshake hash that identifies the transaction.
    #[must_use]
    pub fn handshake_hash(&self) -> &[u8; 32] {
        &self.handshake_hash
    }

    /// The authenticated peer.
    #[must_use]
    pub fn peer(&self) -> &VerifiedDeviceBinding {
        &self.peer
    }
}

impl fmt::Debug for PendingRatchet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingRatchet")
            .field("role", &self.role)
            .field("generation_next", &self.generation_next)
            .field("peer", self.peer.device_public())
            .finish_non_exhaustive()
    }
}

mod sealed {
    pub trait Sealed {}
}

/// Local identity policy and durable ratchet state for one session.
///
/// The establishment phase calls these in a fixed order: [`confirm_peer`]
/// once, then [`journal`] → [`commit`] → [`clear`]; [`abandon`] after any
/// failure that follows a successful [`journal`]. Every method must be
/// durable before returning `Ok` (§4.4: "durably journals", "atomically
/// commits").
///
/// [`confirm_peer`]: Self::confirm_peer
/// [`journal`]: Self::journal
/// [`commit`]: Self::commit
/// [`clear`]: Self::clear
/// [`abandon`]: Self::abandon
pub trait PeerAuthority: sealed::Sealed {
    /// §4.3: pins, revocation, and expiry for an authenticated presentation.
    ///
    /// # Errors
    ///
    /// [`SessionError::Identity`] or a storage error.
    fn confirm_peer(
        &mut self,
        presented: &PeerPresentation<'_>,
    ) -> Result<VerifiedDeviceBinding, SessionError>;

    /// §4.4 steps 1–2: durably journal the pending state and disable
    /// concurrent sessions.
    ///
    /// # Errors
    ///
    /// A storage or state error; the session then closes.
    fn journal(&mut self, pending: &PendingRatchet) -> Result<(), SessionError>;

    /// §4.4 steps 3–4: atomically replace the pair secrets and generation,
    /// keeping the pending marker.
    ///
    /// # Errors
    ///
    /// A storage or state error; the session then closes.
    fn commit(&mut self, pending: &PendingRatchet) -> Result<(), SessionError>;

    /// §4.4 steps 4–5: durably clear the pending marker.
    ///
    /// # Errors
    ///
    /// A storage or state error; the session then closes.
    fn clear(&mut self, pending: &PendingRatchet) -> Result<(), SessionError>;

    /// The transaction failed after [`Self::journal`]: block the pairing
    /// until explicit re-pairing. Best effort; must not restore an old PSK.
    fn abandon(&mut self, pending: &PendingRatchet);
}

/// The [`PeerAuthority`] of an existing contact (`KKpsk2`), backed by a
/// [`ContactStore`].
pub struct ContactAuthority<'s, S: Sealer, B: BlobStorage> {
    store: &'s mut ContactStore<S, B>,
    device: Ed25519PublicKey,
}

impl<S: Sealer, B: BlobStorage> ContactStore<S, B> {
    /// The session authority for `device`, which must be available
    /// ([`Self::availability`]).
    ///
    /// # Errors
    ///
    /// [`SessionError::Unavailable`] or [`SessionError::Storage`] for an
    /// unknown contact.
    pub fn session_authority(
        &mut self,
        device: &Ed25519PublicKey,
    ) -> Result<ContactAuthority<'_, S, B>, SessionError> {
        self.availability(device)
            .map_err(SessionError::Storage)?
            .map_err(SessionError::Unavailable)?;
        Ok(ContactAuthority {
            store: self,
            device: *device,
        })
    }
}

impl<S: Sealer, B: BlobStorage> ContactAuthority<'_, S, B> {
    /// The pinned device this authority confirms.
    #[must_use]
    pub fn device(&self) -> &Ed25519PublicKey {
        &self.device
    }

    /// An initiator plan with the stored PSK, generation, and pinned Noise
    /// static key. `locator` is the contact rendezvous-token prefix (§9),
    /// computed by the discovery layer.
    ///
    /// # Errors
    ///
    /// [`SessionError::Unavailable`] or [`SessionError::Storage`].
    pub fn initiator_plan(&self, locator: [u8; 16]) -> Result<InitiatorPlan, SessionError> {
        let inputs = self.inputs()?;
        Ok(InitiatorPlan::contact(
            inputs.generation,
            locator,
            inputs.psk,
            inputs.noise_static,
        ))
    }

    /// A responder plan for `hello`, which the caller resolved to this
    /// contact through its locator.
    ///
    /// # Errors
    ///
    /// [`SessionError::Usage`] for another mode,
    /// [`SessionError::GenerationMismatch`] when the Hello's generation
    /// differs from the stored one (reported locally only, §4.4), or
    /// [`SessionError::Unavailable`].
    pub fn responder_plan(&self, hello: &Hello) -> Result<ResponderPlan, SessionError> {
        if hello.mode() != SessionMode::Contact {
            return Err(SessionError::Usage);
        }
        let inputs = self.inputs()?;
        if hello.generation() != inputs.generation {
            return Err(SessionError::GenerationMismatch);
        }
        Ok(ResponderPlan::contact(
            inputs.generation,
            inputs.psk,
            inputs.noise_static,
        ))
    }

    fn inputs(&self) -> Result<ContactHandshake, SessionError> {
        self.store
            .availability(&self.device)
            .map_err(SessionError::Storage)?
            .map_err(SessionError::Unavailable)?;
        self.store
            .handshake_inputs(&self.device)
            .map_err(SessionError::Storage)
    }

    fn ratchet_error(error: ContactError) -> SessionError {
        match error {
            ContactError::RatchetMismatch => SessionError::RatchetUncertain,
            other => SessionError::Storage(other),
        }
    }
}

impl<S: Sealer, B: BlobStorage> sealed::Sealed for ContactAuthority<'_, S, B> {}

impl<S: Sealer, B: BlobStorage> PeerAuthority for ContactAuthority<'_, S, B> {
    fn confirm_peer(
        &mut self,
        presented: &PeerPresentation<'_>,
    ) -> Result<VerifiedDeviceBinding, SessionError> {
        if presented.mode != SessionMode::Contact {
            return Err(SessionError::Usage);
        }
        self.store
            .confirm_identity(
                &self.device,
                presented.noise_static,
                presented.binding,
                presented.now,
            )
            .map_err(|error| match error {
                IdentityError::Storage(error) => SessionError::Storage(error),
                other => SessionError::Identity(other),
            })
    }

    fn journal(&mut self, pending: &PendingRatchet) -> Result<(), SessionError> {
        self.store
            .journal_ratchet(
                &self.device,
                pending.generation_next,
                &pending.handshake_hash,
                &pending.psk_next,
            )
            .map_err(Self::ratchet_error)
    }

    fn commit(&mut self, pending: &PendingRatchet) -> Result<(), SessionError> {
        self.store
            .commit_ratchet(&self.device, &pending.handshake_hash)
            .map_err(Self::ratchet_error)
    }

    fn clear(&mut self, pending: &PendingRatchet) -> Result<(), SessionError> {
        self.store
            .clear_ratchet(&self.device, &pending.handshake_hash)
            .map_err(Self::ratchet_error)
    }

    fn abandon(&mut self, _pending: &PendingRatchet) {
        // The block stays in memory even if persisting it fails.
        let _ = self.store.abandon_ratchet(&self.device);
    }
}

impl<S: Sealer, B: BlobStorage> fmt::Debug for ContactAuthority<'_, S, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContactAuthority")
            .field("device", &self.device)
            .finish_non_exhaustive()
    }
}

/// A pairing-mode authority for tests: no stored contact, an optional pin
/// of the peer's full keys, and an in-memory journal with failure injection.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::identity::{Ed25519PublicKey, PersonIdentity, RevocationSet};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Journal {
        Clean,
        Journaled,
        Committed,
        Cleared,
        Abandoned,
    }

    #[derive(Debug)]
    pub(crate) struct PairingAuthority {
        pub(crate) pinned_device: Option<Ed25519PublicKey>,
        pub(crate) journal: Journal,
        pub(crate) committed_psk: Option<Zeroizing<[u8; 32]>>,
        pub(crate) committed_generation: Option<u64>,
        /// Fail the step with this index (0 confirm, 1 journal, 2 commit,
        /// 3 clear) with a storage error.
        pub(crate) fail_step: Option<u8>,
    }

    impl PairingAuthority {
        pub(crate) fn new(pinned_device: Option<Ed25519PublicKey>) -> Self {
            Self {
                pinned_device,
                journal: Journal::Clean,
                committed_psk: None,
                committed_generation: None,
                fail_step: None,
            }
        }

        fn step(&self, index: u8) -> Result<(), SessionError> {
            if self.fail_step == Some(index) {
                Err(SessionError::Storage(ContactError::Storage(
                    crate::identity::storage::StorageError::Io(std::io::ErrorKind::Other),
                )))
            } else {
                Ok(())
            }
        }
    }

    impl sealed::Sealed for PairingAuthority {}

    impl PeerAuthority for PairingAuthority {
        fn confirm_peer(
            &mut self,
            presented: &PeerPresentation<'_>,
        ) -> Result<VerifiedDeviceBinding, SessionError> {
            self.step(0)?;
            // Trust in the root comes from the authenticated pairing itself
            // (§2); the binding must still verify under the root it names.
            let root = Ed25519PublicKey::from_bytes(presented.binding.body().person_root())
                .map_err(|_| SessionError::Identity(IdentityError::AuthenticationFailed))?;
            let verified = PersonIdentity::new(root)
                .verify_binding(presented.binding, presented.now, &RevocationSet::new())
                .map_err(|error| SessionError::Identity(IdentityError::Binding(error)))?;
            if self
                .pinned_device
                .is_some_and(|pinned| pinned != *verified.device_public())
            {
                return Err(SessionError::Identity(IdentityError::AuthenticationFailed));
            }
            Ok(verified)
        }

        fn journal(&mut self, _pending: &PendingRatchet) -> Result<(), SessionError> {
            self.step(1)?;
            if self.journal != Journal::Clean {
                return Err(SessionError::RatchetUncertain);
            }
            self.journal = Journal::Journaled;
            Ok(())
        }

        fn commit(&mut self, pending: &PendingRatchet) -> Result<(), SessionError> {
            self.step(2)?;
            if self.journal != Journal::Journaled {
                return Err(SessionError::RatchetUncertain);
            }
            self.journal = Journal::Committed;
            self.committed_psk = Some(Zeroizing::new(*pending.psk_next));
            self.committed_generation = Some(pending.generation_next);
            Ok(())
        }

        fn clear(&mut self, _pending: &PendingRatchet) -> Result<(), SessionError> {
            self.step(3)?;
            if self.journal != Journal::Committed {
                return Err(SessionError::RatchetUncertain);
            }
            self.journal = Journal::Cleared;
            Ok(())
        }

        fn abandon(&mut self, _pending: &PendingRatchet) {
            self.journal = Journal::Abandoned;
        }
    }
}
