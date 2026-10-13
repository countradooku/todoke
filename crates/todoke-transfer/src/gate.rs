//! The receiver's consent gate (§7.2, §7.3, §8): the single decision point
//! every incoming `FileKey` and `Chunk` passes before any processing.
//!
//! The gate starts closed to content ([`ConsentGate::new`]). Only
//! [`ConsentGate::open`] with an accept proof opens it, once; in the
//! engine the proof is a `todoke_crypto::consent::VerifiedAccept`, which
//! exists only after the receiver's own signed Accept for this session was
//! issued and verified. Then:
//!
//! - a key is admitted only for a file in the proof's selection, under the
//!   proof's Accept hash;
//! - content is admitted only for a selected file whose key was admitted,
//!   under the same Accept hash;
//! - after [`ConsentGate::close`] (cancel, reject, expiry, failure, end of
//!   session) nothing is admitted again.
//!
//! The gate is generic over the proof so that Kani can check these
//! properties for every proof and every sequence of operations
//! (`gate_proofs`); it contains no cryptography and no allocation beyond
//! the set of keyed files.

/// What the gate needs from an accept proof.
pub(crate) trait AcceptProof {
    /// The Accept hash every keyed or content record must name.
    fn accept_hash(&self) -> &[u8; 32];
    /// Whether regular file `file_id` is in the selection.
    fn is_selected(&self, file_id: u32) -> bool;
}

impl AcceptProof for todoke_crypto::consent::VerifiedAccept {
    fn accept_hash(&self) -> &[u8; 32] {
        Self::accept_hash(self)
    }

    fn is_selected(&self, file_id: u32) -> bool {
        self.selection().binary_search(&file_id).is_ok()
    }
}

/// Why the gate refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GateRefusal {
    /// No Accept yet: content or a key before consent (`CONSENT_REQUIRED`).
    NotAccepted,
    /// The file is not in the selection (`CONSENT_REQUIRED`).
    Unselected,
    /// The record names another Accept (`STATE`).
    WrongAccept,
    /// Content for a file whose key has not arrived (`STATE`).
    NoKey,
    /// The authorization ended (late frames are handled before the gate).
    Closed,
    /// A second Accept for the same transfer (`STATE`).
    AlreadyOpen,
}

enum GateState<P> {
    /// No Accept: nothing is admitted.
    Pending,
    /// A verified Accept: selected files may be keyed, keyed files may
    /// carry content.
    Open {
        proof: P,
        /// Files whose key was admitted, sorted.
        keyed: Vec<u32>,
    },
    /// Ended: nothing is admitted, ever again.
    Closed,
}

/// The consent gate of one incoming transfer.
pub(crate) struct ConsentGate<P> {
    state: GateState<P>,
}

impl<P: AcceptProof> ConsentGate<P> {
    /// A gate that admits nothing.
    pub(crate) const fn new() -> Self {
        Self {
            state: GateState::Pending,
        }
    }

    /// Opens the gate with a verified Accept. Only from the initial state.
    pub(crate) fn open(&mut self, proof: P) -> Result<(), GateRefusal> {
        match self.state {
            GateState::Pending => {
                self.state = GateState::Open {
                    proof,
                    keyed: Vec::new(),
                };
                Ok(())
            }
            GateState::Open { .. } => Err(GateRefusal::AlreadyOpen),
            GateState::Closed => Err(GateRefusal::Closed),
        }
    }

    /// Ends the authorization for good; returns the proof, if any, so the
    /// caller can drop it.
    pub(crate) fn close(&mut self) -> Option<P> {
        match core::mem::replace(&mut self.state, GateState::Closed) {
            GateState::Open { proof, .. } => Some(proof),
            GateState::Pending | GateState::Closed => None,
        }
    }

    /// The proof, while open.
    pub(crate) const fn proof(&self) -> Option<&P> {
        match &self.state {
            GateState::Open { proof, .. } => Some(proof),
            GateState::Pending | GateState::Closed => None,
        }
    }

    /// Whether a verified Accept opened the gate and it has not closed.
    #[cfg(any(kani, test))]
    pub(crate) const fn is_open(&self) -> bool {
        matches!(self.state, GateState::Open { .. })
    }

    fn check(&self, accept_hash: &[u8; 32], file_id: u32) -> Result<(&P, &Vec<u32>), GateRefusal> {
        match &self.state {
            GateState::Pending => Err(GateRefusal::NotAccepted),
            GateState::Closed => Err(GateRefusal::Closed),
            GateState::Open { proof, keyed } => {
                if !proof.is_selected(file_id) {
                    Err(GateRefusal::Unselected)
                } else if proof.accept_hash() != accept_hash {
                    Err(GateRefusal::WrongAccept)
                } else {
                    Ok((proof, keyed))
                }
            }
        }
    }

    /// Admits a `FileKey` for `file_id` under `accept_hash`. Returns
    /// whether the file was not keyed before (an identical retransmission
    /// is the caller's to compare, §8).
    pub(crate) fn admit_key(
        &mut self,
        accept_hash: &[u8; 32],
        file_id: u32,
    ) -> Result<bool, GateRefusal> {
        let position = {
            let (_, keyed) = self.check(accept_hash, file_id)?;
            keyed.binary_search(&file_id)
        };
        match (position, &mut self.state) {
            (Err(index), GateState::Open { keyed, .. }) => {
                keyed.insert(index, file_id);
                Ok(true)
            }
            (Ok(_), _) => Ok(false),
            // `check` succeeded, so the state is open.
            (Err(_), GateState::Pending | GateState::Closed) => Err(GateRefusal::Closed),
        }
    }

    /// Admits content for `file_id` under `accept_hash`: the file must be
    /// selected and keyed.
    pub(crate) fn admit_content(
        &self,
        accept_hash: &[u8; 32],
        file_id: u32,
    ) -> Result<(), GateRefusal> {
        let (_, keyed) = self.check(accept_hash, file_id)?;
        if keyed.binary_search(&file_id).is_ok() {
            Ok(())
        } else {
            Err(GateRefusal::NoKey)
        }
    }

    /// Whether `file_id` was keyed.
    pub(crate) fn is_keyed(&self, file_id: u32) -> bool {
        match &self.state {
            GateState::Open { keyed, .. } => keyed.binary_search(&file_id).is_ok(),
            GateState::Pending | GateState::Closed => false,
        }
    }
}
