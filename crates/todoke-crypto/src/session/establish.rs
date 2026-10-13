//! Sans-IO identity confirmation and PSK ratchet (PROTOCOL §4.3, §4.4, §11).
//!
//! After `Split` the only valid sequence is:
//!
//! ```text
//! I -> R  Identity          R verifies, then
//! R -> I  Identity          I verifies, journals (step 1), then
//! I -> R  RatchetReady      R verifies, journals (step 2), then
//! R -> I  RatchetReady      I verifies, commits (step 3), then
//! I -> R  RatchetCommit     R verifies, commits (step 4), then
//! R -> I  RatchetAck        R clears its marker once Ack is queued;
//!                           I verifies, clears its marker (step 5).
//! ```
//!
//! Anything else closes the session silently: no Error is sent before the
//! gate opens, so no failure cause is disclosed. A failure after a journal
//! makes the authority block the pairing (fail closed); a failure before it
//! leaves the old pairing usable.

use core::fmt;
use core::time::Duration;

use todoke_proto::identity::DEVICE_BINDING_LEN;
use todoke_proto::session::{ErrorCode, ErrorRecord, FrameType, Identity, Ratchet};
use zeroize::Zeroizing;

use super::authority::{PeerAuthority, PeerPresentation, PendingRatchet};
use super::engine::Entropy;
use super::handshake::Split;
use super::kdf;
use super::transport::{FrameTransport, Limits, Opened, SessionCore, SessionInfo};
use super::{ESTABLISH_TIMEOUT, LocalIdentity, Role, SessionError, WallClock};
use crate::identity::binding::CLOCK_SKEW_SECONDS;
use crate::identity::{
    Ed25519PublicKey, KeyStore, Signature, SigningDomain, VerifiedDeviceBinding,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Waiting for the peer's Identity.
    AwaitIdentity,
    /// Waiting for the peer's `RatchetReady`.
    AwaitReady,
    /// Responder: waiting for `RatchetCommit`.
    AwaitCommit,
    /// Responder: `RatchetAck` returned, not yet confirmed queued.
    AckPending,
    /// Initiator: waiting for `RatchetAck`.
    AwaitAck,
    /// The ratchet gate is open.
    Open,
    /// Failed; nothing more is accepted.
    Failed,
}

/// The establishment phase of one session.
pub(crate) struct Establishment {
    transport: FrameTransport,
    role: Role,
    mode: todoke_proto::session::SessionMode,
    generation: u64,
    psk: Zeroizing<[u8; 32]>,
    handshake_hash: [u8; 32],
    session_id: [u8; 32],
    peer_static: [u8; 32],
    phase: Phase,
    deadline: Duration,
    /// Trusted wall-clock time for binding checks and the session lifetime.
    wall: WallClock,
    peer: Option<VerifiedDeviceBinding>,
    pending: Option<PendingRatchet>,
    journaled: bool,
}

const fn state() -> SessionError {
    SessionError::Protocol(ErrorCode::STATE)
}

const fn malformed() -> SessionError {
    SessionError::Protocol(ErrorCode::MALFORMED)
}

impl Establishment {
    /// `wall` converts monotonic instants to the caller's trusted wall-clock
    /// time; peer bindings are verified, and the session lifetime computed,
    /// at the time of each step (§2).
    pub(crate) fn new(split: Split, now: Duration, wall: WallClock, limits: Limits) -> Self {
        let Split {
            transport,
            role,
            mode,
            generation,
            psk,
            handshake_hash,
            session_id,
            peer_static,
        } = split;
        Self {
            transport: FrameTransport::new(transport, now, limits),
            role,
            mode,
            generation,
            psk,
            handshake_hash,
            session_id,
            peer_static,
            phase: Phase::AwaitIdentity,
            deadline: now.saturating_add(ESTABLISH_TIMEOUT),
            wall,
            peer: None,
            pending: None,
            journaled: false,
        }
    }

    pub(crate) fn phase(&self) -> Phase {
        self.phase
    }

    /// For tests that forge records under the established keys.
    #[cfg(test)]
    pub(crate) fn transport_mut(&mut self) -> &mut FrameTransport {
        &mut self.transport
    }

    pub(crate) fn deadline(&self) -> Duration {
        self.deadline
    }

    /// The initiator speaks first: its Identity. The responder sends
    /// nothing until it verified the initiator's.
    pub(crate) fn start<K: KeyStore>(
        &mut self,
        local: &LocalIdentity<'_, K>,
        now: Duration,
    ) -> Result<Vec<Vec<u8>>, SessionError> {
        if self.role == Role::Responder {
            return Ok(Vec::new());
        }
        let result = self.identity_record(local, now);
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result.map(|record| vec![record])
    }

    fn identity_record<K: KeyStore>(
        &mut self,
        local: &LocalIdentity<'_, K>,
        now: Duration,
    ) -> Result<Vec<u8>, SessionError> {
        let identity = local.sign_identity(&self.handshake_hash, self.role)?;
        let mut records = self
            .transport
            .seal(FrameType::IDENTITY, &identity.encode(), now)?;
        records.pop().ok_or(SessionError::Usage)
    }

    fn ratchet_record(
        &mut self,
        frame_type: FrameType,
        now: Duration,
    ) -> Result<Vec<u8>, SessionError> {
        let pending = self.pending.as_ref().ok_or_else(state)?;
        let confirmation = kdf::ratchet_confirmation(
            &pending.psk_next,
            frame_type,
            self.role,
            &self.session_id,
            pending.generation_next,
        );
        let body = Ratchet::new(self.session_id, pending.generation_next, confirmation)
            .map_err(|_| state())?
            .encode();
        let mut records = self.transport.seal(frame_type, &body, now)?;
        records.pop().ok_or(SessionError::Usage)
    }

    fn verify_ratchet(&self, frame_type: FrameType, body: &[u8]) -> Result<(), SessionError> {
        let record = Ratchet::decode(body).map_err(|_| malformed())?;
        let pending = self.pending.as_ref().ok_or_else(state)?;
        if record.session_id() != &self.session_id {
            return Err(SessionError::Authentication);
        }
        // Divergent generations are reported locally only (§4.4).
        if record.generation_next() != pending.generation_next {
            return Err(SessionError::GenerationMismatch);
        }
        let expected = kdf::ratchet_confirmation(
            &pending.psk_next,
            frame_type,
            self.role.peer(),
            &self.session_id,
            pending.generation_next,
        );
        if kdf::confirmation_matches(&expected, record.confirmation()) {
            Ok(())
        } else {
            Err(SessionError::Authentication)
        }
    }

    /// §4.3: the peer's Identity proves the signing identity is bound to
    /// the Noise static key and the transcript.
    fn verify_identity<A: PeerAuthority>(
        &self,
        body: &[u8],
        now: todoke_proto::time::UnixTime,
        authority: &mut A,
    ) -> Result<VerifiedDeviceBinding, SessionError> {
        let identity = Identity::decode(body).map_err(|_| malformed())?;
        if identity.handshake_hash() != &self.handshake_hash {
            return Err(SessionError::Authentication);
        }
        let binding = identity.binding();
        if binding.body().noise_static() != &self.peer_static {
            return Err(SessionError::Authentication);
        }
        let device = Ed25519PublicKey::from_bytes(binding.body().device_public())
            .map_err(|_| SessionError::Authentication)?;
        let encoded = binding.encode();
        debug_assert_eq!(encoded.len(), DEVICE_BINDING_LEN);
        let message = kdf::identity_message(&self.handshake_hash, self.role.peer(), &encoded);
        device
            .verify(
                SigningDomain::Identity,
                &message,
                &Signature::from_bytes(*identity.signature()),
            )
            .map_err(|_| SessionError::Authentication)?;
        let verified = authority.confirm_peer(&PeerPresentation {
            mode: self.mode,
            noise_static: &self.peer_static,
            binding,
            now,
        })?;
        // The authority must confirm exactly the presented keys.
        if verified.binding() != binding {
            return Err(SessionError::Authentication);
        }
        Ok(verified)
    }

    fn begin_ratchet<A: PeerAuthority>(&mut self, authority: &mut A) -> Result<(), SessionError> {
        let peer = self.peer.clone().ok_or_else(state)?;
        // §4.4: overflow closes the session and requires a new pairing.
        let generation_next = self
            .generation
            .checked_add(1)
            .ok_or(SessionError::GenerationExhausted)?;
        let psk_next =
            kdf::psk_next(&self.handshake_hash, &self.psk).map_err(|_| SessionError::Random)?;
        let pending = PendingRatchet {
            role: self.role,
            generation_next,
            handshake_hash: self.handshake_hash,
            psk_next,
            peer,
        };
        authority.journal(&pending)?;
        self.pending = Some(pending);
        self.journaled = true;
        Ok(())
    }

    /// Handles one received record body and returns records to send.
    pub(crate) fn receive<K: KeyStore, A: PeerAuthority>(
        &mut self,
        ciphertext: &[u8],
        local: &LocalIdentity<'_, K>,
        authority: &mut A,
        now: Duration,
    ) -> Result<Vec<Vec<u8>>, SessionError> {
        if matches!(self.phase, Phase::Failed | Phase::Open | Phase::AckPending) {
            return Err(SessionError::Closed);
        }
        self.receive_inner(ciphertext, local, authority, now)
            .map_err(|error| self.failure(error, authority))
    }

    fn receive_inner<K: KeyStore, A: PeerAuthority>(
        &mut self,
        ciphertext: &[u8],
        local: &LocalIdentity<'_, K>,
        authority: &mut A,
        now: Duration,
    ) -> Result<Vec<Vec<u8>>, SessionError> {
        if now >= self.deadline {
            return Err(SessionError::Timeout);
        }
        let (frame_type, body) = match self.transport.open(ciphertext, now)? {
            Opened::Frame(frame_type, body) => (frame_type, body),
            Opened::KeyUpdated => return Err(state()),
        };
        if frame_type == FrameType::ERROR {
            // An authenticated Error closes; never answered (§12).
            let code =
                ErrorRecord::decode(&body).map_or(ErrorCode::MALFORMED, |record| record.code());
            return Err(SessionError::PeerError(code));
        }
        match (self.role, self.phase, frame_type) {
            (Role::Responder, Phase::AwaitIdentity, FrameType::IDENTITY) => {
                self.peer = Some(self.verify_identity(&body, self.wall.at(now), authority)?);
                self.phase = Phase::AwaitReady;
                Ok(vec![self.identity_record(local, now)?])
            }
            (Role::Initiator, Phase::AwaitIdentity, FrameType::IDENTITY) => {
                self.peer = Some(self.verify_identity(&body, self.wall.at(now), authority)?);
                self.begin_ratchet(authority)?;
                self.phase = Phase::AwaitReady;
                Ok(vec![self.ratchet_record(FrameType::RATCHET_READY, now)?])
            }
            (Role::Responder, Phase::AwaitReady, FrameType::RATCHET_READY) => {
                // Derive before verifying: the MAC key is psk_next. The
                // journal happens only after the MAC verified.
                let generation_next = self
                    .generation
                    .checked_add(1)
                    .ok_or(SessionError::GenerationExhausted)?;
                let psk_next = kdf::psk_next(&self.handshake_hash, &self.psk)
                    .map_err(|_| SessionError::Random)?;
                let peer = self.peer.clone().ok_or_else(state)?;
                self.pending = Some(PendingRatchet {
                    role: self.role,
                    generation_next,
                    handshake_hash: self.handshake_hash,
                    psk_next,
                    peer,
                });
                self.verify_ratchet(FrameType::RATCHET_READY, &body)?;
                if let Some(pending) = self.pending.as_ref() {
                    authority.journal(pending)?;
                }
                self.journaled = true;
                self.phase = Phase::AwaitCommit;
                Ok(vec![self.ratchet_record(FrameType::RATCHET_READY, now)?])
            }
            (Role::Initiator, Phase::AwaitReady, FrameType::RATCHET_READY) => {
                self.verify_ratchet(FrameType::RATCHET_READY, &body)?;
                authority.commit(self.pending.as_ref().ok_or_else(state)?)?;
                self.phase = Phase::AwaitAck;
                Ok(vec![self.ratchet_record(FrameType::RATCHET_COMMIT, now)?])
            }
            (Role::Responder, Phase::AwaitCommit, FrameType::RATCHET_COMMIT) => {
                self.verify_ratchet(FrameType::RATCHET_COMMIT, &body)?;
                authority.commit(self.pending.as_ref().ok_or_else(state)?)?;
                self.phase = Phase::AckPending;
                Ok(vec![self.ratchet_record(FrameType::RATCHET_ACK, now)?])
            }
            (Role::Initiator, Phase::AwaitAck, FrameType::RATCHET_ACK) => {
                self.verify_ratchet(FrameType::RATCHET_ACK, &body)?;
                authority.clear(self.pending.as_ref().ok_or_else(state)?)?;
                self.phase = Phase::Open;
                Ok(Vec::new())
            }
            _ => Err(state()),
        }
    }

    /// Fails the establishment with [`SessionError::Timeout`] if the §13
    /// deadline passed. The adapter calls this with a fresh clock reading
    /// after every step that may have run authority I/O (journal, commit,
    /// clear) and before sending what that step produced: durable I/O
    /// counts against the 10-second budget, and an overdue step must not be
    /// followed by the next ratchet record.
    pub(crate) fn check_deadline<A: PeerAuthority>(
        &mut self,
        now: Duration,
        authority: &mut A,
    ) -> Result<(), SessionError> {
        if now >= self.deadline {
            return Err(self.failure(SessionError::Timeout, authority));
        }
        Ok(())
    }

    /// Responder step 4: `RatchetAck` was written to the pipe; clear the
    /// marker and open the gate (§4.4).
    pub(crate) fn ack_queued<A: PeerAuthority>(
        &mut self,
        authority: &mut A,
    ) -> Result<(), SessionError> {
        if self.phase != Phase::AckPending {
            return Err(state());
        }
        let result = authority.clear(self.pending.as_ref().ok_or_else(state)?);
        match result {
            Ok(()) => {
                self.phase = Phase::Open;
                Ok(())
            }
            Err(error) => Err(self.failure(error, authority)),
        }
    }

    /// Fails the establishment with `error`. After a journal the authority
    /// blocks the pairing and the result is [`SessionError::RatchetUncertain`]
    /// whatever the cause, since only re-pairing recovers (§4.4). Before it,
    /// the old pairing stays usable and `error` is returned unchanged.
    pub(crate) fn failure<A: PeerAuthority>(
        &mut self,
        error: SessionError,
        authority: &mut A,
    ) -> SessionError {
        if self.phase == Phase::Open {
            return error;
        }
        let first = self.phase != Phase::Failed;
        self.phase = Phase::Failed;
        self.transport.close();
        if !self.journaled {
            return error;
        }
        if first && let Some(pending) = self.pending.as_ref() {
            authority.abandon(pending);
        }
        SessionError::RatchetUncertain
    }

    /// The established session once the gate is open.
    pub(crate) fn into_core<K: KeyStore>(
        self,
        local: &LocalIdentity<'_, K>,
        entropy: Entropy,
        now: Duration,
    ) -> Result<SessionCore, SessionError> {
        if self.phase != Phase::Open {
            return Err(state());
        }
        let peer = self.peer.ok_or_else(state)?;
        // §2: an active session closes when either binding expires,
        // measured from the current trusted time.
        let wall = self.wall.at(now).seconds();
        let expiry = |binding: &VerifiedDeviceBinding| {
            binding
                .binding()
                .body()
                .not_after()
                .seconds()
                .saturating_add(CLOCK_SKEW_SECONDS)
                .saturating_sub(wall)
        };
        let lifetime = Duration::from_secs(expiry(&peer).min(expiry(local.binding())));
        let info = SessionInfo {
            role: self.role,
            mode: self.mode,
            handshake_hash: self.handshake_hash,
            session_id: self.session_id,
            peer_static: self.peer_static,
            peer_binding: peer,
            local_device: *local.binding().device_public(),
            established_at: self.wall.at(now),
        };
        Ok(SessionCore::new(
            self.transport,
            info,
            entropy,
            now,
            lifetime,
        ))
    }
}

impl fmt::Debug for Establishment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Establishment")
            .field("role", &self.role)
            .field("mode", &self.mode)
            .field("phase", &self.phase)
            .field("journaled", &self.journaled)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
