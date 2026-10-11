//! Hybrid Noise sessions for suite 0x0001 (PROTOCOL §4, §5, §12, §13).
//!
//! **Not production-enabled.** PROTOCOL §16 keeps suite 0x0001 disabled for
//! production until the secret-lifecycle (O6) and independent
//! interoperability (O10) gates close. Every entry point takes an
//! [`UnauditedSuite0001`] acknowledgement so that enabling it is a visible,
//! reviewable decision; see `docs/adr/0001-noise-crate.md`.
//!
//! # Layers
//!
//! | Layer | What it does | Spec |
//! | --- | --- | --- |
//! | Engine (private) | Snow's reviewed HFS+PSK state machine over libcrux X25519, ML-KEM-768, ChaCha20-Poly1305, SHA-256 | §4.2 |
//! | Handshake (private, sans-IO) | Prelude records, Hellos, exact `NoiseHandshake` sizes and order, prologue, deadlines | §4.1, §4.2.5–§4.2.6, §13 |
//! | Establishment (private, sans-IO) | `Identity` both ways, then the `RatchetReady`/`Commit`/`Ack` transaction with a durable journal | §4.3, §4.4 |
//! | Transport (private, sans-IO) | Length-prefixed frames, byte/time rekey with `KeyUpdate`, keepalive, Error handling | §5, §12, §13 |
//! | [`Session`] / [`IncomingSession`] | Thin adapter over any `futures-io` `AsyncRead + AsyncWrite` and a caller-supplied [`Timer`] | — |
//!
//! The sans-IO layers take complete records and return records to send, so
//! they can be tested and fuzzed without I/O.
//!
//! # Trust and consent
//!
//! A [`Session`] exists only after the Noise handshake, mutual `Identity`
//! proofs, local identity policy ([`PeerAuthority`]), and a committed PSK
//! ratchet. That is peer authentication only: it is not consent to receive
//! anything (§7). Transfers are not implemented here.
//!
//! # Secrets
//!
//! PSKs, static and ephemeral keys, and decrypted frames live in
//! `Zeroizing` buffers and appear in no `Debug` output or error. Snow 0.10.0
//! keeps its own copies of the chaining key, PSK, and some HKDF/HMAC and DH
//! temporaries without zeroizing them, and libcrux leaves some stack
//! temporaries; these residues are recorded under O6 in the ADR and are one
//! reason this suite stays gated.

mod authority;
mod engine;
mod establish;
mod handshake;
mod io;
mod kdf;
mod keys;
mod transport;

use core::fmt;

use todoke_proto::time::UnixTime;

use crate::identity::binding::check_validity;
use crate::identity::contacts::Unavailable;
use crate::identity::{
    ContactError, IdentityError, KeyId, KeyStore, KeyStoreError, VerifiedDeviceBinding,
};

pub use authority::{ContactAuthority, PeerAuthority, PeerPresentation, PendingRatchet};
pub use handshake::{CodeTranscript, InitiatorPlan, ResponderPlan};
pub use io::{IncomingSession, Session, Timer};
pub use keys::{InvalidNoiseKey, NoiseStaticKey, PairingPsk};
pub use todoke_proto::session::{
    ErrorCode, ErrorRecord, ErrorScope, FrameClass, FrameType, Hello, SessionMode,
};
pub use transport::{
    BYTE_BUDGET, Frame, IDLE_TIMEOUT, LOCAL_REKEY_INTERVAL, MAX_KEY_AGE, MAX_SESSION_DURATION,
    MIN_REKEY_INTERVAL, PING_AFTER, PONG_TIMEOUT,
};

pub(crate) use kdf::session_id;

/// Handshake deadline: 30 seconds from `ClientHello` (§13).
pub const HANDSHAKE_TIMEOUT: core::time::Duration = core::time::Duration::from_secs(30);
/// Identity and ratchet deadline: 10 seconds after `Split`, durable I/O
/// included (§13).
pub const ESTABLISH_TIMEOUT: core::time::Duration = core::time::Duration::from_secs(10);

/// Acknowledgement that suite 0x0001 is not production-ready (§16: gates O6
/// and O10 are open). Required by every session entry point.
///
/// Holding one is a statement by the caller that it is running tests,
/// fixtures, or an explicitly unaudited experiment, not a release build. No
/// production code path in this repository constructs it; doing so is the
/// decision the ADR describes and needs maintainer review.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnauditedSuite0001(());

impl UnauditedSuite0001 {
    /// Acknowledges that the hybrid suite, its ML-KEM backend, and this
    /// integration are unaudited and that PROTOCOL §16 keeps them disabled
    /// for production.
    #[must_use]
    pub const fn acknowledge_not_production_ready() -> Self {
        Self(())
    }
}

/// Handshake role (§4). Transfer sender/receiver roles are independent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// Sends `ClientHello` and the first Noise message.
    Initiator,
    /// Answers with `ServerHello`.
    Responder,
}

impl Role {
    /// The role byte used in signatures and MACs: 0 initiator, 1 responder.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Initiator => 0,
            Self::Responder => 1,
        }
    }

    /// The other role.
    #[must_use]
    pub const fn peer(self) -> Self {
        match self {
            Self::Initiator => Self::Responder,
            Self::Responder => Self::Initiator,
        }
    }
}

/// Why a session failed or closed. Carries no key material, peer bytes, or
/// contact details; what may be sent to the peer is decided separately
/// (§12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionError {
    /// The peer did not authenticate: the Noise handshake, a transport
    /// decryption, the `Identity` signature, or a ratchet confirmation
    /// failed. Deliberately without detail (§4.2.6).
    Authentication,
    /// Local identity policy rejected the authenticated peer (§4.3).
    Identity(IdentityError),
    /// The peer sent a malformed, unexpected, or unsupported record. The
    /// code is what this side reported, if it could (§12).
    Protocol(ErrorCode),
    /// The peer closed the session with a session-scoped `Error`.
    PeerError(ErrorCode),
    /// The Hello generation differs from the stored one (divergent
    /// generations, §4.1, §4.4). Reported locally only; nothing is retried.
    GenerationMismatch,
    /// The pair generation cannot be incremented; a new pairing is required.
    GenerationExhausted,
    /// The ratchet failed after journaling. The pairing is blocked until
    /// explicit re-pairing (§4.4).
    RatchetUncertain,
    /// The contact cannot be used for a session now.
    Unavailable(Unavailable),
    /// A §13 deadline passed.
    Timeout,
    /// The session is closed: after an earlier failure, an interrupted
    /// write, or the peer closing the stream.
    Closed,
    /// The byte pipe failed.
    Io(std::io::ErrorKind),
    /// The local key, binding, and Noise static key do not belong together,
    /// or the local binding is not currently valid (§2).
    LocalIdentity,
    /// The key store could not sign.
    KeyStore(KeyStoreError),
    /// Local persistence failed.
    Storage(ContactError),
    /// OS randomness was unavailable.
    Random,
    /// The caller asked for something this layer does not permit: a plan for
    /// another mode, a session-layer frame type, or a body over its limit.
    Usage,
    /// An explicit rekey was requested less than one second after the last
    /// one (§5).
    RekeyTooSoon,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authentication => f.write_str("peer authentication failed"),
            Self::Identity(error) => write!(f, "peer identity rejected: {error}"),
            Self::Protocol(code) => write!(f, "protocol violation ({:#06x})", code.get()),
            Self::PeerError(code) => write!(f, "peer closed the session ({:#06x})", code.get()),
            Self::GenerationMismatch => f.write_str("pair generation differs from the peer's"),
            Self::GenerationExhausted => f.write_str("pair generation exhausted; re-pair"),
            Self::RatchetUncertain => f.write_str("ratchet interrupted; re-pair"),
            Self::Unavailable(reason) => write!(f, "contact unavailable: {reason:?}"),
            Self::Timeout => f.write_str("session deadline passed"),
            Self::Closed => f.write_str("session closed"),
            Self::Io(kind) => write!(f, "transport I/O error: {kind}"),
            Self::LocalIdentity => f.write_str("local identity is inconsistent or not valid now"),
            Self::KeyStore(error) => write!(f, "key store: {error}"),
            Self::Storage(error) => write!(f, "{error}"),
            Self::Random => f.write_str("randomness unavailable"),
            Self::Usage => f.write_str("operation not permitted by the session layer"),
            Self::RekeyTooSoon => f.write_str("rekey requested too soon"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<engine::NoiseError> for SessionError {
    fn from(error: engine::NoiseError) -> Self {
        match error {
            engine::NoiseError::Authentication => Self::Authentication,
            engine::NoiseError::Random => Self::Random,
            engine::NoiseError::State => Self::Protocol(ErrorCode::STATE),
        }
    }
}

/// This device's identity for one session: the key store holding its
/// device signing key, its verified binding, its Noise static key, and the
/// trusted wall-clock time at session start.
pub struct LocalIdentity<'a, K: KeyStore> {
    key_store: &'a K,
    device_key: KeyId,
    binding: &'a VerifiedDeviceBinding,
    noise_static: &'a NoiseStaticKey,
    now: UnixTime,
}

impl<'a, K: KeyStore> LocalIdentity<'a, K> {
    /// Checks that `device_key` is the binding's device key, that the
    /// binding certifies `noise_static`, and that the binding is valid at
    /// `now` (§2: expired or future bindings must not start a session).
    ///
    /// `now` must come from a trusted clock; an unknown or regressed clock
    /// requires local confirmation instead (§1).
    ///
    /// # Errors
    ///
    /// [`SessionError::LocalIdentity`] or [`SessionError::KeyStore`].
    pub fn new(
        key_store: &'a K,
        device_key: KeyId,
        binding: &'a VerifiedDeviceBinding,
        noise_static: &'a NoiseStaticKey,
        now: UnixTime,
    ) -> Result<Self, SessionError> {
        let public = key_store
            .public_key(&device_key)
            .map_err(SessionError::KeyStore)?;
        if public != *binding.device_public()
            || noise_static.public_key() != binding.noise_static()
            || check_validity(binding.binding().body(), now).is_err()
        {
            return Err(SessionError::LocalIdentity);
        }
        Ok(Self {
            key_store,
            device_key,
            binding,
            noise_static,
            now,
        })
    }

    /// The wall-clock time this identity was checked at.
    #[must_use]
    pub fn now(&self) -> UnixTime {
        self.now
    }

    pub(crate) fn binding(&self) -> &VerifiedDeviceBinding {
        self.binding
    }

    pub(crate) fn noise_static(&self) -> &NoiseStaticKey {
        self.noise_static
    }

    pub(crate) fn sign_identity(
        &self,
        handshake_hash: &[u8; 32],
        role: Role,
    ) -> Result<todoke_proto::session::Identity, SessionError> {
        let encoded = self.binding.encode();
        let message = kdf::identity_message(handshake_hash, role, &encoded);
        let signature = self
            .key_store
            .sign(
                &self.device_key,
                crate::identity::SigningDomain::Identity,
                &message,
            )
            .map_err(SessionError::KeyStore)?;
        Ok(todoke_proto::session::Identity::new(
            self.binding.binding().clone(),
            *handshake_hash,
            signature.to_bytes(),
        ))
    }
}

impl<K: KeyStore> fmt::Debug for LocalIdentity<'_, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalIdentity")
            .field("device_key", &self.device_key)
            .field("device", self.binding.device_public())
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod test_vectors;
#[cfg(test)]
mod tests;
