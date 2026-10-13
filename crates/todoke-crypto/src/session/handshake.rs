//! Sans-IO prelude and Noise handshake (PROTOCOL §4.1, §4.2, §13).
//!
//! The driver consumes complete prelude records (`kind || body`, after the
//! length prefix was validated) and returns complete records to send,
//! prefix included. It enforces the expected kind, sender role, message
//! index, and exact size before Noise sees any byte, builds the exact
//! prologue, and stops at the first failure: no retry, fallback, or second
//! attempt with the same ephemeral material (§4.2.6).

use core::fmt;
use core::time::Duration;

use todoke_proto::pairing::{CodeRole, CodeShare};
use todoke_proto::session::{
    Hello, NoiseHandshakeRecord, PreludeKind, PreludeRecord, SessionMode, encode_prelude_record,
};
use zeroize::Zeroizing;

use super::engine::{Entropy, HandshakeInputs, NoiseHandshake, NoiseTransport, Pattern};
use super::keys::{NoiseStaticKey, PairingPsk};
use super::{ErrorCode, HANDSHAKE_TIMEOUT, Role, SessionError, UnauditedSuite0001};
use crate::pairing::cpace::{self, CpaceError};
use crate::pairing::transcript::{self, AD_A, AD_B};
use crate::pairing::{HumanCode, PairingError, UnauditedCodePairing};

const PROLOGUE_DOMAIN: &[u8] = b"todoke/v1/noise-prologue\0";
/// §13: at most 16 Noise records and 64 KiB of prelude per attempt.
const MAX_NOISE_RECORDS: usize = 16;
const MAX_PRELUDE_BYTES: usize = 64 * 1024;
/// `CodeOfferRequest || CodeOffer` bodies (§3.2).
pub(crate) const CODE_OFFER_LEN: usize = 10 + 34;
/// `CodeShareA` / `CodeShareB` body (§3.2).
pub(crate) const CODE_SHARE_LEN: usize = 49;

/// The public code-pairing records that §3.2 binds into the XX prologue:
/// `code_offer = CodeOfferRequest || CodeOffer` and both `CPace` shares.
///
/// They enter the prologue `code_offer || ClientHello || ServerHello ||
/// CodeShareA || CodeShareB`. Real code pairing builds this after the
/// `CPace` exchange; tests and fuzzing may supply a synthetic one.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CodeTranscript {
    code_offer: [u8; CODE_OFFER_LEN],
    share_a: [u8; CODE_SHARE_LEN],
    share_b: [u8; CODE_SHARE_LEN],
}

impl CodeTranscript {
    /// Wraps the exact public bodies.
    #[cfg(any(test, all(fuzzing, feature = "unaudited-suite-0001")))]
    #[must_use]
    pub(crate) fn new(
        code_offer: [u8; CODE_OFFER_LEN],
        share_a: [u8; CODE_SHARE_LEN],
        share_b: [u8; CODE_SHARE_LEN],
    ) -> Self {
        Self {
            code_offer,
            share_a,
            share_b,
        }
    }
}

impl fmt::Debug for CodeTranscript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CodeTranscript { .. }")
    }
}

/// The secret a plan authenticates with.
enum PlanSecret {
    /// A PSK known before the handshake: QR, contact, or (tests and
    /// fuzzing) a synthetic code transcript.
    Psk {
        psk: PairingPsk,
        code: Option<CodeTranscript>,
    },
    /// Human-code pairing: the code and, once exchanged, the public offer
    /// records. The PSK comes from `CPace` (§3.2).
    Code {
        code: HumanCode,
        code_offer: Option<[u8; CODE_OFFER_LEN]>,
    },
}

impl PlanSecret {
    fn psk(psk: PairingPsk) -> Self {
        Self::Psk { psk, code: None }
    }
}

/// What the initiator needs before sending `ClientHello`. `Debug` omits
/// the locator (§14.2: contact tokens are not logged) and the keys.
///
/// Only authorities build plans: [`ContactAuthority::initiator_plan`](crate::session::ContactAuthority::initiator_plan)
/// and [`ContactStore::begin_qr_pairing`](crate::identity::ContactStore::begin_qr_pairing)
/// (and, for code pairing, [`Session::initiate_code_pairing`](crate::session::Session::initiate_code_pairing)).
pub struct InitiatorPlan {
    mode: SessionMode,
    generation: u64,
    locator: [u8; 16],
    secret: PlanSecret,
    remote_static: Option<[u8; 32]>,
}

impl InitiatorPlan {
    /// QR pairing (`IKpsk2`): the scanner pins the responder's Noise static
    /// key from the QR payload and uses its one-time PSK (§3.1).
    #[must_use]
    pub(crate) fn qr(
        pairing_id: [u8; 16],
        responder_noise_static: [u8; 32],
        psk: PairingPsk,
    ) -> Self {
        Self {
            mode: SessionMode::Qr,
            generation: 0,
            locator: pairing_id,
            secret: PlanSecret::psk(psk),
            remote_static: Some(responder_noise_static),
        }
    }

    /// Human-code pairing (`CPace`, then `XXpsk3`, §3.2) for the offer
    /// `code_offer = CodeOfferRequest || CodeOffer` exchanged on this
    /// stream.
    pub(crate) fn code_pairing(
        _gate: UnauditedCodePairing,
        pairing_id: [u8; 16],
        code: HumanCode,
        code_offer: [u8; CODE_OFFER_LEN],
    ) -> Self {
        Self {
            mode: SessionMode::Code,
            generation: 0,
            locator: pairing_id,
            secret: PlanSecret::Code {
                code,
                code_offer: Some(code_offer),
            },
            remote_static: None,
        }
    }

    /// Code-mode handshake with a caller-chosen PSK and transcript, for the
    /// public `XXpsk3` fixture and handshake tests only: real code pairing
    /// derives both from `CPace` (§3.2).
    #[cfg(any(test, all(fuzzing, feature = "unaudited-suite-0001")))]
    #[must_use]
    pub(crate) fn code_with_psk(
        pairing_id: [u8; 16],
        psk: PairingPsk,
        transcript: CodeTranscript,
    ) -> Self {
        Self {
            mode: SessionMode::Code,
            generation: 0,
            locator: pairing_id,
            secret: PlanSecret::Psk {
                psk,
                code: Some(transcript),
            },
            remote_static: None,
        }
    }

    pub(crate) fn contact(
        generation: u64,
        locator: [u8; 16],
        psk: Zeroizing<[u8; 32]>,
        remote_static: [u8; 32],
    ) -> Self {
        Self {
            mode: SessionMode::Contact,
            generation,
            locator,
            secret: PlanSecret::psk(PairingPsk(psk)),
            remote_static: Some(remote_static),
        }
    }

    /// The mode this plan starts.
    #[must_use]
    pub fn mode(&self) -> SessionMode {
        self.mode
    }
}

/// What the responder needs after reading `ClientHello`. `Debug` omits
/// the keys.
///
/// Only authorities build plans: [`ContactAuthority::responder_plan`](crate::session::ContactAuthority::responder_plan)
/// and [`OfferReservation::into_qr_responder`](crate::pairing::OfferReservation::into_qr_responder)
/// or [`OfferReservation::into_code_responder`](crate::pairing::OfferReservation::into_code_responder).
pub struct ResponderPlan {
    mode: SessionMode,
    generation: u64,
    secret: PlanSecret,
    remote_static: Option<[u8; 32]>,
}

impl ResponderPlan {
    /// QR pairing: the displayer's one-time PSK (§3.1).
    #[must_use]
    pub(crate) fn qr(psk: PairingPsk) -> Self {
        Self {
            mode: SessionMode::Qr,
            generation: 0,
            secret: PlanSecret::psk(psk),
            remote_static: None,
        }
    }

    /// Human-code pairing as the displayer. The offer records exchanged on
    /// the stream are bound in by [`Self::bind_code_offer`].
    pub(crate) fn code_pairing(_gate: UnauditedCodePairing, code: HumanCode) -> Self {
        Self {
            mode: SessionMode::Code,
            generation: 0,
            secret: PlanSecret::Code {
                code,
                code_offer: None,
            },
            remote_static: None,
        }
    }

    /// Binds `code_offer = CodeOfferRequest || CodeOffer` from this stream
    /// into a code-pairing plan.
    pub(crate) fn bind_code_offer(
        &mut self,
        offer: [u8; CODE_OFFER_LEN],
    ) -> Result<(), SessionError> {
        match &mut self.secret {
            PlanSecret::Code {
                code_offer: slot @ None,
                ..
            } => {
                *slot = Some(offer);
                Ok(())
            }
            _ => Err(SessionError::Usage),
        }
    }

    /// Whether this plan runs `CPace` (real code pairing).
    pub(crate) fn is_code_pairing(&self) -> bool {
        matches!(self.secret, PlanSecret::Code { .. })
    }

    /// See [`InitiatorPlan::code_with_psk`]: fixture and tests only.
    #[cfg(any(test, all(fuzzing, feature = "unaudited-suite-0001")))]
    #[must_use]
    pub(crate) fn code_with_psk(psk: PairingPsk, transcript: CodeTranscript) -> Self {
        Self {
            mode: SessionMode::Code,
            generation: 0,
            secret: PlanSecret::Psk {
                psk,
                code: Some(transcript),
            },
            remote_static: None,
        }
    }

    pub(crate) fn contact(
        generation: u64,
        psk: Zeroizing<[u8; 32]>,
        remote_static: [u8; 32],
    ) -> Self {
        Self {
            mode: SessionMode::Contact,
            generation,
            secret: PlanSecret::psk(PairingPsk(psk)),
            remote_static: Some(remote_static),
        }
    }

    /// The mode this plan answers.
    #[must_use]
    pub fn mode(&self) -> SessionMode {
        self.mode
    }
}

impl fmt::Debug for InitiatorPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitiatorPlan")
            .field("mode", &self.mode)
            .field("generation", &self.generation)
            .field("locator", &format_args!("[{} bytes]", self.locator.len()))
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for ResponderPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponderPlan")
            .field("mode", &self.mode)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

/// The result of a completed handshake: the transport and what the
/// establishment phase needs. The PSK is kept only for the §4.4 ratchet.
pub(crate) struct Split {
    pub(crate) transport: NoiseTransport,
    pub(crate) role: Role,
    pub(crate) mode: SessionMode,
    pub(crate) generation: u64,
    pub(crate) psk: Zeroizing<[u8; 32]>,
    pub(crate) handshake_hash: [u8; 32],
    pub(crate) session_id: [u8; 32],
    pub(crate) peer_static: [u8; 32],
}

impl fmt::Debug for Split {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Split")
            .field("role", &self.role)
            .field("mode", &self.mode)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    AwaitServerHello,
    /// Code pairing, initiator: `CodeShareA` sent, waiting for `CodeShareB`.
    AwaitShareB,
    /// Code pairing, responder: `ServerHello` sent, waiting for `CodeShareA`.
    AwaitShareA,
    Noise,
    Done,
    Failed,
}

/// The `CPace` part of a code-pairing attempt.
struct CpaceState {
    code: HumanCode,
    code_offer: [u8; CODE_OFFER_LEN],
    /// Initiator only, between `CodeShareA` and `CodeShareB`.
    initiator: Option<cpace::Initiator>,
    share_a: Option<[u8; CODE_SHARE_LEN]>,
}

fn cpace_error(error: CpaceError) -> SessionError {
    match error {
        // An invalid, neutral, or noncanonical element: abort without
        // detail (§3.2, §4.2.6).
        CpaceError::Abort => SessionError::Authentication,
        CpaceError::Random => SessionError::Random,
        CpaceError::Unavailable => SessionError::Pairing(PairingError::CodePairingUnavailable),
    }
}

/// Reads a `ClientHello` record (`kind || body`).
pub(crate) fn read_client_hello(record: &[u8]) -> Result<Hello, SessionError> {
    let record = PreludeRecord::decode(record).map_err(|_| malformed())?;
    if record.kind() != PreludeKind::ClientHello {
        return Err(state());
    }
    Hello::decode_client(record.body()).map_err(|_| malformed())
}

const fn malformed() -> SessionError {
    SessionError::Protocol(ErrorCode::MALFORMED)
}

const fn state() -> SessionError {
    SessionError::Protocol(ErrorCode::STATE)
}

/// A plan's PSK (if known up front), synthetic code transcript, and
/// `CPace` state.
type SecretParts = (
    Option<Zeroizing<[u8; 32]>>,
    Option<CodeTranscript>,
    Option<CpaceState>,
);

/// One handshake attempt.
pub(crate) struct HandshakeDriver {
    role: Role,
    client: Hello,
    phase: Phase,
    deadline: Duration,
    /// Known up front, or derived from `CPace` in code pairing.
    psk: Option<Zeroizing<[u8; 32]>>,
    local_static: Zeroizing<[u8; 32]>,
    remote_static: Option<[u8; 32]>,
    code: Option<CodeTranscript>,
    cpace: Option<CpaceState>,
    /// The `ServerHello`, once sent or received.
    server: Option<Hello>,
    entropy: Entropy,
    noise: Option<NoiseHandshake>,
    noise_records: usize,
    prelude_bytes: usize,
}

impl HandshakeDriver {
    /// Starts an initiator and returns the `ClientHello` record to send.
    /// `started` is the monotonic time it is sent: the 30-second handshake
    /// deadline runs from there (§13). `_gate` is the §16 acknowledgement:
    /// no Noise state for suite 0x0001 is built without one.
    pub(crate) fn initiator(
        _gate: UnauditedSuite0001,
        plan: InitiatorPlan,
        local_static: &NoiseStaticKey,
        client_nonce: [u8; 16],
        entropy: Entropy,
        started: Duration,
    ) -> Result<(Self, Vec<u8>), SessionError> {
        let client = Hello::client(plan.mode, plan.generation, plan.locator, client_nonce)
            .map_err(|_| SessionError::Usage)?;
        let record = encode_prelude_record(PreludeKind::ClientHello, &client.encode())
            .map_err(|_| SessionError::Usage)?;
        let (psk, code, cpace) = Self::split_secret(plan.secret)?;
        let driver = Self {
            role: Role::Initiator,
            client,
            phase: Phase::AwaitServerHello,
            deadline: started.saturating_add(HANDSHAKE_TIMEOUT),
            psk,
            local_static: Zeroizing::new(*local_static.secret()),
            remote_static: plan.remote_static,
            code,
            cpace,
            server: None,
            entropy,
            noise: None,
            noise_records: 0,
            prelude_bytes: record.len(),
        };
        Ok((driver, record))
    }

    /// Starts a responder for a received `ClientHello` and returns the
    /// `ServerHello` record. `started` is when `ClientHello` arrived.
    pub(crate) fn responder(
        _gate: UnauditedSuite0001,
        client: Hello,
        plan: ResponderPlan,
        local_static: &NoiseStaticKey,
        server_nonce: [u8; 16],
        entropy: Entropy,
        started: Duration,
    ) -> Result<(Self, Vec<u8>), SessionError> {
        if plan.mode != client.mode() {
            return Err(SessionError::Usage);
        }
        // §4.1: a stored contact generation that differs from the Hello is
        // reported locally; no re-pairing, older PSK, or fallback is tried.
        if plan.generation != client.generation() {
            return Err(SessionError::GenerationMismatch);
        }
        let server = client
            .server_reply(server_nonce)
            .map_err(|_| SessionError::Random)?;
        let record = encode_prelude_record(PreludeKind::ServerHello, &server.encode())
            .map_err(|_| SessionError::Usage)?;
        let (psk, code, cpace) = Self::split_secret(plan.secret)?;
        let mut driver = Self {
            role: Role::Responder,
            client,
            phase: Phase::Noise,
            deadline: started.saturating_add(HANDSHAKE_TIMEOUT),
            psk,
            local_static: Zeroizing::new(*local_static.secret()),
            remote_static: plan.remote_static,
            code,
            cpace,
            server: Some(server),
            entropy,
            noise: None,
            noise_records: 0,
            prelude_bytes: record.len(),
        };
        if driver.cpace.is_some() {
            // §3.2: the shares follow both Hellos; Noise waits for the PSK.
            driver.phase = Phase::AwaitShareA;
        } else {
            driver.start_noise(&server)?;
        }
        Ok((driver, record))
    }

    fn split_secret(secret: PlanSecret) -> Result<SecretParts, SessionError> {
        Ok(match secret {
            PlanSecret::Psk { psk, code } => (Some(psk.0), code, None),
            PlanSecret::Code { code, code_offer } => (
                None,
                None,
                Some(CpaceState {
                    code,
                    // A code plan cannot start without the offer records.
                    code_offer: code_offer.ok_or(SessionError::Usage)?,
                    initiator: None,
                    share_a: None,
                }),
            ),
        })
    }

    /// The absolute handshake deadline.
    pub(crate) fn deadline(&self) -> Duration {
        self.deadline
    }

    pub(crate) fn is_done(&self) -> bool {
        self.phase == Phase::Done
    }

    fn prologue(&self, server: &Hello) -> Result<Vec<u8>, SessionError> {
        let mut prologue = PROLOGUE_DOMAIN.to_vec();
        match (self.client.mode(), &self.code) {
            (SessionMode::Code, Some(code)) => {
                prologue.extend_from_slice(&code.code_offer);
                prologue.extend_from_slice(&self.client.encode());
                prologue.extend_from_slice(&server.encode());
                prologue.extend_from_slice(&code.share_a);
                prologue.extend_from_slice(&code.share_b);
            }
            (SessionMode::Qr | SessionMode::Contact, None) => {
                prologue.extend_from_slice(&self.client.encode());
                prologue.extend_from_slice(&server.encode());
            }
            _ => return Err(SessionError::Usage),
        }
        Ok(prologue)
    }

    fn start_noise(&mut self, server: &Hello) -> Result<(), SessionError> {
        let prologue = self.prologue(server)?;
        let psk = self.psk.as_ref().ok_or_else(state)?;
        let noise = NoiseHandshake::new(&HandshakeInputs {
            pattern: Pattern::for_mode(self.client.mode()),
            initiator: self.role == Role::Initiator,
            prologue: &prologue,
            psk,
            local_static: &self.local_static,
            remote_static: self.remote_static.as_ref(),
            entropy: self.entropy.clone(),
        })
        .map_err(|_| SessionError::Usage)?;
        self.noise = Some(noise);
        self.phase = Phase::Noise;
        Ok(())
    }

    /// Writes our next Noise message as a framed record.
    fn write_noise(&mut self) -> Result<Vec<u8>, SessionError> {
        let mode = self.client.mode();
        let noise = self.noise.as_mut().ok_or(SessionError::Usage)?;
        let index = u8::try_from(noise.next_index()).map_err(|_| SessionError::Usage)?;
        let message = noise.write_message()?;
        let record = NoiseHandshakeRecord::encode_record(mode, index, &message)
            .map_err(|_| SessionError::Usage)?;
        let finished = noise.is_finished();
        self.prelude_bytes = self.prelude_bytes.saturating_add(record.len());
        self.count_noise_record()?;
        if finished {
            self.phase = Phase::Done;
        }
        Ok(record)
    }

    fn count_noise_record(&mut self) -> Result<(), SessionError> {
        self.noise_records += 1;
        if self.noise_records > MAX_NOISE_RECORDS || self.prelude_bytes > MAX_PRELUDE_BYTES {
            return Err(SessionError::Protocol(ErrorCode::LIMIT));
        }
        Ok(())
    }

    /// Accepts one peer record (`kind || body`, the bytes counted by its
    /// validated length prefix) and returns the records to send in reply.
    /// Any error poisons the attempt.
    pub(crate) fn receive(
        &mut self,
        record: &[u8],
        now: Duration,
    ) -> Result<Vec<Vec<u8>>, SessionError> {
        let result = self.receive_inner(record, now);
        if result.is_err() {
            self.fail();
        }
        result
    }

    fn receive_inner(
        &mut self,
        record: &[u8],
        now: Duration,
    ) -> Result<Vec<Vec<u8>>, SessionError> {
        if now >= self.deadline {
            return Err(SessionError::Timeout);
        }
        let decoded = PreludeRecord::decode(record).map_err(|_| malformed())?;
        self.prelude_bytes = self.prelude_bytes.saturating_add(record.len() + 2);
        if self.prelude_bytes > MAX_PRELUDE_BYTES {
            return Err(SessionError::Protocol(ErrorCode::LIMIT));
        }
        match (self.phase, decoded.kind()) {
            (Phase::AwaitServerHello, PreludeKind::ServerHello) => {
                let server =
                    Hello::decode_server(decoded.body(), &self.client).map_err(|_| malformed())?;
                self.server = Some(server);
                if self.cpace.is_some() {
                    return Ok(vec![self.send_share_a(&server)?]);
                }
                self.start_noise(&server)?;
                Ok(vec![self.write_noise()?])
            }
            (Phase::AwaitShareB, PreludeKind::CodeShareB) => {
                let share = self.read_share(decoded.body(), CodeRole::B)?;
                self.finish_cpace_initiator(&share)?;
                let server = self.server.ok_or_else(state)?;
                self.start_noise(&server)?;
                Ok(vec![self.write_noise()?])
            }
            (Phase::AwaitShareA, PreludeKind::CodeShareA) => {
                let share = self.read_share(decoded.body(), CodeRole::A)?;
                let reply = self.respond_cpace(&share)?;
                let server = self.server.ok_or_else(state)?;
                self.start_noise(&server)?;
                Ok(vec![reply])
            }
            (Phase::Noise, PreludeKind::NoiseHandshake) => {
                let mode = self.client.mode();
                let noise_record =
                    NoiseHandshakeRecord::decode(decoded.body(), mode).map_err(|_| malformed())?;
                self.count_noise_record()?;
                let noise = self.noise.as_mut().ok_or_else(state)?;
                // Expected sender and index: strictly the next message, from
                // the peer. A replayed or reordered record is a state error.
                if noise.is_our_turn()
                    || usize::from(noise_record.message_index()) != noise.next_index()
                {
                    return Err(state());
                }
                noise.read_message(noise_record.token_bytes())?;
                if noise.is_finished() {
                    self.phase = Phase::Done;
                    return Ok(Vec::new());
                }
                Ok(vec![self.write_noise()?])
            }
            _ => Err(state()),
        }
    }

    /// §3.2: exactly the pending offer's share from the expected role;
    /// anything else aborts. Element validity is `CPace`'s check.
    fn read_share(&self, body: &[u8], role: CodeRole) -> Result<CodeShare, SessionError> {
        let share = CodeShare::decode(body).map_err(|_| malformed())?;
        if share.role() != role || share.pairing_id() != self.client.locator() {
            return Err(state());
        }
        Ok(share)
    }

    /// Initiator (party A): `Ya` from the code and the public context.
    fn send_share_a(&mut self, server: &Hello) -> Result<Vec<u8>, SessionError> {
        let state = self.cpace.as_mut().ok_or_else(state)?;
        let ci = transcript::channel_identifier(&state.code_offer, &self.client, server);
        let sid = transcript::session_identifier(server);
        let (element, initiator) =
            cpace::start(state.code.password(), &ci, &sid, AD_A, &self.entropy)
                .map_err(cpace_error)?;
        let share = CodeShare::new(*self.client.locator(), CodeRole::A, element)
            .map_err(|_| SessionError::Usage)?
            .encode();
        state.initiator = Some(initiator);
        state.share_a = Some(share);
        let record = encode_prelude_record(PreludeKind::CodeShareA, &share)
            .map_err(|_| SessionError::Usage)?;
        self.prelude_bytes = self.prelude_bytes.saturating_add(record.len());
        self.phase = Phase::AwaitShareB;
        Ok(record)
    }

    /// Initiator: the ISK from `Yb`, then the PSK and the code transcript.
    fn finish_cpace_initiator(&mut self, share_b: &CodeShare) -> Result<(), SessionError> {
        let cpace_state = self.cpace.take().ok_or_else(state)?;
        let initiator = cpace_state.initiator.ok_or_else(state)?;
        let share_a = cpace_state.share_a.ok_or_else(state)?;
        let isk = initiator
            .finish(share_b.element(), AD_B)
            .map_err(cpace_error)?;
        self.install_code_psk(&cpace_state.code_offer, share_a, share_b.encode(), &isk)
    }

    /// Responder (party B): `Yb` and the ISK from `Ya`, then the PSK and
    /// the code transcript. Returns the `CodeShareB` record.
    fn respond_cpace(&mut self, share_a: &CodeShare) -> Result<Vec<u8>, SessionError> {
        let cpace_state = self.cpace.take().ok_or_else(state)?;
        let server = self.server.ok_or_else(state)?;
        let ci = transcript::channel_identifier(&cpace_state.code_offer, &self.client, &server);
        let sid = transcript::session_identifier(&server);
        let (element, isk) = cpace::respond(
            share_a.element(),
            cpace_state.code.password(),
            &ci,
            &sid,
            AD_A,
            AD_B,
            &self.entropy,
        )
        .map_err(cpace_error)?;
        let share_b = CodeShare::new(*self.client.locator(), CodeRole::B, element)
            .map_err(|_| SessionError::Usage)?
            .encode();
        self.install_code_psk(&cpace_state.code_offer, share_a.encode(), share_b, &isk)?;
        let record = encode_prelude_record(PreludeKind::CodeShareB, &share_b)
            .map_err(|_| SessionError::Usage)?;
        self.prelude_bytes = self.prelude_bytes.saturating_add(record.len());
        Ok(record)
    }

    /// `psk = HKDF(B3(pre_noise), ISK, "todoke/v1/cpace-psk\0", 32)` and the
    /// transcript bound into the XX prologue (§3.2).
    fn install_code_psk(
        &mut self,
        code_offer: &[u8; CODE_OFFER_LEN],
        share_a: [u8; CODE_SHARE_LEN],
        share_b: [u8; CODE_SHARE_LEN],
        isk: &cpace::Isk,
    ) -> Result<(), SessionError> {
        let server = self.server.ok_or_else(state)?;
        let pre_noise =
            transcript::pre_noise(code_offer, &self.client, &server, &share_a, &share_b);
        self.psk = Some(transcript::psk(&pre_noise, isk).map_err(|_| SessionError::Random)?);
        self.code = Some(CodeTranscript {
            code_offer: *code_offer,
            share_a,
            share_b,
        });
        Ok(())
    }

    /// Poisons the attempt: the Noise and `CPace` state, and with them the
    /// ephemeral secrets, are dropped and every later call fails.
    fn fail(&mut self) {
        self.phase = Phase::Failed;
        self.noise = None;
        self.cpace = None;
    }

    /// The completed handshake. Fails unless every message was processed.
    pub(crate) fn finish(mut self) -> Result<Split, SessionError> {
        if self.phase != Phase::Done {
            return Err(state());
        }
        let noise = self.noise.take().ok_or_else(state)?;
        let transport = noise.into_transport()?;
        let handshake_hash = *transport.handshake_hash();
        let peer_static = *transport.remote_static();
        if let Some(pinned) = self.remote_static {
            // Snow used the pinned key in DH; re-check the reported value.
            if pinned != peer_static {
                return Err(SessionError::Authentication);
            }
        }
        Ok(Split {
            transport,
            role: self.role,
            mode: self.client.mode(),
            generation: self.client.generation(),
            psk: self.psk.take().ok_or_else(state)?,
            handshake_hash,
            session_id: super::session_id(&handshake_hash),
            peer_static,
        })
    }
}

impl fmt::Debug for HandshakeDriver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandshakeDriver")
            .field("role", &self.role)
            .field("mode", &self.client.mode())
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
