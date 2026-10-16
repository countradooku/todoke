//! The sans-IO transfer engine for one authenticated session (§6, §7,
//! §11–§13).
//!
//! The caller feeds it every application frame the session returns
//! ([`TransferEngine::handle_frame`]), runs its timers
//! ([`TransferEngine::poll`]), sends what it queues
//! ([`TransferEngine::pop_frame`]), and shows its events
//! ([`TransferEngine::pop_event`]); [`crate::pump`] does all of that over a
//! `todoke_crypto::session::Session`. Local intent enters through
//! [`TransferEngine::offer`], [`TransferEngine::accept`],
//! [`TransferEngine::reject`], and [`TransferEngine::cancel`].
//!
//! # Session phases (§6, §11)
//!
//! The engine sends this side's `Capabilities` first and accepts exactly one
//! from the peer within 5 seconds; any other frame before it is `STATE`.
//! Then it is "Ready": transfer frames, `Revoke` (handed to the caller,
//! at most 64), and transfer-scoped `Error`s.
//!
//! # Transfers
//!
//! Each transfer is an explicit state machine (enums, no flags):
//!
//! - incoming (this side receives): `Assembling` → `Offered` →
//!   `Receiving` → ended;
//! - outgoing (this side sends): `Offering` → `Serving` (→ awaiting the
//!   receipt) → ended.
//!
//! A transfer ID lives in exactly one of the two maps. Frames only move a
//! transfer forward through validated transitions; a known frame in the
//! wrong state closes the session with `STATE` (§5). A session-scoped
//! failure queues an `Error`, ends every transfer, and closes the engine.

mod ended;
mod link;

pub use link::LinkError;
mod incoming;
mod outgoing;
mod served;

use core::fmt;
use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use todoke_crypto::consent::SessionBinding;
use todoke_crypto::identity::{KeyId, KeyStore};
use todoke_proto::link::{LinkAbilities, LinkOffer, LinkResult, OFFER_ID_LEN};
use todoke_proto::session::{ErrorRecord, ErrorScope, FrameType};
use todoke_proto::time::UnixTime;
use todoke_proto::transfer::{Cancel, CancelReason, Capabilities, RejectReason, TransferId};
use zeroize::Zeroizing;

use self::ended::{Ended, Outcome};
use self::incoming::Incoming;
use self::outgoing::Outgoing;
use crate::capabilities::{LocalCapabilities, Negotiated};
use crate::clock::Clock;
use crate::events::{Direction, Failure, FailureCode, Party, TransferEvent};
use crate::limits::{CAPABILITIES_TIMEOUT, MAX_REVOCATIONS};
use crate::offer::{OfferError, OutgoingOffer};
use crate::storage::{ReceiveSink, SendSource};

/// Per-session settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EngineConfig {
    /// This device's Capabilities for the session (§6).
    pub capabilities: LocalCapabilities,
    /// The label of the transport carrying the session, reported in
    /// progress events. Transports are P09; any short static label works.
    pub transport: &'static str,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            capabilities: LocalCapabilities::defaults(),
            transport: "unknown",
        }
    }
}

/// A frame for the session to send.
#[derive(Clone, PartialEq, Eq)]
pub enum OutgoingFrame {
    /// An application frame (`Session::send`). The body may carry a file
    /// master (`FileKey`), so it is wiped when dropped.
    Frame {
        /// The frame type.
        frame_type: FrameType,
        /// The body.
        body: Zeroizing<Vec<u8>>,
    },
    /// An `Error` (`Session::send_error`); a session-scoped one closes the
    /// session.
    Error(ErrorRecord),
}

impl fmt::Debug for OutgoingFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame { frame_type, body } => f
                .debug_struct("Frame")
                .field("frame_type", frame_type)
                .field("body", &format_args!("[{} bytes]", body.len()))
                .finish(),
            Self::Error(record) => f.debug_tuple("Error").field(record).finish(),
        }
    }
}

/// Why an engine call failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EngineError {
    /// The peer violated the protocol or a deadline passed: the session
    /// must close. A session-scoped `Error` is queued when one may be sent.
    Session(Failure),
    /// The engine is closed.
    Closed,
    /// No such transfer in this session.
    UnknownTransfer,
    /// The transfer is not in a state that permits this.
    WrongState,
    /// The selection is empty, unsorted, not files of the manifest, or, for
    /// a resumed transfer, not the earlier selection (§7.5).
    Selection,
    /// The manifest expired before consent could be given.
    Expired,
    /// An offer was refused.
    Offer(OfferError),
    /// The device key is not this session's local key.
    KeyRole,
    /// The key store could not sign.
    KeyStore,
    /// Durable storage failed; nothing was sent.
    Storage,
    /// OS randomness was unavailable.
    Random,
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(failure) => write!(f, "session failed: {}", failure.code.message()),
            Self::Closed => f.write_str("the transfer engine is closed"),
            Self::UnknownTransfer => f.write_str("no such transfer in this session"),
            Self::WrongState => f.write_str("the transfer is not in a state that permits this"),
            Self::Selection => f.write_str("the selection is invalid"),
            Self::Expired => f.write_str("the offer expired"),
            Self::Offer(error) => write!(f, "offer refused: {error}"),
            Self::KeyRole => f.write_str("the device key does not belong to this session"),
            Self::KeyStore => f.write_str("the key store could not sign"),
            Self::Storage => f.write_str("durable storage failed"),
            Self::Random => f.write_str("randomness unavailable"),
        }
    }
}

impl std::error::Error for EngineError {}

/// A session-closing violation found while handling a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Violation(pub(crate) FailureCode);

pub(crate) type Handled = Result<(), Violation>;

pub(crate) const fn violation(code: FailureCode) -> Violation {
    Violation(code)
}

enum Phase {
    AwaitingCapabilities { deadline: Duration },
    Ready(Negotiated),
    Closed,
}

/// The transfer engine of one authenticated session; see the module
/// documentation.
pub struct TransferEngine<'k, K: KeyStore, S: SendSource, R: ReceiveSink> {
    session: SessionBinding,
    keys: &'k K,
    device_key: KeyId,
    source: S,
    sink: R,
    clock: Clock,
    config: EngineConfig,
    phase: Phase,
    incoming: BTreeMap<TransferId, Incoming>,
    outgoing: BTreeMap<TransferId, Outgoing>,
    frames: VecDeque<OutgoingFrame>,
    events: VecDeque<TransferEvent>,
    revocations: VecDeque<Vec<u8>>,
    revocations_seen: usize,
    /// Link setup (§10.2).
    link: link::LinkSetup,
    /// Accept nonces seen in this session, both directions (§7.3: unique
    /// per session).
    accept_nonces: BTreeSet<[u8; 16]>,
    /// The sender's one outstanding `ResumeQuery` (§7.5).
    resume_query: Option<TransferId>,
    /// Retained segments still to revalidate (§7.5) before more requests.
    revalidation_pending: bool,
}

impl<'k, K: KeyStore, S: SendSource, R: ReceiveSink> TransferEngine<'k, K, S, R> {
    /// An engine for the session `session`, created when its ratchet gate
    /// opened: it queues this side's `Capabilities` at once and expects the
    /// peer's within 5 seconds of `now` (§6, §13).
    ///
    /// `device_key` is this device's key in `keys` (it signs Accepts and
    /// receipts); `clock` maps the session's monotonic time to trusted wall
    /// time; `source` serves this side's offers and `sink` receives the
    /// peer's.
    ///
    /// # Errors
    ///
    /// [`EngineError::KeyRole`] if `device_key` is not the session's local
    /// device key; [`EngineError::KeyStore`].
    #[expect(
        clippy::too_many_arguments,
        reason = "the session, signing key, both stores, clock, config, and time are all required"
    )]
    pub fn new(
        session: SessionBinding,
        keys: &'k K,
        device_key: KeyId,
        source: S,
        sink: R,
        config: EngineConfig,
        clock: Clock,
        now: Duration,
    ) -> Result<Self, EngineError> {
        let public = keys
            .public_key(&device_key)
            .map_err(|_| EngineError::KeyStore)?;
        if public != *session.local_device() {
            return Err(EngineError::KeyRole);
        }
        let mut engine = Self {
            session,
            keys,
            device_key,
            source,
            sink,
            clock,
            config,
            phase: Phase::AwaitingCapabilities {
                deadline: now.saturating_add(CAPABILITIES_TIMEOUT),
            },
            incoming: BTreeMap::new(),
            outgoing: BTreeMap::new(),
            frames: VecDeque::new(),
            events: VecDeque::new(),
            revocations: VecDeque::new(),
            revocations_seen: 0,
            link: link::LinkSetup::new(),
            accept_nonces: BTreeSet::new(),
            resume_query: None,
            revalidation_pending: false,
        };
        let capabilities = config.capabilities.record().encode();
        engine.queue(FrameType::CAPABILITIES, capabilities.to_vec());
        Ok(engine)
    }

    /// The session this engine runs on.
    #[must_use]
    pub const fn session(&self) -> &SessionBinding {
        &self.session
    }

    /// Both peers' Capabilities, once exchanged.
    #[must_use]
    pub const fn negotiated(&self) -> Option<&Negotiated> {
        match &self.phase {
            Phase::Ready(negotiated) => Some(negotiated),
            Phase::AwaitingCapabilities { .. } | Phase::Closed => None,
        }
    }

    /// Whether the engine is closed.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        matches!(self.phase, Phase::Closed)
    }

    /// The sender's content source.
    pub fn source_mut(&mut self) -> &mut S {
        &mut self.source
    }

    /// The receiver's sink.
    #[must_use]
    pub const fn sink(&self) -> &R {
        &self.sink
    }

    /// The receiver's sink, mutably.
    pub fn sink_mut(&mut self) -> &mut R {
        &mut self.sink
    }

    /// Changes the transport label reported in progress events.
    pub fn set_transport(&mut self, transport: &'static str) {
        self.config.transport = transport;
    }

    /// The next frame to send, in order.
    pub fn pop_frame(&mut self) -> Option<OutgoingFrame> {
        self.frames.pop_front()
    }

    /// The next event for the UI.
    pub fn pop_event(&mut self) -> Option<TransferEvent> {
        self.events.pop_front()
    }

    /// The next `Revoke` body the peer forwarded, for the identity layer to
    /// verify and apply (§2). At most 64 per session.
    pub fn pop_revocation(&mut self) -> Option<Vec<u8>> {
        self.revocations.pop_front()
    }

    /// Whether frames are waiting to be sent.
    #[must_use]
    pub fn has_frames(&self) -> bool {
        !self.frames.is_empty()
    }

    /// Whether events are waiting.
    #[must_use]
    pub fn has_events(&self) -> bool {
        !self.events.is_empty()
    }

    /// Incoming transfer records this session keeps, live and ended (at
    /// most [`crate::limits::MAX_INCOMING_TRANSFER_IDS`]).
    #[cfg(test)]
    pub(crate) fn incoming_records(&self) -> usize {
        self.incoming.len()
    }

    /// Bytes of frames waiting to be sent.
    fn queued_bytes(&self) -> usize {
        self.frames
            .iter()
            .map(|frame| match frame {
                OutgoingFrame::Frame { body, .. } => body.len(),
                OutgoingFrame::Error(_) => todoke_proto::session::ERROR_LEN,
            })
            .sum()
    }

    /// The trusted wall-clock time at monotonic `now`.
    fn wall(&self, now: Duration) -> UnixTime {
        self.clock.wall(now)
    }

    fn queue(&mut self, frame_type: FrameType, body: Vec<u8>) {
        self.frames.push_back(OutgoingFrame::Frame {
            frame_type,
            body: Zeroizing::new(body),
        });
    }

    fn queue_secret(&mut self, frame_type: FrameType, body: Zeroizing<Vec<u8>>) {
        self.frames
            .push_back(OutgoingFrame::Frame { frame_type, body });
    }

    fn event(&mut self, event: TransferEvent) {
        self.events.push_back(event);
    }

    /// Queues a transfer-scoped `Error` (§12) for `code`.
    fn transfer_error(&mut self, transfer_id: TransferId, code: FailureCode) {
        if let Some(error_code) = code.error_code()
            && let Ok(record) = ErrorRecord::new(ErrorScope::Transfer(transfer_id), error_code)
        {
            self.frames.push_back(OutgoingFrame::Error(record));
        }
    }

    /// The deadline the caller should next call [`Self::poll`] at, or
    /// `now` if local work (revalidating retained segments) is pending.
    #[must_use]
    pub fn next_deadline(&self, now: Duration) -> Duration {
        if self.revalidation_pending {
            return now;
        }
        let mut deadline = Duration::MAX;
        if let Phase::AwaitingCapabilities { deadline: at } = self.phase {
            deadline = deadline.min(at);
        }
        for incoming in self.incoming.values() {
            deadline = deadline.min(incoming.deadline());
        }
        for outgoing in self.outgoing.values() {
            deadline = deadline.min(outgoing.deadline());
        }
        deadline
    }

    /// Handles one application frame from the session: `Capabilities`,
    /// a transfer frame, `Revoke`, or a transfer-scoped `Error`.
    ///
    /// # Errors
    ///
    /// [`EngineError::Session`] if the session must close (an `Error` is
    /// queued; send it, then close); [`EngineError::Closed`] after that.
    pub fn handle_frame(
        &mut self,
        frame_type: FrameType,
        body: &[u8],
        now: Duration,
    ) -> Result<(), EngineError> {
        if self.queued_bytes() > crate::limits::APP_BUFFER_BUDGET {
            // §13: the caller is not sending what the engine queued; a peer
            // must not grow the buffers without bound meanwhile.
            return self.after(Err(violation(FailureCode::Limit)), now);
        }
        let result = match &self.phase {
            Phase::Closed => return Err(EngineError::Closed),
            Phase::AwaitingCapabilities { .. } => {
                if frame_type == FrameType::CAPABILITIES {
                    self.on_capabilities(body)
                } else {
                    Err(violation(FailureCode::State))
                }
            }
            Phase::Ready(_) => self.dispatch(frame_type, body, now),
        };
        self.after(result, now)
    }

    /// Runs the timers: Capabilities, manifest assembly, consent prompt,
    /// Accept and manifest expiry, chunk requests, cancel acknowledgments,
    /// and the receipt window (§13). Also continues revalidation and
    /// request scheduling.
    ///
    /// # Errors
    ///
    /// As [`Self::handle_frame`].
    pub fn poll(&mut self, now: Duration) -> Result<(), EngineError> {
        let result = match self.phase {
            Phase::Closed => return Err(EngineError::Closed),
            Phase::AwaitingCapabilities { deadline } => {
                if now >= deadline {
                    Err(violation(FailureCode::Timeout))
                } else {
                    Ok(())
                }
            }
            Phase::Ready(_) => self
                .poll_incoming(now)
                .and_then(|()| self.poll_outgoing(now)),
        };
        self.after(result, now)
    }

    fn after(&mut self, result: Handled, now: Duration) -> Result<(), EngineError> {
        if result.is_ok() && matches!(self.phase, Phase::Ready(_)) {
            self.schedule(now);
            self.publish_ready(now);
            self.next_resume_query();
        }
        match result {
            Ok(()) => Ok(()),
            Err(Violation(code)) => {
                let failure = Failure::local(code);
                self.fail_session(failure);
                Err(EngineError::Session(failure))
            }
        }
    }

    fn on_capabilities(&mut self, body: &[u8]) -> Handled {
        let peer = Capabilities::decode(body).map_err(|_| violation(FailureCode::Malformed))?;
        let negotiated = Negotiated::new(&self.config.capabilities, peer)
            .map_err(|_| violation(FailureCode::Unsupported))?;
        self.event(TransferEvent::Ready {
            suite: negotiated.suite(),
        });
        self.phase = Phase::Ready(negotiated);
        Ok(())
    }

    fn dispatch(&mut self, frame_type: FrameType, body: &[u8], now: Duration) -> Handled {
        match frame_type {
            FrameType::MANIFEST_START => self.on_manifest_start(body, now),
            FrameType::MANIFEST_PART => self.on_manifest_part(body, now),
            FrameType::FILE_KEY => self.on_file_key(body, now),
            FrameType::CHUNK => self.on_chunk(body, now),
            FrameType::RESUME_QUERY => self.on_resume_query(body),
            FrameType::ACCEPT => self.on_accept(body, now),
            FrameType::REJECT => self.on_reject(body),
            FrameType::CHUNK_REQUEST => self.on_chunk_request(body, now),
            FrameType::RESUME_STATUS => self.on_resume_status(body, now),
            FrameType::COMPLETE => self.on_complete(body, now),
            FrameType::DELIVERY_RECEIPT => self.on_receipt(body, now),
            FrameType::CANCEL => self.on_cancel(body, now),
            FrameType::CANCEL_ACK => self.on_cancel_ack(body),
            FrameType::ERROR => self.on_transfer_error(body),
            FrameType::LINK_ABILITIES => self.on_link_abilities(body),
            FrameType::LINK_OFFER => self.on_link_offer(body),
            FrameType::LINK_ANSWER => self.on_link_answer(body),
            FrameType::REVOKE => {
                if self.revocations_seen >= MAX_REVOCATIONS {
                    return Err(violation(FailureCode::Limit));
                }
                self.revocations_seen += 1;
                self.revocations.push_back(body.to_vec());
                Ok(())
            }
            // Capabilities a second time, or any other known type.
            _ => Err(violation(FailureCode::State)),
        }
    }

    /// Whether this device's key is the lexicographically smaller of the
    /// two full device keys (it hosts a link both can host, §10.2).
    fn own_key_smaller(&self) -> bool {
        self.session.local_device().as_bytes() < self.session.peer_device().as_bytes()
    }

    /// The peer's link abilities (§10.2): checked, once per session.
    fn on_link_abilities(&mut self, body: &[u8]) -> Handled {
        let smaller = self.own_key_smaller();
        let step = self.link.on_abilities(body, smaller)?;
        self.link_step(step);
        Ok(())
    }

    /// The host's offer (§10.2): checked against the choice, then reported
    /// for this side to join (or decline).
    fn on_link_offer(&mut self, body: &[u8]) -> Handled {
        let step = self.link.on_offer(body)?;
        self.link_step(step);
        Ok(())
    }

    /// The joiner's answer to this side's offer (§10.2).
    fn on_link_answer(&mut self, body: &[u8]) -> Handled {
        let step = self.link.on_answer(body)?;
        self.link_step(step);
        Ok(())
    }

    fn link_step(&mut self, step: link::Step) {
        match step {
            link::Step::Nothing => {}
            link::Step::Chosen(choice) => self.event(TransferEvent::LinkChosen(choice)),
            link::Step::Offered(offer) => self.event(TransferEvent::LinkOffered(offer)),
            link::Step::Answered(answer) => self.event(TransferEvent::LinkAnswered(answer)),
        }
    }

    /// Sends what this endpoint can host and join now (`LinkAbilities`,
    /// §10.2), at most once per session, after Capabilities. Send it only
    /// if it can take part; once both sides have, the choice (if any) is
    /// reported as [`TransferEvent::LinkChosen`].
    ///
    /// # Errors
    ///
    /// [`LinkError::NotReady`] before Capabilities were exchanged or after
    /// the engine closed; [`LinkError::AlreadySent`].
    pub fn send_link_abilities(&mut self, abilities: LinkAbilities) -> Result<(), LinkError> {
        if !matches!(self.phase, Phase::Ready(_)) {
            return Err(LinkError::NotReady);
        }
        let smaller = self.own_key_smaller();
        let step = self.link.send_abilities(abilities, smaller)?;
        self.queue(FrameType::LINK_ABILITIES, abilities.encode().to_vec());
        self.link_step(step);
        Ok(())
    }

    /// Sends the host's offer (§10.2): exactly the chosen kind and
    /// security, once per session. The secret goes out in a zeroized
    /// buffer.
    ///
    /// # Errors
    ///
    /// [`LinkError::NotReady`]; [`LinkError::NotChosen`] unless this side
    /// is the chosen host; [`LinkError::WrongOffer`]; [`LinkError::Done`].
    pub fn offer_link(&mut self, offer: &LinkOffer) -> Result<(), LinkError> {
        if !matches!(self.phase, Phase::Ready(_)) {
            return Err(LinkError::NotReady);
        }
        self.link.offer(offer)?;
        self.queue_secret(FrameType::LINK_OFFER, offer.encode());
        Ok(())
    }

    /// Sends the joiner's answer to the offer it got (§10.2). After
    /// `Joined`, both sides close this session and the joiner connects over
    /// the new link; `Declined` and `Failed` end link setup for the session.
    ///
    /// # Errors
    ///
    /// [`LinkError::NotReady`]; [`LinkError::NoOffer`]; [`LinkError::Done`].
    pub fn answer_link(
        &mut self,
        offer_id: &[u8; OFFER_ID_LEN],
        result: LinkResult,
    ) -> Result<(), LinkError> {
        if !matches!(self.phase, Phase::Ready(_)) {
            return Err(LinkError::NotReady);
        }
        let answer = self.link.answer(offer_id, result)?;
        self.queue(FrameType::LINK_ANSWER, answer.encode().to_vec());
        Ok(())
    }

    /// The link chosen in this session, once both sides sent abilities.
    #[must_use]
    pub const fn link_choice(&self) -> Option<todoke_proto::link::LinkChoice> {
        self.link.choice()
    }

    /// A transfer-scoped `Error` from the peer ends that transfer (§12);
    /// nothing is sent in reply.
    fn on_transfer_error(&mut self, body: &[u8]) -> Handled {
        let record = ErrorRecord::decode(body).map_err(|_| violation(FailureCode::Malformed))?;
        let ErrorScope::Transfer(transfer_id) = record.scope() else {
            // The session layer closes on session-scoped errors itself.
            return Err(violation(FailureCode::State));
        };
        let failure = Failure::peer(FailureCode::from_error_code(record.code()));
        if self.incoming.contains_key(&transfer_id) {
            self.end_incoming(&transfer_id, Outcome::Failed, ended::Late::default());
            self.event(TransferEvent::Failed {
                transfer_id,
                direction: Direction::Incoming,
                failure,
            });
        } else if self.outgoing.contains_key(&transfer_id)
            && self.end_outgoing(&transfer_id, Outcome::Failed, ended::Late::default(), false)
        {
            self.event(TransferEvent::Failed {
                transfer_id,
                direction: Direction::Outgoing,
                failure,
            });
        }
        // An Error for an unknown or already ended transfer needs no
        // action, and an Error is never answered with one (§12).
        Ok(())
    }

    /// Sends a `Cancel` for `transfer_id` (§7.6): either direction, offered
    /// or active. The consent gate closes at once, keys are dropped, and
    /// the ID becomes permanently unusable; the peer must acknowledge
    /// within 5 seconds.
    ///
    /// # Errors
    ///
    /// [`EngineError::UnknownTransfer`], [`EngineError::WrongState`] for a
    /// transfer that already ended for good, [`EngineError::Closed`],
    /// [`EngineError::Random`].
    pub fn cancel(
        &mut self,
        transfer_id: &TransferId,
        reason: CancelReason,
        now: Duration,
    ) -> Result<(), EngineError> {
        if !matches!(self.phase, Phase::Ready(_)) {
            return Err(EngineError::Closed);
        }
        let cancel_id = todoke_crypto::consent::random_id().map_err(|_| EngineError::Random)?;
        let direction = if self.incoming.contains_key(transfer_id) {
            Direction::Incoming
        } else if self.outgoing.contains_key(transfer_id) {
            Direction::Outgoing
        } else {
            return Err(EngineError::UnknownTransfer);
        };
        let manifest_hash = match direction {
            Direction::Incoming => self.cancel_incoming(transfer_id, now)?,
            Direction::Outgoing => self.cancel_outgoing(transfer_id)?,
        };
        let record = Cancel::new(*transfer_id, manifest_hash, cancel_id, reason)
            .map_err(|_| EngineError::Random)?;
        self.queue(FrameType::CANCEL, record.encode().to_vec());
        let deadline = now.saturating_add(crate::limits::CANCEL_ACK_TIMEOUT);
        let pending = ended::PendingCancel { record, deadline };
        if let Some(ended) = self.ended_mut(transfer_id) {
            ended.cancel = Some(pending);
        }
        self.event(TransferEvent::Cancelled {
            transfer_id: *transfer_id,
            direction,
            by: Party::Local,
            reason,
        });
        Ok(())
    }

    fn ended_mut(&mut self, transfer_id: &TransferId) -> Option<&mut Ended> {
        if let Some(incoming) = self.incoming.get_mut(transfer_id) {
            incoming.ended_mut()
        } else {
            self.outgoing
                .get_mut(transfer_id)
                .and_then(Outgoing::ended_mut)
        }
    }

    /// A `Cancel` from the peer (§7.6): acknowledged at once, every time,
    /// for any known transfer; an active one ends.
    fn on_cancel(&mut self, body: &[u8], now: Duration) -> Handled {
        let record = Cancel::decode(body).map_err(|_| violation(FailureCode::Malformed))?;
        let transfer_id = *record.transfer_id();
        let (direction, manifest_hash, active) =
            if let Some(incoming) = self.incoming.get(&transfer_id) {
                (
                    Direction::Incoming,
                    incoming.manifest_hash(),
                    incoming.ended().is_none(),
                )
            } else if let Some(outgoing) = self.outgoing.get(&transfer_id) {
                (
                    Direction::Outgoing,
                    outgoing.manifest_hash(),
                    outgoing.ended().is_none(),
                )
            } else {
                return Err(violation(FailureCode::State));
            };
        if manifest_hash != *record.manifest_hash() {
            return Err(violation(FailureCode::State));
        }
        if active {
            match direction {
                Direction::Incoming => {
                    self.tombstone_incoming(&transfer_id, now);
                    self.end_incoming(&transfer_id, Outcome::Cancelled, ended::Late::default());
                }
                Direction::Outgoing => {
                    self.end_outgoing(
                        &transfer_id,
                        Outcome::Cancelled,
                        ended::Late::default(),
                        false,
                    );
                }
            }
            self.event(TransferEvent::Cancelled {
                transfer_id,
                direction,
                by: Party::Peer,
                reason: record.reason(),
            });
        } else if let Some(ended) = self.ended_mut(&transfer_id)
            && ended.outcome != Outcome::Cancelled
        {
            // A peer cancel after this side ended the transfer otherwise
            // (for example a late cancel of an expired transfer): the ID is
            // now unusable as well.
            ended.outcome = Outcome::Cancelled;
            if direction == Direction::Incoming {
                self.tombstone_incoming(&transfer_id, now);
            }
        }
        self.queue(FrameType::CANCEL_ACK, record.encode().to_vec());
        Ok(())
    }

    /// The peer's acknowledgment of this side's cancel: nothing more is in
    /// flight for the transfer.
    fn on_cancel_ack(&mut self, body: &[u8]) -> Handled {
        let record = Cancel::decode(body).map_err(|_| violation(FailureCode::Malformed))?;
        let ended = self
            .ended_mut(record.transfer_id())
            .ok_or(violation(FailureCode::State))?;
        match ended.cancel {
            Some(pending) if pending.record.cancel_id() == record.cancel_id() => {
                ended.cancel = None;
                ended.late = ended::Late::default();
                Ok(())
            }
            _ => Err(violation(FailureCode::State)),
        }
    }

    /// Closes the engine after a session-scoped failure this side
    /// detected: queues the `Error` (when the code may be sent) and ends
    /// every transfer.
    fn fail_session(&mut self, failure: Failure) {
        if let Some(code) = failure.code.error_code()
            && let Ok(record) = ErrorRecord::new(ErrorScope::Session, code)
        {
            self.frames.push_back(OutgoingFrame::Error(record));
        }
        self.close(Some(failure));
    }

    /// Ends the engine because the session ended (`failure` says why, if
    /// it failed). Unfinished transfers are reported as interrupted (they
    /// may resume in a fresh session with fresh consent) and the engine
    /// accepts nothing more. Call it when the session closes for any reason.
    pub fn close(&mut self, failure: Option<Failure>) {
        if matches!(self.phase, Phase::Closed) {
            return;
        }
        self.phase = Phase::Closed;
        let incoming: Vec<TransferId> = self
            .incoming
            .iter()
            .filter(|(_, transfer)| transfer.ended().is_none())
            .map(|(id, _)| *id)
            .collect();
        for transfer_id in incoming {
            self.end_incoming(&transfer_id, Outcome::Interrupted, ended::Late::default());
            self.event(TransferEvent::Interrupted {
                transfer_id,
                direction: Direction::Incoming,
            });
        }
        let outgoing: Vec<TransferId> = self
            .outgoing
            .iter()
            .filter(|(_, transfer)| transfer.ended().is_none())
            .map(|(id, _)| *id)
            .collect();
        for transfer_id in outgoing {
            self.interrupt_outgoing(&transfer_id);
        }
        self.frames
            .retain(|frame| matches!(frame, OutgoingFrame::Error(_)));
        self.event(TransferEvent::SessionClosed { failure });
    }

    /// Offers this side's interrupted or expired outgoing transfers back,
    /// with their manifests and masters, to resume in a fresh session
    /// (§7.5). Cancelled, rejected, failed, and delivered ones are gone.
    pub fn take_resumable(&mut self) -> Vec<OutgoingOffer> {
        self.outgoing
            .values_mut()
            .filter_map(Outgoing::take_resumable)
            .collect()
    }

    /// Ends the engine and returns the source and sink.
    pub fn into_parts(self) -> (S, R) {
        (self.source, self.sink)
    }

    /// Rejects an offer (§7.3).
    ///
    /// # Errors
    ///
    /// [`EngineError::UnknownTransfer`], [`EngineError::WrongState`] unless
    /// it awaits a decision, [`EngineError::Closed`].
    pub fn reject(
        &mut self,
        transfer_id: &TransferId,
        reason: RejectReason,
    ) -> Result<(), EngineError> {
        if !matches!(self.phase, Phase::Ready(_)) {
            return Err(EngineError::Closed);
        }
        self.reject_offer(transfer_id, reason)
    }
}

impl<K: KeyStore, S: SendSource, R: ReceiveSink> fmt::Debug for TransferEngine<'_, K, S, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let phase = match self.phase {
            Phase::AwaitingCapabilities { .. } => "awaiting-capabilities",
            Phase::Ready(_) => "ready",
            Phase::Closed => "closed",
        };
        f.debug_struct("TransferEngine")
            .field("phase", &phase)
            .field("incoming", &self.incoming.len())
            .field("outgoing", &self.outgoing.len())
            .field("frames", &self.frames.len())
            .field("events", &self.events.len())
            .finish_non_exhaustive()
    }
}
