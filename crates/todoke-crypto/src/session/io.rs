//! Async adapter: runs the sans-IO layers over any `futures-io`
//! [`AsyncRead`] + [`AsyncWrite`] byte pipe, with deadlines from a
//! caller-supplied [`Timer`]. No async runtime is required.

use core::fmt;
use core::future::Future;
use core::pin::{Pin, pin};
use core::task::{Context, Poll};
use core::time::Duration;
use std::future::poll_fn;
use std::io;

use futures_io::{AsyncRead, AsyncWrite};
use todoke_proto::pairing::{
    CODE_OFFER_REQUEST_LEN, CODE_OFFER_TRANSCRIPT_LEN, CodeOffer, CodeOfferRequest,
    STRANGER_TOKEN_LEN,
};
use todoke_proto::session::{
    CIPHERTEXT_PREFIX_LEN, ErrorRecord, FrameType, Hello, PRELUDE_PREFIX_LEN, PreludeKind,
    PreludeRecord, SessionMode, ciphertext_len, encode_prelude_record, prelude_record_len,
};
use todoke_proto::time::UnixTime;

use super::authority::PeerAuthority;
use super::engine::Entropy;
use super::establish::{Establishment, Phase};
use super::handshake::{self, HandshakeDriver, InitiatorPlan, ResponderPlan};
use super::transport::{Frame, Limits, SessionCore};
use super::{
    ErrorCode, HANDSHAKE_TIMEOUT, LocalIdentity, Role, SessionError, UnauditedSuite0001, WallClock,
};
use crate::identity::contacts::PairOutcome;
use crate::identity::{BlobStorage, ContactStore, KeyStore, Sealer, VerifiedDeviceBinding};
use crate::pairing::{
    AttemptPermit, HumanCode, OfferReservation, PairingError, PairingOffers, UnauditedCodePairing,
};
use crate::rng;

/// §3.2: the code offer request and its answer happen within 5 seconds.
pub const CODE_OFFER_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);

/// A monotonic clock and sleeper supplied by the caller's runtime.
///
/// `now` is time since an arbitrary fixed origin and must never go
/// backwards. `sleep_until` resolves at or after `deadline` on that clock.
/// Sessions use it for every §13 deadline; nothing here reads a wall clock.
pub trait Timer {
    /// The sleep future.
    type Sleep: Future<Output = ()>;

    /// The current monotonic time.
    fn now(&self) -> Duration;

    /// A future that completes once [`Self::now`] reaches `deadline`.
    fn sleep_until(&self, deadline: Duration) -> Self::Sleep;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Framing {
    Prelude,
    Transport,
}

/// Incremental reader of one length-prefixed record. Progress survives a
/// cancelled read, and the prefix is validated before the body is
/// buffered (§4.1, §5, §13).
#[derive(Debug)]
pub(super) struct RecordReader {
    prefix: [u8; 2],
    prefix_filled: usize,
    body: Vec<u8>,
    body_filled: usize,
    body_len: Option<usize>,
}

impl RecordReader {
    pub(super) const fn new() -> Self {
        Self {
            prefix: [0; 2],
            prefix_filled: 0,
            body: Vec::new(),
            body_filled: 0,
            body_len: None,
        }
    }

    pub(super) fn poll_record<R: AsyncRead + Unpin>(
        &mut self,
        io: &mut R,
        framing: Framing,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Vec<u8>, SessionError>> {
        debug_assert_eq!(PRELUDE_PREFIX_LEN, CIPHERTEXT_PREFIX_LEN);
        loop {
            let Some(length) = self.body_len else {
                let read = match Pin::new(&mut *io)
                    .poll_read(cx, &mut self.prefix[self.prefix_filled..])
                {
                    Poll::Ready(Ok(read)) => read,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(io_error(&error))),
                    Poll::Pending => return Poll::Pending,
                };
                if read == 0 {
                    return Poll::Ready(Err(SessionError::Closed));
                }
                self.prefix_filled += read;
                if self.prefix_filled == self.prefix.len() {
                    let length = match framing {
                        Framing::Prelude => prelude_record_len(self.prefix),
                        Framing::Transport => ciphertext_len(self.prefix),
                    }
                    .map_err(|_| {
                        SessionError::Protocol(todoke_proto::session::ErrorCode::MALFORMED)
                    });
                    let length = match length {
                        Ok(length) => length,
                        Err(error) => return Poll::Ready(Err(error)),
                    };
                    self.body = vec![0; length];
                    self.body_filled = 0;
                    self.body_len = Some(length);
                }
                continue;
            };
            if self.body_filled == length {
                self.prefix_filled = 0;
                self.body_len = None;
                return Poll::Ready(Ok(core::mem::take(&mut self.body)));
            }
            let read = match Pin::new(&mut *io).poll_read(cx, &mut self.body[self.body_filled..]) {
                Poll::Ready(Ok(read)) => read,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(io_error(&error))),
                Poll::Pending => return Poll::Pending,
            };
            if read == 0 {
                return Poll::Ready(Err(SessionError::Closed));
            }
            self.body_filled += read;
        }
    }
}

fn io_error(error: &io::Error) -> SessionError {
    SessionError::Io(error.kind())
}

/// Writes the rest of `record` from `written` on, then flushes.
fn poll_write_all<W: AsyncWrite + Unpin>(
    io: &mut W,
    record: &[u8],
    written: &mut usize,
    cx: &mut Context<'_>,
) -> Poll<Result<(), SessionError>> {
    while *written < record.len() {
        match Pin::new(&mut *io).poll_write(cx, &record[*written..]) {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(SessionError::Io(io::ErrorKind::WriteZero)));
            }
            Poll::Ready(Ok(count)) => *written += count,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(io_error(&error))),
            Poll::Pending => return Poll::Pending,
        }
    }
    Pin::new(&mut *io)
        .poll_flush(cx)
        .map_err(|error| io_error(&error))
}

/// The byte pipe plus the state that must survive cancellation.
struct Conn<IO, T> {
    io: IO,
    timer: T,
    reader: RecordReader,
    /// Set while a write is in flight. A dropped write leaves it set and the
    /// connection unusable: a partly written record must not be followed by
    /// anything on the same cipher state (§5).
    writing: bool,
    failed: bool,
}

impl<IO: AsyncRead + AsyncWrite + Unpin, T: Timer> Conn<IO, T> {
    fn new(io: IO, timer: T) -> Self {
        Self {
            io,
            timer,
            reader: RecordReader::new(),
            writing: false,
            failed: false,
        }
    }

    fn now(&self) -> Duration {
        self.timer.now()
    }

    fn usable(&self) -> Result<(), SessionError> {
        if self.writing || self.failed {
            Err(SessionError::Closed)
        } else {
            Ok(())
        }
    }

    /// Writes and flushes one record, racing it against `deadline` (§13: a
    /// peer that stops reading must not block us forever). The write is
    /// polled before the timer, so a pipe with room still takes a final
    /// record (such as a closing `Error`) after the deadline. Expiry, like
    /// any write failure, leaves the connection unusable.
    async fn write(&mut self, record: &[u8], deadline: Duration) -> Result<(), SessionError> {
        self.usable()?;
        self.writing = true;
        let mut written = 0;
        let mut sleep = pin!(self.timer.sleep_until(deadline));
        let io = &mut self.io;
        let result = poll_fn(|cx| {
            if let Poll::Ready(result) = poll_write_all(io, record, &mut written, cx) {
                return Poll::Ready(result);
            }
            if sleep.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(SessionError::Timeout));
            }
            Poll::Pending
        })
        .await;
        match result {
            Ok(()) => {
                self.writing = false;
                Ok(())
            }
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }

    /// Reads one record, or returns `Ok(None)` once `deadline` passes.
    async fn read(
        &mut self,
        framing: Framing,
        deadline: Duration,
    ) -> Result<Option<Vec<u8>>, SessionError> {
        self.usable()?;
        if self.timer.now() >= deadline {
            return Ok(None);
        }
        let mut sleep = pin!(self.timer.sleep_until(deadline));
        let reader = &mut self.reader;
        let io = &mut self.io;
        let result = poll_fn(|cx| {
            if let Poll::Ready(result) = reader.poll_record(io, framing, cx) {
                return Poll::Ready(result.map(Some));
            }
            if sleep.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Ok(None));
            }
            Poll::Pending
        })
        .await;
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

fn random_nonce() -> Result<[u8; 16], SessionError> {
    rng::nonzero_id().map_err(|_| SessionError::Random)
}

/// Runs a handshake to completion, then identity and the ratchet.
async fn run<IO, T, K, A>(
    mut conn: Conn<IO, T>,
    mut driver: HandshakeDriver,
    local: &LocalIdentity<'_, K>,
    wall: WallClock,
    authority: &mut A,
) -> Result<Session<IO, T>, SessionError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    T: Timer,
    K: KeyStore,
    A: PeerAuthority,
{
    while !driver.is_done() {
        let record = conn
            .read(Framing::Prelude, driver.deadline())
            .await?
            .ok_or(SessionError::Timeout)?;
        for reply in driver.receive(&record, conn.now())? {
            conn.write(&reply, driver.deadline()).await?;
        }
    }
    let split = driver.finish()?;
    let mut establishment = Establishment::new(split, conn.now(), wall, Limits::SPEC);
    match establish(&mut conn, &mut establishment, local, authority).await {
        Ok(()) => {}
        Err(error) => return Err(establishment.failure(error, authority)),
    }
    let core = establishment.into_core(local, Entropy::Os, conn.now())?;
    Ok(Session { conn, core })
}

async fn establish<IO, T, K, A>(
    conn: &mut Conn<IO, T>,
    establishment: &mut Establishment,
    local: &LocalIdentity<'_, K>,
    authority: &mut A,
) -> Result<(), SessionError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    T: Timer,
    K: KeyStore,
    A: PeerAuthority,
{
    let records = establishment.start(local, conn.now())?;
    establishment.check_deadline(conn.now(), authority)?;
    for record in records {
        conn.write(&record, establishment.deadline()).await?;
    }
    while establishment.phase() != Phase::Open {
        let record = conn
            .read(Framing::Transport, establishment.deadline())
            .await?
            .ok_or(SessionError::Timeout)?;
        let replies = establishment.receive(&record, local, authority, conn.now())?;
        // Authority calls are synchronous; re-read the clock after them so
        // slow durable I/O cannot push a ratchet record past the deadline.
        establishment.check_deadline(conn.now(), authority)?;
        for reply in replies {
            conn.write(&reply, establishment.deadline()).await?;
        }
        if establishment.phase() == Phase::AckPending {
            // The Ack is written and flushed: the responder's gate opens.
            establishment.ack_queued(authority)?;
            establishment.check_deadline(conn.now(), authority)?;
        }
    }
    Ok(())
}

/// An accepted stream whose `ClientHello` was read, waiting for the caller
/// to choose a [`ResponderPlan`] (for example by resolving the locator to a
/// contact, or by reserving a pairing offer).
pub struct IncomingSession<IO, T> {
    conn: Conn<IO, T>,
    hello: Hello,
    received_at: Duration,
    gate: UnauditedSuite0001,
    /// `CodeOfferRequest || CodeOffer` when this stream began with the
    /// code offer exchange (§3.2).
    code_offer: Option<[u8; CODE_OFFER_TRANSCRIPT_LEN]>,
    /// The stream's place in the §13 unauthenticated-attempt budget, from
    /// [`Self::accept_any`], until a reservation takes it over.
    permit: Option<AttemptPermit>,
}

/// What a newly accepted stream began with.
pub enum Accepted<IO, T> {
    /// A `ClientHello`: a QR or contact attempt.
    Hello(IncomingSession<IO, T>),
    /// A `CodeOfferRequest`: a human-code entrant asking for the public
    /// offer (§3.2).
    CodeOfferRequest(IncomingCodeRequest<IO, T>),
}

impl<IO, T> fmt::Debug for Accepted<IO, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hello(incoming) => f.debug_tuple("Hello").field(incoming).finish(),
            Self::CodeOfferRequest(request) => {
                f.debug_tuple("CodeOfferRequest").field(request).finish()
            }
        }
    }
}

/// A stream that began with a `CodeOfferRequest` (§3.2), waiting for the
/// displayer to answer with its live code offer.
pub struct IncomingCodeRequest<IO, T> {
    conn: Conn<IO, T>,
    request: CodeOfferRequest,
    received_at: Duration,
    gate: UnauditedSuite0001,
    /// The stream's place in the §13 unauthenticated-attempt budget.
    permit: AttemptPermit,
}

impl<IO: AsyncRead + AsyncWrite + Unpin, T: Timer> IncomingCodeRequest<IO, T> {
    /// The stranger token the entrant selected (§9). Not to be logged.
    #[must_use]
    pub fn stranger_token(&self) -> &[u8; STRANGER_TOKEN_LEN] {
        self.request.stranger_token()
    }

    /// Answers with the live code offer if the request names `advertised`,
    /// the stranger token this device currently advertises, then reads the
    /// entrant's `ClientHello`, which must be a code-mode Hello for exactly
    /// that offer. The answer and the Hello must both arrive within the
    /// 5-second exchange window that began with the request (§3.2, §13), so
    /// a stream that stops after the offer holds its place in the
    /// unauthenticated-attempt budget for at most that long. Reserve the
    /// offer next, with
    /// [`IncomingSession::reserve_offer`] and
    /// [`OfferReservation::into_code_responder`].
    ///
    /// `now` is the trusted wall-clock time.
    ///
    /// # Errors
    ///
    /// [`SessionError::Pairing`] for a stale or unknown token or no live
    /// code offer (close silently), [`SessionError::Timeout`] if the answer
    /// cannot be written or the Hello does not arrive within 5 seconds of
    /// the request (§3.2), and a protocol or I/O error while reading the
    /// Hello.
    pub async fn answer(
        self,
        _code_gate: UnauditedCodePairing,
        offers: &PairingOffers,
        advertised: &[u8; STRANGER_TOKEN_LEN],
        now: UnixTime,
    ) -> Result<IncomingSession<IO, T>, SessionError> {
        let Self {
            mut conn,
            request,
            received_at,
            gate,
            permit,
        } = self;
        let offer = offers
            .answer_code_request(&request, advertised, now, conn.now())
            .map_err(SessionError::Pairing)?;
        let record = encode_prelude_record(PreludeKind::CodeOffer, &offer.encode())
            .map_err(|_| SessionError::Usage)?;
        let exchange_deadline = received_at.saturating_add(CODE_OFFER_EXCHANGE_TIMEOUT);
        conn.write(&record, exchange_deadline).await?;
        let record = conn
            .read(Framing::Prelude, exchange_deadline)
            .await?
            .ok_or(SessionError::Timeout)?;
        let hello = handshake::read_client_hello(&record)?;
        if hello.mode() != SessionMode::Code || hello.locator() != offer.pairing_id() {
            return Err(SessionError::Protocol(ErrorCode::STATE));
        }
        Ok(IncomingSession {
            received_at: conn.now(),
            conn,
            hello,
            gate,
            code_offer: Some(code_offer_bytes(request, &offer)),
            permit: Some(permit),
        })
    }

    /// Drops the request without answering.
    pub fn reject(self) -> IO {
        self.conn.io
    }
}

impl<IO, T> fmt::Debug for IncomingCodeRequest<IO, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IncomingCodeRequest")
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

/// `code_offer = CodeOfferRequest || CodeOffer` (§3.2).
fn code_offer_bytes(
    request: CodeOfferRequest,
    offer: &CodeOffer,
) -> [u8; CODE_OFFER_TRANSCRIPT_LEN] {
    let mut out = [0; CODE_OFFER_TRANSCRIPT_LEN];
    out[..CODE_OFFER_REQUEST_LEN].copy_from_slice(&request.encode());
    out[CODE_OFFER_REQUEST_LEN..].copy_from_slice(&offer.encode());
    out
}

impl<IO: AsyncRead + AsyncWrite + Unpin, T: Timer> IncomingSession<IO, T> {
    /// Reads the `ClientHello` from a newly accepted stream.
    ///
    /// Waiting for it is bounded by [`HANDSHAKE_TIMEOUT`] as a local quota;
    /// the §13 handshake deadline then runs from its arrival. Hello fields
    /// are untrusted hints until the handshake authenticates them.
    ///
    /// The stream is not counted against the §13 unauthenticated-attempt
    /// budget here; that is the caller's job for contact sessions. Accept
    /// pairing streams with [`Self::accept_any`], which counts them.
    ///
    /// # Errors
    ///
    /// [`SessionError::Timeout`], a malformed or unexpected record, or an
    /// I/O error. Nothing is sent in any case.
    pub async fn accept(io: IO, timer: T, gate: UnauditedSuite0001) -> Result<Self, SessionError> {
        let mut conn = Conn::new(io, timer);
        let deadline = conn.now().saturating_add(HANDSHAKE_TIMEOUT);
        let record = conn
            .read(Framing::Prelude, deadline)
            .await?
            .ok_or(SessionError::Timeout)?;
        let hello = handshake::read_client_hello(&record)?;
        Ok(Self {
            received_at: conn.now(),
            conn,
            hello,
            gate,
            code_offer: None,
            permit: None,
        })
    }

    /// Reads the first record of a newly accepted stream: a `ClientHello`
    /// (QR or contact) or a `CodeOfferRequest` (human-code pairing, §3.2).
    ///
    /// Before reading anything, the stream takes a place in the §13
    /// unauthenticated-attempt budget kept by `offers` (at most 4 at once
    /// and 20 starts per minute), which `timer` must serve as monotonic
    /// clock. It keeps that place until the attempt authenticates or ends:
    /// a pairing stream passes it to its reservation
    /// ([`Self::reserve_offer`]); any other stream holds it until
    /// [`Self::respond`] returns or the stream is dropped.
    ///
    /// Waiting is bounded by [`HANDSHAKE_TIMEOUT`] as a local quota; a code
    /// offer request must arrive within [`CODE_OFFER_EXCHANGE_TIMEOUT`].
    ///
    /// # Errors
    ///
    /// [`SessionError::Pairing`] with [`PairingError::RateLimited`] when the
    /// budget is exhausted: the stream is dropped (closed silently, §12)
    /// without reading from it. [`SessionError::Timeout`], a malformed or
    /// unexpected record, or an I/O error. Nothing is sent in any case.
    pub async fn accept_any(
        io: IO,
        timer: T,
        gate: UnauditedSuite0001,
        offers: &PairingOffers,
    ) -> Result<Accepted<IO, T>, SessionError> {
        let mut conn = Conn::new(io, timer);
        let started = conn.now();
        // §13: reject excess before any work; dropping `conn` closes it.
        let permit = offers.admit(started).map_err(SessionError::Pairing)?;
        let record = conn
            .read(Framing::Prelude, started.saturating_add(HANDSHAKE_TIMEOUT))
            .await?
            .ok_or(SessionError::Timeout)?;
        let malformed = || SessionError::Protocol(ErrorCode::MALFORMED);
        let decoded = PreludeRecord::decode(&record).map_err(|_| malformed())?;
        match decoded.kind() {
            PreludeKind::ClientHello => {
                let hello = Hello::decode_client(decoded.body()).map_err(|_| malformed())?;
                Ok(Accepted::Hello(Self {
                    received_at: conn.now(),
                    conn,
                    hello,
                    gate,
                    code_offer: None,
                    permit: Some(permit),
                }))
            }
            PreludeKind::CodeOfferRequest => {
                if conn.now() >= started.saturating_add(CODE_OFFER_EXCHANGE_TIMEOUT) {
                    return Err(SessionError::Timeout);
                }
                let request = CodeOfferRequest::decode(decoded.body()).map_err(|_| malformed())?;
                Ok(Accepted::CodeOfferRequest(IncomingCodeRequest {
                    received_at: conn.now(),
                    conn,
                    request,
                    gate,
                    permit,
                }))
            }
            _ => Err(SessionError::Protocol(ErrorCode::STATE)),
        }
    }

    /// The untrusted `ClientHello`.
    #[must_use]
    pub fn client_hello(&self) -> &Hello {
        &self.hello
    }

    /// Reserves the pairing offer this stream's `ClientHello` names, for
    /// [`OfferReservation::into_qr_responder`] or
    /// [`OfferReservation::into_code_responder`]. `now` is the trusted
    /// wall-clock time; `offers` must use this stream's [`Timer`] as its
    /// monotonic clock.
    ///
    /// A code-mode Hello is accepted only on a stream that began with the
    /// code offer exchange ([`IncomingCodeRequest::answer`]); any other is
    /// refused before the offer is looked at, so it costs the offer none
    /// of its attempts (§3.2). A stream from [`Self::accept_any`] passes
    /// its place in the §13 budget on to the reservation; any other starts
    /// a new attempt there.
    ///
    /// # Errors
    ///
    /// [`PairingError::NoOfferExchange`], and every refusal of an offer
    /// that is unknown, expired, busy, too soon, or over the §13 budget.
    /// Close the stream silently (§12).
    pub fn reserve_offer(
        &mut self,
        offers: &PairingOffers,
        now: UnixTime,
    ) -> Result<OfferReservation, PairingError> {
        offers.reserve_attempt(
            &self.hello,
            self.code_offer.is_some(),
            &mut self.permit,
            now,
            self.conn.now(),
        )
    }

    /// Completes the handshake, identity confirmation, and ratchet as
    /// responder.
    ///
    /// `now` is the current wall-clock time from a trusted clock (§1: an
    /// unknown or regressed clock requires local confirmation instead). The
    /// local binding must be valid at `now`; the peer's binding is verified,
    /// and the session lifetime computed, at `now` plus the monotonic time
    /// elapsed since this call.
    ///
    /// # Errors
    ///
    /// Any [`SessionError`]; [`SessionError::LocalIdentity`], before
    /// anything is sent, if the local binding is not valid at `now`.
    /// Failures before a journal leave the pairing usable; later ones return
    /// [`SessionError::RatchetUncertain`] and the authority blocks the
    /// pairing.
    pub async fn respond<K: KeyStore, A: PeerAuthority>(
        self,
        local: &LocalIdentity<'_, K>,
        now: UnixTime,
        mut plan: ResponderPlan,
        authority: &mut A,
    ) -> Result<Session<IO, T>, SessionError> {
        let Self {
            mut conn,
            hello,
            received_at,
            gate,
            code_offer,
            permit,
        } = self;
        // A stream that was not reserved for pairing keeps its place in the
        // §13 budget until this attempt ends.
        let _permit = permit;
        local.check_valid_at(now)?;
        // A code-pairing plan needs the offer records of this stream, and a
        // stream that exchanged them can only run code pairing (§3.2).
        match (plan.is_code_pairing(), code_offer) {
            (true, Some(offer)) => plan.bind_code_offer(offer)?,
            (false, None) => {}
            _ => return Err(SessionError::Usage),
        }
        let wall = WallClock::new(now, conn.now());
        let (driver, server_hello) = HandshakeDriver::responder(
            gate,
            hello,
            plan,
            local.noise_static(),
            random_nonce()?,
            Entropy::Os,
            received_at,
        )?;
        conn.write(&server_hello, driver.deadline()).await?;
        // Boxed: the handshake and establishment state make this future
        // large (clippy::large_futures for every caller otherwise).
        Box::pin(run(conn, driver, local, wall, authority)).await
    }

    /// Drops the attempt without sending anything.
    pub fn reject(self) -> IO {
        self.conn.io
    }
}

impl<IO, T> fmt::Debug for IncomingSession<IO, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IncomingSession")
            .field("hello", &self.hello)
            .field("code_offer_exchanged", &self.code_offer.is_some())
            .finish_non_exhaustive()
    }
}

/// An established, mutually authenticated suite 0x0001 session whose PSK
/// ratchet committed (PROTOCOL §4–§5). Authentication only: it grants no
/// consent to receive anything (§7).
///
/// # Caller obligations (§6, §11, §13)
///
/// A new session is in §11's "Ratchet committed" state, which this type
/// does not model. Until a Capabilities step is implemented in this crate,
/// the caller must:
///
/// - send exactly one `Capabilities` frame before any transfer or `Revoke`
///   frame, with local capabilities fixed before reading the peer's;
/// - accept exactly one `Capabilities` from the peer, received within 5
///   seconds of the session being returned (the ratchet gate opening), and
///   close the session (for example with a session `Error`) if it is late,
///   repeated, or preceded by another application frame;
/// - treat the session as §11 "Ready" only after both are exchanged.
///
/// [`Self::recv`] passes `Capabilities`, transfer frames, and `Revoke`
/// through without an exactly-once, deadline, or state check. The session
/// layer only uses Capabilities to admit noncritical extension frames.
///
/// `send` and `recv` take `&mut self`; a full-duplex split is not provided
/// yet. `recv` also runs keepalive and time-based rekeying, so callers keep
/// a `recv` pending while the session is idle.
///
/// Every write is bounded by a §13 deadline: the handshake (30 s) and
/// establishment (10 s) deadlines while connecting, then the session's idle,
/// Pong, and lifetime deadlines. A peer that stops reading closes the
/// session with [`SessionError::Timeout`] instead of blocking it.
pub struct Session<IO, T> {
    conn: Conn<IO, T>,
    core: SessionCore,
}

impl<IO: AsyncRead + AsyncWrite + Unpin, T: Timer> Session<IO, T> {
    /// Runs the initiator side: `ClientHello`, the Noise handshake, identity
    /// confirmation, and the PSK ratchet.
    ///
    /// `now` is the current wall-clock time from a trusted clock (§1: an
    /// unknown or regressed clock requires local confirmation instead). The
    /// local binding must be valid at `now`; the peer's binding is verified,
    /// and the session lifetime computed, at `now` plus the monotonic time
    /// elapsed since this call.
    ///
    /// # Errors
    ///
    /// Any [`SessionError`]; [`SessionError::LocalIdentity`], before
    /// anything is sent, if the local binding is not valid at `now`.
    /// Failures before a journal leave the pairing usable; later ones return
    /// [`SessionError::RatchetUncertain`] and the authority blocks the
    /// pairing.
    pub async fn initiate<K: KeyStore, A: PeerAuthority>(
        io: IO,
        timer: T,
        gate: UnauditedSuite0001,
        local: &LocalIdentity<'_, K>,
        now: UnixTime,
        plan: InitiatorPlan,
        authority: &mut A,
    ) -> Result<Self, SessionError> {
        local.check_valid_at(now)?;
        let mut conn = Conn::new(io, timer);
        let wall = WallClock::new(now, conn.now());
        let (driver, client_hello) = HandshakeDriver::initiator(
            gate,
            plan,
            local.noise_static(),
            random_nonce()?,
            Entropy::Os,
            conn.now(),
        )?;
        conn.write(&client_hello, driver.deadline()).await?;
        // Boxed: the handshake and establishment state make this future
        // large (clippy::large_futures for every caller otherwise).
        Box::pin(run(conn, driver, local, wall, authority)).await
    }

    /// Runs human-code pairing as the entrant (§3.2): the
    /// `CodeOfferRequest` for `stranger_token` (the stranger advertisement
    /// the user selected), `CPace` with `code`, the `XXpsk3` handshake,
    /// identity confirmation, and the first ratchet, which creates the
    /// contact in `store`. Returns the session and whether the contact is
    /// new or replaced an earlier pairing of the same device.
    ///
    /// A wrong code makes the displayer's Noise authentication fail; the
    /// displayer closes without saying why (§3.2), so this side sees a
    /// closed stream or a timeout.
    ///
    /// # Errors
    ///
    /// Any [`SessionError`]: [`SessionError::Pairing`] for an expired or
    /// already used offer, a protocol, timeout, or I/O error during the
    /// offer exchange, and every [`Self::initiate`] error.
    #[expect(
        clippy::too_many_arguments,
        reason = "the two gates, local identity, clock, offer selector, code, and store are all required"
    )]
    pub async fn initiate_code_pairing<K: KeyStore, S: Sealer, B: BlobStorage>(
        io: IO,
        timer: T,
        gate: UnauditedSuite0001,
        code_gate: UnauditedCodePairing,
        local: &LocalIdentity<'_, K>,
        now: UnixTime,
        stranger_token: [u8; STRANGER_TOKEN_LEN],
        code: &HumanCode,
        store: &mut ContactStore<S, B>,
    ) -> Result<(Self, PairOutcome), SessionError> {
        local.check_valid_at(now)?;
        let mut conn = Conn::new(io, timer);
        let wall = WallClock::new(now, conn.now());
        let request = CodeOfferRequest::new(stranger_token).map_err(|_| SessionError::Usage)?;
        let exchange_deadline = conn.now().saturating_add(CODE_OFFER_EXCHANGE_TIMEOUT);
        let record = encode_prelude_record(PreludeKind::CodeOfferRequest, &request.encode())
            .map_err(|_| SessionError::Usage)?;
        conn.write(&record, exchange_deadline).await?;
        let record = conn
            .read(Framing::Prelude, exchange_deadline)
            .await?
            .ok_or(SessionError::Timeout)?;
        let malformed = || SessionError::Protocol(ErrorCode::MALFORMED);
        let decoded = PreludeRecord::decode(&record).map_err(|_| malformed())?;
        if decoded.kind() != PreludeKind::CodeOffer {
            return Err(SessionError::Protocol(ErrorCode::STATE));
        }
        let offer = CodeOffer::decode_reply(decoded.body(), &request).map_err(|_| malformed())?;
        let (plan, mut authority) = store
            .begin_code_pairing(code_gate, request, &offer, code, wall.at(conn.now()))
            .map_err(SessionError::Pairing)?;
        let (driver, client_hello) = HandshakeDriver::initiator(
            gate,
            plan,
            local.noise_static(),
            random_nonce()?,
            Entropy::Os,
            conn.now(),
        )?;
        conn.write(&client_hello, driver.deadline()).await?;
        let session = Box::pin(run(conn, driver, local, wall, &mut authority)).await?;
        let outcome = authority
            .outcome()
            .ok_or(SessionError::Protocol(ErrorCode::STATE))?;
        Ok((session, outcome))
    }

    /// This side's handshake role.
    #[must_use]
    pub fn role(&self) -> Role {
        self.core.info().role
    }

    /// The session mode.
    #[must_use]
    pub fn mode(&self) -> SessionMode {
        self.core.info().mode
    }

    /// The final Noise handshake hash `h` (public).
    #[must_use]
    pub fn handshake_hash(&self) -> &[u8; 32] {
        &self.core.info().handshake_hash
    }

    /// `B3("todoke/v1/session\0" || h)` (§4.2.6).
    #[must_use]
    pub fn session_id(&self) -> &[u8; 32] {
        &self.core.info().session_id
    }

    /// The peer's X25519 Noise static key authenticated by the handshake.
    #[must_use]
    pub fn peer_static(&self) -> &[u8; 32] {
        &self.core.info().peer_static
    }

    /// The peer's verified device binding.
    #[must_use]
    pub fn peer_binding(&self) -> &VerifiedDeviceBinding {
        &self.core.info().peer_binding
    }

    /// Writes queued records. Each write is bounded by the session's close
    /// deadline (idle, Pong, binding/24-hour lifetime): a peer that stops
    /// reading closes the session with [`SessionError::Timeout`].
    async fn flush_outgoing(&mut self) -> Result<(), SessionError> {
        while let Some(record) = self.core.pop_outgoing() {
            let deadline = self.core.close_deadline();
            self.conn.write(&record, deadline).await?;
        }
        Ok(())
    }

    async fn after<R>(&mut self, result: Result<R, SessionError>) -> Result<R, SessionError> {
        // Report-then-close: a queued Error goes out before the error
        // returns. Best effort; the session is closed either way.
        let flushed = self.flush_outgoing().await;
        let value = result?;
        flushed?;
        Ok(value)
    }

    /// Sends one application frame (an assigned type owned by a higher
    /// layer). Due `KeyUpdate`s are sent first.
    ///
    /// # Errors
    ///
    /// [`SessionError::Usage`] for a session-layer, unassigned, or
    /// extension type or an oversized body; [`SessionError::Closed`] after
    /// any failure; I/O and timeout errors.
    pub async fn send(&mut self, frame_type: FrameType, body: &[u8]) -> Result<(), SessionError> {
        self.conn.usable()?;
        let result = self.core.send(frame_type, body, self.conn.now());
        self.after(result).await
    }

    /// Sends an `Error`. A session-scoped one closes the session (§12).
    ///
    /// # Errors
    ///
    /// [`SessionError::Closed`] or an I/O error.
    pub async fn send_error(&mut self, record: ErrorRecord) -> Result<(), SessionError> {
        self.conn.usable()?;
        let result = self.core.send_error(record, self.conn.now());
        self.after(result).await
    }

    /// Sends an early `KeyUpdate` (at most one per second).
    ///
    /// # Errors
    ///
    /// [`SessionError::RekeyTooSoon`], [`SessionError::Closed`], or an I/O
    /// error.
    pub async fn rekey(&mut self) -> Result<(), SessionError> {
        self.conn.usable()?;
        let result = self.core.request_rekey(self.conn.now());
        self.after(result).await
    }

    /// Receives the next frame for the caller. Ping/Pong, `KeyUpdate`,
    /// skipped extensions, and timers are handled internally.
    ///
    /// Application frames, including `Capabilities`, transfer frames, and
    /// `Revoke`, are returned without §6/§11 state checks; see "Caller
    /// obligations" on [`Session`].
    ///
    /// # Errors
    ///
    /// [`SessionError::PeerError`] when the peer closed with an Error,
    /// [`SessionError::Protocol`] after reporting a violation,
    /// [`SessionError::Authentication`] on a decryption failure,
    /// [`SessionError::Timeout`], [`SessionError::Closed`], or I/O errors.
    /// The session is closed after any error.
    pub async fn recv(&mut self) -> Result<Frame, SessionError> {
        loop {
            self.conn.usable()?;
            let polled = self.core.poll(self.conn.now());
            self.after(polled).await?;
            let deadline = self.core.next_deadline();
            let Some(record) = self.conn.read(Framing::Transport, deadline).await? else {
                continue;
            };
            let received = self.core.receive(&record, self.conn.now());
            if let Some(frame) = self.after(received).await? {
                return Ok(frame);
            }
        }
    }

    /// Whether the session is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.core.is_closed() || self.conn.usable().is_err()
    }
}

impl<IO, T> fmt::Debug for Session<IO, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("core", &self.core)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
