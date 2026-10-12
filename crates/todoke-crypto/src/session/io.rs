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
use todoke_proto::session::{
    CIPHERTEXT_PREFIX_LEN, ErrorRecord, FrameType, Hello, PRELUDE_PREFIX_LEN, SessionMode,
    ciphertext_len, prelude_record_len,
};

use super::authority::PeerAuthority;
use super::engine::Entropy;
use super::establish::{Establishment, Phase};
use super::handshake::{self, HandshakeDriver, InitiatorPlan, ResponderPlan};
use super::transport::{Frame, Limits, SessionCore};
use super::{HANDSHAKE_TIMEOUT, LocalIdentity, Role, SessionError, UnauditedSuite0001};
use crate::identity::{KeyStore, VerifiedDeviceBinding};
use crate::rng;

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
enum Framing {
    Prelude,
    Transport,
}

/// Incremental reader of one length-prefixed record. Progress survives a
/// cancelled read, and the prefix is validated before the body is
/// buffered (§4.1, §5, §13).
#[derive(Debug)]
struct RecordReader {
    prefix: [u8; 2],
    prefix_filled: usize,
    body: Vec<u8>,
    body_filled: usize,
    body_len: Option<usize>,
}

impl RecordReader {
    const fn new() -> Self {
        Self {
            prefix: [0; 2],
            prefix_filled: 0,
            body: Vec::new(),
            body_filled: 0,
            body_len: None,
        }
    }

    fn poll_record<R: AsyncRead + Unpin>(
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

    async fn write(&mut self, record: &[u8]) -> Result<(), SessionError> {
        self.usable()?;
        self.writing = true;
        let mut written = 0;
        let io = &mut self.io;
        let result = poll_fn(|cx| {
            while written < record.len() {
                match Pin::new(&mut *io).poll_write(cx, &record[written..]) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(SessionError::Io(io::ErrorKind::WriteZero)));
                    }
                    Poll::Ready(Ok(count)) => written += count,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(io_error(&error))),
                    Poll::Pending => return Poll::Pending,
                }
            }
            Pin::new(&mut *io)
                .poll_flush(cx)
                .map_err(|error| io_error(&error))
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
            conn.write(&reply).await?;
        }
    }
    let split = driver.finish()?;
    let mut establishment = Establishment::new(split, conn.now(), Limits::SPEC);
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
    for record in establishment.start(local, conn.now())? {
        conn.write(&record).await?;
    }
    while establishment.phase() != Phase::Open {
        let record = conn
            .read(Framing::Transport, establishment.deadline())
            .await?
            .ok_or(SessionError::Timeout)?;
        for reply in establishment.receive(&record, local, authority, conn.now())? {
            conn.write(&reply).await?;
        }
        if establishment.phase() == Phase::AckPending {
            // The Ack is written and flushed: the responder's gate opens.
            establishment.ack_queued(authority)?;
        }
    }
    Ok(())
}

/// An accepted stream whose `ClientHello` was read, waiting for the caller
/// to choose a [`ResponderPlan`] (for example by resolving the locator to a
/// contact).
pub struct IncomingSession<IO, T> {
    conn: Conn<IO, T>,
    hello: Hello,
    received_at: Duration,
    gate: UnauditedSuite0001,
}

impl<IO: AsyncRead + AsyncWrite + Unpin, T: Timer> IncomingSession<IO, T> {
    /// Reads the `ClientHello` from a newly accepted stream.
    ///
    /// Waiting for it is bounded by [`HANDSHAKE_TIMEOUT`] as a local quota;
    /// the §13 handshake deadline then runs from its arrival. Hello fields
    /// are untrusted hints until the handshake authenticates them.
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
        })
    }

    /// The untrusted `ClientHello`.
    #[must_use]
    pub fn client_hello(&self) -> &Hello {
        &self.hello
    }

    /// Completes the handshake, identity confirmation, and ratchet as
    /// responder.
    ///
    /// # Errors
    ///
    /// Any [`SessionError`]. Failures before a journal leave the pairing
    /// usable; later ones return [`SessionError::RatchetUncertain`] and the
    /// authority blocks the pairing.
    pub async fn respond<K: KeyStore, A: PeerAuthority>(
        self,
        local: &LocalIdentity<'_, K>,
        plan: ResponderPlan,
        authority: &mut A,
    ) -> Result<Session<IO, T>, SessionError> {
        let Self {
            mut conn,
            hello,
            received_at,
            gate,
        } = self;
        let (driver, server_hello) = HandshakeDriver::responder(
            gate,
            hello,
            plan,
            local.noise_static(),
            random_nonce()?,
            Entropy::Os,
            received_at,
        )?;
        conn.write(&server_hello).await?;
        run(conn, driver, local, authority).await
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
            .finish_non_exhaustive()
    }
}

/// An established, mutually authenticated suite 0x0001 session whose PSK
/// ratchet committed (PROTOCOL §4–§5). Authentication only: it grants no
/// consent to receive anything (§7).
///
/// `send` and `recv` take `&mut self`; a full-duplex split is not provided
/// yet. `recv` also runs keepalive and time-based rekeying, so callers keep
/// a `recv` pending while the session is idle.
pub struct Session<IO, T> {
    conn: Conn<IO, T>,
    core: SessionCore,
}

impl<IO: AsyncRead + AsyncWrite + Unpin, T: Timer> Session<IO, T> {
    /// Runs the initiator side: `ClientHello`, the Noise handshake, identity
    /// confirmation, and the PSK ratchet.
    ///
    /// # Errors
    ///
    /// Any [`SessionError`]. Failures before a journal leave the pairing
    /// usable; later ones return [`SessionError::RatchetUncertain`] and the
    /// authority blocks the pairing.
    pub async fn initiate<K: KeyStore, A: PeerAuthority>(
        io: IO,
        timer: T,
        gate: UnauditedSuite0001,
        local: &LocalIdentity<'_, K>,
        plan: InitiatorPlan,
        authority: &mut A,
    ) -> Result<Self, SessionError> {
        let mut conn = Conn::new(io, timer);
        let (driver, client_hello) = HandshakeDriver::initiator(
            gate,
            plan,
            local.noise_static(),
            random_nonce()?,
            Entropy::Os,
            conn.now(),
        )?;
        conn.write(&client_hello).await?;
        run(conn, driver, local, authority).await
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

    async fn flush_outgoing(&mut self) -> Result<(), SessionError> {
        while let Some(record) = self.core.pop_outgoing() {
            self.conn.write(&record).await?;
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
