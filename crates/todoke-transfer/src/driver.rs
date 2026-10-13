//! Runs a [`TransferEngine`] over an established
//! `todoke_crypto::session::Session`.
//!
//! The session has no full-duplex split, so [`pump`] alternates: it sends
//! every queued frame, runs the engine's timers, and waits for at most one
//! frame, only until the engine's next deadline. The caller loops on it,
//! handling events and local intent (accept, reject, cancel, offer) between
//! calls.

use core::fmt;
use core::time::Duration;

use futures_io::{AsyncRead, AsyncWrite};
use todoke_crypto::identity::KeyStore;
use todoke_crypto::session::{Session, SessionError, Timer};

use crate::engine::{EngineError, OutgoingFrame, TransferEngine};
use crate::events::{Failure, FailureCode};
use crate::storage::{ReceiveSink, SendSource};

/// Why [`pump`] stopped early.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriveError {
    /// The session failed or closed; the engine was closed with it and its
    /// unfinished transfers reported as interrupted.
    Session(SessionError),
    /// The engine closed the session (it queued and sent the `Error`).
    Engine(EngineError),
    /// The engine was built for another session than the one it was
    /// driven over; nothing was sent or received, and neither the engine
    /// nor the session changed.
    WrongSession,
}

impl fmt::Display for DriveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(error) => write!(f, "session: {error}"),
            Self::Engine(error) => write!(f, "transfer: {error}"),
            Self::WrongSession => f.write_str("the transfer engine belongs to another session"),
        }
    }
}

impl std::error::Error for DriveError {}

/// How a session failure looks as a transfer failure.
fn session_failure(error: SessionError) -> Failure {
    match error {
        SessionError::PeerError(code) => Failure::peer(FailureCode::from_error_code(code)),
        SessionError::Protocol(code) => Failure::local(FailureCode::from_error_code(code)),
        SessionError::Timeout => Failure::local(FailureCode::Timeout),
        SessionError::Authentication => Failure::local(FailureCode::Authentication),
        _ => Failure::local(FailureCode::SessionEnded),
    }
}

async fn flush<IO, T, K, S, R>(
    session: &mut Session<IO, T>,
    engine: &mut TransferEngine<'_, K, S, R>,
) -> Result<(), DriveError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    T: Timer,
    K: KeyStore,
    S: SendSource,
    R: ReceiveSink,
{
    while let Some(frame) = engine.pop_frame() {
        let sent = match frame {
            OutgoingFrame::Frame { frame_type, body } => session.send(frame_type, &body).await,
            OutgoingFrame::Error(record) => session.send_error(record).await,
        };
        if let Err(error) = sent {
            engine.close(Some(session_failure(error)));
            return Err(DriveError::Session(error));
        }
    }
    Ok(())
}

/// Moves `engine` one step forward on `session`: sends queued frames, runs
/// timers, and then, unless events are already waiting
/// ([`TransferEngine::pop_event`]) or the session's monotonic clock reached
/// `until`, waits for the next frame until the engine's next deadline (or
/// `until`) and hands it to the engine. Call it in a loop, handling events
/// and local intent between calls.
///
/// The engine must have been built for `session` (its
/// [`TransferEngine::session`] is `session.transfer_binding()`): the
/// signed Accept and receipt are checked against the engine's binding, so
/// an engine driven over another session would accept records bound to
/// the first one (§7.3).
///
/// # Errors
///
/// [`DriveError::WrongSession`] if the engine belongs to another session
/// (checked first; nothing happens then). [`DriveError::Session`] when the
/// session fails or closes, and [`DriveError::Engine`] when the engine
/// closed it after a violation or a deadline; in both cases the engine is
/// closed.
pub async fn pump<IO, T, K, S, R>(
    session: &mut Session<IO, T>,
    engine: &mut TransferEngine<'_, K, S, R>,
    until: Duration,
) -> Result<(), DriveError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    T: Timer,
    K: KeyStore,
    S: SendSource,
    R: ReceiveSink,
{
    if session.transfer_binding() != *engine.session() {
        return Err(DriveError::WrongSession);
    }
    flush(session, engine).await?;
    if engine.is_closed() {
        return Err(DriveError::Engine(EngineError::Closed));
    }
    let now = session.now();
    let polled = engine.poll(now);
    let flushed = flush(session, engine).await;
    polled.map_err(DriveError::Engine)?;
    flushed?;
    if engine.has_events() || now >= until {
        return Ok(());
    }
    let deadline = engine.next_deadline(now).min(until);
    match session.recv_until(deadline).await {
        Ok(Some(frame)) => {
            let handled = engine.handle_frame(frame.frame_type(), frame.body(), session.now());
            // Send replies (or the closing Error) at once.
            let flushed = flush(session, engine).await;
            handled.map_err(DriveError::Engine)?;
            flushed
        }
        Ok(None) => Ok(()),
        Err(error) => {
            engine.close(Some(session_failure(error)));
            Err(DriveError::Session(error))
        }
    }
}
