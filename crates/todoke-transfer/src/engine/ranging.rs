//! Pointing in the session (PROTOCOL §10.4): this engine checks and
//! sequences the ranging records; the caller ranges (the platform's UWB)
//! and decides when. Ranging is an interface hint only.
//!
//! Each side sends `RangingReady` at most once, after Capabilities, if it
//! can range as a controlee now. A controller may start only after the
//! peer's `RangingReady`, with a configuration the peer announced, at most
//! [`MAX_STARTS`] times per session, never while one runs. The controlee
//! accepts the running one once, with its own address for it (never the
//! controller's). Either side may stop the running one, by its session ID.
//! A ranging ends by itself [`MAX_RANGING_SECONDS`] after its start,
//! accepted or not. Anything out of line from the peer is STATE.

use core::time::Duration;

use todoke_proto::ranging::{
    MAX_RANGING_SECONDS, MAX_STARTS, RangingAccept, RangingReady, RangingStart, RangingStop,
};

use super::{Violation, violation};
use crate::events::FailureCode;

/// Why a local pointing step was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangingError {
    /// The session is not ready (Capabilities not exchanged) or closed.
    NotReady,
    /// `RangingReady` was already sent in this session.
    AlreadySent,
    /// The peer cannot range (no `RangingReady`), or not with this
    /// configuration.
    PeerNotReady,
    /// A ranging runs already, or this session used its starts.
    Busy,
    /// No ranging with that session ID runs (or not one this side may
    /// accept: its own, or one accepted already).
    NotRunning,
    /// Not an address for this ranging (0x0000, 0xffff, or the
    /// controller's).
    Address,
}

impl core::fmt::Display for RangingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NotReady => "the session is not ready for pointing",
            Self::AlreadySent => "ranging readiness was already sent in this session",
            Self::PeerNotReady => "the peer cannot range with this configuration",
            Self::Busy => "a ranging runs already, or the session used its starts",
            Self::NotRunning => "no such ranging runs",
            Self::Address => "not a UWB address for this ranging",
        })
    }
}

impl std::error::Error for RangingError {}

/// The ranging running in the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Running {
    session_id: u32,
    ends_at: Duration,
    /// This side started it.
    controller: bool,
    /// The controller's address.
    controller_address: u16,
    accepted: bool,
}

/// The session's pointing.
#[derive(Debug, Default)]
pub(crate) struct Pointing {
    /// This side's readiness (its controlee address and configurations).
    own: Option<RangingReady>,
    /// The peer's.
    peer: Option<RangingReady>,
    starts: u8,
    running: Option<Running>,
}

/// What a step produced, for the engine to report.
pub(crate) enum Step {
    PeerReady(RangingReady),
    Requested(Box<RangingStart>),
    Accepted(RangingAccept),
    Stopped(u32),
}

impl Pointing {
    pub(crate) fn send_ready(&mut self, ready: RangingReady) -> Result<(), RangingError> {
        if self.own.is_some() {
            return Err(RangingError::AlreadySent);
        }
        self.own = Some(ready);
        Ok(())
    }

    pub(crate) fn on_ready(&mut self, body: &[u8]) -> Result<Step, Violation> {
        let ready = RangingReady::decode(body).map_err(|_| violation(FailureCode::Malformed))?;
        if self.peer.replace(ready).is_some() {
            return Err(violation(FailureCode::State));
        }
        Ok(Step::PeerReady(ready))
    }

    fn take_start(&mut self, start: &RangingStart, controller: bool, now: Duration) -> bool {
        if self.running.is_some() || self.starts >= MAX_STARTS {
            return false;
        }
        self.starts += 1;
        self.running = Some(Running {
            session_id: start.session_id,
            ends_at: now + Duration::from_secs(MAX_RANGING_SECONDS),
            controller,
            controller_address: start.controller,
            accepted: false,
        });
        true
    }

    /// This side starts ranging as the controller.
    pub(crate) fn start(
        &mut self,
        start: &RangingStart,
        now: Duration,
    ) -> Result<(), RangingError> {
        let peer = self.peer.ok_or(RangingError::PeerNotReady)?;
        if peer.configs & start.config == 0 {
            return Err(RangingError::PeerNotReady);
        }
        if !self.take_start(start, true, now) {
            return Err(RangingError::Busy);
        }
        Ok(())
    }

    /// The peer starts ranging with this side as the controlee.
    pub(crate) fn on_start(&mut self, body: &[u8], now: Duration) -> Result<Step, Violation> {
        let start = RangingStart::decode(body).map_err(|_| violation(FailureCode::Malformed))?;
        let state = || violation(FailureCode::State);
        let own = self.own.ok_or_else(state)?;
        if own.configs & start.config == 0 || !self.take_start(&start, false, now) {
            return Err(state());
        }
        Ok(Step::Requested(Box::new(start)))
    }

    /// This side, the controlee, accepts the running ranging at its
    /// address for it.
    pub(crate) fn accept(
        &mut self,
        session_id: u32,
        controlee: u16,
    ) -> Result<RangingAccept, RangingError> {
        let running = self
            .running
            .as_mut()
            .filter(|running| {
                running.session_id == session_id && !running.controller && !running.accepted
            })
            .ok_or(RangingError::NotRunning)?;
        let accept = RangingAccept {
            session_id,
            controlee,
        };
        if controlee == running.controller_address
            || RangingAccept::decode(&accept.encode()).is_err()
        {
            return Err(RangingError::Address);
        }
        running.accepted = true;
        Ok(accept)
    }

    /// The peer, the controlee, accepts the ranging this side started.
    pub(crate) fn on_accept(&mut self, body: &[u8]) -> Result<Step, Violation> {
        let accept = RangingAccept::decode(body).map_err(|_| violation(FailureCode::Malformed))?;
        let running = self
            .running
            .as_mut()
            .filter(|running| {
                running.session_id == accept.session_id && running.controller && !running.accepted
            })
            .ok_or_else(|| violation(FailureCode::State))?;
        if accept.controlee == running.controller_address {
            return Err(violation(FailureCode::Malformed));
        }
        running.accepted = true;
        Ok(Step::Accepted(accept))
    }

    /// This side stops the running ranging.
    pub(crate) fn stop(&mut self, session_id: u32) -> Result<RangingStop, RangingError> {
        match self.running {
            Some(running) if running.session_id == session_id => {
                self.running = None;
                Ok(RangingStop { session_id })
            }
            _ => Err(RangingError::NotRunning),
        }
    }

    /// The peer stops the running ranging.
    pub(crate) fn on_stop(&mut self, body: &[u8]) -> Result<Step, Violation> {
        let stop = RangingStop::decode(body).map_err(|_| violation(FailureCode::Malformed))?;
        match self.running {
            Some(running) if running.session_id == stop.session_id => {
                self.running = None;
                Ok(Step::Stopped(stop.session_id))
            }
            _ => Err(violation(FailureCode::State)),
        }
    }

    /// The running ranging, if its time is up, ends: its session ID.
    pub(crate) fn expire(&mut self, now: Duration) -> Option<u32> {
        let running = self.running?;
        (now >= running.ends_at).then(|| {
            self.running = None;
            running.session_id
        })
    }

    /// When the running ranging ends by itself.
    pub(crate) fn deadline(&self) -> Option<Duration> {
        self.running.map(|running| running.ends_at)
    }
}
