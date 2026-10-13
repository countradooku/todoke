//! Racing connections to a peer's candidate addresses (RFC 8305 style).
//!
//! Only connections race, never sessions: one device pair has at most one
//! session attempt at a time (PROTOCOL §4), and every session commits a
//! PSK ratchet step that an interrupted handshake can leave uncertain,
//! which disables the pairing (§4.4). So the first link to connect wins,
//! the others are dropped before any session byte is sent on them, and the
//! one session handshake runs on the winner.
//!
//! Attempts start in preference order, the next one after
//! [`RaceConfig::attempt_delay`] or as soon as the previous one fails. The
//! race is bounded in candidates and time, as direct candidates are in
//! §10 (at most 4 addresses, 5 seconds).

use core::fmt;
use core::future::Future;
use core::pin::Pin;
use core::task::Poll;
use core::time::Duration;
use std::io;
use std::net::SocketAddr;

use tokio::time::{Instant, Sleep};

use crate::link::{Link, LinkKind};

/// At most this many candidates are tried (§10's direct-candidate bound).
pub const MAX_CANDIDATES: usize = 4;

/// A way to reach a peer: an untrusted hint, typically from discovery.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Candidate {
    kind: LinkKind,
    address: SocketAddr,
}

impl Candidate {
    /// A candidate of `kind` at `address`.
    #[must_use]
    pub const fn new(kind: LinkKind, address: SocketAddr) -> Self {
        Self { kind, address }
    }

    /// The link kind.
    #[must_use]
    pub const fn kind(&self) -> LinkKind {
        self.kind
    }

    /// The address; untrusted.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }
}

/// The address is left out: it identifies the user's network.
impl fmt::Debug for Candidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Candidate")
            .field("kind", &self.kind)
            .field("ipv6", &self.address.is_ipv6())
            .finish_non_exhaustive()
    }
}

/// Opens links to candidates.
pub trait Connector {
    /// The links it opens.
    type Link: Link;

    /// Opens a link to `candidate`. Policy checks (which addresses may be
    /// contacted) belong here, before any packet is sent.
    fn connect(&self, candidate: Candidate) -> impl Future<Output = io::Result<Self::Link>> + Send;
}

/// Race timing and bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RaceConfig {
    /// How long an attempt runs alone before the next one starts (RFC 8305
    /// §5 recommends 250 ms).
    pub attempt_delay: Duration,
    /// The whole race's deadline.
    pub deadline: Duration,
    /// How many candidates are tried, at most [`MAX_CANDIDATES`].
    pub max_candidates: usize,
}

impl Default for RaceConfig {
    fn default() -> Self {
        Self {
            attempt_delay: Duration::from_millis(250),
            deadline: Duration::from_secs(5),
            max_candidates: MAX_CANDIDATES,
        }
    }
}

/// Why no link was opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RaceError {
    /// There was nothing to try.
    NoCandidates,
    /// Every attempt failed; the error kinds, in the order they failed.
    Failed(Vec<io::ErrorKind>),
    /// The deadline passed first.
    Timeout,
}

impl fmt::Display for RaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCandidates => f.write_str("no candidate to connect to"),
            Self::Failed(kinds) => write!(f, "every connection attempt failed ({})", kinds.len()),
            Self::Timeout => f.write_str("connecting timed out"),
        }
    }
}

impl std::error::Error for RaceError {}

/// The order attempts start in: higher-ranked kinds first, then (RFC 8305
/// §4) alternating address families starting with IPv6, keeping the given
/// order within a family; duplicates dropped; at most `max` (and at most
/// [`MAX_CANDIDATES`]).
#[must_use]
pub fn order(candidates: &[Candidate], max: usize) -> Vec<Candidate> {
    let mut unique: Vec<Candidate> = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        if !unique.contains(candidate) {
            unique.push(*candidate);
        }
    }
    // Stable: within a rank, the given order is kept.
    unique.sort_by_key(|candidate| core::cmp::Reverse(candidate.kind.rank()));
    let mut ordered = Vec::with_capacity(unique.len());
    let mut start = 0;
    while start < unique.len() {
        let rank = unique[start].kind.rank();
        let end = unique[start..]
            .iter()
            .position(|candidate| candidate.kind.rank() != rank)
            .map_or(unique.len(), |offset| start + offset);
        let group = &unique[start..end];
        let mut v6 = group.iter().filter(|c| c.address.is_ipv6());
        let mut v4 = group.iter().filter(|c| c.address.is_ipv4());
        loop {
            match (v6.next(), v4.next()) {
                (None, None) => break,
                (a, b) => ordered.extend(a.into_iter().chain(b).copied()),
            }
        }
        start = end;
    }
    ordered.truncate(max.min(MAX_CANDIDATES));
    ordered
}

type Attempt<'a, L> = Pin<Box<dyn Future<Output = io::Result<L>> + Send + 'a>>;

/// Connects to the first candidate that answers (see the module notes).
/// Losing attempts are dropped, which closes any connection they opened.
///
/// # Errors
///
/// [`RaceError`].
pub async fn race<C: Connector + Sync>(
    connector: &C,
    candidates: &[Candidate],
    config: &RaceConfig,
) -> Result<C::Link, RaceError> {
    let queue = order(candidates, config.max_candidates);
    if queue.is_empty() {
        return Err(RaceError::NoCandidates);
    }
    let mut queue = queue.into_iter();
    let mut running: Vec<Attempt<'_, C::Link>> = Vec::new();
    let mut failures = Vec::new();
    let mut deadline = Box::pin(tokio::time::sleep(config.deadline));
    let mut next_start: Pin<Box<Sleep>> = Box::pin(tokio::time::sleep(Duration::ZERO));
    let mut more = true;
    core::future::poll_fn(|cx| {
        loop {
            if deadline.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(RaceError::Timeout));
            }
            let mut started = false;
            if more && next_start.as_mut().poll(cx).is_ready() {
                if let Some(candidate) = queue.next() {
                    running.push(Box::pin(connector.connect(candidate)));
                    next_start
                        .as_mut()
                        .reset(Instant::now() + config.attempt_delay);
                    started = true;
                } else {
                    more = false;
                }
            }
            let mut failed = false;
            let mut index = 0;
            while index < running.len() {
                match running[index].as_mut().poll(cx) {
                    Poll::Ready(Ok(link)) => return Poll::Ready(Ok(link)),
                    Poll::Ready(Err(error)) => {
                        failures.push(error.kind());
                        drop(running.swap_remove(index));
                        failed = true;
                    }
                    Poll::Pending => index += 1,
                }
            }
            if failed && more {
                // A failure starts the next attempt at once.
                next_start.as_mut().reset(Instant::now());
            }
            if running.is_empty() && !more {
                return Poll::Ready(Err(RaceError::Failed(core::mem::take(&mut failures))));
            }
            if !started && !failed {
                return Poll::Pending;
            }
        }
    })
    .await
}

#[cfg(test)]
mod tests;
