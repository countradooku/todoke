//! Links: untrusted, ordered, reliable byte pipes (PROTOCOL §5) and what is
//! known about them.

use core::fmt;
use core::time::Duration;
use std::net::SocketAddr;

use futures_io::{AsyncRead, AsyncWrite};

/// The kind of pipe a link is. Every kind carries the same authenticated
/// session (§4): a link's kind decides only how fast it is likely to be,
/// never which mode, suite, or authentication a session uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LinkKind {
    /// TCP on the local network, found through mDNS (§9).
    Lan,
    /// A tunnel through an untrusted relay (§10).
    Relay,
    /// An in-memory pipe with simulated latency, bandwidth, and loss
    /// (tests only).
    #[cfg(test)]
    Simulated,
}

impl LinkKind {
    /// A rough order of expected throughput: a higher rank is preferred
    /// when links are raced and is a reason to migrate.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Lan => 10,
            Self::Relay => 1,
            #[cfg(test)]
            Self::Simulated => 10,
        }
    }
}

/// What is known about a link. Addresses are untrusted routing data, and
/// none of this is evidence of who is at the other end.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LinkInfo {
    kind: LinkKind,
    local: Option<SocketAddr>,
    remote: Option<SocketAddr>,
    latency: Option<Duration>,
    bandwidth: Option<u64>,
}

impl LinkInfo {
    /// Information about a link of `kind`.
    #[must_use]
    pub const fn new(kind: LinkKind) -> Self {
        Self {
            kind,
            local: None,
            remote: None,
            latency: None,
            bandwidth: None,
        }
    }

    /// With the local and remote socket addresses.
    #[must_use]
    pub const fn with_addresses(mut self, local: SocketAddr, remote: SocketAddr) -> Self {
        self.local = Some(local);
        self.remote = Some(remote);
        self
    }

    /// With an estimated round-trip latency (for TCP, the connection setup
    /// time: one round trip).
    #[must_use]
    pub const fn with_latency(mut self, latency: Duration) -> Self {
        self.latency = Some(latency);
        self
    }

    /// With an estimated bandwidth in bytes per second.
    #[must_use]
    pub const fn with_bandwidth(mut self, bytes_per_second: u64) -> Self {
        self.bandwidth = Some(bytes_per_second);
        self
    }

    /// The link's kind.
    #[must_use]
    pub const fn kind(&self) -> LinkKind {
        self.kind
    }

    /// The local socket address, if the link has one.
    #[must_use]
    pub const fn local(&self) -> Option<SocketAddr> {
        self.local
    }

    /// The remote socket address, if the link has one; untrusted.
    #[must_use]
    pub const fn remote(&self) -> Option<SocketAddr> {
        self.remote
    }

    /// The estimated round-trip latency, if measured.
    #[must_use]
    pub const fn latency(&self) -> Option<Duration> {
        self.latency
    }

    /// The estimated bandwidth in bytes per second, if known.
    #[must_use]
    pub const fn bandwidth(&self) -> Option<u64> {
        self.bandwidth
    }
}

/// Addresses are left out: they identify the user's network and devices.
impl fmt::Debug for LinkInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkInfo")
            .field("kind", &self.kind)
            .field("latency", &self.latency)
            .field("bandwidth", &self.bandwidth)
            .finish_non_exhaustive()
    }
}

/// An ordered, reliable byte pipe a session runs over. It is untrusted:
/// the session authenticates the peer and protects every byte (§4, §5).
/// A link carries exactly one session; a session never moves to another
/// link (§5: moving requires a fresh session and a fresh Accept).
pub trait Link: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    /// What is known about this link.
    fn info(&self) -> &LinkInfo;
}
