//! Capabilities (§6): fixed locally per session, exchanged exactly once in
//! each direction before any transfer frame, and negotiated into the
//! content suite and the request budget.

use core::fmt;

use todoke_crypto::content::{ContentSuite, ContentSuites};
use todoke_proto::session::ErrorCode;
use todoke_proto::transfer::{Capabilities, ManifestLimits};

/// Why local capabilities were refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilitiesError {
    /// The suite set lacks `XChaCha` (required in v1) or advertises AES
    /// although this device has no approved AES implementation (§6).
    Suites,
}

impl fmt::Display for CapabilitiesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("content suites are not supported by this device")
    }
}

impl std::error::Error for CapabilitiesError {}

/// This device's Capabilities for one session. Fixed before the peer's
/// arrive (§6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalCapabilities {
    record: Capabilities,
}

impl LocalCapabilities {
    /// The protocol maximums and this device's suites
    /// ([`ContentSuites::local`]).
    #[must_use]
    pub fn defaults() -> Self {
        let maximums = Capabilities::PROTOCOL_MAXIMUMS;
        // The local suite bits are always defined ones; the fallback (XChaCha
        // only) is never used.
        let record = maximums
            .with_content_suites(ContentSuites::local().bits())
            .unwrap_or(maximums);
        Self { record }
    }

    /// Smaller local quotas (§13: implementations MAY impose smaller
    /// limits). The suite set must contain `XChaCha` and nothing this
    /// device cannot run.
    ///
    /// # Errors
    ///
    /// [`CapabilitiesError::Suites`].
    pub fn new(record: Capabilities) -> Result<Self, CapabilitiesError> {
        let suites =
            ContentSuites::from_bits(record.content_suites()).ok_or(CapabilitiesError::Suites)?;
        let local = ContentSuites::local();
        if suites.bits() & !local.bits() != 0 {
            return Err(CapabilitiesError::Suites);
        }
        Ok(Self { record })
    }

    /// The record sent to the peer.
    #[must_use]
    pub const fn record(&self) -> &Capabilities {
        &self.record
    }
}

/// Both peers' Capabilities and what follows from them (§6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Negotiated {
    local: Capabilities,
    peer: Capabilities,
    suite: ContentSuite,
}

impl Negotiated {
    /// Negotiates with the peer's record.
    ///
    /// # Errors
    ///
    /// `UNSUPPORTED` if the peer's suite set lacks `XChaCha` or there is no
    /// common suite (§6: rejected, never retried with less).
    pub(crate) fn new(local: &LocalCapabilities, peer: Capabilities) -> Result<Self, ErrorCode> {
        let ours = ContentSuites::from_bits(local.record.content_suites())
            .ok_or(ErrorCode::UNSUPPORTED)?;
        let theirs =
            ContentSuites::from_bits(peer.content_suites()).ok_or(ErrorCode::UNSUPPORTED)?;
        let suite = ours.select(theirs).ok_or(ErrorCode::UNSUPPORTED)?;
        Ok(Self {
            local: local.record,
            peer,
            suite,
        })
    }

    /// The content suite every new file must use (§6).
    #[must_use]
    pub const fn suite(&self) -> ContentSuite {
        self.suite
    }

    /// Whether both peers advertised `suite`. A resumed transfer keeps its
    /// original suite if so, even where new files use another (§6).
    #[must_use]
    pub fn supports(&self, suite: ContentSuite) -> bool {
        [&self.local, &self.peer].into_iter().all(|record| {
            ContentSuites::from_bits(record.content_suites())
                .is_some_and(|suites| suites.contains(suite))
        })
    }

    /// This device's record.
    #[must_use]
    pub const fn local(&self) -> &Capabilities {
        &self.local
    }

    /// The peer's record.
    #[must_use]
    pub const fn peer(&self) -> &Capabilities {
        &self.peer
    }

    /// How many `ChunkRequest`s this device may have outstanding as a
    /// receiver: `min(own, peer)` (§7.4).
    #[must_use]
    pub fn request_limit(&self) -> usize {
        usize::from(
            self.local
                .max_outstanding_chunks()
                .min(self.peer.max_outstanding_chunks()),
        )
    }

    /// Limits for manifests this device receives: its own Capabilities.
    #[must_use]
    pub fn receive_limits(&self) -> ManifestLimits {
        ManifestLimits::new(
            self.local.max_entries(),
            self.local.max_file_bytes(),
            self.local.max_transfer_bytes(),
        )
    }

    /// Limits for manifests this device sends: the peer's Capabilities.
    #[must_use]
    pub fn send_limits(&self) -> ManifestLimits {
        ManifestLimits::new(
            self.peer.max_entries(),
            self.peer.max_file_bytes(),
            self.peer.max_transfer_bytes(),
        )
    }
}
