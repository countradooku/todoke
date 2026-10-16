//! The events API: what the engine reports to the UI (through the core).
//!
//! Events carry no keys, content, or paths. An offer's names and MIME
//! labels are in [`OfferView`] because the consent prompt must show them;
//! its `Debug` output omits them, so logging an event never records them.

use core::fmt;
use core::time::Duration;
use std::collections::VecDeque;

use todoke_crypto::content::ContentSuite;
use todoke_crypto::identity::Ed25519PublicKey;
use todoke_proto::session::ErrorCode;
use todoke_proto::time::UnixTime;
use todoke_proto::transfer::{CancelReason, EntryKind, RejectReason, TransferId};

use crate::limits::{PROGRESS_INTERVAL, SPEED_WINDOW};

/// Which way a transfer goes, from this device's point of view.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    /// This device receives.
    Incoming,
    /// This device sends.
    Outgoing,
}

/// Who acted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Party {
    /// This device.
    Local,
    /// The peer.
    Peer,
}

/// Why a transfer or the session failed: a stable identifier
/// ([`Self::code`]) and a human-readable message ([`Self::message`]). The
/// §12 protocol codes map one to one; the rest are local.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FailureCode {
    /// A record had the wrong length, encoding, or a reserved value.
    Malformed,
    /// A version, suite, or record type is unsupported.
    Unsupported,
    /// A signature or authentication check failed.
    Authentication,
    /// A record arrived out of order, was replayed, or was unexpected.
    State,
    /// A limit or quota was exceeded.
    Limit,
    /// File content or a key arrived without consent or outside the
    /// selection.
    ConsentRequired,
    /// The manifest was invalid or did not match its hash.
    Manifest,
    /// Content failed verification.
    Integrity,
    /// An authorization, manifest, or binding expired.
    Expired,
    /// A device was revoked.
    Revoked,
    /// Storing or publishing failed.
    Storage,
    /// A deadline passed.
    Timeout,
    /// The pairing state is inconsistent.
    Ratchet,
    /// The transfer cannot be resumed; it needs a new transfer and consent.
    ResumeUnavailable,
    /// The sender's source file changed after the manifest was built.
    SourceChanged,
    /// A local signing key could not be used.
    KeyStore,
    /// The operating system's randomness was unavailable.
    Random,
    /// The session ended for a reason outside the transfer layer.
    SessionEnded,
    /// The peer reported a code this version does not define.
    Unknown,
}

impl FailureCode {
    /// The code for a §12 error code.
    #[must_use]
    pub const fn from_error_code(code: ErrorCode) -> Self {
        match code.get() {
            0x0001 => Self::Malformed,
            0x0002 => Self::Unsupported,
            0x0003 => Self::Authentication,
            0x0004 => Self::State,
            0x0005 => Self::Limit,
            0x0006 => Self::ConsentRequired,
            0x0007 => Self::Manifest,
            0x0008 => Self::Integrity,
            0x0009 => Self::Expired,
            0x000a => Self::Revoked,
            0x000b => Self::Storage,
            0x000c => Self::Timeout,
            0x000d => Self::Ratchet,
            0x000e => Self::ResumeUnavailable,
            _ => Self::Unknown,
        }
    }

    /// The §12 code sent to the peer for this failure, if any.
    #[must_use]
    pub const fn error_code(self) -> Option<ErrorCode> {
        Some(match self {
            Self::Malformed => ErrorCode::MALFORMED,
            Self::Unsupported => ErrorCode::UNSUPPORTED,
            Self::Authentication => ErrorCode::AUTHENTICATION,
            Self::State => ErrorCode::STATE,
            Self::Limit => ErrorCode::LIMIT,
            Self::ConsentRequired => ErrorCode::CONSENT_REQUIRED,
            Self::Manifest => ErrorCode::MANIFEST,
            Self::Integrity => ErrorCode::INTEGRITY,
            Self::Expired => ErrorCode::EXPIRED,
            Self::Revoked => ErrorCode::REVOKED,
            Self::Storage => ErrorCode::STORAGE,
            Self::Timeout => ErrorCode::TIMEOUT,
            Self::Ratchet => ErrorCode::RATCHET,
            Self::ResumeUnavailable => ErrorCode::RESUME_UNAVAILABLE,
            Self::SourceChanged
            | Self::KeyStore
            | Self::Random
            | Self::SessionEnded
            | Self::Unknown => {
                return None;
            }
        })
    }

    /// A stable machine-readable identifier, for UIs and translations.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::Unsupported => "unsupported",
            Self::Authentication => "authentication",
            Self::State => "state",
            Self::Limit => "limit",
            Self::ConsentRequired => "consent_required",
            Self::Manifest => "manifest",
            Self::Integrity => "integrity",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Storage => "storage",
            Self::Timeout => "timeout",
            Self::Ratchet => "ratchet",
            Self::ResumeUnavailable => "resume_unavailable",
            Self::SourceChanged => "source_changed",
            Self::KeyStore => "key_store",
            Self::Random => "random",
            Self::SessionEnded => "session_ended",
            Self::Unknown => "unknown",
        }
    }

    /// A short English explanation.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Malformed => "The other device sent a malformed message.",
            Self::Unsupported => "The other device uses an unsupported protocol feature.",
            Self::Authentication => "A signature or authentication check failed.",
            Self::State => "The other device sent a message out of order.",
            Self::Limit => "A size or quota limit was exceeded.",
            Self::ConsentRequired => "File data arrived without permission and was discarded.",
            Self::Manifest => "The list of files was invalid.",
            Self::Integrity => "File data failed verification and was discarded.",
            Self::Expired => "The permission for this transfer expired.",
            Self::Revoked => "A device was revoked.",
            Self::Storage => "The files could not be stored.",
            Self::Timeout => "The other device stopped responding.",
            Self::Ratchet => "The pairing needs to be renewed.",
            Self::ResumeUnavailable => "This transfer cannot be resumed; send it again.",
            Self::SourceChanged => "A file changed while it was being sent; send it again.",
            Self::KeyStore => "This device's signing key could not be used.",
            Self::Random => "This device could not generate random numbers.",
            Self::SessionEnded => "The connection ended.",
            Self::Unknown => "The other device reported an unknown error.",
        }
    }
}

impl fmt::Display for FailureCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

/// A failure and who reported it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Failure {
    /// What went wrong.
    pub code: FailureCode,
    /// [`Party::Local`] if this device detected it, [`Party::Peer`] if the
    /// peer reported it.
    pub by: Party,
}

impl Failure {
    pub(crate) const fn local(code: FailureCode) -> Self {
        Self {
            code,
            by: Party::Local,
        }
    }

    pub(crate) const fn peer(code: FailureCode) -> Self {
        Self {
            code,
            by: Party::Peer,
        }
    }
}

/// One manifest entry as shown in a consent prompt. Names and MIME labels
/// are untrusted display data; `Debug` omits them.
#[derive(Clone, PartialEq, Eq)]
pub struct OfferEntry {
    /// The entry ID (selections name file IDs).
    pub id: u32,
    /// The parent directory's ID, 0 for the top level.
    pub parent: u32,
    /// File or directory.
    pub kind: EntryKind,
    /// The name component.
    pub name: String,
    /// The MIME label, empty for directories. It grants nothing.
    pub mime: String,
    /// The size in bytes, 0 for directories.
    pub size: u64,
}

impl fmt::Debug for OfferEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OfferEntry")
            .field("id", &self.id)
            .field("parent", &self.parent)
            .field("kind", &self.kind)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

/// A validated incoming offer, for the consent prompt (§7.1, §7.2).
#[derive(Clone, PartialEq, Eq)]
pub struct OfferView {
    /// The transfer.
    pub transfer_id: TransferId,
    /// The authenticated sender's full device key.
    pub sender: Ed25519PublicKey,
    /// When the sender built the manifest.
    pub created_at: UnixTime,
    /// When the manifest expires.
    pub expires_at: UnixTime,
    /// The manifest's hash (§7.1): what the Accept and the receipt bind.
    pub manifest_hash: [u8; 32],
    /// Regular files.
    pub file_count: u32,
    /// Sum of all file sizes.
    pub total_bytes: u64,
    /// Entries in manifest order.
    pub entries: Vec<OfferEntry>,
    /// For a transfer that resumes after an interruption: the earlier
    /// selection, which a new Accept must repeat exactly (§7.5). Consent
    /// is still needed: a fresh Accept for this session.
    pub resume_selection: Option<Vec<u32>>,
}

impl fmt::Debug for OfferView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OfferView")
            .field("file_count", &self.file_count)
            .field("total_bytes", &self.total_bytes)
            .field("entries", &self.entries.len())
            .field("resumable", &self.resume_selection.is_some())
            .finish_non_exhaustive()
    }
}

/// Transfer progress (§7.4): verified-and-stored bytes for a receiver,
/// sent bytes for a sender. A sender counts each segment once, plus, for
/// a resumed transfer, what the receiver claims to hold already, which is
/// a hint, not proof (§7.5); its `files_done` counts only files whose
/// every segment it sent in this session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    /// The transfer.
    pub transfer_id: TransferId,
    /// Which way.
    pub direction: Direction,
    /// Bytes done, of the selected files.
    pub bytes_done: u64,
    /// Bytes in the selected files.
    pub bytes_total: u64,
    /// Files done.
    pub files_done: u32,
    /// Files selected.
    pub files_total: u32,
    /// Recent throughput.
    pub bytes_per_second: u64,
    /// Estimated time left at that throughput, if it is known.
    pub eta: Option<Duration>,
    /// The caller-supplied label of the transport in use (for example
    /// "lan" or "relay"); transports are untrusted pipes.
    pub transport: &'static str,
}

/// Something the UI should know about.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransferEvent {
    /// Both Capabilities were exchanged; transfers may start (§6).
    Ready {
        /// The content suite new files use.
        suite: ContentSuite,
    },
    /// Both sides sent `LinkAbilities` and a link fits (§10.2): the chosen
    /// host may offer it (for a transfer the user started or accepted).
    LinkChosen(todoke_proto::link::LinkChoice),
    /// The host's offer, checked against the choice: join it (or decline)
    /// and answer. It holds the link's secret.
    LinkOffered(Box<todoke_proto::link::LinkOffer>),
    /// The joiner's answer to this side's offer.
    LinkAnswered(todoke_proto::link::LinkAnswer),
    /// The peer can range as a controlee now (§10.4).
    RangingReady(todoke_proto::ranging::RangingReady),
    /// The peer starts ranging with this side as the controlee. It holds
    /// the STS key.
    RangingRequested(Box<todoke_proto::ranging::RangingStart>),
    /// The peer accepts the ranging this side started, at its address:
    /// range now.
    RangingAccepted(todoke_proto::ranging::RangingAccept),
    /// The ranging with this session ID ended (stopped by the peer, or its
    /// time was up).
    RangingStopped {
        /// The ranging session ID.
        session_id: u32,
    },
    /// A validated offer awaits the user's decision (§7.2). Accept or
    /// reject it within 300 seconds.
    OfferReceived(Box<OfferView>),
    /// This device's manifest was queued to the peer.
    OfferSent {
        /// The transfer.
        transfer_id: TransferId,
        /// The manifest's hash (§7.1).
        manifest_hash: [u8; 32],
    },
    /// A verified Accept exists: the receiver signed it, or the sender
    /// verified it.
    Accepted {
        /// The transfer.
        transfer_id: TransferId,
        /// Which way.
        direction: Direction,
        /// Selected files.
        files: u32,
        /// Selected bytes.
        bytes: u64,
    },
    /// The receiver rejected the offer.
    Rejected {
        /// The transfer.
        transfer_id: TransferId,
        /// Which way.
        direction: Direction,
        /// Why.
        reason: RejectReason,
    },
    /// Bytes moved.
    Progress(Progress),
    /// One selected file was verified and published (receiver), or every
    /// one of its segments was sealed and sent in this session (sender; a
    /// receiver's claim to hold segments already never counts, §7.5).
    FileCompleted {
        /// The transfer.
        transfer_id: TransferId,
        /// Which way.
        direction: Direction,
        /// The file.
        file_id: u32,
    },
    /// The receiver published every selected file and sent its signed
    /// receipt.
    Completed {
        /// The transfer.
        transfer_id: TransferId,
        /// When this device finished, on its clock (the receipt's
        /// `completed_at`).
        completed_at: UnixTime,
        /// The ID of the receipt this device signed.
        receipt_id: [u8; 16],
    },
    /// The sender verified the receiver's signed delivery receipt (§7.7).
    DeliveryConfirmed {
        /// The transfer.
        transfer_id: TransferId,
        /// When the receiver finished, on its clock.
        completed_at: UnixTime,
        /// The receipt's ID.
        receipt_id: [u8; 16],
    },
    /// `Complete` arrived but no valid receipt followed in time: delivery
    /// is unconfirmed (§7.7). Never retransfer silently.
    DeliveryUnconfirmed {
        /// The transfer.
        transfer_id: TransferId,
    },
    /// The transfer was cancelled; its ID is permanently unusable (§7.6).
    Cancelled {
        /// The transfer.
        transfer_id: TransferId,
        /// Which way.
        direction: Direction,
        /// Who cancelled.
        by: Party,
        /// Why.
        reason: CancelReason,
    },
    /// The authorization expired; content paused. The transfer may resume
    /// in a fresh session with fresh consent while the manifest is valid
    /// (§7.3).
    Expired {
        /// The transfer.
        transfer_id: TransferId,
        /// Which way.
        direction: Direction,
    },
    /// The session ended mid-transfer. Verified partial content is kept;
    /// the transfer may resume in a fresh session with fresh consent.
    Interrupted {
        /// The transfer.
        transfer_id: TransferId,
        /// Which way.
        direction: Direction,
    },
    /// The transfer failed.
    Failed {
        /// The transfer.
        transfer_id: TransferId,
        /// Which way.
        direction: Direction,
        /// Why.
        failure: Failure,
    },
    /// The session closed; every unfinished transfer was reported as
    /// interrupted or failed first.
    SessionClosed {
        /// Why, if it failed.
        failure: Option<Failure>,
    },
}

/// Measures throughput over a short window for progress events.
#[derive(Clone, Debug)]
pub(crate) struct Meter {
    samples: VecDeque<(Duration, u64)>,
    last_event: Option<Duration>,
}

impl Meter {
    pub(crate) const fn new() -> Self {
        Self {
            samples: VecDeque::new(),
            last_event: None,
        }
    }

    /// Records the cumulative byte count at `now`; returns `(bytes/s, eta)`
    /// if a progress event is due (rate-limited, or forced when done).
    pub(crate) fn record(
        &mut self,
        now: Duration,
        done: u64,
        total: u64,
    ) -> Option<(u64, Option<Duration>)> {
        self.samples.push_back((now, done));
        while self
            .samples
            .front()
            .is_some_and(|&(at, _)| now.saturating_sub(at) > SPEED_WINDOW)
            && self.samples.len() > 2
        {
            self.samples.pop_front();
        }
        let finished = done >= total;
        let due = self
            .last_event
            .is_none_or(|last| now.saturating_sub(last) >= PROGRESS_INTERVAL);
        if !due && !finished {
            return None;
        }
        self.last_event = Some(now);
        let (start, first) = self.samples.front().copied().unwrap_or((now, done));
        let elapsed = now.saturating_sub(start);
        let moved = done.saturating_sub(first);
        let speed = if elapsed.is_zero() {
            0
        } else {
            let per_second = u128::from(moved) * 1_000_000 / elapsed.as_micros().max(1);
            u64::try_from(per_second).unwrap_or(u64::MAX)
        };
        let remaining = total.saturating_sub(done);
        let eta = if remaining == 0 {
            Some(Duration::ZERO)
        } else if speed == 0 {
            None
        } else {
            Some(Duration::from_secs(remaining.div_ceil(speed)))
        };
        Some((speed, eta))
    }
}
