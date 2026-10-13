//! Terminal transfer states and the frames still allowed after them.
//!
//! When this side ends a transfer (cancel, reject, a transfer-scoped
//! error, expiry), the peer may already have frames for it in flight on the
//! ordered stream. Those are discarded without processing, up to what the
//! peer could legitimately have sent before seeing the end (§7.6: in-flight
//! chunks up to the prior outstanding count); anything beyond that is
//! `STATE`. A `CancelAck` proves the peer saw the cancel, so after it
//! nothing more is allowed. When the peer ended the transfer, it sends
//! nothing more for it, so nothing is allowed.

use core::time::Duration;

use todoke_proto::transfer::Cancel;

/// How a transfer ended in this session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    /// Receiver: every selected file published and the receipt sent.
    Completed,
    /// Sender: the signed receipt verified.
    Delivered,
    /// Sender: `Complete` arrived but no valid receipt in time.
    Unconfirmed,
    /// The receiver rejected the offer.
    Rejected,
    /// Either side cancelled; the ID is permanently unusable.
    Cancelled,
    /// The Accept (or the manifest, before consent) expired.
    Expired,
    /// A transfer-scoped error ended it.
    Failed,
    /// The session ended under it; it may resume in a fresh session.
    Interrupted,
}

/// In-flight frames of each kind that may still arrive and be discarded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Late {
    /// Receiver: manifest bytes the sender may still send.
    pub(super) manifest_bytes: u64,
    /// Receiver: `FileKey`s.
    pub(super) file_keys: u32,
    /// Receiver: `Chunk`s, at most the outstanding requests (§7.6).
    pub(super) chunks: u32,
    /// Receiver: `ResumeQuery`s.
    pub(super) resume_queries: u32,
    /// Sender: `Accept`s.
    pub(super) accepts: u32,
    /// Sender: `Reject`s.
    pub(super) rejects: u32,
    /// Sender: `ChunkRequest`s.
    pub(super) requests: u32,
    /// Sender: `ResumeStatus`es.
    pub(super) resume_statuses: u32,
    /// Sender: `Complete`s.
    pub(super) completes: u32,
    /// Sender: `DeliveryReceipt`s.
    pub(super) receipts: u32,
}

/// Which allowance a late frame draws on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LateKind {
    FileKey,
    Chunk,
    ResumeQuery,
    Accept,
    Reject,
    Request,
    ResumeStatus,
    Complete,
    Receipt,
}

impl Late {
    /// Takes one frame of `kind` from the allowance.
    pub(super) fn take(&mut self, kind: LateKind) -> bool {
        let slot = match kind {
            LateKind::FileKey => &mut self.file_keys,
            LateKind::Chunk => &mut self.chunks,
            LateKind::ResumeQuery => &mut self.resume_queries,
            LateKind::Accept => &mut self.accepts,
            LateKind::Reject => &mut self.rejects,
            LateKind::Request => &mut self.requests,
            LateKind::ResumeStatus => &mut self.resume_statuses,
            LateKind::Complete => &mut self.completes,
            LateKind::Receipt => &mut self.receipts,
        };
        if *slot == 0 {
            false
        } else {
            *slot -= 1;
            true
        }
    }

    /// Takes `len` manifest bytes from the allowance.
    pub(super) fn take_manifest(&mut self, len: u64) -> bool {
        if len > self.manifest_bytes {
            false
        } else {
            self.manifest_bytes -= len;
            true
        }
    }
}

/// A cancel this side sent and the peer has not acknowledged yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PendingCancel {
    pub(super) record: Cancel,
    pub(super) deadline: Duration,
}

/// A transfer that ended in this session. No reopening (§11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Ended {
    pub(super) outcome: Outcome,
    pub(super) manifest_hash: [u8; 32],
    pub(super) late: Late,
    pub(super) cancel: Option<PendingCancel>,
}

impl Ended {
    pub(super) const fn new(outcome: Outcome, manifest_hash: [u8; 32], late: Late) -> Self {
        Self {
            outcome,
            manifest_hash,
            late,
            cancel: None,
        }
    }
}
