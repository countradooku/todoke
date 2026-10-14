//! The sender's state machine (§7.1, §7.3–§7.5, §7.7, §8, §11).
//!
//! `Offering` (manifest queued; waiting for the receiver's decision) →
//! `Serving` (a verified Accept: `FileKey`s sent, requests answered, resume
//! queries asked) → `AwaitingReceipt` (`Complete` arrived; at most 10
//! seconds for the signed receipt) → ended.
//!
//! No `FileKey` and no content leaves before the receiver's Accept for this
//! session verified (§7.2): sealing needs an `AcceptedFile`, which only the
//! verified Accept hands out, and only for selected files.

use core::time::Duration;
use std::collections::{BTreeMap, VecDeque};

use todoke_crypto::consent::{
    AcceptError, ReceiptError, VerifiedAccept, verify_accept, verify_receipt,
};
use todoke_crypto::content::{ContentError, ContentSealer, FileKeyBody};
use todoke_crypto::identity::KeyStore;
use todoke_proto::session::FrameType;
use todoke_proto::transfer::{
    Accept, CancelReason, Chunk, ChunkRequest, Complete, DeliveryReceipt, MAX_MANIFEST_PART_DATA,
    ManifestPart, ManifestStart, Reject, ResumeQuery, ResumeStatus, TransferId,
};
use zeroize::Zeroizing;

use super::ended::{Ended, Late, LateKind, Outcome};
use super::served::{Recorded, Served};
use super::{EngineError, Handled, Phase, TransferEngine, violation};
use crate::events::{Direction, Failure, FailureCode, Meter, Progress, TransferEvent};
use crate::limits::RECEIPT_TIMEOUT;
use crate::offer::{OfferError, OutgoingOffer};
use crate::storage::{ReceiveSink, SendSource, segment_bytes};

/// One outgoing transfer.
pub(super) enum Outgoing {
    Offering(Box<Offering>),
    Serving(Box<Serving>),
    AwaitingReceipt(Box<AwaitingReceipt>),
    Ended {
        ended: Ended,
        /// Kept for a resume in a fresh session (§7.5) after an
        /// interruption or expiry; gone after a cancel, reject, failure,
        /// or completion.
        resumable: Option<Box<OutgoingOffer>>,
    },
}

pub(super) struct Offering {
    offer: OutgoingOffer,
    /// Whether an earlier session offered it already.
    resumption: bool,
    /// The manifest's expiry on the monotonic clock.
    expiry: Duration,
}

pub(super) struct Serving {
    offer: OutgoingOffer,
    accept: VerifiedAccept,
    sealers: BTreeMap<u32, ContentSealer>,
    last_request_id: u32,
    /// The Accept's expiry on the monotonic clock.
    expiry: Duration,
    /// Files still to ask about, for a resumed transfer (§7.5).
    resume_files: VecDeque<u32>,
    /// The outstanding `ResumeQuery`: file and `from_index`.
    resume_cursor: Option<(u32, u32)>,
    /// Segments sealed and queued in this session, each counted once.
    served: Served,
    /// Bytes of those segments.
    sent_bytes: u64,
    /// Bytes the receiver claimed to hold already (`ResumeStatus`): a
    /// progress hint only, never proof of delivery (§7.5).
    claimed_bytes: u64,
    meter: Meter,
}

pub(super) struct AwaitingReceipt {
    accept: VerifiedAccept,
    deadline: Duration,
}

impl Outgoing {
    pub(super) fn deadline(&self) -> Duration {
        match self {
            Self::Offering(offering) => offering.expiry,
            Self::Serving(serving) => serving.expiry,
            Self::AwaitingReceipt(awaiting) => awaiting.deadline,
            Self::Ended { ended, .. } => {
                ended.cancel.map_or(Duration::MAX, |cancel| cancel.deadline)
            }
        }
    }

    pub(super) fn manifest_hash(&self) -> [u8; 32] {
        match self {
            Self::Offering(offering) => *offering.offer.manifest().hash(),
            Self::Serving(serving) => *serving.accept.manifest_hash(),
            Self::AwaitingReceipt(awaiting) => *awaiting.accept.manifest_hash(),
            Self::Ended { ended, .. } => ended.manifest_hash,
        }
    }

    pub(super) const fn ended(&self) -> Option<&Ended> {
        match self {
            Self::Ended { ended, .. } => Some(ended),
            Self::Offering(_) | Self::Serving(_) | Self::AwaitingReceipt(_) => None,
        }
    }

    pub(super) const fn ended_mut(&mut self) -> Option<&mut Ended> {
        match self {
            Self::Ended { ended, .. } => Some(ended),
            Self::Offering(_) | Self::Serving(_) | Self::AwaitingReceipt(_) => None,
        }
    }

    pub(super) fn take_resumable(&mut self) -> Option<OutgoingOffer> {
        match self {
            Self::Ended {
                ended, resumable, ..
            } if matches!(ended.outcome, Outcome::Interrupted | Outcome::Expired) => {
                resumable.take().map(|offer| *offer)
            }
            _ => None,
        }
    }

    const fn is_active(&self) -> bool {
        !matches!(self, Self::Ended { .. })
    }
}

impl Serving {
    fn late(&self, request_limit: usize) -> Late {
        Late {
            requests: u32::try_from(request_limit).unwrap_or(u32::MAX),
            resume_statuses: u32::from(self.resume_cursor.is_some()),
            completes: 1,
            receipts: 1,
            ..Late::default()
        }
    }
}

/// What to do once the transfer's borrow ends.
enum RequestOutcome {
    Served(Option<Progress>, Option<u32>),
    Expired,
    SourceChanged,
}

impl<K: KeyStore, S: SendSource, R: ReceiveSink> TransferEngine<'_, K, S, R> {
    fn request_limit(&self) -> usize {
        match &self.phase {
            Phase::Ready(negotiated) => negotiated.request_limit(),
            Phase::AwaitingCapabilities { .. } | Phase::Closed => 0,
        }
    }

    /// Offers `offer` to the peer: queues `ManifestStart` and the manifest
    /// in `ManifestPart`s (§7.1). The offer must be from this device to the
    /// session's peer, use the negotiated suite for every file (a transfer
    /// accepted in an earlier session keeps its original suite instead, if
    /// both peers still support it, §6), fit the peer's advertised limits,
    /// and not be expired. To resume after an
    /// interruption, offer the value [`Self::take_resumable`] returned in a
    /// fresh session; the receiver must accept again (§7.5).
    ///
    /// # Errors
    ///
    /// [`EngineError::Offer`].
    pub fn offer(&mut self, mut offer: OutgoingOffer, now: Duration) -> Result<(), EngineError> {
        let Phase::Ready(negotiated) = &self.phase else {
            return Err(EngineError::Offer(OfferError::NotReady));
        };
        let refuse = |error| Err(EngineError::Offer(error));
        let manifest = offer.manifest();
        let transfer_id = *manifest.transfer_id();
        if self.incoming.contains_key(&transfer_id) || self.outgoing.contains_key(&transfer_id) {
            return refuse(OfferError::Duplicate);
        }
        if manifest.sender() != self.session.local_device()
            || manifest.recipient() != self.session.peer_device()
        {
            return refuse(OfferError::Parties);
        }
        // §6: every new file uses the negotiated suite; a resumed transfer
        // must keep its original one, which both peers must support.
        let resumable = offer.was_accepted();
        if manifest.files().iter().any(|file| {
            file.suite() != negotiated.suite() && !(resumable && negotiated.supports(file.suite()))
        }) {
            return refuse(OfferError::Suite);
        }
        let peer = negotiated.peer();
        let schema = manifest.manifest();
        let entries = u32::try_from(schema.entries().len()).unwrap_or(u32::MAX);
        if u32::try_from(manifest.bytes().len()).unwrap_or(u32::MAX) > peer.max_manifest_bytes()
            || entries > peer.max_entries()
            || schema
                .files()
                .any(|file| file.size() > peer.max_file_bytes())
            || schema.total_file_bytes() > peer.max_transfer_bytes()
        {
            return refuse(OfferError::Limits);
        }
        if manifest.expires_at() <= self.wall(now) {
            return refuse(OfferError::Expired);
        }
        let active = self.outgoing.values().filter(|t| t.is_active()).count();
        if active >= crate::limits::MAX_INCOMING_TRANSFERS {
            return refuse(OfferError::Busy);
        }
        let bytes = manifest.bytes();
        let total =
            u32::try_from(bytes.len()).map_err(|_| EngineError::Offer(OfferError::Limits))?;
        let manifest_hash = *manifest.hash();
        let start = ManifestStart::new(transfer_id, manifest_hash, total)
            .map_err(|_| EngineError::Offer(OfferError::Limits))?;
        let mut parts = Vec::new();
        for (index, data) in bytes.chunks(MAX_MANIFEST_PART_DATA).enumerate() {
            let offset = u32::try_from(index * MAX_MANIFEST_PART_DATA)
                .map_err(|_| EngineError::Offer(OfferError::Limits))?;
            let part = ManifestPart::new(transfer_id, offset, data)
                .map_err(|_| EngineError::Offer(OfferError::Limits))?;
            parts.push(part.encode());
        }
        let expiry = self.clock.monotonic_at(manifest.expires_at());
        self.queue(FrameType::MANIFEST_START, start.encode().to_vec());
        for part in parts {
            self.queue(FrameType::MANIFEST_PART, part);
        }
        let resumption = offer.is_resumption();
        offer.mark_offered();
        self.outgoing.insert(
            transfer_id,
            Outgoing::Offering(Box::new(Offering {
                offer,
                resumption,
                expiry,
            })),
        );
        self.event(TransferEvent::OfferSent {
            transfer_id,
            manifest_hash,
        });
        Ok(())
    }

    pub(super) fn on_accept(&mut self, body: &[u8], now: Duration) -> Handled {
        let record = Accept::decode(body).map_err(|_| violation(FailureCode::Malformed))?;
        let transfer_id = *record.body().transfer_id();
        let wall = self.wall(now);
        let offering = match self.outgoing.get_mut(&transfer_id) {
            None => return Err(violation(FailureCode::State)),
            Some(Outgoing::Ended { ended, .. }) => {
                return if ended.late.take(LateKind::Accept) {
                    Ok(())
                } else {
                    Err(violation(FailureCode::State))
                };
            }
            // §7.3: an identical retransmission is idempotent; a
            // conflicting record for a live transfer is STATE.
            Some(Outgoing::Serving(serving)) => {
                return if serving.accept.encoded() == body {
                    Ok(())
                } else {
                    Err(violation(FailureCode::State))
                };
            }
            Some(Outgoing::AwaitingReceipt(awaiting)) => {
                return if awaiting.accept.encoded() == body {
                    Ok(())
                } else {
                    Err(violation(FailureCode::State))
                };
            }
            Some(Outgoing::Offering(offering)) => offering,
        };
        let accept = match verify_accept(body, &self.session, offering.offer.manifest(), wall) {
            Ok(accept) => accept,
            Err(AcceptError::Expiry) => {
                // Already expired (or too far out) at receipt: no content in
                // this session; the manifest may still resume later.
                self.transfer_error(transfer_id, FailureCode::Expired);
                self.end_outgoing(&transfer_id, Outcome::Expired, Late::default(), true);
                self.event(TransferEvent::Expired {
                    transfer_id,
                    direction: Direction::Outgoing,
                });
                return Ok(());
            }
            Err(AcceptError::Malformed(_)) => return Err(violation(FailureCode::Malformed)),
            Err(AcceptError::Signature) => return Err(violation(FailureCode::Authentication)),
            Err(_) => return Err(violation(FailureCode::State)),
        };
        // §7.3: the nonce is unique per session; a replay is STATE.
        if !self.accept_nonces.insert(*accept.nonce()) {
            return Err(violation(FailureCode::State));
        }
        let Some(Outgoing::Offering(offering)) = self.outgoing.remove(&transfer_id) else {
            return Err(violation(FailureCode::State));
        };
        let Offering {
            mut offer,
            resumption,
            ..
        } = *offering;
        offer.mark_accepted();
        let (sealers, keys) = keys_for(&transfer_id, &accept, &mut offer)?;
        let resume_files: VecDeque<u32> = if resumption {
            accept.selection().iter().copied().collect()
        } else {
            VecDeque::new()
        };
        let (count, bytes) = (accept.selected_count(), accept.selected_bytes());
        let expiry = self.clock.monotonic_at(accept.expires_at());
        self.outgoing.insert(
            transfer_id,
            Outgoing::Serving(Box::new(Serving {
                offer,
                accept,
                sealers,
                last_request_id: 0,
                expiry,
                resume_files,
                resume_cursor: None,
                served: Served::default(),
                sent_bytes: 0,
                claimed_bytes: 0,
                meter: Meter::new(),
            })),
        );
        for key in keys {
            self.queue_secret(FrameType::FILE_KEY, key);
        }
        self.event(TransferEvent::Accepted {
            transfer_id,
            direction: Direction::Outgoing,
            files: count,
            bytes,
        });
        Ok(())
    }

    pub(super) fn on_reject(&mut self, body: &[u8]) -> Handled {
        let record = Reject::decode(body).map_err(|_| violation(FailureCode::Malformed))?;
        let transfer_id = *record.transfer_id();
        match self.outgoing.get_mut(&transfer_id) {
            Some(Outgoing::Offering(offering)) => {
                if offering.offer.manifest().hash() != record.manifest_hash() {
                    return Err(violation(FailureCode::State));
                }
            }
            Some(Outgoing::Ended { ended, .. }) => {
                return if ended.late.take(LateKind::Reject) {
                    Ok(())
                } else {
                    Err(violation(FailureCode::State))
                };
            }
            _ => return Err(violation(FailureCode::State)),
        }
        self.end_outgoing(&transfer_id, Outcome::Rejected, Late::default(), false);
        self.event(TransferEvent::Rejected {
            transfer_id,
            direction: Direction::Outgoing,
            reason: record.reason(),
        });
        Ok(())
    }

    pub(super) fn on_chunk_request(&mut self, body: &[u8], now: Duration) -> Handled {
        let request = ChunkRequest::decode(body).map_err(|_| violation(FailureCode::Malformed))?;
        let transfer_id = *request.transfer_id();
        let transport = self.config.transport;
        let serving = match self.outgoing.get_mut(&transfer_id) {
            Some(Outgoing::Serving(serving)) => serving,
            Some(Outgoing::Ended { ended, .. }) => {
                return if ended.late.take(LateKind::Request) {
                    Ok(())
                } else {
                    Err(violation(FailureCode::State))
                };
            }
            _ => return Err(violation(FailureCode::State)),
        };
        let outcome = if now >= serving.expiry {
            RequestOutcome::Expired
        } else {
            if request.accept_hash() != serving.accept.accept_hash()
                || request.request_id() <= serving.last_request_id
            {
                return Err(violation(FailureCode::State));
            }
            serving.last_request_id = request.request_id();
            let file_id = request.file_id();
            let Some(sealer) = serving.sealers.get(&file_id) else {
                // A request for a file outside the selection.
                return Err(violation(FailureCode::ConsentRequired));
            };
            let index = request.segment_index();
            let size = sealer.binding().layout().size();
            let count = sealer.binding().layout().count();
            if index >= count {
                return Err(violation(FailureCode::State));
            }
            let ciphertext_or = match self.source.open(&transfer_id, file_id) {
                Ok((content, outboard)) => sealer.seal_segment(index, content, outboard),
                Err(_) => Err(ContentError::SourceChanged),
            };
            match ciphertext_or {
                Ok(ciphertext) => {
                    let chunk = Chunk::new(
                        transfer_id,
                        *serving.accept.accept_hash(),
                        request.request_id(),
                        file_id,
                        index,
                        &ciphertext,
                    )
                    .map_err(|_| violation(FailureCode::State))?;
                    self.frames.push_back(super::OutgoingFrame::Frame {
                        frame_type: FrameType::CHUNK,
                        body: Zeroizing::new(chunk.encode()),
                    });
                    // A segment counts once, however often it is requested.
                    let recorded = serving.served.record(file_id, index, count);
                    if recorded != Recorded::Unchanged {
                        serving.sent_bytes = serving
                            .sent_bytes
                            .saturating_add(segment_bytes(size, index));
                    }
                    let finished = (recorded == Recorded::Completed).then_some(file_id);
                    let progress = progress_of(&transfer_id, serving, now, transport);
                    RequestOutcome::Served(progress, finished)
                }
                Err(ContentError::SegmentOutOfRange) => return Err(violation(FailureCode::State)),
                Err(_) => RequestOutcome::SourceChanged,
            }
        };
        match outcome {
            RequestOutcome::Served(progress, finished) => {
                if let Some(file_id) = finished {
                    self.event(TransferEvent::FileCompleted {
                        transfer_id,
                        direction: Direction::Outgoing,
                        file_id,
                    });
                }
                if let Some(progress) = progress {
                    self.event(TransferEvent::Progress(progress));
                }
            }
            RequestOutcome::Expired => {
                // §7.3: expiry pauses content at once; tell the receiver.
                self.transfer_error(transfer_id, FailureCode::Expired);
                self.expire_outgoing(&transfer_id);
                if let Some(ended) = self.ended_mut(&transfer_id) {
                    ended.late.take(LateKind::Request);
                }
            }
            RequestOutcome::SourceChanged => {
                // §8: a changed source needs a new transfer and consent.
                self.event(TransferEvent::Failed {
                    transfer_id,
                    direction: Direction::Outgoing,
                    failure: Failure::local(FailureCode::SourceChanged),
                });
                self.cancel(&transfer_id, CancelReason::Storage, now)
                    .map_err(|_| violation(FailureCode::Random))?;
            }
        }
        Ok(())
    }

    pub(super) fn on_resume_status(&mut self, body: &[u8], now: Duration) -> Handled {
        let status = ResumeStatus::decode(body).map_err(|_| violation(FailureCode::Malformed))?;
        let transfer_id = *status.transfer_id();
        let transport = self.config.transport;
        let serving = match self.outgoing.get_mut(&transfer_id) {
            Some(Outgoing::Serving(serving)) => serving,
            Some(Outgoing::Ended { ended, .. }) => {
                return if ended.late.take(LateKind::ResumeStatus) {
                    Ok(())
                } else {
                    Err(violation(FailureCode::State))
                };
            }
            _ => return Err(violation(FailureCode::State)),
        };
        let Some((file_id, from)) = serving.resume_cursor else {
            return Err(violation(FailureCode::State));
        };
        let layout = serving
            .sealers
            .get(&file_id)
            .map(|sealer| *sealer.binding().layout())
            .ok_or(violation(FailureCode::State))?;
        let count = layout.count();
        let next = status.next_index();
        // §7.5: matching query; next_index > from_index, or both equal the
        // segment count for the empty final page.
        if status.accept_hash() != serving.accept.accept_hash()
            || status.file_id() != file_id
            || status.from_index() != from
            || next > count
            || (next == from && from != count)
        {
            return Err(violation(FailureCode::State));
        }
        // §7.5: claimed progress is not proof. It adjusts the progress
        // hint only; files count as sent only for segments sent here.
        let mut present_bytes: u64 = 0;
        for &(start, length) in status.ranges() {
            let first = u64::from(start) * u64::from(todoke_crypto::content::SEGMENT_LEN);
            let end = u64::from(start.saturating_add(length))
                .saturating_mul(u64::from(todoke_crypto::content::SEGMENT_LEN))
                .min(layout.size());
            present_bytes = present_bytes.saturating_add(end.saturating_sub(first));
        }
        serving.claimed_bytes = serving.claimed_bytes.saturating_add(present_bytes);
        let next_query = if next < count {
            serving.resume_cursor = Some((file_id, next));
            Some(
                ResumeQuery::new(transfer_id, *serving.accept.accept_hash(), file_id, next)
                    .map_err(|_| violation(FailureCode::State))?,
            )
        } else {
            serving.resume_cursor = None;
            None
        };
        let progress = progress_of(&transfer_id, serving, now, transport);
        if let Some(query) = next_query {
            self.queue(FrameType::RESUME_QUERY, query.encode().to_vec());
        } else {
            self.resume_query = None;
        }
        if let Some(progress) = progress {
            self.event(TransferEvent::Progress(progress));
        }
        Ok(())
    }

    /// Sends the next `ResumeQuery` of a resumed transfer, one outstanding
    /// per sending endpoint (§7.5).
    pub(super) fn next_resume_query(&mut self) {
        if self.resume_query.is_some() {
            return;
        }
        for (transfer_id, transfer) in &mut self.outgoing {
            let Outgoing::Serving(serving) = transfer else {
                continue;
            };
            if serving.resume_cursor.is_some() {
                continue;
            }
            let Some(file_id) = serving.resume_files.pop_front() else {
                continue;
            };
            let Ok(query) =
                ResumeQuery::new(*transfer_id, *serving.accept.accept_hash(), file_id, 0)
            else {
                continue;
            };
            serving.resume_cursor = Some((file_id, 0));
            self.resume_query = Some(*transfer_id);
            self.frames.push_back(super::OutgoingFrame::Frame {
                frame_type: FrameType::RESUME_QUERY,
                body: Zeroizing::new(query.encode().to_vec()),
            });
            return;
        }
    }

    pub(super) fn on_complete(&mut self, body: &[u8], now: Duration) -> Handled {
        let complete = Complete::decode(body).map_err(|_| violation(FailureCode::Malformed))?;
        let transfer_id = *complete.transfer_id();
        let serving = match self.outgoing.get_mut(&transfer_id) {
            Some(Outgoing::Serving(serving)) => serving,
            Some(Outgoing::Ended { ended, .. }) => {
                return if ended.late.take(LateKind::Complete) {
                    Ok(())
                } else {
                    Err(violation(FailureCode::State))
                };
            }
            _ => return Err(violation(FailureCode::State)),
        };
        if now >= serving.expiry {
            // §7.7: publication must finish while consent is valid.
            self.expire_outgoing(&transfer_id);
            return Ok(());
        }
        let accept = &serving.accept;
        if complete.manifest_hash() != accept.manifest_hash()
            || complete.accept_hash() != accept.accept_hash()
            || complete.completed_count() != accept.selected_count()
            || complete.total_plaintext_bytes() != accept.selected_bytes()
        {
            return Err(violation(FailureCode::State));
        }
        if serving.resume_cursor.is_some() && self.resume_query == Some(transfer_id) {
            self.resume_query = None;
        }
        let Some(Outgoing::Serving(serving)) = self.outgoing.remove(&transfer_id) else {
            return Err(violation(FailureCode::State));
        };
        // The sealers, masters, and offer go: nothing more is served.
        let Serving { accept, .. } = *serving;
        self.outgoing.insert(
            transfer_id,
            Outgoing::AwaitingReceipt(Box::new(AwaitingReceipt {
                accept,
                deadline: now.saturating_add(RECEIPT_TIMEOUT),
            })),
        );
        Ok(())
    }

    pub(super) fn on_receipt(&mut self, body: &[u8], now: Duration) -> Handled {
        let record =
            DeliveryReceipt::decode(body).map_err(|_| violation(FailureCode::Malformed))?;
        let transfer_id = *record.body().transfer_id();
        let wall = self.wall(now);
        let awaiting = match self.outgoing.get_mut(&transfer_id) {
            Some(Outgoing::AwaitingReceipt(awaiting)) => awaiting,
            Some(Outgoing::Ended { ended, .. }) => {
                return if ended.late.take(LateKind::Receipt) {
                    Ok(())
                } else {
                    Err(violation(FailureCode::State))
                };
            }
            _ => return Err(violation(FailureCode::State)),
        };
        // §7.7: every binding and the signature before confirmed delivery.
        let receipt = match verify_receipt(body, &self.session, &awaiting.accept, wall) {
            Ok(receipt) => receipt,
            // A receipt for this transfer, Accept, and session whose
            // completion time is outside the window (for example a receiver
            // clock more than 120 seconds ahead) or whose totals differ from
            // the Accept proves nothing, like a receipt that never came:
            // delivery is unconfirmed (§7.7). Only this transfer's receipt
            // is unusable, and its content phase is over, so the session
            // stays open; the receiver already ended the transfer, so no
            // Error is sent.
            Err(ReceiptError::Time | ReceiptError::Totals) => {
                self.end_outgoing(&transfer_id, Outcome::Unconfirmed, Late::default(), false);
                self.event(TransferEvent::DeliveryUnconfirmed { transfer_id });
                return Ok(());
            }
            // §12: a bad layout is MALFORMED and a bad signature
            // AUTHENTICATION; a receipt naming another session, transfer,
            // manifest, Accept, or device is a replay or misdirected record
            // (STATE). All are session-scoped.
            Err(ReceiptError::Malformed(_)) => return Err(violation(FailureCode::Malformed)),
            Err(ReceiptError::Signature) => return Err(violation(FailureCode::Authentication)),
            Err(_) => return Err(violation(FailureCode::State)),
        };
        self.end_outgoing(&transfer_id, Outcome::Delivered, Late::default(), false);
        self.event(TransferEvent::DeliveryConfirmed {
            transfer_id,
            completed_at: receipt.completed_at(),
            receipt_id: *receipt.receipt_id(),
        });
        Ok(())
    }

    /// Ends an outgoing transfer, dropping its sealers and, unless it is
    /// kept for a resume, its masters. Returns whether it was active.
    pub(super) fn end_outgoing(
        &mut self,
        transfer_id: &TransferId,
        outcome: Outcome,
        late: Late,
        keep_for_resume: bool,
    ) -> bool {
        let Some(transfer) = self.outgoing.remove(transfer_id) else {
            return false;
        };
        let hash = transfer.manifest_hash();
        if self.resume_query == Some(*transfer_id) {
            self.resume_query = None;
        }
        let (active, offer) = match transfer {
            Outgoing::Offering(offering) => (true, Some(Box::new(offering.offer))),
            Outgoing::Serving(serving) => (true, Some(Box::new(serving.offer))),
            Outgoing::AwaitingReceipt(_) => (true, None),
            Outgoing::Ended { ended, resumable } => {
                // Already ended: keep its record (a late cancel may still
                // need an acknowledgment).
                self.outgoing
                    .insert(*transfer_id, Outgoing::Ended { ended, resumable });
                return false;
            }
        };
        let resumable = if keep_for_resume { offer } else { None };
        self.outgoing.insert(
            *transfer_id,
            Outgoing::Ended {
                ended: Ended::new(outcome, hash, late),
                resumable,
            },
        );
        active
    }

    fn expire_outgoing(&mut self, transfer_id: &TransferId) {
        let limit = self.request_limit();
        let late = match self.outgoing.get(transfer_id) {
            Some(Outgoing::Serving(serving)) => serving.late(limit),
            Some(Outgoing::Offering(_)) => Late {
                accepts: 1,
                rejects: 1,
                ..Late::default()
            },
            _ => Late::default(),
        };
        if self.end_outgoing(transfer_id, Outcome::Expired, late, true) {
            self.event(TransferEvent::Expired {
                transfer_id: *transfer_id,
                direction: Direction::Outgoing,
            });
        }
    }

    /// The session ended under an outgoing transfer: after `Complete`
    /// delivery stays unconfirmed (never retransfer silently, §7.7);
    /// otherwise it is interrupted and kept for a resume.
    pub(super) fn interrupt_outgoing(&mut self, transfer_id: &TransferId) {
        if matches!(
            self.outgoing.get(transfer_id),
            Some(Outgoing::AwaitingReceipt(_))
        ) {
            self.end_outgoing(transfer_id, Outcome::Unconfirmed, Late::default(), false);
            self.event(TransferEvent::DeliveryUnconfirmed {
                transfer_id: *transfer_id,
            });
        } else if self.end_outgoing(transfer_id, Outcome::Interrupted, Late::default(), true) {
            self.event(TransferEvent::Interrupted {
                transfer_id: *transfer_id,
                direction: Direction::Outgoing,
            });
        }
    }

    pub(super) fn cancel_outgoing(
        &mut self,
        transfer_id: &TransferId,
    ) -> Result<[u8; 32], EngineError> {
        let limit = self.request_limit();
        let late = match self.outgoing.get(transfer_id) {
            Some(Outgoing::Offering(_)) => Late {
                accepts: 1,
                rejects: 1,
                ..Late::default()
            },
            Some(Outgoing::Serving(serving)) => serving.late(limit),
            Some(Outgoing::AwaitingReceipt(_)) => Late {
                receipts: 1,
                ..Late::default()
            },
            Some(Outgoing::Ended { ended, .. })
                if matches!(ended.outcome, Outcome::Expired | Outcome::Interrupted) =>
            {
                ended.late
            }
            Some(Outgoing::Ended { .. }) => return Err(EngineError::WrongState),
            None => return Err(EngineError::UnknownTransfer),
        };
        let hash = self
            .outgoing
            .get(transfer_id)
            .map(Outgoing::manifest_hash)
            .ok_or(EngineError::UnknownTransfer)?;
        // A cancelled transfer is never resumed: drop its masters.
        if let Some(Outgoing::Ended { ended, resumable }) = self.outgoing.get_mut(transfer_id) {
            ended.outcome = Outcome::Cancelled;
            *resumable = None;
        } else {
            self.end_outgoing(transfer_id, Outcome::Cancelled, late, false);
        }
        Ok(hash)
    }

    pub(super) fn poll_outgoing(&mut self, now: Duration) -> Handled {
        let ids: Vec<TransferId> = self.outgoing.keys().copied().collect();
        for transfer_id in ids {
            let Some(transfer) = self.outgoing.get(&transfer_id) else {
                continue;
            };
            match transfer {
                Outgoing::Offering(offering) if now >= offering.expiry => {
                    // The manifest expired before a decision: cancel, so
                    // the receiver frees its slot.
                    self.cancel(&transfer_id, CancelReason::Expired, now)
                        .map_err(|_| violation(FailureCode::Random))?;
                }
                Outgoing::Serving(serving) if now >= serving.expiry => {
                    self.expire_outgoing(&transfer_id);
                }
                Outgoing::AwaitingReceipt(awaiting) if now >= awaiting.deadline => {
                    // §7.7: no receipt in 10 seconds: unconfirmed.
                    self.end_outgoing(&transfer_id, Outcome::Unconfirmed, Late::default(), false);
                    if let Some(ended) = self.ended_mut(&transfer_id) {
                        ended.late.receipts = 1;
                    }
                    self.event(TransferEvent::DeliveryUnconfirmed { transfer_id });
                }
                Outgoing::Ended { ended, .. } => {
                    if ended.cancel.is_some_and(|cancel| now >= cancel.deadline) {
                        return Err(violation(FailureCode::Timeout));
                    }
                }
                Outgoing::Offering(_) | Outgoing::Serving(_) | Outgoing::AwaitingReceipt(_) => {}
            }
        }
        Ok(())
    }
}

fn progress_of(
    transfer_id: &TransferId,
    serving: &mut Serving,
    now: Duration,
    transport: &'static str,
) -> Option<Progress> {
    let total = serving.accept.selected_bytes();
    let done = serving
        .sent_bytes
        .saturating_add(serving.claimed_bytes)
        .min(total);
    let (bytes_per_second, eta) = serving.meter.record(now, done, total)?;
    Some(Progress {
        transfer_id: *transfer_id,
        direction: Direction::Outgoing,
        bytes_done: done,
        bytes_total: total,
        files_done: serving.served.files_complete(),
        files_total: serving.accept.selected_count(),
        bytes_per_second,
        eta,
        transport,
    })
}

type Sealers = BTreeMap<u32, ContentSealer>;
type KeyBodies = Vec<Zeroizing<Vec<u8>>>;

/// A sealer and a `FileKey` body for each selected file (§8): one master
/// per file, sent only after the verified Accept and bound to its hash.
fn keys_for(
    transfer_id: &TransferId,
    accept: &VerifiedAccept,
    offer: &mut OutgoingOffer,
) -> Result<(Sealers, KeyBodies), super::Violation> {
    let mut sealers = BTreeMap::new();
    let mut keys = Vec::new();
    for file in accept.files() {
        let file_id = file.binding().file_id();
        let master = offer
            .take_master(file_id)
            .ok_or(violation(FailureCode::State))?;
        let sealer = ContentSealer::new(file, &master);
        let body = FileKeyBody::new(
            *transfer_id,
            *accept.accept_hash(),
            file_id,
            file.binding().suite(),
            master,
        )
        .map_err(|_| violation(FailureCode::State))?;
        keys.push(Zeroizing::new(body.encode().to_vec()));
        offer.return_master(file_id, body.into_master());
        let sealer = sealer.map_err(|error| match error {
            ContentError::SuiteUnavailable => violation(FailureCode::Unsupported),
            _ => violation(FailureCode::State),
        })?;
        sealers.insert(file_id, sealer);
    }
    Ok((sealers, keys))
}
