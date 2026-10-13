//! The receiver's state machine (§7.1–§7.5, §7.7, §11).
//!
//! `Assembling` (`ManifestStart` seen, parts arriving) → `Offered` (a
//! validated manifest awaits the user's decision; nothing about content is
//! accepted) → `Receiving` (this side signed and queued its Accept; the
//! consent gate is open for the selection) → ended.
//!
//! Every `FileKey` and `Chunk` reaches the consent gate before anything
//! else happens to it. A key or chunk for a transfer without an open gate
//! is refused from its transfer ID alone, before its body is even decoded
//! (§7.2).

use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};

use todoke_crypto::consent::{
    AcceptError, CanonicalManifest, VerifiedAccept, manifest_hash, sign_accept, sign_receipt,
};
use todoke_crypto::content::{
    ContentError, ContentOpener, FileKeyBody, FileMaster, SegmentTracker,
};
use todoke_crypto::identity::KeyStore;
use todoke_proto::session::FrameType;
use todoke_proto::time::UnixTime;
use todoke_proto::transfer::{
    Chunk, ChunkRequest, Complete, ManifestPart, ManifestStart, Reject, RejectReason, ResumeQuery,
    ResumeStatus, TransferId,
};

use super::ended::{Ended, Late, LateKind, Outcome};
use super::{EngineError, Handled, Phase, TransferEngine, Violation, violation};
use crate::events::{
    Direction, Failure, FailureCode, Meter, OfferEntry, OfferView, Progress, TransferEvent,
};
use crate::gate::{ConsentGate, GateRefusal};
use crate::limits::{
    CHUNK_REQUEST_TIMEOUT, CONSENT_PROMPT_TIMEOUT, MANIFEST_ASSEMBLY_TIMEOUT,
    MAX_ACTIVE_INCOMING_FILES, MAX_INCOMING_TRANSFERS, MAX_INCOMPLETE_MANIFESTS,
    REVALIDATION_BUDGET, TOMBSTONE_GRACE_SECONDS,
};
use crate::storage::{ReceiveSink, Retained, SendSource, SinkError, SinkRefusal};

/// One incoming transfer.
pub(super) enum Incoming {
    Assembling(Assembly),
    Offered(Box<Offered>),
    Receiving(Box<Receiving>),
    Ended(Ended),
}

pub(super) struct Assembly {
    start: ManifestStart,
    buffer: Vec<u8>,
    deadline: Duration,
}

pub(super) struct Offered {
    manifest: CanonicalManifest,
    gate: ConsentGate<VerifiedAccept>,
    /// The prompt deadline or the manifest's expiry, whichever is first.
    deadline: Duration,
    resume: Option<Retained>,
}

struct Request {
    file_id: u32,
    index: u32,
    deadline: Duration,
}

struct OpenFile {
    opener: ContentOpener,
    tracker: SegmentTracker,
    /// The lowest index not yet requested or revalidated.
    cursor: u32,
}

enum FileState {
    /// Selected; its `FileKey` has not arrived.
    AwaitingKey,
    /// Keyed: segments are being requested, verified, and stored.
    Receiving(Box<OpenFile>),
    /// Verified, published, and durable (§7.7).
    Published { segment_count: u32 },
}

pub(super) struct Receiving {
    manifest: CanonicalManifest,
    gate: ConsentGate<VerifiedAccept>,
    files: BTreeMap<u32, FileState>,
    masters: BTreeMap<u32, FileMaster>,
    outstanding: BTreeMap<u32, Request>,
    /// The next request ID; 0 once the counter is exhausted (§7.4).
    next_request_id: u32,
    /// When the Accept expires, on the monotonic clock.
    expiry: Duration,
    /// Per file: the `from_index` the next `ResumeQuery` must carry.
    resume_next: BTreeMap<u32, u32>,
    resume_done: BTreeSet<u32>,
    bytes_done: u64,
    files_done: u32,
    meter: Meter,
}

impl Receiving {
    fn accept(&self) -> Option<&VerifiedAccept> {
        self.gate.proof()
    }

    fn late(&self) -> Late {
        // The sender sends a FileKey for every selected file, also for
        // files an earlier session already published.
        let pending_keys = self.files.len().saturating_sub(self.masters.len());
        Late {
            file_keys: u32::try_from(pending_keys).unwrap_or(u32::MAX),
            chunks: u32::try_from(self.outstanding.len()).unwrap_or(u32::MAX),
            resume_queries: 1,
            ..Late::default()
        }
    }
}

impl Incoming {
    pub(super) fn deadline(&self) -> Duration {
        match self {
            Self::Assembling(assembly) => assembly.deadline,
            Self::Offered(offered) => offered.deadline,
            Self::Receiving(receiving) => receiving
                .outstanding
                .values()
                .map(|request| request.deadline)
                .fold(receiving.expiry, Duration::min),
            Self::Ended(ended) => ended.cancel.map_or(Duration::MAX, |cancel| cancel.deadline),
        }
    }

    pub(super) fn manifest_hash(&self) -> [u8; 32] {
        match self {
            Self::Assembling(assembly) => *assembly.start.manifest_hash(),
            Self::Offered(offered) => *offered.manifest.hash(),
            Self::Receiving(receiving) => *receiving.manifest.hash(),
            Self::Ended(ended) => ended.manifest_hash,
        }
    }

    pub(super) const fn ended(&self) -> Option<&Ended> {
        match self {
            Self::Ended(ended) => Some(ended),
            Self::Assembling(_) | Self::Offered(_) | Self::Receiving(_) => None,
        }
    }

    pub(super) const fn ended_mut(&mut self) -> Option<&mut Ended> {
        match self {
            Self::Ended(ended) => Some(ended),
            Self::Assembling(_) | Self::Offered(_) | Self::Receiving(_) => None,
        }
    }

    const fn is_active(&self) -> bool {
        !matches!(self, Self::Ended(_))
    }
}

/// The §12 code for a consent-gate refusal.
const fn gate_code(refusal: GateRefusal) -> FailureCode {
    match refusal {
        GateRefusal::NotAccepted | GateRefusal::Unselected => FailureCode::ConsentRequired,
        GateRefusal::WrongAccept
        | GateRefusal::NoKey
        | GateRefusal::Closed
        | GateRefusal::AlreadyOpen => FailureCode::State,
    }
}

fn offer_view(manifest: &CanonicalManifest, resume: Option<&Retained>) -> OfferView {
    let entries = manifest
        .manifest()
        .entries()
        .iter()
        .map(|entry| OfferEntry {
            id: entry.id(),
            parent: entry.parent(),
            kind: entry.kind(),
            name: entry.name().to_owned(),
            mime: entry.mime().to_owned(),
            size: entry.size(),
        })
        .collect();
    OfferView {
        transfer_id: *manifest.transfer_id(),
        sender: *manifest.sender(),
        created_at: manifest.created_at(),
        expires_at: manifest.expires_at(),
        file_count: manifest.manifest().file_count(),
        total_bytes: manifest.manifest().total_file_bytes(),
        entries,
        resume_selection: resume.map(|retained| retained.selection.clone()),
    }
}

/// What to do after a chunk was examined under the transfer's borrow.
enum ChunkOutcome {
    Stored { progress: Option<Progress> },
    Integrity,
    Storage,
    Expired,
}

impl<K: KeyStore, S: SendSource, R: ReceiveSink> TransferEngine<'_, K, S, R> {
    fn negotiated_ready(&self) -> Result<crate::capabilities::Negotiated, Violation> {
        match &self.phase {
            Phase::Ready(negotiated) => Ok(*negotiated),
            Phase::AwaitingCapabilities { .. } | Phase::Closed => {
                Err(violation(FailureCode::State))
            }
        }
    }

    /// Refuses a new incoming transfer before consent with a transfer
    /// `Error`; its remaining manifest parts may still arrive.
    fn refuse_new(&mut self, start: &ManifestStart, code: FailureCode) {
        let transfer_id = *start.transfer_id();
        self.transfer_error(transfer_id, code);
        let late = Late {
            manifest_bytes: u64::from(start.total_len()),
            ..Late::default()
        };
        self.incoming.insert(
            transfer_id,
            Incoming::Ended(Ended::new(Outcome::Failed, *start.manifest_hash(), late)),
        );
        self.event(TransferEvent::Failed {
            transfer_id,
            direction: Direction::Incoming,
            failure: Failure::local(code),
        });
    }

    pub(super) fn on_manifest_start(&mut self, body: &[u8], now: Duration) -> Handled {
        let start = ManifestStart::decode(body).map_err(|_| violation(FailureCode::Malformed))?;
        let transfer_id = *start.transfer_id();
        if self.incoming.contains_key(&transfer_id) || self.outgoing.contains_key(&transfer_id) {
            return Err(violation(FailureCode::State));
        }
        let negotiated = self.negotiated_ready()?;
        let wall = self.wall(now);
        let assembling = self
            .incoming
            .values()
            .filter(|transfer| matches!(transfer, Incoming::Assembling(_)))
            .count();
        let active = self.incoming.values().filter(|t| t.is_active()).count();
        if self.sink.is_tombstoned(&transfer_id, wall) {
            self.refuse_new(&start, FailureCode::ResumeUnavailable);
        } else if start.total_len() > negotiated.local().max_manifest_bytes()
            || assembling >= MAX_INCOMPLETE_MANIFESTS
            || active >= MAX_INCOMING_TRANSFERS
        {
            self.refuse_new(&start, FailureCode::Limit);
        } else {
            self.incoming.insert(
                transfer_id,
                Incoming::Assembling(Assembly {
                    start,
                    buffer: Vec::new(),
                    deadline: now.saturating_add(MANIFEST_ASSEMBLY_TIMEOUT),
                }),
            );
        }
        Ok(())
    }

    pub(super) fn on_manifest_part(&mut self, body: &[u8], now: Duration) -> Handled {
        let part = ManifestPart::decode(body).map_err(|_| violation(FailureCode::Malformed))?;
        let transfer_id = *part.transfer_id();
        let data = part.data();
        let complete = match self.incoming.get_mut(&transfer_id) {
            Some(Incoming::Assembling(assembly)) => {
                let filled = assembly.buffer.len();
                let total = usize::try_from(assembly.start.total_len())
                    .map_err(|_| violation(FailureCode::Limit))?;
                // Contiguous, nonoverlapping, within the declared length.
                if usize::try_from(part.offset()) != Ok(filled) || data.len() > total - filled {
                    return Err(violation(FailureCode::State));
                }
                assembly.buffer.extend_from_slice(data);
                assembly.buffer.len() == total
            }
            Some(Incoming::Ended(ended)) => {
                let len = u64::try_from(data.len()).unwrap_or(u64::MAX);
                return if ended.late.take_manifest(len) {
                    Ok(())
                } else {
                    Err(violation(FailureCode::State))
                };
            }
            _ => return Err(violation(FailureCode::State)),
        };
        if complete {
            self.complete_manifest(transfer_id, now)?;
        }
        Ok(())
    }

    fn fail_offer(&mut self, transfer_id: TransferId, hash: [u8; 32], code: FailureCode) {
        self.transfer_error(transfer_id, code);
        self.incoming.insert(
            transfer_id,
            Incoming::Ended(Ended::new(Outcome::Failed, hash, Late::default())),
        );
        self.event(TransferEvent::Failed {
            transfer_id,
            direction: Direction::Incoming,
            failure: Failure::local(code),
        });
    }

    fn complete_manifest(&mut self, transfer_id: TransferId, now: Duration) -> Handled {
        let Some(Incoming::Assembling(assembly)) = self.incoming.remove(&transfer_id) else {
            return Err(violation(FailureCode::State));
        };
        let negotiated = self.negotiated_ready()?;
        let announced = *assembly.start.manifest_hash();
        // §7.1: the hash of the exact bytes, before anything else.
        if manifest_hash(&assembly.buffer) != announced {
            self.fail_offer(transfer_id, announced, FailureCode::Manifest);
            return Ok(());
        }
        let Ok(manifest) = CanonicalManifest::parse(assembly.buffer, &negotiated.receive_limits())
        else {
            self.fail_offer(transfer_id, announced, FailureCode::Manifest);
            return Ok(());
        };
        let wall = self.wall(now);
        let resume = self.sink.retained(&transfer_id, wall);
        // §6: every new file uses the negotiated suite; a resumed transfer
        // (this side retained it under this manifest) keeps its original
        // one, which both peers must support.
        let resumed = resume
            .as_ref()
            .is_some_and(|retained| retained.manifest_hash == announced);
        let suite_ok = |file_suite| {
            file_suite == negotiated.suite() || (resumed && negotiated.supports(file_suite))
        };
        if *manifest.transfer_id() != transfer_id
            || manifest.sender() != self.session.peer_device()
            || manifest.recipient() != self.session.local_device()
            || manifest.files().iter().any(|file| !suite_ok(file.suite()))
        {
            self.fail_offer(transfer_id, announced, FailureCode::Manifest);
            return Ok(());
        }
        if resume
            .as_ref()
            .is_some_and(|retained| retained.manifest_hash != announced)
        {
            // §7.5: a mutated manifest makes resume unavailable.
            self.fail_offer(transfer_id, announced, FailureCode::ResumeUnavailable);
            return Ok(());
        }
        let refusal = if manifest.expires_at() <= wall {
            Some(RejectReason::Expired)
        } else {
            match self.sink.check_offer(&manifest) {
                Ok(()) => None,
                Err(SinkRefusal::Quota) => Some(RejectReason::Quota),
                Err(SinkRefusal::UnsupportedDestination) => {
                    Some(RejectReason::UnsupportedDestination)
                }
            }
        };
        if let Some(reason) = refusal {
            self.send_reject(transfer_id, announced, reason);
            return Ok(());
        }
        let deadline = now
            .saturating_add(CONSENT_PROMPT_TIMEOUT)
            .min(self.clock.monotonic_at(manifest.expires_at()));
        let view = offer_view(&manifest, resume.as_ref());
        self.incoming.insert(
            transfer_id,
            Incoming::Offered(Box::new(Offered {
                manifest,
                gate: ConsentGate::new(),
                deadline,
                resume,
            })),
        );
        self.event(TransferEvent::OfferReceived(Box::new(view)));
        Ok(())
    }

    fn send_reject(&mut self, transfer_id: TransferId, hash: [u8; 32], reason: RejectReason) {
        if let Ok(record) = Reject::new(transfer_id, hash, reason) {
            self.queue(FrameType::REJECT, record.encode().to_vec());
        }
        self.incoming.insert(
            transfer_id,
            Incoming::Ended(Ended::new(Outcome::Rejected, hash, Late::default())),
        );
        self.event(TransferEvent::Rejected {
            transfer_id,
            direction: Direction::Incoming,
            reason,
        });
    }

    pub(super) fn reject_offer(
        &mut self,
        transfer_id: &TransferId,
        reason: RejectReason,
    ) -> Result<(), EngineError> {
        match self.incoming.get(transfer_id) {
            Some(Incoming::Offered(offered)) => {
                let hash = *offered.manifest.hash();
                self.send_reject(*transfer_id, hash, reason);
                Ok(())
            }
            Some(_) => Err(EngineError::WrongState),
            None => Err(EngineError::UnknownTransfer),
        }
    }

    /// Accepts an offer for `selection` (§7.2, §7.3). **Call only on
    /// locally authorized user intent** for this offer: this signs the
    /// Accept with the device key, records it durably, and queues it. The
    /// selection lists regular-file IDs in increasing order; a resumed
    /// transfer must repeat its earlier selection exactly (§7.5). The
    /// Accept expires at the manifest's expiry or 24 hours from now,
    /// whichever is first.
    ///
    /// # Errors
    ///
    /// [`EngineError::UnknownTransfer`], [`EngineError::WrongState`] unless
    /// the offer awaits a decision, [`EngineError::Selection`],
    /// [`EngineError::Expired`], [`EngineError::KeyStore`],
    /// [`EngineError::Storage`] (nothing is sent), [`EngineError::Random`],
    /// [`EngineError::Closed`].
    pub fn accept(
        &mut self,
        transfer_id: &TransferId,
        selection: Vec<u32>,
        now: Duration,
    ) -> Result<(), EngineError> {
        if !matches!(self.phase, Phase::Ready(_)) {
            return Err(EngineError::Closed);
        }
        let wall = self.wall(now);
        let offered = match self.incoming.get(transfer_id) {
            Some(Incoming::Offered(offered)) => offered,
            Some(_) => return Err(EngineError::WrongState),
            None => return Err(EngineError::UnknownTransfer),
        };
        if offered
            .resume
            .as_ref()
            .is_some_and(|retained| retained.selection != selection)
        {
            return Err(EngineError::Selection);
        }
        let lifetime = todoke_crypto::consent::ACCEPT_LIFETIME_SECONDS;
        let day = UnixTime::new(wall.seconds().saturating_add(lifetime)).unwrap_or(wall);
        let expires_at = offered.manifest.expires_at().min(day);
        let accept = sign_accept(
            self.keys,
            &self.device_key,
            &self.session,
            &offered.manifest,
            selection,
            expires_at,
            wall,
        )
        .map_err(|error| match error {
            AcceptError::Malformed(_) | AcceptError::Selection => EngineError::Selection,
            AcceptError::Expiry => EngineError::Expired,
            AcceptError::Random => EngineError::Random,
            AcceptError::Role => EngineError::KeyRole,
            _ => EngineError::KeyStore,
        })?;
        if !self.accept_nonces.insert(*accept.nonce()) {
            return Err(EngineError::Random);
        }
        // §7.2: durably record the verified Accept before queueing it.
        self.sink
            .record_accept(&offered.manifest, &accept)
            .map_err(|_| EngineError::Storage)?;
        let Some(Incoming::Offered(offered)) = self.incoming.remove(transfer_id) else {
            return Err(EngineError::WrongState);
        };
        let Offered {
            manifest, mut gate, ..
        } = *offered;
        let record = accept.encoded().to_vec();
        // A resumed transfer keeps files an earlier session published, once
        // the sink re-verified them (§7.5).
        let mut files = BTreeMap::new();
        let (mut files_done, mut bytes_done) = (0, 0_u64);
        for file in accept.files() {
            let binding = file.binding();
            let state = if self.sink.published_intact(&manifest, binding.file_id()) {
                files_done += 1;
                bytes_done = bytes_done.saturating_add(binding.layout().size());
                FileState::Published {
                    segment_count: binding.layout().count(),
                }
            } else {
                FileState::AwaitingKey
            };
            files.insert(binding.file_id(), state);
        }
        let (count, bytes) = (accept.selected_count(), accept.selected_bytes());
        let expiry = self.clock.monotonic_at(accept.expires_at());
        gate.open(accept).map_err(|_| EngineError::WrongState)?;
        self.incoming.insert(
            *transfer_id,
            Incoming::Receiving(Box::new(Receiving {
                manifest,
                gate,
                files,
                masters: BTreeMap::new(),
                outstanding: BTreeMap::new(),
                next_request_id: 1,
                expiry,
                resume_next: BTreeMap::new(),
                resume_done: BTreeSet::new(),
                bytes_done,
                files_done,
                meter: Meter::new(),
            })),
        );
        self.queue(FrameType::ACCEPT, record);
        self.event(TransferEvent::Accepted {
            transfer_id: *transfer_id,
            direction: Direction::Incoming,
            files: count,
            bytes,
        });
        Ok(())
    }

    pub(super) fn on_file_key(&mut self, body: &[u8], _now: Duration) -> Handled {
        // §7.2: no FileKey is processed before this side's Accept. Decide
        // from the transfer ID alone; the body (and its master) is decoded
        // only for a transfer whose consent gate is open.
        let transfer_id =
            FileKeyBody::peek_transfer_id(body).map_err(|_| violation(FailureCode::Malformed))?;
        let receiving = match self.incoming.get_mut(&transfer_id) {
            Some(Incoming::Receiving(receiving)) if receiving.gate.proof().is_some() => receiving,
            None
            | Some(Incoming::Assembling(_) | Incoming::Offered(_) | Incoming::Receiving(_)) => {
                return Err(violation(FailureCode::ConsentRequired));
            }
            // In flight before this side ended the transfer: discarded
            // without decoding, within the allowance.
            Some(Incoming::Ended(ended)) => {
                return if ended.late.take(LateKind::FileKey) {
                    Ok(())
                } else {
                    Err(violation(FailureCode::State))
                };
            }
        };
        let key = FileKeyBody::decode(body).map_err(|_| violation(FailureCode::Malformed))?;
        let file_id = key.file_id();
        let new = receiving
            .gate
            .admit_key(key.accept_hash(), file_id)
            .map_err(|refusal| violation(gate_code(refusal)))?;
        let accepted = receiving
            .accept()
            .and_then(|accept| accept.file(file_id))
            .ok_or(violation(FailureCode::State))?;
        if key.suite() != accepted.binding().suite() {
            return Err(violation(FailureCode::State));
        }
        if !new {
            // §8: an identical retransmission is idempotent, a different
            // master is fatal.
            return match receiving.masters.get(&file_id) {
                Some(master) if master.ct_eq(key.master()) => Ok(()),
                _ => Err(violation(FailureCode::State)),
            };
        }
        if matches!(
            receiving.files.get(&file_id),
            Some(FileState::Published { .. })
        ) {
            // Published by an earlier session: nothing to fetch.
            receiving.masters.insert(file_id, key.into_master());
            return Ok(());
        }
        let opener = ContentOpener::new(&accepted, key.master()).map_err(|error| match error {
            ContentError::SuiteUnavailable => violation(FailureCode::Unsupported),
            _ => violation(FailureCode::State),
        })?;
        let tracker = SegmentTracker::new(accepted.binding());
        receiving.masters.insert(file_id, key.into_master());
        receiving.files.insert(
            file_id,
            FileState::Receiving(Box::new(OpenFile {
                opener,
                tracker,
                cursor: 0,
            })),
        );
        // Retained segments of an earlier session are revalidated under
        // this key before they count (§7.5).
        self.revalidation_pending = true;
        Ok(())
    }

    pub(super) fn on_chunk(&mut self, body: &[u8], now: Duration) -> Handled {
        // §7.2: decide from the transfer ID alone; a forbidden chunk is
        // discarded without decoding, decrypting, or storing anything.
        let transfer_id =
            Chunk::peek_transfer_id(body).map_err(|_| violation(FailureCode::Malformed))?;
        let transport = self.config.transport;
        let receiving = match self.incoming.get_mut(&transfer_id) {
            None | Some(Incoming::Assembling(_) | Incoming::Offered(_)) => {
                return Err(violation(FailureCode::ConsentRequired));
            }
            Some(Incoming::Ended(ended)) => {
                return if ended.late.take(LateKind::Chunk) {
                    Ok(())
                } else {
                    Err(violation(FailureCode::State))
                };
            }
            Some(Incoming::Receiving(receiving)) => receiving,
        };
        let outcome = if now >= receiving.expiry {
            ChunkOutcome::Expired
        } else {
            let chunk = Chunk::decode(body).map_err(|_| violation(FailureCode::Malformed))?;
            receiving
                .gate
                .admit_content(chunk.accept_hash(), chunk.file_id())
                .map_err(|refusal| violation(gate_code(refusal)))?;
            // §7.4: only the exact outstanding request.
            match receiving.outstanding.get(&chunk.request_id()) {
                Some(request)
                    if request.file_id == chunk.file_id()
                        && request.index == chunk.segment_index() => {}
                _ => return Err(violation(FailureCode::State)),
            }
            receiving.outstanding.remove(&chunk.request_id());
            let Some(FileState::Receiving(file)) = receiving.files.get_mut(&chunk.file_id()) else {
                return Err(violation(FailureCode::State));
            };
            match file
                .opener
                .open_segment(chunk.segment_index(), chunk.content())
            {
                // §7.4: any failure discards the segment and ends the
                // transfer; nothing from it counts as progress.
                Err(_) => ChunkOutcome::Integrity,
                Ok(segment) => {
                    if file.tracker.can_record(segment.segment().index()) != Ok(true) {
                        return Err(violation(FailureCode::State));
                    }
                    if self.sink.store_segment(&segment, chunk.content()).is_err() {
                        ChunkOutcome::Storage
                    } else if file.tracker.record(&segment).is_err() {
                        return Err(violation(FailureCode::State));
                    } else {
                        receiving.bytes_done = receiving
                            .bytes_done
                            .saturating_add(u64::from(segment.segment().len()));
                        let progress = progress_of(&transfer_id, receiving, now, transport);
                        ChunkOutcome::Stored { progress }
                    }
                }
            }
        };
        match outcome {
            ChunkOutcome::Stored { progress } => {
                if let Some(progress) = progress {
                    self.event(TransferEvent::Progress(progress));
                }
            }
            ChunkOutcome::Integrity => self.fail_incoming(&transfer_id, FailureCode::Integrity),
            ChunkOutcome::Storage => self.fail_incoming(&transfer_id, FailureCode::Storage),
            ChunkOutcome::Expired => {
                self.expire_incoming(&transfer_id);
                // This chunk was already in flight: discard it.
                if let Some(ended) = self.ended_mut(&transfer_id) {
                    ended.late.take(LateKind::Chunk);
                }
            }
        }
        Ok(())
    }

    pub(super) fn on_resume_query(&mut self, body: &[u8]) -> Handled {
        let query = ResumeQuery::decode(body).map_err(|_| violation(FailureCode::Malformed))?;
        let receiving = match self.incoming.get_mut(query.transfer_id()) {
            None | Some(Incoming::Assembling(_) | Incoming::Offered(_)) => {
                return Err(violation(FailureCode::State));
            }
            Some(Incoming::Ended(ended)) => {
                return if ended.late.take(LateKind::ResumeQuery) {
                    Ok(())
                } else {
                    Err(violation(FailureCode::State))
                };
            }
            Some(Incoming::Receiving(receiving)) => receiving,
        };
        let file_id = query.file_id();
        let accept_hash = receiving
            .accept()
            .map(|accept| *accept.accept_hash())
            .ok_or(violation(FailureCode::State))?;
        // §7.5: only after this session's Accept and the file's FileKey.
        if *query.accept_hash() != accept_hash || !receiving.gate.is_keyed(file_id) {
            return Err(violation(FailureCode::State));
        }
        let expected = receiving.resume_next.get(&file_id).copied().unwrap_or(0);
        if receiving.resume_done.contains(&file_id) || query.from_index() != expected {
            return Err(violation(FailureCode::State));
        }
        let (next_index, ranges, count) = match receiving.files.get(&file_id) {
            Some(FileState::Receiving(file)) => {
                let page = file
                    .tracker
                    .resume_page(query.from_index())
                    .map_err(|_| violation(FailureCode::State))?;
                (
                    page.next_index(),
                    page.ranges().to_vec(),
                    file.tracker.segment_count(),
                )
            }
            Some(&FileState::Published { segment_count }) => {
                let from = query.from_index();
                if from > segment_count {
                    return Err(violation(FailureCode::State));
                }
                let ranges = if from < segment_count {
                    vec![(from, segment_count - from)]
                } else {
                    Vec::new()
                };
                (segment_count, ranges, segment_count)
            }
            _ => return Err(violation(FailureCode::State)),
        };
        let status = ResumeStatus::new(
            *query.transfer_id(),
            accept_hash,
            file_id,
            query.from_index(),
            next_index,
            ranges,
        )
        .map_err(|_| violation(FailureCode::State))?;
        if next_index == count {
            receiving.resume_done.insert(file_id);
        } else {
            receiving.resume_next.insert(file_id, next_index);
        }
        self.queue(FrameType::RESUME_STATUS, status.encode());
        Ok(())
    }

    /// Ends an incoming transfer; closes its gate and drops its keys.
    pub(super) fn end_incoming(&mut self, transfer_id: &TransferId, outcome: Outcome, late: Late) {
        let Some(transfer) = self.incoming.get_mut(transfer_id) else {
            return;
        };
        let hash = transfer.manifest_hash();
        if let Incoming::Receiving(receiving) = transfer {
            receiving.gate.close();
        }
        // Replacing the state drops openers and masters (zeroized).
        *transfer = Incoming::Ended(Ended::new(outcome, hash, late));
    }

    fn fail_incoming(&mut self, transfer_id: &TransferId, code: FailureCode) {
        self.fail_incoming_as(transfer_id, code, code);
    }

    /// Fails an incoming transfer: reports `local` to this side's UI and
    /// sends the peer a transfer-scoped `Error` with `wire`'s code.
    fn fail_incoming_as(
        &mut self,
        transfer_id: &TransferId,
        local: FailureCode,
        wire: FailureCode,
    ) {
        let late = match self.incoming.get(transfer_id) {
            Some(Incoming::Receiving(receiving)) => receiving.late(),
            _ => Late::default(),
        };
        self.transfer_error(*transfer_id, wire);
        self.end_incoming(transfer_id, Outcome::Failed, late);
        self.event(TransferEvent::Failed {
            transfer_id: *transfer_id,
            direction: Direction::Incoming,
            failure: Failure::local(local),
        });
    }

    /// §7.3: expiry pauses content at once; retained data stays for a
    /// resume with fresh consent.
    fn expire_incoming(&mut self, transfer_id: &TransferId) {
        let late = match self.incoming.get(transfer_id) {
            Some(Incoming::Receiving(receiving)) => receiving.late(),
            _ => Late::default(),
        };
        self.end_incoming(transfer_id, Outcome::Expired, late);
        self.event(TransferEvent::Expired {
            transfer_id: *transfer_id,
            direction: Direction::Incoming,
        });
    }

    /// Records a tombstone that outlives the manifest by at least 120
    /// seconds and deletes the transfer's temporary data (§7.6).
    pub(super) fn tombstone_incoming(&mut self, transfer_id: &TransferId, now: Duration) {
        let wall = self.wall(now);
        let expires = match self.incoming.get(transfer_id) {
            Some(Incoming::Offered(offered)) => Some(offered.manifest.expires_at()),
            Some(Incoming::Receiving(receiving)) => Some(receiving.manifest.expires_at()),
            _ => None,
        }
        .unwrap_or_else(|| {
            // Unknown expiry: the longest a manifest can live.
            UnixTime::new(wall.seconds().saturating_add(7 * 86_400)).unwrap_or(wall)
        });
        let until = UnixTime::new(expires.seconds().saturating_add(TOMBSTONE_GRACE_SECONDS))
            .unwrap_or(expires);
        self.sink.tombstone(transfer_id, until);
    }

    pub(super) fn cancel_incoming(
        &mut self,
        transfer_id: &TransferId,
        now: Duration,
    ) -> Result<[u8; 32], EngineError> {
        let (hash, late) = match self.incoming.get(transfer_id) {
            Some(Incoming::Assembling(assembly)) => {
                let remaining = u64::from(assembly.start.total_len())
                    .saturating_sub(u64::try_from(assembly.buffer.len()).unwrap_or(u64::MAX));
                (
                    *assembly.start.manifest_hash(),
                    Late {
                        manifest_bytes: remaining,
                        ..Late::default()
                    },
                )
            }
            Some(Incoming::Offered(offered)) => (*offered.manifest.hash(), Late::default()),
            Some(Incoming::Receiving(receiving)) => (*receiving.manifest.hash(), receiving.late()),
            Some(Incoming::Ended(ended))
                if matches!(
                    ended.outcome,
                    Outcome::Expired | Outcome::Failed | Outcome::Interrupted
                ) =>
            {
                (ended.manifest_hash, ended.late)
            }
            Some(Incoming::Ended(_)) => return Err(EngineError::WrongState),
            None => return Err(EngineError::UnknownTransfer),
        };
        self.tombstone_incoming(transfer_id, now);
        self.end_incoming(transfer_id, Outcome::Cancelled, late);
        Ok(hash)
    }

    pub(super) fn poll_incoming(&mut self, now: Duration) -> Handled {
        let ids: Vec<TransferId> = self.incoming.keys().copied().collect();
        for transfer_id in ids {
            let Some(transfer) = self.incoming.get(&transfer_id) else {
                continue;
            };
            match transfer {
                Incoming::Assembling(assembly) if now >= assembly.deadline => {
                    // §7.1: incomplete within 30 seconds of Start.
                    let start = assembly.start;
                    let remaining = u64::from(start.total_len())
                        .saturating_sub(u64::try_from(assembly.buffer.len()).unwrap_or(u64::MAX));
                    self.incoming.remove(&transfer_id);
                    self.refuse_new(&start, FailureCode::Timeout);
                    if let Some(ended) = self.ended_mut(&transfer_id) {
                        ended.late.manifest_bytes = remaining;
                    }
                }
                Incoming::Offered(offered) if now >= offered.deadline => {
                    // §13: the prompt (or the manifest) expired.
                    let hash = *offered.manifest.hash();
                    self.send_reject(transfer_id, hash, RejectReason::Expired);
                }
                Incoming::Receiving(receiving) => {
                    if now >= receiving.expiry {
                        self.expire_incoming(&transfer_id);
                    } else if receiving
                        .outstanding
                        .values()
                        .any(|request| now >= request.deadline)
                    {
                        // §13: close and resume later; never re-request on
                        // the same stream.
                        return Err(violation(FailureCode::Timeout));
                    }
                }
                Incoming::Ended(ended) => {
                    if ended.cancel.is_some_and(|cancel| now >= cancel.deadline) {
                        return Err(violation(FailureCode::Timeout));
                    }
                }
                Incoming::Assembling(_) | Incoming::Offered(_) => {}
            }
        }
        Ok(())
    }

    /// Issues `ChunkRequest`s up to the budgets (§7.4, §13): at most
    /// `min(own, peer)` outstanding, at most two active files, lowest
    /// missing segment first; retained segments are revalidated under this
    /// session's key instead of requested (§7.5).
    pub(super) fn schedule(&mut self, now: Duration) -> Handled {
        let Phase::Ready(negotiated) = &self.phase else {
            return Ok(());
        };
        let mut pass = Pass {
            limit: negotiated.request_limit(),
            outstanding: 0,
            active: Vec::new(),
            budget: REVALIDATION_BUDGET,
            requests: Vec::new(),
            events: Vec::new(),
            pending: false,
            stop: false,
            now,
            transport: self.config.transport,
        };
        for (transfer_id, transfer) in &self.incoming {
            if let Incoming::Receiving(receiving) = transfer {
                pass.outstanding += receiving.outstanding.len();
                for request in receiving.outstanding.values() {
                    if !pass.active.contains(&(*transfer_id, request.file_id)) {
                        pass.active.push((*transfer_id, request.file_id));
                    }
                }
            }
        }
        for (transfer_id, transfer) in &mut self.incoming {
            let Incoming::Receiving(receiving) = transfer else {
                continue;
            };
            if now >= receiving.expiry {
                continue;
            }
            let file_ids: Vec<u32> = receiving.files.keys().copied().collect();
            for file_id in file_ids {
                schedule_file(&mut self.sink, transfer_id, receiving, file_id, &mut pass)?;
                if pass.stop {
                    break;
                }
            }
            if pass.stop {
                break;
            }
        }
        self.revalidation_pending = pass.pending;
        for request in pass.requests {
            self.queue(FrameType::CHUNK_REQUEST, request);
        }
        for event in pass.events {
            self.event(event);
        }
        Ok(())
    }

    /// Publishes complete files and, once every selected file is
    /// published, sends `Complete` and the signed receipt (§7.7).
    pub(super) fn publish_ready(&mut self, now: Duration) {
        let ids: Vec<TransferId> = self
            .incoming
            .iter()
            .filter(|(_, transfer)| matches!(transfer, Incoming::Receiving(_)))
            .map(|(id, _)| *id)
            .collect();
        for transfer_id in ids {
            self.publish_transfer(&transfer_id, now);
        }
    }

    fn publish_transfer(&mut self, transfer_id: &TransferId, now: Duration) {
        let wall = self.wall(now);
        let Some(Incoming::Receiving(receiving)) = self.incoming.get_mut(transfer_id) else {
            return;
        };
        if now >= receiving.expiry {
            return;
        }
        let ready: Vec<(u32, u32)> = receiving
            .files
            .iter()
            .filter_map(|(id, state)| match state {
                FileState::Receiving(file) if file.tracker.is_complete() => {
                    Some((*id, file.tracker.segment_count()))
                }
                _ => None,
            })
            .collect();
        let mut published = Vec::new();
        let mut failure = None;
        for (file_id, segment_count) in ready {
            match self.sink.publish(&receiving.manifest, file_id) {
                Ok(()) => {
                    receiving
                        .files
                        .insert(file_id, FileState::Published { segment_count });
                    receiving.files_done += 1;
                    published.push(file_id);
                }
                Err(SinkError::Integrity) => {
                    failure = Some(FailureCode::Integrity);
                    break;
                }
                Err(SinkError::Storage) => {
                    failure = Some(FailureCode::Storage);
                    break;
                }
            }
        }
        let all_published = receiving
            .files
            .values()
            .all(|state| matches!(state, FileState::Published { .. }));
        for file_id in published {
            self.event(TransferEvent::FileCompleted {
                transfer_id: *transfer_id,
                direction: Direction::Incoming,
                file_id,
            });
        }
        if let Some(code) = failure {
            self.fail_incoming(transfer_id, code);
            return;
        }
        if all_published {
            self.complete_incoming(transfer_id, wall);
        }
    }

    /// §7.7: `Complete`, then the signed `DeliveryReceipt`, only after every
    /// selected file is published while consent is valid.
    fn complete_incoming(&mut self, transfer_id: &TransferId, wall: UnixTime) {
        let Some(Incoming::Receiving(receiving)) = self.incoming.get(transfer_id) else {
            return;
        };
        let Some(accept) = receiving.accept() else {
            return;
        };
        let complete = Complete::new(
            *transfer_id,
            *accept.manifest_hash(),
            *accept.accept_hash(),
            accept.selected_count(),
            accept.selected_bytes(),
        );
        let receipt = sign_receipt(
            self.keys,
            &self.device_key,
            &self.session,
            accept,
            wall,
            wall,
        );
        // FileKeys not yet arrived (files an earlier session published need
        // no key) and the sender's one outstanding ResumeQuery may cross the
        // Complete.
        let pending_keys = receiving
            .files
            .len()
            .saturating_sub(receiving.masters.len());
        let (Ok(complete), Ok(receipt)) = (complete, receipt) else {
            // The files are published but cannot be confirmed: §7.7 allows
            // no Complete without its receipt. Tell the sender at once, or
            // it holds the masters until the Accept expires. KeyStore has no
            // §12 code and STATE is session-scoped only; STORAGE is the
            // transfer-scoped code for a local failure to finish delivery.
            self.fail_incoming_as(transfer_id, FailureCode::KeyStore, FailureCode::Storage);
            return;
        };
        self.queue(FrameType::COMPLETE, complete.encode().to_vec());
        self.queue(FrameType::DELIVERY_RECEIPT, receipt.encode().to_vec());
        self.sink.finish(transfer_id);
        let late = Late {
            file_keys: u32::try_from(pending_keys).unwrap_or(u32::MAX),
            resume_queries: 1,
            ..Late::default()
        };
        self.end_incoming(transfer_id, Outcome::Completed, late);
        self.event(TransferEvent::Completed {
            transfer_id: *transfer_id,
        });
    }
}

fn progress_of(
    transfer_id: &TransferId,
    receiving: &mut Receiving,
    now: Duration,
    transport: &'static str,
) -> Option<Progress> {
    let accept = receiving.gate.proof()?;
    let total = accept.selected_bytes();
    let files_total = accept.selected_count();
    let done = receiving.bytes_done;
    let (bytes_per_second, eta) = receiving.meter.record(now, done, total)?;
    Some(Progress {
        transfer_id: *transfer_id,
        direction: Direction::Incoming,
        bytes_done: done,
        bytes_total: total,
        files_done: receiving.files_done,
        files_total,
        bytes_per_second,
        eta,
        transport,
    })
}

/// One scheduling pass's shared budgets and output.
struct Pass {
    limit: usize,
    outstanding: usize,
    /// Files with requests outstanding (at most two, §13).
    active: Vec<(TransferId, u32)>,
    /// Retained segments this pass may still revalidate.
    budget: u32,
    requests: Vec<Vec<u8>>,
    events: Vec<TransferEvent>,
    /// Revalidation stopped at the budget and continues next call.
    pending: bool,
    /// A session-wide limit was reached: no more requests in this pass.
    stop: bool,
    now: Duration,
    transport: &'static str,
}

/// Requests (or revalidates) the lowest missing segments of one file
/// until a budget is reached.
fn schedule_file<R: ReceiveSink>(
    sink: &mut R,
    transfer_id: &TransferId,
    receiving: &mut Receiving,
    file_id: u32,
    pass: &mut Pass,
) -> Handled {
    let Some(accept_hash) = receiving.accept().map(|accept| *accept.accept_hash()) else {
        return Ok(());
    };
    let key = (*transfer_id, file_id);
    while let Some(FileState::Receiving(file)) = receiving.files.get_mut(&file_id) {
        let is_active = pass.active.contains(&key);
        if pass.outstanding >= pass.limit {
            pass.stop = true;
            break;
        }
        if !is_active && pass.active.len() >= MAX_ACTIVE_INCOMING_FILES {
            break;
        }
        let Some(index) = file.tracker.missing_from(file.cursor).next() else {
            break;
        };
        // A retained segment from an earlier session counts only after it
        // opens under this session's key (§7.5).
        match sink.retained_segment(transfer_id, file_id, index) {
            Ok(Some(ciphertext)) => {
                if pass.budget == 0 {
                    pass.pending = true;
                    pass.stop = true;
                    break;
                }
                pass.budget -= 1;
                file.cursor = index.saturating_add(1);
                if let Ok(segment) = file.opener.open_segment(index, &ciphertext)
                    && file.tracker.can_record(index) == Ok(true)
                    && file.tracker.record(&segment).is_ok()
                {
                    receiving.bytes_done = receiving
                        .bytes_done
                        .saturating_add(u64::from(segment.segment().len()));
                    if let Some(progress) =
                        progress_of(transfer_id, receiving, pass.now, pass.transport)
                    {
                        pass.events.push(TransferEvent::Progress(progress));
                    }
                    continue;
                }
                sink.drop_segment(transfer_id, file_id, index);
                file.cursor = index;
            }
            Ok(None) => {}
            Err(SinkError::Storage | SinkError::Integrity) => {
                return Err(violation(FailureCode::Storage));
            }
        }
        if file.tracker.can_record(index) != Ok(true) {
            break;
        }
        let request_id = receiving.next_request_id;
        if request_id == 0 {
            // §7.4: counter exhaustion needs a new session and Accept.
            pass.stop = true;
            break;
        }
        let Ok(request) = ChunkRequest::new(*transfer_id, accept_hash, request_id, file_id, index)
        else {
            break;
        };
        receiving.next_request_id = request_id.checked_add(1).unwrap_or(0);
        receiving.outstanding.insert(
            request_id,
            Request {
                file_id,
                index,
                deadline: pass.now.saturating_add(CHUNK_REQUEST_TIMEOUT),
            },
        );
        file.cursor = index.saturating_add(1);
        pass.requests.push(request.encode().to_vec());
        pass.outstanding += 1;
        if !is_active {
            pass.active.push(key);
        }
    }
    Ok(())
}
