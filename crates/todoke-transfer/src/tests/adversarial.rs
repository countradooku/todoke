//! Proptest state machines: an honest sender engine (Alice) and an honest
//! receiver engine (Bob) joined by wires an adversary controls in both
//! directions. Each engine therefore faces a malicious authenticated peer
//! that reorders, duplicates, drops, truncates, extends (oversized), bit
//! flips, and replays frames, and injects forged ones: content and keys
//! before consent or outside the selection, records for another session or
//! another Accept, Accepts signed by the wrong key or for another session,
//! expired Accepts, and forged receipts. Users accept, reject, and cancel
//! at arbitrary moments, and time jumps.
//!
//! Invariants, checked after every operation and at the end:
//!
//! - **Receiver consent:** Bob stores or publishes nothing for the transfer
//!   unless Bob's user accepted it; every published file is selected and
//!   byte-for-byte the sender's file; no progress before Bob's Accepted
//!   event.
//! - **Sender consent:** every `FileKey` and `Chunk` Alice emits names the
//!   hash of an Accept signed with Bob's key for this session and a file in
//!   its selection, and only after Alice reported the Accept.
//! - **Receipts:** Alice confirms delivery only after Bob completed.
//! - **Closure:** a closed engine accepts nothing more.
//! - **Honest runs:** with an untouched wire, only users acting and time
//!   moving, no engine reports a protocol violation (cancel and timer races
//!   included); at most a deadline closes the session.

use core::time::Duration;
use std::collections::BTreeSet;

use proptest::prelude::*;
use todoke_crypto::consent::{accept_hash, sign_accept};
use todoke_crypto::content::{ContentSuites, FileKeyBody, FileMaster};
use todoke_crypto::identity::{KeyStore, SigningDomain};
use todoke_proto::session::FrameType;
use todoke_proto::transfer::{
    Accept, AcceptBody, CancelReason, Chunk, ChunkRequest, Complete, ManifestPart, ManifestStart,
    RejectReason, ResumeQuery, ResumeStatus, TransferId,
};

use super::basic::standard_specs;
use super::support::{
    AnyResult, Fixture, Link, START, TestResult, WALL, Which, build_offer, config, content,
    deliver_to, fixture, raw, time,
};
use crate::{
    EngineError, FailureCode, MemorySink, MemorySource, OutgoingFrame, ReceiveSink, TransferEvent,
};

#[derive(Clone, Copy, Debug)]
enum Forge {
    /// Toward Bob: a chunk with the chosen file, index, request ID, and
    /// hash (real or zero), content of the chosen length.
    Chunk {
        file: u8,
        index: u8,
        request: u8,
        real_hash: bool,
        len: u16,
    },
    /// Toward Bob: a `FileKey` for the chosen file and hash.
    FileKey { file: u8, real_hash: bool },
    /// Toward Bob: another `ManifestStart` (same or new transfer).
    ManifestStart { same: bool, len: u32 },
    /// Toward Bob: a manifest part at an arbitrary offset.
    ManifestPart { offset: u16, len: u16 },
    /// Toward Bob: a resume query.
    ResumeQuery { file: u8, from: u8 },
    /// Toward Alice: an Accept signed by Bob's key for the other session.
    AcceptOtherSession { selection: u8 },
    /// Toward Alice: an Accept for this session signed by Alice's key.
    AcceptWrongSigner { selection: u8 },
    /// Toward Alice: an Accept by Bob's key for this session with any
    /// selection (a receiver device may sign what it likes).
    AcceptByReceiverKey { selection: u8 },
    /// Toward Alice: an Accept by Bob's key for this session whose expiry
    /// has already passed.
    AcceptExpired { selection: u8 },
    /// Toward Alice: a request with the chosen fields.
    Request {
        file: u8,
        index: u8,
        request: u32,
        real_hash: bool,
    },
    /// Toward Alice: a Complete and a receipt of random bytes.
    Completion { count: u8 },
    /// Toward Alice: a resume status.
    ResumeStatus { file: u8, next: u8 },
    /// Either way: a frame body of the maximum size.
    Oversized { to_bob: bool, kind: u8 },
}

#[derive(Clone, Debug)]
enum Op {
    Deliver(bool),
    /// Delivers every frame on that wire, and what they cause, honestly.
    DeliverAll(bool),
    Duplicate(bool),
    Swap(bool),
    Drop(bool),
    Flip(bool, u16, u8),
    Truncate(bool, u16),
    Extend(bool, u8),
    Replay(bool, u8),
    Forge(Forge),
    Accept(u8),
    Reject,
    Cancel(bool),
    Advance(u16),
    /// The connection drops; the transfer resumes in the fixture's second
    /// session (fresh consent needed), once per run. With `true`, Bob's
    /// sink revokes Alice first, so resume must be refused.
    Reconnect(bool),
}

impl Op {
    const fn is_adversarial(&self) -> bool {
        !matches!(
            self,
            Self::Deliver(_)
                | Self::DeliverAll(_)
                | Self::Accept(_)
                | Self::Reject
                | Self::Cancel(_)
                | Self::Advance(_)
                | Self::Reconnect(_)
        )
    }
}

fn arb_forge() -> impl Strategy<Value = Forge> {
    prop_oneof![
        (0..8u8, 0..4u8, 0..40u8, any::<bool>(), 0..32_800u16).prop_map(
            |(file, index, request, real_hash, len)| Forge::Chunk {
                file,
                index,
                request,
                real_hash,
                len
            }
        ),
        (0..8u8, any::<bool>()).prop_map(|(file, real_hash)| Forge::FileKey { file, real_hash }),
        (any::<bool>(), any::<u32>()).prop_map(|(same, len)| Forge::ManifestStart { same, len }),
        (any::<u16>(), 0..2000u16).prop_map(|(offset, len)| Forge::ManifestPart { offset, len }),
        (0..8u8, 0..8u8).prop_map(|(file, from)| Forge::ResumeQuery { file, from }),
        any::<u8>().prop_map(|selection| Forge::AcceptOtherSession { selection }),
        any::<u8>().prop_map(|selection| Forge::AcceptWrongSigner { selection }),
        any::<u8>().prop_map(|selection| Forge::AcceptByReceiverKey { selection }),
        any::<u8>().prop_map(|selection| Forge::AcceptExpired { selection }),
        (0..8u8, 0..8u8, any::<u32>(), any::<bool>()).prop_map(
            |(file, index, request, real_hash)| Forge::Request {
                file,
                index,
                request,
                real_hash
            }
        ),
        (0..6u8).prop_map(|count| Forge::Completion { count }),
        (0..8u8, 0..8u8).prop_map(|(file, next)| Forge::ResumeStatus { file, next }),
        (any::<bool>(), 0..16u8).prop_map(|(to_bob, kind)| Forge::Oversized { to_bob, kind }),
    ]
}

fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        20 => any::<bool>().prop_map(Op::Deliver),
        4 => any::<bool>().prop_map(Op::DeliverAll),
        1 => any::<bool>().prop_map(Op::Duplicate),
        1 => any::<bool>().prop_map(Op::Swap),
        1 => any::<bool>().prop_map(Op::Drop),
        1 => (any::<bool>(), any::<u16>(), 0..8u8).prop_map(|(d, p, b)| Op::Flip(d, p, b)),
        1 => (any::<bool>(), any::<u16>()).prop_map(|(d, n)| Op::Truncate(d, n)),
        1 => (any::<bool>(), any::<u8>()).prop_map(|(d, n)| Op::Extend(d, n)),
        1 => (any::<bool>(), any::<u8>()).prop_map(|(d, n)| Op::Replay(d, n)),
        2 => arb_forge().prop_map(Op::Forge),
        2 => any::<u8>().prop_map(Op::Accept),
        1 => Just(Op::Reject),
        1 => any::<bool>().prop_map(Op::Cancel),
        1 => (0..400u16).prop_map(Op::Advance),
        1 => any::<bool>().prop_map(Op::Reconnect),
    ]
}

fn arb_honest_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        14 => any::<bool>().prop_map(Op::Deliver),
        3 => any::<bool>().prop_map(Op::DeliverAll),
        2 => any::<u8>().prop_map(Op::Accept),
        1 => Just(Op::Reject),
        1 => any::<bool>().prop_map(Op::Cancel),
        2 => (0..4u16).prop_map(Op::Advance),
        1 => any::<bool>().prop_map(Op::Reconnect),
    ]
}

/// The run's state as the test tracks it.
struct Run<'k> {
    fixture: &'k Fixture,
    link: Link<'k>,
    transfer_id: TransferId,
    manifest: todoke_crypto::consent::CanonicalManifest,
    files: Vec<(u32, Vec<u8>)>,
    /// What Bob's user accepted.
    accepted: Option<Vec<u32>>,
    /// Hashes and selections of Accepts signed with Bob's key for this
    /// session (Bob's own, or a forged-by-receiver-key one).
    bob_accepts: Vec<([u8; 32], Vec<u32>)>,
    history_to_bob: Vec<OutgoingFrame>,
    history_to_alice: Vec<OutgoingFrame>,
    /// Session failures each side reported.
    failures: Vec<FailureCode>,
    /// Whether Bob's user accepted in any session.
    ever_accepted: bool,
    /// Every selection Bob's user accepted, across sessions.
    selections: Vec<Vec<u32>>,
    /// The transfer resumed in the second session (at most once).
    reconnected: bool,
    /// Segments Bob held when the second session started.
    stored_at_reconnect: usize,
    /// Bob's sink revoked Alice before the second session while it held
    /// resumable state for the transfer.
    revoked: bool,
}

type CaseResult = Result<(), TestCaseError>;

fn fail(error: impl std::fmt::Display) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}

fn selection_from(bits: u8, files: &[u32]) -> Vec<u32> {
    files
        .iter()
        .enumerate()
        .filter(|(index, _)| bits & (1 << index) != 0)
        .map(|(_, id)| *id)
        .collect()
}

impl<'k> Run<'k> {
    fn new(fixture: &'k Fixture) -> AnyResult<Self> {
        let mut source = MemorySource::new();
        let specs = standard_specs();
        let offer = build_offer(
            &fixture.alice.key(),
            &fixture.bob.key(),
            &specs,
            &mut source,
            3600,
        )?;
        let transfer_id = *offer.transfer_id();
        let manifest = offer.manifest().clone();
        let files = vec![
            (2, content(40_000, 1)),
            (3, content(0, 2)),
            (5, content(16_384 * 3 + 5, 3)),
            (6, content(100, 4)),
        ];
        let mut link = Link::new(
            fixture,
            Which::First,
            (source, MemorySource::new()),
            (MemorySink::new(), MemorySink::new()),
            (config(4)?, config(3)?),
        )?;
        link.settle()?;
        link.a.offer(offer, link.now)?;
        link.collect();
        Ok(Self {
            fixture,
            link,
            transfer_id,
            manifest,
            files,
            accepted: None,
            bob_accepts: Vec::new(),
            history_to_bob: Vec::new(),
            history_to_alice: Vec::new(),
            failures: Vec::new(),
            ever_accepted: false,
            selections: Vec::new(),
            reconnected: false,
            stored_at_reconnect: 0,
            revoked: false,
        })
    }

    fn record(&mut self, result: Result<(), EngineError>) {
        if let Err(EngineError::Session(failure)) = result {
            self.failures.push(failure.code);
        }
    }

    fn wire(&mut self, to_bob: bool) -> &mut std::collections::VecDeque<OutgoingFrame> {
        if to_bob {
            &mut self.link.to_b
        } else {
            &mut self.link.to_a
        }
    }

    fn inject(&mut self, to_bob: bool, frame_type: FrameType, body: Vec<u8>) {
        let frame = OutgoingFrame::Frame {
            frame_type,
            body: zeroize::Zeroizing::new(body),
        };
        self.deliver_frame(to_bob, frame);
    }

    fn deliver_frame(&mut self, to_bob: bool, frame: OutgoingFrame) {
        if to_bob {
            self.history_to_bob.push(frame.clone());
        } else {
            self.history_to_alice.push(frame.clone());
        }
        let now = self.link.now;
        let engine = if to_bob {
            &mut self.link.b
        } else {
            &mut self.link.a
        };
        let result = deliver_to(engine, frame, now);
        self.record(result);
        self.link.collect();
    }

    fn deliver(&mut self, to_bob: bool) {
        self.link.collect();
        if let Some(frame) = self.wire(to_bob).pop_front() {
            self.deliver_frame(to_bob, frame);
        }
    }

    fn mutate_next(&mut self, to_bob: bool, change: impl FnOnce(&mut Vec<u8>)) {
        self.link.collect();
        let Some(frame) = self.wire(to_bob).pop_front() else {
            return;
        };
        let (frame_type, mut body) = raw(&frame);
        change(&mut body);
        body.truncate(todoke_proto::session::MAX_BODY_LEN);
        self.inject(to_bob, frame_type, body);
    }

    /// Drops the connection and resumes in the second session: Alice
    /// re-offers whatever is resumable; Bob must consent again.
    fn reconnect(&mut self, revoke: bool) -> TestResult {
        if self.reconnected {
            return Ok(());
        }
        self.reconnected = true;
        self.link.a.close(None);
        self.link.b.close(None);
        self.link.collect();
        let now = self.link.now;
        let placeholder = Link::new(
            self.fixture,
            Which::Second,
            (MemorySource::new(), MemorySource::new()),
            (MemorySink::new(), MemorySink::new()),
            (config(4)?, config(3)?),
        )?;
        let mut old = core::mem::replace(&mut self.link, placeholder);
        let offers = old.a.take_resumable();
        let (a_source, a_sink) = old.a.into_parts();
        let (b_source, mut b_sink) = old.b.into_parts();
        if revoke {
            // Only retained state is revocable; a transfer Bob never
            // accepted left nothing behind and may be offered afresh.
            let wall = time(WALL + now.saturating_sub(START).as_secs())?;
            self.revoked = b_sink.retained(&self.transfer_id, wall).is_some();
            b_sink.revoke_sender(&self.fixture.alice.key(), time(WALL + 30 * 86_400)?);
        }
        self.stored_at_reconnect = b_sink.stored_segments(&self.transfer_id);
        let mut link = Link::new(
            self.fixture,
            Which::Second,
            (a_source, b_source),
            (a_sink, b_sink),
            (config(4)?, config(3)?),
        )?;
        link.now = now;
        link.settle()?;
        for offer in offers {
            link.a.offer(offer, link.now)?;
        }
        link.collect();
        self.link = link;
        self.accepted = None;
        self.bob_accepts.clear();
        self.history_to_bob.clear();
        self.history_to_alice.clear();
        Ok(())
    }

    /// The real Accept hash Alice and Bob use, once Bob accepted.
    fn real_hash(&self) -> [u8; 32] {
        self.bob_accepts.first().map_or([0; 32], |(hash, _)| *hash)
    }

    #[expect(clippy::too_many_lines, reason = "one arm per forged record kind")]
    fn forge(&mut self, forge: Forge) -> TestResult {
        let id = self.transfer_id;
        let file_ids: Vec<u32> = self.files.iter().map(|(id, _)| *id).collect();
        let hash = |real: bool| if real { self.real_hash() } else { [0; 32] };
        let fixture_now = time(WALL)?;
        let expires = time(WALL + 600)?;
        let suite = ContentSuites::local()
            .select(ContentSuites::local())
            .ok_or("suite")?;
        match forge {
            Forge::Chunk {
                file,
                index,
                request,
                real_hash,
                len,
            } => {
                let content = vec![0x5a; usize::from(len).clamp(24, 32_784)];
                if let Ok(chunk) = Chunk::new(
                    id,
                    hash(real_hash),
                    u32::from(request) + 1,
                    u32::from(file) + 1,
                    u32::from(index),
                    &content,
                ) {
                    self.inject(true, FrameType::CHUNK, chunk.encode());
                }
            }
            Forge::FileKey { file, real_hash } => {
                let key = FileKeyBody::new(
                    id,
                    hash(real_hash),
                    u32::from(file) + 1,
                    suite,
                    FileMaster::generate()?,
                )?;
                self.inject(true, FrameType::FILE_KEY, key.encode().to_vec());
            }
            Forge::ManifestStart { same, len } => {
                let target = if same { id } else { [0x77; 16] };
                let len = len % 4_194_400;
                if let Ok(start) = ManifestStart::new(target, [1; 32], len) {
                    self.inject(true, FrameType::MANIFEST_START, start.encode().to_vec());
                }
            }
            Forge::ManifestPart { offset, len } => {
                let data = vec![0x11; usize::from(len).max(1)];
                if let Ok(part) = ManifestPart::new(id, u32::from(offset), &data) {
                    self.inject(true, FrameType::MANIFEST_PART, part.encode());
                }
            }
            Forge::ResumeQuery { file, from } => {
                let query =
                    ResumeQuery::new(id, self.real_hash(), u32::from(file) + 1, u32::from(from))?;
                self.inject(true, FrameType::RESUME_QUERY, query.encode().to_vec());
            }
            Forge::AcceptOtherSession { selection } => {
                let fixture = fixture()?;
                let selection = selection_from(selection, &file_ids);
                let other = if self.reconnected {
                    &fixture.first.1
                } else {
                    &fixture.second.1
                };
                if let Ok(accept) = sign_accept(
                    &fixture.bob.keys,
                    &fixture.bob.signing_key,
                    other,
                    &self.manifest,
                    selection,
                    expires,
                    fixture_now,
                ) {
                    self.inject(false, FrameType::ACCEPT, accept.encoded().to_vec());
                }
            }
            Forge::AcceptWrongSigner { selection } => {
                let fixture = fixture()?;
                let selection = selection_from(selection, &file_ids);
                if let Ok(body) = AcceptBody::new(
                    *fixture.first.0.session_id(),
                    id,
                    *self.manifest.hash(),
                    *fixture.alice.key().as_bytes(),
                    *fixture.bob.key().as_bytes(),
                    [0x3c; 16],
                    expires,
                    selection,
                ) {
                    let signature = fixture.alice.keys.sign(
                        &fixture.alice.signing_key,
                        SigningDomain::Accept,
                        &body.encode(),
                    )?;
                    let accept = Accept::new(body, signature.to_bytes());
                    self.inject(false, FrameType::ACCEPT, accept.encode());
                }
            }
            Forge::AcceptByReceiverKey { selection } => {
                let fixture = fixture()?;
                let selection = selection_from(selection, &file_ids);
                let current = if self.reconnected {
                    &fixture.second.1
                } else {
                    &fixture.first.1
                };
                if let Ok(accept) = sign_accept(
                    &fixture.bob.keys,
                    &fixture.bob.signing_key,
                    current,
                    &self.manifest,
                    selection,
                    expires,
                    fixture_now,
                ) {
                    self.bob_accepts
                        .push((*accept.accept_hash(), accept.selection().to_vec()));
                    self.inject(false, FrameType::ACCEPT, accept.encoded().to_vec());
                }
            }
            Forge::AcceptExpired { selection } => {
                let fixture = fixture()?;
                let selection = selection_from(selection, &file_ids);
                let elapsed = self.link.now.saturating_sub(START).as_secs();
                let passed = time((WALL + elapsed).saturating_sub(1))?;
                let session = if self.reconnected {
                    &fixture.second.1
                } else {
                    &fixture.first.1
                };
                if let Ok(body) = AcceptBody::new(
                    *session.session_id(),
                    id,
                    *self.manifest.hash(),
                    *fixture.alice.key().as_bytes(),
                    *fixture.bob.key().as_bytes(),
                    [0x3d; 16],
                    passed,
                    selection,
                ) {
                    let signature = fixture.bob.keys.sign(
                        &fixture.bob.signing_key,
                        SigningDomain::Accept,
                        &body.encode(),
                    )?;
                    let accept = Accept::new(body, signature.to_bytes());
                    self.inject(false, FrameType::ACCEPT, accept.encode());
                }
            }
            Forge::Request {
                file,
                index,
                request,
                real_hash,
            } => {
                if let Ok(request) = ChunkRequest::new(
                    id,
                    hash(real_hash),
                    request.max(1),
                    u32::from(file) + 1,
                    u32::from(index),
                ) {
                    self.inject(false, FrameType::CHUNK_REQUEST, request.encode().to_vec());
                }
            }
            Forge::Completion { count } => {
                if let Ok(complete) = Complete::new(
                    id,
                    *self.manifest.hash(),
                    self.real_hash(),
                    u32::from(count).max(1),
                    40_000,
                ) {
                    self.inject(false, FrameType::COMPLETE, complete.encode().to_vec());
                }
                self.inject(false, FrameType::DELIVERY_RECEIPT, vec![0x42; 279]);
            }
            Forge::ResumeStatus { file, next } => {
                if let Ok(status) = ResumeStatus::new(
                    id,
                    self.real_hash(),
                    u32::from(file) + 1,
                    0,
                    u32::from(next),
                    vec![],
                ) {
                    self.inject(false, FrameType::RESUME_STATUS, status.encode());
                }
            }
            Forge::Oversized { to_bob, kind } => {
                let frame_type = FrameType::new(0x0010 + u16::from(kind % 13));
                let mut body = vec![0xee; todoke_proto::session::MAX_BODY_LEN];
                body[..16].copy_from_slice(&id);
                self.inject(to_bob, frame_type, body);
            }
        }
        Ok(())
    }

    #[expect(clippy::too_many_lines, reason = "one arm per operation")]
    fn apply(&mut self, op: &Op) -> CaseResult {
        match op {
            Op::Deliver(to_bob) => self.deliver(*to_bob),
            Op::DeliverAll(to_bob) => {
                for _ in 0..10_000 {
                    self.link.collect();
                    if self.wire(*to_bob).is_empty() {
                        break;
                    }
                    self.deliver(*to_bob);
                }
            }
            Op::Duplicate(to_bob) => {
                self.link.collect();
                if let Some(frame) = self.wire(*to_bob).front().cloned() {
                    self.deliver_frame(*to_bob, frame);
                    self.deliver(*to_bob);
                }
            }
            Op::Swap(to_bob) => {
                self.link.collect();
                let wire = self.wire(*to_bob);
                if wire.len() >= 2 {
                    wire.swap(0, 1);
                }
            }
            Op::Drop(to_bob) => {
                self.link.collect();
                self.wire(*to_bob).pop_front();
            }
            Op::Flip(to_bob, position, bit) => self.mutate_next(*to_bob, |body| {
                if !body.is_empty() {
                    let index = usize::from(*position) % body.len();
                    body[index] ^= 1 << bit;
                }
            }),
            Op::Truncate(to_bob, cut) => self.mutate_next(*to_bob, |body| {
                let keep = usize::from(*cut) % body.len().max(1);
                body.truncate(keep);
            }),
            Op::Extend(to_bob, extra) => self.mutate_next(*to_bob, |body| {
                body.extend(core::iter::repeat_n(0xab, usize::from(*extra) + 1));
            }),
            Op::Replay(to_bob, pick) => {
                let history = if *to_bob {
                    &self.history_to_bob
                } else {
                    &self.history_to_alice
                };
                if !history.is_empty() {
                    let frame = history[usize::from(*pick) % history.len()].clone();
                    self.deliver_frame(*to_bob, frame);
                }
            }
            Op::Forge(forge) => self.forge(*forge).map_err(fail)?,
            Op::Accept(bits) => {
                let file_ids: Vec<u32> = self.files.iter().map(|(id, _)| *id).collect();
                let selection = selection_from(*bits, &file_ids);
                let now = self.link.now;
                if self
                    .link
                    .b
                    .accept(&self.transfer_id, selection.clone(), now)
                    .is_ok()
                {
                    self.accepted = Some(selection.clone());
                    self.ever_accepted = true;
                    self.selections.push(selection.clone());
                    self.link.collect();
                    if let Some(frame) = self
                        .link
                        .emitted_b
                        .iter()
                        .rev()
                        .find(|f| raw(f).0 == FrameType::ACCEPT)
                    {
                        self.bob_accepts
                            .push((accept_hash(&raw(frame).1), selection));
                    }
                }
            }
            Op::Reject => {
                let _ = self
                    .link
                    .b
                    .reject(&self.transfer_id, RejectReason::Declined);
                self.link.collect();
            }
            Op::Cancel(by_bob) => {
                let now = self.link.now;
                let engine = if *by_bob {
                    &mut self.link.b
                } else {
                    &mut self.link.a
                };
                let _ = engine.cancel(&self.transfer_id, CancelReason::User, now);
                self.link.collect();
            }
            Op::Advance(seconds) => {
                let (a, b) = self.link.advance(Duration::from_secs(u64::from(*seconds)));
                self.record(a);
                self.record(b);
            }
            Op::Reconnect(revoke) => self.reconnect(*revoke).map_err(fail)?,
        }
        self.check()
    }

    /// The invariants in the module documentation.
    fn check(&mut self) -> CaseResult {
        self.link.collect();
        let id = self.transfer_id;
        // Receiver consent.
        let sink = self.link.b.sink();
        if !self.ever_accepted {
            prop_assert_eq!(sink.stored_segments(&id), 0);
            prop_assert_eq!(sink.published_count(), 0);
        }
        // Retained data only grows under this session's consent.
        if self.reconnected && self.accepted.is_none() {
            let stored = sink.stored_segments(&id);
            prop_assert!(
                stored <= self.stored_at_reconnect,
                "stored without this session's consent"
            );
        }
        // After revocation nothing of the transfer remains or returns.
        if self.revoked {
            prop_assert_eq!(sink.stored_segments(&id), 0);
            prop_assert!(self.accepted.is_none(), "accepted after revocation");
        }
        for (file_id, bytes) in &self.files {
            if let Some(published) = sink.published(&id, *file_id) {
                let selected = self.selections.iter().any(|s| s.contains(file_id));
                prop_assert!(selected, "published unselected file {}", file_id);
                prop_assert_eq!(published, bytes.as_slice());
            }
        }
        let accepted_at = self
            .link
            .b_events
            .iter()
            .position(|e| matches!(e, TransferEvent::Accepted { .. }));
        let progress_at = self.link.b_events.iter().position(|e| {
            matches!(
                e,
                TransferEvent::Progress(_)
                    | TransferEvent::FileCompleted { .. }
                    | TransferEvent::Completed { .. }
            )
        });
        if let Some(progress) = progress_at {
            let ordered = accepted_at.is_some_and(|accepted| accepted < progress);
            prop_assert!(ordered, "progress before Bob's Accepted event");
        }
        // Sender consent.
        let alice_accepted = self.link.a_events.iter().any(
            |e| matches!(e, TransferEvent::Accepted { transfer_id, .. } if *transfer_id == id),
        );
        for frame in &self.link.emitted_a {
            let (frame_type, body) = raw(frame);
            let (hash, file) = match frame_type {
                FrameType::FILE_KEY => (
                    <[u8; 32]>::try_from(&body[16..48]).map_err(|_| TestCaseError::fail("key"))?,
                    u32::from_be_bytes(
                        body[48..52]
                            .try_into()
                            .map_err(|_| TestCaseError::fail("key"))?,
                    ),
                ),
                FrameType::CHUNK => {
                    let chunk = Chunk::decode(&body).map_err(|_| TestCaseError::fail("chunk"))?;
                    (*chunk.accept_hash(), chunk.file_id())
                }
                _ => continue,
            };
            prop_assert!(alice_accepted, "content before Alice's Accepted event");
            let covered = self
                .bob_accepts
                .iter()
                .any(|(accepted, selection)| *accepted == hash && selection.contains(&file));
            prop_assert!(
                covered,
                "Alice sent file {} without a matching Accept",
                file
            );
        }
        // Receipts.
        if self
            .link
            .a_events
            .iter()
            .any(|e| matches!(e, TransferEvent::DeliveryConfirmed { .. }))
        {
            let completed = self
                .link
                .b_events
                .iter()
                .any(|e| matches!(e, TransferEvent::Completed { .. }));
            prop_assert!(completed, "delivery confirmed without completion");
        }
        // Closure.
        let now = self.link.now;
        for engine in [&mut self.link.a, &mut self.link.b] {
            if engine.is_closed() {
                prop_assert_eq!(
                    engine.handle_frame(FrameType::CANCEL, &[0; 66], now),
                    Err(EngineError::Closed)
                );
                prop_assert_eq!(engine.accept(&id, vec![2], now), Err(EngineError::Closed));
            }
        }
        Ok(())
    }

    /// An honest start: `0` from the offer on the wire, `1` from Bob's
    /// Accept for `bits`, `2` from the first stored segment.
    fn prefix(&mut self, start: u8, bits: u8) -> CaseResult {
        if start == 0 {
            return Ok(());
        }
        self.apply(&Op::DeliverAll(true))?;
        self.apply(&Op::Accept(bits))?;
        if start == 2 {
            for _ in 0..10_000 {
                self.link.collect();
                if self.link.b.sink().stored_segments(&self.transfer_id) > 0
                    || self.link.b.sink().published_count() > 0
                    || (self.link.to_a.is_empty() && self.link.to_b.is_empty())
                {
                    break;
                }
                let to_bob = !self.link.to_b.is_empty();
                self.deliver(to_bob);
            }
        }
        self.check()
    }

    /// Delivers whatever is left, honestly.
    fn drain(&mut self) -> CaseResult {
        for _ in 0..20_000 {
            self.link.collect();
            if self.link.to_b.is_empty() && self.link.to_a.is_empty() {
                break;
            }
            let to_bob = !self.link.to_b.is_empty();
            self.deliver(to_bob);
        }
        self.check()
    }
}

fn config_cases() -> ProptestConfig {
    ProptestConfig {
        cases: 128,
        max_shrink_iters: 2000,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config_cases())]

    /// Both engines against a malicious peer: the invariants hold whatever
    /// the wire does.
    #[test]
    fn engines_hold_consent_against_an_adversarial_peer(
        start in 0..3u8,
        bits in 1..16u8,
        ops in proptest::collection::vec(arb_op(), 1..120),
    ) {
        let fixture = fixture().map_err(fail)?;
        let mut run = Run::new(&fixture).map_err(fail)?;
        run.prefix(start, bits)?;
        for op in &ops {
            run.apply(op)?;
        }
        run.drain()?;
        if !ops.iter().any(Op::is_adversarial) {
            for failure in &run.failures {
                prop_assert_eq!(*failure, FailureCode::Timeout);
            }
        }
    }

    /// Honest wires with users acting at arbitrary moments (accept, reject,
    /// cancel on either side, small clock steps): no protocol violation
    /// ever, the transfer reaches the same end on both sides, and a
    /// completed transfer delivers exactly the selected files.
    #[test]
    fn honest_races_never_violate_the_protocol(ops in proptest::collection::vec(arb_honest_op(), 1..120)) {
        let fixture = fixture().map_err(fail)?;
        let mut run = Run::new(&fixture).map_err(fail)?;
        for op in &ops {
            run.apply(op)?;
        }
        run.drain()?;
        // Let every timer run out, delivering what they produce.
        for _ in 0..4 {
            let (a, b) = run.link.advance(Duration::from_secs(400));
            run.record(a);
            run.record(b);
            run.drain()?;
        }
        for failure in &run.failures {
            prop_assert_eq!(*failure, FailureCode::Timeout, "honest run failed: {:?}", run.failures);
        }
        let id = run.transfer_id;
        let ended = |events: &[TransferEvent]| events.iter().rev().find_map(|e| match e {
            TransferEvent::Completed { transfer_id }
            | TransferEvent::DeliveryConfirmed { transfer_id, .. } if *transfer_id == id => Some("done"),
            TransferEvent::Cancelled { transfer_id, .. } if *transfer_id == id => Some("cancelled"),
            TransferEvent::Rejected { transfer_id, .. } if *transfer_id == id => Some("rejected"),
            _ => None,
        });
        // A cancel may cross a completion (the receiver finished, the
        // sender cancelled before it heard): only cancel-free runs must end
        // the same way on both sides.
        if run.failures.is_empty() && !ops.iter().any(|op| matches!(op, Op::Cancel(_))) {
            prop_assert_eq!(ended(&run.link.a_events), ended(&run.link.b_events));
        }
        if run.link.b_events.iter().any(|e| matches!(e, TransferEvent::Completed { .. })) {
            let selection: BTreeSet<u32> = run.accepted.clone().unwrap_or_default().into_iter().collect();
            for (file_id, bytes) in &run.files {
                let published = run.link.b.sink().published(&id, *file_id);
                prop_assert_eq!(published.is_some(), selection.contains(file_id));
                if let Some(published) = published {
                    prop_assert_eq!(published, bytes.as_slice());
                }
            }
        }
    }
}
