//! Deterministic scenarios over the sans-IO link: every consent, ordering,
//! limit, timer, cancel, completion, expiry, and resume rule.

use core::time::Duration;

use todoke_crypto::consent::{CanonicalManifest, random_id, sign_accept};
use todoke_crypto::content::{ContentSuites, FileKeyBody, FileMaster};
use todoke_proto::session::{ErrorCode, FrameType};
use todoke_proto::transfer::{
    CancelReason, Capabilities, Chunk, ChunkRequest, ManifestPart, ManifestStart, RejectReason,
    TransferId,
};

use super::support::*;
use crate::{
    EngineError, FailureCode, MemorySink, MemorySource, OutgoingFrame, Party, SinkRefusal,
    TransferEvent,
};

pub(super) fn standard_specs() -> Vec<Spec> {
    vec![
        dir("photos", 0),
        file("a.bin", 1, 40_000, 1),
        file("empty", 1, 0, 2),
        dir("deep", 1),
        file("b.bin", 4, 16_384 * 3 + 5, 3),
        file("c.txt", 0, 100, 4),
    ]
}

/// A link with Capabilities exchanged and `specs` offered to Bob.
pub(super) fn offered<'f>(
    fixture: &'f Fixture,
    specs: &[Spec],
    lifetime: u64,
    configs: (u16, u16),
) -> AnyResult<(Link<'f>, TransferId, CanonicalManifest)> {
    let mut source = MemorySource::new();
    let offer = build_offer(
        &fixture.alice.key(),
        &fixture.bob.key(),
        specs,
        &mut source,
        lifetime,
    )?;
    let transfer_id = *offer.transfer_id();
    let manifest = offer.manifest().clone();
    let mut link = Link::new(
        fixture,
        Which::First,
        (source, MemorySource::new()),
        (MemorySink::new(), MemorySink::new()),
        (config(configs.0)?, config(configs.1)?),
    )?;
    link.settle()?;
    link.a.offer(offer, link.now)?;
    link.settle()?;
    if link.transfer_id_of_offer() != Some(transfer_id) {
        return Err("no offer".into());
    }
    Ok((link, transfer_id, manifest))
}

pub(super) fn session_failure(result: Result<(), EngineError>) -> Option<FailureCode> {
    match result {
        Err(EngineError::Session(failure)) => Some(failure.code),
        _ => None,
    }
}

pub(super) fn has(events: &[TransferEvent], test: impl Fn(&TransferEvent) -> bool) -> bool {
    events.iter().any(test)
}

pub(super) fn sent_session_error(link: &mut Link<'_>, to_bob: bool, code: ErrorCode) -> bool {
    link.collect();
    let wire = if to_bob { &link.to_b } else { &link.to_a };
    wire.iter().any(|frame| {
        matches!(frame, OutgoingFrame::Error(record)
            if record.scope() == todoke_proto::session::ErrorScope::Session && record.code() == code)
    })
}

pub(super) fn sent_transfer_error(link: &mut Link<'_>, to_bob: bool, code: ErrorCode) -> bool {
    link.collect();
    let wire = if to_bob { &link.to_b } else { &link.to_a };
    wire.iter().any(|frame| {
        matches!(frame, OutgoingFrame::Error(record)
            if matches!(record.scope(), todoke_proto::session::ErrorScope::Transfer(_)) && record.code() == code)
    })
}

#[test]
fn happy_path_multi_file_with_folders_and_empty_file() -> TestResult {
    let fixture = fixture()?;
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    let view = link
        .b_events
        .iter()
        .find_map(|event| match event {
            TransferEvent::OfferReceived(view) => Some(view.clone()),
            _ => None,
        })
        .ok_or("view")?;
    assert_eq!(view.file_count, 4);
    assert_eq!(view.entries.len(), 6);
    assert_eq!(view.entries[4].name, "b.bin");
    assert_eq!(view.sender, fixture.alice.key());
    assert!(view.resume_selection.is_none());
    // Names never appear in Debug output.
    let debug = format!("{:?}", link.b_events);
    assert!(!debug.contains("a.bin") && !debug.contains("photos") && !debug.contains("octet"));
    link.b.accept(&transfer_id, vec![2, 3, 5, 6], link.now)?;
    link.settle()?;
    let sink = link.b.sink();
    for (id, len, salt) in [
        (2, 40_000, 1),
        (3, 0, 2),
        (5, 16_384 * 3 + 5, 3),
        (6, 100, 4),
    ] {
        assert_eq!(
            sink.published(&transfer_id, id),
            Some(content(len, salt).as_slice()),
            "file {id}"
        );
    }
    assert_eq!(sink.stored_segments(&transfer_id), 0);
    assert!(has(&link.b_events, |e| matches!(
        e,
        TransferEvent::Completed { .. }
    )));
    assert!(has(&link.a_events, |e| matches!(
        e,
        TransferEvent::DeliveryConfirmed { .. }
    )));
    // Progress events carry the transport label and reach the total.
    let last = link
        .b_events
        .iter()
        .rev()
        .find_map(|event| match event {
            TransferEvent::Progress(progress) => Some(*progress),
            _ => None,
        })
        .ok_or("progress")?;
    assert_eq!(last.transport, "test-pipe");
    assert_eq!(last.bytes_done, last.bytes_total);
    assert_eq!(last.eta, Some(Duration::ZERO));
    // Accepted precedes every progress and completion event.
    let accepted = link
        .b_events
        .iter()
        .position(|e| matches!(e, TransferEvent::Accepted { .. }))
        .ok_or("accepted")?;
    let first_progress = link
        .b_events
        .iter()
        .position(|e| {
            matches!(
                e,
                TransferEvent::Progress(_) | TransferEvent::FileCompleted { .. }
            )
        })
        .ok_or("progress")?;
    assert!(accepted < first_progress);
    // A finished transfer is not resumable.
    assert!(link.a.take_resumable().is_empty());
    Ok(())
}

#[test]
fn partial_selection_publishes_only_selected_files() -> TestResult {
    let fixture = fixture()?;
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    link.b.accept(&transfer_id, vec![5], link.now)?;
    link.settle()?;
    let sink = link.b.sink();
    assert_eq!(sink.published_count(), 1);
    assert!(sink.published(&transfer_id, 5).is_some());
    for id in [2, 3, 6] {
        assert!(sink.published(&transfer_id, id).is_none());
    }
    assert!(has(&link.a_events, |e| matches!(
        e,
        TransferEvent::DeliveryConfirmed { .. }
    )));
    // Directories and unknown IDs cannot be selected.
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    for selection in [vec![1], vec![2, 7], vec![], vec![5, 2]] {
        assert_eq!(
            link.b.accept(&transfer_id, selection, link.now),
            Err(EngineError::Selection)
        );
    }
    Ok(())
}

#[test]
fn capabilities_are_exchanged_exactly_once_first() -> TestResult {
    let fixture = fixture()?;
    let link = |configs| {
        Link::new(
            &fixture,
            Which::First,
            (MemorySource::new(), MemorySource::new()),
            (MemorySink::new(), MemorySink::new()),
            configs,
        )
    };
    // The first frame each side queues is its Capabilities.
    let mut l = link((config(16)?, config(16)?))?;
    l.collect();
    let first = l.to_b.front().map(raw).ok_or("frame")?;
    assert_eq!(first.0, FrameType::CAPABILITIES);
    // A transfer frame before the peer's Capabilities is STATE.
    let start = ManifestStart::new([7; 16], [1; 32], 200)?;
    let result =
        l.b.handle_frame(FrameType::MANIFEST_START, &start.encode(), l.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    assert!(sent_session_error(&mut l, false, ErrorCode::STATE));
    assert!(l.b.is_closed());
    assert_eq!(
        l.b.handle_frame(FrameType::CAPABILITIES, &[], l.now),
        Err(EngineError::Closed)
    );
    // A second Capabilities is STATE.
    let mut l = link((config(16)?, config(16)?))?;
    l.settle()?;
    let caps = config(4)?.capabilities.record().encode();
    let result = l.b.handle_frame(FrameType::CAPABILITIES, &caps, l.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    // None within 5 seconds: TIMEOUT.
    let mut l = link((config(16)?, config(16)?))?;
    let (_, b) = l.advance(Duration::from_secs(5));
    assert_eq!(session_failure(b), Some(FailureCode::Timeout));
    assert!(has(&l.b_events, |e| matches!(
        e,
        TransferEvent::SessionClosed { failure: Some(_) }
    )));
    // Malformed, and without XChaCha (no common suite): rejected.
    let mut l = link((config(16)?, config(16)?))?;
    let result =
        l.b.handle_frame(FrameType::CAPABILITIES, &caps[..37], l.now);
    assert_eq!(session_failure(result), Some(FailureCode::Malformed));
    let mut l = link((config(16)?, config(16)?))?;
    let aes_only = Capabilities::PROTOCOL_MAXIMUMS
        .with_content_suites(0b01)?
        .encode();
    let result = l.b.handle_frame(FrameType::CAPABILITIES, &aes_only, l.now);
    assert_eq!(session_failure(result), Some(FailureCode::Unsupported));
    // Ready reports the negotiated suite.
    let mut l = link((config(16)?, config(16)?))?;
    l.settle()?;
    let suite = ContentSuites::local()
        .select(ContentSuites::local())
        .ok_or("suite")?;
    assert!(has(&l.b_events, |e| *e == TransferEvent::Ready { suite }));
    assert_eq!(
        l.b.negotiated().map(crate::Negotiated::request_limit),
        Some(16)
    );
    Ok(())
}

#[test]
fn no_key_or_content_before_accept() -> TestResult {
    let fixture = fixture()?;
    let suite = ContentSuites::local()
        .select(ContentSuites::local())
        .ok_or("suite")?;
    // Before the offer is even known, and while it awaits the decision.
    for during_offer in [false, true] {
        let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
        let target = if during_offer {
            transfer_id
        } else {
            [0x99; 16]
        };
        let chunk = Chunk::new(target, [3; 32], 1, 2, 0, &[0; 40])?.encode();
        let result = link.b.handle_frame(FrameType::CHUNK, &chunk, link.now);
        assert_eq!(session_failure(result), Some(FailureCode::ConsentRequired));
        assert!(sent_session_error(
            &mut link,
            false,
            ErrorCode::CONSENT_REQUIRED
        ));
        assert_eq!(link.b.sink().stored_segments(&transfer_id), 0);
        assert!(!has(&link.b_events, |e| matches!(
            e,
            TransferEvent::Progress(_)
        )));

        let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
        let target = if during_offer {
            transfer_id
        } else {
            [0x99; 16]
        };
        let key = FileKeyBody::new(target, [3; 32], 2, suite, FileMaster::generate()?)?.encode();
        let result = link
            .b
            .handle_frame(FrameType::FILE_KEY, key.as_slice(), link.now);
        assert_eq!(session_failure(result), Some(FailureCode::ConsentRequired));
    }
    Ok(())
}

/// Delivers frames until the frame at the head of the wire toward Bob
/// (`toward_bob`) or Alice is of `frame_type`.
pub(super) fn run_until(
    link: &mut Link<'_>,
    toward_bob: bool,
    frame_type: FrameType,
) -> TestResult {
    for _ in 0..100_000 {
        link.collect();
        let (wire, other) = if toward_bob {
            (&link.to_b, &link.to_a)
        } else {
            (&link.to_a, &link.to_b)
        };
        if wire.front().map(raw).is_some_and(|(t, _)| t == frame_type) {
            return Ok(());
        }
        let deliver_chosen = !wire.is_empty();
        if !deliver_chosen && other.is_empty() {
            return Err("nothing more to deliver".into());
        }
        let toward = if deliver_chosen {
            toward_bob
        } else {
            !toward_bob
        };
        if let Some(Err(error)) = link.deliver(toward) {
            return Err(format!("delivery failed: {error}").into());
        }
    }
    Err("frame not found".into())
}

/// A transfer Bob accepted with `selection`, run until its first chunk is
/// on the wire; returns the Accept hash.
pub(super) fn receiving(
    fixture: &Fixture,
    selection: Vec<u32>,
) -> AnyResult<(Link<'_>, TransferId, [u8; 32])> {
    let (mut link, transfer_id, _) = offered(fixture, &standard_specs(), 3600, (16, 16))?;
    link.b.accept(&transfer_id, selection, link.now)?;
    run_until(&mut link, true, FrameType::CHUNK)?;
    let chunk = link.to_b.front().map(raw).ok_or("chunk")?;
    let accept_hash = *Chunk::decode(&chunk.1)?.accept_hash();
    Ok((link, transfer_id, accept_hash))
}

#[test]
fn keys_and_content_only_within_the_selection() -> TestResult {
    let fixture = fixture()?;
    let suite = ContentSuites::local()
        .select(ContentSuites::local())
        .ok_or("suite")?;
    let probe = |frame_type: FrameType,
                 make: &dyn Fn(TransferId, [u8; 32]) -> AnyResult<Vec<u8>>|
     -> AnyResult<Option<FailureCode>> {
        let (mut link, transfer_id, accept_hash) = receiving(&fixture, vec![2, 6])?;
        let body = make(transfer_id, accept_hash)?;
        let result = link.b.handle_frame(frame_type, &body, link.now);
        assert_eq!(link.b.sink().published(&transfer_id, 5), None);
        Ok(session_failure(result))
    };
    // A FileKey for unselected file 5: CONSENT_REQUIRED.
    assert_eq!(
        probe(FrameType::FILE_KEY, &|id, hash| Ok(FileKeyBody::new(
            id,
            hash,
            5,
            suite,
            FileMaster::generate()?
        )?
        .encode()
        .to_vec()))?,
        Some(FailureCode::ConsentRequired)
    );
    // Content for unselected file 5, and for directory 1.
    for file_id in [5, 1] {
        assert_eq!(
            probe(FrameType::CHUNK, &|id, hash| Ok(Chunk::new(
                id, hash, 1, file_id, 0, &[0; 40]
            )?
            .encode()))?,
            Some(FailureCode::ConsentRequired)
        );
    }
    // A selected file under another Accept hash: STATE.
    assert_eq!(
        probe(FrameType::FILE_KEY, &|id, _| Ok(FileKeyBody::new(
            id,
            [0x55; 32],
            2,
            suite,
            FileMaster::generate()?
        )?
        .encode()
        .to_vec()))?,
        Some(FailureCode::State)
    );
    assert_eq!(
        probe(FrameType::CHUNK, &|id, _| Ok(Chunk::new(
            id, [0x55; 32], 1, 2, 0, &[0; 40]
        )?
        .encode()))?,
        Some(FailureCode::State)
    );
    // A chunk that answers no outstanding request: STATE.
    assert_eq!(
        probe(FrameType::CHUNK, &|id, hash| Ok(Chunk::new(
            id, hash, 999, 2, 1, &[0; 40]
        )?
        .encode()))?,
        Some(FailureCode::State)
    );
    // The identical FileKey again is idempotent; a different master is
    // fatal.
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    link.b.accept(&transfer_id, vec![2, 6], link.now)?;
    run_until(&mut link, true, FrameType::FILE_KEY)?;
    let key = link.to_b.front().map(raw).ok_or("key")?;
    link.deliver(true).ok_or("deliver")??;
    assert_eq!(
        link.b.handle_frame(FrameType::FILE_KEY, &key.1, link.now),
        Ok(())
    );
    let mut other = key.1;
    other[85] ^= 1;
    assert_eq!(
        session_failure(link.b.handle_frame(FrameType::FILE_KEY, &other, link.now)),
        Some(FailureCode::State)
    );
    Ok(())
}

#[test]
fn tampered_content_fails_the_transfer_with_integrity() -> TestResult {
    let fixture = fixture()?;
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    link.b.accept(&transfer_id, vec![2], link.now)?;
    run_until(&mut link, true, FrameType::CHUNK)?;
    let OutgoingFrame::Frame { body, .. } = link.to_b.front_mut().ok_or("chunk")? else {
        return Err("not a frame".into());
    };
    let last = body.len() - 1;
    body[last] ^= 1;
    link.deliver(true).ok_or("deliver")??;
    assert!(sent_transfer_error(&mut link, false, ErrorCode::INTEGRITY));
    assert!(has(&link.b_events, |e| matches!(e,
        TransferEvent::Failed { failure, .. } if failure.code == FailureCode::Integrity && failure.by == Party::Local)));
    // The remaining in-flight chunks are discarded; the sender stops.
    link.settle()?;
    assert!(link.b.sink().published(&transfer_id, 2).is_none());
    assert!(has(&link.a_events, |e| matches!(e,
        TransferEvent::Failed { failure, .. } if failure.code == FailureCode::Integrity && failure.by == Party::Peer)));
    Ok(())
}

#[test]
#[expect(clippy::too_many_lines, reason = "one table of assembly violations")]
fn manifest_assembly_rules() -> TestResult {
    let fixture = fixture()?;
    let mut source = MemorySource::new();
    let offer = build_offer(
        &fixture.alice.key(),
        &fixture.bob.key(),
        &standard_specs(),
        &mut source,
        3600,
    )?;
    let manifest = offer.manifest().clone();
    let bytes = manifest.bytes();
    let id = *manifest.transfer_id();
    let start = |hash: [u8; 32], len: usize| -> AnyResult<Vec<u8>> {
        Ok(ManifestStart::new(id, hash, u32::try_from(len)?)?
            .encode()
            .to_vec())
    };
    let ready = || -> AnyResult<Link<'_>> {
        let mut link = Link::new(
            &fixture,
            Which::First,
            (MemorySource::new(), MemorySource::new()),
            (MemorySink::new(), MemorySink::new()),
            (config(16)?, config(16)?),
        )?;
        link.settle()?;
        Ok(link)
    };
    // A wrong hash: MANIFEST, before any prompt.
    let mut link = ready()?;
    link.b.handle_frame(
        FrameType::MANIFEST_START,
        &start([0x42; 32], bytes.len())?,
        link.now,
    )?;
    link.b.handle_frame(
        FrameType::MANIFEST_PART,
        &ManifestPart::new(id, 0, bytes)?.encode(),
        link.now,
    )?;
    assert!(sent_transfer_error(&mut link, false, ErrorCode::MANIFEST));
    assert!(!has(&link.b_events, |e| matches!(
        e,
        TransferEvent::OfferReceived(_)
    )));
    // Parts out of order or past the declared length: STATE.
    let mut link = ready()?;
    link.b.handle_frame(
        FrameType::MANIFEST_START,
        &start(*manifest.hash(), bytes.len())?,
        link.now,
    )?;
    let gap = ManifestPart::new(id, 1, &bytes[1..])?.encode();
    assert_eq!(
        session_failure(
            link.b
                .handle_frame(FrameType::MANIFEST_PART, &gap, link.now)
        ),
        Some(FailureCode::State)
    );
    let mut link = ready()?;
    link.b.handle_frame(
        FrameType::MANIFEST_START,
        &start(*manifest.hash(), bytes.len() - 1)?,
        link.now,
    )?;
    let long = ManifestPart::new(id, 0, bytes)?.encode();
    assert_eq!(
        session_failure(
            link.b
                .handle_frame(FrameType::MANIFEST_PART, &long, link.now)
        ),
        Some(FailureCode::State)
    );
    // Split delivery works, and a duplicate part is STATE.
    let mut link = ready()?;
    link.b.handle_frame(
        FrameType::MANIFEST_START,
        &start(*manifest.hash(), bytes.len())?,
        link.now,
    )?;
    let first = ManifestPart::new(id, 0, &bytes[..50])?.encode();
    link.b
        .handle_frame(FrameType::MANIFEST_PART, &first, link.now)?;
    assert_eq!(
        session_failure(
            link.b
                .handle_frame(FrameType::MANIFEST_PART, &first, link.now)
        ),
        Some(FailureCode::State)
    );
    // Incomplete after 30 seconds: TIMEOUT, then its late parts are
    // discarded within the declared length.
    let mut link = ready()?;
    link.b.handle_frame(
        FrameType::MANIFEST_START,
        &start(*manifest.hash(), bytes.len())?,
        link.now,
    )?;
    link.b
        .handle_frame(FrameType::MANIFEST_PART, &first, link.now)?;
    let (_, b) = link.advance(Duration::from_secs(30));
    b?;
    assert!(sent_transfer_error(&mut link, false, ErrorCode::TIMEOUT));
    let rest = ManifestPart::new(id, 50, &bytes[50..])?.encode();
    assert_eq!(
        link.b
            .handle_frame(FrameType::MANIFEST_PART, &rest, link.now),
        Ok(())
    );
    assert_eq!(
        session_failure(
            link.b
                .handle_frame(FrameType::MANIFEST_PART, &rest, link.now)
        ),
        Some(FailureCode::State)
    );
    // A second incomplete manifest, a third transfer, an oversized one:
    // LIMIT for the new transfer only.
    let mut link = ready()?;
    link.b.handle_frame(
        FrameType::MANIFEST_START,
        &start(*manifest.hash(), bytes.len())?,
        link.now,
    )?;
    let other = ManifestStart::new([0x31; 16], [1; 32], 500)?.encode();
    link.b
        .handle_frame(FrameType::MANIFEST_START, &other, link.now)?;
    assert!(sent_transfer_error(&mut link, false, ErrorCode::LIMIT));
    let huge = ManifestStart::new([0x32; 16], [1; 32], 4_194_304)?.encode();
    let mut small = ready_with(&fixture, 16, 200)?;
    small
        .b
        .handle_frame(FrameType::MANIFEST_START, &huge, small.now)?;
    assert!(sent_transfer_error(&mut small, false, ErrorCode::LIMIT));
    // A known transfer ID again: STATE.
    let mut link = ready()?;
    link.b.handle_frame(
        FrameType::MANIFEST_START,
        &start(*manifest.hash(), bytes.len())?,
        link.now,
    )?;
    assert_eq!(
        session_failure(link.b.handle_frame(
            FrameType::MANIFEST_START,
            &start(*manifest.hash(), bytes.len())?,
            link.now
        )),
        Some(FailureCode::State)
    );
    Ok(())
}

fn ready_with(fixture: &Fixture, outstanding: u16, max_manifest: u32) -> AnyResult<Link<'_>> {
    let mut b_config = config(outstanding)?;
    let record = *b_config.capabilities.record();
    b_config.capabilities = crate::LocalCapabilities::new(Capabilities::new(
        record.content_suites(),
        max_manifest,
        record.max_entries(),
        record.max_file_bytes(),
        record.max_transfer_bytes(),
        outstanding,
    )?)?;
    let mut link = Link::new(
        fixture,
        Which::First,
        (MemorySource::new(), MemorySource::new()),
        (MemorySink::new(), MemorySink::new()),
        (config(16)?, b_config),
    )?;
    link.settle()?;
    Ok(link)
}

#[test]
fn incoming_transfer_quota() -> TestResult {
    let fixture = fixture()?;
    let mut source = MemorySource::new();
    let mut offers = Vec::new();
    for _ in 0..3 {
        offers.push(build_offer(
            &fixture.alice.key(),
            &fixture.bob.key(),
            &standard_specs(),
            &mut source,
            3600,
        )?);
    }
    let mut link = Link::new(
        &fixture,
        Which::First,
        (source, MemorySource::new()),
        (MemorySink::new(), MemorySink::new()),
        (config(16)?, config(16)?),
    )?;
    link.settle()?;
    let mut ids = Vec::new();
    for offer in offers {
        ids.push(*offer.transfer_id());
        match link.a.offer(offer, link.now) {
            Ok(()) => link.settle()?,
            // The sender itself keeps to the receiver's 2-transfer budget.
            Err(EngineError::Offer(crate::OfferError::Busy)) => {}
            Err(error) => return Err(error.into()),
        }
    }
    let offered = link
        .b_events
        .iter()
        .filter(|e| matches!(e, TransferEvent::OfferReceived(_)))
        .count();
    assert_eq!(offered, 2);
    Ok(())
}

#[test]
fn offers_refused_before_the_prompt() -> TestResult {
    let fixture = fixture()?;
    for (refusal, reason) in [
        (SinkRefusal::Quota, RejectReason::Quota),
        (
            SinkRefusal::UnsupportedDestination,
            RejectReason::UnsupportedDestination,
        ),
    ] {
        let mut source = MemorySource::new();
        let offer = build_offer(
            &fixture.alice.key(),
            &fixture.bob.key(),
            &standard_specs(),
            &mut source,
            3600,
        )?;
        let mut sink = MemorySink::new();
        sink.set_refusal(Some(refusal));
        let mut link = Link::new(
            &fixture,
            Which::First,
            (source, MemorySource::new()),
            (MemorySink::new(), sink),
            (config(16)?, config(16)?),
        )?;
        link.settle()?;
        link.a.offer(offer, link.now)?;
        link.settle()?;
        assert!(!has(&link.b_events, |e| matches!(
            e,
            TransferEvent::OfferReceived(_)
        )));
        assert!(has(
            &link.a_events,
            |e| matches!(e, TransferEvent::Rejected { reason: r, .. } if *r == reason)
        ));
        assert!(link.a.take_resumable().is_empty());
    }
    Ok(())
}

#[test]
fn consent_prompt_expires_after_300_seconds() -> TestResult {
    let fixture = fixture()?;
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    let (_, b) = link.advance(Duration::from_secs(299));
    b?;
    assert!(!has(&link.b_events, |e| matches!(
        e,
        TransferEvent::Rejected { .. }
    )));
    let (_, b) = link.advance(Duration::from_secs(1));
    b?;
    link.settle()?;
    assert!(has(&link.a_events, |e| matches!(
        e,
        TransferEvent::Rejected {
            reason: RejectReason::Expired,
            ..
        }
    )));
    assert_eq!(
        link.b.accept(&transfer_id, vec![2], link.now),
        Err(EngineError::WrongState)
    );
    // A user reject.
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    link.b.reject(&transfer_id, RejectReason::Declined)?;
    link.settle()?;
    assert!(has(&link.a_events, |e| matches!(
        e,
        TransferEvent::Rejected {
            reason: RejectReason::Declined,
            ..
        }
    )));
    assert_eq!(
        link.b.reject(&transfer_id, RejectReason::Declined),
        Err(EngineError::WrongState)
    );
    assert_eq!(
        link.b.reject(&[9; 16], RejectReason::Declined),
        Err(EngineError::UnknownTransfer)
    );
    Ok(())
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one table of forged and replayed Accepts"
)]
fn sender_accept_rules() -> TestResult {
    let fixture = fixture()?;
    let wall = time(WALL)?;
    let later = time(WALL + 600)?;
    // Accept for an unknown transfer: STATE.
    let (mut link, transfer_id, manifest) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    let accept = sign_accept(
        &fixture.bob.keys,
        &fixture.bob.signing_key,
        &fixture.first.1,
        &manifest,
        vec![2],
        later,
        wall,
    )?;
    let (mut empty, _, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    assert_eq!(
        session_failure(
            empty
                .a
                .handle_frame(FrameType::ACCEPT, accept.encoded(), empty.now)
        ),
        Some(FailureCode::State)
    );
    // The honest Accept, then the identical record again: idempotent.
    link.a
        .handle_frame(FrameType::ACCEPT, accept.encoded(), link.now)?;
    link.a
        .handle_frame(FrameType::ACCEPT, accept.encoded(), link.now)?;
    // A second, different valid Accept for the live transfer: STATE.
    let second = sign_accept(
        &fixture.bob.keys,
        &fixture.bob.signing_key,
        &fixture.first.1,
        &manifest,
        vec![2],
        later,
        wall,
    )?;
    assert_eq!(
        session_failure(
            link.a
                .handle_frame(FrameType::ACCEPT, second.encoded(), link.now)
        ),
        Some(FailureCode::State)
    );
    let _ = transfer_id;
    // An Accept signed for another session: STATE (a reconnect needs a
    // fresh Accept).
    let (mut link, _, manifest) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    let other = sign_accept(
        &fixture.bob.keys,
        &fixture.bob.signing_key,
        &fixture.second.1,
        &manifest,
        vec![2],
        later,
        wall,
    )?;
    assert_eq!(
        session_failure(
            link.a
                .handle_frame(FrameType::ACCEPT, other.encoded(), link.now)
        ),
        Some(FailureCode::State)
    );
    // A tampered signature: AUTHENTICATION.
    let (mut link, _, manifest) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    let mut forged = sign_accept(
        &fixture.bob.keys,
        &fixture.bob.signing_key,
        &fixture.first.1,
        &manifest,
        vec![2],
        later,
        wall,
    )?
    .encoded()
    .to_vec();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    assert_eq!(
        session_failure(link.a.handle_frame(FrameType::ACCEPT, &forged, link.now)),
        Some(FailureCode::Authentication)
    );
    // Malformed.
    let (mut link, _, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    assert_eq!(
        session_failure(
            link.a
                .handle_frame(FrameType::ACCEPT, &forged[..100], link.now)
        ),
        Some(FailureCode::Malformed)
    );
    // Expired by the time it arrives: no content, EXPIRED to the peer, and
    // the offer stays resumable.
    let (mut link, transfer_id, manifest) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    let short = sign_accept(
        &fixture.bob.keys,
        &fixture.bob.signing_key,
        &fixture.first.1,
        &manifest,
        vec![2],
        time(WALL + 30)?,
        wall,
    )?;
    link.now += Duration::from_secs(31);
    link.a
        .handle_frame(FrameType::ACCEPT, short.encoded(), link.now)?;
    assert!(sent_transfer_error(&mut link, true, ErrorCode::EXPIRED));
    assert!(
        !link
            .to_b
            .iter()
            .any(|f| matches!(raw(f).0, FrameType::FILE_KEY | FrameType::CHUNK))
    );
    assert!(has(
        &link.a_events,
        |e| matches!(e, TransferEvent::Expired { transfer_id: t, .. } if *t == transfer_id)
    ));
    assert_eq!(link.a.take_resumable().len(), 1);
    Ok(())
}

#[test]
fn sender_request_rules() -> TestResult {
    let fixture = fixture()?;
    // A request before any Accept: STATE.
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    let early = ChunkRequest::new(transfer_id, [1; 32], 1, 2, 0)?.encode();
    assert_eq!(
        session_failure(
            link.a
                .handle_frame(FrameType::CHUNK_REQUEST, &early, link.now)
        ),
        Some(FailureCode::State)
    );
    // After the Accept: a first request with ID 5, then the probe.
    let probe = |request_id, file_id, index| -> AnyResult<Option<FailureCode>> {
        let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
        link.b.accept(&transfer_id, vec![2, 6], link.now)?;
        run_until(&mut link, true, FrameType::FILE_KEY)?;
        let key = link.to_b.front().map(raw).ok_or("key")?;
        let accept_hash: [u8; 32] = key.1[16..48].try_into()?;
        let first = ChunkRequest::new(transfer_id, accept_hash, 5, 2, 0)?.encode();
        link.a
            .handle_frame(FrameType::CHUNK_REQUEST, &first, link.now)?;
        let body =
            ChunkRequest::new(transfer_id, accept_hash, request_id, file_id, index)?.encode();
        Ok(session_failure(link.a.handle_frame(
            FrameType::CHUNK_REQUEST,
            &body,
            link.now,
        )))
    };
    // Request IDs strictly increase.
    assert_eq!(probe(5, 2, 1)?, Some(FailureCode::State));
    assert_eq!(probe(4, 2, 1)?, Some(FailureCode::State));
    assert_eq!(probe(6, 2, 1)?, None);
    // An unselected file, a directory, an index past the end.
    assert_eq!(probe(6, 5, 0)?, Some(FailureCode::ConsentRequired));
    assert_eq!(probe(6, 1, 0)?, Some(FailureCode::ConsentRequired));
    assert_eq!(probe(6, 2, 3)?, Some(FailureCode::State));
    Ok(())
}

/// The receiver never has more than `min(own, peer)` requests or more
/// than two files outstanding (§7.4, §13).
#[test]
fn request_budget_and_active_files() -> TestResult {
    let fixture = fixture()?;
    let specs = vec![
        file("a", 0, 16_384 * 9, 1),
        file("b", 0, 16_384 * 9, 2),
        file("c", 0, 16_384 * 9, 3),
        file("d", 0, 16_384 * 9, 4),
    ];
    for (own, peer) in [(3, 16), (16, 2), (16, 16)] {
        let (mut link, transfer_id, _) = offered(&fixture, &specs, 3600, (peer, own))?;
        link.b.accept(&transfer_id, vec![1, 2, 3, 4], link.now)?;
        let limit = usize::from(own.min(peer));
        let mut max_seen = 0;
        for _ in 0..10_000 {
            link.collect();
            // Requests Bob sent that Alice has not answered yet, plus the
            // answers still on the way to Bob.
            let mut files = std::collections::BTreeSet::new();
            let mut in_flight = 0;
            for frame in link.to_a.iter().chain(link.to_b.iter()) {
                let (frame_type, body) = raw(frame);
                if frame_type == FrameType::CHUNK_REQUEST {
                    in_flight += 1;
                    files.insert(ChunkRequest::decode(&body)?.file_id());
                } else if frame_type == FrameType::CHUNK {
                    in_flight += 1;
                    files.insert(Chunk::decode(&body)?.file_id());
                }
            }
            assert!(in_flight <= limit, "{in_flight} > {limit}");
            assert!(files.len() <= 2, "{files:?}");
            max_seen = max_seen.max(in_flight);
            if link.to_a.is_empty() && link.to_b.is_empty() {
                break;
            }
            // Deliver one frame each way per step.
            if !link.to_a.is_empty() {
                link.deliver(false).ok_or("a")??;
            }
            if !link.to_b.is_empty() {
                link.deliver(true).ok_or("b")??;
            }
        }
        assert_eq!(max_seen, limit);
        assert_eq!(link.b.sink().published_count(), 4);
    }
    Ok(())
}

#[test]
fn cancel_by_receiver_mid_transfer() -> TestResult {
    let fixture = fixture()?;
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    link.b.accept(&transfer_id, vec![2, 5], link.now)?;
    run_until(&mut link, true, FrameType::CHUNK)?;
    // Some chunks are in flight when Bob cancels.
    let in_flight = link
        .to_b
        .iter()
        .filter(|f| raw(f).0 == FrameType::CHUNK)
        .count();
    assert!(in_flight > 0);
    link.b.cancel(&transfer_id, CancelReason::User, link.now)?;
    link.settle()?;
    assert!(has(&link.b_events, |e| matches!(
        e,
        TransferEvent::Cancelled {
            by: Party::Local,
            ..
        }
    )));
    assert!(has(&link.a_events, |e| matches!(
        e,
        TransferEvent::Cancelled {
            by: Party::Peer,
            reason: CancelReason::User,
            ..
        }
    )));
    let wall = time(WALL)?;
    assert!(crate::ReceiveSink::is_tombstoned(
        link.b.sink(),
        &transfer_id,
        wall
    ));
    assert_eq!(link.b.sink().stored_segments(&transfer_id), 0);
    assert_eq!(link.b.sink().published_count(), 0);
    // Cancel again: the transfer is gone for good.
    assert_eq!(
        link.b.cancel(&transfer_id, CancelReason::User, link.now),
        Err(EngineError::WrongState)
    );
    assert!(link.a.take_resumable().is_empty());
    assert_eq!(
        link.b.cancel(&[3; 16], CancelReason::User, link.now),
        Err(EngineError::UnknownTransfer)
    );
    Ok(())
}

#[test]
fn cancel_by_sender_and_simultaneous_cancel() -> TestResult {
    let fixture = fixture()?;
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    link.b.accept(&transfer_id, vec![2, 5], link.now)?;
    run_until(&mut link, true, FrameType::CHUNK)?;
    link.a.cancel(&transfer_id, CancelReason::User, link.now)?;
    link.settle()?;
    assert!(has(&link.b_events, |e| matches!(
        e,
        TransferEvent::Cancelled {
            by: Party::Peer,
            ..
        }
    )));
    assert!(link.a.take_resumable().is_empty());
    // Both cancel before seeing the other's: each acknowledges the other.
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    link.b.accept(&transfer_id, vec![2, 5], link.now)?;
    run_until(&mut link, true, FrameType::CHUNK)?;
    link.a.cancel(&transfer_id, CancelReason::User, link.now)?;
    link.b
        .cancel(&transfer_id, CancelReason::Policy, link.now)?;
    link.settle()?;
    let (a, b) = link.advance(Duration::from_secs(6));
    a?;
    b?;
    // A cancel nobody acknowledges closes the session after 5 seconds.
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    link.b.cancel(&transfer_id, CancelReason::User, link.now)?;
    link.collect();
    link.to_a.clear();
    let (_, b) = link.advance(Duration::from_secs(5));
    assert_eq!(session_failure(b), Some(FailureCode::Timeout));
    // An unsolicited CancelAck, and a Cancel with the wrong hash: STATE.
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    let ack = todoke_proto::transfer::Cancel::new(
        transfer_id,
        [0; 32],
        random_id()?,
        CancelReason::User,
    )?
    .encode();
    assert_eq!(
        session_failure(link.a.handle_frame(FrameType::CANCEL_ACK, &ack, link.now)),
        Some(FailureCode::State)
    );
    let (mut link, _, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    let id = link.transfer_id_of_offer().ok_or("id")?;
    let wrong = todoke_proto::transfer::Cancel::new(id, [0; 32], random_id()?, CancelReason::User)?
        .encode();
    assert_eq!(
        session_failure(link.a.handle_frame(FrameType::CANCEL, &wrong, link.now)),
        Some(FailureCode::State)
    );
    Ok(())
}
