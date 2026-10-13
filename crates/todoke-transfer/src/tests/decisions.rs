//! One test per security- or protocol-relevant decision that no other test
//! pinned down: each fails if its comparison is flipped, a boundary moves
//! by one, or a field check is dropped. Manifest admission, consent at the
//! receiver (keys, chunks, resume queries, expiry), the sender's checks of
//! requests, resume pages, `Complete`, receipts, `Reject`, and Accept
//! nonces, offer limits, cancel handling, the §13 timers at their exact
//! boundaries, the application buffer bound, revalidation pacing, and the
//! §12 code mapping.

use core::time::Duration;

use todoke_crypto::consent::{CanonicalManifest, manifest_hash, sign_accept};
use todoke_crypto::content::{ContentSuite, ContentSuites, FileKeyBody, FileMaster};
use todoke_crypto::identity::{KeyStore, SigningDomain};
use todoke_proto::session::{ErrorCode, FrameType};
use todoke_proto::transfer::{
    Accept, AcceptBody, Cancel, CancelReason, Capabilities, Chunk, ChunkRequest, Complete,
    DeliveryReceipt, ManifestLimits, ManifestPart, ManifestStart, ReceiptBody, Reject,
    RejectReason, ResumeQuery, ResumeStatus, TransferId,
};

use super::basic::{
    has, offered, receiving, run_until, sent_session_error, sent_transfer_error, session_failure,
    standard_specs,
};
use super::lifecycle::{inject_manifest, interrupted, interrupted_with};
use super::support::*;
use crate::{
    Clock, Direction, EngineConfig, EngineError, FailureCode, LocalCapabilities, ManifestBuilder,
    MemoryFile, MemorySink, MemorySource, OfferError, OutgoingFrame, OutgoingOffer, Party,
    TransferEngine, TransferEvent,
};

fn local_suite() -> AnyResult<ContentSuite> {
    Ok(ContentSuites::local()
        .select(ContentSuites::local())
        .ok_or("suite")?)
}

/// A link with Capabilities exchanged and nothing offered.
fn ready(fixture: &Fixture) -> AnyResult<Link<'_>> {
    let mut link = Link::new(
        fixture,
        Which::First,
        (MemorySource::new(), MemorySource::new()),
        (MemorySink::new(), MemorySink::new()),
        (config(16)?, config(16)?),
    )?;
    link.settle()?;
    Ok(link)
}

/// The bodies of every frame of `frame_type` in `frames`.
fn bodies(frames: &[OutgoingFrame], frame_type: FrameType) -> Vec<Vec<u8>> {
    frames
        .iter()
        .map(raw)
        .filter(|(kind, _)| *kind == frame_type)
        .map(|(_, body)| body)
        .collect()
}

/// The bodies of every frame of `frame_type` waiting toward Bob
/// (`to_bob`) or Alice.
fn waiting(link: &mut Link<'_>, to_bob: bool, frame_type: FrameType) -> Vec<Vec<u8>> {
    link.collect();
    let wire: Vec<OutgoingFrame> = if to_bob {
        link.to_b.iter().cloned().collect()
    } else {
        link.to_a.iter().cloned().collect()
    };
    bodies(&wire, frame_type)
}

/// A one-file manifest from `sender` to `recipient`, valid from
/// `created_at` until `expires_at`.
fn one_file_manifest(
    transfer_id: Option<TransferId>,
    sender: &todoke_crypto::identity::Ed25519PublicKey,
    recipient: &todoke_crypto::identity::Ed25519PublicKey,
    created_at: u64,
    expires_at: u64,
) -> AnyResult<CanonicalManifest> {
    let memory = MemoryFile::new(content(100, 1));
    let mut builder = match transfer_id {
        Some(id) => ManifestBuilder::with_transfer_id(
            id,
            sender,
            recipient,
            time(created_at)?,
            time(expires_at)?,
        ),
        None => ManifestBuilder::new(sender, recipient, time(created_at)?, time(expires_at)?)?,
    };
    builder.add_file(
        0,
        "a",
        "application/octet-stream",
        memory.size(),
        *memory.root(),
    );
    Ok(builder.build(local_suite()?, &ManifestLimits::SPEC)?)
}

fn offer_received(link: &Link<'_>, transfer_id: &TransferId) -> bool {
    has(
        &link.b_events,
        |e| matches!(e, TransferEvent::OfferReceived(view) if view.transfer_id == *transfer_id),
    )
}

fn failed_with(events: &[TransferEvent], transfer_id: &TransferId, code: FailureCode) -> bool {
    has(events, |e| {
        matches!(e, TransferEvent::Failed { transfer_id: t, failure, .. }
            if t == transfer_id && failure.code == code)
    })
}

// ---------------------------------------------------------------------
// Manifest admission (§7, §7.1, §7.5, §13)
// ---------------------------------------------------------------------

/// A `ManifestStart` for an ID this side is itself offering reuses a
/// transfer ID: `STATE` (§7: one transfer per ID, in one direction).
#[test]
fn manifest_start_for_an_outgoing_transfer_id_is_state() -> TestResult {
    let fixture = fixture()?;
    let (mut link, transfer_id, manifest) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    let start = ManifestStart::new(
        transfer_id,
        *manifest.hash(),
        u32::try_from(manifest.bytes().len())?,
    )?
    .encode();
    let result = link
        .a
        .handle_frame(FrameType::MANIFEST_START, &start, link.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    assert!(sent_session_error(&mut link, true, ErrorCode::STATE));
    Ok(())
}

/// Two offers from Alice that Bob has both received and not decided.
fn two_offers(fixture: &Fixture) -> AnyResult<(Link<'_>, Vec<(TransferId, CanonicalManifest)>)> {
    let mut source = MemorySource::new();
    let mut offers = Vec::new();
    for _ in 0..2 {
        offers.push(build_offer(
            &fixture.alice.key(),
            &fixture.bob.key(),
            &standard_specs(),
            &mut source,
            3600,
        )?);
    }
    let mut link = Link::new(
        fixture,
        Which::First,
        (source, MemorySource::new()),
        (MemorySink::new(), MemorySink::new()),
        (config(16)?, config(16)?),
    )?;
    link.settle()?;
    let mut ids = Vec::new();
    for offer in offers {
        ids.push((*offer.transfer_id(), offer.manifest().clone()));
        link.a.offer(offer, link.now)?;
        link.settle()?;
    }
    for (id, _) in &ids {
        if !offer_received(&link, id) {
            return Err("offer not received".into());
        }
    }
    Ok((link, ids))
}

/// §7, §13: at most two concurrent incoming transfers. With two offers
/// awaiting a decision (neither still assembling), a third `ManifestStart`
/// is refused with a transfer-scoped `LIMIT`; once one offer ends, a new
/// one is admitted.
#[test]
fn a_third_concurrent_incoming_transfer_is_refused() -> TestResult {
    let fixture = fixture()?;
    let (mut link, offers) = two_offers(&fixture)?;
    let third = [0x33; 16];
    let start = ManifestStart::new(third, [1; 32], 500)?.encode();
    link.b
        .handle_frame(FrameType::MANIFEST_START, &start, link.now)?;
    assert!(sent_transfer_error(&mut link, false, ErrorCode::LIMIT));
    assert!(failed_with(&link.b_events, &third, FailureCode::Limit));
    // One offer ends: a new transfer fits again.
    let (first, _) = &offers[0];
    link.b.reject(first, RejectReason::Declined)?;
    link.collect();
    link.to_a.clear();
    let fourth = [0x34; 16];
    let start = ManifestStart::new(fourth, [1; 32], 500)?.encode();
    link.b
        .handle_frame(FrameType::MANIFEST_START, &start, link.now)?;
    link.collect();
    assert!(!sent_transfer_error(&mut link, false, ErrorCode::LIMIT));
    assert!(!has(&link.b_events, |e| matches!(
        e,
        TransferEvent::Failed { transfer_id, .. } if *transfer_id == fourth
    )));
    Ok(())
}

/// Manifest bytes that match the announced hash but break the §7.1 schema
/// are refused with a transfer-scoped `MANIFEST`, before any prompt.
#[test]
fn a_manifest_matching_its_hash_must_still_be_valid() -> TestResult {
    let fixture = fixture()?;
    let manifest = one_file_manifest(
        None,
        &fixture.alice.key(),
        &fixture.bob.key(),
        WALL,
        WALL + 3600,
    )?;
    let mut bytes = manifest.bytes().to_vec();
    // Nonzero flags (§7.1: flags = 0).
    bytes[107] = 1;
    let id = *manifest.transfer_id();
    let mut link = ready(&fixture)?;
    let start = ManifestStart::new(id, manifest_hash(&bytes), u32::try_from(bytes.len())?)?;
    link.b
        .handle_frame(FrameType::MANIFEST_START, &start.encode(), link.now)?;
    link.b.handle_frame(
        FrameType::MANIFEST_PART,
        &ManifestPart::new(id, 0, &bytes)?.encode(),
        link.now,
    )?;
    assert!(sent_transfer_error(&mut link, false, ErrorCode::MANIFEST));
    assert!(!offer_received(&link, &id));
    Ok(())
}

/// §7, §7.1: the manifest must name the transfer it arrived under, the
/// authenticated peer as its sender, and this device as its recipient;
/// otherwise the transfer fails with `MANIFEST` before any prompt.
#[test]
fn a_manifest_must_name_this_transfer_and_both_devices() -> TestResult {
    let fixture = fixture()?;
    let (alice, bob) = (fixture.alice.key(), fixture.bob.key());
    // Another transfer ID inside than outside.
    let manifest = one_file_manifest(None, &alice, &bob, WALL, WALL + 3600)?;
    let outer = [0x44; 16];
    let bytes = manifest.bytes();
    let mut link = ready(&fixture)?;
    let start = ManifestStart::new(outer, *manifest.hash(), u32::try_from(bytes.len())?)?;
    link.b
        .handle_frame(FrameType::MANIFEST_START, &start.encode(), link.now)?;
    link.b.handle_frame(
        FrameType::MANIFEST_PART,
        &ManifestPart::new(outer, 0, bytes)?.encode(),
        link.now,
    )?;
    assert!(sent_transfer_error(&mut link, false, ErrorCode::MANIFEST));
    assert!(!offer_received(&link, &outer));
    assert!(!offer_received(&link, manifest.transfer_id()));
    // From Bob (not the peer) to Bob, and from Alice to Alice (not this
    // device).
    for (sender, recipient) in [(&bob, &bob), (&alice, &alice)] {
        let manifest = one_file_manifest(None, sender, recipient, WALL, WALL + 3600)?;
        let mut link = ready(&fixture)?;
        inject_manifest(&mut link, &manifest)?;
        assert!(sent_transfer_error(&mut link, false, ErrorCode::MANIFEST));
        assert!(!offer_received(&link, manifest.transfer_id()));
    }
    // The same construction between the right devices is offered.
    let manifest = one_file_manifest(None, &alice, &bob, WALL, WALL + 3600)?;
    let mut link = ready(&fixture)?;
    inject_manifest(&mut link, &manifest)?;
    assert!(offer_received(&link, manifest.transfer_id()));
    Ok(())
}

/// A manifest that has expired by the time it is complete is rejected as
/// expired without a prompt (§7.3 reason 4); one that expires a second
/// later is offered.
#[test]
fn an_expired_manifest_is_rejected_without_a_prompt() -> TestResult {
    let fixture = fixture()?;
    for (expires_at, prompted) in [(WALL, false), (WALL + 1, true)] {
        let manifest = one_file_manifest(
            None,
            &fixture.alice.key(),
            &fixture.bob.key(),
            WALL - 120,
            expires_at,
        )?;
        let mut link = ready(&fixture)?;
        inject_manifest(&mut link, &manifest)?;
        let id = manifest.transfer_id();
        assert_eq!(offer_received(&link, id), prompted, "expires {expires_at}");
        let rejects = waiting(&mut link, false, FrameType::REJECT);
        if prompted {
            assert_eq!(rejects, Vec::<Vec<u8>>::new());
        } else {
            let reject = Reject::decode(rejects.first().ok_or("reject")?)?;
            assert_eq!(reject.reason(), RejectReason::Expired);
            assert_eq!(reject.transfer_id(), id);
        }
    }
    Ok(())
}

/// §7.5: a manifest mutation makes resume unavailable. A retained transfer
/// re-offered under the same ID with a different manifest fails with
/// `RESUME_UNAVAILABLE` and is not offered.
#[test]
fn a_mutated_manifest_under_a_retained_id_cannot_resume() -> TestResult {
    let fixture = fixture()?;
    let (_, transfer_id, sources, sinks, now) = interrupted(&fixture, vec![2, 4], 3)?;
    assert!(sinks.1.stored_segments(&transfer_id) > 0);
    let mut link = Link::new(
        &fixture,
        Which::Second,
        sources,
        sinks,
        (config(4)?, config(4)?),
    )?;
    link.now = now;
    link.settle()?;
    let mutated = one_file_manifest(
        Some(transfer_id),
        &fixture.alice.key(),
        &fixture.bob.key(),
        WALL,
        WALL + 3600,
    )?;
    inject_manifest(&mut link, &mutated)?;
    assert!(sent_transfer_error(
        &mut link,
        false,
        ErrorCode::RESUME_UNAVAILABLE
    ));
    assert!(!offer_received(&link, &transfer_id));
    Ok(())
}

/// The user's accept after the offer expired (before the timer ran) signs
/// nothing and sends nothing; a second earlier it is accepted.
#[test]
fn accepting_an_expired_offer_signs_nothing() -> TestResult {
    let fixture = fixture()?;
    for (elapsed, ok) in [(99, true), (100, false)] {
        let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 100, (16, 16))?;
        link.now += Duration::from_secs(elapsed);
        let result = link.b.accept(&transfer_id, vec![2], link.now);
        let accepts = waiting(&mut link, false, FrameType::ACCEPT);
        if ok {
            assert_eq!(result, Ok(()));
            assert_eq!(accepts.len(), 1);
        } else {
            assert_eq!(result, Err(EngineError::Expired));
            assert_eq!(accepts, Vec::<Vec<u8>>::new());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Consent at the receiver (§7.2, §7.4, §7.5, §8)
// ---------------------------------------------------------------------

/// A `FileKey` for a selected file under the right Accept, but in another
/// content suite than the manifest binds for that file, is `STATE` (§6:
/// the suite is bound into the manifest and Accept; no suite change).
#[test]
fn a_file_key_in_another_suite_is_refused() -> TestResult {
    let fixture = fixture()?;
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    link.b.accept(&transfer_id, vec![2, 6], link.now)?;
    run_until(&mut link, true, FrameType::FILE_KEY)?;
    let key = FileKeyBody::decode(&raw(link.to_b.front().ok_or("key")?).1)?;
    let other = match key.suite() {
        ContentSuite::Aes256GcmStream => ContentSuite::XChaCha20Poly1305Stream,
        ContentSuite::XChaCha20Poly1305Stream => ContentSuite::Aes256GcmStream,
    };
    let forged = FileKeyBody::new(
        transfer_id,
        *key.accept_hash(),
        key.file_id(),
        other,
        FileMaster::generate()?,
    )?
    .encode();
    let result = link
        .b
        .handle_frame(FrameType::FILE_KEY, forged.as_slice(), link.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    assert_eq!(
        waiting(&mut link, false, FrameType::CHUNK_REQUEST),
        Vec::<Vec<u8>>::new()
    );
    assert_eq!(link.b.sink().stored_segments(&transfer_id), 0);
    Ok(())
}

/// §7.3: expiry pauses content at once. A chunk that arrives at the
/// Accept's expiry, before any timer ran, is discarded unprocessed and the
/// transfer expires; one second earlier it is stored.
#[test]
fn a_chunk_at_accept_expiry_is_discarded() -> TestResult {
    let fixture = fixture()?;
    for (elapsed, stored) in [(599, true), (600, false)] {
        // The Accept expires with the manifest, 600 seconds from now.
        let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 600, (16, 16))?;
        link.b.accept(&transfer_id, vec![2], link.now)?;
        run_until(&mut link, true, FrameType::CHUNK)?;
        link.now = START + Duration::from_secs(elapsed);
        link.deliver(true).ok_or("deliver")??;
        assert_eq!(
            link.b.sink().stored_segments(&transfer_id) > 0,
            stored,
            "after {elapsed} s"
        );
        let expired = has(&link.b_events, |e| {
            matches!(
                e,
                TransferEvent::Expired {
                    direction: Direction::Incoming,
                    ..
                }
            )
        });
        assert_eq!(expired, !stored);
        assert!(!failed_with(
            &link.b_events,
            &transfer_id,
            FailureCode::Integrity
        ));
    }
    Ok(())
}

/// §7.4: a chunk must answer its request exactly. The right request ID
/// with another (selected, keyed) file or another index is `STATE`, not
/// an integrity failure after trying to open it.
#[test]
fn a_chunk_must_match_its_request_file_and_index() -> TestResult {
    let fixture = fixture()?;
    for change_file in [true, false] {
        let (mut link, transfer_id, accept_hash) = receiving(&fixture, vec![2, 6])?;
        let chunk_body = raw(&link.to_b.pop_front().ok_or("chunk")?).1;
        let chunk = Chunk::decode(&chunk_body)?;
        let (file_id, index) = if change_file {
            (
                if chunk.file_id() == 2 { 6 } else { 2 },
                chunk.segment_index(),
            )
        } else {
            (chunk.file_id(), chunk.segment_index() + 1)
        };
        let forged = Chunk::new(
            transfer_id,
            accept_hash,
            chunk.request_id(),
            file_id,
            index,
            chunk.content(),
        )?
        .encode();
        let result = link.b.handle_frame(FrameType::CHUNK, &forged, link.now);
        assert_eq!(
            session_failure(result),
            Some(FailureCode::State),
            "change file: {change_file}"
        );
        assert_eq!(link.b.sink().stored_segments(&transfer_id), 0);
    }
    Ok(())
}

/// §7.5: the receiver answers a `ResumeQuery` only under this session's
/// Accept, for a keyed selected file, from exactly the expected index,
/// and once per page.
#[test]
fn resume_queries_follow_the_receivers_rules() -> TestResult {
    let fixture = fixture()?;
    let probe = |hash: Option<[u8; 32]>, file_id, from| -> AnyResult<Option<FailureCode>> {
        let (mut link, transfer_id, accept_hash) = receiving(&fixture, vec![2, 6])?;
        let query = ResumeQuery::new(transfer_id, hash.unwrap_or(accept_hash), file_id, from)?;
        Ok(session_failure(link.b.handle_frame(
            FrameType::RESUME_QUERY,
            &query.encode(),
            link.now,
        )))
    };
    assert_eq!(probe(None, 2, 0)?, None);
    assert_eq!(probe(Some([9; 32]), 2, 0)?, Some(FailureCode::State));
    assert_eq!(probe(None, 2, 1)?, Some(FailureCode::State));
    assert_eq!(probe(None, 5, 0)?, Some(FailureCode::State));
    // The page answers [0, 3) (all of file 2); asking again is STATE.
    let (mut link, transfer_id, accept_hash) = receiving(&fixture, vec![2, 6])?;
    let query = ResumeQuery::new(transfer_id, accept_hash, 2, 0)?.encode();
    link.b
        .handle_frame(FrameType::RESUME_QUERY, &query, link.now)?;
    let statuses = waiting(&mut link, false, FrameType::RESUME_STATUS);
    let status = ResumeStatus::decode(statuses.first().ok_or("status")?)?;
    assert_eq!(
        (status.file_id(), status.from_index(), status.next_index()),
        (2, 0, 3)
    );
    assert_eq!(status.accept_hash(), &accept_hash);
    assert_eq!(
        session_failure(
            link.b
                .handle_frame(FrameType::RESUME_QUERY, &query, link.now)
        ),
        Some(FailureCode::State)
    );
    Ok(())
}

// ---------------------------------------------------------------------
// The sender's checks (§7.3–§7.7)
// ---------------------------------------------------------------------

/// §7.3: expiry pauses content at once on the sender too. A request that
/// arrives at the Accept's expiry gets no chunk; the receiver is told
/// `EXPIRED`. One second earlier it is served.
#[test]
fn a_request_at_accept_expiry_gets_no_chunk() -> TestResult {
    let fixture = fixture()?;
    for (elapsed, served) in [(599, true), (600, false)] {
        let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 600, (16, 16))?;
        link.b.accept(&transfer_id, vec![2], link.now)?;
        run_until(&mut link, false, FrameType::CHUNK_REQUEST)?;
        link.now = START + Duration::from_secs(elapsed);
        link.deliver(false).ok_or("deliver")??;
        let chunks = bodies(&link.emitted_a, FrameType::CHUNK).len();
        assert_eq!(chunks > 0, served, "after {elapsed} s");
        if !served {
            assert!(sent_transfer_error(&mut link, true, ErrorCode::EXPIRED));
            assert!(has(&link.a_events, |e| matches!(
                e,
                TransferEvent::Expired {
                    direction: Direction::Outgoing,
                    ..
                }
            )));
        }
    }
    Ok(())
}

/// A resumed transfer in its fresh session, with the sender's first
/// `ResumeQuery` (file 2, from 0) taken off the wire. Returns the Accept
/// hash.
fn resumed_query(fixture: &Fixture) -> AnyResult<(Link<'_>, TransferId, [u8; 32])> {
    let (offer, transfer_id, sources, sinks, now) = interrupted(fixture, vec![2, 4], 3)?;
    let mut link = Link::new(
        fixture,
        Which::Second,
        sources,
        sinks,
        (config(4)?, config(4)?),
    )?;
    link.now = now;
    link.settle()?;
    link.a.offer(offer, link.now)?;
    link.settle()?;
    link.b.accept(&transfer_id, vec![2, 4], link.now)?;
    run_until(&mut link, true, FrameType::RESUME_QUERY)?;
    let query = ResumeQuery::decode(&raw(&link.to_b.pop_front().ok_or("query")?).1)?;
    if (query.file_id(), query.from_index()) != (2, 0) {
        return Err("unexpected first query".into());
    }
    Ok((link, transfer_id, *query.accept_hash()))
}

/// §7.5: a `ResumeStatus` must answer the outstanding query: same Accept,
/// file, and `from_index`; `next_index` above `from_index` and at most
/// the segment count (or both equal to it for the empty final page).
/// Otherwise `STATE`. A partial page leads to the next query from its
/// `next_index`.
#[test]
fn resume_statuses_must_answer_the_outstanding_query() -> TestResult {
    let fixture = fixture()?;
    // File 2 has 13 segments, file 4 one.
    let cases: [(bool, u32, u32, u32); 5] = [
        (false, 2, 0, 13),
        (true, 4, 0, 1),
        (true, 2, 1, 13),
        (true, 2, 0, 14),
        (true, 2, 0, 0),
    ];
    for (right_hash, file_id, from, next) in cases {
        let (mut link, transfer_id, accept_hash) = resumed_query(&fixture)?;
        let hash = if right_hash { accept_hash } else { [9; 32] };
        let status = ResumeStatus::new(transfer_id, hash, file_id, from, next, vec![])?;
        let result = link
            .a
            .handle_frame(FrameType::RESUME_STATUS, &status.encode(), link.now);
        assert_eq!(
            session_failure(result),
            Some(FailureCode::State),
            "hash ok {right_hash}, file {file_id}, from {from}, next {next}"
        );
    }
    // A partial page, then the final one: the next query continues from
    // next_index, then moves to the next file.
    let (mut link, transfer_id, accept_hash) = resumed_query(&fixture)?;
    let partial = ResumeStatus::new(transfer_id, accept_hash, 2, 0, 5, vec![(0, 2)])?;
    link.a
        .handle_frame(FrameType::RESUME_STATUS, &partial.encode(), link.now)?;
    let queries = waiting(&mut link, true, FrameType::RESUME_QUERY);
    let next = ResumeQuery::decode(queries.last().ok_or("next query")?)?;
    assert_eq!((next.file_id(), next.from_index()), (2, 5));
    link.to_b.clear();
    let last = ResumeStatus::new(transfer_id, accept_hash, 2, 5, 13, vec![])?;
    link.a
        .handle_frame(FrameType::RESUME_STATUS, &last.encode(), link.now)?;
    let queries = waiting(&mut link, true, FrameType::RESUME_QUERY);
    let next = ResumeQuery::decode(queries.last().ok_or("next file")?)?;
    assert_eq!((next.file_id(), next.from_index()), (4, 0));
    Ok(())
}

/// §7.7: `Complete` must name this manifest and Accept and carry the
/// selection's count and total; any one field off is `STATE`.
#[test]
fn complete_must_match_the_accept_field_by_field() -> TestResult {
    let fixture = fixture()?;
    for field in 0..4 {
        let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
        link.b.accept(&transfer_id, vec![6], link.now)?;
        run_until(&mut link, false, FrameType::COMPLETE)?;
        let complete = Complete::decode(&raw(link.to_a.front().ok_or("complete")?).1)?;
        let mut manifest_hash = *complete.manifest_hash();
        let mut accept_hash = *complete.accept_hash();
        let mut count = complete.completed_count();
        let mut bytes = complete.total_plaintext_bytes();
        match field {
            0 => manifest_hash[0] ^= 1,
            1 => accept_hash[0] ^= 1,
            2 => count += 1,
            _ => bytes += 1,
        }
        let forged = Complete::new(transfer_id, manifest_hash, accept_hash, count, bytes)?;
        let result = link
            .a
            .handle_frame(FrameType::COMPLETE, &forged.encode(), link.now);
        assert_eq!(
            session_failure(result),
            Some(FailureCode::State),
            "field {field}"
        );
    }
    Ok(())
}

/// §7.7: publication must finish while consent is valid. A `Complete`
/// that arrives at the Accept's expiry ends the transfer as expired and
/// delivery is never confirmed; one second earlier it is confirmed.
#[test]
fn complete_at_accept_expiry_confirms_nothing() -> TestResult {
    let fixture = fixture()?;
    for (elapsed, confirmed) in [(599, true), (600, false)] {
        let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 600, (16, 16))?;
        link.b.accept(&transfer_id, vec![6], link.now)?;
        run_until(&mut link, false, FrameType::COMPLETE)?;
        link.now = START + Duration::from_secs(elapsed);
        link.settle()?;
        let delivered = has(&link.a_events, |e| {
            matches!(e, TransferEvent::DeliveryConfirmed { .. })
        });
        assert_eq!(delivered, confirmed, "after {elapsed} s");
        let expired = has(&link.a_events, |e| {
            matches!(
                e,
                TransferEvent::Expired {
                    direction: Direction::Outgoing,
                    ..
                }
            )
        });
        assert_eq!(expired, !confirmed);
    }
    Ok(())
}

/// While the sender waits for the receipt, the identical Accept again is
/// idempotent and a different one is `STATE` (§7.3).
#[test]
fn accepts_while_awaiting_the_receipt() -> TestResult {
    let fixture = fixture()?;
    let (mut link, transfer_id, manifest) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    link.b.accept(&transfer_id, vec![6], link.now)?;
    run_until(&mut link, false, FrameType::DELIVERY_RECEIPT)?;
    let accept = bodies(&link.emitted_b, FrameType::ACCEPT)
        .pop()
        .ok_or("accept")?;
    assert_eq!(
        link.a.handle_frame(FrameType::ACCEPT, &accept, link.now),
        Ok(())
    );
    let other = sign_accept(
        &fixture.bob.keys,
        &fixture.bob.signing_key,
        &fixture.first.1,
        &manifest,
        vec![6],
        time(WALL + 600)?,
        time(WALL)?,
    )?;
    let result = link
        .a
        .handle_frame(FrameType::ACCEPT, other.encoded(), link.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    Ok(())
}

/// §7.7, §12: a second receipt after delivery was confirmed is `STATE`; a
/// receipt that does not decode is `MALFORMED`; a receipt the receiver
/// really signed but for another session is `STATE` and confirms nothing.
#[test]
fn receipts_after_confirmation_malformed_or_for_another_session() -> TestResult {
    let fixture = fixture()?;
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    link.b.accept(&transfer_id, vec![6], link.now)?;
    link.settle()?;
    assert!(has(&link.a_events, |e| matches!(
        e,
        TransferEvent::DeliveryConfirmed { .. }
    )));
    let receipt = bodies(&link.emitted_b, FrameType::DELIVERY_RECEIPT)
        .pop()
        .ok_or("receipt")?;
    let result = link
        .a
        .handle_frame(FrameType::DELIVERY_RECEIPT, &receipt, link.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));

    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    link.b.accept(&transfer_id, vec![6], link.now)?;
    run_until(&mut link, false, FrameType::DELIVERY_RECEIPT)?;
    let receipt = raw(&link.to_a.pop_front().ok_or("receipt")?).1;
    let result = link.a.handle_frame(
        FrameType::DELIVERY_RECEIPT,
        &receipt[..receipt.len() - 1],
        link.now,
    );
    assert_eq!(session_failure(result), Some(FailureCode::Malformed));

    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    link.b.accept(&transfer_id, vec![6], link.now)?;
    run_until(&mut link, false, FrameType::DELIVERY_RECEIPT)?;
    let honest = DeliveryReceipt::decode(&raw(&link.to_a.pop_front().ok_or("receipt")?).1)?;
    let body = honest.body();
    let other = ReceiptBody::new(
        *fixture.second.1.session_id(),
        *body.transfer_id(),
        *body.manifest_hash(),
        *body.accept_hash(),
        *body.sender_public(),
        *body.receiver_public(),
        *body.receipt_id(),
        body.completed_at(),
        body.completed_count(),
        body.total_plaintext_bytes(),
    )?;
    let signature = fixture.bob.keys.sign(
        &fixture.bob.signing_key,
        SigningDomain::DeliveryReceipt,
        &other.encode(),
    )?;
    let replayed = DeliveryReceipt::new(other, signature.to_bytes()).encode();
    let result = link
        .a
        .handle_frame(FrameType::DELIVERY_RECEIPT, &replayed, link.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    assert!(!has(&link.a_events, |e| matches!(
        e,
        TransferEvent::DeliveryConfirmed { .. } | TransferEvent::DeliveryUnconfirmed { .. }
    )));
    Ok(())
}

/// §7.3: a `Reject` must name the offered manifest and arrive while the
/// offer awaits a decision; after this side cancelled an offer, one late
/// `Reject` is discarded and a second is `STATE`.
#[test]
fn rejects_must_match_the_offer() -> TestResult {
    let fixture = fixture()?;
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    let wrong = Reject::new(transfer_id, [9; 32], RejectReason::Declined)?.encode();
    let result = link.a.handle_frame(FrameType::REJECT, &wrong, link.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    assert!(!has(&link.a_events, |e| matches!(
        e,
        TransferEvent::Rejected { .. }
    )));
    // While serving.
    let (mut link, transfer_id, manifest) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    link.b.accept(&transfer_id, vec![2], link.now)?;
    run_until(&mut link, true, FrameType::FILE_KEY)?;
    let reject = Reject::new(transfer_id, *manifest.hash(), RejectReason::Declined)?.encode();
    let result = link.a.handle_frame(FrameType::REJECT, &reject, link.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    // After this side cancelled the offer.
    let (mut link, transfer_id, manifest) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    link.a.cancel(&transfer_id, CancelReason::User, link.now)?;
    let reject = Reject::new(transfer_id, *manifest.hash(), RejectReason::Declined)?.encode();
    assert_eq!(
        link.a.handle_frame(FrameType::REJECT, &reject, link.now),
        Ok(())
    );
    let result = link.a.handle_frame(FrameType::REJECT, &reject, link.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    Ok(())
}

/// An Accept for `transfer_id` signed with Bob's device key for the first
/// session, with the given nonce, selecting file 2.
fn accept_with_nonce(
    fixture: &Fixture,
    transfer_id: TransferId,
    manifest: &CanonicalManifest,
    nonce: [u8; 16],
) -> AnyResult<Vec<u8>> {
    let body = AcceptBody::new(
        *fixture.first.1.session_id(),
        transfer_id,
        *manifest.hash(),
        *fixture.alice.key().as_bytes(),
        *fixture.bob.key().as_bytes(),
        nonce,
        time(WALL + 600)?,
        vec![2],
    )?;
    let signature = fixture.bob.keys.sign(
        &fixture.bob.signing_key,
        SigningDomain::Accept,
        &body.encode(),
    )?;
    Ok(Accept::new(body, signature.to_bytes()).encode())
}

/// §7.3: the Accept nonce is unique per session. A validly signed Accept
/// for a second transfer that reuses the first Accept's nonce is `STATE`
/// and opens nothing; the same record with a fresh nonce is accepted.
#[test]
fn an_accept_nonce_cannot_be_reused_in_a_session() -> TestResult {
    let fixture = fixture()?;
    for reuse in [true, false] {
        let (mut link, offers) = two_offers(&fixture)?;
        let (first, _) = &offers[0];
        let (second, second_manifest) = &offers[1];
        link.b.accept(first, vec![2], link.now)?;
        link.collect();
        let accept = Accept::decode(
            &bodies(&link.emitted_b, FrameType::ACCEPT)
                .pop()
                .ok_or("accept")?,
        )?;
        link.settle()?;
        let nonce = if reuse {
            *accept.body().accept_nonce()
        } else {
            [0x5c; 16]
        };
        let record = accept_with_nonce(&fixture, *second, second_manifest, nonce)?;
        let result = link.a.handle_frame(FrameType::ACCEPT, &record, link.now);
        let keys_for_second = bodies(&link.emitted_a, FrameType::FILE_KEY)
            .iter()
            .chain(waiting(&mut link, true, FrameType::FILE_KEY).iter())
            .filter(|body| body.get(..16) == Some(second.as_slice()))
            .count();
        if reuse {
            assert_eq!(session_failure(result), Some(FailureCode::State));
            assert_eq!(keys_for_second, 0);
        } else {
            assert_eq!(result, Ok(()));
            assert_eq!(keys_for_second, 1);
        }
    }
    Ok(())
}

/// Engine configuration advertising the given receive limits.
fn limits_config(
    manifest_bytes: u32,
    entries: u32,
    file_bytes: u64,
    transfer_bytes: u64,
) -> AnyResult<EngineConfig> {
    let base = config(16)?;
    let record = *base.capabilities.record();
    Ok(EngineConfig {
        capabilities: LocalCapabilities::new(Capabilities::new(
            record.content_suites(),
            manifest_bytes,
            entries,
            file_bytes,
            transfer_bytes,
            16,
        )?)?,
        transport: base.transport,
    })
}

/// §6, §13: the sender offers only what fits the receiver's advertised
/// limits: manifest bytes, entries, the largest file, and the total, each
/// allowed at exactly the limit and refused one below it.
#[test]
fn offers_must_fit_every_advertised_limit() -> TestResult {
    let fixture = fixture()?;
    let mut scratch = MemorySource::new();
    let probe = build_offer(
        &fixture.alice.key(),
        &fixture.bob.key(),
        &standard_specs(),
        &mut scratch,
        3600,
    )?;
    let schema = probe.manifest().manifest();
    let len = u32::try_from(probe.manifest().bytes().len())?;
    let entries = u32::try_from(schema.entries().len())?;
    let largest = schema
        .files()
        .map(todoke_proto::transfer::ManifestEntry::size)
        .max()
        .ok_or("files")?;
    let total = schema.total_file_bytes();
    let max = Capabilities::PROTOCOL_MAXIMUMS;
    let (m, e, f, t) = (
        max.max_manifest_bytes(),
        max.max_entries(),
        max.max_file_bytes(),
        max.max_transfer_bytes(),
    );
    for (limits, fits) in [
        ((len, e, f, t), true),
        ((len - 1, e, f, t), false),
        ((m, entries, f, t), true),
        ((m, entries - 1, f, t), false),
        ((m, e, largest, t), true),
        ((m, e, largest - 1, t), false),
        ((m, e, f, total), true),
        ((m, e, f, total - 1), false),
    ] {
        let (manifest_bytes, max_entries, file_bytes, transfer_bytes) = limits;
        let mut link = Link::new(
            &fixture,
            Which::First,
            (MemorySource::new(), MemorySource::new()),
            (MemorySink::new(), MemorySink::new()),
            (
                config(16)?,
                limits_config(manifest_bytes, max_entries, file_bytes, transfer_bytes)?,
            ),
        )?;
        link.settle()?;
        let offer = build_offer(
            &fixture.alice.key(),
            &fixture.bob.key(),
            &standard_specs(),
            &mut scratch,
            3600,
        )?;
        let result = link.a.offer(offer, link.now);
        if fits {
            assert_eq!(result, Ok(()), "{limits:?}");
        } else {
            assert_eq!(
                result,
                Err(EngineError::Offer(OfferError::Limits)),
                "{limits:?}"
            );
        }
    }
    Ok(())
}

/// A transfer ID this side already uses, in either direction, cannot be
/// offered again (§7: unique transfer IDs).
#[test]
fn an_offer_cannot_reuse_a_live_transfer_id() -> TestResult {
    let fixture = fixture()?;
    let id = [0x55; 16];
    let make = || -> AnyResult<OutgoingOffer> {
        Ok(OutgoingOffer::new(one_file_manifest(
            Some(id),
            &fixture.alice.key(),
            &fixture.bob.key(),
            WALL,
            WALL + 3600,
        )?)?)
    };
    let mut link = ready(&fixture)?;
    link.a.offer(make()?, link.now)?;
    assert_eq!(
        link.a.offer(make()?, link.now),
        Err(EngineError::Offer(OfferError::Duplicate))
    );
    // An ID the peer is sending to this side.
    let mut link = ready(&fixture)?;
    let start = ManifestStart::new(id, [1; 32], 500)?.encode();
    link.a
        .handle_frame(FrameType::MANIFEST_START, &start, link.now)?;
    assert_eq!(
        link.a.offer(make()?, link.now),
        Err(EngineError::Offer(OfferError::Duplicate))
    );
    Ok(())
}

// ---------------------------------------------------------------------
// Cancel (§7.6)
// ---------------------------------------------------------------------

/// An offer whose manifest expires before a decision is cancelled as
/// expired by the sender's own timer, exactly at the expiry.
#[test]
fn an_undecided_offer_is_cancelled_at_manifest_expiry() -> TestResult {
    let fixture = fixture()?;
    for (elapsed, cancelled) in [(99, false), (100, true)] {
        let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 100, (16, 16))?;
        link.now = START + Duration::from_secs(elapsed);
        link.a.poll(link.now)?;
        let cancels = waiting(&mut link, true, FrameType::CANCEL);
        assert_eq!(!cancels.is_empty(), cancelled, "after {elapsed} s");
        if cancelled {
            let cancel = Cancel::decode(cancels.first().ok_or("cancel")?)?;
            assert_eq!(cancel.reason(), CancelReason::Expired);
            assert_eq!(cancel.transfer_id(), &transfer_id);
            assert!(has(&link.a_events, |e| matches!(
                e,
                TransferEvent::Cancelled {
                    by: Party::Local,
                    reason: CancelReason::Expired,
                    ..
                }
            )));
        }
    }
    Ok(())
}

/// §7.6: a repeated identical `Cancel` is idempotent: each copy is
/// acknowledged with its own `cancel_id`, and the transfer ends once. A
/// `CancelAck` with another `cancel_id` is `STATE`; the right one ends the
/// wait, so the 5-second acknowledgment timer no longer fires.
#[test]
fn repeated_cancels_and_acknowledgments() -> TestResult {
    let fixture = fixture()?;
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    link.a.cancel(&transfer_id, CancelReason::User, link.now)?;
    let cancel = waiting(&mut link, true, FrameType::CANCEL)
        .pop()
        .ok_or("cancel")?;
    link.to_b.clear();
    link.b.handle_frame(FrameType::CANCEL, &cancel, link.now)?;
    link.b.handle_frame(FrameType::CANCEL, &cancel, link.now)?;
    let acks = waiting(&mut link, false, FrameType::CANCEL_ACK);
    assert_eq!(acks, vec![cancel.clone(), cancel.clone()]);
    let cancelled = link
        .b_events
        .iter()
        .filter(|e| {
            matches!(
                e,
                TransferEvent::Cancelled {
                    by: Party::Peer,
                    ..
                }
            )
        })
        .count();
    assert_eq!(cancelled, 1);
    // The right acknowledgment clears the wait.
    link.a
        .handle_frame(FrameType::CANCEL_ACK, &cancel, link.now)?;
    let (a, _) = link.advance(Duration::from_secs(6));
    a?;
    // Another cancel_id.
    let (mut link, transfer_id, manifest) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    link.a.cancel(&transfer_id, CancelReason::User, link.now)?;
    let wrong = Cancel::new(
        transfer_id,
        *manifest.hash(),
        [0x77; 16],
        CancelReason::User,
    )?;
    let result = link
        .a
        .handle_frame(FrameType::CANCEL_ACK, &wrong.encode(), link.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    Ok(())
}

// ---------------------------------------------------------------------
// The §13 timers at their boundaries
// ---------------------------------------------------------------------

/// Capabilities 5 s, manifest assembly 30 s, chunk request 30 s, and
/// `CancelAck` 5 s: nothing fires a millisecond before, and each fires
/// exactly at its bound.
#[test]
fn timers_fire_exactly_at_their_bounds() -> TestResult {
    let fixture = fixture()?;
    let just_before = |seconds: u64| Duration::from_millis(seconds * 1000 - 1);
    let tick = Duration::from_millis(1);

    // Capabilities: 5 seconds (§6).
    let mut link = Link::new(
        &fixture,
        Which::First,
        (MemorySource::new(), MemorySource::new()),
        (MemorySink::new(), MemorySink::new()),
        (config(16)?, config(16)?),
    )?;
    let (a, b) = link.advance(just_before(5));
    a?;
    b?;
    let (_, b) = link.advance(tick);
    assert_eq!(session_failure(b), Some(FailureCode::Timeout));

    // Manifest assembly: 30 seconds from ManifestStart (§7.1).
    let manifest = one_file_manifest(
        None,
        &fixture.alice.key(),
        &fixture.bob.key(),
        WALL,
        WALL + 3600,
    )?;
    let id = *manifest.transfer_id();
    let bytes = manifest.bytes();
    let mut link = ready(&fixture)?;
    let start = ManifestStart::new(id, *manifest.hash(), u32::try_from(bytes.len())?)?;
    link.b
        .handle_frame(FrameType::MANIFEST_START, &start.encode(), link.now)?;
    link.b.handle_frame(
        FrameType::MANIFEST_PART,
        &ManifestPart::new(id, 0, &bytes[..10])?.encode(),
        link.now,
    )?;
    let (_, b) = link.advance(just_before(30));
    b?;
    assert!(!sent_transfer_error(&mut link, false, ErrorCode::TIMEOUT));
    let (_, b) = link.advance(tick);
    b?;
    assert!(sent_transfer_error(&mut link, false, ErrorCode::TIMEOUT));

    // An outstanding chunk request: 30 seconds (§13), then the session
    // closes.
    let (mut link, _, _) = receiving(&fixture, vec![2])?;
    let (_, b) = link.advance(just_before(30));
    b?;
    let (_, b) = link.advance(tick);
    assert_eq!(session_failure(b), Some(FailureCode::Timeout));

    // An unacknowledged Cancel: 5 seconds (§7.6).
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    link.b.cancel(&transfer_id, CancelReason::User, link.now)?;
    link.collect();
    link.to_a.clear();
    let (_, b) = link.advance(just_before(5));
    b?;
    let (_, b) = link.advance(tick);
    assert_eq!(session_failure(b), Some(FailureCode::Timeout));
    Ok(())
}

// ---------------------------------------------------------------------
// Engine-wide bounds
// ---------------------------------------------------------------------

/// An engine is only built with this session's own device key.
#[test]
fn an_engine_needs_the_sessions_device_key() -> TestResult {
    let fixture = fixture()?;
    let result = TransferEngine::new(
        fixture.first.0,
        &fixture.bob.keys,
        fixture.bob.signing_key,
        MemorySource::new(),
        MemorySink::new(),
        config(16)?,
        Clock::new(time(WALL)?, START),
        START,
    );
    assert_eq!(result.err(), Some(EngineError::KeyRole));
    let mut link = ready(&fixture)?;
    link.a.close(None);
    assert_eq!(link.a.poll(link.now), Err(EngineError::Closed));
    Ok(())
}

/// §13: at most 16 MiB of application frames wait per session. A peer
/// that keeps requesting while the caller sends nothing is cut off with
/// `LIMIT` as soon as the queue exceeds the bound, not before.
#[test]
fn queued_frames_are_bounded_at_16_mib() -> TestResult {
    let fixture = fixture()?;
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    link.b.accept(&transfer_id, vec![2], link.now)?;
    run_until(&mut link, false, FrameType::CHUNK_REQUEST)?;
    let first = ChunkRequest::decode(&raw(link.to_a.front().ok_or("request")?).1)?;
    let accept_hash = *first.accept_hash();
    link.to_a.clear();
    link.collect();
    // One request first, to measure the chunk it produces.
    let request = |id: u32| -> AnyResult<Vec<u8>> {
        Ok(ChunkRequest::new(transfer_id, accept_hash, id, 2, 0)?
            .encode()
            .to_vec())
    };
    link.a
        .handle_frame(FrameType::CHUNK_REQUEST, &request(1000)?, link.now)?;
    let chunk_len = match link.a.pop_frame().ok_or("chunk")? {
        OutgoingFrame::Frame { body, .. } => body.len(),
        OutgoingFrame::Error(_) => return Err("error".into()),
    };
    let budget = 16_usize << 20;
    let mut queued = 0_usize;
    let mut refused = false;
    for id in 1001..3000 {
        match link
            .a
            .handle_frame(FrameType::CHUNK_REQUEST, &request(id)?, link.now)
        {
            Ok(()) => queued += 1,
            Err(error) => {
                assert_eq!(session_failure(Err(error)), Some(FailureCode::Limit));
                refused = true;
                break;
            }
        }
    }
    assert!(refused);
    // Refused only once the queue exceeded the bound.
    assert!(queued * chunk_len > budget);
    assert!((queued - 1) * chunk_len <= budget);
    Ok(())
}

/// §7.5: retained segments are revalidated at most 64 per engine call so
/// that a large resumed file does not stall the session: the engine asks
/// to be polled again at once while some remain, requests nothing until
/// they are done, and then completes with only the missing segments.
#[test]
fn revalidation_is_paced_across_calls() -> TestResult {
    let fixture = fixture()?;
    let size = 16_384 * 80;
    let specs = vec![file("big", 0, size, 3)];
    let (offer, transfer_id, sources, sinks, now) =
        interrupted_with(&fixture, &specs, vec![1], 70)?;
    let retained = sinks.1.stored_segments(&transfer_id);
    assert!(retained > 64, "{retained}");
    let mut link = Link::new(
        &fixture,
        Which::Second,
        sources,
        sinks,
        (config(4)?, config(4)?),
    )?;
    link.now = now;
    link.settle()?;
    link.a.offer(offer, link.now)?;
    link.settle()?;
    link.b.accept(&transfer_id, vec![1], link.now)?;
    run_until(&mut link, true, FrameType::FILE_KEY)?;
    link.deliver(true).ok_or("key")??;
    // 64 revalidated; the rest wait for the next call.
    assert_eq!(link.b.next_deadline(link.now), link.now);
    assert_eq!(
        waiting(&mut link, false, FrameType::CHUNK_REQUEST),
        Vec::<Vec<u8>>::new()
    );
    link.b.poll(link.now)?;
    assert!(link.b.next_deadline(link.now) > link.now);
    link.settle()?;
    assert_eq!(
        link.b.sink().published(&transfer_id, 1),
        Some(content(size, 3).as_slice())
    );
    assert_eq!(
        link.delivered(false, FrameType::CHUNK_REQUEST),
        80 - retained
    );
    Ok(())
}

// ---------------------------------------------------------------------
// §12 codes
// ---------------------------------------------------------------------

/// Every §12 code maps to its own failure and back; the reserved and
/// unknown codes are a generic failure; local-only failures send nothing;
/// the stable identifiers and messages are distinct.
#[test]
fn error_codes_map_one_to_one() -> TestResult {
    let mut seen = std::collections::BTreeSet::new();
    for value in 1..=0x000e_u16 {
        let code = ErrorCode::new(value)?;
        let failure = FailureCode::from_error_code(code);
        assert_ne!(failure, FailureCode::Unknown, "{value:#06x}");
        assert_eq!(failure.error_code(), Some(code));
        assert!(seen.insert(failure.code()));
    }
    for value in [0x000f, 0x0100, u16::MAX] {
        assert_eq!(
            FailureCode::from_error_code(ErrorCode::new(value)?),
            FailureCode::Unknown
        );
    }
    let local = [
        FailureCode::SourceChanged,
        FailureCode::KeyStore,
        FailureCode::Random,
        FailureCode::SessionEnded,
        FailureCode::Unknown,
    ];
    for failure in local {
        assert_eq!(failure.error_code(), None);
        assert!(seen.insert(failure.code()));
    }
    let messages: std::collections::BTreeSet<&str> = (1..=0x000e_u16)
        .filter_map(|value| ErrorCode::new(value).ok())
        .map(FailureCode::from_error_code)
        .chain(local)
        .map(FailureCode::message)
        .collect();
    assert_eq!(messages.len(), 14 + local.len());
    assert_eq!(FailureCode::State.to_string(), FailureCode::State.message());
    Ok(())
}

// ---------------------------------------------------------------------
// Further boundaries
// ---------------------------------------------------------------------

/// §7.1: a manifest may be as long as the receiver's own advertised
/// `max_manifest_bytes`, not longer; a longer `ManifestStart` is refused
/// with a transfer-scoped `LIMIT`.
#[test]
fn a_manifest_may_be_exactly_the_local_size_limit() -> TestResult {
    let fixture = fixture()?;
    let max = Capabilities::PROTOCOL_MAXIMUMS;
    for (slack, admitted) in [(0, true), (1, false)] {
        let manifest = one_file_manifest(
            None,
            &fixture.alice.key(),
            &fixture.bob.key(),
            WALL,
            WALL + 3600,
        )?;
        let cap = u32::try_from(manifest.bytes().len())? - slack;
        let mut link = Link::new(
            &fixture,
            Which::First,
            (MemorySource::new(), MemorySource::new()),
            (MemorySink::new(), MemorySink::new()),
            (
                config(16)?,
                limits_config(
                    cap,
                    max.max_entries(),
                    max.max_file_bytes(),
                    max.max_transfer_bytes(),
                )?,
            ),
        )?;
        link.settle()?;
        inject_manifest(&mut link, &manifest)?;
        assert_eq!(
            offer_received(&link, manifest.transfer_id()),
            admitted,
            "cap {cap}"
        );
        assert_eq!(
            sent_transfer_error(&mut link, false, ErrorCode::LIMIT),
            !admitted
        );
    }
    Ok(())
}

/// The bounds ADR 0005 and §13 document, by value: the tests that
/// exercise them are written against the constants, so a changed
/// constant must also change its documentation.
#[test]
fn documented_bounds_have_their_documented_values() {
    use crate::limits::{
        APP_BUFFER_BUDGET, CANCEL_ACK_TIMEOUT, CAPABILITIES_TIMEOUT, CHUNK_REQUEST_TIMEOUT,
        CONSENT_PROMPT_TIMEOUT, LATE_MANIFEST_BUDGET, MANIFEST_ASSEMBLY_TIMEOUT,
        MAX_ACTIVE_INCOMING_FILES, MAX_INCOMING_TRANSFER_IDS, MAX_INCOMING_TRANSFERS,
        MAX_INCOMPLETE_MANIFESTS, MAX_REVOCATIONS, RECEIPT_TIMEOUT, RESUME_METADATA_BUDGET,
        REVALIDATION_BUDGET, TOMBSTONE_GRACE_SECONDS,
    };
    assert_eq!(MAX_INCOMING_TRANSFER_IDS, 1024);
    assert_eq!(LATE_MANIFEST_BUDGET, 8 * 1024 * 1024);
    assert_eq!(APP_BUFFER_BUDGET, 16 * 1024 * 1024);
    assert_eq!(RESUME_METADATA_BUDGET, 8 * 1024 * 1024);
    assert_eq!(MAX_REVOCATIONS, 64);
    assert_eq!(MAX_INCOMING_TRANSFERS, 2);
    assert_eq!(MAX_ACTIVE_INCOMING_FILES, 2);
    assert_eq!(MAX_INCOMPLETE_MANIFESTS, 1);
    assert_eq!(TOMBSTONE_GRACE_SECONDS, 120);
    assert_eq!(REVALIDATION_BUDGET, 64);
    assert_eq!(CAPABILITIES_TIMEOUT, Duration::from_secs(5));
    assert_eq!(MANIFEST_ASSEMBLY_TIMEOUT, Duration::from_secs(30));
    assert_eq!(CONSENT_PROMPT_TIMEOUT, Duration::from_secs(300));
    assert_eq!(CHUNK_REQUEST_TIMEOUT, Duration::from_secs(30));
    assert_eq!(CANCEL_ACK_TIMEOUT, Duration::from_secs(5));
    assert_eq!(RECEIPT_TIMEOUT, Duration::from_secs(10));
}

/// §7.6: after this side cancels, the peer's chunks already in flight are
/// discarded, at most the number of requests outstanding at the cancel;
/// one more before the acknowledgment is `STATE`.
#[test]
fn late_chunks_after_a_cancel_are_bounded_by_the_outstanding_count() -> TestResult {
    let fixture = fixture()?;
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    link.b.accept(&transfer_id, vec![2, 5], link.now)?;
    run_until(&mut link, true, FrameType::CHUNK)?;
    let extra = raw(link.to_b.front().ok_or("chunk")?).1;
    link.b.cancel(&transfer_id, CancelReason::User, link.now)?;
    // Alice answers the requests still on their way, then acknowledges.
    while !link.to_a.is_empty() {
        link.deliver(false).ok_or("to alice")??;
    }
    link.collect();
    let late = link
        .to_b
        .iter()
        .filter(|frame| raw(frame).0 == FrameType::CHUNK)
        .count();
    assert!(late > 0);
    // Every in-flight chunk is discarded quietly, up to the CancelAck.
    for _ in 0..late {
        link.deliver(true).ok_or("chunk")??;
    }
    assert_eq!(
        link.to_b.front().map(|frame| raw(frame).0),
        Some(FrameType::CANCEL_ACK)
    );
    assert_eq!(link.b.sink().stored_segments(&transfer_id), 0);
    // One more is more than could have been in flight.
    let result = link.b.handle_frame(FrameType::CHUNK, &extra, link.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    Ok(())
}

/// §7.3: no request after the Accept expired. A `FileKey` that arrives at
/// the expiry, before the timer ran, leads to no `ChunkRequest`; a second
/// earlier it does.
#[test]
fn no_request_is_issued_after_accept_expiry() -> TestResult {
    let fixture = fixture()?;
    for (elapsed, requested) in [(599, true), (600, false)] {
        let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 600, (16, 16))?;
        link.b.accept(&transfer_id, vec![2], link.now)?;
        run_until(&mut link, true, FrameType::FILE_KEY)?;
        link.now = START + Duration::from_secs(elapsed);
        link.deliver(true).ok_or("key")??;
        let requests = waiting(&mut link, false, FrameType::CHUNK_REQUEST);
        assert_eq!(!requests.is_empty(), requested, "after {elapsed} s");
        link.b.poll(link.now)?;
        link.collect();
        let expired = has(&link.b_events, |e| {
            matches!(
                e,
                TransferEvent::Expired {
                    direction: Direction::Incoming,
                    ..
                }
            )
        });
        assert_eq!(expired, !requested);
    }
    Ok(())
}

/// §7.4: the sender serves a request only under this session's Accept
/// hash; another hash is `STATE` and gets no chunk.
#[test]
fn a_request_under_another_accept_hash_is_refused() -> TestResult {
    let fixture = fixture()?;
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    link.b.accept(&transfer_id, vec![2], link.now)?;
    run_until(&mut link, false, FrameType::CHUNK_REQUEST)?;
    let request = ChunkRequest::decode(&raw(link.to_a.front().ok_or("request")?).1)?;
    let mut other_hash = *request.accept_hash();
    other_hash[0] ^= 1;
    let forged = ChunkRequest::new(
        transfer_id,
        other_hash,
        request.request_id(),
        request.file_id(),
        request.segment_index(),
    )?
    .encode();
    let result = link
        .a
        .handle_frame(FrameType::CHUNK_REQUEST, &forged, link.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    assert_eq!(bodies(&link.emitted_a, FrameType::CHUNK).len(), 0);
    assert_eq!(waiting(&mut link, true, FrameType::CHUNK).len(), 0);
    Ok(())
}

/// §7.5: `ResumeQuery` follows the file's `FileKey` in this session. For
/// a file an earlier session already published, a query before its key is
/// `STATE`, although the receiver could answer it.
#[test]
fn a_resume_query_before_the_files_key_is_refused() -> TestResult {
    let fixture = fixture()?;
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (4, 4))?;
    link.b.accept(&transfer_id, vec![2, 6], link.now)?;
    run_until(&mut link, false, FrameType::COMPLETE)?;
    // Complete and the receipt are lost with the connection.
    link.a.close(None);
    link.b.close(None);
    link.collect();
    let offer = link.a.take_resumable().pop().ok_or("resumable")?;
    let (a_source, a_sink) = link.a.into_parts();
    let (b_source, b_sink) = link.b.into_parts();
    let mut again = Link::new(
        &fixture,
        Which::Second,
        (a_source, b_source),
        (a_sink, b_sink),
        (config(4)?, config(4)?),
    )?;
    again.settle()?;
    again.a.offer(offer, again.now)?;
    again.settle()?;
    again.b.accept(&transfer_id, vec![2, 6], again.now)?;
    let record = waiting(&mut again, false, FrameType::ACCEPT)
        .pop()
        .ok_or("accept")?;
    let accept_hash = todoke_crypto::consent::accept_hash(&record);
    let query = ResumeQuery::new(transfer_id, accept_hash, 2, 0)?.encode();
    let result = again
        .b
        .handle_frame(FrameType::RESUME_QUERY, &query, again.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    Ok(())
}

/// §7.6: a cancel makes a transfer permanently unusable, also after it
/// expired: its masters are dropped and it is never offered for resume.
/// Without the cancel the expired transfer stays resumable; a delivered
/// one cannot be cancelled.
#[test]
fn cancelling_an_expired_outgoing_transfer_ends_it_for_good() -> TestResult {
    let fixture = fixture()?;
    for cancel in [false, true] {
        let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 600, (16, 16))?;
        link.b.accept(&transfer_id, vec![2], link.now)?;
        run_until(&mut link, true, FrameType::CHUNK)?;
        link.now = START + Duration::from_secs(600);
        link.a.poll(link.now)?;
        link.collect();
        assert!(has(&link.a_events, |e| matches!(
            e,
            TransferEvent::Expired {
                direction: Direction::Outgoing,
                ..
            }
        )));
        if cancel {
            link.a.cancel(&transfer_id, CancelReason::User, link.now)?;
            let cancels = waiting(&mut link, true, FrameType::CANCEL);
            assert_eq!(cancels.len(), 1);
            assert_eq!(link.a.take_resumable().len(), 0);
            // Cancelled for good: a second cancel is refused.
            assert_eq!(
                link.a.cancel(&transfer_id, CancelReason::User, link.now),
                Err(EngineError::WrongState)
            );
        } else {
            assert_eq!(link.a.take_resumable().len(), 1);
        }
    }
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    link.b.accept(&transfer_id, vec![6], link.now)?;
    link.settle()?;
    assert_eq!(
        link.a.cancel(&transfer_id, CancelReason::User, link.now),
        Err(EngineError::WrongState)
    );
    Ok(())
}
