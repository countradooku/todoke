//! Completion, receipts, expiry, interruption, resume (with revalidation
//! and revocation), source mutation, storage failures, peer errors, and
//! forwarded revocations.

use core::time::Duration;

use todoke_crypto::consent::random_id;
use todoke_crypto::identity::{
    Ed25519PublicKey, ExportPolicy, KeyId, KeyRole, KeyStore, KeyStoreError, Signature,
    SigningDomain, WrappedKey, WrappingKey,
};
use todoke_proto::session::{ErrorCode, FrameType};
use todoke_proto::transfer::{CancelReason, Complete, TransferId};

use super::basic::{
    has, offered, receiving, run_until, sent_transfer_error, session_failure, standard_specs,
};
use super::support::*;
use crate::{
    Clock, EngineError, FailureCode, MemorySink, MemorySource, OutgoingFrame, OutgoingOffer, Party,
    ReceiveSink, TransferEngine, TransferEvent,
};

#[test]
fn receipt_window_and_forged_receipts() -> TestResult {
    let fixture = fixture()?;
    // The receipt never arrives: unconfirmed after 10 seconds.
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    link.b.accept(&transfer_id, vec![6], link.now)?;
    run_until(&mut link, false, FrameType::DELIVERY_RECEIPT)?;
    let receipt = link.to_a.pop_front().ok_or("receipt")?;
    let (a, _) = link.advance(Duration::from_secs(9));
    a?;
    assert!(!has(&link.a_events, |e| matches!(
        e,
        TransferEvent::DeliveryUnconfirmed { .. }
    )));
    let (a, _) = link.advance(Duration::from_secs(1));
    a?;
    assert!(has(
        &link.a_events,
        |e| matches!(e, TransferEvent::DeliveryUnconfirmed { transfer_id: t } if *t == transfer_id)
    ));
    // One late receipt is still discarded quietly; nothing is confirmed.
    deliver_to(&mut link.a, receipt, link.now)?;
    assert!(!has(&link.a_events, |e| matches!(
        e,
        TransferEvent::DeliveryConfirmed { .. }
    )));
    // An unconfirmed delivery is never retransferred silently.
    assert!(link.a.take_resumable().is_empty());

    // A tampered receipt closes the session.
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    link.b.accept(&transfer_id, vec![6], link.now)?;
    run_until(&mut link, false, FrameType::DELIVERY_RECEIPT)?;
    let OutgoingFrame::Frame { body, .. } = link.to_a.front_mut().ok_or("receipt")? else {
        return Err("not a frame".into());
    };
    let last = body.len() - 1;
    body[last] ^= 1;
    let result = link.deliver(false).ok_or("deliver")?;
    assert_eq!(session_failure(result), Some(FailureCode::Authentication));
    assert!(!has(&link.a_events, |e| matches!(
        e,
        TransferEvent::DeliveryConfirmed { .. }
    )));

    // A Complete whose totals differ from the selection: STATE.
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    link.b.accept(&transfer_id, vec![6], link.now)?;
    run_until(&mut link, false, FrameType::COMPLETE)?;
    let complete = Complete::decode(&raw(link.to_a.front().ok_or("complete")?).1)?;
    let wrong = Complete::new(
        transfer_id,
        *complete.manifest_hash(),
        *complete.accept_hash(),
        1,
        complete.total_plaintext_bytes() + 1,
    )?;
    let result = link
        .a
        .handle_frame(FrameType::COMPLETE, &wrong.encode(), link.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    // A receipt before Complete: STATE.
    let (mut link, transfer_id, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    link.b.accept(&transfer_id, vec![6], link.now)?;
    run_until(&mut link, false, FrameType::COMPLETE)?;
    link.to_a.pop_front();
    let result = link.deliver(false).ok_or("deliver")?;
    assert_eq!(session_failure(result), Some(FailureCode::State));
    Ok(())
}

/// Runs until Bob has stored at least `segments` verified segments.
fn run_until_stored(link: &mut Link<'_>, transfer_id: &TransferId, segments: usize) -> TestResult {
    for _ in 0..100_000 {
        if link.b.sink().stored_segments(transfer_id) >= segments {
            return Ok(());
        }
        link.collect();
        let toward_bob = !link.to_b.is_empty();
        if !toward_bob && link.to_a.is_empty() {
            return Err("transfer stalled".into());
        }
        if let Some(Err(error)) = link.deliver(toward_bob) {
            return Err(format!("delivery failed: {error}").into());
        }
    }
    Err("not stored".into())
}

fn big_specs() -> Vec<Spec> {
    vec![
        dir("folder", 0),
        file("big", 1, 16_384 * 12 + 77, 7),
        file("empty", 1, 0, 8),
        file("small", 0, 999, 9),
    ]
}

#[test]
fn accept_expiry_pauses_content_and_resume_needs_fresh_consent() -> TestResult {
    let fixture = fixture()?;
    // Manifest valid for two days; the Accept for 24 hours.
    let (mut link, transfer_id, _) = offered(&fixture, &big_specs(), 2 * 86_400, (4, 4))?;
    link.b.accept(&transfer_id, vec![2, 3, 4], link.now)?;
    run_until_stored(&mut link, &transfer_id, 3)?;
    link.collect();
    let (a, b) = link.advance(Duration::from_hours(24));
    a?;
    b?;
    assert!(has(
        &link.a_events,
        |e| matches!(e, TransferEvent::Expired { transfer_id: t, .. } if *t == transfer_id)
    ));
    assert!(has(
        &link.b_events,
        |e| matches!(e, TransferEvent::Expired { transfer_id: t, .. } if *t == transfer_id)
    ));
    // Frames already in flight are discarded within the allowance.
    link.settle()?;
    assert!(link.b.sink().published(&transfer_id, 2).is_none());
    let stored = link.b.sink().stored_segments(&transfer_id);
    assert!(stored >= 3);
    // A fresh session with fresh consent finishes it.
    let mut offers = link.a.take_resumable();
    let offer = offers.pop().ok_or("resumable")?;
    assert!(offer.is_resumption());
    let (a_source, a_sink) = link.a.into_parts();
    let (b_source, b_sink) = link.b.into_parts();
    let mut second = Link::new(
        &fixture,
        Which::Second,
        (a_source, b_source),
        (a_sink, b_sink),
        (config(4)?, config(4)?),
    )?;
    second.now = link.now;
    second.settle()?;
    second.a.offer(offer, second.now)?;
    second.settle()?;
    let view = second
        .b_events
        .iter()
        .find_map(|e| match e {
            TransferEvent::OfferReceived(view) => Some(view.clone()),
            _ => None,
        })
        .ok_or("offer")?;
    assert_eq!(view.resume_selection, Some(vec![2, 3, 4]));
    second.b.accept(&transfer_id, vec![2, 3, 4], second.now)?;
    second.settle()?;
    for (id, len, salt) in [(2, 16_384 * 12 + 77, 7), (3, 0, 8), (4, 999, 9)] {
        assert_eq!(
            second.b.sink().published(&transfer_id, id),
            Some(content(len, salt).as_slice())
        );
    }
    // Only what was missing was sent again.
    let total_segments = 13 + 1 + 1;
    assert!(second.delivered(true, FrameType::CHUNK) <= total_segments - stored);
    assert!(has(&second.a_events, |e| matches!(
        e,
        TransferEvent::DeliveryConfirmed { .. }
    )));
    Ok(())
}

/// What a fresh session needs after an interruption.
type Interrupted = (
    OutgoingOffer,
    TransferId,
    (MemorySource, MemorySource),
    (MemorySink, MemorySink),
    Duration,
);

/// Interrupts a transfer after `stored` segments and returns everything a
/// fresh session needs.
fn interrupted(fixture: &Fixture, selection: Vec<u32>, stored: usize) -> AnyResult<Interrupted> {
    let (mut link, transfer_id, _) = offered(fixture, &big_specs(), 3600, (4, 4))?;
    link.b.accept(&transfer_id, selection, link.now)?;
    run_until_stored(&mut link, &transfer_id, stored)?;
    link.a.close(None);
    link.b.close(None);
    link.collect();
    assert!(has(&link.a_events, |e| matches!(
        e,
        TransferEvent::Interrupted { .. }
    )));
    assert!(has(&link.b_events, |e| matches!(
        e,
        TransferEvent::Interrupted { .. }
    )));
    assert!(has(&link.b_events, |e| matches!(
        e,
        TransferEvent::SessionClosed { failure: None }
    )));
    assert_eq!(
        link.b.accept(&transfer_id, vec![2], link.now),
        Err(EngineError::Closed)
    );
    let offer = link.a.take_resumable().pop().ok_or("resumable")?;
    let now = link.now;
    let (a_source, a_sink) = link.a.into_parts();
    let (b_source, b_sink) = link.b.into_parts();
    Ok((
        offer,
        transfer_id,
        (a_source, b_source),
        (a_sink, b_sink),
        now,
    ))
}

#[test]
fn resume_after_interruption_revalidates_retained_segments() -> TestResult {
    let fixture = fixture()?;
    let (offer, transfer_id, sources, mut sinks, now) = interrupted(&fixture, vec![2, 4], 5)?;
    let retained = sinks.1.stored_segments(&transfer_id);
    let published = usize::from(sinks.1.published(&transfer_id, 4).is_some());
    // One retained segment no longer opens: it is dropped and requested
    // again, never trusted.
    let corrupted = usize::from(sinks.1.has_segment(&transfer_id, 2, 0));
    sinks.1.corrupt_segment(&transfer_id, 2, 0);
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
    // The earlier selection must be repeated exactly.
    assert_eq!(
        link.b.accept(&transfer_id, vec![2], link.now),
        Err(EngineError::Selection)
    );
    link.b.accept(&transfer_id, vec![2, 4], link.now)?;
    link.settle()?;
    assert_eq!(
        link.b.sink().published(&transfer_id, 2),
        Some(content(16_384 * 12 + 77, 7).as_slice())
    );
    assert_eq!(
        link.b.sink().published(&transfer_id, 4),
        Some(content(999, 9).as_slice())
    );
    // Requests: everything not retained, plus the corrupted segment.
    let requests = link.delivered(false, FrameType::CHUNK_REQUEST);
    assert_eq!(requests, 13 + 1 - published - retained + corrupted);
    // The resumed sender asked what the receiver holds (§7.5).
    assert_eq!(link.delivered(false, FrameType::RESUME_QUERY), 0);
    assert!(link.delivered(true, FrameType::RESUME_QUERY) >= 1);
    assert!(link.delivered(false, FrameType::RESUME_STATUS) >= 1);
    assert!(has(&link.a_events, |e| matches!(
        e,
        TransferEvent::DeliveryConfirmed { .. }
    )));
    Ok(())
}

#[test]
fn resume_is_unavailable_after_revocation_or_cancel() -> TestResult {
    let fixture = fixture()?;
    // Revocation of the sender invalidates the retained state.
    let (offer, transfer_id, sources, mut sinks, now) = interrupted(&fixture, vec![2, 4], 3)?;
    let wall = time(WALL)?;
    sinks
        .1
        .revoke_sender(&fixture.alice.key(), time(WALL + 7 * 86_400)?);
    assert!(sinks.1.is_tombstoned(&transfer_id, wall));
    assert_eq!(sinks.1.stored_segments(&transfer_id), 0);
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
    link.collect();
    link.settle()?;
    assert!(!has(&link.b_events, |e| matches!(
        e,
        TransferEvent::OfferReceived(_)
    )));
    assert!(has(&link.a_events, |e| matches!(e,
        TransferEvent::Failed { failure, .. } if failure.code == FailureCode::ResumeUnavailable && failure.by == Party::Peer)));

    // A cancelled transfer is gone on both sides: nothing to resume, and
    // its ID is refused if it comes back.
    let (mut link, transfer_id, manifest) = offered(&fixture, &big_specs(), 3600, (4, 4))?;
    link.b.accept(&transfer_id, vec![2], link.now)?;
    run_until_stored(&mut link, &transfer_id, 2)?;
    link.b.cancel(&transfer_id, CancelReason::User, link.now)?;
    link.settle()?;
    assert!(link.a.take_resumable().is_empty());
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
    again.a.offer(OutgoingOffer::new(manifest)?, again.now)?;
    again.settle()?;
    assert!(!has(&again.b_events, |e| matches!(
        e,
        TransferEvent::OfferReceived(_)
    )));
    assert!(has(&again.a_events, |e| matches!(e,
        TransferEvent::Failed { failure, .. } if failure.code == FailureCode::ResumeUnavailable)));
    Ok(())
}

#[test]
fn source_changes_cancel_the_transfer() -> TestResult {
    let fixture = fixture()?;
    let (mut link, transfer_id, _) = offered(&fixture, &big_specs(), 3600, (4, 4))?;
    link.b.accept(&transfer_id, vec![2], link.now)?;
    run_until(&mut link, false, FrameType::CHUNK_REQUEST)?;
    let file = link
        .a
        .source_mut()
        .file_mut(&transfer_id, 2)
        .ok_or("source file")?;
    file.content_mut()[0] ^= 1;
    link.settle()?;
    assert!(has(&link.a_events, |e| matches!(e,
        TransferEvent::Failed { failure, .. } if failure.code == FailureCode::SourceChanged)));
    assert!(has(&link.b_events, |e| matches!(
        e,
        TransferEvent::Cancelled {
            by: Party::Peer,
            reason: CancelReason::Storage,
            ..
        }
    )));
    assert!(link.b.sink().published(&transfer_id, 2).is_none());
    Ok(())
}

#[test]
fn storage_failures() -> TestResult {
    let fixture = fixture()?;
    // The Accept cannot be recorded durably: nothing is sent.
    let (mut link, transfer_id, _) = offered(&fixture, &big_specs(), 3600, (4, 4))?;
    link.b.sink_mut().set_failing(true);
    assert_eq!(
        link.b.accept(&transfer_id, vec![2], link.now),
        Err(EngineError::Storage)
    );
    link.collect();
    assert!(!link.to_a.iter().any(|f| raw(f).0 == FrameType::ACCEPT));
    // A segment cannot be stored: STORAGE for the transfer.
    link.b.sink_mut().set_failing(false);
    link.b.accept(&transfer_id, vec![2], link.now)?;
    run_until(&mut link, true, FrameType::CHUNK)?;
    link.b.sink_mut().set_failing(true);
    link.deliver(true).ok_or("deliver")??;
    assert!(sent_transfer_error(&mut link, false, ErrorCode::STORAGE));
    link.settle()?;
    assert!(has(&link.a_events, |e| matches!(e,
        TransferEvent::Failed { failure, .. } if failure.code == FailureCode::Storage && failure.by == Party::Peer)));
    Ok(())
}

#[test]
fn peer_errors_and_revocations() -> TestResult {
    let fixture = fixture()?;
    let (mut link, transfer_id, _) = receiving(&fixture, vec![2])?;
    let error = transfer_error(transfer_id, ErrorCode::STORAGE)?;
    link.b.handle_frame(FrameType::ERROR, &error, link.now)?;
    link.collect();
    assert!(has(&link.b_events, |e| matches!(e,
        TransferEvent::Failed { failure, .. } if failure.code == FailureCode::Storage && failure.by == Party::Peer)));
    // An Error for an unknown transfer needs nothing.
    link.b.handle_frame(
        FrameType::ERROR,
        &transfer_error([0x66; 16], ErrorCode::STATE)?,
        link.now,
    )?;
    // Forwarded revocations reach the caller, at most 64 per session.
    let (mut link, _, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    for index in 0..64_u8 {
        link.b
            .handle_frame(FrameType::REVOKE, &[index; 172], link.now)?;
    }
    assert_eq!(link.b.pop_revocation(), Some(vec![0; 172]));
    let result = link.b.handle_frame(FrameType::REVOKE, &[1; 172], link.now);
    assert_eq!(session_failure(result), Some(FailureCode::Limit));
    // Unknown transfer-layer frame types in Ready: STATE.
    let (mut link, _, _) = offered(&fixture, &standard_specs(), 3600, (16, 16))?;
    let result = link
        .b
        .handle_frame(FrameType::new(0x0005), &[0; 38], link.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    let _ = random_id()?;
    Ok(())
}

#[test]
fn offers_must_fit_the_session() -> TestResult {
    let fixture = fixture()?;
    let mut source = MemorySource::new();
    let mut link = Link::new(
        &fixture,
        Which::First,
        (MemorySource::new(), MemorySource::new()),
        (MemorySink::new(), MemorySink::new()),
        (config(16)?, config(16)?),
    )?;
    // Before Capabilities.
    let offer = build_offer(
        &fixture.alice.key(),
        &fixture.bob.key(),
        &standard_specs(),
        &mut source,
        3600,
    )?;
    assert_eq!(
        link.a.offer(offer, link.now),
        Err(EngineError::Offer(crate::OfferError::NotReady))
    );
    link.settle()?;
    // To the wrong device, or from the wrong one.
    let wrong = build_offer(
        &fixture.alice.key(),
        &fixture.alice.key(),
        &standard_specs(),
        &mut source,
        3600,
    )?;
    assert_eq!(
        link.a.offer(wrong, link.now),
        Err(EngineError::Offer(crate::OfferError::Parties))
    );
    let wrong = build_offer(
        &fixture.bob.key(),
        &fixture.bob.key(),
        &standard_specs(),
        &mut source,
        3600,
    )?;
    assert_eq!(
        link.a.offer(wrong, link.now),
        Err(EngineError::Offer(crate::OfferError::Parties))
    );
    // Expired.
    let offer = build_offer(
        &fixture.alice.key(),
        &fixture.bob.key(),
        &standard_specs(),
        &mut source,
        60,
    )?;
    link.now += Duration::from_secs(61);
    assert_eq!(
        link.a.offer(offer, link.now),
        Err(EngineError::Offer(crate::OfferError::Expired))
    );
    Ok(())
}

/// The connection drops after the receiver completed but before the
/// sender heard: a re-offer must repeat the selection and completes from
/// the published files without fetching anything again (§7.3, §7.7).
#[test]
fn reoffer_after_unheard_completion_needs_no_retransfer() -> TestResult {
    let fixture = fixture()?;
    let (mut link, transfer_id, _) = offered(&fixture, &big_specs(), 3600, (4, 4))?;
    link.b.accept(&transfer_id, vec![2, 4], link.now)?;
    run_until(&mut link, false, FrameType::COMPLETE)?;
    assert!(has(&link.b_events, |e| matches!(
        e,
        TransferEvent::Completed { .. }
    )));
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
    let view = again
        .b_events
        .iter()
        .find_map(|e| match e {
            TransferEvent::OfferReceived(view) => Some(view.clone()),
            _ => None,
        })
        .ok_or("offer")?;
    assert_eq!(view.resume_selection, Some(vec![2, 4]));
    assert_eq!(
        again.b.accept(&transfer_id, vec![2], again.now),
        Err(EngineError::Selection)
    );
    again.b.accept(&transfer_id, vec![2, 4], again.now)?;
    again.settle()?;
    assert_eq!(again.delivered(false, FrameType::CHUNK_REQUEST), 0);
    assert!(has(&again.a_events, |e| matches!(
        e,
        TransferEvent::DeliveryConfirmed { .. }
    )));
    assert_eq!(
        again.b.sink().published(&transfer_id, 2),
        Some(content(16_384 * 12 + 77, 7).as_slice())
    );
    Ok(())
}

/// A device key store that signs everything except delivery receipts.
struct NoReceipts<'k>(&'k Keys);

impl KeyStore for NoReceipts<'_> {
    fn generate(&mut self, _role: KeyRole, _export: ExportPolicy) -> Result<KeyId, KeyStoreError> {
        Err(KeyStoreError::Capacity)
    }

    fn role(&self, key: &KeyId) -> Result<KeyRole, KeyStoreError> {
        self.0.role(key)
    }

    fn public_key(&self, key: &KeyId) -> Result<Ed25519PublicKey, KeyStoreError> {
        self.0.public_key(key)
    }

    fn sign(
        &self,
        key: &KeyId,
        domain: SigningDomain,
        message: &[u8],
    ) -> Result<Signature, KeyStoreError> {
        if domain == SigningDomain::DeliveryReceipt {
            return Err(KeyStoreError::Seal);
        }
        self.0.sign(key, domain, message)
    }

    fn export_wrapped(
        &self,
        key: &KeyId,
        wrapping_key: &WrappingKey,
    ) -> Result<WrappedKey, KeyStoreError> {
        self.0.export_wrapped(key, wrapping_key)
    }

    fn delete(&mut self, _key: &KeyId) -> Result<(), KeyStoreError> {
        Err(KeyStoreError::UnknownKey)
    }
}

/// The receiver cannot sign its receipt once every file is published: the
/// sender must hear at once, by a transfer-scoped `STORAGE` error, instead
/// of holding the masters until the Accept expires (§7.7, §12).
#[test]
fn a_receipt_that_cannot_be_signed_fails_the_transfer_on_both_sides() -> TestResult {
    let fixture = fixture()?;
    let mut source = MemorySource::new();
    let offer = build_offer(
        &fixture.alice.key(),
        &fixture.bob.key(),
        &standard_specs(),
        &mut source,
        3600,
    )?;
    let transfer_id = *offer.transfer_id();
    let clock = Clock::new(time(WALL)?, START);
    let mut alice = TransferEngine::new(
        fixture.first.0,
        &fixture.alice.keys,
        fixture.alice.signing_key,
        source,
        MemorySink::new(),
        config(16)?,
        clock,
        START,
    )?;
    let keys = NoReceipts(&fixture.bob.keys);
    let mut bob = TransferEngine::new(
        fixture.first.1,
        &keys,
        fixture.bob.signing_key,
        MemorySource::new(),
        MemorySink::new(),
        config(16)?,
        clock,
        START,
    )?;
    let (mut a_events, mut b_events, mut to_alice) = (Vec::new(), Vec::new(), Vec::new());
    let mut offer = Some(offer);
    let mut accepted = false;
    for _ in 0..10_000 {
        let mut moved = false;
        while let Some(frame) = alice.pop_frame() {
            moved = true;
            deliver_to(&mut bob, frame, START)?;
        }
        while let Some(frame) = bob.pop_frame() {
            moved = true;
            to_alice.push(raw(&frame).0);
            deliver_to(&mut alice, frame, START)?;
        }
        while let Some(event) = alice.pop_event() {
            a_events.push(event);
        }
        while let Some(event) = bob.pop_event() {
            b_events.push(event);
        }
        if let Some(offer) = offer.take_if(|_| alice.negotiated().is_some()) {
            alice.offer(offer, START)?;
            moved = true;
        }
        if !accepted && has(&b_events, |e| matches!(e, TransferEvent::OfferReceived(_))) {
            bob.accept(&transfer_id, vec![6], START)?;
            accepted = true;
            moved = true;
        }
        if !moved {
            break;
        }
    }
    assert!(accepted);
    assert!(bob.sink().published(&transfer_id, 6).is_some());
    assert!(has(&b_events, |e| matches!(e,
        TransferEvent::Failed { failure, .. } if failure.code == FailureCode::KeyStore && failure.by == Party::Local)));
    assert!(!has(&b_events, |e| matches!(
        e,
        TransferEvent::Completed { .. }
    )));
    // Neither Complete nor a receipt was sent; the sender heard STORAGE and
    // ended the transfer at once.
    assert!(!to_alice.contains(&FrameType::COMPLETE));
    assert!(!to_alice.contains(&FrameType::DELIVERY_RECEIPT));
    assert!(has(&a_events, |e| matches!(e,
        TransferEvent::Failed { transfer_id: t, failure, .. }
            if *t == transfer_id && failure.code == FailureCode::Storage && failure.by == Party::Peer)));
    assert_eq!(alice.next_deadline(START), core::time::Duration::MAX);
    assert!(!alice.is_closed() && !bob.is_closed());
    Ok(())
}
