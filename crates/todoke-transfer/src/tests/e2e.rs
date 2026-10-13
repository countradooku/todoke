//! End-to-end transfers over the real P04 session layer: QR pairing and
//! contact sessions (hybrid Noise, identity, ratchet) over an in-memory
//! byte pipe, with both engines driven by [`crate::pump`].

use core::time::Duration;

use todoke_proto::transfer::CancelReason;

use super::basic::standard_specs;
use super::support::*;
use crate::{
    Clock, DriveError, MemorySink, MemorySource, OutgoingOffer, TransferEngine, TransferEvent, pump,
};

type Side = todoke_crypto::session::Session<End, ManualTimer>;

/// What the receiver's user does.
#[derive(Clone, Copy)]
enum Receiver<'s> {
    /// Accept this selection and wait for completion.
    Accept(&'s [u32]),
    /// Accept, then cancel at the first progress event.
    AcceptThenCancel(&'s [u32]),
    /// Accept, then disconnect once this many segments are stored.
    AcceptThenDisconnect(&'s [u32], usize),
}

fn engine<'k>(
    session: &Side,
    device: &'k Device,
    source: MemorySource,
    sink: MemorySink,
) -> AnyResult<Engine<'k>> {
    let now = session.now();
    Ok(TransferEngine::new(
        session.transfer_binding(),
        &device.keys,
        device.signing_key,
        source,
        sink,
        config(16)?,
        Clock::new(time(WALL)?, now),
        now,
    )?)
}

/// Alice: offers once Capabilities are exchanged; stops at the first
/// terminal event or when the session ends.
async fn run_sender(
    mut session: Side,
    mut engine: Engine<'_>,
    offer: OutgoingOffer,
) -> (Vec<TransferEvent>, Engine<'_>, Option<DriveError>) {
    let mut offer = Some(offer);
    let mut events = Vec::new();
    loop {
        let until = session.now() + Duration::from_secs(3600);
        let pumped = pump(&mut session, &mut engine, until).await;
        let mut done = false;
        while let Some(event) = engine.pop_event() {
            match &event {
                TransferEvent::Ready { .. } => {
                    if let Some(offer) = offer.take()
                        && engine.offer(offer, session.now()).is_err()
                    {
                        done = true;
                    }
                }
                TransferEvent::DeliveryConfirmed { .. }
                | TransferEvent::DeliveryUnconfirmed { .. }
                | TransferEvent::Cancelled { .. }
                | TransferEvent::Rejected { .. }
                | TransferEvent::Failed { .. }
                | TransferEvent::Interrupted { .. } => done = true,
                _ => {}
            }
            events.push(event);
        }
        if let Err(error) = pumped {
            return (events, engine, Some(error));
        }
        if done {
            let now = session.now();
            let _ = pump(&mut session, &mut engine, now).await;
            return (events, engine, None);
        }
    }
}

/// Bob: acts as `policy` says.
async fn run_receiver<'k>(
    mut session: Side,
    mut engine: Engine<'k>,
    policy: Receiver<'_>,
) -> (Vec<TransferEvent>, Engine<'k>, Option<DriveError>) {
    let mut events = Vec::new();
    loop {
        let until = session.now() + Duration::from_secs(3600);
        let pumped = pump(&mut session, &mut engine, until).await;
        let mut done = false;
        let mut disconnect = false;
        while let Some(event) = engine.pop_event() {
            match (&event, policy) {
                (
                    TransferEvent::OfferReceived(view),
                    Receiver::Accept(selection)
                    | Receiver::AcceptThenCancel(selection)
                    | Receiver::AcceptThenDisconnect(selection, _),
                ) => {
                    if engine
                        .accept(&view.transfer_id, selection.to_vec(), session.now())
                        .is_err()
                    {
                        done = true;
                    }
                }
                (TransferEvent::Progress(progress), Receiver::AcceptThenCancel(_)) => {
                    let _ = engine.cancel(&progress.transfer_id, CancelReason::User, session.now());
                }
                // After a local cancel, wait for the peer to acknowledge and
                // close (the session's end ends the loop).
                (
                    TransferEvent::Cancelled {
                        by: crate::Party::Local,
                        ..
                    },
                    _,
                ) => {}
                (
                    TransferEvent::Completed { .. }
                    | TransferEvent::Cancelled { .. }
                    | TransferEvent::Rejected { .. }
                    | TransferEvent::Failed { .. }
                    | TransferEvent::Interrupted { .. },
                    _,
                ) => done = true,
                _ => {}
            }
            events.push(event);
        }
        if let Receiver::AcceptThenDisconnect(_, segments) = policy
            && engine.sink().stored_count() >= segments
        {
            disconnect = true;
        }
        if disconnect {
            // The pipe drops without a goodbye: a lost connection.
            drop(session);
            engine.close(None);
            while let Some(event) = engine.pop_event() {
                events.push(event);
            }
            return (events, engine, None);
        }
        if let Err(error) = pumped {
            return (events, engine, Some(error));
        }
        if done {
            let now = session.now();
            let _ = pump(&mut session, &mut engine, now).await;
            return (events, engine, None);
        }
    }
}

#[test]
fn multi_file_transfer_with_folders_empty_file_and_receipt() -> TestResult {
    let timer = ManualTimer::at(START);
    let (pair, (alice_session, bob_session)) = Pair::new(&timer)?;
    let mut source = MemorySource::new();
    let offer = build_offer(
        &pair.alice.key(),
        &pair.bob.key(),
        &standard_specs(),
        &mut source,
        3600,
    )?;
    let transfer_id = *offer.transfer_id();
    let alice = engine(&alice_session, &pair.alice, source, MemorySink::new())?;
    let bob = engine(
        &bob_session,
        &pair.bob,
        MemorySource::new(),
        MemorySink::new(),
    )?;
    let selection = [2, 3, 5];
    let ((alice_events, _, alice_error), (bob_events, bob, bob_error)) = join(
        run_sender(alice_session, alice, offer),
        run_receiver(bob_session, bob, Receiver::Accept(&selection)),
    )?;
    assert_eq!(alice_error, None);
    assert_eq!(bob_error, None);
    assert!(alice_events.iter().any(|e| matches!(e, TransferEvent::DeliveryConfirmed { transfer_id: t, .. } if *t == transfer_id)));
    assert!(
        bob_events
            .iter()
            .any(|e| matches!(e, TransferEvent::Completed { .. }))
    );
    let sink = bob.sink();
    assert_eq!(
        sink.published(&transfer_id, 2),
        Some(content(40_000, 1).as_slice())
    );
    assert_eq!(sink.published(&transfer_id, 3), Some(&[][..]));
    assert_eq!(
        sink.published(&transfer_id, 5),
        Some(content(16_384 * 3 + 5, 3).as_slice())
    );
    assert!(sink.published(&transfer_id, 6).is_none());
    assert_eq!(sink.published_count(), 3);
    Ok(())
}

#[test]
fn cancel_mid_transfer_over_a_session() -> TestResult {
    let timer = ManualTimer::at(START);
    let (pair, (alice_session, bob_session)) = Pair::new(&timer)?;
    let mut source = MemorySource::new();
    let specs = vec![file("big", 0, 16_384 * 20, 5)];
    let offer = build_offer(
        &pair.alice.key(),
        &pair.bob.key(),
        &specs,
        &mut source,
        3600,
    )?;
    let transfer_id = *offer.transfer_id();
    let alice = engine(&alice_session, &pair.alice, source, MemorySink::new())?;
    let bob = engine(
        &bob_session,
        &pair.bob,
        MemorySource::new(),
        MemorySink::new(),
    )?;
    let ((alice_events, mut alice, _), (bob_events, bob, _)) = join(
        run_sender(alice_session, alice, offer),
        run_receiver(bob_session, bob, Receiver::AcceptThenCancel(&[1])),
    )?;
    assert!(alice_events.iter().any(|e| matches!(
        e,
        TransferEvent::Cancelled {
            by: crate::Party::Peer,
            ..
        }
    )));
    assert!(bob_events.iter().any(|e| matches!(
        e,
        TransferEvent::Cancelled {
            by: crate::Party::Local,
            ..
        }
    )));
    assert!(bob.sink().published(&transfer_id, 1).is_none());
    assert_eq!(bob.sink().stored_segments(&transfer_id), 0);
    assert!(alice.take_resumable().is_empty());
    Ok(())
}

#[test]
fn resume_in_a_fresh_session_after_a_lost_connection() -> TestResult {
    let timer = ManualTimer::at(START);
    let (mut pair, (alice_session, bob_session)) = Pair::new(&timer)?;
    let mut source = MemorySource::new();
    let specs = vec![
        dir("album", 0),
        file("one", 1, 16_384 * 10 + 3, 6),
        file("two", 1, 5000, 7),
        file("zero", 0, 0, 8),
    ];
    let offer = build_offer(
        &pair.alice.key(),
        &pair.bob.key(),
        &specs,
        &mut source,
        3600,
    )?;
    let transfer_id = *offer.transfer_id();
    let selection = [2, 3, 4];
    // Session 1 (the QR pairing session): the connection drops midway.
    let alice = engine(&alice_session, &pair.alice, source, MemorySink::new())?;
    let bob = engine(
        &bob_session,
        &pair.bob,
        MemorySource::new(),
        MemorySink::new(),
    )?;
    let ((alice_events, mut alice, alice_error), (bob_events, bob, _)) = join(
        run_sender(alice_session, alice, offer),
        run_receiver(
            bob_session,
            bob,
            Receiver::AcceptThenDisconnect(&selection, 4),
        ),
    )?;
    assert!(alice_error.is_some());
    assert!(
        alice_events
            .iter()
            .any(|e| matches!(e, TransferEvent::Interrupted { .. }))
    );
    assert!(
        bob_events
            .iter()
            .any(|e| matches!(e, TransferEvent::Interrupted { .. }))
    );
    let offer = alice.take_resumable().pop().ok_or("resumable offer")?;
    let (source, _) = alice.into_parts();
    let (_, sink) = bob.into_parts();
    let retained = sink.stored_segments(&transfer_id);
    assert!(retained > 0);
    // Session 2 (a contact session after the ratchet): fresh Accept, then
    // only the missing segments.
    let (alice_session, bob_session) = pair.contact_session(&timer)?;
    let alice = engine(&alice_session, &pair.alice, source, MemorySink::new())?;
    let bob = engine(&bob_session, &pair.bob, MemorySource::new(), sink)?;
    let ((alice_events, _, alice_error), (bob_events, bob, bob_error)) = join(
        run_sender(alice_session, alice, offer),
        run_receiver(bob_session, bob, Receiver::Accept(&selection)),
    )?;
    assert_eq!((alice_error, bob_error), (None, None));
    let view = bob_events
        .iter()
        .find_map(|e| match e {
            TransferEvent::OfferReceived(view) => Some(view.clone()),
            _ => None,
        })
        .ok_or("offer")?;
    assert_eq!(view.resume_selection.as_deref(), Some(&selection[..]));
    assert!(
        alice_events
            .iter()
            .any(|e| matches!(e, TransferEvent::DeliveryConfirmed { .. }))
    );
    assert_eq!(
        bob.sink().published(&transfer_id, 2),
        Some(content(16_384 * 10 + 3, 6).as_slice())
    );
    assert_eq!(
        bob.sink().published(&transfer_id, 3),
        Some(content(5000, 7).as_slice())
    );
    assert_eq!(bob.sink().published(&transfer_id, 4), Some(&[][..]));
    drop(pair);
    Ok(())
}
