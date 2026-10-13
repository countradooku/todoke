//! Local storage failures (§7.7, §12): `STORAGE` and `INTEGRITY` are
//! transfer-scoped codes, so a sink that cannot read retained data or
//! publish a file fails that transfer, tells the peer with a
//! transfer-scoped `Error`, sends no `Complete` or receipt, and leaves the
//! session running.

use core::time::Duration;

use todoke_crypto::consent::{CanonicalManifest, VerifiedAccept};
use todoke_crypto::content::VerifiedSegment;
use todoke_crypto::identity::{Ed25519PublicKey, KeyStore};
use todoke_proto::session::{ErrorCode, ErrorScope};
use todoke_proto::time::UnixTime;
use todoke_proto::transfer::TransferId;

use super::basic::standard_specs;
use super::support::*;
use crate::{
    Clock, FailureCode, MemorySink, MemorySource, OutgoingFrame, Party, ReceiveSink, Retained,
    SendSource, SinkError, SinkRefusal, TransferEngine, TransferEvent,
};

/// A [`MemorySink`] whose reads of retained segments fail (`reads`), or
/// whose publication fails with `publish`.
struct Failing {
    sink: MemorySink,
    reads: bool,
    publish: Option<SinkError>,
}

impl ReceiveSink for Failing {
    fn check_offer(&mut self, manifest: &CanonicalManifest) -> Result<(), SinkRefusal> {
        self.sink.check_offer(manifest)
    }

    fn is_tombstoned(&self, transfer_id: &TransferId, now: UnixTime) -> bool {
        self.sink.is_tombstoned(transfer_id, now)
    }

    fn tombstone(&mut self, transfer_id: &TransferId, until: UnixTime) {
        self.sink.tombstone(transfer_id, until);
    }

    fn tombstone_room(&mut self, now: UnixTime) -> bool {
        self.sink.tombstone_room(now)
    }

    fn retained(&self, transfer_id: &TransferId, now: UnixTime) -> Option<Retained> {
        self.sink.retained(transfer_id, now)
    }

    fn record_accept(
        &mut self,
        manifest: &CanonicalManifest,
        accept: &VerifiedAccept,
    ) -> Result<(), SinkError> {
        self.sink.record_accept(manifest, accept)
    }

    fn retained_segment(
        &mut self,
        transfer_id: &TransferId,
        file_id: u32,
        index: u32,
    ) -> Result<Option<Vec<u8>>, SinkError> {
        if self.reads {
            return Err(SinkError::Storage);
        }
        self.sink.retained_segment(transfer_id, file_id, index)
    }

    fn drop_segment(&mut self, transfer_id: &TransferId, file_id: u32, index: u32) {
        self.sink.drop_segment(transfer_id, file_id, index);
    }

    fn store_segment(
        &mut self,
        segment: &VerifiedSegment,
        ciphertext: &[u8],
    ) -> Result<(), SinkError> {
        self.sink.store_segment(segment, ciphertext)
    }

    fn publish(&mut self, manifest: &CanonicalManifest, file_id: u32) -> Result<(), SinkError> {
        if let Some(error) = self.publish {
            return Err(error);
        }
        self.sink.publish(manifest, file_id)
    }

    fn published_intact(&mut self, manifest: &CanonicalManifest, file_id: u32) -> bool {
        self.sink.published_intact(manifest, file_id)
    }

    fn finish(&mut self, transfer_id: &TransferId) {
        self.sink.finish(transfer_id);
    }

    fn revoke_sender(&mut self, sender: &Ed25519PublicKey, until: UnixTime) {
        self.sink.revoke_sender(sender, until);
    }
}

/// Moves every queued frame between the two engines until both are quiet,
/// as the session layer would. Returns the frames each side sent.
fn exchange<K, S1, R1, S2, R2>(
    a: &mut TransferEngine<'_, K, S1, R1>,
    b: &mut TransferEngine<'_, K, S2, R2>,
    now: Duration,
) -> (Vec<OutgoingFrame>, Vec<OutgoingFrame>)
where
    K: KeyStore,
    S1: SendSource,
    R1: ReceiveSink,
    S2: SendSource,
    R2: ReceiveSink,
{
    let (mut from_a, mut from_b) = (Vec::new(), Vec::new());
    for _ in 0..100_000 {
        let mut moved = false;
        while let Some(frame) = a.pop_frame() {
            moved = true;
            from_a.push(frame.clone());
            // A refusal closes the receiving engine; the test inspects
            // what each side sent and reported.
            let _ = deliver_to(b, frame, now);
        }
        while let Some(frame) = b.pop_frame() {
            moved = true;
            from_b.push(frame.clone());
            let _ = deliver_to(a, frame, now);
        }
        if !moved {
            break;
        }
    }
    (from_a, from_b)
}

fn events<K: KeyStore, S: SendSource, R: ReceiveSink>(
    engine: &mut TransferEngine<'_, K, S, R>,
) -> Vec<TransferEvent> {
    core::iter::from_fn(|| engine.pop_event()).collect()
}

/// Runs a transfer of file 2 of the standard offer into `sink` until both
/// engines are quiet. Returns the receiver's `Error` frames, both sides'
/// events, the frame types the receiver sent, and whether either engine
/// closed.
#[expect(
    clippy::type_complexity,
    reason = "one tuple of everything the tests inspect"
)]
fn run_into(
    sink: Failing,
) -> AnyResult<(
    TransferId,
    Vec<(ErrorScope, ErrorCode)>,
    Vec<TransferEvent>,
    Vec<TransferEvent>,
    Vec<todoke_proto::session::FrameType>,
    bool,
    usize,
)> {
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
    let mut bob = TransferEngine::new(
        fixture.first.1,
        &fixture.bob.keys,
        fixture.bob.signing_key,
        MemorySource::new(),
        sink,
        config(16)?,
        clock,
        START,
    )?;
    exchange(&mut alice, &mut bob, START);
    alice.offer(offer, START)?;
    exchange(&mut alice, &mut bob, START);
    bob.accept(&transfer_id, vec![2], START)?;
    let (_, from_bob) = exchange(&mut alice, &mut bob, START);
    let errors = from_bob
        .iter()
        .filter_map(|frame| match frame {
            OutgoingFrame::Error(record) => Some((record.scope(), record.code())),
            OutgoingFrame::Frame { .. } => None,
        })
        .collect();
    let kinds = from_bob.iter().map(|frame| raw(frame).0).collect();
    let closed = alice.is_closed() || bob.is_closed();
    let stored = bob.sink().sink.stored_segments(&transfer_id);
    Ok((
        transfer_id,
        errors,
        events(&mut bob),
        events(&mut alice),
        kinds,
        closed,
        stored,
    ))
}

fn failed(
    events: &[TransferEvent],
    transfer_id: &TransferId,
    code: FailureCode,
    by: Party,
) -> bool {
    events.iter().any(|e| {
        matches!(e, TransferEvent::Failed { transfer_id: t, failure, .. }
            if t == transfer_id && failure.code == code && failure.by == by)
    })
}

#[test]
fn a_failed_read_of_retained_data_fails_only_that_transfer() -> TestResult {
    let (transfer_id, errors, bob_events, alice_events, _, closed, stored) = run_into(Failing {
        sink: MemorySink::new(),
        reads: true,
        publish: None,
    })?;
    assert_eq!(
        errors,
        vec![(ErrorScope::Transfer(transfer_id), ErrorCode::STORAGE)]
    );
    assert!(!closed);
    assert!(failed(
        &bob_events,
        &transfer_id,
        FailureCode::Storage,
        Party::Local
    ));
    assert!(failed(
        &alice_events,
        &transfer_id,
        FailureCode::Storage,
        Party::Peer
    ));
    assert_eq!(stored, 0);
    Ok(())
}

/// §7.7: a file that fails its whole-file check or cannot be published
/// fails the transfer with `INTEGRITY` or `STORAGE`; no `Complete` and no
/// receipt are sent, and the sender never confirms delivery.
#[test]
fn a_failed_publication_sends_no_complete_or_receipt() -> TestResult {
    for (error, code, wire) in [
        (
            SinkError::Integrity,
            FailureCode::Integrity,
            ErrorCode::INTEGRITY,
        ),
        (SinkError::Storage, FailureCode::Storage, ErrorCode::STORAGE),
    ] {
        let (transfer_id, errors, bob_events, alice_events, kinds, closed, _) =
            run_into(Failing {
                sink: MemorySink::new(),
                reads: false,
                publish: Some(error),
            })?;
        assert_eq!(errors, vec![(ErrorScope::Transfer(transfer_id), wire)]);
        assert!(!closed);
        assert!(!kinds.contains(&todoke_proto::session::FrameType::COMPLETE));
        assert!(!kinds.contains(&todoke_proto::session::FrameType::DELIVERY_RECEIPT));
        assert!(failed(&bob_events, &transfer_id, code, Party::Local));
        assert!(failed(&alice_events, &transfer_id, code, Party::Peer));
        assert!(!alice_events.iter().any(|e| matches!(
            e,
            TransferEvent::DeliveryConfirmed { .. } | TransferEvent::DeliveryUnconfirmed { .. }
        )));
        assert!(!bob_events.iter().any(|e| matches!(
            e,
            TransferEvent::Completed { .. } | TransferEvent::FileCompleted { .. }
        )));
    }
    Ok(())
}
