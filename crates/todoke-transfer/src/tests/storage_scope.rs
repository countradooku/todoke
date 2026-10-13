//! §12 scope of a local storage failure: `STORAGE` is a transfer-scoped
//! code, so a sink that cannot read retained data fails that transfer,
//! tells the peer with a transfer-scoped `Error`, and leaves the session
//! (and any other transfer) running.

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

/// A [`MemorySink`] whose reads of retained segments fail.
struct FailingReads(MemorySink);

impl ReceiveSink for FailingReads {
    fn check_offer(&mut self, manifest: &CanonicalManifest) -> Result<(), SinkRefusal> {
        self.0.check_offer(manifest)
    }

    fn is_tombstoned(&self, transfer_id: &TransferId, now: UnixTime) -> bool {
        self.0.is_tombstoned(transfer_id, now)
    }

    fn tombstone(&mut self, transfer_id: &TransferId, until: UnixTime) {
        self.0.tombstone(transfer_id, until);
    }

    fn tombstone_room(&mut self, now: UnixTime) -> bool {
        self.0.tombstone_room(now)
    }

    fn retained(&self, transfer_id: &TransferId, now: UnixTime) -> Option<Retained> {
        self.0.retained(transfer_id, now)
    }

    fn record_accept(
        &mut self,
        manifest: &CanonicalManifest,
        accept: &VerifiedAccept,
    ) -> Result<(), SinkError> {
        self.0.record_accept(manifest, accept)
    }

    fn retained_segment(
        &mut self,
        _transfer_id: &TransferId,
        _file_id: u32,
        _index: u32,
    ) -> Result<Option<Vec<u8>>, SinkError> {
        Err(SinkError::Storage)
    }

    fn drop_segment(&mut self, transfer_id: &TransferId, file_id: u32, index: u32) {
        self.0.drop_segment(transfer_id, file_id, index);
    }

    fn store_segment(
        &mut self,
        segment: &VerifiedSegment,
        ciphertext: &[u8],
    ) -> Result<(), SinkError> {
        self.0.store_segment(segment, ciphertext)
    }

    fn publish(&mut self, manifest: &CanonicalManifest, file_id: u32) -> Result<(), SinkError> {
        self.0.publish(manifest, file_id)
    }

    fn published_intact(&mut self, manifest: &CanonicalManifest, file_id: u32) -> bool {
        self.0.published_intact(manifest, file_id)
    }

    fn finish(&mut self, transfer_id: &TransferId) {
        self.0.finish(transfer_id);
    }

    fn revoke_sender(&mut self, sender: &Ed25519PublicKey, until: UnixTime) {
        self.0.revoke_sender(sender, until);
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

#[test]
fn a_failed_read_of_retained_data_fails_only_that_transfer() -> TestResult {
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
        FailingReads(MemorySink::new()),
        config(16)?,
        clock,
        START,
    )?;
    exchange(&mut alice, &mut bob, START);
    alice.offer(offer, START)?;
    exchange(&mut alice, &mut bob, START);
    bob.accept(&transfer_id, vec![2], START)?;
    // Bob's Accept, Alice's FileKey: scheduling the first request reads
    // the sink for retained data, which fails.
    let (_, from_bob) = exchange(&mut alice, &mut bob, START);
    let errors: Vec<_> = from_bob
        .iter()
        .filter_map(|frame| match frame {
            OutgoingFrame::Error(record) => Some((record.scope(), record.code())),
            OutgoingFrame::Frame { .. } => None,
        })
        .collect();
    assert_eq!(
        errors,
        vec![(ErrorScope::Transfer(transfer_id), ErrorCode::STORAGE)]
    );
    assert!(!bob.is_closed());
    assert!(!alice.is_closed());
    assert!(events(&mut bob).iter().any(|e| matches!(e,
        TransferEvent::Failed { transfer_id: t, failure, .. }
            if *t == transfer_id && failure.code == FailureCode::Storage && failure.by == Party::Local)));
    assert!(events(&mut alice).iter().any(|e| matches!(e,
        TransferEvent::Failed { transfer_id: t, failure, .. }
            if *t == transfer_id && failure.code == FailureCode::Storage && failure.by == Party::Peer)));
    assert_eq!(bob.sink().0.stored_segments(&transfer_id), 0);
    Ok(())
}
