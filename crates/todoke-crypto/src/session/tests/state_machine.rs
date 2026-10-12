//! Proptest state machine over a full contact session: an adversary
//! controls the wire (ordering, replay, truncation, corruption, injection),
//! either process may crash, and time may jump past deadlines.
//!
//! Invariants checked after every run, on the state a restart would load:
//!
//! * never two usable pairings that disagree on generation or PSK;
//! * a side that opened its gate is committed at the next generation;
//! * any interrupted journal blocks the pairing (`RatchetUncertain`), and
//!   no journal survives a restart;
//! * a side that failed before journaling keeps the old pairing;
//! * if both sides opened, they agree on the handshake hash;
//! * an untouched run always completes on both sides.

use core::time::Duration;

use proptest::prelude::*;

use super::establishment::check_policy_stores;
use super::support::*;
use crate::identity::{MemoryStorage, SoftwareSealer};
use crate::session::ContactAuthority;
use crate::session::SessionMode;
use crate::session::establish::Phase;
use crate::session::kdf;

const GENERATION: u64 = 11;
const LOCATOR: [u8; 16] = [0x5e; 16];

#[derive(Clone, Debug)]
enum Op {
    /// Deliver the next record toward the responder (`true`) or initiator.
    Deliver(bool),
    /// Lose the next record.
    Drop(bool),
    /// Deliver the next record twice.
    Replay(bool),
    /// Deliver only a prefix of the next record; the stream desynchronizes.
    Truncate(bool, u16),
    /// Flip one bit of the next record.
    Flip(bool, u16, u8),
    /// Swap the next two records.
    Swap(bool),
    /// Inject arbitrary bytes into the stream.
    Inject(bool, Vec<u8>),
    /// The responder's deferred "Ack queued" step.
    ConfirmAck,
    CrashInitiator,
    CrashResponder,
    /// Advance the monotonic clock by this many seconds.
    Advance(u8),
}

impl Op {
    fn is_adversarial(&self) -> bool {
        !matches!(self, Self::Deliver(_) | Self::ConfirmAck | Self::Advance(0))
    }
}

fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        8 => any::<bool>().prop_map(Op::Deliver),
        2 => Just(Op::ConfirmAck),
        1 => any::<bool>().prop_map(Op::Drop),
        1 => any::<bool>().prop_map(Op::Replay),
        1 => (any::<bool>(), any::<u16>()).prop_map(|(d, n)| Op::Truncate(d, n)),
        1 => (any::<bool>(), any::<u16>(), 0..8u8).prop_map(|(d, p, b)| Op::Flip(d, p, b)),
        1 => any::<bool>().prop_map(Op::Swap),
        1 => (any::<bool>(), proptest::collection::vec(any::<u8>(), 0..80)).prop_map(|(d, v)| Op::Inject(d, v)),
        1 => Just(Op::CrashInitiator),
        1 => Just(Op::CrashResponder),
        1 => (0..15u8).prop_map(Op::Advance),
    ]
}

type ContactAuth<'a> = ContactAuthority<'a, SoftwareSealer, MemoryStorage>;

fn apply(harness: &mut Harness<'_, ContactAuth<'_>, ContactAuth<'_>>, op: &Op) {
    match op {
        Op::Deliver(direction) => {
            harness.deliver(*direction);
        }
        Op::Drop(direction) => {
            harness.queue(*direction).pop_front();
        }
        Op::Replay(direction) => {
            if let Some(record) = harness.queue(*direction).pop_front() {
                harness.deliver_bytes(*direction, &record);
                harness.deliver_bytes(*direction, &record);
            }
        }
        Op::Truncate(direction, cut) => {
            if let Some(record) = harness.queue(*direction).pop_front() {
                let keep = usize::from(*cut) % record.len().max(1);
                harness.deliver_bytes(*direction, &record[..keep]);
            }
        }
        Op::Flip(direction, position, bit) => {
            if let Some(mut record) = harness.queue(*direction).pop_front() {
                if !record.is_empty() {
                    let index = usize::from(*position) % record.len();
                    record[index] ^= 1 << bit;
                }
                harness.deliver_bytes(*direction, &record);
            }
        }
        Op::Swap(direction) => {
            let queue = harness.queue(*direction);
            if queue.len() >= 2 {
                queue.swap(0, 1);
            }
        }
        Op::Inject(direction, bytes) => harness.deliver_bytes(*direction, bytes),
        Op::ConfirmAck => {
            let now = harness.now;
            harness.responder.confirm_ack(now);
        }
        Op::CrashInitiator => harness.initiator.crash(),
        Op::CrashResponder => harness.responder.crash(),
        Op::Advance(seconds) => harness.now += Duration::from_secs(u64::from(*seconds)),
    }
}

fn run(ops: &[Op]) -> Result<(), TestCaseError> {
    let fail = |error: Box<dyn std::error::Error>| TestCaseError::fail(error.to_string());
    let alice = Device::new().map_err(fail)?;
    let bob = Device::new().map_err(fail)?;
    let mut alice_store = store_pairing(&bob, GENERATION).map_err(fail)?;
    let mut bob_store = store_pairing(&alice, GENERATION).map_err(fail)?;
    let (alice_key, bob_key) = (alice.key(), bob.key());
    let honest = !ops.iter().any(Op::is_adversarial);
    let (alice_open, bob_open) = {
        let alice_local = alice.local().map_err(fail)?;
        let bob_local = bob.local().map_err(fail)?;
        let initiator_authority = alice_store
            .session_authority(&bob_key)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let plan = initiator_authority
            .initiator_plan(LOCATOR)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let responder_authority = bob_store
            .session_authority(&alice_key)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let hello = todoke_proto::session::Hello::client(
            SessionMode::Contact,
            GENERATION,
            LOCATOR,
            [1; 16],
        )
        .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let responder_plan = responder_authority
            .responder_plan(&hello)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let mut responder = Side::responder(bob_local, responder_authority, responder_plan);
        responder.defer_ack = true;
        let mut harness = Harness::new(
            Side::initiator(alice_local, initiator_authority),
            responder,
            plan,
        )
        .map_err(fail)?;
        for op in ops {
            apply(&mut harness, op);
        }
        // Whatever remains is delivered honestly, then deadlines fire.
        harness.drain();
        let now = harness.now;
        harness.responder.confirm_ack(now);
        harness.drain();
        harness.finish();
        for side_phase in [&harness.initiator.stage, &harness.responder.stage] {
            if let Stage::Establish(establishment) = side_phase {
                prop_assert_ne!(establishment.phase(), Phase::Open);
            }
        }
        let alice_hash = harness
            .initiator
            .core()
            .map(|core| core.info().handshake_hash);
        let bob_hash = harness
            .responder
            .core()
            .map(|core| core.info().handshake_hash);
        if let (Some(a), Some(b)) = (alice_hash, bob_hash) {
            prop_assert_eq!(a, b);
        }
        if honest {
            prop_assert!(
                alice_hash.is_some() && bob_hash.is_some(),
                "honest run did not complete"
            );
        }
        (alice_hash, bob_hash)
    };
    check_policy_stores(
        GENERATION,
        &alice_store,
        &bob_store,
        &alice_key,
        &bob_key,
        alice_open.is_some(),
        bob_open.is_some(),
        &format!("{ops:?}"),
    )
    .map_err(fail)?;
    // An opened side holds exactly HKDF(h, old PSK) at the next generation.
    for (hash, store, peer) in [
        (alice_open, &alice_store, &bob_key),
        (bob_open, &bob_store, &alice_key),
    ] {
        if let Some(hash) = hash {
            let next = kdf::psk_next(&hash, &OLD_PSK).map_err(|_| TestCaseError::fail("kdf"))?;
            prop_assert_eq!(
                usable(store, peer).map_err(fail)?,
                Some((GENERATION + 1, *next))
            );
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn adversarial_wire_and_crashes_preserve_the_ratchet_policy(
        ops in proptest::collection::vec(arb_op(), 0..40),
    ) {
        run(&ops)?;
    }
}

#[test]
fn honest_operation_sequences_complete() -> TestResult {
    // The model's honest baseline, including a deferred Ack confirmation
    // and no clock movement.
    run(&[]).map_err(|error| error.to_string())?;
    run(&[
        Op::Deliver(true),
        Op::Deliver(false),
        Op::ConfirmAck,
        Op::Advance(0),
    ])
    .map_err(|error| error.to_string())?;
    Ok(())
}
