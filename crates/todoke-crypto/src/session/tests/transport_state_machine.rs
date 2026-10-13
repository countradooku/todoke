//! Proptest state machine over an established session (§5, §11 "Ratchet
//! committed"/"Ready", §12, §13): both endpoints' `SessionCore`s after the
//! ratchet gate, an adversary on the wire, and a clock that jumps.
//!
//! Checked after every step:
//!
//! * each side has received exactly a prefix of the application frames the
//!   other sent, in order and intact: nothing is lost, duplicated,
//!   reordered, or altered without the session closing;
//! * a modified, truncated, injected, or replayed record is never accepted;
//! * a side that returned an error is closed and returns nothing more;
//! * without an adversary, no side fails with an authentication, malformed,
//!   state, or unsupported error: only deadlines, local quotas, and the
//!   peer's `Error` close an honest session;
//! * key epochs never decrease.
//!
//! At the end of an honest run the wire is drained: if both sides are still
//! open, every frame arrived and both directions agree on their key epoch.

use core::time::Duration;
use std::collections::VecDeque;

use proptest::prelude::*;

use super::support::AnyResult;
use crate::identity::test_support::Enrolled;
use crate::session::engine::{Entropy, HandshakeInputs, NoiseHandshake, Pattern};
use crate::session::transport::{FrameTransport, Limits, SessionCore, SessionInfo};
use crate::session::{
    ErrorCode, ErrorRecord, ErrorScope, FrameType, MAX_SESSION_DURATION, NoiseStaticKey, Role,
    SessionError, SessionMode,
};

const START: Duration = Duration::from_secs(1_000);
/// A few large frames exhaust it and force byte-budget `KeyUpdate`s, while
/// it still exceeds one maximum ciphertext, so the received-update rate
/// limit applies to the other updates.
const LIMITS: Limits = Limits {
    byte_budget: 200_000,
};
const APPLICATION: [FrameType; 3] = [
    FrameType::CAPABILITIES,
    FrameType::new(0x0015),
    FrameType::REVOKE,
];
const BODY_LENS: [usize; 4] = [0, 1, 300, 40_000];
const TRANSFER_ID: [u8; 16] = [0x7d; 16];

/// `true` is the initiator `a` acting, or the direction from `a` to `b`.
#[derive(Clone, Debug)]
enum Op {
    Send(bool, u8, u8),
    /// A transfer-scoped `Error`: an ordinary frame for the peer.
    SendTransferError(bool),
    /// A session-scoped `Error`: closes both sides.
    SendSessionError(bool),
    Rekey(bool),
    /// Run the timers: keepalive, time-based rekey, deadlines.
    Poll(bool),
    Deliver(bool),
    Advance(u8),
    Drop(bool),
    Replay(bool),
    Flip(bool, u16, u8),
    Truncate(bool, u16),
    Swap(bool),
    Inject(bool, Vec<u8>),
}

impl Op {
    fn is_adversarial(&self) -> bool {
        matches!(
            self,
            Self::Drop(_)
                | Self::Replay(_)
                | Self::Flip(..)
                | Self::Truncate(..)
                | Self::Swap(_)
                | Self::Inject(..)
        )
    }
}

fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        6 => (any::<bool>(), 0..3u8, 0..4u8).prop_map(|(d, t, l)| Op::Send(d, t, l)),
        1 => any::<bool>().prop_map(Op::SendTransferError),
        1 => any::<bool>().prop_map(Op::SendSessionError),
        2 => any::<bool>().prop_map(Op::Rekey),
        3 => any::<bool>().prop_map(Op::Poll),
        8 => any::<bool>().prop_map(Op::Deliver),
        3 => (0..45u8).prop_map(Op::Advance),
        1 => any::<bool>().prop_map(Op::Drop),
        1 => any::<bool>().prop_map(Op::Replay),
        1 => (any::<bool>(), any::<u16>(), 0..8u8).prop_map(|(d, p, b)| Op::Flip(d, p, b)),
        1 => (any::<bool>(), any::<u16>()).prop_map(|(d, n)| Op::Truncate(d, n)),
        1 => any::<bool>().prop_map(Op::Swap),
        1 => (any::<bool>(), proptest::collection::vec(any::<u8>(), 0..80))
            .prop_map(|(d, v)| Op::Inject(d, v)),
    ]
}

/// One endpoint and what it observed.
struct Endpoint {
    core: SessionCore,
    /// Application frames this side queued, in order.
    sent: Vec<(FrameType, Vec<u8>)>,
    /// Frames this side's `receive` returned, in order.
    received: Vec<(FrameType, Vec<u8>)>,
    /// The first error that closed this side.
    error: Option<SessionError>,
    epochs: (u64, u64),
}

impl Endpoint {
    fn new(core: SessionCore) -> Self {
        Self {
            core,
            sent: Vec::new(),
            received: Vec::new(),
            error: None,
            epochs: (0, 0),
        }
    }

    /// Records the outcome of a call that closes the session on error.
    fn outcome<T>(&mut self, result: Result<T, SessionError>) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            // Local refusals that leave the session open.
            Err(SessionError::RekeyTooSoon) => None,
            Err(error) => {
                self.error.get_or_insert(error);
                None
            }
        }
    }
}

struct Wire {
    a: Endpoint,
    b: Endpoint,
    /// Records in flight toward `b` (`to_b`) and toward `a`.
    to_b: VecDeque<Vec<u8>>,
    to_a: VecDeque<Vec<u8>>,
    now: Duration,
}

fn established() -> AnyResult<Wire> {
    let a = NoiseStaticKey::generate()?;
    let b = NoiseStaticKey::generate()?;
    let inputs = |initiator: bool| HandshakeInputs {
        pattern: Pattern::KkPsk2,
        initiator,
        prologue: b"transport state machine",
        psk: &[0x42; 32],
        local_static: if initiator { a.secret() } else { b.secret() },
        remote_static: Some(if initiator {
            b.public_key()
        } else {
            a.public_key()
        }),
        entropy: Entropy::Os,
    };
    let mut initiator = NoiseHandshake::new(&inputs(true))?;
    let mut responder = NoiseHandshake::new(&inputs(false))?;
    responder.read_message(&initiator.write_message()?)?;
    initiator.read_message(&responder.write_message()?)?;
    let enrolled = Enrolled::new()?;
    let info = |role| -> AnyResult<SessionInfo> {
        Ok(SessionInfo {
            role,
            mode: SessionMode::Contact,
            handshake_hash: [1; 32],
            session_id: [2; 32],
            peer_static: [3; 32],
            peer_binding: enrolled.bind(1)?,
            local_device: *enrolled.bind(2)?.device_public(),
            established_at: crate::identity::test_support::time(crate::identity::test_support::T0)?,
        })
    };
    let core = |noise, role| -> AnyResult<SessionCore> {
        Ok(SessionCore::new(
            FrameTransport::new(noise, START, LIMITS),
            info(role)?,
            Entropy::Os,
            START,
            MAX_SESSION_DURATION,
        ))
    };
    Ok(Wire {
        a: Endpoint::new(core(initiator.into_transport()?, Role::Initiator)?),
        b: Endpoint::new(core(responder.into_transport()?, Role::Responder)?),
        to_b: VecDeque::new(),
        to_a: VecDeque::new(),
        now: START,
    })
}

impl Wire {
    /// The acting endpoint and the queue its records go to.
    fn sender(&mut self, from_a: bool) -> (&mut Endpoint, &mut VecDeque<Vec<u8>>) {
        if from_a {
            (&mut self.a, &mut self.to_b)
        } else {
            (&mut self.b, &mut self.to_a)
        }
    }

    fn queue(&mut self, toward_b: bool) -> &mut VecDeque<Vec<u8>> {
        if toward_b {
            &mut self.to_b
        } else {
            &mut self.to_a
        }
    }

    /// Moves every queued record onto the wire.
    fn flush(&mut self) {
        while let Some(record) = self.a.core.pop_outgoing() {
            self.to_b.push_back(record);
        }
        while let Some(record) = self.b.core.pop_outgoing() {
            self.to_a.push_back(record);
        }
    }

    /// Hands `record` (prefix included) to the receiver; `true` if accepted.
    fn deliver_bytes(&mut self, toward_b: bool, record: &[u8]) -> bool {
        let now = self.now;
        let receiver = if toward_b { &mut self.b } else { &mut self.a };
        let ciphertext = record.get(2..).unwrap_or_default();
        let result = receiver.core.receive(ciphertext, now);
        let accepted = result.is_ok();
        if let Some(Some(frame)) = receiver.outcome(result) {
            receiver
                .received
                .push((frame.frame_type(), frame.body().to_vec()));
        }
        self.flush();
        accepted
    }

    fn deliver(&mut self, toward_b: bool) -> bool {
        match self.queue(toward_b).pop_front() {
            Some(record) => {
                self.deliver_bytes(toward_b, &record);
                true
            }
            None => false,
        }
    }

    /// Applies one operation; returns `false` if a tampered record was
    /// accepted.
    fn apply(&mut self, op: &Op) -> bool {
        let now = self.now;
        match op {
            Op::Send(from_a, kind, length) => {
                let frame_type = APPLICATION[usize::from(*kind) % APPLICATION.len()];
                let body = vec![*kind ^ *length; BODY_LENS[usize::from(*length) % BODY_LENS.len()]];
                let (endpoint, _) = self.sender(*from_a);
                let result = endpoint.core.send(frame_type, &body, now);
                if endpoint.outcome(result).is_some() {
                    endpoint.sent.push((frame_type, body));
                }
            }
            Op::SendTransferError(from_a) => {
                let (endpoint, _) = self.sender(*from_a);
                if let Ok(record) =
                    ErrorRecord::new(ErrorScope::Transfer(TRANSFER_ID), ErrorCode::INTEGRITY)
                {
                    let result = endpoint.core.send_error(record, now);
                    if endpoint.outcome(result).is_some() {
                        endpoint
                            .sent
                            .push((FrameType::ERROR, record.encode().to_vec()));
                    }
                }
            }
            Op::SendSessionError(from_a) => {
                let (endpoint, _) = self.sender(*from_a);
                if let Ok(record) = ErrorRecord::new(ErrorScope::Session, ErrorCode::STORAGE) {
                    let result = endpoint.core.send_error(record, now);
                    if endpoint.outcome(result).is_some() {
                        // Closing by our own Error is this side's end.
                        endpoint.error = Some(SessionError::Closed);
                    }
                }
            }
            Op::Rekey(from_a) => {
                let (endpoint, _) = self.sender(*from_a);
                let result = endpoint.core.request_rekey(now);
                endpoint.outcome(result);
            }
            Op::Poll(from_a) => {
                let (endpoint, _) = self.sender(*from_a);
                let result = endpoint.core.poll(now);
                endpoint.outcome(result);
            }
            Op::Deliver(toward_b) => {
                self.deliver(*toward_b);
            }
            Op::Advance(seconds) => self.now += Duration::from_secs(u64::from(*seconds)),
            Op::Drop(toward_b) => {
                self.queue(*toward_b).pop_front();
            }
            Op::Replay(toward_b) => {
                if let Some(record) = self.queue(*toward_b).pop_front() {
                    self.deliver_bytes(*toward_b, &record);
                    if self.deliver_bytes(*toward_b, &record) {
                        return false;
                    }
                }
            }
            Op::Flip(toward_b, position, bit) => {
                if let Some(mut record) = self.queue(*toward_b).pop_front() {
                    // The prefix is outside the ciphertext: flip a byte after it.
                    let index = 2 + usize::from(*position) % record.len().saturating_sub(2).max(1);
                    if let Some(byte) = record.get_mut(index) {
                        *byte ^= 1 << bit;
                    }
                    if self.deliver_bytes(*toward_b, &record) {
                        return false;
                    }
                }
            }
            Op::Truncate(toward_b, keep) => {
                if let Some(record) = self.queue(*toward_b).pop_front() {
                    let keep = usize::from(*keep) % record.len().max(1);
                    if self.deliver_bytes(*toward_b, &record[..keep]) {
                        return false;
                    }
                }
            }
            Op::Swap(toward_b) => {
                let queue = self.queue(*toward_b);
                if queue.len() >= 2 {
                    queue.swap(0, 1);
                }
            }
            Op::Inject(toward_b, bytes) => {
                if self.deliver_bytes(*toward_b, bytes) {
                    return false;
                }
            }
        }
        self.flush();
        true
    }
}

/// Errors an honest peer, an honest wire, and our own clock can cause.
fn honest_error(error: SessionError) -> bool {
    matches!(
        error,
        SessionError::Timeout
            | SessionError::Closed
            | SessionError::PeerError(_)
            | SessionError::Protocol(ErrorCode::LIMIT)
    )
}

fn check(wire: &mut Wire, honest: bool) -> Result<(), TestCaseError> {
    for (receiver, sender) in [(&wire.b, &wire.a), (&wire.a, &wire.b)] {
        prop_assert!(receiver.received.len() <= sender.sent.len());
        prop_assert_eq!(
            receiver.received.as_slice(),
            &sender.sent[..receiver.received.len()]
        );
    }
    for endpoint in [&mut wire.a, &mut wire.b] {
        if let Some(error) = endpoint.error {
            prop_assert!(endpoint.core.is_closed(), "{error:?} left the session open");
            prop_assert_eq!(
                endpoint.core.receive(&[0; 40], START).map(|_| ()),
                Err(SessionError::Closed)
            );
            if honest {
                prop_assert!(honest_error(error), "honest run failed with {error:?}");
            }
        }
        let epochs = endpoint.core.transport().epochs();
        prop_assert!(epochs.0 >= endpoint.epochs.0 && epochs.1 >= endpoint.epochs.1);
        endpoint.epochs = epochs;
    }
    Ok(())
}

fn run(ops: &[Op]) -> Result<(), TestCaseError> {
    let mut wire = established().map_err(|error| TestCaseError::fail(error.to_string()))?;
    let mut honest = true;
    for op in ops {
        honest &= !op.is_adversarial();
        prop_assert!(wire.apply(op), "a tampered record was accepted: {op:?}");
        check(&mut wire, honest)?;
    }
    if honest {
        // Drain the wire without moving the clock.
        while wire.deliver(true) || wire.deliver(false) {}
        check(&mut wire, honest)?;
        if wire.a.error.is_none() && wire.b.error.is_none() {
            prop_assert_eq!(&wire.b.received, &wire.a.sent);
            prop_assert_eq!(&wire.a.received, &wire.b.sent);
            let (a, b) = (
                wire.a.core.transport().epochs(),
                wire.b.core.transport().epochs(),
            );
            prop_assert_eq!((a.0, a.1), (b.1, b.0));
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn established_sessions_never_accept_altered_traffic(
        ops in proptest::collection::vec(arb_op(), 0..48),
    ) {
        run(&ops)?;
    }
}

/// A fixed honest schedule reaches byte-budget and requested rekeys,
/// keepalive, and transfer errors, and completes on both sides.
#[test]
fn honest_schedule_exercises_every_session_mechanism() -> Result<(), TestCaseError> {
    let mut ops = Vec::new();
    for round in 0..6u8 {
        ops.extend([
            Op::Send(true, round, 3),
            Op::Send(false, round, 2),
            Op::Deliver(true),
            Op::Deliver(false),
        ]);
    }
    ops.extend([
        // A requested update at least a second after the budget update.
        Op::Advance(2),
        Op::Rekey(true),
        Op::Rekey(false),
        Op::Deliver(true),
        Op::Deliver(false),
        Op::SendTransferError(false),
        Op::Advance(31),
        Op::Poll(true),
        Op::Deliver(true),
        Op::Deliver(false),
        Op::Deliver(true),
    ]);
    let mut wire = established().map_err(|error| TestCaseError::fail(error.to_string()))?;
    for op in &ops {
        let in_flight = wire.to_b.len();
        prop_assert!(wire.apply(op));
        if matches!(op, Op::Poll(true)) {
            prop_assert_eq!(
                wire.to_b.len(),
                in_flight + 1,
                "keepalive Ping after 31 idle seconds"
            );
        }
        check(&mut wire, true)?;
    }
    while wire.deliver(true) || wire.deliver(false) {}
    check(&mut wire, true)?;
    prop_assert_eq!(wire.a.error, None);
    prop_assert_eq!(wire.b.error, None);
    prop_assert_eq!(&wire.b.received, &wire.a.sent);
    prop_assert_eq!(&wire.a.received, &wire.b.sent);
    let (a, b) = (
        wire.a.core.transport().epochs(),
        wire.b.core.transport().epochs(),
    );
    // One byte-budget update after five 40 KB frames, one requested update
    // each way.
    prop_assert_eq!((a.0, b.0), (2, 1));
    prop_assert_eq!((a.0, a.1), (b.1, b.0));
    Ok(())
}
