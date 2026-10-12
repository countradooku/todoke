use super::*;
use crate::identity::test_support::Enrolled;
use crate::session::engine::{HandshakeInputs, NoiseHandshake, Pattern};
use crate::session::keys::NoiseStaticKey;
use todoke_proto::session::{CIPHERTEXT_PREFIX_LEN, ciphertext_len};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

const T0: Duration = Duration::from_secs(5000);
const SMALL: Limits = Limits { byte_budget: 300 };

fn transports() -> AnyResult<(NoiseTransport, NoiseTransport)> {
    let a = NoiseStaticKey::generate()?;
    let b = NoiseStaticKey::generate()?;
    let inputs = |initiator: bool| HandshakeInputs {
        pattern: Pattern::KkPsk2,
        initiator,
        prologue: b"transport tests",
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
    Ok((initiator.into_transport()?, responder.into_transport()?))
}

fn pair(limits: Limits, updates: bool) -> AnyResult<(FrameTransport, FrameTransport)> {
    let (a, b) = transports()?;
    let mut a = FrameTransport::new(a, T0, limits);
    let mut b = FrameTransport::new(b, T0, limits);
    if updates {
        a.allow_updates();
        b.allow_updates();
    }
    Ok((a, b))
}

/// The ciphertext after a validated length prefix.
fn body(record: &[u8]) -> AnyResult<&[u8]> {
    let prefix = record
        .first_chunk::<CIPHERTEXT_PREFIX_LEN>()
        .ok_or("short")?;
    let length = ciphertext_len(*prefix)?;
    let rest = &record[CIPHERTEXT_PREFIX_LEN..];
    if rest.len() != length {
        return Err("prefix mismatch".into());
    }
    Ok(rest)
}

fn frame(opened: Opened) -> AnyResult<(FrameType, Vec<u8>)> {
    match opened {
        Opened::Frame(frame_type, body) => Ok((frame_type, body.to_vec())),
        Opened::KeyUpdated => Err("unexpected KeyUpdate".into()),
    }
}

const fn protocol_error(code: ErrorCode) -> Result<(), SessionError> {
    Err(SessionError::Protocol(code))
}

#[test]
fn frames_round_trip_with_exact_framing() -> TestResult {
    let (mut a, mut b) = pair(Limits::SPEC, false)?;
    for body_len in [0, 1, 1000, todoke_proto::session::MAX_BODY_LEN] {
        let records = a.seal(FrameType::CAPABILITIES, &vec![7; body_len], T0)?;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].len(), CIPHERTEXT_PREFIX_LEN + 4 + body_len + 16);
        let (frame_type, received) = frame(b.open(body(&records[0])?, T0)?)?;
        assert_eq!(frame_type, FrameType::CAPABILITIES);
        assert_eq!(received, vec![7; body_len]);
    }
    assert_eq!(
        a.seal(
            FrameType::CAPABILITIES,
            &vec![0; todoke_proto::session::MAX_BODY_LEN + 1],
            T0
        )
        .map(|_| ()),
        Err(SessionError::Usage)
    );
    // Both directions are independent.
    let reply = b.seal(FrameType::REVOKE, b"r", T0)?;
    assert_eq!(frame(a.open(body(&reply[0])?, T0)?)?.1, b"r".to_vec());
    Ok(())
}

#[test]
fn replayed_truncated_or_modified_ciphertexts_close_the_transport() -> TestResult {
    let ciphertext = |a: &mut FrameTransport| -> AnyResult<Vec<u8>> {
        Ok(body(&a.seal(FrameType::CAPABILITIES, b"hello", T0)?[0])?.to_vec())
    };
    // Replay.
    let (mut a, mut b) = pair(Limits::SPEC, false)?;
    let first = ciphertext(&mut a)?;
    b.open(&first, T0)?;
    assert_eq!(
        b.open(&first, T0).map(|_| ()),
        Err(SessionError::Authentication)
    );
    assert!(b.is_closed());
    assert_eq!(b.open(&first, T0).map(|_| ()), Err(SessionError::Closed));
    // Reordering: the second ciphertext first.
    let (mut a, mut b) = pair(Limits::SPEC, false)?;
    let _first = ciphertext(&mut a)?;
    let second = ciphertext(&mut a)?;
    assert_eq!(
        b.open(&second, T0).map(|_| ()),
        Err(SessionError::Authentication)
    );
    // Truncation and every single-bit flip position class.
    for change in [0_usize, 3, 8, 20] {
        let (mut a, mut b) = pair(Limits::SPEC, false)?;
        let mut changed = ciphertext(&mut a)?;
        if change == 20 {
            changed.pop();
        } else {
            changed[change] ^= 0x40;
        }
        assert_eq!(
            b.open(&changed, T0).map(|_| ()),
            Err(SessionError::Authentication)
        );
    }
    // Lengths outside 20..=65535 never reach the cipher.
    let (_, mut b) = pair(Limits::SPEC, false)?;
    assert_eq!(
        b.open(&[0; 19], T0).map(|_| ()),
        protocol_error(ErrorCode::MALFORMED)
    );
    Ok(())
}

#[test]
fn key_update_is_refused_before_the_ratchet_commits() -> TestResult {
    let (mut a, mut b) = pair(Limits::SPEC, false)?;
    assert_eq!(a.key_update(T0).map(|_| ()), Err(SessionError::Usage));
    // A peer that sends one anyway (crafted here) is a state violation.
    let crafted = a.seal(FrameType::KEY_UPDATE, &1_u64.to_be_bytes(), T0)?;
    assert_eq!(
        b.open(body(&crafted[0])?, T0).map(|_| ()),
        protocol_error(ErrorCode::STATE)
    );
    // Pre-gate, the byte budget cannot be exceeded at all.
    let (mut a, _) = pair(SMALL, false)?;
    a.seal(FrameType::CAPABILITIES, &[0; 200], T0)?;
    assert_eq!(
        a.seal(FrameType::CAPABILITIES, &[0; 200], T0).map(|_| ()),
        protocol_error(ErrorCode::LIMIT)
    );
    Ok(())
}

#[test]
fn byte_budget_forces_key_update_before_the_overflowing_frame() -> TestResult {
    let (mut a, mut b) = pair(SMALL, true)?;
    let mut updates = 0;
    for round in 0..20_u8 {
        let records = a.seal(FrameType::CAPABILITIES, &[round; 100], T0)?;
        for record in &records {
            match b.open(body(record)?, T0)? {
                Opened::KeyUpdated => {
                    updates += 1;
                    assert_eq!(body(record)?.len(), KEY_UPDATE_CIPHERTEXT_LEN);
                }
                Opened::Frame(_, received) => assert_eq!(received.as_slice(), &[round; 100]),
            }
        }
    }
    // 120-byte ciphertexts, budget 300: two fit per key.
    assert_eq!(updates, 9);
    assert_eq!(a.epochs().0, 9);
    assert_eq!(b.epochs().1, 9);
    Ok(())
}

#[test]
fn receiver_enforces_the_byte_budget_and_epoch_sequence() -> TestResult {
    // A sender with a larger budget overruns the receiver's: fatal.
    let (a, b) = transports()?;
    let mut a = FrameTransport::new(
        a,
        T0,
        Limits {
            byte_budget: 10_000,
        },
    );
    let mut b = FrameTransport::new(b, T0, SMALL);
    a.allow_updates();
    b.allow_updates();
    for _ in 0..2 {
        b.open(
            body(&a.seal(FrameType::CAPABILITIES, &[0; 100], T0)?[0])?,
            T0,
        )?;
    }
    let third = a.seal(FrameType::CAPABILITIES, &[0; 100], T0)?;
    assert_eq!(
        b.open(body(&third[0])?, T0).map(|_| ()),
        protocol_error(ErrorCode::LIMIT)
    );
    // Skipped epoch.
    let (mut a, mut b) = pair(Limits::SPEC, true)?;
    let skipped = a.seal(FrameType::KEY_UPDATE, &2_u64.to_be_bytes(), T0)?;
    assert_eq!(
        b.open(body(&skipped[0])?, T0).map(|_| ()),
        protocol_error(ErrorCode::STATE)
    );
    // Duplicate epoch: epoch 1 again under the new key.
    let (mut a, mut b) = pair(Limits::SPEC, true)?;
    let update = a.key_update(T0)?;
    assert!(matches!(b.open(body(&update)?, T0)?, Opened::KeyUpdated));
    let duplicate = a.seal(FrameType::KEY_UPDATE, &1_u64.to_be_bytes(), T0)?;
    assert_eq!(
        b.open(body(&duplicate[0])?, T0).map(|_| ()),
        protocol_error(ErrorCode::STATE)
    );
    // Epoch zero and an oversized KeyUpdate body.
    for crafted in [
        0_u64.to_be_bytes().to_vec(),
        [0, 0, 0, 0, 0, 0, 0, 1, 0].to_vec(),
    ] {
        let (mut a, mut b) = pair(Limits::SPEC, true)?;
        let record = a.seal(FrameType::KEY_UPDATE, &crafted, T0)?;
        assert_eq!(
            b.open(body(&record[0])?, T0).map(|_| ()),
            protocol_error(ErrorCode::MALFORMED)
        );
    }
    // A dropped frame desynchronizes the nonce: the KeyUpdate that follows
    // it no longer authenticates.
    let (mut a, mut b) = pair(Limits::SPEC, true)?;
    let _dropped = a.seal(FrameType::CAPABILITIES, b"x", T0)?;
    let update = a.key_update(T0)?;
    assert!(matches!(
        b.open(body(&update)?, T0),
        Err(SessionError::Authentication)
    ));
    Ok(())
}

#[test]
fn rekey_rate_limit_and_nonce_continuity() -> TestResult {
    let (mut a, mut b) = pair(Limits::SPEC, true)?;
    let first = a.requested_key_update(T0)?;
    assert_eq!(
        a.requested_key_update(T0 + Duration::from_millis(999))
            .map(|_| ()),
        Err(SessionError::RekeyTooSoon)
    );
    let second = a.requested_key_update(T0 + MIN_REKEY_INTERVAL)?;
    for record in [&first, &second] {
        assert!(matches!(b.open(body(record)?, T0)?, Opened::KeyUpdated));
    }
    // REKEY does not reset the nonce (§5): two updates used nonces 0 and 1.
    let records = a.seal(FrameType::CAPABILITIES, b"after", T0)?;
    assert_eq!(frame(b.open(body(&records[0])?, T0)?)?.1, b"after".to_vec());
    assert_eq!(
        a.rekey_deadline(),
        T0 + MIN_REKEY_INTERVAL + LOCAL_REKEY_INTERVAL
    );
    Ok(())
}

fn info() -> AnyResult<SessionInfo> {
    let enrolled = Enrolled::new()?;
    Ok(SessionInfo {
        role: Role::Initiator,
        mode: SessionMode::Contact,
        handshake_hash: [1; 32],
        session_id: [2; 32],
        peer_static: [3; 32],
        peer_binding: enrolled.bind(1)?,
    })
}

fn cores(lifetime: Duration) -> AnyResult<(SessionCore, SessionCore)> {
    let (a, b) = pair(Limits::SPEC, false)?;
    let a = SessionCore::new(a, info()?, Entropy::Os, T0, lifetime);
    let b = SessionCore::new(b, info()?, Entropy::Os, T0, lifetime);
    Ok((a, b))
}

fn drain(from: &mut SessionCore) -> Vec<Vec<u8>> {
    core::iter::from_fn(|| from.pop_outgoing()).collect()
}

/// Delivers everything queued at `from` to `to`, returning delivered frames.
fn relay(from: &mut SessionCore, to: &mut SessionCore, now: Duration) -> AnyResult<Vec<Frame>> {
    let mut frames = Vec::new();
    for record in drain(from) {
        if let Some(frame) = to.receive(body(&record)?, now)? {
            frames.push(frame);
        }
    }
    Ok(frames)
}

/// Decrypts the single record queued at `from` with a fresh view of what
/// `to` would see, and returns the decoded Error record.
fn queued_error(from: &mut SessionCore, to: &mut SessionCore) -> AnyResult<ErrorRecord> {
    let records = drain(from);
    assert_eq!(records.len(), 1, "exactly one Error");
    match to.receive(body(&records[0])?, T0) {
        Err(SessionError::PeerError(code)) => {
            ErrorRecord::new(ErrorScope::Session, code).map_err(Into::into)
        }
        other => Err(format!("expected a session Error, got {other:?}").into()),
    }
}

#[test]
fn application_frames_flow_and_session_types_are_refused() -> TestResult {
    let (mut a, mut b) = cores(MAX_SESSION_DURATION)?;
    a.send(FrameType::CAPABILITIES, b"caps", T0)?;
    a.send(FrameType::new(0x0015), b"chunk request", T0)?;
    let frames = relay(&mut a, &mut b, T0)?;
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].frame_type(), FrameType::CAPABILITIES);
    assert_eq!(frames[1].body(), b"chunk request");
    assert!(format!("{:?}", frames[1]).contains("[13 bytes]"));
    for refused in [
        FrameType::IDENTITY,
        FrameType::RATCHET_ACK,
        FrameType::KEY_UPDATE,
        FrameType::PING,
        FrameType::ERROR,
        FrameType::new(0x8000),
        FrameType::new(0xc000),
        FrameType::new(0x0100),
    ] {
        assert_eq!(
            a.send(refused, b"", T0),
            Err(SessionError::Usage),
            "{refused:?}"
        );
    }
    assert!(!a.is_closed());
    Ok(())
}

#[test]
fn unsupported_and_misplaced_frames_are_reported_once_and_close() -> TestResult {
    let crafted_cases = [
        (FrameType::new(0x000a), ErrorCode::UNSUPPORTED),
        (FrameType::new(0x0200), ErrorCode::UNSUPPORTED),
        (FrameType::new(0xc001), ErrorCode::UNSUPPORTED),
        (FrameType::IDENTITY, ErrorCode::STATE),
        (FrameType::RATCHET_READY, ErrorCode::STATE),
        (FrameType::new(0x8001), ErrorCode::STATE),
        (FrameType::PONG, ErrorCode::STATE),
    ];
    for (frame_type, code) in crafted_cases {
        let (mut a, mut b) = cores(MAX_SESSION_DURATION)?;
        let body_bytes = if frame_type == FrameType::PONG {
            9_u64.to_be_bytes().to_vec()
        } else {
            Vec::new()
        };
        let record = a.transport.seal(frame_type, &body_bytes, T0)?;
        assert_eq!(
            b.receive(body(&record[0])?, T0).map(|_| ()),
            Err(SessionError::Protocol(code)),
            "{frame_type:?}"
        );
        assert!(b.is_closed());
        assert_eq!(queued_error(&mut b, &mut a)?.code(), code);
        assert_eq!(
            b.receive(body(&record[0])?, T0).map(|_| ()),
            Err(SessionError::Closed)
        );
    }
    Ok(())
}

#[test]
fn noncritical_frames_are_skipped_within_budget_after_capabilities() -> TestResult {
    let (mut a, mut b) = cores(MAX_SESSION_DURATION)?;
    a.send(FrameType::CAPABILITIES, b"caps", T0)?;
    relay(&mut a, &mut b, T0)?;
    for _ in 0..MAX_NONCRITICAL_FRAMES {
        let record =
            a.transport
                .seal(FrameType::new(0x9000), &[0; MAX_NONCRITICAL_BODY_LEN], T0)?;
        assert!(b.receive(body(&record[0])?, T0)?.is_none());
    }
    let record = a.transport.seal(FrameType::new(0x9000), b"", T0)?;
    assert_eq!(
        b.receive(body(&record[0])?, T0).map(|_| ()),
        Err(SessionError::Protocol(ErrorCode::LIMIT))
    );
    let (mut a, mut b) = cores(MAX_SESSION_DURATION)?;
    a.send(FrameType::CAPABILITIES, b"caps", T0)?;
    relay(&mut a, &mut b, T0)?;
    let record = a.transport.seal(
        FrameType::new(0x9000),
        &[0; MAX_NONCRITICAL_BODY_LEN + 1],
        T0,
    )?;
    assert_eq!(
        b.receive(body(&record[0])?, T0).map(|_| ()),
        Err(SessionError::Protocol(ErrorCode::LIMIT))
    );
    Ok(())
}

#[test]
fn error_frames_close_or_pass_through_and_are_never_answered() -> TestResult {
    let (mut a, mut b) = cores(MAX_SESSION_DURATION)?;
    let transfer = ErrorRecord::new(ErrorScope::Transfer([4; 16]), ErrorCode::INTEGRITY)?;
    a.send_error(transfer, T0)?;
    let frames = relay(&mut a, &mut b, T0)?;
    assert_eq!(frames.len(), 1);
    assert_eq!(ErrorRecord::decode(frames[0].body())?, transfer);
    assert!(!a.is_closed() && !b.is_closed());
    a.send_error(
        ErrorRecord::new(ErrorScope::Session, ErrorCode::STORAGE)?,
        T0,
    )?;
    assert!(a.is_closed());
    let records = drain(&mut a);
    assert_eq!(
        b.receive(body(&records[0])?, T0).map(|_| ()),
        Err(SessionError::PeerError(ErrorCode::STORAGE))
    );
    assert!(b.is_closed());
    assert_eq!(
        drain(&mut b),
        Vec::<Vec<u8>>::new(),
        "an Error is never answered"
    );
    // A malformed Error closes without a reply too.
    for crafted in [
        vec![0; 18],
        vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        vec![2; 19],
    ] {
        let (mut a, mut b) = cores(MAX_SESSION_DURATION)?;
        let record = a.transport.seal(FrameType::ERROR, &crafted, T0)?;
        assert_eq!(
            b.receive(body(&record[0])?, T0).map(|_| ()),
            Err(SessionError::PeerError(ErrorCode::MALFORMED))
        );
        assert_eq!(drain(&mut b), Vec::<Vec<u8>>::new());
    }
    Ok(())
}

#[test]
fn keepalive_ping_pong_and_idle_timeout() -> TestResult {
    let (mut a, mut b) = cores(MAX_SESSION_DURATION)?;
    assert_eq!(a.next_deadline(), T0 + PING_AFTER);
    a.poll(T0 + Duration::from_millis(29_999))?;
    assert_eq!(drain(&mut a), Vec::<Vec<u8>>::new());
    let ping_at = T0 + PING_AFTER;
    a.poll(ping_at)?;
    assert_eq!(a.next_deadline(), ping_at + PONG_TIMEOUT);
    // b answers the Ping; a accepts the matching Pong.
    assert!(relay(&mut a, &mut b, ping_at)?.is_empty());
    assert!(relay(&mut b, &mut a, ping_at)?.is_empty());
    assert_eq!(a.next_deadline(), ping_at + PING_AFTER);
    // No Pong in time: Timeout, reported with an Error(TIMEOUT).
    let (mut a, mut b) = cores(MAX_SESSION_DURATION)?;
    a.poll(ping_at)?;
    relay(&mut a, &mut b, ping_at)?;
    drain(&mut b); // the Pong is lost
    assert_eq!(a.poll(ping_at + PONG_TIMEOUT), Err(SessionError::Timeout));
    assert_eq!(queued_error(&mut a, &mut b)?.code(), ErrorCode::TIMEOUT);
    assert_eq!(a.poll(ping_at + PONG_TIMEOUT), Err(SessionError::Closed));
    Ok(())
}

#[test]
fn idle_session_still_rekeys_on_time() -> TestResult {
    let (mut a, mut b) = cores(MAX_SESSION_DURATION)?;
    // Keep traffic flowing every 20 s so keepalive stays quiet.
    let mut now = T0;
    let mut updates = 0;
    while now < T0 + Duration::from_secs(250) {
        now += Duration::from_secs(20);
        a.poll(now)?;
        a.send(FrameType::CAPABILITIES, b"x", now)?;
        b.send(FrameType::CAPABILITIES, b"y", now)?;
        for record in drain(&mut a) {
            if body(&record)?.len() == KEY_UPDATE_CIPHERTEXT_LEN {
                updates += 1;
            }
            b.receive(body(&record)?, now)?;
        }
        relay(&mut b, &mut a, now)?;
    }
    // Updates at 100 s and 200 s after the last key (polled at 20 s steps).
    assert_eq!(updates, 2);
    assert_eq!(a.transport().epochs().0, 2);
    assert_eq!(b.transport().epochs().1, 2);
    Ok(())
}

#[test]
fn idle_timeout_and_hard_deadlines() -> TestResult {
    let (mut a, _) = cores(MAX_SESSION_DURATION)?;
    // 135 seconds without authenticated traffic closes.
    assert_eq!(a.poll(T0 + IDLE_TIMEOUT), Err(SessionError::Timeout));
    // 24-hour cap: TIMEOUT.
    let (mut a, mut b) = cores(MAX_SESSION_DURATION + Duration::from_secs(1))?;
    assert_eq!(a.next_deadline(), T0 + PING_AFTER);
    assert_eq!(a.hard_deadline, T0 + MAX_SESSION_DURATION);
    // §13: at most 24 hours.
    assert_eq!(MAX_SESSION_DURATION, Duration::from_secs(86_400));
    a.last_received = T0 + MAX_SESSION_DURATION;
    assert_eq!(
        a.poll(T0 + MAX_SESSION_DURATION),
        Err(SessionError::Timeout)
    );
    assert_eq!(queued_error(&mut a, &mut b)?.code(), ErrorCode::TIMEOUT);
    // Binding expiry before the cap: EXPIRED.
    let (mut a, mut b) = cores(Duration::from_secs(50))?;
    a.last_received = T0 + Duration::from_secs(50);
    assert_eq!(
        a.poll(T0 + Duration::from_secs(50)),
        Err(SessionError::Timeout)
    );
    assert_eq!(queued_error(&mut a, &mut b)?.code(), ErrorCode::EXPIRED);
    Ok(())
}

#[test]
fn explicit_rekey_through_the_core() -> TestResult {
    let (mut a, mut b) = cores(MAX_SESSION_DURATION)?;
    a.request_rekey(T0)?;
    assert_eq!(a.request_rekey(T0), Err(SessionError::RekeyTooSoon));
    assert!(relay(&mut a, &mut b, T0)?.is_empty());
    assert_eq!(b.transport().epochs().1, 1);
    assert!(format!("{a:?}").contains("send_epoch: 1"));
    Ok(())
}

/// §5 allows at most one `KeyUpdate` per second absent byte-budget
/// exhaustion. Local quota (§13 permits smaller local limits): a burst of
/// [`KEY_UPDATE_BURST`] for network bunching, then one per second; more is
/// a session LIMIT error.
#[test]
fn received_key_updates_are_rate_limited() -> TestResult {
    let second = MIN_REKEY_INTERVAL;
    // A burst at one instant: the first KEY_UPDATE_BURST pass.
    let (mut a, mut b) = pair(Limits::SPEC, true)?;
    for _ in 0..KEY_UPDATE_BURST {
        let update = a.key_update(T0)?;
        assert!(matches!(b.open(body(&update)?, T0)?, Opened::KeyUpdated));
    }
    let excess = a.key_update(T0)?;
    assert_eq!(
        b.open(body(&excess)?, T0 + second / 2).map(|_| ()),
        protocol_error(ErrorCode::LIMIT)
    );
    assert!(b.is_closed());
    // The quota refills at one per second.
    let (mut a, mut b) = pair(Limits::SPEC, true)?;
    for _ in 0..KEY_UPDATE_BURST {
        b.open(body(&a.key_update(T0)?)?, T0)?;
    }
    let later = T0 + second;
    assert!(matches!(
        b.open(body(&a.key_update(later)?)?, later)?,
        Opened::KeyUpdated
    ));
    assert_eq!(
        b.open(body(&a.key_update(later)?)?, later).map(|_| ()),
        protocol_error(ErrorCode::LIMIT)
    );
    // A steady one per second is always accepted.
    let (mut a, mut b) = pair(Limits::SPEC, true)?;
    for step in 0..40 {
        let now = T0 + second * step;
        assert!(matches!(
            b.open(body(&a.key_update(now)?)?, now)?,
            Opened::KeyUpdated
        ));
    }
    Ok(())
}

/// An update forced by the byte budget is not limited by time: the
/// receiver accepts it when the previous key carried enough ciphertext that
/// no further maximum-size frame would have fit.
#[test]
fn byte_budget_key_updates_bypass_the_rate_limit() -> TestResult {
    let limits = Limits {
        byte_budget: 200_000,
    };
    let (mut a, mut b) = pair(limits, true)?;
    for _ in 0..KEY_UPDATE_BURST {
        b.open(body(&a.key_update(T0)?)?, T0)?;
    }
    // Fill the receive budget to within one maximum-size ciphertext.
    for _ in 0..3 {
        let records = a.seal(FrameType::CAPABILITIES, &vec![0; 50_000], T0)?;
        assert_eq!(records.len(), 1);
        b.open(body(&records[0])?, T0)?;
    }
    assert!(matches!(
        b.open(body(&a.key_update(T0)?)?, T0)?,
        Opened::KeyUpdated
    ));
    // The new key carried nothing yet: the time quota applies again.
    assert_eq!(
        b.open(body(&a.key_update(T0)?)?, T0).map(|_| ()),
        protocol_error(ErrorCode::LIMIT)
    );
    Ok(())
}

/// §13 allows one outstanding Ping per direction. Local quota: a burst of
/// [`PING_BURST`], then one per [`MIN_PING_INTERVAL`]; more is a session
/// LIMIT error, reported once.
#[test]
fn received_pings_are_rate_limited() -> TestResult {
    let (mut a, mut b) = cores(MAX_SESSION_DURATION)?;
    let ping = |a: &mut SessionCore, nonce: u64, now| -> AnyResult<Vec<u8>> {
        let records = a
            .transport
            .seal(FrameType::PING, &nonce.to_be_bytes(), now)?;
        Ok(body(&records[0])?.to_vec())
    };
    // What `a` sees from `b`, read below the keepalive logic.
    let replies = |a: &mut SessionCore, b: &mut SessionCore| -> AnyResult<Vec<FrameType>> {
        let mut types = Vec::new();
        for record in drain(b) {
            types.push(frame(a.transport.open(body(&record)?, T0)?)?.0);
        }
        Ok(types)
    };
    for nonce in 1..=u64::from(PING_BURST) {
        assert!(b.receive(&ping(&mut a, nonce, T0)?, T0)?.is_none());
    }
    assert_eq!(
        replies(&mut a, &mut b)?,
        vec![FrameType::PONG; usize::from(PING_BURST)],
        "every Ping answered"
    );
    let later = T0 + MIN_PING_INTERVAL;
    assert!(b.receive(&ping(&mut a, 99, later)?, later)?.is_none());
    assert_eq!(replies(&mut a, &mut b)?, vec![FrameType::PONG]);
    assert_eq!(
        b.receive(&ping(&mut a, 100, later)?, later).map(|_| ()),
        Err(SessionError::Protocol(ErrorCode::LIMIT))
    );
    let records = drain(&mut b);
    assert_eq!(records.len(), 1, "one Error, no Pong");
    let (frame_type, error) = frame(a.transport.open(body(&records[0])?, T0)?)?;
    assert_eq!(frame_type, FrameType::ERROR);
    assert_eq!(ErrorRecord::decode(&error)?.code(), ErrorCode::LIMIT);
    assert!(b.is_closed());
    Ok(())
}

/// §5: a closed transport seals nothing and sends no `KeyUpdate`; a sending
/// epoch at `u64::MAX` cannot wrap, so the update fails with LIMIT and the
/// transport closes; a receiver at `u64::MAX` rejects any further update.
#[test]
fn closed_or_exhausted_transports_send_nothing() -> TestResult {
    let (mut a, _) = pair(Limits::SPEC, true)?;
    a.close();
    assert_eq!(
        a.seal(FrameType::CAPABILITIES, b"x", T0),
        Err(SessionError::Closed)
    );
    assert_eq!(a.key_update(T0), Err(SessionError::Closed));
    let (mut a, _) = pair(Limits::SPEC, true)?;
    a.send.epoch = u64::MAX;
    assert_eq!(
        a.key_update(T0).map(|_| ()),
        protocol_error(ErrorCode::LIMIT)
    );
    assert!(a.is_closed());
    assert_eq!(
        a.seal(FrameType::CAPABILITIES, b"x", T0),
        Err(SessionError::Closed)
    );
    let (mut c, mut d) = pair(Limits::SPEC, true)?;
    d.recv.epoch = u64::MAX;
    let update = c.key_update(T0)?;
    assert_eq!(
        d.open(body(&update)?, T0).map(|_| ()),
        protocol_error(ErrorCode::STATE)
    );
    assert!(d.is_closed());
    Ok(())
}

/// §13: a Pong must echo the outstanding Ping's nonce; any other nonce is
/// STATE. Ping nonces are nonzero: an all-zero draw is replaced.
#[test]
fn pongs_must_echo_the_outstanding_nonzero_ping() -> TestResult {
    let (a, b) = pair(Limits::SPEC, false)?;
    let mut a = SessionCore::new(
        a,
        info()?,
        Entropy::scripted(vec![vec![0; 8], vec![9; 8]]),
        T0,
        MAX_SESSION_DURATION,
    );
    let mut b = SessionCore::new(b, info()?, Entropy::Os, T0, MAX_SESSION_DURATION);
    let ping_at = T0 + PING_AFTER;
    a.poll(ping_at)?;
    let records = drain(&mut a);
    assert_eq!(records.len(), 1);
    let (frame_type, nonce) = frame(b.transport.open(body(&records[0])?, ping_at)?)?;
    assert_eq!((frame_type, nonce), (FrameType::PING, vec![9; 8]));
    let wrong = b
        .transport
        .seal(FrameType::PONG, &[8; 8], ping_at)?
        .pop()
        .ok_or("no record")?;
    assert_eq!(
        a.receive(body(&wrong)?, ping_at).map(|_| ()),
        protocol_error(ErrorCode::STATE)
    );
    assert!(a.is_closed());
    Ok(())
}

/// A missing Pong before an earlier binding expiry is a TIMEOUT, not
/// EXPIRED: EXPIRED is reported only once the expiry itself is reached.
#[test]
fn pong_timeout_before_binding_expiry_reports_timeout() -> TestResult {
    let (mut a, mut b) = cores(Duration::from_secs(50))?;
    let ping_at = T0 + PING_AFTER;
    a.poll(ping_at)?;
    relay(&mut a, &mut b, ping_at)?;
    drain(&mut b); // the Pong is lost
    assert_eq!(a.poll(ping_at + PONG_TIMEOUT), Err(SessionError::Timeout));
    assert!(ping_at + PONG_TIMEOUT < a.hard_deadline());
    assert_eq!(queued_error(&mut a, &mut b)?.code(), ErrorCode::TIMEOUT);
    Ok(())
}
