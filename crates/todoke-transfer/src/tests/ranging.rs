//! Pointing in the session (PROTOCOL §10.4): readiness once each, starts
//! only toward a ready peer with a configuration it announced, one at a
//! time and at most eight, stops by session ID, and an end after 120 s.

use core::time::Duration;

use todoke_proto::ranging::{
    CONFIG_PROVISIONED_DS_TWR, MAX_STARTS, RangingReady, RangingStart, RangingStop, STS_KEY_LEN,
};
use todoke_proto::session::FrameType;
use zeroize::Zeroizing;

use super::basic::session_failure;
use super::support::{Link, TestResult, Which, config, fixture};
use crate::{FailureCode, MemorySink, MemorySource, RangingError, TransferEvent};

fn link(fixture: &super::support::Fixture) -> Result<Link<'_>, Box<dyn std::error::Error>> {
    let mut link = Link::new(
        fixture,
        Which::First,
        (MemorySource::new(), MemorySource::new()),
        (MemorySink::new(), MemorySink::new()),
        (config(4)?, config(4)?),
    )?;
    link.settle()?;
    Ok(link)
}

const READY: RangingReady = RangingReady {
    address: 0x2222,
    configs: CONFIG_PROVISIONED_DS_TWR,
};

fn start(session_id: u32) -> RangingStart {
    RangingStart {
        session_id,
        controller: 0x1111,
        channel: 9,
        preamble: 10,
        config: CONFIG_PROVISIONED_DS_TWR,
        sts_key: Zeroizing::new([3; STS_KEY_LEN]),
    }
}

/// Bob says he can range; Alice starts, Bob gets her parameters; Alice
/// stops, Bob hears it; a ranging ends by itself after 120 seconds.
#[test]
fn a_ranging_starts_and_stops() -> TestResult {
    let fixture = fixture()?;
    let mut link = link(&fixture)?;
    // Not before the peer is ready.
    assert_eq!(
        link.a.start_ranging(&start(1), link.now),
        Err(RangingError::PeerNotReady)
    );
    link.b.send_ranging_ready(READY)?;
    assert_eq!(
        link.b.send_ranging_ready(READY),
        Err(RangingError::AlreadySent)
    );
    link.settle()?;
    assert!(link.a_events.contains(&TransferEvent::RangingReady(READY)));
    link.a.start_ranging(&start(7), link.now)?;
    assert_eq!(
        link.a.start_ranging(&start(8), link.now),
        Err(RangingError::Busy)
    );
    link.settle()?;
    let requested = link.b_events.iter().find_map(|event| match event {
        TransferEvent::RangingRequested(start) => Some(start.clone()),
        _ => None,
    });
    assert_eq!(requested.as_deref(), Some(&start(7)));
    assert_eq!(link.a.stop_ranging(8), Err(RangingError::NotRunning));
    link.a.stop_ranging(7)?;
    link.settle()?;
    assert!(
        link.b_events
            .contains(&TransferEvent::RangingStopped { session_id: 7 })
    );
    // A new one, left to run out: both ends see it end.
    link.a.start_ranging(&start(9), link.now)?;
    link.settle()?;
    let (a, b) = link.advance(Duration::from_secs(121));
    a?;
    b?;
    for events in [&link.a_events, &link.b_events] {
        assert!(events.contains(&TransferEvent::RangingStopped { session_id: 9 }));
    }
    link.a.start_ranging(&start(10), link.now)?;
    Ok(())
}

/// At most eight starts per session.
#[test]
fn a_session_starts_at_most_eight() -> TestResult {
    let fixture = fixture()?;
    let mut link = link(&fixture)?;
    link.b.send_ranging_ready(READY)?;
    link.settle()?;
    for id in 1..=u32::from(MAX_STARTS) {
        link.a.start_ranging(&start(id), link.now)?;
        link.a.stop_ranging(id)?;
    }
    link.settle()?;
    assert_eq!(
        link.a.start_ranging(&start(99), link.now),
        Err(RangingError::Busy)
    );
    Ok(())
}

/// Out of line from the peer: a start to a side that never said it could
/// range, a second readiness, a start while one runs, a stop for another
/// ranging, and a ninth start are all STATE.
#[test]
fn pointing_out_of_line_is_state() -> TestResult {
    let fixture = fixture()?;
    let body = start(5).encode();
    let mut unready = link(&fixture)?;
    let result = unready
        .b
        .handle_frame(FrameType::RANGING_START, &body, unready.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    let mut twice = link(&fixture)?;
    twice
        .a
        .handle_frame(FrameType::RANGING_READY, &READY.encode(), twice.now)?;
    let result = twice
        .a
        .handle_frame(FrameType::RANGING_READY, &READY.encode(), twice.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    let mut busy = link(&fixture)?;
    busy.b.send_ranging_ready(READY)?;
    busy.b
        .handle_frame(FrameType::RANGING_START, &body, busy.now)?;
    let result = busy
        .b
        .handle_frame(FrameType::RANGING_START, &start(6).encode(), busy.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    let mut other = link(&fixture)?;
    other.b.send_ranging_ready(READY)?;
    other
        .b
        .handle_frame(FrameType::RANGING_START, &body, other.now)?;
    let stop = RangingStop { session_id: 6 }.encode();
    let result = other
        .b
        .handle_frame(FrameType::RANGING_STOP, &stop, other.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    let mut ninth = link(&fixture)?;
    ninth.b.send_ranging_ready(READY)?;
    for id in 1..=u32::from(MAX_STARTS) {
        ninth
            .b
            .handle_frame(FrameType::RANGING_START, &start(id).encode(), ninth.now)?;
        ninth.b.handle_frame(
            FrameType::RANGING_STOP,
            &RangingStop { session_id: id }.encode(),
            ninth.now,
        )?;
    }
    let result = ninth
        .b
        .handle_frame(FrameType::RANGING_START, &start(99).encode(), ninth.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    // A malformed body: MALFORMED.
    let mut malformed = link(&fixture)?;
    let result = malformed
        .a
        .handle_frame(FrameType::RANGING_READY, &[0, 0, 1], malformed.now);
    assert_eq!(session_failure(result), Some(FailureCode::Malformed));
    Ok(())
}
