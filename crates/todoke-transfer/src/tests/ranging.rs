//! Pointing in the session (PROTOCOL §10.4): readiness once each, starts
//! only toward a ready peer with a configuration it announced, one at a
//! time and at most eight, accepted once by the controlee at an address of
//! its own, stops by session ID, and an end after 120 s.

use core::time::Duration;

use todoke_proto::ranging::{
    CONFIG_APPLE_PEER, CONFIG_PROVISIONED_DS_TWR, MAX_STARTS, PeerRanging, RangingAccept,
    RangingReady, RangingStart, RangingStop, STS_KEY_LEN,
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
    // Bob accepts at an address of his own, once; Alice may not accept
    // her own start.
    assert_eq!(
        link.b.accept_ranging(8, 0x2222),
        Err(RangingError::NotRunning)
    );
    assert_eq!(link.b.accept_ranging(7, 0x1111), Err(RangingError::Address));
    assert_eq!(link.b.accept_ranging(7, 0xffff), Err(RangingError::Address));
    assert_eq!(
        link.a.accept_ranging(7, 0x2222),
        Err(RangingError::NotRunning)
    );
    link.b.accept_ranging(7, 0x2222)?;
    assert_eq!(
        link.b.accept_ranging(7, 0x2223),
        Err(RangingError::NotRunning)
    );
    link.settle()?;
    assert!(
        link.a_events
            .contains(&TransferEvent::RangingAccepted(RangingAccept {
                session_id: 7,
                controlee: 0x2222,
            }))
    );
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
/// range, a second readiness, a second start of the running ranging, a stop
/// for a ranging that never ran, and a ninth start are all STATE.
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
        .handle_frame(FrameType::RANGING_START, &body, busy.now);
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
    // An accept to the controlee, for another ranging, or a second one:
    // STATE; at the controller's own address: MALFORMED.
    let accept = |session_id, controlee| {
        RangingAccept {
            session_id,
            controlee,
        }
        .encode()
    };
    let mut to_controlee = link(&fixture)?;
    to_controlee.b.send_ranging_ready(READY)?;
    to_controlee
        .b
        .handle_frame(FrameType::RANGING_START, &body, to_controlee.now)?;
    let result = to_controlee.b.handle_frame(
        FrameType::RANGING_ACCEPT,
        &accept(5, 0x2222),
        to_controlee.now,
    );
    assert_eq!(session_failure(result), Some(FailureCode::State));
    for (bodies, failure) in [
        (vec![accept(6, 0x2222)], FailureCode::State),
        (
            vec![accept(5, 0x2222), accept(5, 0x2222)],
            FailureCode::State,
        ),
        (vec![accept(5, 0x1111)], FailureCode::Malformed),
    ] {
        let mut controller = link(&fixture)?;
        controller
            .a
            .handle_frame(FrameType::RANGING_READY, &READY.encode(), controller.now)?;
        controller.a.start_ranging(&start(5), controller.now)?;
        let (last, first) = bodies.split_last().ok_or("no body")?;
        for body in first {
            controller
                .a
                .handle_frame(FrameType::RANGING_ACCEPT, body, controller.now)?;
        }
        let result = controller
            .a
            .handle_frame(FrameType::RANGING_ACCEPT, last, controller.now);
        assert_eq!(session_failure(result), Some(failure));
    }
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
        .handle_frame(FrameType::RANGING_READY, &[0], malformed.now);
    assert_eq!(session_failure(result), Some(FailureCode::Malformed));
    Ok(())
}

/// Records that cross on the wire settle without failing the session: an
/// accept or a stop for a ranging that ended here is ignored, a new start
/// from the controller replaces its ranging, and when both sides start at
/// once the larger session ID stands on both (equal IDs: neither).
#[test]
fn crossing_records_settle() -> TestResult {
    let fixture = fixture()?;
    let ready = |link: &mut Link<'_>| -> TestResult {
        link.a.send_ranging_ready(READY)?;
        link.b.send_ranging_ready(READY)?;
        link.settle()?;
        Ok(())
    };
    // The controller stops while the accept is on its way.
    let mut stop_accept = link(&fixture)?;
    ready(&mut stop_accept)?;
    stop_accept.a.start_ranging(&start(5), stop_accept.now)?;
    stop_accept.settle()?;
    stop_accept.b.accept_ranging(5, 0x2222)?;
    stop_accept.a.stop_ranging(5)?;
    stop_accept.settle()?;
    assert!(
        !stop_accept
            .a_events
            .iter()
            .any(|event| matches!(event, TransferEvent::RangingAccepted(_)))
    );
    assert!(
        stop_accept
            .b_events
            .contains(&TransferEvent::RangingStopped { session_id: 5 })
    );
    // Both stop at once.
    let mut both_stop = link(&fixture)?;
    ready(&mut both_stop)?;
    both_stop.a.start_ranging(&start(5), both_stop.now)?;
    both_stop.settle()?;
    both_stop.a.stop_ranging(5)?;
    both_stop.b.stop_ranging(5)?;
    both_stop.settle()?;
    // Each side's time runs out on its own clock; a stop for a ranging that
    // ran out here is ignored.
    let mut expired = link(&fixture)?;
    ready(&mut expired)?;
    expired.a.start_ranging(&start(5), expired.now)?;
    expired.settle()?;
    let (a, b) = expired.advance(Duration::from_secs(121));
    a?;
    b?;
    let stop = RangingStop { session_id: 5 }.encode();
    expired
        .a
        .handle_frame(FrameType::RANGING_STOP, &stop, expired.now)?;
    // The controller starts again: the old ranging ended there.
    let mut again = link(&fixture)?;
    ready(&mut again)?;
    again.a.start_ranging(&start(5), again.now)?;
    again.settle()?;
    again
        .b
        .handle_frame(FrameType::RANGING_START, &start(6).encode(), again.now)?;
    again.settle()?;
    assert!(
        again
            .b_events
            .contains(&TransferEvent::RangingStopped { session_id: 5 })
    );
    // Both start at once: 9 stands on both sides, 5 is dropped on both.
    let mut crossing = link(&fixture)?;
    ready(&mut crossing)?;
    crossing.a.start_ranging(&start(5), crossing.now)?;
    crossing.b.start_ranging(&start(9), crossing.now)?;
    crossing.settle()?;
    assert!(
        crossing
            .a_events
            .contains(&TransferEvent::RangingStopped { session_id: 5 })
    );
    let requested = |events: &[TransferEvent]| {
        events
            .iter()
            .filter_map(|event| match event {
                TransferEvent::RangingRequested(start) => Some(start.session_id),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(requested(&crossing.a_events), [9]);
    assert_eq!(requested(&crossing.b_events), Vec::<u32>::new());
    crossing.a.accept_ranging(9, 0x2222)?;
    crossing.settle()?;
    assert!(
        crossing
            .b_events
            .contains(&TransferEvent::RangingAccepted(RangingAccept {
                session_id: 9,
                controlee: 0x2222,
            }))
    );
    // The same ID from both: neither stands, and both may start again.
    let mut same = link(&fixture)?;
    ready(&mut same)?;
    same.a.start_ranging(&start(7), same.now)?;
    same.b.start_ranging(&start(7), same.now)?;
    same.settle()?;
    for events in [&same.a_events, &same.b_events] {
        assert!(events.contains(&TransferEvent::RangingStopped { session_id: 7 }));
    }
    same.a.start_ranging(&start(8), same.now)?;
    Ok(())
}

/// Each side has its own eight starts: a contact that pointed eight times
/// leaves this side its own.
#[test]
fn each_side_starts_eight() -> TestResult {
    let fixture = fixture()?;
    let mut link = link(&fixture)?;
    link.a.send_ranging_ready(READY)?;
    link.b.send_ranging_ready(READY)?;
    link.settle()?;
    for id in 1..=u32::from(MAX_STARTS) {
        link.b.start_ranging(&start(id), link.now)?;
        link.b.stop_ranging(id)?;
        link.settle()?;
    }
    link.a.start_ranging(&start(100), link.now)?;
    link.settle()?;
    Ok(())
}

/// Apple peer ranging: tokens instead of addresses, only toward a peer
/// that announced it, accepted once with the controlee's own token; an
/// accept of the other kind is STATE; the starts are the same eight.
#[test]
fn peer_ranging_runs_like_fira() -> TestResult {
    let fixture = fixture()?;
    let apple = RangingReady {
        configs: CONFIG_APPLE_PEER,
    };
    let peer = |session_id, byte| PeerRanging {
        session_id,
        token: vec![byte; 200],
    };
    let mut fira = link(&fixture)?;
    fira.b.send_ranging_ready(READY)?;
    fira.settle()?;
    // Bob ranges with FiRa only.
    assert_eq!(
        fira.a.start_peer_ranging(&peer(5, 1), fira.now),
        Err(RangingError::PeerNotReady)
    );
    let mut apple_link = link(&fixture)?;
    apple_link.b.send_ranging_ready(apple)?;
    apple_link.settle()?;
    assert_eq!(
        apple_link.a.start_ranging(&start(4), apple_link.now),
        Err(RangingError::PeerNotReady)
    );
    apple_link
        .a
        .start_peer_ranging(&peer(5, 1), apple_link.now)?;
    apple_link.settle()?;
    let requested = apple_link.b_events.iter().find_map(|event| match event {
        TransferEvent::PeerRangingRequested(start) => Some(start.clone()),
        _ => None,
    });
    assert_eq!(requested.as_deref(), Some(&peer(5, 1)));
    // A FiRa accept for it, or an empty token: refused.
    assert_eq!(
        apple_link.b.accept_ranging(5, 0x2222),
        Err(RangingError::NotRunning)
    );
    assert_eq!(
        apple_link.b.accept_peer_ranging(5, Vec::new()),
        Err(RangingError::Address)
    );
    apple_link.b.accept_peer_ranging(5, vec![2; 200])?;
    apple_link.settle()?;
    assert!(
        apple_link
            .a_events
            .contains(&TransferEvent::PeerRangingAccepted(Box::new(peer(5, 2))))
    );
    apple_link.a.stop_ranging(5)?;
    apple_link.settle()?;
    assert!(
        apple_link
            .b_events
            .contains(&TransferEvent::RangingStopped { session_id: 5 })
    );
    // From the peer: an accept of the other kind is STATE.
    let mut mixed = link(&fixture)?;
    mixed
        .a
        .handle_frame(FrameType::RANGING_READY, &apple.encode(), mixed.now)?;
    mixed.a.start_peer_ranging(&peer(6, 1), mixed.now)?;
    let fira_accept = RangingAccept {
        session_id: 6,
        controlee: 0x2222,
    }
    .encode();
    let result = mixed
        .a
        .handle_frame(FrameType::RANGING_ACCEPT, &fira_accept, mixed.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    // A peer start to a side that announced FiRa only: STATE.
    let mut fira_only = link(&fixture)?;
    fira_only.b.send_ranging_ready(READY)?;
    let result = fira_only.b.handle_frame(
        FrameType::PEER_RANGING_START,
        &peer(7, 1).encode(),
        fira_only.now,
    );
    assert_eq!(session_failure(result), Some(FailureCode::State));
    // Both kinds share the eight starts.
    let mut both = link(&fixture)?;
    both.b.send_ranging_ready(RangingReady {
        configs: CONFIG_APPLE_PEER | CONFIG_PROVISIONED_DS_TWR,
    })?;
    both.settle()?;
    for id in 1..=u32::from(MAX_STARTS) {
        if id % 2 == 0 {
            both.a.start_ranging(&start(id), both.now)?;
        } else {
            both.a.start_peer_ranging(&peer(id, 1), both.now)?;
        }
        both.a.stop_ranging(id)?;
    }
    assert_eq!(
        both.a.start_peer_ranging(&peer(99, 1), both.now),
        Err(RangingError::Busy)
    );
    Ok(())
}
