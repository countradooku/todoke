//! The room table against §10's order and limits.

use std::time::{Duration, Instant};

use todoke_proto::relay::{Candidate, CloseCode, Random16, RendezvousToken};
use tokio::sync::mpsc;

use super::*;

type Table = Rooms<&'static str>;

fn table() -> Table {
    Rooms::new(Limits { max_rooms: 4 })
}

fn token(byte: u8) -> RendezvousToken {
    RendezvousToken::new([byte; 32]).unwrap_or_else(|_| unreachable!())
}

fn nonce(byte: u8) -> Random16 {
    Random16::new([byte; 16]).unwrap_or_else(|_| unreachable!())
}

fn channel() -> (mpsc::Sender<RoomEvent>, mpsc::Receiver<RoomEvent>) {
    mpsc::channel(8)
}

/// Two members of one token, matched.
type Matched = (
    Joined,
    Joined,
    mpsc::Receiver<RoomEvent>,
    mpsc::Receiver<RoomEvent>,
);

fn matched(rooms: &mut Table, now: Instant) -> Result<Matched, String> {
    let (first_tx, mut first_rx) = channel();
    let (second_tx, second_rx) = channel();
    let first = rooms
        .register(&token(1), nonce(1), 120, 1, first_tx, now)
        .map_err(|code| format!("{code:?}"))?;
    assert!(first.peer.is_none());
    let second = rooms
        .register(&token(1), nonce(2), 60, 2, second_tx, now)
        .map_err(|code| format!("{code:?}"))?;
    assert_eq!(second.peer, Some(nonce(1)));
    assert!(matches!(first_rx.try_recv(), Ok(RoomEvent::PeerReady(peer)) if peer == nonce(2)));
    Ok((first, second, first_rx, second_rx))
}

#[test]
fn two_members_match_and_a_third_is_refused() -> Result<(), String> {
    let now = Instant::now();
    let mut rooms = table();
    let (first, second, _, _) = matched(&mut rooms, now)?;
    assert_eq!(first.ticket.room, second.ticket.room);
    assert_eq!(first.expires_in, 120);
    // The second never gets more than it asked for.
    assert_eq!(second.expires_in, 60);
    let (third, _) = channel();
    assert_eq!(
        rooms.register(&token(1), nonce(3), 10, 3, third, now).err(),
        Some(CloseCode::Full)
    );
    assert_eq!(rooms.len(), 1);
    Ok(())
}

#[test]
fn an_endpoint_never_matches_itself_or_reuses_a_nonce() {
    let now = Instant::now();
    let mut rooms = table();
    let (a, _) = channel();
    rooms.register(&token(1), nonce(1), 10, 7, a, now).ok();
    let (b, _) = channel();
    assert_eq!(
        rooms.register(&token(1), nonce(2), 10, 7, b, now).err(),
        Some(CloseCode::Full)
    );
    let (c, _) = channel();
    assert_eq!(
        rooms.register(&token(1), nonce(1), 10, 8, c, now).err(),
        Some(CloseCode::Malformed)
    );
}

#[test]
fn the_wait_and_the_room_are_bounded() -> Result<(), String> {
    let now = Instant::now();
    let mut rooms = table();
    let (a, mut a_rx) = channel();
    let joined = rooms
        .register(&token(1), nonce(1), 120, 1, a, now)
        .map_err(|code| format!("{code:?}"))?;
    assert_eq!(joined.wait_until, now + Duration::from_secs(30));
    assert_eq!(joined.expires, now + Duration::from_secs(120));
    let (b, _) = channel();
    let short = rooms
        .register(&token(2), nonce(1), 5, 1, b, now)
        .map_err(|code| format!("{code:?}"))?;
    assert_eq!(short.wait_until, now + Duration::from_secs(5));
    rooms.expire(now + Duration::from_secs(119));
    assert_eq!(rooms.len(), 1);
    rooms.expire(now + Duration::from_secs(120));
    assert_eq!(rooms.len(), 0);
    assert!(matches!(
        a_rx.try_recv(),
        Ok(RoomEvent::Closed(CloseCode::Expired))
    ));
    // An expired token is free again.
    let (c, _) = channel();
    assert!(
        rooms
            .register(
                &token(1),
                nonce(9),
                10,
                1,
                c,
                now + Duration::from_secs(121)
            )
            .is_ok()
    );
    Ok(())
}

#[test]
fn the_table_has_a_room_limit() {
    let now = Instant::now();
    let mut rooms = table();
    for byte in 1..=4 {
        let (tx, _) = channel();
        assert!(
            rooms
                .register(&token(byte), nonce(1), 10, 1, tx, now)
                .is_ok()
        );
    }
    let (tx, _) = channel();
    assert_eq!(
        rooms.register(&token(5), nonce(1), 10, 1, tx, now).err(),
        Some(CloseCode::Unavailable)
    );
}

#[test]
fn candidates_pass_once_and_both_lead_to_a_punch() -> Result<(), String> {
    let now = Instant::now();
    let mut rooms = table();
    let (first, second, mut first_rx, mut second_rx) = matched(&mut rooms, now)?;
    let room = first.ticket.room;
    let candidate =
        Candidate::new(([198, 51, 100, 1], 4000).into()).unwrap_or_else(|_| unreachable!());
    assert!(
        rooms
            .candidates(first.ticket, room, vec![candidate])
            .is_ok()
    );
    assert!(
        matches!(second_rx.try_recv(), Ok(RoomEvent::Candidates(list)) if list == vec![candidate])
    );
    assert!(rooms.candidates(second.ticket, room, Vec::new()).is_ok());
    assert!(matches!(first_rx.try_recv(), Ok(RoomEvent::Candidates(list)) if list.is_empty()));
    let punch = |rx: &mut mpsc::Receiver<RoomEvent>| match rx.try_recv() {
        Ok(RoomEvent::Punch { nonce, delay_ms }) => Some((nonce, delay_ms)),
        _ => None,
    };
    let (a, b) = (punch(&mut first_rx), punch(&mut second_rx));
    assert!(a.is_some() && a == b);
    // A second Candidates closes the room for both.
    assert_eq!(
        rooms.candidates(first.ticket, room, Vec::new()),
        Err(CloseCode::Malformed)
    );
    assert!(matches!(
        second_rx.try_recv(),
        Ok(RoomEvent::Closed(CloseCode::Malformed))
    ));
    assert_eq!(rooms.len(), 0);
    Ok(())
}

#[test]
fn nothing_but_register_before_the_peer_is_ready() -> Result<(), String> {
    let now = Instant::now();
    let mut rooms = table();
    let (a, _) = channel();
    let joined = rooms
        .register(&token(1), nonce(1), 10, 1, a, now)
        .map_err(|code| format!("{code:?}"))?;
    assert!(
        rooms
            .candidates(joined.ticket, joined.ticket.room, Vec::new())
            .is_err()
    );
    let (b, _) = channel();
    let joined = rooms
        .register(&token(2), nonce(1), 10, 1, b, now)
        .map_err(|code| format!("{code:?}"))?;
    assert!(matches!(
        rooms.forward(joined.ticket, joined.ticket.room, "a"),
        Err((CloseCode::Malformed, "a"))
    ));
    assert_eq!(rooms.len(), 0);
    Ok(())
}

#[test]
fn both_forwards_hand_over_the_streams_and_end_the_room() -> Result<(), String> {
    let now = Instant::now();
    let mut rooms = table();
    let (first, second, _, _) = matched(&mut rooms, now)?;
    let room = first.ticket.room;
    assert!(matches!(
        rooms.forward(first.ticket, room, "first"),
        Ok(Forwarded::Waiting)
    ));
    // A wrong room ID is malformed.
    let wrong = nonce(0x55);
    assert!(rooms.forward(second.ticket, wrong, "x").is_err());
    let (first, second, _, _) = matched(&mut rooms, now)?;
    let room = first.ticket.room;
    assert!(matches!(
        rooms.forward(first.ticket, room, "first"),
        Ok(Forwarded::Waiting)
    ));
    assert!(matches!(
        rooms.forward(second.ticket, room, "second"),
        Ok(Forwarded::Tunnel {
            mine: "second",
            theirs: "first"
        })
    ));
    assert_eq!(rooms.len(), 0);
    // Nothing is left to withdraw.
    assert_eq!(rooms.withdraw(first.ticket, CloseCode::Expired), None);
    Ok(())
}

#[test]
fn a_waiting_member_can_take_its_streams_back() -> Result<(), String> {
    let now = Instant::now();
    let mut rooms = table();
    let (first, _, _, mut second_rx) = matched(&mut rooms, now)?;
    assert!(matches!(
        rooms.forward(first.ticket, first.ticket.room, "first"),
        Ok(Forwarded::Waiting)
    ));
    assert_eq!(
        rooms.withdraw(first.ticket, CloseCode::Expired),
        Some("first")
    );
    assert!(matches!(
        second_rx.try_recv(),
        Ok(RoomEvent::Closed(CloseCode::Expired))
    ));
    assert_eq!(rooms.len(), 0);
    Ok(())
}
