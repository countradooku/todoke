use core::time::Duration;
use std::net::SocketAddr;

use proptest::prelude::*;
use tokio::time::Instant;

use super::*;
use crate::sim::{Answer, Path, SimConnector};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const MS: Duration = Duration::from_millis(1);

fn v4(last: u8) -> SocketAddr {
    SocketAddr::from(([192, 168, 1, last], 45_000))
}

fn v6(last: u16) -> SocketAddr {
    SocketAddr::from((
        std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, last),
        45_000,
    ))
}

fn lan(address: SocketAddr) -> Candidate {
    Candidate::new(LinkKind::Simulated, address)
}

fn connects(setup_ms: u64) -> Answer {
    Answer::Connect {
        setup: MS * u32::try_from(setup_ms).unwrap_or(u32::MAX),
        path: Path::new(MS),
    }
}

/// When each attempt started, relative to `start`, by address.
fn starts(connector: &SimConnector, start: Instant) -> Vec<(SocketAddr, Duration)> {
    connector
        .attempts()
        .into_iter()
        .map(|(address, at)| (address, at - start))
        .collect()
}

#[tokio::test(start_paused = true)]
async fn the_first_candidate_to_connect_wins() -> TestResult {
    let connector = SimConnector::default();
    // The first candidate is slow; the second starts 250 ms in and
    // connects 10 ms later, long before the first.
    connector.answer(v6(1), connects(2_000));
    connector.answer(v4(2), connects(10));
    let start = Instant::now();
    let link = race(
        &connector,
        &[lan(v6(1)), lan(v4(2))],
        &RaceConfig::default(),
    )
    .await?;
    assert_eq!(link.info().remote(), Some(v4(2)));
    assert_eq!(start.elapsed(), MS * 260);
    assert_eq!(
        starts(&connector, start),
        vec![(v6(1), Duration::ZERO), (v4(2), MS * 250)]
    );
    // The losing attempt was dropped: only the winner's far end exists.
    let accepted = connector.accepted();
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted.first().map(|(address, _)| *address), Some(v4(2)));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_failure_starts_the_next_attempt_at_once() -> TestResult {
    let connector = SimConnector::default();
    connector.answer(v6(1), Answer::Refuse { after: MS * 20 });
    connector.answer(v4(1), Answer::Refuse { after: MS * 5 });
    connector.answer(v6(2), connects(30));
    let start = Instant::now();
    let link = race(
        &connector,
        &[lan(v6(1)), lan(v4(1)), lan(v6(2))],
        &RaceConfig::default(),
    )
    .await?;
    assert_eq!(link.info().remote(), Some(v6(2)));
    assert_eq!(
        starts(&connector, start),
        vec![(v6(1), Duration::ZERO), (v4(1), MS * 20), (v6(2), MS * 25),]
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn the_race_reports_every_failure_or_the_deadline() -> TestResult {
    let connector = SimConnector::default();
    connector.answer(v4(1), Answer::Refuse { after: MS });
    connector.answer(v4(2), Answer::Refuse { after: MS });
    let failed = race(
        &connector,
        &[lan(v4(1)), lan(v4(2))],
        &RaceConfig::default(),
    )
    .await;
    assert_eq!(
        failed.err(),
        Some(RaceError::Failed(vec![
            std::io::ErrorKind::ConnectionRefused,
            std::io::ErrorKind::ConnectionRefused
        ]))
    );
    // Silent candidates: the deadline ends the race.
    let start = Instant::now();
    let silent = race(&connector, &[lan(v4(9))], &RaceConfig::default()).await;
    assert_eq!(silent.err(), Some(RaceError::Timeout));
    assert_eq!(start.elapsed(), Duration::from_secs(5));
    assert_eq!(
        race(&connector, &[], &RaceConfig::default()).await.err(),
        Some(RaceError::NoCandidates)
    );
    Ok(())
}

/// At most four candidates are ever tried (§10), however many are offered.
#[tokio::test(start_paused = true)]
async fn at_most_four_candidates_are_tried() -> TestResult {
    let connector = SimConnector::default();
    let candidates: Vec<Candidate> = (1..=12).map(|n| lan(v4(n))).collect();
    for candidate in &candidates {
        connector.answer(candidate.address(), Answer::Refuse { after: MS });
    }
    let config = RaceConfig {
        max_candidates: 100,
        ..RaceConfig::default()
    };
    assert!(race(&connector, &candidates, &config).await.is_err());
    assert_eq!(connector.attempts().len(), MAX_CANDIDATES);
    Ok(())
}

#[test]
fn families_alternate_starting_with_ipv6_and_duplicates_go() {
    let given = [
        lan(v4(1)),
        lan(v4(2)),
        lan(v6(1)),
        lan(v4(1)),
        lan(v6(2)),
        lan(v4(3)),
    ];
    let ordered: Vec<SocketAddr> = order(&given, 10).iter().map(Candidate::address).collect();
    assert_eq!(ordered, vec![v6(1), v4(1), v6(2), v4(2)]);
    assert_eq!(order(&given, 1).len(), 1);
    assert_eq!(order(&given, 0).len(), 0);
}

#[test]
fn candidate_debug_output_hides_the_address() {
    let shown = format!("{:?}", lan(v4(77)));
    assert!(!shown.contains("192.168"), "{shown}");
}

proptest! {
    /// Ordering keeps a subset of the input without duplicates, bounded,
    /// alternating families while both remain.
    #[test]
    fn ordering_is_a_bounded_interleaving(
        picks in proptest::collection::vec((any::<bool>(), 1_u8..8), 0..20),
        max in 0_usize..8,
    ) {
        let given: Vec<Candidate> = picks
            .iter()
            .map(|(six, n)| lan(if *six { v6(u16::from(*n)) } else { v4(*n) }))
            .collect();
        let ordered = order(&given, max);
        prop_assert!(ordered.len() <= max.min(MAX_CANDIDATES));
        for (index, candidate) in ordered.iter().enumerate() {
            prop_assert!(given.contains(candidate));
            prop_assert!(!ordered[..index].contains(candidate));
        }
        let sixes = given.iter().filter(|c| c.address().is_ipv6()).count();
        if sixes > 0
            && let Some(first) = ordered.first()
        {
            prop_assert!(first.address().is_ipv6());
        }
    }
}
