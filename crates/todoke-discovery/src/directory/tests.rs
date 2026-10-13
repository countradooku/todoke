use core::time::Duration;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use todoke_proto::discovery::{DiscoveryRecord, Epoch, MDNS_SERVICE};
use todoke_transport::LanPolicy;

use super::*;
use crate::support::{WALL, paired};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SECOND: Duration = Duration::from_secs(1);

fn label(n: u64) -> Result<InstanceLabel, Box<dyn std::error::Error>> {
    Ok(InstanceLabel::from_random((n + 1).to_be_bytes())?)
}

fn sighting(
    label: &InstanceLabel,
    record: &DiscoveryRecord,
    host: u8,
) -> Result<Sighting, Box<dyn std::error::Error>> {
    let value = record.txt_value();
    Ok(Sighting::check(
        &format!("{}.{MDNS_SERVICE}", label.as_str()),
        47_000,
        [(IpAddr::from(Ipv4Addr::new(192, 168, 1, host)), 1)],
        [("v1", Some(value.as_bytes()))],
        LanPolicy::new(),
    )?)
}

fn address(host: u8) -> SocketAddr {
    SocketAddr::from(([192, 168, 1, host], 47_000))
}

/// A contact's own advertisement is found; others are not stored.
#[tokio::test]
async fn sightings_of_contacts_are_kept_and_others_are_not() -> TestResult {
    let (alice, bob) = paired().await?;
    let table = alice.table(WALL)?;
    let bob_record = bob
        .table(WALL)?
        .advertisement(&alice.key())
        .ok_or("record")?;
    let mut directory = Directory::new();
    let now = SECOND * 100;
    assert_eq!(
        directory.observe(sighting(&label(1)?, &bob_record, 5)?, &table, now),
        Observed::Kept
    );
    let found = directory.contact(&bob.key(), now).ok_or("bob")?;
    assert_eq!(found.addresses(), &[address(5)]);
    assert_eq!(found.candidates().len(), 1);
    assert_eq!(directory.contacts(now).len(), 1);
    // A random paired token matches nobody and is not stored.
    let stranger_token = DiscoveryRecord::new(DiscoveryMode::Paired, table.epoch(), [0x42; 8])?;
    assert_eq!(
        directory.observe(sighting(&label(2)?, &stranger_token, 6)?, &table, now),
        Observed::Unmatched
    );
    // A stranger record is ignored unless stranger browsing is on.
    let stranger = DiscoveryRecord::new(DiscoveryMode::Stranger, table.epoch(), [0x43; 8])?;
    assert_eq!(
        directory.observe(sighting(&label(3)?, &stranger, 7)?, &table, now),
        Observed::Unmatched
    );
    directory.set_stranger_browsing(true);
    assert_eq!(
        directory.observe(sighting(&label(3)?, &stranger, 7)?, &table, now),
        Observed::Kept
    );
    let strangers = directory.strangers(now);
    assert_eq!(strangers.len(), 1);
    assert_eq!(strangers.first().map(|(token, _)| *token), Some([0x43; 8]));
    directory.set_stranger_browsing(false);
    assert_eq!(directory.strangers(now).len(), 0);
    Ok(())
}

/// §9: cached data expires within 120 seconds; a goodbye removes it at
/// once; a contact that leaves the table (revoked, blocked) goes too.
#[tokio::test]
async fn entries_expire_and_say_goodbye() -> TestResult {
    let (alice, bob) = paired().await?;
    let table = alice.table(WALL)?;
    let record = bob
        .table(WALL)?
        .advertisement(&alice.key())
        .ok_or("record")?;
    let mut directory = Directory::new();
    let start = SECOND * 1000;
    directory.observe(sighting(&label(1)?, &record, 5)?, &table, start);
    assert!(
        directory
            .contact(&bob.key(), start + CACHE_LIFETIME.saturating_sub(SECOND))
            .is_some()
    );
    assert!(
        directory
            .contact(&bob.key(), start + CACHE_LIFETIME)
            .is_none()
    );
    directory.expire(&table, start + CACHE_LIFETIME);
    assert_eq!(directory.contacts(start).len(), 0);
    // Seen again, then gone.
    directory.observe(sighting(&label(1)?, &record, 5)?, &table, start);
    directory.remove(&label(1)?);
    assert!(directory.contact(&bob.key(), start).is_none());
    // Dropped from the table: dropped here.
    directory.observe(sighting(&label(1)?, &record, 5)?, &table, start);
    let mut blocked = alice;
    blocked.store.mark_ratchet_uncertain(&bob.key())?;
    directory.expire(&blocked.table(WALL)?, start);
    assert!(directory.contact(&bob.key(), start).is_none());
    Ok(())
}

/// R1: copies of a contact's (public) record under other labels and
/// addresses cannot displace the instance that was there first; it stays
/// first among the candidates, and the copies beyond the bound are dropped.
#[tokio::test]
async fn copies_of_a_record_never_displace_the_first_instance() -> TestResult {
    let (alice, bob) = paired().await?;
    let table = alice.table(WALL)?;
    let record = bob
        .table(WALL)?
        .advertisement(&alice.key())
        .ok_or("record")?;
    let mut directory = Directory::new();
    assert_eq!(
        directory.observe(sighting(&label(0)?, &record, 10)?, &table, SECOND * 100),
        Observed::Kept
    );
    let mut outcomes = Vec::new();
    for n in 1..10_u8 {
        let now = Duration::from_secs(100 + u64::from(n));
        outcomes.push(directory.observe(
            sighting(&label(n.into())?, &record, 10 + n)?,
            &table,
            now,
        ));
    }
    assert_eq!(
        outcomes.iter().filter(|o| **o == Observed::Kept).count(),
        MAX_INSTANCES_PER_CONTACT - 1
    );
    assert_eq!(
        outcomes.iter().filter(|o| **o == Observed::Full).count(),
        10 - MAX_INSTANCES_PER_CONTACT
    );
    let found = directory.contact(&bob.key(), SECOND * 110).ok_or("bob")?;
    assert_eq!(
        found.addresses(),
        &[address(10), address(11), address(12), address(13)]
    );
    // The first instance refreshed from a new address keeps its place.
    directory.observe(sighting(&label(0)?, &record, 99)?, &table, SECOND * 111);
    let found = directory.contact(&bob.key(), SECOND * 111).ok_or("bob")?;
    assert_eq!(found.addresses().first(), Some(&address(99)));
    // Once the copies expire, a newcomer finds room again.
    for _ in 0..3 {
        directory.observe(sighting(&label(0)?, &record, 99)?, &table, SECOND * 230);
    }
    assert_eq!(
        directory.observe(sighting(&label(50)?, &record, 50)?, &table, SECOND * 231),
        Observed::Kept
    );
    assert_eq!(
        directory
            .contact(&bob.key(), SECOND * 231)
            .map(|r| r.addresses().to_vec()),
        Some(vec![address(99), address(50)])
    );
    Ok(())
}

/// R1: records that match no contact cost no matching budget, so a flood
/// of them cannot rate-limit a real contact's record.
#[tokio::test]
async fn unmatched_floods_do_not_starve_contacts() -> TestResult {
    let (alice, bob) = paired().await?;
    let table = alice.table(WALL)?;
    let mut directory = Directory::new();
    let now = SECOND * 300;
    for n in 0..500_u64 {
        let token = (n + 1).to_be_bytes();
        let junk = DiscoveryRecord::new(DiscoveryMode::Paired, table.epoch(), token)?;
        assert_eq!(
            directory.observe(sighting(&label(n)?, &junk, 7)?, &table, now),
            Observed::Unmatched
        );
    }
    let record = bob
        .table(WALL)?
        .advertisement(&alice.key())
        .ok_or("record")?;
    assert_eq!(
        directory.observe(sighting(&label(999)?, &record, 5)?, &table, now),
        Observed::Kept
    );
    Ok(())
}

/// A flood of stranger records keeps at most `MAX_STRANGERS`, and matching
/// stops at the per-second budget; own advertisements are never matched.
#[tokio::test]
async fn floods_are_bounded_and_own_records_ignored() -> TestResult {
    let (alice, bob) = paired().await?;
    let table = alice.table(WALL)?;
    let mut directory = Directory::new();
    directory.set_stranger_browsing(true);
    let now = SECOND * 500;
    let mut outcomes = Vec::new();
    for n in 0..200_u64 {
        let token = (n + 1).to_be_bytes();
        let record = DiscoveryRecord::new(DiscoveryMode::Stranger, Epoch::new(1)?, token)?;
        let host = u8::try_from(n % 200 + 1)?;
        outcomes.push(directory.observe(sighting(&label(n)?, &record, host)?, &table, now));
    }
    let kept = outcomes.iter().filter(|o| **o == Observed::Kept).count();
    let limited = outcomes
        .iter()
        .filter(|o| **o == Observed::RateLimited)
        .count();
    assert_eq!(kept, usize::try_from(MAX_SIGHTINGS_PER_SECOND)?);
    assert_eq!(limited, 200 - kept);
    assert_eq!(directory.strangers(now).len(), MAX_STRANGERS);
    // The next second has a fresh budget.
    let record = bob
        .table(WALL)?
        .advertisement(&alice.key())
        .ok_or("record")?;
    assert_eq!(
        directory.observe(sighting(&label(500)?, &record, 5)?, &table, now + SECOND),
        Observed::Kept
    );
    // Our own label, even with a matching record: never a candidate.
    directory.set_own(vec![label(500)?, label(501)?]);
    assert!(directory.contact(&bob.key(), now + SECOND).is_none());
    assert_eq!(
        directory.observe(sighting(&label(501)?, &record, 6)?, &table, now + SECOND),
        Observed::Own
    );
    Ok(())
}

#[tokio::test]
async fn debug_output_hides_addresses() -> TestResult {
    let (alice, bob) = paired().await?;
    let table = alice.table(WALL)?;
    let record = bob
        .table(WALL)?
        .advertisement(&alice.key())
        .ok_or("record")?;
    let mut directory = Directory::new();
    directory.observe(sighting(&label(1)?, &record, 5)?, &table, SECOND);
    let shown = format!("{directory:?} {:?}", directory.contact(&bob.key(), SECOND));
    assert!(!shown.contains("192.168"), "{shown}");
    Ok(())
}
