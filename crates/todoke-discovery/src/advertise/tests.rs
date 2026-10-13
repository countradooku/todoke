use core::time::Duration;

use todoke_proto::discovery::EPOCH_SECONDS;

use super::*;
use crate::support::{WALL, paired, time};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SECOND: Duration = Duration::from_secs(1);

/// Deterministic "randomness": a counter.
struct Counter(u64);

impl Random for Counter {
    fn bytes(&mut self) -> Option<[u8; 8]> {
        self.0 += 1;
        Some(self.0.to_be_bytes())
    }
}

struct Empty;

impl Random for Empty {
    fn bytes(&mut self) -> Option<[u8; 8]> {
        None
    }
}

#[tokio::test]
async fn the_contact_record_is_advertised_under_an_epoch_label() -> TestResult {
    let (alice, bob) = paired().await?;
    let table = alice.table(WALL)?;
    let mut random = Counter(0);
    let mut advertiser = Advertiser::new();
    let plan = advertiser.plan(&table, None, time(WALL)?, SECOND, &mut random);
    let paired = plan.paired.ok_or("paired")?;
    assert_eq!(Some(paired.record), table.advertisement(&bob.key()));
    assert_eq!(plan.stranger, None);
    // The same label all epoch long; a new one at the next epoch.
    let later = advertiser.plan(&table, None, time(WALL + 30)?, SECOND * 31, &mut random);
    assert_eq!(later.paired.map(|a| a.label), Some(paired.label));
    let boundary = (WALL / EPOCH_SECONDS + 1) * EPOCH_SECONDS;
    let next_table = alice.table(boundary)?;
    let next = advertiser.plan(
        &next_table,
        None,
        time(boundary)?,
        SECOND * 900,
        &mut random,
    );
    let next = next.paired.ok_or("paired")?;
    assert_ne!(next.label, paired.label);
    assert_eq!(Some(next.record), next_table.advertisement(&bob.key()));
    assert_ne!(next.record, paired.record);
    assert_eq!(plan.labels(), vec![paired.label]);
    // R1: the old table is not used past its epoch.
    let stale = advertiser.plan(&table, None, time(boundary)?, SECOND * 901, &mut random);
    assert_eq!(stale.paired, None);
    Ok(())
}

#[tokio::test]
async fn nothing_is_advertised_without_contacts_or_randomness() -> TestResult {
    let (mut alice, bob) = paired().await?;
    let mut advertiser = Advertiser::new();
    let table = alice.table(WALL)?;
    assert_eq!(
        advertiser.plan(&table, None, time(WALL)?, SECOND, &mut Empty),
        Plan::default()
    );
    alice.store.mark_ratchet_uncertain(&bob.key())?;
    let empty = alice.table(WALL)?;
    assert_eq!(
        advertiser.plan(&empty, None, time(WALL)?, SECOND, &mut Counter(0)),
        Plan::default()
    );
    assert!(!advertiser.enable_stranger(time(WALL)?, SECOND, &mut Empty));
    Ok(())
}

/// A priority contact gets every other slot; with one contact it is the
/// only record anyway, and an unknown priority changes nothing.
#[tokio::test]
async fn a_priority_contact_takes_even_slots() -> TestResult {
    let (alice, bob) = paired().await?;
    let table = alice.table(WALL)?;
    let mut advertiser = Advertiser::new();
    let mut random = Counter(0);
    for slot in 0..6_u64 {
        let mono = ROTATION * u32::try_from(slot)?;
        let plan = advertiser.plan(&table, Some(&bob.key()), time(WALL)?, mono, &mut random);
        assert_eq!(
            plan.paired.map(|a| a.record),
            table.advertisement(&bob.key())
        );
        let unknown = advertiser.plan(&table, Some(&alice.key()), time(WALL)?, mono, &mut random);
        assert_eq!(unknown.paired, plan.paired);
    }
    Ok(())
}

/// §9: stranger mode only after an explicit enable, at most 300 seconds,
/// a fresh token and label every 60 seconds, no identity.
#[tokio::test]
async fn stranger_mode_is_explicit_short_and_rotating() -> TestResult {
    let (alice, _) = paired().await?;
    let table = alice.table(WALL)?;
    let mut advertiser = Advertiser::new();
    let mut random = Counter(0);
    let wall = time(WALL)?;
    assert_eq!(
        advertiser
            .plan(&table, None, wall, SECOND, &mut random)
            .stranger,
        None
    );
    let start = SECOND * 50;
    assert!(advertiser.enable_stranger(wall, start, &mut random));
    let first = advertiser
        .plan(&table, None, wall, start, &mut random)
        .stranger
        .ok_or("stranger")?;
    assert_eq!(first.record.mode(), DiscoveryMode::Stranger);
    let paired = advertiser
        .plan(&table, None, wall, start, &mut random)
        .paired
        .ok_or("paired")?;
    assert_ne!(first.label, paired.label);
    assert_ne!(first.record.token(), paired.record.token());
    let same = advertiser.plan(&table, None, wall, start + SECOND * 59, &mut random);
    assert_eq!(same.stranger, Some(first));
    let rotated = advertiser
        .plan(&table, None, wall, start + STRANGER_ROTATION, &mut random)
        .stranger
        .ok_or("stranger")?;
    assert_ne!(rotated.label, first.label);
    assert_ne!(rotated.record.token(), first.record.token());
    let mut seen = vec![first, rotated];
    let mut mono = start + STRANGER_ROTATION;
    while mono + SECOND < start + STRANGER_LIFETIME {
        mono += SECOND * 10;
        if let Some(advertisement) = advertiser
            .plan(&table, None, wall, mono, &mut random)
            .stranger
            && !seen.contains(&advertisement)
        {
            seen.push(advertisement);
        }
    }
    assert_eq!(seen.len(), 5);
    let expired = advertiser.plan(&table, None, wall, start + STRANGER_LIFETIME, &mut random);
    assert_eq!(expired.stranger, None);
    assert!(!advertiser.stranger_enabled());
    // Disabling ends it at once.
    assert!(advertiser.enable_stranger(wall, mono, &mut random));
    advertiser.disable_stranger();
    assert_eq!(
        advertiser
            .plan(&table, None, wall, mono, &mut random)
            .stranger,
        None
    );
    Ok(())
}
