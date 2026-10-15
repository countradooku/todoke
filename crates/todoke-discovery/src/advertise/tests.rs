use core::time::Duration;
use std::collections::BTreeMap;

use todoke_proto::discovery::EPOCH_SECONDS;

use super::*;
use crate::support::{WALL, paired, qr_stranger, time};

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
    let plan = advertiser.plan(&table, time(WALL)?, SECOND, &mut random);
    let paired = plan.paired.ok_or("paired")?;
    assert_eq!(Some(paired.record), table.advertisement(&bob.key()));
    assert_eq!(plan.stranger, None);
    // The same label all epoch long; a new one at the next epoch.
    let later = advertiser.plan(&table, time(WALL + 30)?, SECOND * 31, &mut random);
    assert_eq!(later.paired.map(|a| a.label), Some(paired.label));
    let boundary = (WALL / EPOCH_SECONDS + 1) * EPOCH_SECONDS;
    let next_table = alice.table(boundary)?;
    let next = advertiser.plan(&next_table, time(boundary)?, SECOND * 900, &mut random);
    let next = next.paired.ok_or("paired")?;
    assert_ne!(next.label, paired.label);
    assert_eq!(Some(next.record), next_table.advertisement(&bob.key()));
    assert_ne!(next.record, paired.record);
    assert_eq!(plan.labels(), vec![paired.label]);
    // R1: the old table is not used past its epoch.
    let stale = advertiser.plan(&table, time(boundary)?, SECOND * 901, &mut random);
    assert_eq!(stale.paired, None);
    Ok(())
}

#[tokio::test]
async fn nothing_is_advertised_without_contacts_or_randomness() -> TestResult {
    let (mut alice, bob) = paired().await?;
    let mut advertiser = Advertiser::new();
    let table = alice.table(WALL)?;
    assert_eq!(
        advertiser.plan(&table, time(WALL)?, SECOND, &mut Empty),
        Plan::default()
    );
    alice.store.mark_ratchet_uncertain(&bob.key())?;
    let empty = alice.table(WALL)?;
    assert_eq!(
        advertiser.plan(&empty, time(WALL)?, SECOND, &mut Counter(0)),
        Plan::default()
    );
    assert!(!advertiser.enable_stranger(time(WALL)?, SECOND, &mut Empty));
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
        advertiser.plan(&table, wall, SECOND, &mut random).stranger,
        None
    );
    let start = SECOND * 50;
    assert!(advertiser.enable_stranger(wall, start, &mut random));
    let first = advertiser
        .plan(&table, wall, start, &mut random)
        .stranger
        .ok_or("stranger")?;
    assert_eq!(first.record.mode(), DiscoveryMode::Stranger);
    let paired = advertiser
        .plan(&table, wall, start, &mut random)
        .paired
        .ok_or("paired")?;
    assert_ne!(first.label, paired.label);
    assert_ne!(first.record.token(), paired.record.token());
    let same = advertiser.plan(&table, wall, start + SECOND * 59, &mut random);
    assert_eq!(same.stranger, Some(first));
    let rotated = advertiser
        .plan(&table, wall, start + STRANGER_ROTATION, &mut random)
        .stranger
        .ok_or("stranger")?;
    assert_ne!(rotated.label, first.label);
    assert_ne!(rotated.record.token(), first.record.token());
    let mut seen = vec![first, rotated];
    let mut mono = start + STRANGER_ROTATION;
    while mono + SECOND < start + STRANGER_LIFETIME {
        mono += SECOND * 10;
        if let Some(advertisement) = advertiser.plan(&table, wall, mono, &mut random).stranger
            && !seen.contains(&advertisement)
        {
            seen.push(advertisement);
        }
    }
    assert_eq!(seen.len(), 5);
    let expired = advertiser.plan(&table, wall, start + STRANGER_LIFETIME, &mut random);
    assert_eq!(expired.stranger, None);
    assert!(!advertiser.stranger_enabled());
    // Disabling ends it at once.
    assert!(advertiser.enable_stranger(wall, mono, &mut random));
    advertiser.disable_stranger();
    assert_eq!(
        advertiser.plan(&table, wall, mono, &mut random).stranger,
        None
    );
    Ok(())
}

/// §9: while a QR is shown, the stranger token is the QR's token for the
/// current minute, which its scanner recognises: the same all minute, a
/// new one under a new label at each minute boundary; stranger mode still
/// ends after 300 seconds, and early once the wall clock leaves the
/// offer's minutes.
#[test]
fn a_shown_qr_advertises_its_token_for_each_minute() -> TestResult {
    let (key, tokens, table) = qr_stranger(WALL)?;
    let mut advertiser = Advertiser::new();
    let mut random = Counter(0);
    let start = SECOND * 50;
    let minute_start = WALL / 60 * 60;
    assert!(advertiser.enable_qr_stranger(tokens.clone(), time(WALL)?, start, &mut random));
    let mut plan = |advertiser: &mut Advertiser, wall: u64, mono: Duration| {
        time(wall).map(|wall| advertiser.plan(&table, wall, mono, &mut random).stranger)
    };
    let first = plan(&mut advertiser, WALL, start)?.ok_or("stranger")?;
    assert_eq!(first.record.mode(), DiscoveryMode::Stranger);
    assert!(key.matches(first.record.token(), time(WALL)?));
    // Unchanged until the minute ends, however long that is in `mono`.
    let same = plan(&mut advertiser, minute_start + 59, start + SECOND * 59)?;
    assert_eq!(same, Some(first));
    let next = plan(&mut advertiser, minute_start + 60, start + SECOND * 60)?.ok_or("next")?;
    assert_ne!(next.label, first.label);
    assert_ne!(next.record.token(), first.record.token());
    assert_eq!(
        Some(*next.record.token()),
        tokens.at(time(minute_start + 60)?)
    );
    assert!(key.matches(next.record.token(), time(minute_start + 60)?));
    // The lifetime still ends it.
    assert_eq!(
        plan(&mut advertiser, WALL + 300, start + STRANGER_LIFETIME)?,
        None
    );
    assert!(!advertiser.stranger_enabled());
    // A wall clock outside the offer's minutes ends it too, and cannot
    // start it.
    assert!(advertiser.enable_qr_stranger(tokens.clone(), time(WALL)?, start, &mut Counter(99)));
    assert_eq!(plan(&mut advertiser, WALL + 3600, start + SECOND)?, None);
    assert!(!advertiser.stranger_enabled());
    assert!(!advertiser.enable_qr_stranger(tokens, time(WALL - 3600)?, start, &mut Counter(99)));
    Ok(())
}

/// Randomness that hands out a fixed script, then nothing.
struct Script(Vec<[u8; 8]>);

impl Random for Script {
    fn bytes(&mut self) -> Option<[u8; 8]> {
        (!self.0.is_empty()).then(|| self.0.remove(0))
    }
}

/// `SplitMix64`: deterministic, well-mixed bytes, so the statistical tests
/// below give the same verdict on every run.
struct SplitMix(u64);

impl Random for SplitMix {
    fn bytes(&mut self) -> Option<[u8; 8]> {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        Some((z ^ (z >> 31)).to_be_bytes())
    }
}

/// The contact whose record `record` is.
fn whose(
    table: &DiscoveryTable,
    record: Option<DiscoveryRecord>,
) -> Result<Ed25519PublicKey, Box<dyn std::error::Error>> {
    let record = record.ok_or("nothing advertised")?;
    table
        .contacts()
        .find(|contact| table.advertisement(contact) == Some(record))
        .copied()
        .ok_or_else(|| "a record of nobody".into())
}

/// Each turn from the start: the contact shown, and for how long, asking
/// exactly when each turn ends.
fn turns(
    advertiser: &mut Advertiser,
    table: &DiscoveryTable,
    wall: UnixTime,
    count: usize,
    random: &mut impl Random,
) -> Result<Vec<(Ed25519PublicKey, Duration)>, Box<dyn std::error::Error>> {
    let mut mono = Duration::ZERO;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let plan = advertiser.plan(table, wall, mono, random);
        let until = advertiser.rotation.until;
        out.push((
            whose(table, plan.paired.map(|a| a.record))?,
            until.saturating_sub(mono),
        ));
        mono = until;
    }
    Ok(out)
}

/// §9 rotation, randomised: every round shows each contact exactly once,
/// all six orders of three contacts come up about equally often (a
/// chi-square test, 5 degrees of freedom, against 30: p < 2e-5), and each
/// record stays up between 2 and 4 seconds, about 3 on average and
/// spreading over the whole range.
#[test]
fn rounds_show_every_contact_once_in_a_random_order_for_a_random_time() -> TestResult {
    let fixture = crate::support::fixture()?;
    let table = fixture.tables.first().ok_or("table")?;
    let wall = time(*fixture.walls.first().ok_or("wall")?)?;
    let mut contacts: Vec<Ed25519PublicKey> = table.contacts().copied().collect();
    contacts.sort();
    assert_eq!(contacts.len(), 3);
    let rounds = 6000;
    let turns = turns(
        &mut Advertiser::new(),
        table,
        wall,
        rounds * 3,
        &mut SplitMix(1),
    )?;
    let mut orders: BTreeMap<Vec<usize>, u32> = BTreeMap::new();
    for round in turns.chunks(3) {
        let mut order = Vec::new();
        for (device, _) in round {
            order.push(contacts.binary_search(device).map_err(|_| "unknown")?);
        }
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, [0, 1, 2], "a round is not a permutation");
        *orders.entry(order).or_default() += 1;
    }
    assert_eq!(orders.len(), 6);
    let expected = f64::from(u32::try_from(rounds)?) / 6.0;
    let chi_square: f64 = orders
        .values()
        .map(|&seen| (f64::from(seen) - expected).powi(2) / expected)
        .sum();
    assert!(
        chi_square < 30.0,
        "orders are skewed: chi-square {chi_square}"
    );

    let dwells: Vec<Duration> = turns.iter().map(|(_, dwell)| *dwell).collect();
    assert!(
        dwells
            .iter()
            .all(|dwell| (ROTATION_MIN..=ROTATION_MAX).contains(dwell))
    );
    let mean = dwells.iter().sum::<Duration>() / u32::try_from(dwells.len())?;
    assert!(
        mean.abs_diff(Duration::from_secs(3)) < Duration::from_millis(30),
        "{mean:?}"
    );
    assert!(
        dwells
            .iter()
            .any(|dwell| *dwell < ROTATION_MIN + Duration::from_millis(50))
    );
    assert!(
        dwells
            .iter()
            .any(|dwell| *dwell > ROTATION_MAX.saturating_sub(Duration::from_millis(50)))
    );
    Ok(())
}

/// A contact that leaves the table (ratchet-uncertain) is replaced at once,
/// and never shown again while it is out.
#[test]
fn a_contact_that_leaves_is_not_shown() -> TestResult {
    let fixture = crate::support::fixture()?;
    let full = fixture.tables.first().ok_or("table")?;
    let gone = *fixture.contacts.first().ok_or("contact")?;
    assert!(fixture.reduced.advertisement(&gone).is_none());
    let wall = time(*fixture.walls.first().ok_or("wall")?)?;
    let mut advertiser = Advertiser::new();
    let mut random = SplitMix(4);
    // Turn until the leaving contact is shown, then switch tables.
    let mut mono = Duration::ZERO;
    loop {
        let plan = advertiser.plan(full, wall, mono, &mut random);
        if whose(full, plan.paired.map(|a| a.record))? == gone {
            break;
        }
        mono = advertiser.rotation.until;
    }
    for _ in 0..30 {
        let plan = advertiser.plan(&fixture.reduced, wall, mono, &mut random);
        assert_ne!(
            whose(&fixture.reduced, plan.paired.map(|a| a.record))?,
            gone
        );
        mono = advertiser.rotation.until;
    }
    Ok(())
}

/// A source that fails between the dwell and the shuffle changes nothing:
/// the round and the record shown stay as they were, and the next plan
/// with randomness carries on from there.
#[test]
fn a_failing_source_leaves_the_round_intact() -> TestResult {
    let fixture = crate::support::fixture()?;
    let table = fixture.tables.first().ok_or("table")?;
    let wall = time(*fixture.walls.first().ok_or("wall")?)?;
    let mut advertiser = Advertiser::new();
    let mut random = SplitMix(5);
    advertiser.plan(table, wall, Duration::ZERO, &mut random);
    // Run to the last turn of the round, so the next turn needs a shuffle.
    while !advertiser.rotation.left.is_empty() {
        let next = advertiser.rotation.until;
        advertiser.plan(table, wall, next, &mut random);
    }
    let shown = advertiser.rotation.shown;
    let mut mono = advertiser.rotation.until;
    // Enough for the dwell, then nothing for the shuffle.
    let plan = advertiser.plan(table, wall, mono, &mut Script(vec![[1; 8]]));
    assert_eq!(plan.paired, None);
    assert_eq!(advertiser.rotation.shown, shown);
    assert_eq!(advertiser.rotation.left.len(), 0);
    // With randomness again: a whole new round.
    let mut seen = Vec::new();
    for _ in 0..3 {
        let plan = advertiser.plan(table, wall, mono, &mut random);
        seen.push(whose(table, plan.paired.map(|a| a.record))?);
        mono = advertiser.rotation.until;
    }
    seen.sort();
    let mut all: Vec<Ed25519PublicKey> = table.contacts().copied().collect();
    all.sort();
    assert_eq!(seen, all);
    Ok(())
}

/// A clock that goes back ends the turn rather than stretching it, and
/// `next_change` says when the record changes (never a time already past).
#[test]
fn turns_end_on_time_and_never_stretch() -> TestResult {
    let fixture = crate::support::fixture()?;
    let table = fixture.tables.first().ok_or("table")?;
    let wall = time(*fixture.walls.first().ok_or("wall")?)?;
    let mut advertiser = Advertiser::new();
    assert_eq!(advertiser.next_change(Duration::ZERO), None);
    let mut random = SplitMix(6);
    let start = SECOND * 100;
    advertiser.plan(table, wall, start, &mut random);
    let until = advertiser.rotation.until;
    assert_eq!(advertiser.next_change(start), Some(until));
    assert_eq!(advertiser.next_change(until), None);
    // Back in time: a new turn starts there, at most 4 seconds long.
    let back = SECOND * 50;
    advertiser.plan(table, wall, back, &mut random);
    assert_eq!(advertiser.rotation.since, back);
    assert!(advertiser.rotation.until <= back + ROTATION_MAX);
    // Near the end of the clock's range: no overflow.
    advertiser.plan(table, wall, Duration::MAX, &mut random);
    assert_eq!(advertiser.rotation.until, Duration::MAX);
    Ok(())
}

/// Debug output shows neither contacts nor tokens, only counts.
#[test]
fn debug_output_hides_the_contacts() -> TestResult {
    let fixture = crate::support::fixture()?;
    let table = fixture.tables.first().ok_or("table")?;
    let wall = time(*fixture.walls.first().ok_or("wall")?)?;
    let mut advertiser = Advertiser::new();
    advertiser.plan(table, wall, Duration::ZERO, &mut SplitMix(7));
    advertiser.enable_stranger(wall, Duration::ZERO, &mut SplitMix(8));
    let text = format!("{advertiser:?}");
    for contact in table.contacts() {
        // A key's own Debug output is its full hex.
        assert!(!text.contains(&format!("{contact:?}")), "{text}");
    }
    assert!(text.contains("left_in_round: 2"), "{text}");
    Ok(())
}

/// Rejection sampling: a source that only gives rejected values ends in
/// `None` rather than a hang, and a value just below the zone is accepted.
#[test]
fn uniform_draws_reject_the_partial_run() {
    // For bound 3, u64::MAX % 3 == 0, so the zone is u64::MAX: only
    // u64::MAX itself is rejected.
    let mut rejected = Script(vec![[0xff; 8]; 64]);
    assert_eq!(below(3, &mut rejected), None);
    let mut accepted = Script(vec![[0xff; 8], (u64::MAX - 1).to_be_bytes()]);
    assert_eq!(below(3, &mut accepted), Some((u64::MAX - 1) % 3));
    assert_eq!(below(1, &mut Counter(0)), Some(0));
}

/// R3: no randomness when a stranger token is due to rotate ends stranger
/// mode rather than keep the old token; a token or label the OS could not
/// supply (all-zero bytes, or none for the label) starts nothing.
#[tokio::test]
async fn stranger_mode_stops_without_randomness() -> TestResult {
    let (alice, _) = paired().await?;
    let table = alice.table(WALL)?;
    let wall = time(WALL)?;
    let mut advertiser = Advertiser::new();
    assert!(advertiser.enable_stranger(wall, SECOND, &mut Counter(0)));
    let rotated = advertiser.plan(&table, wall, SECOND * 61, &mut Empty);
    assert_eq!(rotated.stranger, None);
    assert!(!advertiser.stranger_enabled());
    // A token but no label.
    assert!(!advertiser.enable_stranger(wall, SECOND, &mut Script(vec![[1; 8]])));
    // A zero token: no valid record.
    assert!(!advertiser.enable_stranger(wall, SECOND, &mut Script(vec![[0; 8], [1; 8]])));
    // A zero label.
    assert!(!advertiser.enable_stranger(wall, SECOND, &mut Script(vec![[1; 8], [0; 8]])));
    // A failed enable turns an earlier stranger mode off too.
    assert!(advertiser.enable_stranger(wall, SECOND, &mut Counter(0)));
    assert!(!advertiser.enable_stranger(wall, SECOND, &mut Empty));
    assert!(!advertiser.stranger_enabled());
    // A zero paired label: nothing paired.
    let mut fresh = Advertiser::new();
    assert_eq!(
        fresh
            .plan(&table, wall, SECOND, &mut Script(vec![[0; 8]]))
            .paired,
        None
    );
    Ok(())
}

#[test]
fn os_randomness_gives_distinct_labels() -> TestResult {
    let (a, b) = (OsRandom.bytes().ok_or("os")?, OsRandom.bytes().ok_or("os")?);
    assert_ne!(a, b);
    Ok(())
}

mod model {
    //! R3: a property test of the advertising schedule. Stranger mode is
    //! checked against a model of its timing only (when it starts, rotates,
    //! and ends); the paired record against properties that hold whatever
    //! the random values are, so the test is no copy of the schedule.

    use proptest::prelude::*;

    use super::*;
    use crate::support::fixture;

    /// Well-spread randomness (`SplitMix64` from a generated seed) that can
    /// be switched off.
    struct Switchable {
        source: SplitMix,
        off: bool,
    }

    impl Random for Switchable {
        fn bytes(&mut self) -> Option<[u8; 8]> {
            if self.off {
                return None;
            }
            self.source.bytes()
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum Table {
        /// The table for the wall clock's epoch, if the fixture has one.
        Current,
        /// One contact fewer (ratchet-uncertain), for `WALL`'s epoch.
        Reduced,
        /// One for another epoch.
        Stale,
        /// One without contacts.
        Empty,
    }

    #[derive(Clone, Debug)]
    enum Op {
        Plan {
            mono_ms: u64,
            wall: u64,
            table: Table,
        },
        Enable {
            mono_ms: u64,
        },
        Disable,
        Randomness(bool),
    }

    fn step() -> impl Strategy<Value = u64> {
        proptest::sample::select(vec![
            0_u64, 1, 500, 1_999, 2_000, 2_001, 3_000, 3_999, 4_000, 4_001, 30_000, 59_999, 60_000,
            240_000, 299_999, 300_000,
        ])
    }

    fn op() -> impl Strategy<Value = Op> {
        let table = prop_oneof![
            5 => Just(Table::Current),
            2 => Just(Table::Reduced),
            1 => Just(Table::Stale),
            1 => Just(Table::Empty),
        ];
        prop_oneof![
            8 => (step(), proptest::sample::select(vec![0_u64, 1, 100, 450, 899, 900]), table)
                .prop_map(|(mono_ms, wall, table)| Op::Plan { mono_ms, wall, table }),
            2 => step().prop_map(|mono_ms| Op::Enable { mono_ms }),
            1 => Just(Op::Disable),
            1 => any::<bool>().prop_map(Op::Randomness),
        ]
    }

    /// Stranger mode's timing (§9): on from an enable, a new record every
    /// 60 seconds, off at 300 seconds or when a rotation finds no
    /// randomness.
    #[derive(Default)]
    struct Stranger {
        on: Option<(Duration, Duration)>,
        last: Option<Advertisement>,
    }

    impl Stranger {
        /// What the plan at `mono` must show: `Ok(None)` nothing,
        /// `Ok(Some(last))` the same record, `Err(())` a new one.
        fn expect(
            &mut self,
            mono: Duration,
            random_off: bool,
        ) -> Result<Option<Advertisement>, ()> {
            let Some((started, rotated)) = self.on else {
                return Ok(None);
            };
            if mono.saturating_sub(started) >= STRANGER_LIFETIME {
                self.on = None;
                return Ok(None);
            }
            if mono.saturating_sub(rotated) >= STRANGER_ROTATION {
                if random_off {
                    self.on = None;
                    return Ok(None);
                }
                self.on = Some((started, mono));
                return Err(());
            }
            Ok(self.last)
        }
    }

    fn fail(error: impl core::fmt::Display) -> TestCaseError {
        TestCaseError::fail(error.to_string())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// R3: whatever the random values, through table changes and
        /// randomness failures:
        /// - nothing paired from a stale or empty table;
        /// - a paired record is a listed contact's, for the current epoch,
        ///   under one label per epoch that no other epoch reuses;
        /// - a record stays until its time is up (unless its contact left),
        ///   each turn lasts 2 to 4 seconds, and `next_change` says when;
        /// - without randomness no new contact is shown;
        /// - stranger mode follows its timing model, never shares the
        ///   paired label, and never outlives 300 seconds.
        #[test]
        fn the_schedule_keeps_its_properties(
            seed in any::<u64>(),
            ops in proptest::collection::vec(op(), 1..60),
        ) {
            let fixture = fixture().map_err(fail)?;
            let first_wall = *fixture.walls.first().ok_or_else(|| fail("wall"))?;
            let mut advertiser = Advertiser::new();
            let mut random = Switchable { source: SplitMix(seed), off: false };
            let mut stranger = Stranger::default();
            let (mut mono, mut wall) = (Duration::ZERO, first_wall + 10);
            let mut labels: Vec<(Epoch, InstanceLabel)> = Vec::new();
            for op in ops {
                match op {
                    Op::Plan { mono_ms, wall: dw, table } => {
                        mono += Duration::from_millis(mono_ms);
                        wall += dw;
                        let now = time(wall).map_err(fail)?;
                        let current = fixture.tables.iter().find(|t| !t.is_stale(now));
                        let table = match table {
                            Table::Current => current.unwrap_or(&fixture.reduced),
                            Table::Reduced => &fixture.reduced,
                            Table::Stale => fixture
                                .tables
                                .iter()
                                .find(|t| t.is_stale(now))
                                .ok_or_else(|| fail("stale table"))?,
                            Table::Empty => &fixture.empty,
                        };
                        let before = advertiser.rotation.clone();
                        let plan = advertiser.plan(table, now, mono, &mut random);
                        let after = &advertiser.rotation;

                        if table.is_stale(now) || table.is_empty() {
                            prop_assert_eq!(plan.paired, None);
                        }
                        if let Some(paired) = plan.paired {
                            let shown = after.shown.ok_or_else(|| fail("shown"))?;
                            prop_assert_eq!(table.advertisement(&shown), Some(paired.record));
                            prop_assert_eq!(paired.record.mode(), DiscoveryMode::Paired);
                            prop_assert_eq!(paired.record.epoch(), Epoch::of(now));
                            for (epoch, label) in &labels {
                                prop_assert_eq!(*epoch == Epoch::of(now), *label == paired.label);
                            }
                            if !labels.contains(&(Epoch::of(now), paired.label)) {
                                labels.push((Epoch::of(now), paired.label));
                            }
                            let kept = before.shown.is_some_and(|previous| {
                                previous == shown
                                    && (before.since..before.until).contains(&mono)
                            });
                            let due = before.shown.is_none_or(|previous| {
                                !(before.since..before.until).contains(&mono)
                                    || table.advertisement(&previous).is_none()
                            });
                            // Kept while not due; a new turn only when due.
                            prop_assert!(kept != due, "kept {} due {}", kept, due);
                            if due {
                                prop_assert!(!random.off, "a new turn without randomness");
                                prop_assert_eq!(after.since, mono);
                                let dwell = after.until.saturating_sub(after.since);
                                prop_assert!((ROTATION_MIN..=ROTATION_MAX).contains(&dwell));
                            }
                            prop_assert_eq!(advertiser.next_change(mono), Some(after.until));
                        }

                        let expected = stranger.expect(mono, random.off);
                        match (expected, plan.stranger) {
                            (Ok(None), None) => {}
                            (Ok(Some(last)), Some(now_shown)) => prop_assert_eq!(last, now_shown),
                            (Err(()), Some(fresh)) => {
                                prop_assert!(stranger.last != Some(fresh), "no new stranger record");
                            }
                            (expected, got) => {
                                return Err(fail(format!("stranger: expected {expected:?}, got {got:?}")));
                            }
                        }
                        if let Some(record) = plan.stranger {
                            prop_assert_eq!(record.record.mode(), DiscoveryMode::Stranger);
                            prop_assert!(plan.paired.is_none_or(|p| p.label != record.label));
                        }
                        stranger.last = plan.stranger;
                        prop_assert_eq!(advertiser.stranger_enabled(), stranger.on.is_some());
                    }
                    Op::Enable { mono_ms } => {
                        mono += Duration::from_millis(mono_ms);
                        let now = time(wall).map_err(fail)?;
                        let started = advertiser.enable_stranger(now, mono, &mut random);
                        prop_assert_eq!(started, !random.off);
                        stranger.on = started.then_some((mono, mono));
                        stranger.last = None;
                        if started {
                            // The first plan shows the record made at the
                            // enable: take it as the one to keep.
                            let plan = advertiser.plan(&fixture.empty, now, mono, &mut random);
                            stranger.last = plan.stranger;
                            prop_assert!(stranger.last.is_some());
                        }
                    }
                    Op::Disable => {
                        advertiser.disable_stranger();
                        stranger = Stranger::default();
                        prop_assert!(!advertiser.stranger_enabled());
                    }
                    Op::Randomness(on) => random.off = !on,
                }
            }
        }
    }
}
