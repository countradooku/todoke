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

/// A priority contact gets every other turn; with one contact it is the
/// only record anyway, and an unknown priority changes nothing.
#[tokio::test]
async fn a_priority_contact_takes_even_slots() -> TestResult {
    let (alice, bob) = paired().await?;
    let table = alice.table(WALL)?;
    let mut advertiser = Advertiser::new();
    let mut random = Counter(0);
    for slot in 0..6_u64 {
        let mono = ROTATION_MAX * u32::try_from(slot)?;
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
        time(wall).map(|wall| {
            advertiser
                .plan(&table, None, wall, mono, &mut random)
                .stranger
        })
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
    priority: Option<&Ed25519PublicKey>,
    wall: UnixTime,
    count: usize,
    random: &mut impl Random,
) -> Result<Vec<(Ed25519PublicKey, Duration)>, Box<dyn std::error::Error>> {
    let mut mono = Duration::ZERO;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let plan = advertiser.plan(table, priority, wall, mono, random);
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
        None,
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

/// A priority contact takes every other turn, and the turns between still
/// go round all the contacts, the priority one included; a priority that is
/// not a contact changes nothing.
#[test]
fn a_priority_contact_takes_every_other_turn() -> TestResult {
    let fixture = crate::support::fixture()?;
    let table = fixture.tables.first().ok_or("table")?;
    let wall = time(*fixture.walls.first().ok_or("wall")?)?;
    let priority = *fixture.contacts.get(2).ok_or("contact")?;
    let turns = turns(
        &mut Advertiser::new(),
        table,
        Some(&priority),
        wall,
        60,
        &mut SplitMix(2),
    )?;
    for (index, (device, _)) in turns.iter().enumerate() {
        if index % 2 == 0 {
            assert_eq!(*device, priority, "turn {index}");
        }
    }
    for round in turns
        .iter()
        .skip(1)
        .step_by(2)
        .collect::<Vec<_>>()
        .chunks(3)
    {
        let mut seen: Vec<Ed25519PublicKey> = round.iter().map(|(device, _)| *device).collect();
        seen.sort();
        let mut all: Vec<Ed25519PublicKey> = table.contacts().copied().collect();
        all.sort();
        assert_eq!(seen, all);
    }
    // Alice herself is no contact: the same as no priority.
    let unknown = turns_for(table, Some(&fixture.alice), wall)?;
    let none = turns_for(table, None, wall)?;
    assert_eq!(unknown, none);
    Ok(())
}

fn turns_for(
    table: &DiscoveryTable,
    priority: Option<&Ed25519PublicKey>,
    wall: UnixTime,
) -> Result<Vec<(Ed25519PublicKey, Duration)>, Box<dyn std::error::Error>> {
    turns(
        &mut Advertiser::new(),
        table,
        priority,
        wall,
        30,
        &mut SplitMix(3),
    )
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
        let plan = advertiser.plan(full, None, wall, mono, &mut random);
        if whose(full, plan.paired.map(|a| a.record))? == gone {
            break;
        }
        mono = advertiser.rotation.until;
    }
    for _ in 0..30 {
        let plan = advertiser.plan(&fixture.reduced, None, wall, mono, &mut random);
        assert_ne!(
            whose(&fixture.reduced, plan.paired.map(|a| a.record))?,
            gone
        );
        mono = advertiser.rotation.until;
    }
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
    let rotated = advertiser.plan(&table, None, wall, SECOND * 61, &mut Empty);
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
            .plan(&table, None, wall, SECOND, &mut Script(vec![[0; 8]]))
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
    //! R3: a model-based test of the advertising schedule.

    use proptest::prelude::*;

    use super::*;
    use crate::support::fixture;

    /// Counter randomness that can be switched off.
    #[derive(Clone, Debug, Default)]
    struct Switchable {
        next: u64,
        off: bool,
    }

    impl Random for Switchable {
        fn bytes(&mut self) -> Option<[u8; 8]> {
            if self.off {
                return None;
            }
            self.next += 1;
            Some(self.next.to_be_bytes())
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum Table {
        /// The table for the wall clock's epoch, if the fixture has one.
        Current,
        /// One for another epoch.
        Stale,
        /// One without contacts.
        Empty,
    }

    #[derive(Clone, Debug)]
    enum Op {
        Plan {
            mono: u64,
            wall: u64,
            table: Table,
            /// An index into the contacts; 3 is Alice herself (no contact).
            priority: Option<usize>,
        },
        Enable {
            mono: u64,
        },
        Disable,
        Randomness(bool),
    }

    fn step() -> impl Strategy<Value = u64> {
        proptest::sample::select(vec![0_u64, 1, 2, 3, 30, 59, 60, 61, 240, 299, 300])
    }

    fn op() -> impl Strategy<Value = Op> {
        let table = prop_oneof![
            6 => Just(Table::Current),
            1 => Just(Table::Stale),
            1 => Just(Table::Empty),
        ];
        prop_oneof![
            8 => (
                step(),
                proptest::sample::select(vec![0_u64, 1, 100, 450, 899, 900]),
                table,
                proptest::option::of(0_usize..4),
            )
                .prop_map(|(mono, wall, table, priority)| Op::Plan { mono, wall, table, priority }),
            2 => step().prop_map(|mono| Op::Enable { mono }),
            1 => Just(Op::Disable),
            1 => any::<bool>().prop_map(Op::Randomness),
        ]
    }

    #[derive(Clone, Copy, Debug)]
    struct Stranger {
        started: Duration,
        rotated: Duration,
        advertisement: Advertisement,
    }

    /// The schedule's rules, written plainly.
    #[derive(Default)]
    struct Model {
        random: Switchable,
        label: Option<(Epoch, InstanceLabel)>,
        shown: Option<Ed25519PublicKey>,
        until: Duration,
        priority_turn: bool,
        left: Vec<Ed25519PublicKey>,
        stranger: Option<Stranger>,
    }

    impl Model {
        /// A uniform draw below `bound`, rejecting the partial run.
        fn uniform(&mut self, bound: u64) -> Option<u64> {
            for _ in 0..64 {
                let value = u64::from_be_bytes(self.random.bytes()?);
                if value < u64::MAX - u64::MAX % bound {
                    return Some(value % bound);
                }
            }
            None
        }

        /// Who is shown: the current one until its time is up; then the
        /// priority if it did not have the last turn; else the next of the
        /// round, a new shuffled round when it is used up.
        fn turn(
            &mut self,
            table: &DiscoveryTable,
            priority: Option<&Ed25519PublicKey>,
            mono: Duration,
        ) -> Option<Ed25519PublicKey> {
            let listed = |device: &Ed25519PublicKey| table.advertisement(device).is_some();
            if let Some(shown) = self.shown
                && mono < self.until
                && listed(&shown)
            {
                return Some(shown);
            }
            let (device, priority_turn) = match priority.filter(|device| listed(device)) {
                Some(device) if !self.priority_turn => (*device, true),
                _ => {
                    let mut next = None;
                    while let Some(device) = self.left.pop() {
                        if listed(&device) {
                            next = Some(device);
                            break;
                        }
                    }
                    if next.is_none() {
                        let mut round: Vec<Ed25519PublicKey> = table.contacts().copied().collect();
                        for last in (1..round.len()).rev() {
                            let pick = self.uniform(u64::try_from(last).ok()? + 1)?;
                            round.swap(last, usize::try_from(pick).ok()?);
                        }
                        next = round.pop();
                        self.left = round;
                    }
                    (next?, false)
                }
            };
            let dwell = 2000 + self.uniform(2001)?;
            self.shown = Some(device);
            self.until = mono + Duration::from_millis(dwell);
            self.priority_turn = priority_turn;
            Some(device)
        }

        fn stranger_record(&mut self, wall: UnixTime) -> Option<Advertisement> {
            let token = self.random.bytes()?;
            let label = InstanceLabel::from_random(self.random.bytes()?).ok()?;
            let record =
                DiscoveryRecord::new(DiscoveryMode::Stranger, Epoch::of(wall), token).ok()?;
            Some(Advertisement { label, record })
        }

        fn paired(
            &mut self,
            table: &DiscoveryTable,
            priority: Option<&Ed25519PublicKey>,
            wall: UnixTime,
            mono: Duration,
        ) -> Option<Advertisement> {
            if table.is_stale(wall) || table.is_empty() {
                return None;
            }
            let epoch = Epoch::of(wall);
            let label = match self.label {
                Some((at, label)) if at == epoch => label,
                _ => {
                    let label = InstanceLabel::from_random(self.random.bytes()?).ok()?;
                    self.label = Some((epoch, label));
                    label
                }
            };
            let device = self.turn(table, priority, mono)?;
            Some(Advertisement {
                label,
                record: table.advertisement(&device)?,
            })
        }

        fn stranger(&mut self, wall: UnixTime, mono: Duration) -> Option<Advertisement> {
            let current = self.stranger?;
            if mono.saturating_sub(current.started) >= Duration::from_secs(300) {
                self.stranger = None;
                return None;
            }
            if mono.saturating_sub(current.rotated) >= Duration::from_secs(60) {
                let Some(advertisement) = self.stranger_record(wall) else {
                    self.stranger = None;
                    return None;
                };
                self.stranger = Some(Stranger {
                    rotated: mono,
                    advertisement,
                    ..current
                });
                return Some(advertisement);
            }
            Some(current.advertisement)
        }
    }

    fn fail(error: impl core::fmt::Display) -> TestCaseError {
        TestCaseError::fail(error.to_string())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// R3: the schedule against a plain model: one paired record at a
        /// time, rotating over the contacts in shuffled rounds for 2 to 4
        /// seconds each (a priority contact every other turn), a label per
        /// epoch, nothing paired from a
        /// stale or empty table; stranger mode only after an enable, for at
        /// most 300 seconds, a new token and label every 60, and off when
        /// randomness fails.
        #[test]
        fn the_schedule_follows_its_model(ops in proptest::collection::vec(op(), 1..50)) {
            let fixture = fixture().map_err(fail)?;
            let first_wall = *fixture.walls.first().ok_or_else(|| fail("wall"))?;
            let mut advertiser = Advertiser::new();
            let mut random = Switchable::default();
            let mut model = Model::default();
            let (mut mono, mut wall) = (Duration::ZERO, first_wall + 10);
            let mut paired_labels: Vec<(Epoch, InstanceLabel)> = Vec::new();
            let mut enabled_at = None;
            for op in ops {
                match op {
                    Op::Plan { mono: dm, wall: dw, table, priority } => {
                        mono += Duration::from_secs(dm);
                        wall += dw;
                        let now = time(wall).map_err(fail)?;
                        let current = fixture.tables.iter().find(|t| !t.is_stale(now));
                        let table = match table {
                            Table::Current => current.unwrap_or(&fixture.reduced),
                            Table::Stale => fixture
                                .tables
                                .iter()
                                .find(|t| t.is_stale(now))
                                .ok_or_else(|| fail("stale table"))?,
                            Table::Empty => &fixture.empty,
                        };
                        let priority = priority.map(|index| fixture.contacts.get(index).unwrap_or(&fixture.alice));
                        let plan = advertiser.plan(table, priority, now, mono, &mut random);
                        let expected = Plan {
                            paired: model.paired(table, priority, now, mono),
                            stranger: model.stranger(now, mono),
                        };
                        prop_assert_eq!(plan, expected);
                        // Independently of the model:
                        if let Some(paired) = plan.paired {
                            prop_assert!(!table.is_stale(now));
                            prop_assert_eq!(paired.record.mode(), DiscoveryMode::Paired);
                            prop_assert_eq!(paired.record.epoch(), Epoch::of(now));
                            prop_assert!(table.contacts().any(|c| table.advertisement(c) == Some(paired.record)));
                            // One label per epoch, never reused in another.
                            for (epoch, label) in &paired_labels {
                                prop_assert_eq!(*epoch == Epoch::of(now), *label == paired.label);
                            }
                            if !paired_labels.contains(&(Epoch::of(now), paired.label)) {
                                paired_labels.push((Epoch::of(now), paired.label));
                            }
                        }
                        if let Some(stranger) = plan.stranger {
                            prop_assert_eq!(stranger.record.mode(), DiscoveryMode::Stranger);
                            let since = enabled_at.map(|at| mono.saturating_sub(at));
                            prop_assert!(since.is_some_and(|since| since < STRANGER_LIFETIME));
                            prop_assert!(plan.paired.is_none_or(|p| p.label != stranger.label));
                        } else {
                            enabled_at = None;
                        }
                        prop_assert_eq!(advertiser.stranger_enabled(), model.stranger.is_some());
                    }
                    Op::Enable { mono: dm } => {
                        mono += Duration::from_secs(dm);
                        let now = time(wall).map_err(fail)?;
                        let started = advertiser.enable_stranger(now, mono, &mut random);
                        model.stranger = model.stranger_record(now).map(|advertisement| Stranger {
                            started: mono,
                            rotated: mono,
                            advertisement,
                        });
                        prop_assert_eq!(started, model.stranger.is_some());
                        enabled_at = started.then_some(mono);
                    }
                    Op::Disable => {
                        advertiser.disable_stranger();
                        model.stranger = None;
                        enabled_at = None;
                        prop_assert!(!advertiser.stranger_enabled());
                    }
                    Op::Randomness(on) => {
                        random.off = !on;
                        model.random.off = !on;
                    }
                }
            }
        }
    }
}
