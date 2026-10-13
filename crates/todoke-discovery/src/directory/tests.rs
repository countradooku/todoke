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

/// R3: a stranger entry refreshed under its label keeps when it was first
/// seen, so it stays ahead of later instances with the same token.
#[tokio::test]
async fn refreshed_strangers_keep_their_first_sighting() -> TestResult {
    let (alice, _) = paired().await?;
    let table = alice.table(WALL)?;
    let token = [0x51; 8];
    let stranger = DiscoveryRecord::new(DiscoveryMode::Stranger, table.epoch(), token)?;
    let mut directory = Directory::new();
    directory.set_stranger_browsing(true);
    directory.observe(sighting(&label(1)?, &stranger, 1)?, &table, SECOND * 10);
    directory.observe(sighting(&label(2)?, &stranger, 2)?, &table, SECOND * 11);
    directory.observe(sighting(&label(1)?, &stranger, 3)?, &table, SECOND * 12);
    let found = directory.strangers(SECOND * 12);
    assert_eq!(found.len(), 1);
    assert_eq!(
        found.first().map(|(_, r)| r.addresses().to_vec()),
        Some(vec![address(3), address(2)])
    );
    // Both expire 120 seconds after they were last seen, not before.
    assert_eq!(directory.strangers(SECOND * 131).len(), 1);
    assert_eq!(directory.strangers(SECOND * 132).len(), 0);
    // A goodbye removes a stranger instance too.
    directory.remove(&label(1)?);
    assert_eq!(
        directory
            .strangers(SECOND * 12)
            .first()
            .map(|(_, r)| r.addresses().to_vec()),
        Some(vec![address(2)])
    );
    Ok(())
}

/// R3: an instance last seen exactly `CACHE_LIFETIME` ago no longer holds
/// a place, so a newcomer is kept; one second earlier it still does.
#[tokio::test]
async fn places_free_exactly_at_the_cache_lifetime() -> TestResult {
    let (alice, bob) = paired().await?;
    let table = alice.table(WALL)?;
    let record = bob
        .table(WALL)?
        .advertisement(&alice.key())
        .ok_or("record")?;
    let mut directory = Directory::new();
    let start = SECOND * 1000;
    for n in 0..4_u8 {
        assert_eq!(
            directory.observe(sighting(&label(n.into())?, &record, n + 1)?, &table, start),
            Observed::Kept
        );
    }
    let almost = (start + CACHE_LIFETIME).saturating_sub(Duration::from_millis(1));
    assert_eq!(
        directory.observe(sighting(&label(9)?, &record, 9)?, &table, almost),
        Observed::Full
    );
    assert_eq!(
        directory.observe(
            sighting(&label(9)?, &record, 9)?,
            &table,
            start + CACHE_LIFETIME
        ),
        Observed::Kept
    );
    // Expired entries are not reported even before `expire` runs, and two
    // instances at one address give that address once.
    directory.observe(
        sighting(&label(10)?, &record, 9)?,
        &table,
        start + CACHE_LIFETIME,
    );
    assert_eq!(
        directory
            .contact(&bob.key(), start + CACHE_LIFETIME)
            .map(|r| r.addresses().to_vec()),
        Some(vec![address(9)])
    );
    assert_eq!(directory.contacts(start + CACHE_LIFETIME * 2).len(), 0);
    Ok(())
}

/// R3: paired records are rate-limited like stranger ones: after
/// `MAX_SIGHTINGS_PER_SECOND` matching sightings in one second, a real
/// contact's record waits for the next second.
#[tokio::test]
async fn paired_matching_is_rate_limited() -> TestResult {
    let (alice, bob) = paired().await?;
    let table = alice.table(WALL)?;
    let record = bob
        .table(WALL)?
        .advertisement(&alice.key())
        .ok_or("record")?;
    let mut directory = Directory::new();
    let now = SECOND * 700 + Duration::from_millis(5);
    for _ in 0..MAX_SIGHTINGS_PER_SECOND {
        assert_eq!(
            directory.observe(sighting(&label(1)?, &record, 1)?, &table, now),
            Observed::Kept
        );
    }
    let later = SECOND * 700 + Duration::from_millis(999);
    assert_eq!(
        directory.observe(sighting(&label(2)?, &record, 2)?, &table, later),
        Observed::RateLimited
    );
    assert_eq!(
        directory.observe(sighting(&label(2)?, &record, 2)?, &table, SECOND * 701),
        Observed::Kept
    );
    Ok(())
}

mod model {
    //! R3: a model-based test of the directory (see `directory_follows_its_model`).

    use std::collections::{BTreeMap, VecDeque};

    use proptest::prelude::*;

    use super::*;
    use crate::support::fixture;

    #[derive(Clone, Debug)]
    enum Op {
        /// Contact `contact`'s record under `label` from `host`.
        Contact {
            contact: usize,
            label: u8,
            host: u8,
        },
        /// A paired record that matches nobody.
        Junk {
            label: u8,
            host: u8,
        },
        /// A stranger record with token `[token; 8]`.
        Stranger {
            token: u8,
            label: u8,
            host: u8,
        },
        /// One contact sighting `count` times at once.
        Burst {
            contact: usize,
            label: u8,
            count: u8,
        },
        Remove {
            label: u8,
        },
        /// Expire against the full table or the one without contact 0.
        Expire {
            reduced: bool,
        },
        SetOwn {
            labels: Vec<u8>,
        },
        Browsing(bool),
        Advance(Duration),
    }

    fn op() -> impl Strategy<Value = Op> {
        let label = 0_u8..10;
        let host = 1_u8..6;
        prop_oneof![
            6 => (0_usize..3, label.clone(), host.clone())
                .prop_map(|(contact, label, host)| Op::Contact { contact, label, host }),
            1 => (label.clone(), host.clone()).prop_map(|(label, host)| Op::Junk { label, host }),
            3 => (1_u8..4, label.clone(), host)
                .prop_map(|(token, label, host)| Op::Stranger { token, label, host }),
            1 => (0_usize..3, label.clone(), 1_u8..80)
                .prop_map(|(contact, label, count)| Op::Burst { contact, label, count }),
            1 => label.clone().prop_map(|label| Op::Remove { label }),
            1 => any::<bool>().prop_map(|reduced| Op::Expire { reduced }),
            1 => proptest::collection::vec(label, 0..3).prop_map(|labels| Op::SetOwn { labels }),
            1 => any::<bool>().prop_map(Op::Browsing),
            4 => proptest::sample::select(vec![
                0_u64, 1, 300, 999, 1_000, 59_000, 60_000, 119_000, 119_999, 120_000, 121_000,
            ])
            .prop_map(|ms| Op::Advance(Duration::from_millis(ms))),
        ]
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Entry {
        label: u8,
        addresses: Vec<SocketAddr>,
        first: Duration,
        seen: Duration,
    }

    fn live(entry: &Entry, now: Duration) -> bool {
        now.saturating_sub(entry.seen) < CACHE_LIFETIME
    }

    /// The directory's rules, written plainly.
    #[derive(Default)]
    struct Model {
        contacts: BTreeMap<usize, Vec<Entry>>,
        strangers: VecDeque<(u8, Entry)>,
        browsing: bool,
        own: Vec<u8>,
        window: u64,
        in_window: u32,
    }

    impl Model {
        fn admit(&mut self, now: Duration) -> bool {
            if now.as_secs() != self.window {
                self.window = now.as_secs();
                self.in_window = 0;
            }
            if self.in_window >= MAX_SIGHTINGS_PER_SECOND {
                return false;
            }
            self.in_window += 1;
            true
        }

        fn contact(&mut self, contact: usize, entry: Entry, now: Duration) -> Observed {
            if self.own.contains(&entry.label) {
                return Observed::Own;
            }
            if !self.admit(now) {
                return Observed::RateLimited;
            }
            let entries = self.contacts.entry(contact).or_default();
            entries.retain(|old| live(old, now));
            let outcome = if let Some(old) = entries.iter_mut().find(|old| old.label == entry.label)
            {
                old.addresses = entry.addresses;
                old.seen = now;
                Observed::Kept
            } else if entries.len() >= MAX_INSTANCES_PER_CONTACT {
                Observed::Full
            } else {
                entries.push(entry);
                Observed::Kept
            };
            self.contacts.retain(|_, entries| !entries.is_empty());
            outcome
        }

        fn stranger(&mut self, token: u8, mut entry: Entry, now: Duration) -> Observed {
            if self.own.contains(&entry.label) {
                return Observed::Own;
            }
            if !self.browsing {
                return Observed::Unmatched;
            }
            if !self.admit(now) {
                return Observed::RateLimited;
            }
            if let Some((_, old)) = self
                .strangers
                .iter()
                .find(|(_, old)| old.label == entry.label)
            {
                entry.first = old.first;
            }
            self.strangers.retain(|(_, old)| old.label != entry.label);
            self.strangers.push_front((token, entry));
            self.strangers.truncate(MAX_STRANGERS);
            Observed::Kept
        }

        fn remove(&mut self, label: u8) {
            for entries in self.contacts.values_mut() {
                entries.retain(|entry| entry.label != label);
            }
            self.contacts.retain(|_, entries| !entries.is_empty());
            self.strangers.retain(|(_, entry)| entry.label != label);
        }

        fn expire(&mut self, reduced: bool, now: Duration) {
            self.contacts.retain(|contact, entries| {
                entries.retain(|entry| live(entry, now));
                !entries.is_empty() && (!reduced || *contact != 0)
            });
            self.strangers.retain(|(_, entry)| live(entry, now));
        }

        fn set_own(&mut self, labels: Vec<u8>) {
            for entries in self.contacts.values_mut() {
                entries.retain(|entry| !labels.contains(&entry.label));
            }
            self.contacts.retain(|_, entries| !entries.is_empty());
            self.strangers
                .retain(|(_, entry)| !labels.contains(&entry.label));
            self.own = labels;
        }
    }

    fn reachable<'a>(
        entries: impl Iterator<Item = &'a Entry>,
        now: Duration,
    ) -> Option<Vec<SocketAddr>> {
        let mut live: Vec<&Entry> = entries.filter(|entry| live(entry, now)).collect();
        live.sort_by_key(|entry| entry.first);
        let mut addresses: Vec<SocketAddr> = Vec::new();
        for address in live.iter().flat_map(|entry| entry.addresses.iter()) {
            if !addresses.contains(address) {
                addresses.push(*address);
            }
        }
        (!addresses.is_empty()).then_some(addresses)
    }

    fn label_number(label: &InstanceLabel) -> Result<u8, TestCaseError> {
        (0_u8..=255)
            .find(|n| self::super::label(u64::from(*n)).is_ok_and(|l| l == *label))
            .ok_or_else(|| TestCaseError::fail("unknown label"))
    }

    fn entry(label: u8, host: u8, now: Duration) -> Entry {
        Entry {
            label,
            addresses: vec![address(host)],
            first: now,
            seen: now,
        }
    }

    fn fail(error: impl core::fmt::Display) -> TestCaseError {
        TestCaseError::fail(error.to_string())
    }

    /// Compares the directory's state and answers with the model's, and
    /// checks the bounds independently of the model.
    fn check(
        directory: &Directory,
        model: &Model,
        keys: &[Ed25519PublicKey],
        now: Duration,
    ) -> Result<(), TestCaseError> {
        // Bounds, whatever the model says.
        for entries in directory.contacts.values() {
            prop_assert!(entries.len() <= MAX_INSTANCES_PER_CONTACT);
        }
        prop_assert!(directory.strangers.len() <= MAX_STRANGERS);
        prop_assert!(directory.stranger_browsing || directory.strangers.is_empty());
        for entry in directory
            .contacts
            .values()
            .flatten()
            .chain(directory.strangers.iter())
        {
            prop_assert!(!directory.own.contains(entry.sighting.label()));
            prop_assert!(entry.first <= entry.seen && entry.seen <= now);
        }
        // The stored state.
        for (index, key) in keys.iter().enumerate() {
            let stored: Vec<Entry> = directory
                .contacts
                .get(key)
                .map(|entries| {
                    entries
                        .iter()
                        .map(|entry| {
                            Ok(Entry {
                                label: label_number(entry.sighting.label())?,
                                addresses: entry.sighting.addresses().to_vec(),
                                first: entry.first,
                                seen: entry.seen,
                            })
                        })
                        .collect::<Result<Vec<_>, TestCaseError>>()
                })
                .transpose()?
                .unwrap_or_default();
            let expected = model.contacts.get(&index).cloned().unwrap_or_default();
            prop_assert_eq!(&stored, &expected, "contact {}", index);
            // What callers see: live entries only, longest known first.
            let seen = directory.contact(key, now).map(|r| r.addresses().to_vec());
            prop_assert_eq!(seen, reachable(expected.iter(), now));
        }
        let strangers: Vec<(u8, Entry)> = directory
            .strangers
            .iter()
            .map(|entry| {
                Ok((
                    entry.sighting.record().token()[0],
                    Entry {
                        label: label_number(entry.sighting.label())?,
                        addresses: entry.sighting.addresses().to_vec(),
                        first: entry.first,
                        seen: entry.seen,
                    },
                ))
            })
            .collect::<Result<_, TestCaseError>>()?;
        prop_assert_eq!(
            &strangers,
            &model.strangers.iter().cloned().collect::<Vec<_>>()
        );
        let mut by_token: BTreeMap<u8, Vec<&Entry>> = BTreeMap::new();
        for (token, entry) in &model.strangers {
            by_token.entry(*token).or_default().push(entry);
        }
        let expected: Vec<([u8; 8], Vec<SocketAddr>)> = by_token
            .into_iter()
            .filter_map(|(token, entries)| Some(([token; 8], reachable(entries.into_iter(), now)?)))
            .collect();
        let found: Vec<([u8; 8], Vec<SocketAddr>)> = directory
            .strangers(now)
            .into_iter()
            .map(|(token, r)| (token, r.addresses().to_vec()))
            .collect();
        prop_assert_eq!(found, expected);
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// R3: the directory against a plain model, with time: the bounds
        /// (`MAX_INSTANCES_PER_CONTACT`, `MAX_STRANGERS`), the 120-second
        /// expiry, longest-known-first retention (live instances are never
        /// displaced), own labels never stored or returned, stranger
        /// records only while browsing, and the per-second matching budget.
        #[test]
        fn directory_follows_its_model(ops in proptest::collection::vec(op(), 1..60)) {
            let fixture = fixture().map_err(fail)?;
            let table = fixture.tables.first().ok_or_else(|| fail("table"))?;
            let keys = &fixture.contacts;
            let mut directory = Directory::new();
            let mut model = Model::default();
            let mut now = SECOND * 1000;
            // Matching sightings stored or refreshed, per second.
            let mut budget: BTreeMap<u64, u32> = BTreeMap::new();
            for op in ops {
                let mut outcomes = Vec::new();
                match op {
                    Op::Contact { contact, label, host } => {
                        let record = fixture.records.get(contact).ok_or_else(|| fail("record"))?;
                        let key = keys.get(contact).ok_or_else(|| fail("key"))?;
                        let before: Vec<InstanceLabel> = directory
                            .contacts
                            .get(key)
                            .map(|entries| {
                                entries
                                    .iter()
                                    .filter(|entry| now.saturating_sub(entry.seen) < CACHE_LIFETIME)
                                    .map(|entry| *entry.sighting.label())
                                    .collect()
                            })
                            .unwrap_or_default();
                        let sighting = sighting(&self::super::label(label.into()).map_err(fail)?, record, host).map_err(fail)?;
                        let observed = directory.observe(sighting, table, now);
                        prop_assert_eq!(observed, model.contact(contact, entry(label, host, now), now));
                        // A live instance is never displaced by another.
                        if let Some(entries) = directory.contacts.get(key) {
                            for old in &before {
                                prop_assert!(entries.iter().any(|entry| entry.sighting.label() == old));
                            }
                        }
                        outcomes.push(observed);
                    }
                    Op::Junk { label, host } => {
                        let junk = DiscoveryRecord::new(DiscoveryMode::Paired, table.epoch(), [0xee, label, host, 1, 2, 3, 4, 5]).map_err(fail)?;
                        let sighting = sighting(&self::super::label(label.into()).map_err(fail)?, &junk, host).map_err(fail)?;
                        let expected = if model.own.contains(&label) { Observed::Own } else { Observed::Unmatched };
                        prop_assert_eq!(directory.observe(sighting, table, now), expected);
                    }
                    Op::Stranger { token, label, host } => {
                        let record = DiscoveryRecord::new(DiscoveryMode::Stranger, table.epoch(), [token; 8]).map_err(fail)?;
                        let sighting = sighting(&self::super::label(label.into()).map_err(fail)?, &record, host).map_err(fail)?;
                        let observed = directory.observe(sighting, table, now);
                        prop_assert_eq!(observed, model.stranger(token, entry(label, host, now), now));
                        outcomes.push(observed);
                    }
                    Op::Burst { contact, label, count } => {
                        let record = fixture.records.get(contact).ok_or_else(|| fail("record"))?;
                        for _ in 0..count {
                            let sighting = sighting(&self::super::label(label.into()).map_err(fail)?, record, 1).map_err(fail)?;
                            let observed = directory.observe(sighting, table, now);
                            prop_assert_eq!(observed, model.contact(contact, entry(label, 1, now), now));
                            outcomes.push(observed);
                        }
                    }
                    Op::Remove { label } => {
                        directory.remove(&self::super::label(label.into()).map_err(fail)?);
                        model.remove(label);
                    }
                    Op::Expire { reduced } => {
                        let table = if reduced { &fixture.reduced } else { table };
                        directory.expire(table, now);
                        model.expire(reduced, now);
                    }
                    Op::SetOwn { labels } => {
                        let own = labels
                            .iter()
                            .map(|n| self::super::label((*n).into()))
                            .collect::<Result<Vec<_>, _>>()
                            .map_err(fail)?;
                        directory.set_own(own);
                        model.set_own(labels);
                    }
                    Op::Browsing(on) => {
                        directory.set_stranger_browsing(on);
                        model.browsing = on;
                        if !on {
                            model.strangers.clear();
                        }
                    }
                    Op::Advance(step) => now += step,
                }
                let used = outcomes
                    .iter()
                    .filter(|o| matches!(o, Observed::Kept | Observed::Full))
                    .count();
                let spent = budget.entry(now.as_secs()).or_default();
                *spent += u32::try_from(used).map_err(fail)?;
                prop_assert!(*spent <= MAX_SIGHTINGS_PER_SECOND);
                check(&directory, &model, keys, now)?;
            }
        }
    }
}
