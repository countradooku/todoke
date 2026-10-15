//! Receiver-side discovery matching (PROTOCOL §9) with 1,000 contacts:
//!
//! - building the table (three epochs of tokens and locators per contact,
//!   and a rendezvous token), which a device does at every 15-minute epoch
//!   and after every committed session;
//! - matching one record against it, for a contact's record and for a
//!   record of nobody known (a random token);
//! - a whole sighting: the TXT string and address checks, the match, and
//!   storing it in the directory.
//!
//! Synthetic contacts only (random pair PSKs, through the `bench-support`
//! feature). See `bench/README.md`.
//!
//! On wasm32, which has no criterion (see `Cargo.toml`), this is an empty
//! program.

#[cfg(not(target_family = "wasm"))]
criterion::criterion_main!(discovery::benches);

#[cfg(target_family = "wasm")]
fn main() {}

#[cfg(not(target_family = "wasm"))]
mod discovery {
    use core::time::Duration;
    use std::hint::black_box;
    use std::net::IpAddr;

    use criterion::{BatchSize, Criterion, Throughput, criterion_group};
    use todoke_crypto::discovery::DiscoveryTable;
    use todoke_crypto::identity::Ed25519PublicKey;
    use todoke_discovery::{Directory, Sighting};
    use todoke_proto::discovery::{
        DiscoveryMode, DiscoveryRecord, Epoch, MDNS_SERVICE, MDNS_TXT_KEY,
    };
    use todoke_proto::time::UnixTime;
    use todoke_transport::LanPolicy;

    /// Contacts in the table: the P15 target (the store holds 1,024).
    const CONTACTS: usize = 1_000;
    /// A fixed time, so every run builds the same epochs.
    const NOW: u64 = 1_790_000_000;

    struct Fixture {
        now: UnixTime,
        contacts: Vec<(Ed25519PublicKey, [u8; 32])>,
        table: DiscoveryTable,
        /// What each contact advertises for this device now.
        records: Vec<DiscoveryRecord>,
    }

    fn fixture() -> Option<Fixture> {
        let now = UnixTime::new(NOW)?;
        let mut contacts = Vec::with_capacity(CONTACTS);
        for index in 0..CONTACTS {
            let mut seed = [0_u8; 32];
            seed[..8].copy_from_slice(&u64::try_from(index).ok()?.to_be_bytes());
            let device = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
            let device = Ed25519PublicKey::from_bytes(device.as_bytes()).ok()?;
            let mut psk = [0_u8; 32];
            getrandom::fill(&mut psk).ok()?;
            contacts.push((device, psk));
        }
        let table = build(now, &contacts)?;
        // A pair's token is the same in both directions (§9), so the record
        // this device would show a contact is the one the contact shows it.
        let records = contacts
            .iter()
            .map(|(device, _)| table.advertisement(device))
            .collect::<Option<Vec<_>>>()?;
        Some(Fixture {
            now,
            contacts,
            table,
            records,
        })
    }

    fn build(now: UnixTime, contacts: &[(Ed25519PublicKey, [u8; 32])]) -> Option<DiscoveryTable> {
        DiscoveryTable::from_pair_psks(now, contacts.iter().map(|(device, psk)| (*device, psk, 1)))
            .ok()
    }

    fn sighting(index: usize, record: &DiscoveryRecord) -> Option<Sighting> {
        Sighting::check(
            &format!("{index:016x}.{MDNS_SERVICE}"),
            47_000,
            [(IpAddr::from([192, 168, 1, 5]), 1)],
            [(MDNS_TXT_KEY, Some(record.txt_value().as_bytes()))],
            LanPolicy::new(),
        )
        .ok()
    }

    fn matching(c: &mut Criterion) {
        let Some(fixture) = fixture() else {
            eprintln!("discovery: the fixture could not be built");
            return;
        };
        let mut group = c.benchmark_group("discovery/1000-contacts");

        group.throughput(Throughput::Elements(1));
        group.bench_function("table-build", |b| {
            b.iter(|| build(black_box(fixture.now), black_box(&fixture.contacts)));
        });

        let mut next = 0;
        group.bench_function("match-contact", |b| {
            b.iter(|| {
                next = (next + 1) % CONTACTS;
                black_box(fixture.table.candidates(black_box(&fixture.records[next])))
            });
        });

        let epoch = Epoch::of(fixture.now);
        let mut token = [0_u8; 8];
        group.bench_function("match-unknown", |b| {
            b.iter_batched(
                || {
                    let _ = getrandom::fill(&mut token);
                    DiscoveryRecord::new(DiscoveryMode::Paired, epoch, token).ok()
                },
                |record| record.map(|record| fixture.table.candidates(black_box(&record))),
                BatchSize::SmallInput,
            );
        });

        // The whole path: check the resolved instance, match, store. Each
        // second of the directory's clock is a fresh rate-limit window.
        let mut directory = Directory::new();
        let mut index = 0;
        let mut second = 0_u64;
        group.bench_function("observe-sighting", |b| {
            b.iter(|| {
                index = (index + 1) % CONTACTS;
                second += 1;
                sighting(index, &fixture.records[index]).map(|sighting| {
                    directory.observe(sighting, &fixture.table, Duration::from_secs(second))
                })
            });
        });
        group.finish();
    }

    criterion_group!(benches, matching);
}
