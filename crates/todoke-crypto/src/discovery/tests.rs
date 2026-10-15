use super::*;
use todoke_proto::discovery::EPOCH_SECONDS;

use crate::identity::contacts::PairPsk;
use crate::identity::test_support::{Enrolled, T0, sealer, time};
use crate::identity::{KeyStore as _, MemoryStorage, SoftwareSealer, TrustOrigin};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Store = ContactStore<SoftwareSealer, MemoryStorage>;

fn load(name: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/test-vectors")
        .join(name);
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

fn hex_at<const N: usize>(
    value: &serde_json::Value,
    pointer: &str,
) -> Result<[u8; N], Box<dyn std::error::Error>> {
    let text = value
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .ok_or("missing fixture field")?;
    let bytes = hex::decode(text)?;
    Ok(bytes.as_slice().try_into()?)
}

/// Any valid key: the table only uses it as a label.
fn device() -> Result<Ed25519PublicKey, Box<dyn std::error::Error>> {
    let enrolled = Enrolled::new()?;
    Ok(enrolled.store.public_key(&enrolled.device)?)
}

/// Builds the committed chain's table from the fixture's next PSK at its
/// reference time.
fn fixture_table() -> Result<(DiscoveryTable, Ed25519PublicKey), Box<dyn std::error::Error>> {
    let ratchet = load("psk-ratchet.json")?;
    let psk = hex_at::<32>(&ratchet, "/next_psk_hex")?;
    let chain = load("discovery-token.json")?;
    let reference = chain
        .pointer("/derived_chain/reference_unix_seconds")
        .and_then(serde_json::Value::as_u64)
        .ok_or("reference")?;
    let key = device()?;
    let table = DiscoveryTable::build(time(reference)?, [(key, &psk, 1)].into_iter())?;
    Ok((table, key))
}

/// Tokens, locators, records, and TXT strings for the previous, current,
/// and next epochs are the committed chain's, byte for byte.
#[test]
fn table_matches_the_committed_chain() -> TestResult {
    let chain = load("discovery-token.json")?;
    let (table, key) = fixture_table()?;
    let epochs = chain
        .pointer("/derived_chain/epochs")
        .and_then(serde_json::Value::as_array)
        .ok_or("epochs")?;
    assert_eq!(epochs.len(), 3);
    for (index, entry) in epochs.iter().enumerate() {
        let at = |field: &str| format!("/derived_chain/epochs/{index}/{field}");
        let epoch = Epoch::new(
            entry
                .get("epoch")
                .and_then(serde_json::Value::as_u64)
                .ok_or("epoch")?,
        )?;
        let token = hex_at::<8>(&chain, &at("token_hex"))?;
        let locator = hex_at::<16>(&chain, &at("contact_locator_hex"))?;
        assert_eq!(table.token_at(&key, epoch), Some(token));
        assert_eq!(table.resolve_locator(&locator), &[key]);
        let record = DiscoveryRecord::decode(&hex::decode(
            entry
                .get("discovery_record_hex")
                .and_then(serde_json::Value::as_str)
                .ok_or("record")?,
        )?)?;
        assert_eq!(table.candidates(&record), vec![key]);
        if entry.get("position").and_then(serde_json::Value::as_str) == Some("current") {
            assert_eq!(table.epoch(), epoch);
            assert_eq!(table.advertisement(&key), Some(record));
            assert_eq!(
                table.advertisement(&key).map(|r| r.to_txt()),
                entry
                    .get("mdns_txt")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            );
            assert_eq!(table.locator(&key), Some(locator));
            let rendezvous = hex_at::<32>(&chain, &at("rendezvous_token_hex"))?;
            assert_eq!(table.rendezvous_token(&key).as_deref(), Some(&rendezvous));
        }
    }
    Ok(())
}

/// The HMAC-BLAKE3 cases of the fixture (a fixed pair key, several times).
#[test]
fn tokens_match_the_hmac_blake3_cases() -> TestResult {
    let chain = load("discovery-token.json")?;
    let pair_key = hex_at::<32>(&chain, "/pair_key_hex")?;
    let keys = PairKeys {
        pair_secret: Zeroizing::new([0; 32]),
        pair_key: Zeroizing::new(pair_key),
    };
    let cases = chain
        .pointer("/cases")
        .and_then(serde_json::Value::as_array)
        .ok_or("cases")?;
    assert_ne!(cases.len(), 0);
    for (index, case) in cases.iter().enumerate() {
        let seconds = case
            .get("unix_seconds")
            .and_then(serde_json::Value::as_u64)
            .ok_or("seconds")?;
        let epoch = Epoch::of(time(seconds)?);
        assert_eq!(
            Some(epoch.get()),
            case.get("epoch").and_then(serde_json::Value::as_u64)
        );
        assert_eq!(
            keys.token(epoch)?,
            hex_at::<8>(&chain, &format!("/cases/{index}/token_hex"))?
        );
    }
    Ok(())
}

/// A record is matched only for the epoch it claims, and only if that is
/// the local epoch or a neighbour; stranger records match nobody.
#[test]
fn records_match_only_their_claimed_epoch_near_now() -> TestResult {
    let (table, key) = fixture_table()?;
    let now = table.epoch();
    let current = table.token_at(&key, now).ok_or("token")?;
    let next = Epoch::new(now.get() + 1)?;
    // The current token claimed for the next epoch: no match.
    let shifted = DiscoveryRecord::new(DiscoveryMode::Paired, next, current)?;
    assert_eq!(table.candidates(&shifted).len(), 0);
    // Two epochs away: never tested, even with the right token.
    let far = Epoch::new(now.get() + 2)?;
    let keys_far = DiscoveryRecord::new(DiscoveryMode::Paired, far, current)?;
    assert_eq!(table.candidates(&keys_far).len(), 0);
    let stranger = DiscoveryRecord::new(DiscoveryMode::Stranger, now, current)?;
    assert_eq!(table.candidates(&stranger).len(), 0);
    let unknown = DiscoveryRecord::new(DiscoveryMode::Paired, now, [0x42; 8])?;
    assert_eq!(table.candidates(&unknown).len(), 0);
    assert_eq!(table.resolve_locator(&[0x42; 16]).len(), 0);
    Ok(())
}

#[test]
fn tables_go_stale_at_the_epoch_boundary() -> TestResult {
    let (table, _) = fixture_table()?;
    let boundary = table.epoch().next_boundary().ok_or("boundary")?;
    assert!(!table.is_stale(time(boundary.seconds() - 1)?));
    assert!(table.is_stale(boundary));
    Ok(())
}

/// Only contacts that may start a session now are advertised or matched;
/// a new PSK (a committed session) changes every token and locator.
#[test]
fn the_store_table_covers_available_contacts_only() -> TestResult {
    let enrolled = Enrolled::new()?;
    let key = enrolled.store.public_key(&enrolled.device)?;
    let mut store: Store = ContactStore::open(sealer(9), MemoryStorage::new())?;
    assert_eq!(store.discovery_table(time(T0)?)?.len(), 0);
    store.pair(
        &enrolled.bind(1)?,
        TrustOrigin::QrPairing,
        PairPsk::new([0x77; 32]),
        1,
        time(T0)?,
    )?;
    let table = store.discovery_table(time(T0)?)?;
    assert_eq!(table.contacts().collect::<Vec<_>>(), vec![&key]);
    assert_eq!(table.generation(&key), Some(1));
    let record = table.advertisement(&key).ok_or("advertised")?;
    assert_eq!(table.candidates(&record), vec![key]);
    // Re-paired with another PSK: the old record no longer matches.
    store.pair(
        &enrolled.bind(1)?,
        TrustOrigin::QrPairing,
        PairPsk::new([0x78; 32]),
        2,
        time(T0)?,
    )?;
    let renewed = store.discovery_table(time(T0)?)?;
    assert_eq!(renewed.generation(&key), Some(2));
    assert_eq!(renewed.candidates(&record).len(), 0);
    assert_ne!(renewed.locator(&key), table.locator(&key));
    // Blocked: neither advertised nor matched.
    store.mark_ratchet_uncertain(&key)?;
    let blocked = store.discovery_table(time(T0)?)?;
    assert_eq!(blocked.len(), 0);
    assert_eq!(blocked.advertisement(&key), None);
    assert_eq!(blocked.locator(&key), None);
    Ok(())
}

#[test]
fn debug_output_shows_no_tokens_or_locators() -> TestResult {
    let (table, key) = fixture_table()?;
    let shown = format!("{table:?}");
    let token = table.token_at(&key, table.epoch()).ok_or("token")?;
    assert!(!shown.contains(&hex::encode(token)));
    assert!(!shown.contains(&format!("{token:?}")));
    let locator = table.locator(&key).ok_or("locator")?;
    assert!(!shown.contains(&hex::encode(locator)));
    Ok(())
}

/// R3: the fixture fields no other test reads. Each HMAC case's full
/// 32-byte HMAC-BLAKE3 tag and big-endian epoch; the chain's source PSK
/// (the ratchet vector's `next_psk_hex`), its info strings, and for each
/// epoch the full 32-byte rendezvous token (the locator is its prefix)
/// and its HKDF salt (the epoch as u64 big-endian).
#[test]
fn every_fixture_field_is_reproduced() -> TestResult {
    let chain = load("discovery-token.json")?;
    let pair_key = hex_at::<32>(&chain, "/pair_key_hex")?;
    let cases = chain
        .pointer("/cases")
        .and_then(serde_json::Value::as_array)
        .ok_or("cases")?;
    for (index, case) in cases.iter().enumerate() {
        let epoch = case
            .get("epoch")
            .and_then(serde_json::Value::as_u64)
            .ok_or("epoch")?;
        assert_eq!(
            hex_at::<8>(&chain, &format!("/cases/{index}/epoch_be_hex"))?,
            epoch.to_be_bytes()
        );
        let mut mac = SimpleHmac::<blake3::Hasher>::new_from_slice(&pair_key)?;
        mac.update(&epoch.to_be_bytes());
        let tag: [u8; 32] = mac.finalize().into_bytes().into();
        assert_eq!(
            tag,
            hex_at::<32>(&chain, &format!("/cases/{index}/hmac_blake3_hex"))?
        );
        assert_eq!(
            tag[..DISCOVERY_TOKEN_LEN],
            hex_at::<8>(&chain, &format!("/cases/{index}/token_hex"))?
        );
    }
    let ratchet = load("psk-ratchet.json")?;
    let psk = hex_at::<32>(&chain, "/derived_chain/next_psk_hex")?;
    assert_eq!(psk, hex_at::<32>(&ratchet, "/next_psk_hex")?);
    // The info strings are the ones the derivations use.
    let info = |name: &str| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(hex::decode(
            chain
                .pointer(&format!("/derived_chain/{name}"))
                .and_then(serde_json::Value::as_str)
                .ok_or("info")?,
        )?)
    };
    let pair_secret = kdf::pair_secret(&psk).map_err(|_| "kdf")?;
    assert_eq!(
        *kdf::hkdf_sha256(&[], &psk, &info("pair_secret_info_hex")?).map_err(|_| "kdf")?,
        *pair_secret
    );
    assert_eq!(
        *kdf::hkdf_sha256(
            &[],
            pair_secret.as_slice(),
            &info("discovery_key_info_hex")?
        )
        .map_err(|_| "kdf")?,
        *kdf::discovery_key(&pair_secret).map_err(|_| "kdf")?
    );
    assert_eq!(info("rendezvous_info_hex")?, RENDEZVOUS_INFO);
    let keys = PairKeys::derive(&psk)?;
    let epochs = chain
        .pointer("/derived_chain/epochs")
        .and_then(serde_json::Value::as_array)
        .ok_or("epochs")?;
    for (index, entry) in epochs.iter().enumerate() {
        let at = |field: &str| format!("/derived_chain/epochs/{index}/{field}");
        let epoch = Epoch::new(
            entry
                .get("epoch")
                .and_then(serde_json::Value::as_u64)
                .ok_or("epoch")?,
        )?;
        assert_eq!(
            hex_at::<8>(&chain, &at("rendezvous_salt_hex"))?,
            epoch.get().to_be_bytes()
        );
        let rendezvous = keys.rendezvous_token(epoch)?;
        assert_eq!(
            *rendezvous,
            hex_at::<32>(&chain, &at("rendezvous_token_hex"))?
        );
        assert_eq!(
            rendezvous[..LOCATOR_LEN],
            hex_at::<16>(&chain, &at("contact_locator_hex"))?
        );
        assert_eq!(keys.token(epoch)?, hex_at::<8>(&chain, &at("token_hex"))?);
    }
    Ok(())
}

#[test]
fn errors_and_empty_tables() -> TestResult {
    assert_ne!(DiscoveryError.to_string(), "");
    assert_eq!(DiscoveryError::from(KdfError), DiscoveryError);
    let empty: Store = ContactStore::open(sealer(9), MemoryStorage::new())?;
    let table = empty.discovery_table(time(T0)?)?;
    assert!(table.is_empty());
    let (table, _) = fixture_table()?;
    assert!(!table.is_empty());
    Ok(())
}

/// Bit statistics of a run of tokens, against independent uniform 64-bit
/// values: overall and per-position balance within six standard
/// deviations, the Hamming distance between neighbours with mean 32 and
/// variance 16, and no repeats. The inputs are fixed, so the verdict is
/// the same on every run.
fn random_looking(tokens: &[[u8; DISCOVERY_TOKEN_LEN]]) -> TestResult {
    let count = u32::try_from(tokens.len())?;
    let n = f64::from(count);
    let words: Vec<u64> = tokens
        .iter()
        .map(|token| u64::from_be_bytes(*token))
        .collect();

    // Each bit position is 1 about half the time: sigma = sqrt(n) / 2.
    for position in 0..64 {
        let ones = words
            .iter()
            .filter(|word| *word >> position & 1 == 1)
            .count();
        let ones = f64::from(u32::try_from(ones)?);
        check((ones - n / 2.0).abs() < 6.0 * n.sqrt() / 2.0, || {
            format!("bit {position}: {ones} of {n}")
        })?;
    }
    let total = f64::from(words.iter().map(|word| word.count_ones()).sum::<u32>());
    let bits = 64.0 * n;
    check((total - bits / 2.0).abs() < 6.0 * bits.sqrt() / 2.0, || {
        format!("{total} ones of {bits}")
    })?;

    // Neighbours share nothing: their distance is Binomial(64, 1/2).
    let distances: Vec<f64> = words
        .windows(2)
        .map(|pair| f64::from((pair[0] ^ pair[1]).count_ones()))
        .collect();
    let pairs = f64::from(u32::try_from(distances.len())?);
    let mean = distances.iter().sum::<f64>() / pairs;
    let variance = distances.iter().map(|d| (d - mean).powi(2)).sum::<f64>() / pairs;
    // Standard errors: 4 / sqrt(pairs) for the mean, about
    // 16 * sqrt(2 / pairs) for the variance.
    check((mean - 32.0).abs() < 6.0 * 4.0 / pairs.sqrt(), || {
        format!("mean distance {mean}")
    })?;
    check(
        (variance - 16.0).abs() < 6.0 * 16.0 * (2.0 / pairs).sqrt(),
        || format!("distance variance {variance}"),
    )?;

    let mut sorted = words.clone();
    sorted.sort_unstable();
    sorted.dedup();
    check(sorted.len() == words.len(), || "a token repeats".to_owned())
}

fn check(holds: bool, what: impl FnOnce() -> String) -> TestResult {
    if holds { Ok(()) } else { Err(what().into()) }
}

/// §9 unlinkability across epochs: one pair's tokens over 20,000
/// consecutive epochs (about seven months) look like independent random
/// values, so one epoch's token says nothing about the next one's.
#[test]
fn a_pairs_tokens_are_unlinkable_across_epochs() -> TestResult {
    let keys = PairKeys::derive(&[0x5a; 32])?;
    let first = Epoch::of(time(T0)?).get();
    let mut tokens = Vec::with_capacity(20_000);
    for epoch in first..first + 20_000 {
        tokens.push(keys.token(Epoch::new(epoch)?)?);
    }
    random_looking(&tokens)
}

/// §9 unlinkability across pairs and ratchets: 2,000 pairs (or one pair
/// over 2,000 ratchet generations, each a fresh PSK) in one epoch give
/// tokens that look independent of each other.
#[test]
fn tokens_of_different_pairs_are_unlinkable() -> TestResult {
    let epoch = Epoch::of(time(T0)?);
    let tokens = (0..2_000_u32)
        .map(|index| {
            let mut psk = [0_u8; 32];
            psk[..4].copy_from_slice(&index.to_be_bytes());
            PairKeys::derive(&psk)?.token(epoch)
        })
        .collect::<Result<Vec<_>, _>>()?;
    random_looking(&tokens)
}

/// The statistics above have teeth: tokens that count up, drift a bit at a
/// time, or repeat are refused, so passing them means something.
#[test]
fn the_statistics_refuse_linkable_tokens() -> TestResult {
    let counting: Vec<[u8; DISCOVERY_TOKEN_LEN]> = (0..2_000_u64)
        .map(|n| (n * 0x0101_0101).to_be_bytes())
        .collect();
    assert!(random_looking(&counting).is_err());
    // A random-looking start, then one bit flipped per epoch.
    let mut word = 0x9e37_79b9_7f4a_7c15_u64;
    let drifting: Vec<[u8; DISCOVERY_TOKEN_LEN]> = (0..2_000_u32)
        .map(|n| {
            word ^= 1 << (n % 64);
            word.to_be_bytes()
        })
        .collect();
    assert!(random_looking(&drifting).is_err());
    // Real tokens, but the epochs come round twice.
    let keys = PairKeys::derive(&[1; 32])?;
    let mut repeating = Vec::new();
    for epoch in 0..1_000 {
        repeating.push(keys.token(Epoch::new(epoch % 500)?)?);
    }
    assert!(random_looking(&repeating).is_err());
    Ok(())
}

/// Whether a record `advertiser` shows at `at` for `receiver`'s pair is
/// matched by `receiver` whose clock reads `seen`.
fn matched(psk: &[u8; 32], at: u64, seen: u64) -> Result<bool, Box<dyn std::error::Error>> {
    let (advertiser, receiver) = (device()?, device()?);
    let shown = DiscoveryTable::build(time(at)?, [(receiver, psk, 1)].into_iter())?;
    let record = shown.advertisement(&receiver).ok_or("no record")?;
    let table = DiscoveryTable::build(time(seen)?, [(advertiser, psk, 1)].into_iter())?;
    Ok(table.candidates(&record) == [advertiser])
}

/// §9 skew: peers whose clocks differ by up to the §1 120 seconds match
/// on both sides of an epoch boundary; any skew that leaves them in
/// adjacent epochs matches (up to 900 seconds and beyond, depending on
/// where in the epoch), and two epochs apart never does.
#[test]
fn clock_skew_is_tolerated_across_epoch_boundaries() -> TestResult {
    let psk = [0x33; 32];
    let boundary = (Epoch::of(time(T0)?).get() + 1) * EPOCH_SECONDS;
    for at in [
        boundary - 120,
        boundary - 1,
        boundary,
        boundary + 1,
        boundary + 119,
    ] {
        for skew in [-120_i64, -61, -1, 0, 1, 59, 120] {
            let seen = at.checked_add_signed(skew).ok_or("time")?;
            assert!(matched(&psk, at, seen)?, "shown at {at}, seen at {seen}");
        }
    }
    // A whole epoch apart, either way: still a neighbour.
    assert!(matched(&psk, boundary, boundary + EPOCH_SECONDS)?);
    assert!(matched(&psk, boundary + EPOCH_SECONDS - 1, boundary - 1)?);
    // Two epochs apart: never.
    assert!(!matched(&psk, boundary, boundary + 2 * EPOCH_SECONDS)?);
    assert!(!matched(&psk, boundary + 2 * EPOCH_SECONDS, boundary - 1)?);
    Ok(())
}

/// At the start of time there is no epoch before 0: the first epoch's
/// table tests epochs 0 and 1 only, and still matches its neighbour.
#[test]
fn the_first_epoch_has_no_predecessor() -> TestResult {
    let table = DiscoveryTable::build(time(0)?, [(device()?, &[0x44; 32], 1)].into_iter())?;
    assert_eq!(table.epoch().get(), 0);
    assert_eq!(
        table.epoch().adjacent().map(Epoch::get).collect::<Vec<_>>(),
        [0, 1]
    );
    assert!(matched(&[0x44; 32], 0, EPOCH_SECONDS)?);
    assert!(matched(&[0x44; 32], EPOCH_SECONDS, 0)?);
    Ok(())
}

/// At the end of the protocol's time range there is no epoch after the
/// last: its table tests the last two epochs only, and still matches its
/// predecessor's records both ways.
#[test]
fn the_last_epoch_has_no_successor() -> TestResult {
    let last = todoke_proto::time::MAX_UNIX_TIME;
    let table = DiscoveryTable::build(time(last)?, [(device()?, &[0x55; 32], 1)].into_iter())?;
    let epoch = table.epoch().get();
    assert_eq!(
        table.epoch().adjacent().map(Epoch::get).collect::<Vec<_>>(),
        [epoch - 1, epoch]
    );
    assert!(matched(&[0x55; 32], last, last - EPOCH_SECONDS)?);
    assert!(matched(&[0x55; 32], last - EPOCH_SECONDS, last)?);
    Ok(())
}

/// R3: the QR stranger token (§9, `HMAC-BLAKE3(stranger_key, minute)`)
/// passes the same checks: one shown offer's tokens over 20,000
/// consecutive minutes, and 2,000 offers' tokens in one minute, look like
/// independent random values, so a scanner-side observer cannot follow an
/// offer from minute to minute or tell two offers' tokens apart.
#[test]
fn qr_stranger_tokens_are_unlinkable() -> TestResult {
    use crate::pairing::{QR_STRANGER_MINUTE, QrPayload};

    let vector = load("qr-payload.json")?;
    let binary = hex::decode(
        vector
            .pointer("/binary_hex")
            .and_then(serde_json::Value::as_str)
            .ok_or("binary_hex")?,
    )?;
    let created = time(T0)?;
    let key = QrPayload::from_bytes(&binary, created)?.stranger_key()?;
    let first = T0 / QR_STRANGER_MINUTE;
    let over_time = (first..first + 20_000)
        .map(|minute| key.token(minute))
        .collect::<Result<Vec<_>, _>>()?;
    random_looking(&over_time)?;
    // Offers differing only in their pairing ID (bytes 8..24).
    let mut across_offers = Vec::with_capacity(2_000);
    for index in 1..=2_000_u32 {
        let mut other = binary.clone();
        other
            .get_mut(8..12)
            .ok_or("pairing id")?
            .copy_from_slice(&index.to_be_bytes());
        let key = QrPayload::from_bytes(&other, created)?.stranger_key()?;
        across_offers.push(key.token(first)?);
    }
    random_looking(&across_offers)
}

/// A contact's device key, committed pair PSK, and generation.
type RawContact = (Ed25519PublicKey, [u8; 32], u64);

/// Three contacts paired into a store at `T0`, with their PSKs and
/// generations.
fn three_paired() -> Result<(Store, Vec<RawContact>), Box<dyn std::error::Error>> {
    let mut store: Store = ContactStore::open(sealer(9), MemoryStorage::new())?;
    let mut contacts = Vec::new();
    for (index, generation) in [(0x11_u8, 1_u64), (0x22, 7), (0x33, 1 << 40)] {
        let enrolled = Enrolled::new()?;
        let key = enrolled.store.public_key(&enrolled.device)?;
        let psk = [index; 32];
        store.pair(
            &enrolled.bind(1)?,
            TrustOrigin::QrPairing,
            PairPsk::new(psk),
            generation,
            time(T0)?,
        )?;
        contacts.push((key, psk, generation));
    }
    Ok((store, contacts))
}

/// R3: the builder the matching benchmark reaches through
/// `from_pair_psks` gives, from the same devices, PSKs, and generations,
/// exactly the table the contact store gives, so the benchmark measures
/// the shipped table (in every epoch, not only the store's pairing time).
#[test]
fn raw_psk_tables_equal_the_store_table() -> TestResult {
    let (store, contacts) = three_paired()?;
    for at in [T0, T0 + EPOCH_SECONDS, T0 + 1_000 * EPOCH_SECONDS] {
        let now = time(at)?;
        let raw = DiscoveryTable::build(
            now,
            contacts
                .iter()
                .map(|(device, psk, generation)| (*device, psk, *generation)),
        )?;
        assert_eq!(raw, store.discovery_table(now)?);
        assert_eq!(raw.len(), 3);
    }
    Ok(())
}

/// R3: `from_pair_psks` itself (the `bench-support` feature) equals the
/// store's table, whatever order the contacts come in.
#[cfg(feature = "bench-support")]
#[test]
fn from_pair_psks_equals_the_store_table() -> TestResult {
    let (store, mut contacts) = three_paired()?;
    contacts.reverse();
    let now = time(T0 + 3 * EPOCH_SECONDS)?;
    let raw = DiscoveryTable::from_pair_psks(
        now,
        contacts
            .iter()
            .map(|(device, psk, generation)| (*device, psk, *generation)),
    )?;
    assert_eq!(raw, store.discovery_table(now)?);
    for (device, _, generation) in &contacts {
        assert_eq!(raw.generation(device), Some(*generation));
    }
    Ok(())
}
