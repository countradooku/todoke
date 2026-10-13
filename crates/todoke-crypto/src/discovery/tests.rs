use super::*;
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
