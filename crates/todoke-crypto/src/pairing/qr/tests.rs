use proptest::prelude::*;

use super::*;
use crate::session::test_vectors::{hex_array_at, hex_at, json_at, load};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The fixture's expiry is 1760000300; it was created 300 seconds earlier.
const CREATED: u64 = 1_760_000_000;
const EXPIRES: u64 = 1_760_000_300;

fn at(seconds: u64) -> Result<UnixTime, &'static str> {
    UnixTime::new(seconds).ok_or("time")
}

fn fixture_text() -> Result<String, Box<dyn std::error::Error>> {
    let vector = load("qr-payload.json")?;
    Ok(json_at(&vector, "/qr_text")?
        .as_str()
        .ok_or("qr_text")?
        .to_owned())
}

fn fixture_binary() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    hex_at(&load("qr-payload.json")?, "/binary_hex")
}

#[test]
fn committed_vector_round_trips_byte_for_byte() -> TestResult {
    let vector = load("qr-payload.json")?;
    let text = fixture_text()?;
    let binary = fixture_binary()?;
    assert_eq!(text.len(), QR_TEXT_LEN);
    assert_eq!(binary.len(), QR_PAYLOAD_LEN);
    assert_eq!(
        json_at(&vector, "/binary_length")?.as_u64(),
        Some(QR_PAYLOAD_LEN as u64)
    );
    let payload = QrPayload::from_text(&text, at(CREATED)?)?;
    assert_eq!(payload.encode().as_slice(), binary.as_slice());
    assert_eq!(payload.to_text().as_str(), text);
    assert_eq!(
        &text[QR_TEXT_PREFIX.len()..],
        json_at(&vector, "/base45")?.as_str().ok_or("base45")?
    );
    let from_binary = QrPayload::from_bytes(&binary, at(CREATED)?)?;
    assert_eq!(from_binary.to_text().as_str(), text);

    assert_eq!(
        payload.pairing_id(),
        &hex_array_at::<16>(&vector, "/pairing_id_hex")?
    );
    assert_eq!(
        Some(payload.expires_at().seconds()),
        json_at(&vector, "/expires_at")?.as_u64()
    );
    assert_eq!(
        payload.device_public().as_bytes(),
        &hex_array_at::<32>(&vector, "/device_ed25519_public_key_hex")?
    );
    assert_eq!(
        payload.noise_static(),
        &hex_array_at::<32>(&vector, "/noise_x25519_public_key_hex")?
    );
    assert_eq!(
        payload.kem_static().as_slice(),
        hex_at(&vector, "/mlkem768_encapsulation_key_hex")?.as_slice()
    );
    assert_eq!(
        payload.psk().as_slice(),
        &hex_array_at::<32>(&vector, "/one_time_psk_hex")?
    );
    assert_eq!(
        hex_at(&vector, "/pairing_rendezvous_info_hex")?.as_slice(),
        RENDEZVOUS_INFO
    );
    assert_eq!(
        payload.rendezvous_token()?.as_bytes(),
        &hex_array_at::<32>(&vector, "/pairing_rendezvous_token_hex")?
    );
    Ok(())
}

#[test]
fn text_checks_length_prefix_and_base45() -> TestResult {
    let text = fixture_text()?;
    let now = at(CREATED)?;
    assert_eq!(
        QrPayload::from_text(&text[..QR_TEXT_LEN - 1], now).err(),
        Some(QrError::Length)
    );
    assert_eq!(
        QrPayload::from_text(&format!("{text}0"), now).err(),
        Some(QrError::Length)
    );
    assert_eq!(QrPayload::from_text("", now).err(), Some(QrError::Length));
    for prefix in ["todoke:", "TODOKE;", "TODOKE ", "XODOKE:", " ODOKE:"] {
        let changed = format!("{prefix}{}", &text[QR_TEXT_PREFIX.len()..]);
        assert_eq!(
            QrPayload::from_text(&changed, now).err(),
            Some(QrError::Prefix),
            "{prefix:?}"
        );
    }
    // Lowercase, padding, and characters outside the alphabet.
    let body = &text[QR_TEXT_PREFIX.len()..];
    for replacement in ['a', '=', '\n', '_', '#'] {
        let mut changed = String::from(QR_TEXT_PREFIX);
        changed.push(replacement);
        changed.push_str(&body[1..]);
        assert_eq!(
            QrPayload::from_text(&changed, now).err(),
            Some(QrError::Base45),
            "{replacement:?}"
        );
    }
    // Spaces are significant: replacing one with another character changes
    // the payload, not merely its formatting.
    let space = body.find(' ').ok_or("the fixture has a space")?;
    let mut no_space = text.clone();
    no_space.replace_range(
        QR_TEXT_PREFIX.len() + space..=QR_TEXT_PREFIX.len() + space,
        "0",
    );
    assert_ne!(
        QrPayload::from_text(&no_space, now)
            .map(|payload| payload.to_text().as_str() == text)
            .ok(),
        Some(true)
    );
    // A non-canonical group (65536, "GGW") in place of the first group.
    let mut non_canonical = String::from(QR_TEXT_PREFIX);
    non_canonical.push_str("GGW");
    non_canonical.push_str(&body[3..]);
    assert_eq!(
        QrPayload::from_text(&non_canonical, now).err(),
        Some(QrError::Base45)
    );
    // A multi-byte character of the right byte length is rejected too.
    let mut unicode = String::from(QR_TEXT_PREFIX);
    unicode.push('é');
    unicode.push_str(&body[2..]);
    assert_eq!(unicode.len(), QR_TEXT_LEN);
    assert_eq!(
        QrPayload::from_text(&unicode, now).err(),
        Some(QrError::Base45)
    );
    Ok(())
}

fn mutated(offset: usize, bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut binary = fixture_binary()?;
    binary[offset..offset + bytes.len()].copy_from_slice(bytes);
    Ok(binary)
}

#[test]
fn binary_checks_every_header_field_and_key() -> TestResult {
    let now = at(CREATED)?;
    let decode = |bytes: &[u8]| QrPayload::from_bytes(bytes, now).err();
    let binary = fixture_binary()?;
    assert_eq!(decode(&binary[..QR_PAYLOAD_LEN - 1]), Some(QrError::Length));
    assert_eq!(
        decode(&[binary.as_slice(), &[0]].concat()),
        Some(QrError::Length)
    );
    assert_eq!(decode(&mutated(0, b"TDKR")?), Some(QrError::Magic));
    assert_eq!(decode(&mutated(0, b"tdkq")?), Some(QrError::Magic));
    assert_eq!(decode(&mutated(4, &[0, 2])?), Some(QrError::Version));
    assert_eq!(decode(&mutated(4, &[0, 0])?), Some(QrError::Version));
    assert_eq!(decode(&mutated(6, &[0, 2])?), Some(QrError::Suite));
    assert_eq!(decode(&mutated(6, &[0, 0])?), Some(QrError::Suite));
    assert_eq!(decode(&mutated(8, &[0; 16])?), Some(QrError::ZeroPairingId));
    assert_eq!(
        decode(&mutated(24, &u64::MAX.to_be_bytes())?),
        Some(QrError::ExpiryTooFar)
    );
    // Device key: small order (identity) and non-canonical encodings.
    let mut identity = [0; 32];
    identity[0] = 1;
    assert_eq!(decode(&mutated(32, &identity)?), Some(QrError::InvalidKey));
    assert_eq!(
        decode(&mutated(32, &[0xff; 32])?),
        Some(QrError::InvalidKey)
    );
    // Noise static: all zero and another small-order point.
    assert_eq!(decode(&mutated(64, &[0; 32])?), Some(QrError::InvalidKey));
    let mut one = [0; 32];
    one[0] = 1;
    assert_eq!(decode(&mutated(64, &one)?), Some(QrError::InvalidKey));
    // ML-KEM: a coefficient of 4095 (>= q) fails the FIPS 203 check.
    assert_eq!(
        decode(&mutated(96, &[0xff, 0xff, 0xff])?),
        Some(QrError::InvalidKey)
    );
    // The PSK is opaque: any value decodes.
    assert!(decode(&mutated(1280, &[0; 32])?).is_none());
    Ok(())
}

#[test]
fn expiry_allows_the_skew_and_no_more() -> TestResult {
    let binary = fixture_binary()?;
    let decode = |now: u64| -> Result<Option<QrError>, &'static str> {
        Ok(QrPayload::from_bytes(&binary, at(now)?).err())
    };
    // Created at 1760000000 and valid until 1760000300 + 120 s skew.
    assert_eq!(decode(CREATED)?, None);
    assert_eq!(decode(EXPIRES)?, None);
    assert_eq!(decode(EXPIRES + CLOCK_SKEW_SECONDS - 1)?, None);
    assert_eq!(
        decode(EXPIRES + CLOCK_SKEW_SECONDS)?,
        Some(QrError::Expired)
    );
    assert_eq!(decode(u64::from(u32::MAX) * 2)?, Some(QrError::Expired));
    // A scanner whose clock is up to 120 s behind the displayer's.
    let earliest = EXPIRES - OFFER_LIFETIME_SECONDS - CLOCK_SKEW_SECONDS;
    assert_eq!(decode(earliest)?, None);
    assert_eq!(decode(earliest - 1)?, Some(QrError::ExpiryTooFar));
    assert_eq!(decode(0)?, Some(QrError::ExpiryTooFar));
    Ok(())
}

#[test]
fn debug_and_errors_never_show_secrets() -> TestResult {
    let payload = QrPayload::from_text(&fixture_text()?, at(CREATED)?)?;
    let debug = format!("{payload:?}");
    assert!(debug.starts_with("QrPayload { expires_at: UnixTime(1760000300), device_public: "));
    assert!(debug.ends_with(", .. }"));
    for secret in ["5555", "a1a1", "PairingPsk"] {
        assert!(!debug.contains(secret), "{debug}");
    }
    assert_eq!(
        format!("{:?}", payload.rendezvous_token()?),
        "RendezvousToken([REDACTED])"
    );
    let messages: Vec<String> = [
        QrError::Length,
        QrError::Prefix,
        QrError::Base45,
        QrError::Magic,
        QrError::Version,
        QrError::Suite,
        QrError::ZeroPairingId,
        QrError::InvalidKey,
        QrError::Expired,
        QrError::ExpiryTooFar,
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    crate::identity::test_support::assert_distinct_messages(&messages);
    assert_eq!(
        QrRendezvousError.to_string(),
        "rendezvous token derivation failed"
    );
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// A payload rebuilt from decoded fields with any pairing ID, expiry,
    /// and PSK round-trips through both forms; any single changed text
    /// character is rejected or decodes to a different payload.
    #[test]
    fn fields_round_trip_and_text_edits_never_alias(
        pairing_id in any::<[u8; 16]>(),
        lifetime in 0..=OFFER_LIFETIME_SECONDS,
        psk in any::<[u8; 32]>(),
        position in 0..QR_TEXT_LEN,
        replacement in prop::sample::select(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:a".to_vec()),
    ) {
        prop_assume!(pairing_id != [0; 16]);
        let fail = |error: &dyn std::error::Error| TestCaseError::fail(error.to_string());
        let base = QrPayload::from_bytes(&fixture_binary().map_err(|e| fail(&*e))?, at(CREATED).map_err(TestCaseError::fail)?)
            .map_err(|e| fail(&e))?;
        let now = at(CREATED).map_err(TestCaseError::fail)?;
        let expires = at(CREATED + lifetime).map_err(TestCaseError::fail)?;
        let payload = QrPayload::new(
            pairing_id,
            expires,
            *base.device_public(),
            *base.noise_static(),
            Box::new(*base.kem_static()),
            Zeroizing::new(psk),
        );
        let text = payload.to_text();
        let decoded = QrPayload::from_text(&text, now).map_err(|e| fail(&e))?;
        prop_assert_eq!(decoded.encode(), payload.encode());
        let mut edited = text.as_bytes().to_vec();
        prop_assume!(edited[position] != replacement);
        edited[position] = replacement;
        let edited = String::from_utf8(edited).map_err(|e| fail(&e))?;
        if let Ok(other) = QrPayload::from_text(&edited, now) {
            prop_assert_ne!(other.encode(), payload.encode());
        }
    }
}
