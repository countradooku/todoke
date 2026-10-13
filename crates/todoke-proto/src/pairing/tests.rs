use super::*;
use crate::time::MAX_UNIX_TIME;
use proptest::prelude::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TOKEN: [u8; 8] = [0x5e; 8];
const PAIRING_ID: [u8; 16] = [0xa1; 16];

fn request() -> Result<CodeOfferRequest, DecodeError> {
    CodeOfferRequest::new(TOKEN)
}

fn offer() -> Result<CodeOffer, Box<dyn std::error::Error>> {
    Ok(CodeOffer::new(
        &request()?,
        PAIRING_ID,
        UnixTime::new(1_760_000_300).ok_or("time")?,
    )?)
}

#[test]
fn spec_lengths() {
    assert_eq!(CODE_OFFER_REQUEST_LEN, 2 + 8);
    assert_eq!(CODE_OFFER_LEN, 2 + 8 + 16 + 8);
    assert_eq!(CODE_OFFER_TRANSCRIPT_LEN, 44);
    assert_eq!(CODE_SHARE_LEN, 16 + 1 + 32);
}

#[test]
fn request_layout_round_trips() -> TestResult {
    let encoded = request()?.encode();
    assert_eq!(encoded[..2], [0, 1]);
    assert_eq!(encoded[2..], TOKEN);
    let decoded = CodeOfferRequest::decode(&encoded)?;
    assert_eq!(decoded, request()?);
    assert_eq!(decoded.stranger_token(), &TOKEN);
    Ok(())
}

#[test]
fn request_rejects_every_malformation() -> TestResult {
    let encoded = request()?.encode();
    for length in [0, 9, 11] {
        let mut bytes = encoded.to_vec();
        bytes.resize(length, 0);
        assert_eq!(CodeOfferRequest::decode(&bytes), Err(DecodeError::Length));
    }
    for version in [[0, 0], [0, 2], [1, 1], [0xff, 0xff]] {
        let mut bytes = encoded;
        bytes[..2].copy_from_slice(&version);
        assert_eq!(CodeOfferRequest::decode(&bytes), Err(DecodeError::Version));
    }
    let mut zero = encoded;
    zero[2..].fill(0);
    assert_eq!(
        CodeOfferRequest::decode(&zero),
        Err(DecodeError::ZeroIdentifier)
    );
    assert_eq!(
        CodeOfferRequest::new([0; 8]),
        Err(DecodeError::ZeroIdentifier)
    );
    Ok(())
}

#[test]
fn offer_layout_round_trips_and_echoes() -> TestResult {
    let offer = offer()?;
    let encoded = offer.encode();
    assert_eq!(encoded[..2], [0, 1]);
    assert_eq!(encoded[2..10], TOKEN);
    assert_eq!(encoded[10..26], PAIRING_ID);
    assert_eq!(encoded[26..], 1_760_000_300_u64.to_be_bytes());
    let decoded = CodeOffer::decode_reply(&encoded, &request()?)?;
    assert_eq!(decoded, offer);
    assert_eq!(decoded.pairing_id(), &PAIRING_ID);
    assert_eq!(decoded.stranger_token(), &TOKEN);
    assert_eq!(decoded.expires_at().seconds(), 1_760_000_300);
    let other = CodeOfferRequest::new([0x5f; 8])?;
    assert_eq!(
        CodeOffer::decode_reply(&encoded, &other),
        Err(DecodeError::Reserved)
    );
    Ok(())
}

#[test]
fn offer_rejects_every_malformation() -> TestResult {
    let encoded = offer()?.encode();
    for length in [0, 33, 35, 44] {
        let mut bytes = encoded.to_vec();
        bytes.resize(length, 0);
        assert_eq!(CodeOffer::decode(&bytes), Err(DecodeError::Length));
    }
    let mut version = encoded;
    version[1] = 2;
    assert_eq!(CodeOffer::decode(&version), Err(DecodeError::Version));
    let mut token = encoded;
    token[2..10].fill(0);
    assert_eq!(CodeOffer::decode(&token), Err(DecodeError::ZeroIdentifier));
    let mut id = encoded;
    id[10..26].fill(0);
    assert_eq!(CodeOffer::decode(&id), Err(DecodeError::ZeroIdentifier));
    let mut late = encoded;
    late[26..].copy_from_slice(&(MAX_UNIX_TIME + 1).to_be_bytes());
    assert_eq!(CodeOffer::decode(&late), Err(DecodeError::Range));
    let mut last = encoded;
    last[26..].copy_from_slice(&MAX_UNIX_TIME.to_be_bytes());
    assert!(CodeOffer::decode(&last).is_ok());
    assert_eq!(
        CodeOffer::new(&request()?, [0; 16], UnixTime::new(0).ok_or("time")?),
        Err(DecodeError::ZeroIdentifier)
    );
    Ok(())
}

#[test]
fn share_layout_round_trips() -> TestResult {
    for (role, byte) in [(CodeRole::A, 0), (CodeRole::B, 1)] {
        let share = CodeShare::new(PAIRING_ID, role, [0x33; 32])?;
        let encoded = share.encode();
        assert_eq!(encoded[..16], PAIRING_ID);
        assert_eq!(encoded[16], byte);
        assert_eq!(encoded[17..], [0x33; 32]);
        let decoded = CodeShare::decode(&encoded)?;
        assert_eq!(decoded, share);
        assert_eq!(decoded.role(), role);
        assert_eq!(decoded.pairing_id(), &PAIRING_ID);
        assert_eq!(decoded.element(), &[0x33; 32]);
        assert_eq!(CodeRole::from_u8(byte), Some(role));
        assert_eq!(role.to_u8(), byte);
    }
    Ok(())
}

#[test]
fn share_rejects_every_malformation() -> TestResult {
    let encoded = CodeShare::new(PAIRING_ID, CodeRole::A, [0x33; 32])?.encode();
    for length in [0, 48, 50] {
        let mut bytes = encoded.to_vec();
        bytes.resize(length, 0);
        assert_eq!(CodeShare::decode(&bytes), Err(DecodeError::Length));
    }
    for role in [2, 3, 0x80, 0xff] {
        let mut bytes = encoded;
        bytes[16] = role;
        assert_eq!(CodeShare::decode(&bytes), Err(DecodeError::UnknownEnum));
        assert_eq!(CodeRole::from_u8(role), None);
    }
    let mut zero = encoded;
    zero[..16].fill(0);
    assert_eq!(CodeShare::decode(&zero), Err(DecodeError::ZeroIdentifier));
    // The element is opaque here: even the neutral encoding has a valid
    // layout; todoke-crypto rejects it.
    let mut neutral = encoded;
    neutral[17..].fill(0);
    assert!(CodeShare::decode(&neutral).is_ok());
    Ok(())
}

#[test]
fn debug_output_redacts_locators() -> TestResult {
    let request = format!("{:?}", request()?);
    assert_eq!(request, "CodeOfferRequest { stranger_token: [8 bytes] }");
    let offer = format!("{:?}", offer()?);
    assert_eq!(
        offer,
        "CodeOffer { stranger_token: [8 bytes], pairing_id: [16 bytes], expires_at: UnixTime(1760000300) }"
    );
    let share = format!("{:?}", CodeShare::new(PAIRING_ID, CodeRole::B, [0x33; 32])?);
    assert_eq!(
        share,
        "CodeShare { pairing_id: [16 bytes], role: B, element: [32 bytes] }"
    );
    Ok(())
}

proptest! {
    /// Accepted input is canonical: it re-encodes to the same bytes.
    #[test]
    fn accepted_bodies_are_canonical(bytes in proptest::collection::vec(any::<u8>(), 0..60)) {
        if let Ok(request) = CodeOfferRequest::decode(&bytes) {
            prop_assert_eq!(request.encode().to_vec(), bytes.clone());
        }
        if let Ok(offer) = CodeOffer::decode(&bytes) {
            prop_assert_eq!(offer.encode().to_vec(), bytes.clone());
        }
        if let Ok(share) = CodeShare::decode(&bytes) {
            prop_assert_eq!(share.encode().to_vec(), bytes.clone());
        }
    }

    #[test]
    fn valid_fields_round_trip(
        token in any::<[u8; 8]>(),
        id in any::<[u8; 16]>(),
        expires in 0..=MAX_UNIX_TIME,
        role in any::<bool>(),
        element in any::<[u8; 32]>(),
    ) {
        prop_assume!(token != [0; 8] && id != [0; 16]);
        let request = CodeOfferRequest::new(token).map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(CodeOfferRequest::decode(&request.encode()), Ok(request));
        let expires = UnixTime::new(expires).ok_or_else(|| TestCaseError::fail("time"))?;
        let offer = CodeOffer::new(&request, id, expires).map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(CodeOffer::decode_reply(&offer.encode(), &request), Ok(offer));
        let role = if role { CodeRole::B } else { CodeRole::A };
        let share = CodeShare::new(id, role, element).map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(CodeShare::decode(&share.encode()), Ok(share));
    }
}
