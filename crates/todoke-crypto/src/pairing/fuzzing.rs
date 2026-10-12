//! Entry points for `cargo fuzz` harnesses; compiled only with `--cfg fuzzing`.

use todoke_proto::time::UnixTime;
use zeroize::Zeroizing;

use super::code::HumanCode;
use super::qr::{QR_PAYLOAD_LEN, QrPayload};

/// Decodes a binary QR payload, checking expiry at the time it claims (so
/// expiry never hides the other checks), and returns the re-encoding.
#[must_use]
pub fn qr_payload(data: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let now = claimed_expiry(data)?;
    QrPayload::from_bytes(data, now)
        .ok()
        .map(|payload| payload.encode())
}

/// Decodes QR text the same way and returns its re-encoding.
#[must_use]
pub fn qr_text(text: &str) -> Option<Zeroizing<String>> {
    let mut binary = Zeroizing::new([0; QR_PAYLOAD_LEN]);
    let now = text
        .as_bytes()
        .get(super::QR_TEXT_PREFIX.len()..)
        .and_then(|body| super::base45::decode_into(body, binary.as_mut_slice()).ok())
        .and_then(|()| claimed_expiry(binary.as_slice()))
        .or_else(|| UnixTime::new(0))?;
    QrPayload::from_text(text, now)
        .ok()
        .map(|payload| payload.to_text())
}

/// Parses typed code input both ways: [`HumanCode::parse_and_wipe`] on
/// a copy of `data`, which must end up all zeroes, and
/// [`HumanCode::parse`] on `data` as text. Both must agree, and an
/// accepted code must be exactly the input bytes.
///
/// # Panics
///
/// On any violation of the above, which is a bug.
pub fn human_code(data: &[u8]) {
    let mut typed = data.to_vec();
    let wiped = HumanCode::parse_and_wipe(&mut typed);
    assert!(typed.iter().all(|&byte| byte == 0), "input not wiped");
    let parsed = core::str::from_utf8(data).ok().map(HumanCode::parse);
    match (wiped, parsed) {
        (Ok(code), Some(Ok(same))) => {
            assert_eq!(code.as_str().as_bytes(), data);
            assert_eq!(same.as_str(), code.as_str());
        }
        (Err(_), None | Some(Err(_))) => {}
        _ => panic!("parse and parse_and_wipe disagree"),
    }
}

fn claimed_expiry(data: &[u8]) -> Option<UnixTime> {
    let bytes = data.get(24..32)?;
    UnixTime::new(u64::from_be_bytes(bytes.try_into().ok()?))
}
