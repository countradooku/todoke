//! Labeled derivations bound to a session (PROTOCOL §4.2.6, §4.3, §4.4).
//!
//! HKDF is RFC 5869 HKDF-SHA-256 and HMAC is HMAC-SHA-256, both from libcrux.
//! These are distinct from Noise's internal HKDF (§4.2.3). libcrux's HACL
//! HMAC/HKDF stack temporaries are not covered by an audited zeroization
//! guarantee (O6); every buffer owned here is `Zeroizing`.

use libcrux_hkdf::{Hkdf, Sha2_256};
use libcrux_secrets::{ClassifyRef as _, ClassifyRefMut as _};
use subtle::ConstantTimeEq as _;
use todoke_proto::session::FrameType;
use zeroize::Zeroizing;

use super::Role;
use super::engine::KEY_LEN;

const SESSION_DOMAIN: &[u8] = b"todoke/v1/session\0";
const RATCHET_INFO: &[u8] = b"todoke/v1/psk-ratchet\0";
const RATCHET_CONFIRM_DOMAIN: &[u8] = b"todoke/v1/ratchet-confirm\0";
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "consumed by discovery (§9), not built yet")
)]
const PAIR_SECRET_INFO: &[u8] = b"todoke/v1/pair-secret\0";
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "consumed by discovery (§9), not built yet")
)]
const DISCOVERY_KEY_INFO: &[u8] = b"todoke/v1/discovery-key\0";

/// `session_id = B3("todoke/v1/session\0" || h)` (§4.2.6).
#[must_use]
pub(crate) fn session_id(handshake_hash: &[u8; KEY_LEN]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SESSION_DOMAIN);
    hasher.update(handshake_hash);
    *hasher.finalize().as_bytes()
}

/// The derivation failed inside libcrux; unreachable for these fixed
/// lengths, and fails closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KdfError;

fn hkdf_sha256(
    salt: &[u8],
    ikm: &[u8; KEY_LEN],
    info: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, KdfError> {
    let mut prk = Zeroizing::new([0; KEY_LEN]);
    Hkdf::<Sha2_256>::extract(
        prk.as_mut_slice().classify_ref_mut(),
        salt.classify_ref(),
        ikm.as_slice().classify_ref(),
    )
    .map_err(|_| KdfError)?;
    let mut okm = Zeroizing::new([0; KEY_LEN]);
    Hkdf::<Sha2_256>::expand(
        okm.as_mut_slice().classify_ref_mut(),
        prk.as_slice().classify_ref(),
        info,
    )
    .map_err(|_| KdfError)?;
    Ok(okm)
}

/// `psk_next = HKDF(h, psk, "todoke/v1/psk-ratchet\0", 32)`: the handshake
/// hash is the Extract salt (§4.4). This is key separation, not
/// post-compromise healing: `h` is not a fresh secret.
pub(crate) fn psk_next(
    handshake_hash: &[u8; KEY_LEN],
    psk: &[u8; KEY_LEN],
) -> Result<Zeroizing<[u8; KEY_LEN]>, KdfError> {
    hkdf_sha256(handshake_hash, psk, RATCHET_INFO)
}

/// Discovery (§9) is not implemented; it will derive its state from the
/// committed PSK with these two functions, which the fixtures pin now.
///
/// `pair_secret = HKDF(empty, psk_next, "todoke/v1/pair-secret\0", 32)`; an
/// empty salt means 32 zero bytes (RFC 5869). Derived only from committed
/// state, so it changes on every committed session (§4.4).
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "consumed by discovery (§9), not built yet")
)]
pub(crate) fn pair_secret(
    committed_psk: &[u8; KEY_LEN],
) -> Result<Zeroizing<[u8; KEY_LEN]>, KdfError> {
    hkdf_sha256(&[], committed_psk, PAIR_SECRET_INFO)
}

/// `pair_key = HKDF(empty, pair_secret, "todoke/v1/discovery-key\0", 32)`.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "consumed by discovery (§9), not built yet")
)]
pub(crate) fn discovery_key(
    pair_secret: &[u8; KEY_LEN],
) -> Result<Zeroizing<[u8; KEY_LEN]>, KdfError> {
    hkdf_sha256(&[], pair_secret, DISCOVERY_KEY_INFO)
}

/// `HMAC-SHA256(psk_next, "todoke/v1/ratchet-confirm\0" || type:u16 ||
/// role:u8 || session_id || generation_next:u64)`, with `role` the sending
/// endpoint's handshake role (§4.4).
pub(crate) fn ratchet_confirmation(
    psk_next: &[u8; KEY_LEN],
    frame_type: FrameType,
    sender: Role,
    session_id: &[u8; 32],
    generation_next: u64,
) -> [u8; 32] {
    let mut input = Vec::with_capacity(RATCHET_CONFIRM_DOMAIN.len() + 2 + 1 + 32 + 8);
    input.extend_from_slice(RATCHET_CONFIRM_DOMAIN);
    input.extend_from_slice(&frame_type.get().to_be_bytes());
    input.push(sender.to_u8());
    input.extend_from_slice(session_id);
    input.extend_from_slice(&generation_next.to_be_bytes());
    let mut tag = Zeroizing::new([0; 32]);
    // Panics only for inputs longer than u32::MAX bytes; these are fixed-size.
    libcrux_hmac::hmac_sha2_256(&mut tag, psk_next, &input);
    *tag
}

/// Constant-time comparison of a received confirmation (§4.4).
pub(crate) fn confirmation_matches(expected: &[u8; 32], received: &[u8; 32]) -> bool {
    expected.ct_eq(received).into()
}

/// The message signed in `Identity`: `h || role:u8 || B3(binding)`; the key
/// store prepends `todoke/v1/identity\0` (§4.3).
pub(crate) fn identity_message(
    handshake_hash: &[u8; KEY_LEN],
    signer: Role,
    binding: &[u8],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(KEY_LEN + 1 + 32);
    message.extend_from_slice(handshake_hash);
    message.push(signer.to_u8());
    message.extend_from_slice(blake3::hash(binding).as_bytes());
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::test_vectors::{hex_array_at, load};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn psk_ratchet_matches_committed_vector() -> TestResult {
        let vector = load("psk-ratchet.json")?;
        let psk = hex_array_at::<32>(&vector, "/psk_hex")?;
        let hash = hex_array_at::<32>(&vector, "/handshake_hash_and_extract_salt_hex")?;
        let next = psk_next(&hash, &psk).map_err(|_| "kdf")?;
        assert_eq!(*next, hex_array_at::<32>(&vector, "/next_psk_hex")?);
        assert_eq!(
            hex_array_at::<22>(&vector, "/expand_info_hex")?.as_slice(),
            RATCHET_INFO
        );
        Ok(())
    }

    #[test]
    fn pair_secret_and_discovery_key_match_committed_chain() -> TestResult {
        let ratchet = load("psk-ratchet.json")?;
        let chain = load("discovery-token.json")?;
        let next = hex_array_at::<32>(&ratchet, "/next_psk_hex")?;
        let secret = pair_secret(&next).map_err(|_| "kdf")?;
        assert_eq!(
            *secret,
            hex_array_at::<32>(&chain, "/derived_chain/pair_secret_hex")?
        );
        let key = discovery_key(&secret).map_err(|_| "kdf")?;
        assert_eq!(
            *key,
            hex_array_at::<32>(&chain, "/derived_chain/pair_key_hex")?
        );
        Ok(())
    }

    /// RFC 4231 test case 2 for the HMAC-SHA-256 entry point (key "Jefe").
    #[test]
    fn hmac_entry_point_matches_rfc4231() {
        let mut tag = [0; 32];
        libcrux_hmac::hmac_sha2_256(&mut tag, b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(tag),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn confirmation_binds_every_input() {
        let base = ratchet_confirmation(
            &[1; 32],
            FrameType::RATCHET_READY,
            Role::Initiator,
            &[2; 32],
            3,
        );
        for other in [
            ratchet_confirmation(
                &[9; 32],
                FrameType::RATCHET_READY,
                Role::Initiator,
                &[2; 32],
                3,
            ),
            ratchet_confirmation(
                &[1; 32],
                FrameType::RATCHET_COMMIT,
                Role::Initiator,
                &[2; 32],
                3,
            ),
            ratchet_confirmation(
                &[1; 32],
                FrameType::RATCHET_READY,
                Role::Responder,
                &[2; 32],
                3,
            ),
            ratchet_confirmation(
                &[1; 32],
                FrameType::RATCHET_READY,
                Role::Initiator,
                &[3; 32],
                3,
            ),
            ratchet_confirmation(
                &[1; 32],
                FrameType::RATCHET_READY,
                Role::Initiator,
                &[2; 32],
                4,
            ),
        ] {
            assert_ne!(base, other);
            assert!(!confirmation_matches(&base, &other));
        }
        assert!(confirmation_matches(&base, &base));
        let mut input = Vec::new();
        input.extend_from_slice(RATCHET_CONFIRM_DOMAIN);
        input.extend_from_slice(&[0, 2, 0]);
        input.extend_from_slice(&[2; 32]);
        input.extend_from_slice(&3_u64.to_be_bytes());
        let mut expected = [0; 32];
        libcrux_hmac::hmac_sha2_256(&mut expected, &[1; 32], &input);
        assert_eq!(base, expected);
    }

    #[test]
    fn identity_message_layout() {
        let message = identity_message(&[7; 32], Role::Responder, b"binding");
        assert_eq!(&message[..32], &[7; 32]);
        assert_eq!(message[32], 1);
        assert_eq!(&message[33..], blake3::hash(b"binding").as_bytes());
        assert_eq!(identity_message(&[7; 32], Role::Initiator, b"b")[32], 0);
    }
}
