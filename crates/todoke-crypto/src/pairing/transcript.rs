//! The code-pairing context formulas of PROTOCOL §3.2.
//!
//! ```text
//! code_offer = CodeOfferRequest || CodeOffer                  (bodies)
//! CI         = "todoke/v1/cpace-ci\0" || code_offer || ClientHello || ServerHello
//! sid        = client_nonce || server_nonce
//! ADa        = "todoke/v1/cpace-a\0"
//! ADb        = "todoke/v1/cpace-b\0"
//! pre_noise  = code_offer || ClientHello || ServerHello || CodeShareA || CodeShareB
//! psk        = HKDF(B3(pre_noise), ISK, "todoke/v1/cpace-psk\0", 32)
//! ```
//!
//! Hello bytes are the 58-byte bodies; share bytes are the 49-byte bodies.
//! The same `pre_noise` follows the Noise prologue domain (§4.2.6). These
//! context choices still need conformance vectors before release (§3.2).

use todoke_proto::pairing::{CODE_OFFER_TRANSCRIPT_LEN, CODE_SHARE_LEN};
use todoke_proto::session::{HELLO_LEN, Hello};
use zeroize::Zeroizing;

use super::cpace::Isk;
use crate::session::kdf::{self, KdfError};

/// `CPace` channel identifier domain.
pub(crate) const CI_DOMAIN: &[u8] = b"todoke/v1/cpace-ci\0";
/// Associated data of party A (the initiator).
pub(crate) const AD_A: &[u8] = b"todoke/v1/cpace-a\0";
/// Associated data of party B (the responder).
pub(crate) const AD_B: &[u8] = b"todoke/v1/cpace-b\0";
const PSK_INFO: &[u8] = b"todoke/v1/cpace-psk\0";

/// `CI = "todoke/v1/cpace-ci\0" || code_offer || ClientHello || ServerHello`.
pub(crate) fn channel_identifier(
    code_offer: &[u8; CODE_OFFER_TRANSCRIPT_LEN],
    client: &Hello,
    server: &Hello,
) -> Vec<u8> {
    let mut ci = Vec::with_capacity(CI_DOMAIN.len() + CODE_OFFER_TRANSCRIPT_LEN + 2 * HELLO_LEN);
    ci.extend_from_slice(CI_DOMAIN);
    ci.extend_from_slice(code_offer);
    ci.extend_from_slice(&client.encode());
    ci.extend_from_slice(&server.encode());
    ci
}

/// `sid = client_nonce || server_nonce`.
pub(crate) fn session_identifier(server: &Hello) -> [u8; 32] {
    let mut sid = [0; 32];
    sid[..16].copy_from_slice(server.client_nonce());
    sid[16..].copy_from_slice(server.server_nonce());
    sid
}

/// `pre_noise = code_offer || ClientHello || ServerHello || CodeShareA ||
/// CodeShareB`.
pub(crate) fn pre_noise(
    code_offer: &[u8; CODE_OFFER_TRANSCRIPT_LEN],
    client: &Hello,
    server: &Hello,
    share_a: &[u8; CODE_SHARE_LEN],
    share_b: &[u8; CODE_SHARE_LEN],
) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(CODE_OFFER_TRANSCRIPT_LEN + 2 * HELLO_LEN + 2 * CODE_SHARE_LEN);
    out.extend_from_slice(code_offer);
    out.extend_from_slice(&client.encode());
    out.extend_from_slice(&server.encode());
    out.extend_from_slice(share_a);
    out.extend_from_slice(share_b);
    out
}

/// `psk = HKDF(B3(pre_noise), ISK, "todoke/v1/cpace-psk\0", 32)`.
pub(crate) fn psk(pre_noise: &[u8], isk: &Isk) -> Result<Zeroizing<[u8; 32]>, KdfError> {
    let salt = blake3::hash(pre_noise);
    kdf::hkdf_sha256(salt.as_bytes(), isk.as_bytes(), PSK_INFO)
}

#[cfg(test)]
mod tests {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    use super::*;
    use todoke_proto::session::SessionMode;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn hellos() -> Result<(Hello, Hello), Box<dyn std::error::Error>> {
        let client = Hello::client(SessionMode::Code, [0xa1; 16], [0xc1; 16])?;
        let server = client.server_reply([0x5c; 16])?;
        Ok((client, server))
    }

    #[test]
    fn context_layouts() -> TestResult {
        let (client, server) = hellos()?;
        let offer = [0x0f; CODE_OFFER_TRANSCRIPT_LEN];
        let ci = channel_identifier(&offer, &client, &server);
        assert_eq!(ci.len(), 19 + 44 + 58 + 58);
        assert_eq!(&ci[..19], b"todoke/v1/cpace-ci\0");
        assert_eq!(&ci[19..63], &offer);
        assert_eq!(&ci[63..121], &client.encode());
        assert_eq!(&ci[121..], &server.encode());
        let sid = session_identifier(&server);
        assert_eq!(&sid[..16], &[0xc1; 16]);
        assert_eq!(&sid[16..], &[0x5c; 16]);
        assert_eq!(AD_A, b"todoke/v1/cpace-a\0");
        assert_eq!(AD_B, b"todoke/v1/cpace-b\0");
        let pre = pre_noise(&offer, &client, &server, &[0xaa; 49], &[0xbb; 49]);
        assert_eq!(pre.len(), 44 + 58 + 58 + 49 + 49);
        assert_eq!(&pre[..44], &offer);
        assert_eq!(&pre[44..102], &client.encode());
        assert_eq!(&pre[102..160], &server.encode());
        assert_eq!(&pre[160..209], &[0xaa; 49]);
        assert_eq!(&pre[209..], &[0xbb; 49]);
        Ok(())
    }

    /// The PSK formula recomputed with an independent HKDF (`RustCrypto`
    /// HMAC-SHA-256, RFC 5869 by hand).
    #[test]
    fn psk_is_hkdf_with_the_hashed_transcript_as_salt() -> TestResult {
        let (client, server) = hellos()?;
        let pre = pre_noise(&[1; 44], &client, &server, &[2; 49], &[3; 49]);
        let isk = Isk(Zeroizing::new([0x42; 64]));
        let derived = psk(&pre, &isk).map_err(|_| "kdf")?;
        let salt = blake3::hash(&pre);
        let mut extract = <Hmac<Sha256> as KeyInit>::new_from_slice(salt.as_bytes())?;
        extract.update(&[0x42; 64]);
        let prk = extract.finalize().into_bytes();
        let mut expand = <Hmac<Sha256> as KeyInit>::new_from_slice(&prk)?;
        expand.update(b"todoke/v1/cpace-psk\0");
        expand.update(&[1]);
        let okm = expand.finalize().into_bytes();
        assert_eq!(derived.as_slice(), okm.as_slice());
        // Every transcript byte matters.
        let other = pre_noise(&[1; 44], &client, &server, &[2; 49], &[4; 49]);
        assert_ne!(*psk(&other, &isk).map_err(|_| "kdf")?, *derived);
        Ok(())
    }
}
