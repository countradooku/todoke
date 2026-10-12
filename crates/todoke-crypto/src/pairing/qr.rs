//! The QR pairing payload and its text form (PROTOCOL §3.1, §10).
//!
//! The payload carries the displayer's one-time PSK. It is redacted in
//! `Debug`, zeroized on drop, and never appears in an error. Decoding
//! enforces every §3.1 rule: both exact lengths, the `TODOKE:` prefix,
//! canonical RFC 9285 Base45, magic, version, suite, a nonzero pairing ID,
//! full key validation, and expiry under the §1 clock-skew rules.

use core::fmt;

use todoke_proto::identity::KEM_STATIC_LEN;
use todoke_proto::session::{HYBRID_SUITE, PROTOCOL_VERSION};
use todoke_proto::time::UnixTime;
use zeroize::Zeroizing;

use super::base45;
use crate::identity::binding::{kem_static_is_valid, noise_static_is_valid};
use crate::identity::{CLOCK_SKEW_SECONDS, Ed25519PublicKey};
use crate::session::kdf;

/// Binary payload length (§3.1).
pub const QR_PAYLOAD_LEN: usize = 1312;
/// The QR text prefix, exact case (§3.1).
pub const QR_TEXT_PREFIX: &str = "TODOKE:";
/// QR text length: the prefix plus 656 Base45 groups (§3.1).
pub const QR_TEXT_LEN: usize = QR_TEXT_PREFIX.len() + base45::encoded_len(QR_PAYLOAD_LEN);
/// Payload magic, ASCII `TDKQ`.
pub const QR_MAGIC: [u8; 4] = *b"TDKQ";
/// The longest offer lifetime: a QR or code offer expires no more than 300
/// seconds after creation (§3.1, §3.2, §13).
pub const OFFER_LIFETIME_SECONDS: u64 = 300;

const _: () = assert!(QR_TEXT_LEN == 1975);
const _: () = assert!(4 + 2 + 2 + 16 + 8 + 32 + 32 + KEM_STATIC_LEN + 32 == QR_PAYLOAD_LEN);

const RENDEZVOUS_INFO: &[u8] = b"todoke/v1/pairing-rendezvous\0";

/// Why a QR payload or text was rejected. Carries no payload bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum QrError {
    /// The text or binary payload does not have the exact length.
    Length,
    /// The text does not start with `TODOKE:` exactly.
    Prefix,
    /// The text is not canonical RFC 9285 Base45.
    Base45,
    /// The payload magic is not `TDKQ`.
    Magic,
    /// The payload version is not 1.
    Version,
    /// The hybrid suite is not 0x0001.
    Suite,
    /// The pairing ID is all zero.
    ZeroPairingId,
    /// A responder key failed validation (Ed25519 canonical and not small
    /// order, X25519 not small order, ML-KEM-768 FIPS 203 input check).
    InvalidKey,
    /// The offer expired, allowing the §1 clock skew.
    Expired,
    /// The expiry lies further ahead than an offer can live (300 seconds
    /// plus the §1 clock skew).
    ExpiryTooFar,
}

impl fmt::Display for QrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Length => "QR payload has the wrong length",
            Self::Prefix => "QR text has the wrong prefix",
            Self::Base45 => "QR text is not canonical Base45",
            Self::Magic => "QR payload has the wrong magic",
            Self::Version => "unsupported QR payload version",
            Self::Suite => "unsupported hybrid suite in QR payload",
            Self::ZeroPairingId => "QR pairing ID is zero",
            Self::InvalidKey => "QR payload carries an invalid key",
            Self::Expired => "QR offer expired",
            Self::ExpiryTooFar => "QR offer expiry is too far ahead",
        })
    }
}

impl std::error::Error for QrError {}

/// The QR pairing rendezvous capability (§10):
/// `HKDF(pairing_id, one_time_psk, "todoke/v1/pairing-rendezvous\0", 32)`.
///
/// It is derived, never carried in the QR. Whoever holds it can register
/// with a relay for this offer, so it is redacted in `Debug` and zeroized
/// on drop. Relay rendezvous is not implemented yet.
pub struct RendezvousToken(Zeroizing<[u8; 32]>);

impl RendezvousToken {
    /// The token bytes, for the relay `Register` record only.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RendezvousToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RendezvousToken([REDACTED])")
    }
}

/// A validated QR pairing payload (§3.1): the responder's three full public
/// keys, a pairing ID, an expiry, and the one-time PSK.
///
/// The PSK has no public accessor; it reaches the session layer only
/// through the QR pairing authority. `Debug` shows neither the PSK nor the
/// pairing ID.
pub struct QrPayload {
    pairing_id: [u8; 16],
    expires_at: UnixTime,
    device_public: Ed25519PublicKey,
    noise_static: [u8; 32],
    kem_static: Box<[u8; KEM_STATIC_LEN]>,
    psk: Zeroizing<[u8; 32]>,
}

impl QrPayload {
    /// Assembles a payload from already validated keys (offer creation).
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "used by QR offers, added with the pairing authority"
        )
    )]
    pub(crate) fn new(
        pairing_id: [u8; 16],
        expires_at: UnixTime,
        device_public: Ed25519PublicKey,
        noise_static: [u8; 32],
        kem_static: Box<[u8; KEM_STATIC_LEN]>,
        psk: Zeroizing<[u8; 32]>,
    ) -> Self {
        Self {
            pairing_id,
            expires_at,
            device_public,
            noise_static,
            kem_static,
            psk,
        }
    }

    /// Decodes and validates scanned QR text at the trusted wall-clock time
    /// `now`.
    ///
    /// `now` must come from a trusted clock; an unknown or regressed clock
    /// requires local confirmation instead of decoding (§1).
    ///
    /// # Errors
    ///
    /// The first failed §3.1 check, as a [`QrError`].
    pub fn from_text(text: &str, now: UnixTime) -> Result<Self, QrError> {
        let text = text.as_bytes();
        if text.len() != QR_TEXT_LEN {
            return Err(QrError::Length);
        }
        let (prefix, encoded) = text.split_at(QR_TEXT_PREFIX.len());
        if prefix != QR_TEXT_PREFIX.as_bytes() {
            return Err(QrError::Prefix);
        }
        let mut binary = Zeroizing::new([0; QR_PAYLOAD_LEN]);
        base45::decode_into(encoded, binary.as_mut_slice()).map_err(|_| QrError::Base45)?;
        Self::from_bytes(binary.as_slice(), now)
    }

    /// Decodes and validates a binary payload at the trusted wall-clock
    /// time `now`.
    ///
    /// # Errors
    ///
    /// The first failed §3.1 check, as a [`QrError`].
    pub fn from_bytes(bytes: &[u8], now: UnixTime) -> Result<Self, QrError> {
        let payload = Self::decode_layout(bytes)?;
        payload.check_expiry(now)?;
        Ok(payload)
    }

    /// Layout and key checks, without expiry.
    pub(crate) fn decode_layout(bytes: &[u8]) -> Result<Self, QrError> {
        let bytes: &[u8; QR_PAYLOAD_LEN] = bytes.try_into().map_err(|_| QrError::Length)?;
        let (magic, rest) = bytes.split_first_chunk::<4>().ok_or(QrError::Length)?;
        if *magic != QR_MAGIC {
            return Err(QrError::Magic);
        }
        let (version, rest) = rest.split_first_chunk::<2>().ok_or(QrError::Length)?;
        if u16::from_be_bytes(*version) != PROTOCOL_VERSION {
            return Err(QrError::Version);
        }
        let (suite, rest) = rest.split_first_chunk::<2>().ok_or(QrError::Length)?;
        if u16::from_be_bytes(*suite) != HYBRID_SUITE {
            return Err(QrError::Suite);
        }
        let (pairing_id, rest) = rest.split_first_chunk::<16>().ok_or(QrError::Length)?;
        if *pairing_id == [0; 16] {
            return Err(QrError::ZeroPairingId);
        }
        let (expires_at, rest) = rest.split_first_chunk::<8>().ok_or(QrError::Length)?;
        // Beyond the protocol time range can never be a valid expiry.
        let expires_at =
            UnixTime::new(u64::from_be_bytes(*expires_at)).ok_or(QrError::ExpiryTooFar)?;
        let (device_public, rest) = rest.split_first_chunk::<32>().ok_or(QrError::Length)?;
        let device_public =
            Ed25519PublicKey::from_bytes(device_public).map_err(|_| QrError::InvalidKey)?;
        let (noise_static, rest) = rest.split_first_chunk::<32>().ok_or(QrError::Length)?;
        if !noise_static_is_valid(noise_static) {
            return Err(QrError::InvalidKey);
        }
        let (kem_static, rest) = rest
            .split_first_chunk::<KEM_STATIC_LEN>()
            .ok_or(QrError::Length)?;
        if !kem_static_is_valid(kem_static) {
            return Err(QrError::InvalidKey);
        }
        let mut psk = Zeroizing::new([0; 32]);
        psk.copy_from_slice(rest);
        Ok(Self {
            pairing_id: *pairing_id,
            expires_at,
            device_public,
            noise_static: *noise_static,
            kem_static: Box::new(*kem_static),
            psk,
        })
    }

    /// §1/§3.1: expired once `now >= expires_at + skew`; refused if the
    /// expiry is more than 300 seconds plus the skew ahead of `now`.
    pub(crate) fn check_expiry(&self, now: UnixTime) -> Result<(), QrError> {
        check_offer_expiry(self.expires_at, now).map_err(|error| match error {
            ExpiryError::Expired => QrError::Expired,
            ExpiryError::TooFar => QrError::ExpiryTooFar,
        })
    }

    /// The exact 1312-byte payload. Contains the PSK: keep it in this
    /// zeroizing buffer and never log, upload, or pass it across FFI
    /// (§3.1, O5).
    #[must_use]
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(QR_PAYLOAD_LEN));
        out.extend_from_slice(&QR_MAGIC);
        out.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        out.extend_from_slice(&HYBRID_SUITE.to_be_bytes());
        out.extend_from_slice(&self.pairing_id);
        out.extend_from_slice(&self.expires_at.seconds().to_be_bytes());
        out.extend_from_slice(self.device_public.as_bytes());
        out.extend_from_slice(&self.noise_static);
        out.extend_from_slice(&self.kem_static[..]);
        out.extend_from_slice(self.psk.as_slice());
        out
    }

    /// The exact 1975-character QR text, `TODOKE:` + Base45. Contains the
    /// PSK, with the same handling rules as [`Self::encode`].
    #[must_use]
    pub fn to_text(&self) -> Zeroizing<String> {
        let binary = self.encode();
        let mut text = Zeroizing::new(String::with_capacity(QR_TEXT_LEN));
        text.push_str(QR_TEXT_PREFIX);
        base45::encode_into(&binary, &mut text);
        text
    }

    /// The one-time pairing ID (the Hello locator). Public on the wire, but
    /// not to be logged (§14.2).
    #[must_use]
    pub fn pairing_id(&self) -> &[u8; 16] {
        &self.pairing_id
    }

    /// The offer expiry claimed by the displayer.
    #[must_use]
    pub fn expires_at(&self) -> UnixTime {
        self.expires_at
    }

    /// The responder's device key, to be pinned against its binding.
    #[must_use]
    pub fn device_public(&self) -> &Ed25519PublicKey {
        &self.device_public
    }

    /// The responder's X25519 Noise static key.
    #[must_use]
    pub fn noise_static(&self) -> &[u8; 32] {
        &self.noise_static
    }

    /// The responder's ML-KEM-768 credential (not the HFS key; compared as
    /// data only, §2).
    #[must_use]
    pub fn kem_static(&self) -> &[u8; KEM_STATIC_LEN] {
        &self.kem_static
    }

    /// The §10 pairing rendezvous capability for this offer.
    ///
    /// # Errors
    ///
    /// [`QrRendezvousError`] if the derivation fails inside libcrux, which
    /// the fixed lengths rule out.
    pub fn rendezvous_token(&self) -> Result<RendezvousToken, QrRendezvousError> {
        kdf::hkdf_sha256(&self.pairing_id, self.psk.as_slice(), RENDEZVOUS_INFO)
            .map(RendezvousToken)
            .map_err(|_| QrRendezvousError)
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by the QR pairing authority, added next")
    )]
    pub(crate) fn psk(&self) -> &Zeroizing<[u8; 32]> {
        &self.psk
    }
}

impl fmt::Debug for QrPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QrPayload")
            .field("expires_at", &self.expires_at)
            .field("device_public", &self.device_public)
            .finish_non_exhaustive()
    }
}

/// The rendezvous derivation failed (unreachable for fixed lengths).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QrRendezvousError;

impl fmt::Display for QrRendezvousError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("rendezvous token derivation failed")
    }
}

impl std::error::Error for QrRendezvousError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExpiryError {
    Expired,
    TooFar,
}

/// The §1 expiry rule for an offer received from a peer whose clock may be
/// up to [`CLOCK_SKEW_SECONDS`] off: expired once `now >= expires_at +
/// skew`, and refused if `expires_at > now + 300 + skew`, since no offer
/// lives longer than 300 seconds.
pub(crate) fn check_offer_expiry(expires_at: UnixTime, now: UnixTime) -> Result<(), ExpiryError> {
    let now = now.seconds();
    let expires_at = expires_at.seconds();
    if now >= expires_at.saturating_add(CLOCK_SKEW_SECONDS) {
        return Err(ExpiryError::Expired);
    }
    if expires_at > now.saturating_add(OFFER_LIFETIME_SECONDS + CLOCK_SKEW_SECONDS) {
        return Err(ExpiryError::TooFar);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
