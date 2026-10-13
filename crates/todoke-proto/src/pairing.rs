//! Human-code pairing prelude bodies (PROTOCOL §3.2, §4.1 kinds 0x03, 0x04,
//! 0x06, 0x07).
//!
//! `CodeOfferRequest` and `CodeOffer` precede `ClientHello` on a stream the
//! code entrant opened; `CodeShareA` and `CodeShareB` follow both Hellos and
//! carry the `CPace` public shares. All four are public, unauthenticated
//! bootstrap data: the code-pairing transcript binds them into `CPace` and
//! the Noise prologue, and nothing here authenticates a peer.
//!
//! These codecs check layout only: exact lengths, version, enum values,
//! nonzero identifiers, and the time range. Whether a share is a canonical,
//! non-neutral Ristretto255 element, whether a token is the one currently
//! advertised, and every ordering rule belong to `todoke-crypto`.

use core::fmt;

use crate::session::DecodeError;
use crate::time::UnixTime;

/// The only version of the code-offer records (§3.2).
pub const CODE_OFFER_VERSION: u16 = 1;
/// `CodeOfferRequest` body length (§3.2).
pub const CODE_OFFER_REQUEST_LEN: usize = 10;
/// `CodeOffer` body length (§3.2).
pub const CODE_OFFER_LEN: usize = 34;
/// `code_offer = CodeOfferRequest || CodeOffer`, as bound into `CPace` and
/// the Noise prologue (§3.2).
pub const CODE_OFFER_TRANSCRIPT_LEN: usize = CODE_OFFER_REQUEST_LEN + CODE_OFFER_LEN;
/// `CodeShareA` / `CodeShareB` body length (§3.2).
pub const CODE_SHARE_LEN: usize = 49;
/// Length of a discovery stranger token (§9).
pub const STRANGER_TOKEN_LEN: usize = 8;

/// `CodeOfferRequest` body: `version:u16 || stranger_token[8]`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CodeOfferRequest {
    stranger_token: [u8; STRANGER_TOKEN_LEN],
}

impl CodeOfferRequest {
    /// A request for the offer behind `stranger_token`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::ZeroIdentifier`] for an all-zero token (§1).
    pub fn new(stranger_token: [u8; STRANGER_TOKEN_LEN]) -> Result<Self, DecodeError> {
        if stranger_token == [0; STRANGER_TOKEN_LEN] {
            return Err(DecodeError::ZeroIdentifier);
        }
        Ok(Self { stranger_token })
    }

    /// Parses exactly [`CODE_OFFER_REQUEST_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`], [`DecodeError::Version`], or
    /// [`DecodeError::ZeroIdentifier`].
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let bytes: &[u8; CODE_OFFER_REQUEST_LEN] =
            bytes.try_into().map_err(|_| DecodeError::Length)?;
        let (version, token) = bytes.split_first_chunk::<2>().ok_or(DecodeError::Length)?;
        check_version(*version)?;
        let token: [u8; STRANGER_TOKEN_LEN] = token.try_into().map_err(|_| DecodeError::Length)?;
        Self::new(token)
    }

    /// The exact [`CODE_OFFER_REQUEST_LEN`]-byte body.
    #[must_use]
    pub fn encode(&self) -> [u8; CODE_OFFER_REQUEST_LEN] {
        let mut out = [0; CODE_OFFER_REQUEST_LEN];
        out[..2].copy_from_slice(&CODE_OFFER_VERSION.to_be_bytes());
        out[2..].copy_from_slice(&self.stranger_token);
        out
    }

    /// The requested stranger token.
    #[must_use]
    pub fn stranger_token(&self) -> &[u8; STRANGER_TOKEN_LEN] {
        &self.stranger_token
    }
}

/// Redacted: the stranger token is a discovery token (§14.2).
impl fmt::Debug for CodeOfferRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CodeOfferRequest")
            .field("stranger_token", &Redacted(STRANGER_TOKEN_LEN))
            .finish()
    }
}

/// `CodeOffer` body: `version:u16 || stranger_token[8] || pairing_id[16] ||
/// expires_at:u64`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CodeOffer {
    stranger_token: [u8; STRANGER_TOKEN_LEN],
    pairing_id: [u8; 16],
    expires_at: UnixTime,
}

impl CodeOffer {
    /// The offer answering `request`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::ZeroIdentifier`] for a zero pairing ID.
    pub fn new(
        request: &CodeOfferRequest,
        pairing_id: [u8; 16],
        expires_at: UnixTime,
    ) -> Result<Self, DecodeError> {
        if pairing_id == [0; 16] {
            return Err(DecodeError::ZeroIdentifier);
        }
        Ok(Self {
            stranger_token: request.stranger_token,
            pairing_id,
            expires_at,
        })
    }

    /// Parses exactly [`CODE_OFFER_LEN`] bytes and requires the token to echo
    /// `request` exactly.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`], [`DecodeError::Version`],
    /// [`DecodeError::ZeroIdentifier`], [`DecodeError::Range`] for a time
    /// beyond the protocol range, or [`DecodeError::Reserved`] when the
    /// token differs from the request's.
    pub fn decode_reply(bytes: &[u8], request: &CodeOfferRequest) -> Result<Self, DecodeError> {
        let offer = Self::decode(bytes)?;
        if offer.stranger_token != request.stranger_token {
            return Err(DecodeError::Reserved);
        }
        Ok(offer)
    }

    /// Parses exactly [`CODE_OFFER_LEN`] bytes without an echo check.
    ///
    /// # Errors
    ///
    /// As [`Self::decode_reply`], except the echo check.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let bytes: &[u8; CODE_OFFER_LEN] = bytes.try_into().map_err(|_| DecodeError::Length)?;
        let (version, rest) = bytes.split_first_chunk::<2>().ok_or(DecodeError::Length)?;
        check_version(*version)?;
        let (token, rest) = rest
            .split_first_chunk::<STRANGER_TOKEN_LEN>()
            .ok_or(DecodeError::Length)?;
        let (pairing_id, rest) = rest.split_first_chunk::<16>().ok_or(DecodeError::Length)?;
        let expires_at: [u8; 8] = rest.try_into().map_err(|_| DecodeError::Length)?;
        let request = CodeOfferRequest::new(*token)?;
        let expires_at = UnixTime::new(u64::from_be_bytes(expires_at)).ok_or(DecodeError::Range)?;
        Self::new(&request, *pairing_id, expires_at)
    }

    /// The exact [`CODE_OFFER_LEN`]-byte body.
    #[must_use]
    pub fn encode(&self) -> [u8; CODE_OFFER_LEN] {
        let mut out = [0; CODE_OFFER_LEN];
        out[..2].copy_from_slice(&CODE_OFFER_VERSION.to_be_bytes());
        out[2..10].copy_from_slice(&self.stranger_token);
        out[10..26].copy_from_slice(&self.pairing_id);
        out[26..].copy_from_slice(&self.expires_at.seconds().to_be_bytes());
        out
    }

    /// The echoed stranger token.
    #[must_use]
    pub fn stranger_token(&self) -> &[u8; STRANGER_TOKEN_LEN] {
        &self.stranger_token
    }

    /// The offer's pairing ID, used as the Hello locator.
    #[must_use]
    pub fn pairing_id(&self) -> &[u8; 16] {
        &self.pairing_id
    }

    /// Claimed offer expiry (untrusted).
    #[must_use]
    pub fn expires_at(&self) -> UnixTime {
        self.expires_at
    }
}

/// Redacted: the token and pairing ID are locators (§14.2).
impl fmt::Debug for CodeOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CodeOffer")
            .field("stranger_token", &Redacted(STRANGER_TOKEN_LEN))
            .field("pairing_id", &Redacted(16))
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Which `CPace` party sent a share: A (the initiator, code entrant) or B
/// (the responder, code displayer). The prelude kind and this byte must
/// agree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CodeRole {
    /// `CodeShareA`, role byte 0.
    A,
    /// `CodeShareB`, role byte 1.
    B,
}

impl CodeRole {
    /// The role byte.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::A => 0,
            Self::B => 1,
        }
    }

    /// Decodes a role byte.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::A),
            1 => Some(Self::B),
            _ => None,
        }
    }
}

/// `CodeShareA` / `CodeShareB` body: `pairing_id[16] || role:u8 ||
/// element[32]`. The element is unvalidated here.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CodeShare {
    pairing_id: [u8; 16],
    role: CodeRole,
    element: [u8; 32],
}

impl CodeShare {
    /// Assembles a share.
    ///
    /// # Errors
    ///
    /// [`DecodeError::ZeroIdentifier`] for a zero pairing ID.
    pub fn new(
        pairing_id: [u8; 16],
        role: CodeRole,
        element: [u8; 32],
    ) -> Result<Self, DecodeError> {
        if pairing_id == [0; 16] {
            return Err(DecodeError::ZeroIdentifier);
        }
        Ok(Self {
            pairing_id,
            role,
            element,
        })
    }

    /// Parses exactly [`CODE_SHARE_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`], [`DecodeError::UnknownEnum`] for a role
    /// other than 0 or 1, or [`DecodeError::ZeroIdentifier`].
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let bytes: &[u8; CODE_SHARE_LEN] = bytes.try_into().map_err(|_| DecodeError::Length)?;
        let (pairing_id, rest) = bytes.split_first_chunk::<16>().ok_or(DecodeError::Length)?;
        let (&role, element) = rest.split_first().ok_or(DecodeError::Length)?;
        let role = CodeRole::from_u8(role).ok_or(DecodeError::UnknownEnum)?;
        let element: [u8; 32] = element.try_into().map_err(|_| DecodeError::Length)?;
        Self::new(*pairing_id, role, element)
    }

    /// The exact [`CODE_SHARE_LEN`]-byte body.
    #[must_use]
    pub fn encode(&self) -> [u8; CODE_SHARE_LEN] {
        let mut out = [0; CODE_SHARE_LEN];
        out[..16].copy_from_slice(&self.pairing_id);
        out[16] = self.role.to_u8();
        out[17..].copy_from_slice(&self.element);
        out
    }

    /// The claimed pending offer.
    #[must_use]
    pub fn pairing_id(&self) -> &[u8; 16] {
        &self.pairing_id
    }

    /// The sender's claimed role.
    #[must_use]
    pub fn role(&self) -> CodeRole {
        self.role
    }

    /// The claimed Ristretto255 element encoding.
    #[must_use]
    pub fn element(&self) -> &[u8; 32] {
        &self.element
    }
}

/// Redacted: the pairing ID is a locator (§14.2). The element is public
/// but adds nothing to a log.
impl fmt::Debug for CodeShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CodeShare")
            .field("pairing_id", &Redacted(16))
            .field("role", &self.role)
            .field("element", &Redacted(32))
            .finish()
    }
}

fn check_version(version: [u8; 2]) -> Result<(), DecodeError> {
    if u16::from_be_bytes(version) == CODE_OFFER_VERSION {
        Ok(())
    } else {
        Err(DecodeError::Version)
    }
}

/// Prints only a length, for values that must not appear in logs.
struct Redacted(usize);

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{} bytes]", self.0)
    }
}

#[cfg(test)]
mod tests;
