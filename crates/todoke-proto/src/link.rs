//! Link setup records (PROTOCOL §10.2): `LinkAbilities`, `LinkOffer`, and
//! `LinkAnswer`, sent inside an authenticated session to move two devices
//! to a faster direct link, and the rule that picks the link and its host.
//!
//! The codecs check layout only: exact lengths, reserved bits, enum values,
//! ranges (expiry, port), that the security fits the kind, the exact SSID
//! and passphrase shapes, and that an offer ID is not all zero. When each
//! record may come is the session's job.
//!
//! An offer carries a Wi-Fi credential (a Wi-Fi Aware PMK or a passphrase):
//! it is kept in zeroizing memory and never printed.

use core::fmt;

use zeroize::Zeroizing;

use crate::session::DecodeError;

/// Offer ID length (§10.2).
pub const OFFER_ID_LEN: usize = 16;
/// Shortest offer lifetime, in seconds (§10.2).
pub const MIN_OFFER_SECONDS: u8 = 10;
/// Longest offer lifetime, in seconds (§10.2).
pub const MAX_OFFER_SECONDS: u8 = 120;
/// Lowest listening port a host may offer (§10.1).
pub const MIN_PORT: u16 = 1024;
/// Longest SSID (§10.2).
pub const MAX_SSID_LEN: usize = 32;
/// Wi-Fi Aware PMK length (§10.2).
pub const PMK_LEN: usize = 32;
/// Passphrase length (§10.2): 63 characters from `A-Z a-z 0-9 - _`.
pub const PASSPHRASE_LEN: usize = 63;
/// Hotspot SSID: `todoke-` and 16 lowercase hexadecimal digits (§10.2).
pub const HOTSPOT_SSID_LEN: usize = 23;
/// Wi-Fi Direct SSID: `DIRECT-`, 2 lowercase hexadecimal digits, `-tdk-`,
/// and 16 lowercase hexadecimal digits (§10.2).
pub const DIRECT_SSID_LEN: usize = 30;
/// Length of a `LinkAbilities` body.
pub const ABILITIES_LEN: usize = 3;
/// Length of a `LinkAnswer` body.
pub const ANSWER_LEN: usize = OFFER_ID_LEN + 1;
/// Fixed part of a `LinkOffer` body (without SSID and secret).
const OFFER_FIXED_LEN: usize = OFFER_ID_LEN + 1 + 1 + 1 + 2 + 1 + 1;

/// A direct link kind (§10.2), in order of preference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LinkKind {
    /// A Wi-Fi Aware data path.
    WifiAware,
    /// A Wi-Fi Direct group.
    WifiDirect,
    /// A hotspot one device hosts for the other.
    Hotspot,
}

impl LinkKind {
    /// Every kind, most preferred first.
    pub const ALL: [Self; 3] = [Self::WifiAware, Self::WifiDirect, Self::Hotspot];

    /// The kind's code in a `LinkOffer`.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::WifiAware => 1,
            Self::WifiDirect => 2,
            Self::Hotspot => 3,
        }
    }

    /// The kind's bit in a `LinkAbilities` mask.
    #[must_use]
    pub const fn bit(self) -> u8 {
        1 << (self.code() - 1)
    }

    const fn from_code(code: u8) -> Result<Self, DecodeError> {
        match code {
            1 => Ok(Self::WifiAware),
            2 => Ok(Self::WifiDirect),
            3 => Ok(Self::Hotspot),
            _ => Err(DecodeError::UnknownEnum),
        }
    }
}

/// The link-layer security of an offer (§10.2); never open, WEP, or WPS.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LinkSecurity {
    /// WPA3-Personal, SAE only.
    Wpa3,
    /// WPA3-Personal transition mode (SAE or WPA2-PSK).
    Wpa3Transition,
    /// WPA2-PSK.
    Wpa2,
    /// Wi-Fi Aware NCS-SK-256.
    AwareSk256,
    /// Wi-Fi Aware NCS-SK-128.
    AwareSk128,
}

impl LinkSecurity {
    /// Every value, strongest first within each kind.
    pub const ALL: [Self; 5] = [
        Self::Wpa3,
        Self::Wpa3Transition,
        Self::Wpa2,
        Self::AwareSk256,
        Self::AwareSk128,
    ];

    /// The value's bit in a `LinkAbilities` security mask.
    #[must_use]
    pub const fn bit(self) -> u8 {
        1 << (self.code() - 1)
    }

    /// The value in a `LinkOffer`.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Wpa3 => 1,
            Self::Wpa3Transition => 2,
            Self::Wpa2 => 3,
            Self::AwareSk256 => 4,
            Self::AwareSk128 => 5,
        }
    }

    /// Whether this security belongs to `kind`.
    #[must_use]
    pub const fn fits(self, kind: LinkKind) -> bool {
        matches!(
            (kind, self),
            (LinkKind::WifiAware, Self::AwareSk256 | Self::AwareSk128)
                | (LinkKind::WifiDirect | LinkKind::Hotspot, Self::Wpa2)
                | (LinkKind::Hotspot, Self::Wpa3 | Self::Wpa3Transition)
        )
    }

    const fn from_code(code: u8) -> Result<Self, DecodeError> {
        match code {
            1 => Ok(Self::Wpa3),
            2 => Ok(Self::Wpa3Transition),
            3 => Ok(Self::Wpa2),
            4 => Ok(Self::AwareSk256),
            5 => Ok(Self::AwareSk128),
            _ => Err(DecodeError::UnknownEnum),
        }
    }
}

/// What an endpoint can host and join now (`LinkAbilities`, 0x0020).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkAbilities {
    host: u8,
    join: u8,
    join_security: u8,
}

/// Every defined kind bit.
const KIND_BITS: u8 = 0b111;
/// Every defined security bit.
const SECURITY_BITS: u8 = 0b1_1111;

impl LinkAbilities {
    /// Abilities from the kinds this endpoint can host and join, and the
    /// security it can join with.
    #[must_use]
    pub fn new(host: &[LinkKind], join: &[LinkKind], join_security: &[LinkSecurity]) -> Self {
        let kinds = |kinds: &[LinkKind]| kinds.iter().fold(0, |mask, kind| mask | kind.bit());
        Self {
            host: kinds(host),
            join: kinds(join),
            join_security: join_security
                .iter()
                .fold(0, |mask, security| mask | security.bit()),
        }
    }

    /// Whether this endpoint can host `kind`.
    #[must_use]
    pub const fn hosts(self, kind: LinkKind) -> bool {
        self.host & kind.bit() != 0
    }

    /// Whether this endpoint can join `kind`.
    #[must_use]
    pub const fn joins(self, kind: LinkKind) -> bool {
        self.join & kind.bit() != 0
    }

    /// The strongest security of `kind` this endpoint can join with.
    #[must_use]
    pub fn strongest(self, kind: LinkKind) -> Option<LinkSecurity> {
        LinkSecurity::ALL
            .into_iter()
            .find(|security| security.fits(kind) && self.join_security & security.bit() != 0)
    }

    /// The body.
    #[must_use]
    pub const fn encode(self) -> [u8; ABILITIES_LEN] {
        [self.host, self.join, self.join_security]
    }

    /// Decodes a body.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`] for a body that is not 3 bytes;
    /// [`DecodeError::Reserved`] for an undefined kind or security bit.
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let [host, join, join_security] =
            <[u8; ABILITIES_LEN]>::try_from(body).map_err(|_| DecodeError::Length)?;
        if (host | join) & !KIND_BITS != 0 || join_security & !SECURITY_BITS != 0 {
            return Err(DecodeError::Reserved);
        }
        Ok(Self {
            host,
            join,
            join_security,
        })
    }
}

/// Which side hosts the chosen link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkRole {
    /// This endpoint hosts and sends the `LinkOffer`.
    Host,
    /// This endpoint joins.
    Join,
}

/// The link two endpoints set up, its host, and its security.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkChoice {
    /// The link kind.
    pub kind: LinkKind,
    /// This endpoint's role.
    pub role: LinkRole,
    /// The strongest security of the kind the joiner can join with.
    pub security: LinkSecurity,
}

/// The link two endpoints set up (§10.2): the first kind, in order of
/// preference, that one can host and the other can join with some
/// security of that kind. If both can host it, the endpoint with the
/// lexicographically smaller full device key hosts (`own_key_smaller`).
/// The security is the strongest the joiner can join with. `None` when no
/// kind fits.
#[must_use]
pub fn choose(
    own: LinkAbilities,
    peer: LinkAbilities,
    own_key_smaller: bool,
) -> Option<LinkChoice> {
    LinkKind::ALL.into_iter().find_map(|kind| {
        let own_hosts = own.hosts(kind) && peer.joins(kind) && peer.strongest(kind).is_some();
        let peer_hosts = peer.hosts(kind) && own.joins(kind) && own.strongest(kind).is_some();
        let role = match (own_hosts, peer_hosts) {
            (true, true) if own_key_smaller => LinkRole::Host,
            (_, true) => LinkRole::Join,
            (true, false) => LinkRole::Host,
            (false, false) => return None,
        };
        let joiner = match role {
            LinkRole::Host => peer,
            LinkRole::Join => own,
        };
        Some(LinkChoice {
            kind,
            role,
            security: joiner.strongest(kind)?,
        })
    })
}

/// A host's offer of a link (`LinkOffer`, 0x0021).
#[derive(Clone, PartialEq, Eq)]
pub struct LinkOffer {
    offer_id: [u8; OFFER_ID_LEN],
    kind: LinkKind,
    security: LinkSecurity,
    expires_in: u8,
    port: u16,
    ssid: Vec<u8>,
    secret: Zeroizing<Vec<u8>>,
}

impl LinkOffer {
    /// An offer, checked as [`Self::decode`] checks one.
    ///
    /// # Errors
    ///
    /// The [`DecodeError`] the encoded offer would fail with.
    pub fn new(
        offer_id: [u8; OFFER_ID_LEN],
        kind: LinkKind,
        security: LinkSecurity,
        expires_in: u8,
        port: u16,
        ssid: Vec<u8>,
        secret: Zeroizing<Vec<u8>>,
    ) -> Result<Self, DecodeError> {
        let offer = Self {
            offer_id,
            kind,
            security,
            expires_in,
            port,
            ssid,
            secret,
        };
        offer.check()?;
        Ok(offer)
    }

    fn check(&self) -> Result<(), DecodeError> {
        if self.offer_id == [0; OFFER_ID_LEN] {
            return Err(DecodeError::ZeroIdentifier);
        }
        if !self.security.fits(self.kind) {
            return Err(DecodeError::UnknownEnum);
        }
        if !(MIN_OFFER_SECONDS..=MAX_OFFER_SECONDS).contains(&self.expires_in)
            || self.port < MIN_PORT
        {
            return Err(DecodeError::Range);
        }
        let passphrase = |secret: &[u8]| {
            secret.len() == PASSPHRASE_LEN
                && secret
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        };
        let shaped = match self.kind {
            LinkKind::WifiAware => self.ssid.is_empty() && self.secret.len() == PMK_LEN,
            LinkKind::WifiDirect => direct_ssid(&self.ssid) && passphrase(&self.secret),
            LinkKind::Hotspot => hotspot_ssid(&self.ssid) && passphrase(&self.secret),
        };
        if !shaped {
            return Err(DecodeError::Length);
        }
        Ok(())
    }

    /// The offer ID.
    #[must_use]
    pub const fn offer_id(&self) -> &[u8; OFFER_ID_LEN] {
        &self.offer_id
    }

    /// The link kind.
    #[must_use]
    pub const fn kind(&self) -> LinkKind {
        self.kind
    }

    /// The link-layer security.
    #[must_use]
    pub const fn security(&self) -> LinkSecurity {
        self.security
    }

    /// Seconds the offer stays open.
    #[must_use]
    pub const fn expires_in(&self) -> u8 {
        self.expires_in
    }

    /// The host's listening port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The network name (empty for Wi-Fi Aware).
    #[must_use]
    pub fn ssid(&self) -> &[u8] {
        &self.ssid
    }

    /// The PMK (Wi-Fi Aware) or passphrase. A secret: never log it.
    #[must_use]
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    /// The body.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(
            OFFER_FIXED_LEN + self.ssid.len() + self.secret.len(),
        ));
        out.extend_from_slice(&self.offer_id);
        out.extend_from_slice(&[self.kind.code(), self.security.code(), self.expires_in]);
        out.extend_from_slice(&self.port.to_be_bytes());
        // Both lengths are checked at construction (<= 63).
        out.push(u8::try_from(self.ssid.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(&self.ssid);
        out.push(u8::try_from(self.secret.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(&self.secret);
        out
    }

    /// Decodes a body.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`] for a body whose lengths disagree with it or
    /// with the kind; [`DecodeError::UnknownEnum`] for an undefined kind or
    /// security, or a security of another kind;
    /// [`DecodeError::Range`] for an expiry or port out of range;
    /// [`DecodeError::ZeroIdentifier`] for an all-zero offer ID.
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let (fixed, rest) = body
            .split_at_checked(OFFER_FIXED_LEN - 1)
            .ok_or(DecodeError::Length)?;
        let (offer_id, fixed) = fixed.split_at(OFFER_ID_LEN);
        let offer_id: [u8; OFFER_ID_LEN] = offer_id.try_into().map_err(|_| DecodeError::Length)?;
        let [kind, security, expires_in, port_hi, port_lo, ssid_len] =
            <[u8; 6]>::try_from(fixed).map_err(|_| DecodeError::Length)?;
        let (ssid, rest) = rest
            .split_at_checked(usize::from(ssid_len))
            .ok_or(DecodeError::Length)?;
        let (&secret_len, secret) = rest.split_first().ok_or(DecodeError::Length)?;
        if secret.len() != usize::from(secret_len) || ssid.len() > MAX_SSID_LEN {
            return Err(DecodeError::Length);
        }
        Self::new(
            offer_id,
            LinkKind::from_code(kind)?,
            LinkSecurity::from_code(security)?,
            expires_in,
            u16::from_be_bytes([port_hi, port_lo]),
            ssid.to_vec(),
            Zeroizing::new(secret.to_vec()),
        )
    }
}

/// Lowercase hexadecimal digits only.
fn lower_hex(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

/// `todoke-` and 16 lowercase hexadecimal digits.
fn hotspot_ssid(ssid: &[u8]) -> bool {
    ssid.len() == HOTSPOT_SSID_LEN && ssid.strip_prefix(b"todoke-").is_some_and(lower_hex)
}

/// `DIRECT-`, 2 lowercase hexadecimal digits, `-tdk-`, and 16 lowercase
/// hexadecimal digits (Android requires the `DIRECT-xy` prefix).
fn direct_ssid(ssid: &[u8]) -> bool {
    ssid.len() == DIRECT_SSID_LEN
        && ssid.strip_prefix(b"DIRECT-").is_some_and(|rest| {
            let (xy, rest) = rest.split_at(2);
            lower_hex(xy) && rest.strip_prefix(b"-tdk-").is_some_and(lower_hex)
        })
}

/// Redacted: the secret is a Wi-Fi credential.
impl fmt::Debug for LinkOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkOffer")
            .field("kind", &self.kind)
            .field("security", &self.security)
            .field("expires_in", &self.expires_in)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

/// The joiner's answer (§10.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkResult {
    /// It is joining: it leaves the session, joins, and connects over
    /// the link next (sent before it joins: one radio cannot keep the
    /// session's network and join another).
    Joining,
    /// It will not join this offer.
    Declined,
    /// It could not join (for example, the security is not supported).
    Failed,
}

/// The answer to an offer (`LinkAnswer`, 0x0022).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkAnswer {
    /// The offer answered.
    pub offer_id: [u8; OFFER_ID_LEN],
    /// The result.
    pub result: LinkResult,
}

impl LinkAnswer {
    /// The body.
    #[must_use]
    pub fn encode(&self) -> [u8; ANSWER_LEN] {
        let mut out = [0; ANSWER_LEN];
        out[..OFFER_ID_LEN].copy_from_slice(&self.offer_id);
        out[OFFER_ID_LEN] = match self.result {
            LinkResult::Joining => 1,
            LinkResult::Declined => 2,
            LinkResult::Failed => 3,
        };
        out
    }

    /// Decodes a body.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`] for a body that is not 17 bytes;
    /// [`DecodeError::UnknownEnum`] for an undefined result;
    /// [`DecodeError::ZeroIdentifier`] for an all-zero offer ID.
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let body = <[u8; ANSWER_LEN]>::try_from(body).map_err(|_| DecodeError::Length)?;
        let (offer_id, result) = body.split_at(OFFER_ID_LEN);
        let offer_id: [u8; OFFER_ID_LEN] = offer_id.try_into().map_err(|_| DecodeError::Length)?;
        if offer_id == [0; OFFER_ID_LEN] {
            return Err(DecodeError::ZeroIdentifier);
        }
        let result = match result {
            [1] => LinkResult::Joining,
            [2] => LinkResult::Declined,
            [3] => LinkResult::Failed,
            _ => return Err(DecodeError::UnknownEnum),
        };
        Ok(Self { offer_id, result })
    }
}

#[cfg(test)]
mod tests;
