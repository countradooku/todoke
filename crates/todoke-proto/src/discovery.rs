//! Discovery records (PROTOCOL §9): the 19-byte `DiscoveryRecord` embedded
//! in mDNS (and, once allocated, BLE), its mDNS TXT string, and the mDNS
//! instance label.
//!
//! Discovery never authenticates a peer. A record that decodes is only a
//! candidate filter: its token may match a contact by chance or by replay,
//! and its addresses and ports are untrusted routing hints. Whether a token
//! matches a contact, and for which epoch, belongs to `todoke-crypto`; what
//! to connect to belongs to the transport layer.
//!
//! These codecs check layout only: exact lengths, version, mode, the epoch
//! range, the reserved flags, nonzero tokens, and lowercase hex.

use core::fmt;

use crate::session::DecodeError;
use crate::time::{MAX_UNIX_TIME, UnixTime};

/// The only `DiscoveryRecord` version (§9).
pub const DISCOVERY_VERSION: u8 = 1;
/// `DiscoveryRecord` length (§9).
pub const DISCOVERY_RECORD_LEN: usize = 19;
/// Discovery token length (§9).
pub const DISCOVERY_TOKEN_LEN: usize = 8;
/// Length of one discovery epoch in seconds: `epoch = floor(unix_time / 900)`.
pub const EPOCH_SECONDS: u64 = 900;
/// The mDNS service type (§9).
pub const MDNS_SERVICE: &str = "_todoke._tcp.local.";
/// The mDNS TXT key; the TXT string is the key, `=`, and the record in hex (§9).
pub const MDNS_TXT_KEY: &str = "v1";
/// Length of the mDNS TXT string `v1=` plus 38 lowercase hex characters.
pub const MDNS_TXT_LEN: usize = 3 + 2 * DISCOVERY_RECORD_LEN;
/// Length of an mDNS instance label: 16 lowercase hex characters (§9).
pub const INSTANCE_LABEL_LEN: usize = 16;

/// The largest epoch of a protocol time (§1).
const MAX_EPOCH: u64 = MAX_UNIX_TIME / EPOCH_SECONDS;

/// What a record advertises (§9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DiscoveryMode {
    /// A paired device's rotating per-pair token.
    Paired,
    /// A device in explicitly enabled stranger mode, for QR or code pairing;
    /// the token is uniform random and identifies nobody.
    Stranger,
}

impl DiscoveryMode {
    const fn to_u8(self) -> u8 {
        match self {
            Self::Paired => 0,
            Self::Stranger => 1,
        }
    }

    const fn from_u8(value: u8) -> Result<Self, DecodeError> {
        match value {
            0 => Ok(Self::Paired),
            1 => Ok(Self::Stranger),
            _ => Err(DecodeError::UnknownEnum),
        }
    }
}

/// A discovery epoch, `floor(unix_time / 900)`, within the protocol time
/// range (§1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Epoch(u64);

impl Epoch {
    /// The epoch containing `time`.
    #[must_use]
    pub const fn of(time: UnixTime) -> Self {
        Self(time.seconds() / EPOCH_SECONDS)
    }

    /// An epoch number.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Range`] beyond the protocol time range.
    pub const fn new(epoch: u64) -> Result<Self, DecodeError> {
        if epoch > MAX_EPOCH {
            return Err(DecodeError::Range);
        }
        Ok(Self(epoch))
    }

    /// The epoch number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The epochs a receiver tests for a record of this epoch: the previous
    /// (if any), this, and the next (if in range), in that order (§9).
    pub fn adjacent(self) -> impl Iterator<Item = Self> {
        [self.0.checked_sub(1), Some(self.0), self.0.checked_add(1)]
            .into_iter()
            .flatten()
            .filter(|&epoch| epoch <= MAX_EPOCH)
            .map(Self)
    }

    /// The first second of the next epoch, when tokens and instance labels
    /// rotate; `None` for the last epoch of the protocol range.
    #[must_use]
    pub fn next_boundary(self) -> Option<UnixTime> {
        let seconds = self.0.checked_add(1)?.checked_mul(EPOCH_SECONDS)?;
        UnixTime::new(seconds)
    }
}

/// `DiscoveryRecord`: `version:u8 || mode:u8 || epoch:u64 || token[8] ||
/// flags:u8` (§9).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DiscoveryRecord {
    mode: DiscoveryMode,
    epoch: Epoch,
    token: [u8; DISCOVERY_TOKEN_LEN],
}

impl DiscoveryRecord {
    /// A record advertising `token` for `epoch`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::ZeroIdentifier`] for an all-zero token, which no live
    /// message may carry (§1).
    pub fn new(
        mode: DiscoveryMode,
        epoch: Epoch,
        token: [u8; DISCOVERY_TOKEN_LEN],
    ) -> Result<Self, DecodeError> {
        if token == [0; DISCOVERY_TOKEN_LEN] {
            return Err(DecodeError::ZeroIdentifier);
        }
        Ok(Self { mode, epoch, token })
    }

    /// Parses exactly [`DISCOVERY_RECORD_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`], [`DecodeError::Version`],
    /// [`DecodeError::UnknownEnum`] for a mode other than 0 or 1,
    /// [`DecodeError::Range`] for an epoch beyond the protocol time range,
    /// [`DecodeError::Reserved`] for nonzero flags, or
    /// [`DecodeError::ZeroIdentifier`] for an all-zero token.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let bytes: &[u8; DISCOVERY_RECORD_LEN] =
            bytes.try_into().map_err(|_| DecodeError::Length)?;
        let [version, mode, rest @ ..] = bytes;
        if *version != DISCOVERY_VERSION {
            return Err(DecodeError::Version);
        }
        let mode = DiscoveryMode::from_u8(*mode)?;
        let (epoch, rest) = rest.split_first_chunk::<8>().ok_or(DecodeError::Length)?;
        let (token, flags) = rest
            .split_first_chunk::<DISCOVERY_TOKEN_LEN>()
            .ok_or(DecodeError::Length)?;
        if flags != [0] {
            return Err(DecodeError::Reserved);
        }
        Self::new(mode, Epoch::new(u64::from_be_bytes(*epoch))?, *token)
    }

    /// The exact [`DISCOVERY_RECORD_LEN`]-byte record.
    #[must_use]
    pub fn encode(&self) -> [u8; DISCOVERY_RECORD_LEN] {
        let mut out = [0; DISCOVERY_RECORD_LEN];
        out[0] = DISCOVERY_VERSION;
        out[1] = self.mode.to_u8();
        out[2..10].copy_from_slice(&self.epoch.0.to_be_bytes());
        out[10..18].copy_from_slice(&self.token);
        out
    }

    /// Parses the mDNS TXT string: exactly `v1=` and 38 lowercase hex
    /// characters (§9).
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`] for any other length or key,
    /// [`DecodeError::Reserved`] for a character that is not lowercase hex
    /// (uppercase included), or any [`Self::decode`] error.
    pub fn from_txt(txt: &[u8]) -> Result<Self, DecodeError> {
        let txt: &[u8; MDNS_TXT_LEN] = txt.try_into().map_err(|_| DecodeError::Length)?;
        let (key, hex) = txt.split_first_chunk::<3>().ok_or(DecodeError::Length)?;
        if key != b"v1=" {
            return Err(DecodeError::Length);
        }
        let mut record = [0; DISCOVERY_RECORD_LEN];
        decode_lower_hex(hex, &mut record)?;
        Self::decode(&record)
    }

    /// The mDNS TXT string value, the 38 lowercase hex characters after
    /// `v1=`.
    #[must_use]
    pub fn txt_value(&self) -> String {
        let mut out = String::with_capacity(2 * DISCOVERY_RECORD_LEN);
        for byte in self.encode() {
            push_lower_hex(&mut out, byte);
        }
        out
    }

    /// The whole mDNS TXT string, `v1=` and the record in lowercase hex.
    #[must_use]
    pub fn to_txt(&self) -> String {
        format!("{MDNS_TXT_KEY}={}", self.txt_value())
    }

    /// The record's mode.
    #[must_use]
    pub const fn mode(&self) -> DiscoveryMode {
        self.mode
    }

    /// The epoch the advertiser claims; untrusted.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// The advertised token.
    #[must_use]
    pub const fn token(&self) -> &[u8; DISCOVERY_TOKEN_LEN] {
        &self.token
    }
}

/// Redacted: tokens link a device pair within an epoch (§14.2).
impl fmt::Debug for DiscoveryRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiscoveryRecord")
            .field("mode", &self.mode)
            .field("epoch", &self.epoch)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// An mDNS instance label: 16 lowercase hex characters from 8 random bytes,
/// never a device name (§9).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct InstanceLabel([u8; INSTANCE_LABEL_LEN]);

impl InstanceLabel {
    /// The label for 8 random bytes (from an OS CSPRNG, §1).
    ///
    /// # Errors
    ///
    /// [`DecodeError::ZeroIdentifier`] for all-zero bytes.
    pub fn from_random(random: [u8; 8]) -> Result<Self, DecodeError> {
        if random == [0; 8] {
            return Err(DecodeError::ZeroIdentifier);
        }
        let mut out = String::with_capacity(INSTANCE_LABEL_LEN);
        for byte in random {
            push_lower_hex(&mut out, byte);
        }
        let mut label = [0; INSTANCE_LABEL_LEN];
        label.copy_from_slice(out.as_bytes());
        Ok(Self(label))
    }

    /// Parses an instance label: exactly 16 lowercase hex characters.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`], [`DecodeError::Reserved`] for a character
    /// that is not lowercase hex, or [`DecodeError::ZeroIdentifier`].
    pub fn parse(label: &str) -> Result<Self, DecodeError> {
        let bytes: &[u8; INSTANCE_LABEL_LEN] = label
            .as_bytes()
            .try_into()
            .map_err(|_| DecodeError::Length)?;
        let mut random = [0; 8];
        decode_lower_hex(bytes, &mut random)?;
        Self::from_random(random)
    }

    /// The label text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Only lowercase hex digits are ever stored.
        core::str::from_utf8(&self.0).unwrap_or_default()
    }
}

impl fmt::Debug for InstanceLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InstanceLabel(<redacted>)")
    }
}

fn push_lower_hex(out: &mut String, byte: u8) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    out.push(char::from(DIGITS[usize::from(byte >> 4)]));
    out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
}

/// Decodes exactly `2 * out.len()` lowercase hex characters.
fn decode_lower_hex(hex: &[u8], out: &mut [u8]) -> Result<(), DecodeError> {
    if hex.len() != 2 * out.len() {
        return Err(DecodeError::Length);
    }
    let (pairs, _) = hex.as_chunks::<2>();
    for ([high, low], byte) in pairs.iter().zip(out.iter_mut()) {
        *byte = (nibble(*high)? << 4) | nibble(*low)?;
    }
    Ok(())
}

const fn nibble(c: u8) -> Result<u8, DecodeError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(DecodeError::Reserved),
    }
}

#[cfg(test)]
mod tests;
