//! Pointing records (PROTOCOL §10.4): `RangingReady`, `RangingStart`,
//! `RangingAccept`, and `RangingStop`, which let two contacts in a session
//! range with ultra-wideband so a user can pick a nearby contact by
//! pointing at it. Every UWB address serves one ranging only: each side
//! sends its own with each ranging (the start, the accept).
//! Ranging is an interface hint only; nothing here authenticates or
//! consents to anything.
//!
//! The codecs check layout only: exact lengths, reserved bits, the address,
//! channel, preamble, and configuration ranges, and non-zero session IDs.
//! When each record may come is the session's job. A start carries the
//! provisioned STS key: it is kept in zeroizing memory and never printed.

use core::fmt;

use zeroize::Zeroizing;

use crate::session::DecodeError;

/// `RangingReady` body length.
pub const READY_LEN: usize = 1;
/// `RangingStart` body length.
pub const START_LEN: usize = 25;
/// `RangingAccept` body length.
pub const ACCEPT_LEN: usize = 6;
/// `RangingStop` body length.
pub const STOP_LEN: usize = 4;
/// STS key length (provisioned STS).
pub const STS_KEY_LEN: usize = 16;
/// Starts per session (§13).
pub const MAX_STARTS: u8 = 8;
/// How long one ranging may run, in seconds (§10.4).
pub const MAX_RANGING_SECONDS: u64 = 120;

/// The configurations (bit 0: provisioned-STS unicast DS-TWR).
pub const CONFIG_PROVISIONED_DS_TWR: u8 = 0b1;
const CONFIGS: u8 = CONFIG_PROVISIONED_DS_TWR;

/// A UWB short address that may name a device (not 0x0000 or 0xffff).
fn address(value: u16) -> Result<u16, DecodeError> {
    if value == 0 || value == u16::MAX {
        return Err(DecodeError::Range);
    }
    Ok(value)
}

/// `RangingReady` (0x0023): this endpoint can range as a controlee now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangingReady {
    /// The configurations it supports (a bitmask, not zero).
    pub configs: u8,
}

impl RangingReady {
    /// The body.
    #[must_use]
    pub const fn encode(&self) -> [u8; READY_LEN] {
        [self.configs]
    }

    /// Decodes a body.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`]; [`DecodeError::Reserved`] for no or an
    /// unassigned configuration.
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let [configs] = <[u8; READY_LEN]>::try_from(body).map_err(|_| DecodeError::Length)?;
        if configs == 0 || configs & !CONFIGS != 0 {
            return Err(DecodeError::Reserved);
        }
        Ok(Self { configs })
    }
}

/// `RangingStart` (0x0024): the controller's parameters for one ranging.
#[derive(Clone, PartialEq, Eq)]
pub struct RangingStart {
    /// The ranging session ID (not zero).
    pub session_id: u32,
    /// The controller's UWB short address.
    pub controller: u16,
    /// The channel: 5 or 9.
    pub channel: u8,
    /// The preamble index: 9..12 or 25..32.
    pub preamble: u8,
    /// The one configuration used.
    pub config: u8,
    /// The provisioned STS key, fresh for this start.
    pub sts_key: Zeroizing<[u8; STS_KEY_LEN]>,
}

impl fmt::Debug for RangingStart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RangingStart")
            .field("session_id", &self.session_id)
            .field("controller", &self.controller)
            .field("channel", &self.channel)
            .field("preamble", &self.preamble)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl RangingStart {
    /// The body (holds the key: zeroized when dropped).
    #[must_use]
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(START_LEN));
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.extend_from_slice(&self.controller.to_be_bytes());
        out.extend_from_slice(&[self.channel, self.preamble, self.config]);
        out.extend_from_slice(&*self.sts_key);
        out
    }

    /// Decodes a body.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`]; [`DecodeError::ZeroIdentifier`] for a zero
    /// session ID; [`DecodeError::Range`] for an address, channel, or
    /// preamble outside its limits; [`DecodeError::Reserved`] for a
    /// configuration that is not exactly one assigned bit.
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let body = <&[u8; START_LEN]>::try_from(body).map_err(|_| DecodeError::Length)?;
        let session_id = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        if session_id == 0 {
            return Err(DecodeError::ZeroIdentifier);
        }
        let controller = address(u16::from_be_bytes([body[4], body[5]]))?;
        let (channel, preamble, config) = (body[6], body[7], body[8]);
        if !matches!(channel, 5 | 9) || !matches!(preamble, 9..=12 | 25..=32) {
            return Err(DecodeError::Range);
        }
        if config.count_ones() != 1 || config & !CONFIGS != 0 {
            return Err(DecodeError::Reserved);
        }
        let mut sts_key = Zeroizing::new([0; STS_KEY_LEN]);
        sts_key.copy_from_slice(&body[9..]);
        Ok(Self {
            session_id,
            controller,
            channel,
            preamble,
            config,
            sts_key,
        })
    }
}

/// `RangingAccept` (0x0026): the controlee ranges, at this address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangingAccept {
    /// The ranging session ID.
    pub session_id: u32,
    /// The controlee's UWB short address for this ranging.
    pub controlee: u16,
}

impl RangingAccept {
    /// The body.
    #[must_use]
    pub fn encode(&self) -> [u8; ACCEPT_LEN] {
        let mut out = [0; ACCEPT_LEN];
        out[..4].copy_from_slice(&self.session_id.to_be_bytes());
        out[4..].copy_from_slice(&self.controlee.to_be_bytes());
        out
    }

    /// Decodes a body.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`]; [`DecodeError::ZeroIdentifier`];
    /// [`DecodeError::Range`] for an address that names no device.
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let body = <[u8; ACCEPT_LEN]>::try_from(body).map_err(|_| DecodeError::Length)?;
        let session_id = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        if session_id == 0 {
            return Err(DecodeError::ZeroIdentifier);
        }
        Ok(Self {
            session_id,
            controlee: address(u16::from_be_bytes([body[4], body[5]]))?,
        })
    }
}

/// `RangingStop` (0x0025): the ranging with this session ID ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangingStop {
    /// The ranging session ID.
    pub session_id: u32,
}

impl RangingStop {
    /// The body.
    #[must_use]
    pub const fn encode(&self) -> [u8; STOP_LEN] {
        self.session_id.to_be_bytes()
    }

    /// Decodes a body.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`]; [`DecodeError::ZeroIdentifier`].
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let bytes = <[u8; STOP_LEN]>::try_from(body).map_err(|_| DecodeError::Length)?;
        let session_id = u32::from_be_bytes(bytes);
        if session_id == 0 {
            return Err(DecodeError::ZeroIdentifier);
        }
        Ok(Self { session_id })
    }
}

#[cfg(test)]
mod tests;
