//! Relay control records (PROTOCOL §10): the envelope
//! `length:u16 || type:u8 || body` on a relay control stream, and the
//! exact body of each record.
//!
//! A relay is untrusted. These records only match two endpoints that know
//! the same rendezvous token and switch their stream to an opaque tunnel;
//! nothing in them authenticates a peer, and a decoded record proves
//! nothing about who sent it. Room, nonce, and candidate values are
//! routing hints.
//!
//! The codecs check layout only: exact body lengths, the version, ranges
//! (TTL, expiry, delay, candidate count and ports), nonzero random values,
//! IPv4 padding, and duplicate candidates. Which record may come when (the
//! per-room order of §10) is the state machine's job, in the relay and the
//! client.

use core::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::session::DecodeError;

/// The only `Register` version (§10).
pub const RELAY_VERSION: u16 = 1;
/// Largest envelope `length` (type and body), §10.
pub const MAX_CONTROL_LEN: usize = 2048;
/// Envelope header: the `length` field.
pub const CONTROL_HEADER_LEN: usize = 2;
/// Rendezvous token length (§9, §10).
pub const RENDEZVOUS_TOKEN_LEN: usize = 32;
/// Room ID and nonce lengths (§10).
pub const ROOM_ID_LEN: usize = 16;
/// Client, peer, and punch nonce length (§10).
pub const NONCE_LEN: usize = 16;
/// Longest room lifetime, and the largest `ttl_seconds` (§10).
pub const MAX_ROOM_SECONDS: u16 = 120;
/// Longest wait for the other endpoint (§10).
pub const MAX_WAIT_SECONDS: u16 = 30;
/// Clients per rendezvous token (§10).
pub const MAX_CLIENTS_PER_TOKEN: usize = 2;
/// Simultaneous rooms per endpoint (§10).
pub const MAX_ROOMS_PER_ENDPOINT: usize = 2;
/// Candidates per endpoint (§10).
pub const MAX_CANDIDATES: usize = 4;
/// Largest `Punch` delay (§10).
pub const MAX_PUNCH_DELAY_MS: u16 = 2000;
/// Longest forwarding tunnel (§10).
pub const MAX_TUNNEL_SECONDS: u64 = 24 * 3600;
/// Most bytes a tunnel forwards in each direction (§10).
pub const MAX_TUNNEL_BYTES: u64 = 16 << 40;
/// Most bytes a relay buffers in each direction of a tunnel (§10).
pub const MAX_TUNNEL_BUFFER: usize = 1 << 20;

const REGISTER_LEN: usize = 2 + RENDEZVOUS_TOKEN_LEN + NONCE_LEN + 2;
const REGISTERED_LEN: usize = ROOM_ID_LEN + NONCE_LEN + 2;
const PEER_READY_LEN: usize = ROOM_ID_LEN + NONCE_LEN;
const CANDIDATE_LEN: usize = 19;
const PUNCH_LEN: usize = ROOM_ID_LEN + 2 + NONCE_LEN;
const FORWARD_LEN: usize = ROOM_ID_LEN;
const RELAY_CLOSE_LEN: usize = ROOM_ID_LEN + 2;

/// A rendezvous token (§9 for contacts, §10 for QR pairing): never zero.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RendezvousToken([u8; RENDEZVOUS_TOKEN_LEN]);

impl RendezvousToken {
    /// A token.
    ///
    /// # Errors
    ///
    /// [`DecodeError::ZeroIdentifier`] for all-zero bytes.
    pub const fn new(bytes: [u8; RENDEZVOUS_TOKEN_LEN]) -> Result<Self, DecodeError> {
        if is_zero(&bytes) {
            return Err(DecodeError::ZeroIdentifier);
        }
        Ok(Self(bytes))
    }

    /// The bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; RENDEZVOUS_TOKEN_LEN] {
        &self.0
    }
}

impl fmt::Debug for RendezvousToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Linkable within an epoch (§10): never in logs.
        f.write_str("RendezvousToken(<redacted>)")
    }
}

/// A random 16-byte value that must not be zero: a room ID or a nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Random16([u8; 16]);

impl Random16 {
    /// A value.
    ///
    /// # Errors
    ///
    /// [`DecodeError::ZeroIdentifier`] for all-zero bytes.
    pub const fn new(bytes: [u8; 16]) -> Result<Self, DecodeError> {
        if is_zero(&bytes) {
            return Err(DecodeError::ZeroIdentifier);
        }
        Ok(Self(bytes))
    }

    /// The bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// A relay-assigned room ID.
pub type RoomId = Random16;
/// A client, peer, or punch nonce.
pub type Nonce = Random16;

/// Why a relay or client closed a room before the tunnel (§10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CloseCode {
    /// The room or the wait expired.
    Expired,
    /// The token already has two clients, or the endpoint two rooms.
    Full,
    /// A rate or byte quota was reached.
    Quota,
    /// A record was malformed, duplicated, or out of order.
    Malformed,
    /// The relay cannot serve the room.
    Unavailable,
}

impl CloseCode {
    const fn to_u16(self) -> u16 {
        match self {
            Self::Expired => 1,
            Self::Full => 2,
            Self::Quota => 3,
            Self::Malformed => 4,
            Self::Unavailable => 5,
        }
    }

    const fn from_u16(value: u16) -> Result<Self, DecodeError> {
        match value {
            1 => Ok(Self::Expired),
            2 => Ok(Self::Full),
            3 => Ok(Self::Quota),
            4 => Ok(Self::Malformed),
            5 => Ok(Self::Unavailable),
            _ => Err(DecodeError::UnknownEnum),
        }
    }
}

/// A direct-path candidate (§10): an untrusted address hint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Candidate(SocketAddr);

impl Candidate {
    /// A candidate for `address`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Range`] for port 0.
    pub const fn new(address: SocketAddr) -> Result<Self, DecodeError> {
        if address.port() == 0 {
            return Err(DecodeError::Range);
        }
        Ok(Self(address))
    }

    /// The address.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.0
    }

    fn encode(self, out: &mut Vec<u8>) {
        match self.0.ip() {
            IpAddr::V4(ip) => {
                out.push(4);
                out.extend_from_slice(&ip.octets());
                out.extend_from_slice(&[0; 12]);
            }
            IpAddr::V6(ip) => {
                out.push(6);
                out.extend_from_slice(&ip.octets());
            }
        }
        out.extend_from_slice(&self.0.port().to_be_bytes());
    }

    fn decode(bytes: &[u8; CANDIDATE_LEN]) -> Result<Self, DecodeError> {
        let (family, rest) = bytes.split_at(1);
        let (address, port) = rest.split_at(16);
        let port = u16::from_be_bytes([port[0], port[1]]);
        let ip = match family[0] {
            4 => {
                if !is_zero(&address[4..]) {
                    return Err(DecodeError::Reserved);
                }
                IpAddr::V4(Ipv4Addr::new(
                    address[0], address[1], address[2], address[3],
                ))
            }
            6 => {
                let mut octets = [0; 16];
                octets.copy_from_slice(address);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return Err(DecodeError::UnknownEnum),
        };
        Self::new(SocketAddr::new(ip, port))
    }
}

/// One relay control record (§10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Control {
    /// Client → relay: join (or open) the room for `token`.
    Register {
        /// The rendezvous token.
        token: RendezvousToken,
        /// Fresh random, distinct from the peer's.
        client_nonce: Nonce,
        /// Room lifetime asked for, 1..=120 seconds.
        ttl_seconds: u16,
    },
    /// Relay → client: the room it joined.
    Registered {
        /// The room.
        room: RoomId,
        /// The client's nonce, echoed.
        client_nonce: Nonce,
        /// Seconds left, 1..=120 (at most the TTL asked for).
        expires_in: u16,
    },
    /// Relay → both clients: the other endpoint joined.
    PeerReady {
        /// The room.
        room: RoomId,
        /// The other endpoint's nonce.
        peer_nonce: Nonce,
    },
    /// Client → relay → other client: direct-path candidates.
    Candidates {
        /// The room.
        room: RoomId,
        /// At most four, no duplicates.
        candidates: Vec<Candidate>,
    },
    /// Relay → both clients: when to try the candidates.
    Punch {
        /// The room.
        room: RoomId,
        /// 0..=2000 ms after receipt.
        delay_ms: u16,
        /// Random per attempt.
        punch_nonce: Nonce,
    },
    /// Client → relay: switch this stream to a tunnel.
    Forward {
        /// The room.
        room: RoomId,
    },
    /// Relay → client: the stream is a tunnel from now on.
    ForwardReady {
        /// The room.
        room: RoomId,
    },
    /// Either way, before the tunnel: the room is closed.
    RelayClose {
        /// The room, or `None` (zero) if registration failed.
        room: Option<RoomId>,
        /// Why.
        code: CloseCode,
    },
}

impl Control {
    /// The record type (§10).
    #[must_use]
    pub const fn kind(&self) -> u8 {
        match self {
            Self::Register { .. } => 0x01,
            Self::Registered { .. } => 0x02,
            Self::PeerReady { .. } => 0x03,
            Self::Candidates { .. } => 0x04,
            Self::Punch { .. } => 0x05,
            Self::Forward { .. } => 0x06,
            Self::ForwardReady { .. } => 0x07,
            Self::RelayClose { .. } => 0x08,
        }
    }

    /// The whole envelope: `length:u16 || type:u8 || body`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Range`] or [`DecodeError::Length`] for a record that
    /// would not decode (a TTL, expiry, or delay out of range, more than
    /// four or duplicate candidates).
    pub fn encode(&self) -> Result<Vec<u8>, DecodeError> {
        let mut body = Vec::with_capacity(64);
        body.push(self.kind());
        match self {
            Self::Register {
                token,
                client_nonce,
                ttl_seconds,
            } => {
                body.extend_from_slice(&RELAY_VERSION.to_be_bytes());
                body.extend_from_slice(token.as_bytes());
                body.extend_from_slice(client_nonce.as_bytes());
                body.extend_from_slice(&ttl_seconds.to_be_bytes());
            }
            Self::Registered {
                room,
                client_nonce,
                expires_in,
            } => {
                body.extend_from_slice(room.as_bytes());
                body.extend_from_slice(client_nonce.as_bytes());
                body.extend_from_slice(&expires_in.to_be_bytes());
            }
            Self::PeerReady { room, peer_nonce } => {
                body.extend_from_slice(room.as_bytes());
                body.extend_from_slice(peer_nonce.as_bytes());
            }
            Self::Candidates { room, candidates } => {
                body.extend_from_slice(room.as_bytes());
                let count = u8::try_from(candidates.len()).map_err(|_| DecodeError::Range)?;
                body.push(count);
                for candidate in candidates {
                    candidate.encode(&mut body);
                }
            }
            Self::Punch {
                room,
                delay_ms,
                punch_nonce,
            } => {
                body.extend_from_slice(room.as_bytes());
                body.extend_from_slice(&delay_ms.to_be_bytes());
                body.extend_from_slice(punch_nonce.as_bytes());
            }
            Self::Forward { room } | Self::ForwardReady { room } => {
                body.extend_from_slice(room.as_bytes());
            }
            Self::RelayClose { room, code } => {
                let room = room.map_or([0; ROOM_ID_LEN], |room| room.0);
                body.extend_from_slice(&room);
                body.extend_from_slice(&code.to_u16().to_be_bytes());
            }
        }
        // What does not decode is never sent.
        Self::decode(body[0], &body[1..])?;
        let length = u16::try_from(body.len()).map_err(|_| DecodeError::Length)?;
        let mut out = Vec::with_capacity(CONTROL_HEADER_LEN + body.len());
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// The envelope at the start of `input`, and the bytes it took; `None`
    /// while it is incomplete.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`] for a length outside 1..=2048 or a body of
    /// the wrong size; [`DecodeError::UnknownEnum`] for a reserved type
    /// (close; there is no fallback); the body's errors.
    pub fn split(input: &[u8]) -> Result<Option<(Self, usize)>, DecodeError> {
        let Some((header, rest)) = input.split_first_chunk::<CONTROL_HEADER_LEN>() else {
            return Ok(None);
        };
        let length = usize::from(u16::from_be_bytes(*header));
        if length == 0 || length > MAX_CONTROL_LEN {
            return Err(DecodeError::Length);
        }
        let Some(record) = rest.get(..length) else {
            return Ok(None);
        };
        let control = Self::decode(record[0], &record[1..])?;
        Ok(Some((control, CONTROL_HEADER_LEN + length)))
    }

    /// The record of type `kind` with `body`.
    ///
    /// # Errors
    ///
    /// As [`Control::split`].
    pub fn decode(kind: u8, body: &[u8]) -> Result<Self, DecodeError> {
        match kind {
            0x01 => decode_register(body),
            0x02 => {
                let body: &[u8; REGISTERED_LEN] = exact(body)?;
                let (room, rest) = body.split_at(ROOM_ID_LEN);
                let (nonce, expires) = rest.split_at(NONCE_LEN);
                let expires_in = u16::from_be_bytes([expires[0], expires[1]]);
                if !(1..=MAX_ROOM_SECONDS).contains(&expires_in) {
                    return Err(DecodeError::Range);
                }
                Ok(Self::Registered {
                    room: Random16::new(array(room)?)?,
                    client_nonce: Random16::new(array(nonce)?)?,
                    expires_in,
                })
            }
            0x03 => {
                let body: &[u8; PEER_READY_LEN] = exact(body)?;
                let (room, nonce) = body.split_at(ROOM_ID_LEN);
                Ok(Self::PeerReady {
                    room: Random16::new(array(room)?)?,
                    peer_nonce: Random16::new(array(nonce)?)?,
                })
            }
            0x04 => decode_candidates(body),
            0x05 => {
                let body: &[u8; PUNCH_LEN] = exact(body)?;
                let (room, rest) = body.split_at(ROOM_ID_LEN);
                let (delay, nonce) = rest.split_at(2);
                let delay_ms = u16::from_be_bytes([delay[0], delay[1]]);
                if delay_ms > MAX_PUNCH_DELAY_MS {
                    return Err(DecodeError::Range);
                }
                Ok(Self::Punch {
                    room: Random16::new(array(room)?)?,
                    delay_ms,
                    punch_nonce: Random16::new(array(nonce)?)?,
                })
            }
            0x06 | 0x07 => {
                let body: &[u8; FORWARD_LEN] = exact(body)?;
                let room = Random16::new(*body)?;
                Ok(if kind == 0x06 {
                    Self::Forward { room }
                } else {
                    Self::ForwardReady { room }
                })
            }
            0x08 => {
                let body: &[u8; RELAY_CLOSE_LEN] = exact(body)?;
                let (room, code) = body.split_at(ROOM_ID_LEN);
                let room = array(room)?;
                Ok(Self::RelayClose {
                    room: if is_zero(&room) {
                        None
                    } else {
                        Some(Random16(room))
                    },
                    code: CloseCode::from_u16(u16::from_be_bytes([code[0], code[1]]))?,
                })
            }
            _ => Err(DecodeError::UnknownEnum),
        }
    }
}

fn decode_register(body: &[u8]) -> Result<Control, DecodeError> {
    let body: &[u8; REGISTER_LEN] = exact(body)?;
    let (version, rest) = body.split_at(2);
    if u16::from_be_bytes([version[0], version[1]]) != RELAY_VERSION {
        return Err(DecodeError::Version);
    }
    let (token, rest) = rest.split_at(RENDEZVOUS_TOKEN_LEN);
    let (nonce, ttl) = rest.split_at(NONCE_LEN);
    let ttl_seconds = u16::from_be_bytes([ttl[0], ttl[1]]);
    if !(1..=MAX_ROOM_SECONDS).contains(&ttl_seconds) {
        return Err(DecodeError::Range);
    }
    Ok(Control::Register {
        token: RendezvousToken::new(array(token)?)?,
        client_nonce: Random16::new(array(nonce)?)?,
        ttl_seconds,
    })
}

fn decode_candidates(body: &[u8]) -> Result<Control, DecodeError> {
    let (room, rest) = body
        .split_at_checked(ROOM_ID_LEN)
        .ok_or(DecodeError::Length)?;
    let (count, records) = rest.split_first().ok_or(DecodeError::Length)?;
    let count = usize::from(*count);
    if count > MAX_CANDIDATES {
        return Err(DecodeError::Range);
    }
    if records.len() != count * CANDIDATE_LEN {
        return Err(DecodeError::Length);
    }
    let mut candidates: Vec<Candidate> = Vec::with_capacity(count);
    for record in records.as_chunks::<CANDIDATE_LEN>().0 {
        let candidate = Candidate::decode(record)?;
        if candidates.contains(&candidate) {
            return Err(DecodeError::Range);
        }
        candidates.push(candidate);
    }
    Ok(Control::Candidates {
        room: Random16::new(array(room)?)?,
        candidates,
    })
}

fn exact<const N: usize>(body: &[u8]) -> Result<&[u8; N], DecodeError> {
    body.try_into().map_err(|_| DecodeError::Length)
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], DecodeError> {
    bytes.try_into().map_err(|_| DecodeError::Length)
}

const fn is_zero(bytes: &[u8]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests;
