//! Session prelude records and Noise transport frames (PROTOCOL §4.1,
//! §4.2.5, §4.3, §4.4, §5, §12, §13).
//!
//! These codecs check layout only: exact lengths, magic, version, suite,
//! enum values, reserved fields, and nonzero identifiers. Nothing here is
//! authenticated. Hello fields remain untrusted hints until the Noise
//! transcript that binds them completes, and transport frame bodies are only
//! meaningful after `todoke-crypto` decrypted them under an established
//! session. Cryptographic checks and state-machine ordering live in
//! `todoke-crypto::session`.
//!
//! The `CodeOfferRequest`, `CodeOffer`, `CodeShareA`, and `CodeShareB`
//! bodies (§3.2, kinds 0x03/0x04/0x06/0x07) are in [`crate::pairing`].

use core::fmt;

use crate::identity::{self, DEVICE_BINDING_LEN, DeviceBinding, SIGNATURE_LEN};

/// Two-byte big-endian length prefix of a prelude record (§4.1).
pub const PRELUDE_PREFIX_LEN: usize = 2;
/// Largest prelude `length` value: kind plus body (§4.1, §13).
pub const PRELUDE_MAX_LEN: usize = 8192;
/// Largest prelude body.
pub const PRELUDE_MAX_BODY_LEN: usize = PRELUDE_MAX_LEN - 1;

/// `ClientHello` / `ServerHello` body length (§4.1).
pub const HELLO_LEN: usize = 66;
/// Hello magic, ASCII `TDKE`.
pub const HELLO_MAGIC: [u8; 4] = *b"TDKE";
/// The only protocol version (§4.1, §6). Exact equality, no version list.
pub const PROTOCOL_VERSION: u16 = 1;
/// The assigned hybrid suite (§4.2). Its production use is gated (§16).
pub const HYBRID_SUITE: u16 = 0x0001;

/// Two-byte big-endian transport length prefix (§5).
pub const CIPHERTEXT_PREFIX_LEN: usize = 2;
/// Noise AEAD tag length.
pub const TAG_LEN: usize = 16;
/// Decrypted frame header: `type:u16 || flags:u16` (§5).
pub const FRAME_HEADER_LEN: usize = 4;
/// Smallest transport ciphertext: an empty-body frame plus its tag (§5).
pub const MIN_CIPHERTEXT_LEN: usize = FRAME_HEADER_LEN + TAG_LEN;
/// Largest transport ciphertext (§5).
pub const MAX_CIPHERTEXT_LEN: usize = 65_535;
/// Largest decrypted frame (§5).
pub const MAX_PLAINTEXT_LEN: usize = MAX_CIPHERTEXT_LEN - TAG_LEN;
/// Largest frame body (§5).
pub const MAX_BODY_LEN: usize = MAX_PLAINTEXT_LEN - FRAME_HEADER_LEN;
/// Largest body of an unknown noncritical frame (§5, §13).
pub const MAX_NONCRITICAL_BODY_LEN: usize = 1024;

/// `Identity` body length (§4.3).
pub const IDENTITY_LEN: usize = 2 + DEVICE_BINDING_LEN + 32 + SIGNATURE_LEN;
/// `binding_len` as transmitted: u16 1438.
const BINDING_LEN_PREFIX: [u8; 2] = [0x05, 0x9e];
const _: () = assert!(DEVICE_BINDING_LEN == 0x059e);
/// `RatchetReady` / `RatchetCommit` / `RatchetAck` body length (§4.4).
pub const RATCHET_LEN: usize = 72;
/// `KeyUpdate` body length (§5).
pub const KEY_UPDATE_LEN: usize = 8;
/// `Ping` / `Pong` body length (§13).
pub const PING_LEN: usize = 8;
/// `Error` body length (§12).
pub const ERROR_LEN: usize = 19;

/// Why a session record was rejected. Variants carry no peer data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// The input does not have the exact required length, or a length
    /// prefix is out of range.
    Length,
    /// The Hello magic is not `TDKE`.
    Magic,
    /// The version is not [`PROTOCOL_VERSION`].
    Version,
    /// The hybrid suite is not [`HYBRID_SUITE`].
    Suite,
    /// A reserved or flags field is nonzero, or a field that must be zero in
    /// this record is not.
    Reserved,
    /// A counter, epoch, or generation is out of range.
    Range,
    /// An identifier or nonce that must be random is all zero.
    ZeroIdentifier,
    /// An enum value (prelude kind, mode, scope, error code) is not defined.
    UnknownEnum,
    /// A Noise handshake message index is outside the pattern.
    Index,
    /// An embedded `DeviceBinding` is malformed.
    Binding(identity::DecodeError),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length => f.write_str("record has the wrong length"),
            Self::Magic => f.write_str("bad hello magic"),
            Self::Version => f.write_str("unsupported protocol version"),
            Self::Suite => f.write_str("unsupported hybrid suite"),
            Self::Reserved => f.write_str("reserved field is nonzero"),
            Self::Range => f.write_str("field is out of range"),
            Self::ZeroIdentifier => f.write_str("identifier is zero"),
            Self::UnknownEnum => f.write_str("unknown enum value"),
            Self::Index => f.write_str("handshake message index out of range"),
            Self::Binding(error) => write!(f, "embedded binding: {error}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Prelude record kinds (§4.1). 0x00 and 0x08..=0xff are reserved and
/// rejected; there is no fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PreludeKind {
    /// `ClientHello`.
    ClientHello = 0x01,
    /// `ServerHello`.
    ServerHello = 0x02,
    /// `CodeShareA` (§3.2; body in [`crate::pairing::CodeShare`]).
    CodeShareA = 0x03,
    /// `CodeShareB` (§3.2; body in [`crate::pairing::CodeShare`]).
    CodeShareB = 0x04,
    /// `NoiseHandshake`.
    NoiseHandshake = 0x05,
    /// `CodeOfferRequest` (§3.2; body in [`crate::pairing::CodeOfferRequest`]).
    CodeOfferRequest = 0x06,
    /// `CodeOffer` (§3.2; body in [`crate::pairing::CodeOffer`]).
    CodeOffer = 0x07,
}

impl PreludeKind {
    /// Decodes a kind byte.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0x01 => Self::ClientHello,
            0x02 => Self::ServerHello,
            0x03 => Self::CodeShareA,
            0x04 => Self::CodeShareB,
            0x05 => Self::NoiseHandshake,
            0x06 => Self::CodeOfferRequest,
            0x07 => Self::CodeOffer,
            _ => return None,
        })
    }

    /// The kind byte.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Validates a prelude length prefix before anything is buffered and returns
/// how many bytes (kind and body) follow it.
///
/// # Errors
///
/// [`DecodeError::Length`] unless the value is in `1..=8192`.
pub fn prelude_record_len(prefix: [u8; PRELUDE_PREFIX_LEN]) -> Result<usize, DecodeError> {
    let length = usize::from(u16::from_be_bytes(prefix));
    if (1..=PRELUDE_MAX_LEN).contains(&length) {
        Ok(length)
    } else {
        Err(DecodeError::Length)
    }
}

/// A prelude record after its length prefix: `kind || body`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreludeRecord<'a> {
    kind: PreludeKind,
    body: &'a [u8],
}

impl<'a> PreludeRecord<'a> {
    /// Splits `kind || body`, the bytes counted by the length prefix.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`] for an empty or oversized record,
    /// [`DecodeError::UnknownEnum`] for a reserved kind.
    pub fn decode(record: &'a [u8]) -> Result<Self, DecodeError> {
        let (&kind, body) = record.split_first().ok_or(DecodeError::Length)?;
        if record.len() > PRELUDE_MAX_LEN {
            return Err(DecodeError::Length);
        }
        let kind = PreludeKind::from_u8(kind).ok_or(DecodeError::UnknownEnum)?;
        Ok(Self { kind, body })
    }

    /// The record kind.
    #[must_use]
    pub fn kind(&self) -> PreludeKind {
        self.kind
    }

    /// The body, still untrusted.
    #[must_use]
    pub fn body(&self) -> &'a [u8] {
        self.body
    }
}

/// Encodes a complete prelude record, length prefix included.
///
/// # Errors
///
/// [`DecodeError::Length`] if the body exceeds [`PRELUDE_MAX_BODY_LEN`].
pub fn encode_prelude_record(kind: PreludeKind, body: &[u8]) -> Result<Vec<u8>, DecodeError> {
    if body.len() > PRELUDE_MAX_BODY_LEN {
        return Err(DecodeError::Length);
    }
    let length = u16::try_from(body.len() + 1).map_err(|_| DecodeError::Length)?;
    let mut out = Vec::with_capacity(PRELUDE_PREFIX_LEN + 1 + body.len());
    out.extend_from_slice(&length.to_be_bytes());
    out.push(kind.to_u8());
    out.extend_from_slice(body);
    Ok(out)
}

/// Session mode carried in the Hellos; it selects the Noise pattern (§4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SessionMode {
    /// QR pairing, `IKpsk2+hfs`.
    Qr = 1,
    /// Human-code pairing, `XXpsk3+hfs`.
    Code = 2,
    /// Existing contact, `KKpsk2+hfs`.
    Contact = 3,
}

impl SessionMode {
    /// Decodes a mode byte.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Qr),
            2 => Some(Self::Code),
            3 => Some(Self::Contact),
            _ => None,
        }
    }

    /// The mode byte.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Exact inner Noise message sizes, in message order (§4.2.5).
    #[must_use]
    pub const fn noise_message_lens(self) -> &'static [usize] {
        match self {
            Self::Qr => &[1296, 1152],
            Self::Contact => &[1248, 1152],
            Self::Code => &[1248, 1200, 64],
        }
    }
}

/// `ClientHello` / `ServerHello` body (§4.1). Untrusted until the transcript
/// authenticates it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Hello {
    mode: SessionMode,
    generation: u64,
    locator: [u8; 16],
    client_nonce: [u8; 16],
    server_nonce: [u8; 16],
}

impl Hello {
    /// A `ClientHello`: the server nonce is zero.
    ///
    /// # Errors
    ///
    /// [`DecodeError::ZeroIdentifier`] for a zero locator or client nonce,
    /// [`DecodeError::Range`] for a nonzero generation in a pairing mode.
    pub fn client(
        mode: SessionMode,
        generation: u64,
        locator: [u8; 16],
        client_nonce: [u8; 16],
    ) -> Result<Self, DecodeError> {
        let hello = Self {
            mode,
            generation,
            locator,
            client_nonce,
            server_nonce: [0; 16],
        };
        hello.check_client()?;
        Ok(hello)
    }

    /// The `ServerHello` echoing this `ClientHello` with `server_nonce`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::ZeroIdentifier`] for a zero server nonce.
    pub fn server_reply(&self, server_nonce: [u8; 16]) -> Result<Self, DecodeError> {
        if server_nonce == [0; 16] {
            return Err(DecodeError::ZeroIdentifier);
        }
        Ok(Self {
            server_nonce,
            ..*self
        })
    }

    /// Parses a `ClientHello` body.
    ///
    /// # Errors
    ///
    /// Any layout violation, a nonzero server nonce, a zero locator or client
    /// nonce, or a nonzero generation in a pairing mode.
    pub fn decode_client(bytes: &[u8]) -> Result<Self, DecodeError> {
        let hello = Self::decode(bytes)?;
        if hello.server_nonce != [0; 16] {
            return Err(DecodeError::Reserved);
        }
        hello.check_client()?;
        Ok(hello)
    }

    /// Parses a `ServerHello` body and requires it to echo `client` exactly.
    ///
    /// # Errors
    ///
    /// Any layout violation, a zero server nonce, or any echoed field that
    /// differs from `client` ([`DecodeError::Reserved`]).
    pub fn decode_server(bytes: &[u8], client: &Self) -> Result<Self, DecodeError> {
        let hello = Self::decode(bytes)?;
        if hello.server_nonce == [0; 16] {
            return Err(DecodeError::ZeroIdentifier);
        }
        let echoed = Self {
            server_nonce: [0; 16],
            ..hello
        };
        if echoed != *client {
            return Err(DecodeError::Reserved);
        }
        Ok(hello)
    }

    fn check_client(&self) -> Result<(), DecodeError> {
        if self.locator == [0; 16] || self.client_nonce == [0; 16] {
            return Err(DecodeError::ZeroIdentifier);
        }
        if self.mode != SessionMode::Contact && self.generation != 0 {
            return Err(DecodeError::Range);
        }
        Ok(())
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let bytes: &[u8; HELLO_LEN] = bytes.try_into().map_err(|_| DecodeError::Length)?;
        let (magic, rest) = bytes.split_first_chunk::<4>().ok_or(DecodeError::Length)?;
        if *magic != HELLO_MAGIC {
            return Err(DecodeError::Magic);
        }
        let (version, rest) = rest.split_first_chunk::<2>().ok_or(DecodeError::Length)?;
        if u16::from_be_bytes(*version) != PROTOCOL_VERSION {
            return Err(DecodeError::Version);
        }
        let (suite, rest) = rest.split_first_chunk::<2>().ok_or(DecodeError::Length)?;
        if u16::from_be_bytes(*suite) != HYBRID_SUITE {
            return Err(DecodeError::Suite);
        }
        let (&[mode, flags], rest) = rest.split_first_chunk::<2>().ok_or(DecodeError::Length)?;
        let mode = SessionMode::from_u8(mode).ok_or(DecodeError::UnknownEnum)?;
        if flags != 0 {
            return Err(DecodeError::Reserved);
        }
        let (generation, rest) = rest.split_first_chunk::<8>().ok_or(DecodeError::Length)?;
        let (locator, rest) = rest.split_first_chunk::<16>().ok_or(DecodeError::Length)?;
        let (client_nonce, rest) = rest.split_first_chunk::<16>().ok_or(DecodeError::Length)?;
        let server_nonce: [u8; 16] = rest.try_into().map_err(|_| DecodeError::Length)?;
        Ok(Self {
            mode,
            generation: u64::from_be_bytes(*generation),
            locator: *locator,
            client_nonce: *client_nonce,
            server_nonce,
        })
    }

    /// The exact 66-byte body.
    #[must_use]
    pub fn encode(&self) -> [u8; HELLO_LEN] {
        let mut out = [0; HELLO_LEN];
        out[..4].copy_from_slice(&HELLO_MAGIC);
        out[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        out[6..8].copy_from_slice(&HYBRID_SUITE.to_be_bytes());
        out[8] = self.mode.to_u8();
        out[9] = 0;
        out[10..18].copy_from_slice(&self.generation.to_be_bytes());
        out[18..34].copy_from_slice(&self.locator);
        out[34..50].copy_from_slice(&self.client_nonce);
        out[50..66].copy_from_slice(&self.server_nonce);
        out
    }

    /// The session mode.
    #[must_use]
    pub fn mode(&self) -> SessionMode {
        self.mode
    }

    /// Pair generation: 0 for a new pairing, the persisted value for a contact.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Pairing ID or contact rendezvous-token prefix (§9).
    #[must_use]
    pub fn locator(&self) -> &[u8; 16] {
        &self.locator
    }

    /// The initiator's nonce.
    #[must_use]
    pub fn client_nonce(&self) -> &[u8; 16] {
        &self.client_nonce
    }

    /// The responder's nonce; zero in a `ClientHello`.
    #[must_use]
    pub fn server_nonce(&self) -> &[u8; 16] {
        &self.server_nonce
    }
}

/// Redacted: the locator is a pairing ID or a contact rendezvous-token prefix
/// and the nonces identify the attempt; §14.2 forbids logging contact tokens.
impl fmt::Debug for Hello {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted = Redacted(self.locator.len());
        f.debug_struct("Hello")
            .field("mode", &self.mode)
            .field("generation", &self.generation)
            .field("locator", &redacted)
            .field("client_nonce", &redacted)
            .field("server_nonce", &redacted)
            .finish()
    }
}

/// `NoiseHandshake` prelude body: `message_index:u8 || token_bytes` (§4.1).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NoiseHandshakeRecord<'a> {
    message_index: u8,
    token_bytes: &'a [u8],
}

impl<'a> NoiseHandshakeRecord<'a> {
    /// Parses a body for `mode`, enforcing the exact inner size for its
    /// index. Whether the index is the expected next one, and from the
    /// expected sender, is the state machine's decision.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Index`] for an index outside the pattern,
    /// [`DecodeError::Length`] for any other inner size.
    pub fn decode(body: &'a [u8], mode: SessionMode) -> Result<Self, DecodeError> {
        let (&message_index, token_bytes) = body.split_first().ok_or(DecodeError::Length)?;
        let expected = Self::inner_len(mode, message_index).ok_or(DecodeError::Index)?;
        if token_bytes.len() != expected {
            return Err(DecodeError::Length);
        }
        Ok(Self {
            message_index,
            token_bytes,
        })
    }

    /// The exact inner length of message `message_index` (1-based) in `mode`.
    #[must_use]
    pub fn inner_len(mode: SessionMode, message_index: u8) -> Option<usize> {
        let position = usize::from(message_index).checked_sub(1)?;
        mode.noise_message_lens().get(position).copied()
    }

    /// Encodes a complete prelude record for message `message_index`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Index`] or [`DecodeError::Length`] as for
    /// [`Self::decode`].
    pub fn encode_record(
        mode: SessionMode,
        message_index: u8,
        token_bytes: &[u8],
    ) -> Result<Vec<u8>, DecodeError> {
        let expected = Self::inner_len(mode, message_index).ok_or(DecodeError::Index)?;
        if token_bytes.len() != expected {
            return Err(DecodeError::Length);
        }
        let mut body = Vec::with_capacity(1 + token_bytes.len());
        body.push(message_index);
        body.extend_from_slice(token_bytes);
        encode_prelude_record(PreludeKind::NoiseHandshake, &body)
    }

    /// The 1-based message index.
    #[must_use]
    pub fn message_index(&self) -> u8 {
        self.message_index
    }

    /// The inner Noise message.
    #[must_use]
    pub fn token_bytes(&self) -> &'a [u8] {
        self.token_bytes
    }
}

impl fmt::Debug for NoiseHandshakeRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoiseHandshakeRecord")
            .field("message_index", &self.message_index)
            .field(
                "token_bytes",
                &format_args!("[{} bytes]", self.token_bytes.len()),
            )
            .finish()
    }
}

/// Validates a transport length prefix before anything is buffered and
/// returns the ciphertext length that follows (§5).
///
/// # Errors
///
/// [`DecodeError::Length`] unless the value is in `20..=65535`.
pub fn ciphertext_len(prefix: [u8; CIPHERTEXT_PREFIX_LEN]) -> Result<usize, DecodeError> {
    let length = usize::from(u16::from_be_bytes(prefix));
    if length >= MIN_CIPHERTEXT_LEN {
        Ok(length)
    } else {
        Err(DecodeError::Length)
    }
}

/// A transport frame type from the §5 registry.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrameType(u16);

/// How the session layer treats a frame type (§5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FrameClass {
    /// Handled by the session layer itself: Identity, the ratchet messages,
    /// `KeyUpdate`, Ping/Pong, and Error.
    Session,
    /// An assigned type owned by a higher layer (Capabilities, transfers,
    /// Revoke).
    Application,
    /// Noncritical extension space: unknown types may be skipped within the
    /// §13 budget.
    Noncritical,
    /// Unassigned or reserved critical type: abort with UNSUPPORTED.
    UnsupportedCritical,
    /// Experimental/private space: rejected in v1.
    Experimental,
}

impl FrameType {
    /// `Identity` (§4.3).
    pub const IDENTITY: Self = Self(0x0001);
    /// `RatchetReady` (§4.4).
    pub const RATCHET_READY: Self = Self(0x0002);
    /// `RatchetCommit` (§4.4).
    pub const RATCHET_COMMIT: Self = Self(0x0003);
    /// `RatchetAck` (§4.4).
    pub const RATCHET_ACK: Self = Self(0x0004);
    /// `Capabilities` (§6).
    pub const CAPABILITIES: Self = Self(0x0005);
    /// `KeyUpdate` (§5).
    pub const KEY_UPDATE: Self = Self(0x0006);
    /// `Ping` (§13).
    pub const PING: Self = Self(0x0007);
    /// `Pong` (§13).
    pub const PONG: Self = Self(0x0008);
    /// `Error` (§12).
    pub const ERROR: Self = Self(0x0009);
    /// `ManifestStart` (§7.1).
    pub const MANIFEST_START: Self = Self(0x0010);
    /// `ManifestPart` (§7.1).
    pub const MANIFEST_PART: Self = Self(0x0011);
    /// `Accept` (`AcceH`, §7.3).
    pub const ACCEPT: Self = Self(0x0012);
    /// `Reject` (§7.3).
    pub const REJECT: Self = Self(0x0013);
    /// `FileKey` (§8).
    pub const FILE_KEY: Self = Self(0x0014);
    /// `ChunkRequest` (§7.4).
    pub const CHUNK_REQUEST: Self = Self(0x0015);
    /// `Chunk` (§7.4).
    pub const CHUNK: Self = Self(0x0016);
    /// `ResumeQuery` (§7.5).
    pub const RESUME_QUERY: Self = Self(0x0017);
    /// `ResumeStatus` (§7.5).
    pub const RESUME_STATUS: Self = Self(0x0018);
    /// `Cancel` (§7.6).
    pub const CANCEL: Self = Self(0x0019);
    /// `CancelAck` (§7.6).
    pub const CANCEL_ACK: Self = Self(0x001a);
    /// `Complete` (§7.7).
    pub const COMPLETE: Self = Self(0x001b);
    /// `DeliveryReceipt` (§7.7).
    pub const DELIVERY_RECEIPT: Self = Self(0x001c);
    /// `Revoke` (§2).
    pub const REVOKE: Self = Self(0x0040);

    /// Wraps a raw type value; any value is representable.
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// The raw value.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }

    /// Classifies the type per the §5 registry.
    #[must_use]
    pub const fn class(self) -> FrameClass {
        match self.0 {
            0x0001..=0x0004 | 0x0006..=0x0009 => FrameClass::Session,
            0x0005 | 0x0010..=0x001c | 0x0040 => FrameClass::Application,
            0x8000..=0xbfff => FrameClass::Noncritical,
            0xc000..=0xffff => FrameClass::Experimental,
            _ => FrameClass::UnsupportedCritical,
        }
    }
}

impl fmt::Debug for FrameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FrameType({:#06x})", self.0)
    }
}

/// Splits a decrypted frame into its type and body (§5).
///
/// # Errors
///
/// [`DecodeError::Length`] for a frame shorter than its header or longer
/// than [`MAX_PLAINTEXT_LEN`]; [`DecodeError::Reserved`] for nonzero flags.
pub fn decode_frame(plaintext: &[u8]) -> Result<(FrameType, &[u8]), DecodeError> {
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(DecodeError::Length);
    }
    let (frame_type, rest) = plaintext
        .split_first_chunk::<2>()
        .ok_or(DecodeError::Length)?;
    let (flags, body) = rest.split_first_chunk::<2>().ok_or(DecodeError::Length)?;
    if *flags != [0, 0] {
        return Err(DecodeError::Reserved);
    }
    Ok((FrameType(u16::from_be_bytes(*frame_type)), body))
}

/// Appends a decrypted frame (`type || flags=0 || body`) to `out`.
///
/// # Errors
///
/// [`DecodeError::Length`] if the body exceeds [`MAX_BODY_LEN`].
pub fn encode_frame_into(
    frame_type: FrameType,
    body: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), DecodeError> {
    if body.len() > MAX_BODY_LEN {
        return Err(DecodeError::Length);
    }
    out.reserve(FRAME_HEADER_LEN + body.len());
    out.extend_from_slice(&frame_type.0.to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(body);
    Ok(())
}

/// `Identity` body (§4.3). The role byte in the signature is reconstructed
/// by the receiver, not transmitted.
#[derive(Clone, PartialEq, Eq)]
pub struct Identity {
    binding: DeviceBinding,
    handshake_hash: [u8; 32],
    signature: [u8; SIGNATURE_LEN],
}

impl Identity {
    /// Assembles a record without checking the signature.
    #[must_use]
    pub fn new(
        binding: DeviceBinding,
        handshake_hash: [u8; 32],
        signature: [u8; SIGNATURE_LEN],
    ) -> Self {
        Self {
            binding,
            handshake_hash,
            signature,
        }
    }

    /// Parses exactly [`IDENTITY_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`] (including a `binding_len` other than 1438) or
    /// [`DecodeError::Binding`] for a malformed binding.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let bytes: &[u8; IDENTITY_LEN] = bytes.try_into().map_err(|_| DecodeError::Length)?;
        let (binding_len, rest) = bytes.split_first_chunk::<2>().ok_or(DecodeError::Length)?;
        if usize::from(u16::from_be_bytes(*binding_len)) != DEVICE_BINDING_LEN {
            return Err(DecodeError::Length);
        }
        let (binding, rest) = rest.split_at(DEVICE_BINDING_LEN);
        let binding = DeviceBinding::decode(binding).map_err(DecodeError::Binding)?;
        let (handshake_hash, rest) = rest.split_first_chunk::<32>().ok_or(DecodeError::Length)?;
        let signature: [u8; SIGNATURE_LEN] = rest.try_into().map_err(|_| DecodeError::Length)?;
        Ok(Self {
            binding,
            handshake_hash: *handshake_hash,
            signature,
        })
    }

    /// The exact [`IDENTITY_LEN`]-byte encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(IDENTITY_LEN);
        out.extend_from_slice(&BINDING_LEN_PREFIX);
        out.extend_from_slice(&self.binding.encode());
        out.extend_from_slice(&self.handshake_hash);
        out.extend_from_slice(&self.signature);
        out
    }

    /// The presented binding, unverified.
    #[must_use]
    pub fn binding(&self) -> &DeviceBinding {
        &self.binding
    }

    /// The claimed handshake hash.
    #[must_use]
    pub fn handshake_hash(&self) -> &[u8; 32] {
        &self.handshake_hash
    }

    /// The device signature.
    #[must_use]
    pub fn signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.signature
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("binding", self.binding.body())
            .field("handshake_hash", &Hex(&self.handshake_hash))
            .field("signature", &Hex(&self.signature))
            .finish()
    }
}

/// `RatchetReady` / `RatchetCommit` / `RatchetAck` body (§4.4). The
/// confirmation is a MAC under a secret key; the body itself is public.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ratchet {
    session_id: [u8; 32],
    generation_next: u64,
    confirmation: [u8; 32],
}

impl Ratchet {
    /// Assembles a record.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Range`] for `generation_next` 0 (it is always a
    /// generation plus one).
    pub fn new(
        session_id: [u8; 32],
        generation_next: u64,
        confirmation: [u8; 32],
    ) -> Result<Self, DecodeError> {
        if generation_next == 0 {
            return Err(DecodeError::Range);
        }
        Ok(Self {
            session_id,
            generation_next,
            confirmation,
        })
    }

    /// Parses exactly [`RATCHET_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`] or [`DecodeError::Range`].
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let bytes: &[u8; RATCHET_LEN] = bytes.try_into().map_err(|_| DecodeError::Length)?;
        let (session_id, rest) = bytes.split_first_chunk::<32>().ok_or(DecodeError::Length)?;
        let (generation, rest) = rest.split_first_chunk::<8>().ok_or(DecodeError::Length)?;
        let confirmation: [u8; 32] = rest.try_into().map_err(|_| DecodeError::Length)?;
        Self::new(*session_id, u64::from_be_bytes(*generation), confirmation)
    }

    /// The exact [`RATCHET_LEN`]-byte encoding.
    #[must_use]
    pub fn encode(&self) -> [u8; RATCHET_LEN] {
        let mut out = [0; RATCHET_LEN];
        out[..32].copy_from_slice(&self.session_id);
        out[32..40].copy_from_slice(&self.generation_next.to_be_bytes());
        out[40..].copy_from_slice(&self.confirmation);
        out
    }

    /// The claimed session ID.
    #[must_use]
    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// The claimed next generation.
    #[must_use]
    pub fn generation_next(&self) -> u64 {
        self.generation_next
    }

    /// The claimed confirmation MAC.
    #[must_use]
    pub fn confirmation(&self) -> &[u8; 32] {
        &self.confirmation
    }
}

impl fmt::Debug for Ratchet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ratchet")
            .field("session_id", &Hex(&self.session_id))
            .field("generation_next", &self.generation_next)
            .field("confirmation", &Hex(&self.confirmation))
            .finish()
    }
}

/// Parses a `KeyUpdate` body and returns its nonzero epoch (§5).
///
/// # Errors
///
/// [`DecodeError::Length`] or [`DecodeError::Range`] for epoch 0.
pub fn decode_key_update(bytes: &[u8]) -> Result<u64, DecodeError> {
    let bytes: [u8; KEY_UPDATE_LEN] = bytes.try_into().map_err(|_| DecodeError::Length)?;
    match u64::from_be_bytes(bytes) {
        0 => Err(DecodeError::Range),
        epoch => Ok(epoch),
    }
}

/// Parses a `Ping` or `Pong` body and returns its nonzero nonce (§13).
///
/// # Errors
///
/// [`DecodeError::Length`] or [`DecodeError::ZeroIdentifier`].
pub fn decode_ping(bytes: &[u8]) -> Result<u64, DecodeError> {
    let bytes: [u8; PING_LEN] = bytes.try_into().map_err(|_| DecodeError::Length)?;
    match u64::from_be_bytes(bytes) {
        0 => Err(DecodeError::ZeroIdentifier),
        nonce => Ok(nonce),
    }
}

/// Error scope (§12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorScope {
    /// Closes the session.
    Session,
    /// Terminates one transfer.
    Transfer([u8; 16]),
}

/// An error code from the §12 registry. Unknown nonzero codes are kept as
/// raw values: they mean a generic failure, never a retry instruction.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ErrorCode(u16);

impl ErrorCode {
    /// Length, canonical encoding, reserved field, overflow.
    pub const MALFORMED: Self = Self(0x0001);
    /// Version, suite, or type unsupported; no downgrade.
    pub const UNSUPPORTED: Self = Self(0x0002);
    /// Authentication failure where no oracle risk exists.
    pub const AUTHENTICATION: Self = Self(0x0003);
    /// Replay, wrong ordering, unexpected record.
    pub const STATE: Self = Self(0x0004);
    /// A limit was exceeded.
    pub const LIMIT: Self = Self(0x0005);
    /// Premature or unselected content or key.
    pub const CONSENT_REQUIRED: Self = Self(0x0006);
    /// Manifest hash, schema, or path conflict.
    pub const MANIFEST: Self = Self(0x0007);
    /// Content AEAD, Bao, root, or length mismatch.
    pub const INTEGRITY: Self = Self(0x0008);
    /// Transfer, Accept, or binding expired.
    pub const EXPIRED: Self = Self(0x0009);
    /// Revoked; no further identity detail.
    pub const REVOKED: Self = Self(0x000a);
    /// Insufficient space, write, or publish failure.
    pub const STORAGE: Self = Self(0x000b);
    /// A timeout.
    pub const TIMEOUT: Self = Self(0x000c);
    /// Generation or persistence inconsistency.
    pub const RATCHET: Self = Self(0x000d);
    /// Resume unavailable; a new transfer needs new consent.
    pub const RESUME_UNAVAILABLE: Self = Self(0x000e);

    /// Wraps a raw code.
    ///
    /// # Errors
    ///
    /// [`DecodeError::UnknownEnum`] for the reserved code 0.
    pub const fn new(value: u16) -> Result<Self, DecodeError> {
        if value == 0 {
            Err(DecodeError::UnknownEnum)
        } else {
            Ok(Self(value))
        }
    }

    /// The raw code.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl fmt::Debug for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ErrorCode({:#06x})", self.0)
    }
}

/// `Error` body (§12). Contains no strings, paths, or peer data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ErrorRecord {
    scope: ErrorScope,
    code: ErrorCode,
}

impl ErrorRecord {
    /// Assembles a record.
    ///
    /// # Errors
    ///
    /// [`DecodeError::ZeroIdentifier`] for a transfer scope with a zero ID.
    pub fn new(scope: ErrorScope, code: ErrorCode) -> Result<Self, DecodeError> {
        if scope == ErrorScope::Transfer([0; 16]) {
            return Err(DecodeError::ZeroIdentifier);
        }
        Ok(Self { scope, code })
    }

    /// Parses exactly [`ERROR_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`], [`DecodeError::UnknownEnum`] for an unknown
    /// scope or code 0, [`DecodeError::Reserved`] for a session error with a
    /// nonzero transfer ID, [`DecodeError::ZeroIdentifier`] for a transfer
    /// error with a zero one.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let bytes: &[u8; ERROR_LEN] = bytes.try_into().map_err(|_| DecodeError::Length)?;
        let (&scope, rest) = bytes.split_first().ok_or(DecodeError::Length)?;
        let (code, rest) = rest.split_first_chunk::<2>().ok_or(DecodeError::Length)?;
        let transfer_id: [u8; 16] = rest.try_into().map_err(|_| DecodeError::Length)?;
        let code = ErrorCode::new(u16::from_be_bytes(*code))?;
        let scope = match scope {
            0 if transfer_id == [0; 16] => ErrorScope::Session,
            0 => return Err(DecodeError::Reserved),
            1 => ErrorScope::Transfer(transfer_id),
            _ => return Err(DecodeError::UnknownEnum),
        };
        Self::new(scope, code)
    }

    /// The exact [`ERROR_LEN`]-byte encoding.
    #[must_use]
    pub fn encode(&self) -> [u8; ERROR_LEN] {
        let mut out = [0; ERROR_LEN];
        if let ErrorScope::Transfer(id) = self.scope {
            out[0] = 1;
            out[3..].copy_from_slice(&id);
        }
        out[1..3].copy_from_slice(&self.code.0.to_be_bytes());
        out
    }

    /// The scope.
    #[must_use]
    pub fn scope(&self) -> ErrorScope {
        self.scope
    }

    /// The code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        self.code
    }
}

struct Hex<'a>(&'a [u8]);

/// Prints only a length, for values that must not appear in logs.
struct Redacted(usize);

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{} bytes]", self.0)
    }
}

impl fmt::Debug for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
