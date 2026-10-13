//! Capabilities and transfer records (PROTOCOL §6, §7).
//!
//! These codecs check layout only: exact lengths, versions, reserved fields,
//! enum values, nonzero identifiers, numeric ranges, and canonical ordering
//! inside one record. They do not authenticate anything, compare a record
//! with transfer state, or verify a signature. A decoded record is untrusted
//! until the transfer engine (`todoke-transfer`) has checked it against the
//! session and transfer state and `todoke-crypto` has verified any
//! signature. The secret-bearing `FileKey` body (§8) lives in
//! `todoke_crypto::content`.
//!
//! The canonical manifest (§7.1) is in [`manifest`]: it is assembled from
//! `ManifestPart` data and validated as a whole.
//!
//! Debug output of every record here is safe to log: identifiers and hashes
//! are public. A manifest's names and MIME labels are not printed.

pub mod manifest;

use core::fmt;

use crate::identity::{PUBLIC_KEY_LEN, SIGNATURE_LEN};
use crate::time::UnixTime;

pub use manifest::{
    EntryKind, MANIFEST_ENTRY_FIXED_LEN, MANIFEST_HEADER_LEN, MANIFEST_MAGIC, Manifest,
    ManifestEntry, ManifestError, ManifestHeader, ManifestLimits,
};

/// The version of `Capabilities`, the manifest, `Accept`, and
/// `DeliveryReceipt` (§6, §7).
pub const TRANSFER_VERSION: u16 = 1;

/// A transfer ID: 16 random bytes, never zero (§1, §7).
pub type TransferId = [u8; 16];

/// `Capabilities` body length (§6).
pub const CAPABILITIES_LEN: usize = 38;
/// Smallest `max_manifest_bytes` and `ManifestStart` `total_len`: the fixed
/// manifest header (§6, §7.1).
pub const MIN_MANIFEST_BYTES: u32 = 108;
/// Largest manifest: 4 MiB (§6, §7.1, §13).
pub const MAX_MANIFEST_BYTES: u32 = 4_194_304;
/// Most manifest entries, directories included (§6, §7.1, §13).
pub const MAX_ENTRIES: u32 = 10_000;
/// Largest file: 1 TiB (§6, §7.1, §13).
pub const MAX_FILE_BYTES: u64 = 1 << 40;
/// Largest sum of file sizes in one manifest: 16 TiB (§6, §7.1, §13).
pub const MAX_TRANSFER_BYTES: u64 = 1 << 44;
/// Largest `max_outstanding_chunks` (§6, §7.4, §13).
pub const MAX_OUTSTANDING_CHUNKS: u16 = 16;

/// `ManifestStart` body length (§7.1).
pub const MANIFEST_START_LEN: usize = 52;
/// `ManifestPart` fixed fields before `data` (§7.1).
pub const MANIFEST_PART_HEADER_LEN: usize = 22;
/// Largest `ManifestPart` `data_len` (§7.1).
pub const MAX_MANIFEST_PART_DATA: usize = 60_000;

/// `Accept` fixed fields before the selection (§7.3).
pub const ACCEPT_PREFIX_LEN: usize = 174;
/// Shortest signed `Accept`: one selected file.
pub const MIN_ACCEPT_LEN: usize = ACCEPT_PREFIX_LEN + 4 + SIGNATURE_LEN;
/// Longest signed `Accept`: 10000 selected files (§7.3).
pub const MAX_ACCEPT_LEN: usize = ACCEPT_PREFIX_LEN + 4 * MAX_ENTRIES as usize + SIGNATURE_LEN;
/// `Reject` body length (§7.3).
pub const REJECT_LEN: usize = 50;
/// `ChunkRequest` body length (§7.4).
pub const CHUNK_REQUEST_LEN: usize = 60;
/// `Chunk` fixed fields before the content (§7.4).
pub const CHUNK_HEADER_LEN: usize = 62;
/// Shortest content ciphertext: the empty file's eight-byte slice and tag.
pub const MIN_CONTENT_LEN: usize = 24;
/// Longest content ciphertext: a 32768-byte slice and tag (§7.4, §13).
pub const MAX_CONTENT_LEN: usize = 32_784;
/// `ResumeQuery` body length (§7.5).
pub const RESUME_QUERY_LEN: usize = 56;
/// `ResumeStatus` fixed fields before the ranges (§7.5).
pub const RESUME_STATUS_HEADER_LEN: usize = 62;
/// Most ranges in one `ResumeStatus` (§7.5).
pub const MAX_RESUME_RANGES: usize = 1024;
/// `Cancel` / `CancelAck` body length (§7.6).
pub const CANCEL_LEN: usize = 66;
/// `Complete` body length (§7.7).
pub const COMPLETE_LEN: usize = 92;
/// `DeliveryReceipt` fields before the signature (§7.7).
pub const RECEIPT_PREFIX_LEN: usize = 215;
/// `DeliveryReceipt` body length (§7.7).
pub const DELIVERY_RECEIPT_LEN: usize = RECEIPT_PREFIX_LEN + SIGNATURE_LEN;

/// `manifest_hash = B3(MANIFEST_HASH_DOMAIN || canonical_manifest)` (§7.1).
pub const MANIFEST_HASH_DOMAIN: &[u8] = b"todoke/v1/manifest\0";
/// Receiver signature domain of `Accept` (§7.3).
pub const ACCEPT_DOMAIN: &[u8] = b"todoke/v1/accept\0";
/// `accept_hash = B3(ACCEPT_HASH_DOMAIN || complete_signed_accept)` (§7.3).
pub const ACCEPT_HASH_DOMAIN: &[u8] = b"todoke/v1/accept-hash\0";
/// Receiver signature domain of `DeliveryReceipt` (§7.7).
pub const DELIVERY_RECEIPT_DOMAIN: &[u8] = b"todoke/v1/delivery-receipt\0";

/// Why a transfer record was rejected. Variants carry no peer data. A
/// failure here is `MALFORMED` (§12), except [`Self::Manifest`], which is
/// `MANIFEST`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// The input does not have the exact required length, or a length or
    /// count field disagrees with it.
    Length,
    /// The version is not [`TRANSFER_VERSION`].
    Version,
    /// A reserved field, flag, or extension is nonzero.
    Reserved,
    /// A numeric field is outside its permitted range.
    Range,
    /// An identifier or nonce that must be random is all zero.
    ZeroIdentifier,
    /// An enum value (reason, status) is not defined.
    UnknownEnum,
    /// A selection or range list is not in canonical order: not strictly
    /// increasing, overlapping, or adjacent.
    Order,
    /// The canonical manifest is invalid.
    Manifest(ManifestError),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length => f.write_str("record has the wrong length"),
            Self::Version => f.write_str("unsupported record version"),
            Self::Reserved => f.write_str("reserved field is nonzero"),
            Self::Range => f.write_str("field is out of range"),
            Self::ZeroIdentifier => f.write_str("identifier is zero"),
            Self::UnknownEnum => f.write_str("unknown enum value"),
            Self::Order => f.write_str("list is not in canonical order"),
            Self::Manifest(error) => write!(f, "invalid manifest: {error}"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl From<ManifestError> for DecodeError {
    fn from(error: ManifestError) -> Self {
        Self::Manifest(error)
    }
}

/// Sequential big-endian reader over one record. Every read checks the
/// remaining length first.
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let (head, rest) = self
            .bytes
            .split_first_chunk::<N>()
            .ok_or(DecodeError::Length)?;
        self.bytes = rest;
        Ok(*head)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, DecodeError> {
        self.array().map(u16::from_be_bytes)
    }

    pub(crate) fn u32(&mut self) -> Result<u32, DecodeError> {
        self.array().map(u32::from_be_bytes)
    }

    pub(crate) fn u64(&mut self) -> Result<u64, DecodeError> {
        self.array().map(u64::from_be_bytes)
    }

    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        if len > self.bytes.len() {
            return Err(DecodeError::Length);
        }
        let (head, rest) = self.bytes.split_at(len);
        self.bytes = rest;
        Ok(head)
    }

    pub(crate) const fn remaining(&self) -> usize {
        self.bytes.len()
    }

    /// Fails unless every byte was read.
    pub(crate) const fn finish(&self) -> Result<(), DecodeError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::Length)
        }
    }
}

fn version(reader: &mut Reader<'_>) -> Result<(), DecodeError> {
    if reader.u16()? == TRANSFER_VERSION {
        Ok(())
    } else {
        Err(DecodeError::Version)
    }
}

fn nonzero_id(reader: &mut Reader<'_>) -> Result<[u8; 16], DecodeError> {
    let id = reader.array::<16>()?;
    if id == [0; 16] {
        Err(DecodeError::ZeroIdentifier)
    } else {
        Ok(id)
    }
}

fn unix_time(reader: &mut Reader<'_>) -> Result<UnixTime, DecodeError> {
    UnixTime::new(reader.u64()?).ok_or(DecodeError::Range)
}

fn check_id(id: [u8; 16]) -> Result<[u8; 16], DecodeError> {
    if id == [0; 16] {
        Err(DecodeError::ZeroIdentifier)
    } else {
        Ok(id)
    }
}

/// `Capabilities` body (§6). The record's version (1) and `extensions` (0)
/// are implied.
///
/// `content_suites` is kept as its wire value with every reserved bit
/// zero; whether it contains `XChaCha` (required in v1) is checked by
/// `todoke_crypto::content::ContentSuites::from_bits`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Capabilities {
    content_suites: u16,
    max_manifest_bytes: u32,
    max_entries: u32,
    max_file_bytes: u64,
    max_transfer_bytes: u64,
    max_outstanding_chunks: u16,
}

impl Capabilities {
    /// The protocol maximums of every limit, advertising only `XChaCha`
    /// (bit 1), the suite every v1 device supports.
    pub const PROTOCOL_MAXIMUMS: Self = Self {
        content_suites: 0b10,
        max_manifest_bytes: MAX_MANIFEST_BYTES,
        max_entries: MAX_ENTRIES,
        max_file_bytes: MAX_FILE_BYTES,
        max_transfer_bytes: MAX_TRANSFER_BYTES,
        max_outstanding_chunks: MAX_OUTSTANDING_CHUNKS,
    };

    /// The same limits with another `content_suites` value.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Reserved`] for a bit other than 0 and 1.
    pub const fn with_content_suites(self, content_suites: u16) -> Result<Self, DecodeError> {
        if content_suites & !0b11 != 0 {
            return Err(DecodeError::Reserved);
        }
        Ok(Self {
            content_suites,
            ..self
        })
    }

    /// Assembles a record, checking every §6 range.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Reserved`] for a content suite bit other than 0 and 1;
    /// [`DecodeError::Range`] for any limit outside its §6 range.
    pub fn new(
        content_suites: u16,
        max_manifest_bytes: u32,
        max_entries: u32,
        max_file_bytes: u64,
        max_transfer_bytes: u64,
        max_outstanding_chunks: u16,
    ) -> Result<Self, DecodeError> {
        if content_suites & !0b11 != 0 {
            return Err(DecodeError::Reserved);
        }
        if !(MIN_MANIFEST_BYTES..=MAX_MANIFEST_BYTES).contains(&max_manifest_bytes)
            || !(1..=MAX_ENTRIES).contains(&max_entries)
            || max_file_bytes > MAX_FILE_BYTES
            || max_transfer_bytes > MAX_TRANSFER_BYTES
            || !(1..=MAX_OUTSTANDING_CHUNKS).contains(&max_outstanding_chunks)
        {
            return Err(DecodeError::Range);
        }
        Ok(Self {
            content_suites,
            max_manifest_bytes,
            max_entries,
            max_file_bytes,
            max_transfer_bytes,
            max_outstanding_chunks,
        })
    }

    /// Parses exactly [`CAPABILITIES_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`], [`DecodeError::Version`],
    /// [`DecodeError::Reserved`] (a reserved suite bit or nonzero
    /// `extensions`), or [`DecodeError::Range`].
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != CAPABILITIES_LEN {
            return Err(DecodeError::Length);
        }
        let mut reader = Reader::new(bytes);
        version(&mut reader)?;
        let content_suites = reader.u16()?;
        let max_manifest_bytes = reader.u32()?;
        let max_entries = reader.u32()?;
        let max_file_bytes = reader.u64()?;
        let max_transfer_bytes = reader.u64()?;
        let max_outstanding_chunks = reader.u16()?;
        if reader.u64()? != 0 {
            return Err(DecodeError::Reserved);
        }
        reader.finish()?;
        Self::new(
            content_suites,
            max_manifest_bytes,
            max_entries,
            max_file_bytes,
            max_transfer_bytes,
            max_outstanding_chunks,
        )
    }

    /// The exact [`CAPABILITIES_LEN`]-byte body.
    #[must_use]
    pub fn encode(&self) -> [u8; CAPABILITIES_LEN] {
        let mut out = [0; CAPABILITIES_LEN];
        out[..2].copy_from_slice(&TRANSFER_VERSION.to_be_bytes());
        out[2..4].copy_from_slice(&self.content_suites.to_be_bytes());
        out[4..8].copy_from_slice(&self.max_manifest_bytes.to_be_bytes());
        out[8..12].copy_from_slice(&self.max_entries.to_be_bytes());
        out[12..20].copy_from_slice(&self.max_file_bytes.to_be_bytes());
        out[20..28].copy_from_slice(&self.max_transfer_bytes.to_be_bytes());
        out[28..30].copy_from_slice(&self.max_outstanding_chunks.to_be_bytes());
        out
    }

    /// The `content_suites` bits (bit 0 AES, bit 1 `XChaCha`).
    #[must_use]
    pub const fn content_suites(&self) -> u16 {
        self.content_suites
    }

    /// Largest manifest this endpoint receives.
    #[must_use]
    pub const fn max_manifest_bytes(&self) -> u32 {
        self.max_manifest_bytes
    }

    /// Most manifest entries this endpoint receives.
    #[must_use]
    pub const fn max_entries(&self) -> u32 {
        self.max_entries
    }

    /// Largest file this endpoint receives.
    #[must_use]
    pub const fn max_file_bytes(&self) -> u64 {
        self.max_file_bytes
    }

    /// Largest manifest size sum this endpoint receives.
    #[must_use]
    pub const fn max_transfer_bytes(&self) -> u64 {
        self.max_transfer_bytes
    }

    /// This endpoint's receive-side request budget (§7.4).
    #[must_use]
    pub const fn max_outstanding_chunks(&self) -> u16 {
        self.max_outstanding_chunks
    }
}

/// `ManifestStart` body (§7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ManifestStart {
    transfer_id: TransferId,
    manifest_hash: [u8; 32],
    total_len: u32,
}

impl ManifestStart {
    /// Assembles a record.
    ///
    /// # Errors
    ///
    /// [`DecodeError::ZeroIdentifier`] for a zero transfer ID;
    /// [`DecodeError::Range`] for a length outside 108..=4194304. The
    /// receiver's own smaller cap is its state machine's check.
    pub fn new(
        transfer_id: TransferId,
        manifest_hash: [u8; 32],
        total_len: u32,
    ) -> Result<Self, DecodeError> {
        let transfer_id = check_id(transfer_id)?;
        if !(MIN_MANIFEST_BYTES..=MAX_MANIFEST_BYTES).contains(&total_len) {
            return Err(DecodeError::Range);
        }
        Ok(Self {
            transfer_id,
            manifest_hash,
            total_len,
        })
    }

    /// Parses exactly [`MANIFEST_START_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// As [`Self::new`], or [`DecodeError::Length`].
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != MANIFEST_START_LEN {
            return Err(DecodeError::Length);
        }
        let mut reader = Reader::new(bytes);
        let transfer_id = reader.array()?;
        let manifest_hash = reader.array()?;
        let total_len = reader.u32()?;
        reader.finish()?;
        Self::new(transfer_id, manifest_hash, total_len)
    }

    /// The exact [`MANIFEST_START_LEN`]-byte body.
    #[must_use]
    pub fn encode(&self) -> [u8; MANIFEST_START_LEN] {
        let mut out = [0; MANIFEST_START_LEN];
        out[..16].copy_from_slice(&self.transfer_id);
        out[16..48].copy_from_slice(&self.manifest_hash);
        out[48..].copy_from_slice(&self.total_len.to_be_bytes());
        out
    }

    /// The new transfer's ID.
    #[must_use]
    pub const fn transfer_id(&self) -> &TransferId {
        &self.transfer_id
    }

    /// The announced manifest hash.
    #[must_use]
    pub const fn manifest_hash(&self) -> &[u8; 32] {
        &self.manifest_hash
    }

    /// The canonical manifest's exact length.
    #[must_use]
    pub const fn total_len(&self) -> u32 {
        self.total_len
    }
}

/// `ManifestPart` body (§7.1), borrowing its data.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ManifestPart<'a> {
    transfer_id: TransferId,
    offset: u32,
    data: &'a [u8],
}

impl<'a> ManifestPart<'a> {
    /// Assembles a record.
    ///
    /// # Errors
    ///
    /// [`DecodeError::ZeroIdentifier`] for a zero transfer ID;
    /// [`DecodeError::Range`] for data outside 1..=60000 bytes or an offset
    /// at or past the 4 MiB manifest maximum.
    pub fn new(transfer_id: TransferId, offset: u32, data: &'a [u8]) -> Result<Self, DecodeError> {
        let transfer_id = check_id(transfer_id)?;
        if data.is_empty() || data.len() > MAX_MANIFEST_PART_DATA || offset >= MAX_MANIFEST_BYTES {
            return Err(DecodeError::Range);
        }
        Ok(Self {
            transfer_id,
            offset,
            data,
        })
    }

    /// Parses a body whose `data_len` must account for every remaining byte.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`] if the body is shorter than its header or
    /// `data_len` disagrees with the body length; otherwise as [`Self::new`].
    pub fn decode(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes);
        let transfer_id = reader.array()?;
        let offset = reader.u32()?;
        let data_len = usize::from(reader.u16()?);
        if reader.remaining() != data_len {
            return Err(DecodeError::Length);
        }
        let data = reader.take(data_len)?;
        Self::new(transfer_id, offset, data)
    }

    /// The body: header and data.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MANIFEST_PART_HEADER_LEN + self.data.len());
        out.extend_from_slice(&self.transfer_id);
        out.extend_from_slice(&self.offset.to_be_bytes());
        // `new` bounds the length by 60000.
        out.extend_from_slice(&u16::try_from(self.data.len()).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(self.data);
        out
    }

    /// The transfer whose manifest this continues.
    #[must_use]
    pub const fn transfer_id(&self) -> &TransferId {
        &self.transfer_id
    }

    /// Where `data` starts in the canonical manifest.
    #[must_use]
    pub const fn offset(&self) -> u32 {
        self.offset
    }

    /// The canonical manifest bytes carried.
    #[must_use]
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }
}

impl fmt::Debug for ManifestPart<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManifestPart")
            .field("offset", &self.offset)
            .field("data_len", &self.data.len())
            .finish_non_exhaustive()
    }
}

/// The signed fields of an `Accept` (`AcceH`, §7.3), before the signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AcceptBody {
    session_id: [u8; 32],
    transfer_id: TransferId,
    manifest_hash: [u8; 32],
    sender_public: [u8; PUBLIC_KEY_LEN],
    receiver_public: [u8; PUBLIC_KEY_LEN],
    accept_nonce: [u8; 16],
    expires_at: UnixTime,
    selection: Vec<u32>,
}

impl AcceptBody {
    /// Assembles the signed fields.
    ///
    /// # Errors
    ///
    /// [`DecodeError::ZeroIdentifier`] for a zero session ID, transfer ID,
    /// or nonce; [`DecodeError::Range`] for an empty selection, more than
    /// 10000 IDs, or ID 0; [`DecodeError::Order`] unless the IDs strictly
    /// increase.
    #[expect(
        clippy::too_many_arguments,
        reason = "one argument per signed field of the §7.3 layout"
    )]
    pub fn new(
        session_id: [u8; 32],
        transfer_id: TransferId,
        manifest_hash: [u8; 32],
        sender_public: [u8; PUBLIC_KEY_LEN],
        receiver_public: [u8; PUBLIC_KEY_LEN],
        accept_nonce: [u8; 16],
        expires_at: UnixTime,
        selection: Vec<u32>,
    ) -> Result<Self, DecodeError> {
        if session_id == [0; 32] {
            return Err(DecodeError::ZeroIdentifier);
        }
        let transfer_id = check_id(transfer_id)?;
        let accept_nonce = check_id(accept_nonce)?;
        check_selection(&selection)?;
        Ok(Self {
            session_id,
            transfer_id,
            manifest_hash,
            sender_public,
            receiver_public,
            accept_nonce,
            expires_at,
            selection,
        })
    }

    /// The signed bytes: every field before `signature`, without the domain.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ACCEPT_PREFIX_LEN + 4 * self.selection.len());
        out.extend_from_slice(&TRANSFER_VERSION.to_be_bytes());
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.transfer_id);
        out.extend_from_slice(&self.manifest_hash);
        out.extend_from_slice(&self.sender_public);
        out.extend_from_slice(&self.receiver_public);
        out.extend_from_slice(&self.accept_nonce);
        out.extend_from_slice(&self.expires_at.seconds().to_be_bytes());
        // `check_selection` bounds the count by 10000.
        let count = u32::try_from(self.selection.len()).unwrap_or(0);
        out.extend_from_slice(&count.to_be_bytes());
        for id in &self.selection {
            out.extend_from_slice(&id.to_be_bytes());
        }
        out
    }

    /// The session this consent is bound to.
    #[must_use]
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// The accepted transfer.
    #[must_use]
    pub const fn transfer_id(&self) -> &TransferId {
        &self.transfer_id
    }

    /// The accepted canonical manifest's hash.
    #[must_use]
    pub const fn manifest_hash(&self) -> &[u8; 32] {
        &self.manifest_hash
    }

    /// The sender's full device key (unvalidated).
    #[must_use]
    pub const fn sender_public(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.sender_public
    }

    /// The receiver's full device key, the signing authority (unvalidated).
    #[must_use]
    pub const fn receiver_public(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.receiver_public
    }

    /// The fresh per-session nonce.
    #[must_use]
    pub const fn accept_nonce(&self) -> &[u8; 16] {
        &self.accept_nonce
    }

    /// When this authorization ends.
    #[must_use]
    pub const fn expires_at(&self) -> UnixTime {
        self.expires_at
    }

    /// The selected regular-file IDs, strictly increasing.
    #[must_use]
    pub fn selection(&self) -> &[u32] {
        &self.selection
    }
}

/// Checks a selection: 1..=10000 nonzero, strictly increasing IDs.
fn check_selection(selection: &[u32]) -> Result<(), DecodeError> {
    if selection.is_empty() || selection.len() > MAX_ENTRIES as usize || selection[0] == 0 {
        return Err(DecodeError::Range);
    }
    if selection.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(())
    } else {
        Err(DecodeError::Order)
    }
}

/// A complete signed `Accept` record (§7.3): the body and the receiver's
/// signature over `todoke/v1/accept\0 || body`. Unverified.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Accept {
    body: AcceptBody,
    signature: [u8; SIGNATURE_LEN],
}

impl Accept {
    /// Attaches a signature to `body`.
    #[must_use]
    pub const fn new(body: AcceptBody, signature: [u8; SIGNATURE_LEN]) -> Self {
        Self { body, signature }
    }

    /// Parses a complete signed record of `238 + 4 × selected_count` bytes.
    /// The count field is checked against the length before any selection
    /// entry is read.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`] for a length outside 242..=40238 or not
    /// matching `selected_count`, [`DecodeError::Version`], and every
    /// [`AcceptBody::new`] error.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if !(MIN_ACCEPT_LEN..=MAX_ACCEPT_LEN).contains(&bytes.len())
            || !(bytes.len() - ACCEPT_PREFIX_LEN - SIGNATURE_LEN).is_multiple_of(4)
        {
            return Err(DecodeError::Length);
        }
        let mut reader = Reader::new(bytes);
        version(&mut reader)?;
        let session_id = reader.array()?;
        let transfer_id = reader.array()?;
        let manifest_hash = reader.array()?;
        let sender_public = reader.array()?;
        let receiver_public = reader.array()?;
        let accept_nonce = reader.array()?;
        let expires_at = unix_time(&mut reader)?;
        let count = usize::try_from(reader.u32()?).map_err(|_| DecodeError::Length)?;
        if count.checked_mul(4) != Some(reader.remaining() - SIGNATURE_LEN) {
            return Err(DecodeError::Length);
        }
        let mut selection = Vec::with_capacity(count);
        for _ in 0..count {
            selection.push(reader.u32()?);
        }
        let signature = reader.array()?;
        reader.finish()?;
        let body = AcceptBody::new(
            session_id,
            transfer_id,
            manifest_hash,
            sender_public,
            receiver_public,
            accept_nonce,
            expires_at,
            selection,
        )?;
        Ok(Self { body, signature })
    }

    /// The complete signed record.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.body.encode();
        out.extend_from_slice(&self.signature);
        out
    }

    /// The signed fields.
    #[must_use]
    pub const fn body(&self) -> &AcceptBody {
        &self.body
    }

    /// The receiver's Ed25519 signature (unverified).
    #[must_use]
    pub const fn signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.signature
    }
}

/// `Reject` reasons (§7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RejectReason {
    /// The user declined.
    Declined,
    /// A local quota would be exceeded.
    Quota,
    /// The destination cannot hold this manifest.
    UnsupportedDestination,
    /// The prompt or manifest expired.
    Expired,
}

impl RejectReason {
    /// The wire value, 1..=4.
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        match self {
            Self::Declined => 1,
            Self::Quota => 2,
            Self::UnsupportedDestination => 3,
            Self::Expired => 4,
        }
    }

    /// Parses a wire value.
    ///
    /// # Errors
    ///
    /// [`DecodeError::UnknownEnum`] outside 1..=4.
    pub const fn from_u16(value: u16) -> Result<Self, DecodeError> {
        match value {
            1 => Ok(Self::Declined),
            2 => Ok(Self::Quota),
            3 => Ok(Self::UnsupportedDestination),
            4 => Ok(Self::Expired),
            _ => Err(DecodeError::UnknownEnum),
        }
    }
}

/// `Reject` body (§7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Reject {
    transfer_id: TransferId,
    manifest_hash: [u8; 32],
    reason: RejectReason,
}

impl Reject {
    /// Assembles a record.
    ///
    /// # Errors
    ///
    /// [`DecodeError::ZeroIdentifier`] for a zero transfer ID.
    pub fn new(
        transfer_id: TransferId,
        manifest_hash: [u8; 32],
        reason: RejectReason,
    ) -> Result<Self, DecodeError> {
        Ok(Self {
            transfer_id: check_id(transfer_id)?,
            manifest_hash,
            reason,
        })
    }

    /// Parses exactly [`REJECT_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`], [`DecodeError::ZeroIdentifier`], or
    /// [`DecodeError::UnknownEnum`].
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != REJECT_LEN {
            return Err(DecodeError::Length);
        }
        let mut reader = Reader::new(bytes);
        let transfer_id = nonzero_id(&mut reader)?;
        let manifest_hash = reader.array()?;
        let reason = RejectReason::from_u16(reader.u16()?)?;
        reader.finish()?;
        Self::new(transfer_id, manifest_hash, reason)
    }

    /// The exact [`REJECT_LEN`]-byte body.
    #[must_use]
    pub fn encode(&self) -> [u8; REJECT_LEN] {
        let mut out = [0; REJECT_LEN];
        out[..16].copy_from_slice(&self.transfer_id);
        out[16..48].copy_from_slice(&self.manifest_hash);
        out[48..].copy_from_slice(&self.reason.to_u16().to_be_bytes());
        out
    }

    /// The rejected transfer.
    #[must_use]
    pub const fn transfer_id(&self) -> &TransferId {
        &self.transfer_id
    }

    /// The rejected manifest's hash.
    #[must_use]
    pub const fn manifest_hash(&self) -> &[u8; 32] {
        &self.manifest_hash
    }

    /// Why.
    #[must_use]
    pub const fn reason(&self) -> RejectReason {
        self.reason
    }
}

/// `ChunkRequest` body (§7.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChunkRequest {
    transfer_id: TransferId,
    accept_hash: [u8; 32],
    request_id: u32,
    file_id: u32,
    segment_index: u32,
}

impl ChunkRequest {
    /// Assembles a record.
    ///
    /// # Errors
    ///
    /// [`DecodeError::ZeroIdentifier`] for a zero transfer ID;
    /// [`DecodeError::Range`] for request ID 0 or file ID 0.
    pub fn new(
        transfer_id: TransferId,
        accept_hash: [u8; 32],
        request_id: u32,
        file_id: u32,
        segment_index: u32,
    ) -> Result<Self, DecodeError> {
        let transfer_id = check_id(transfer_id)?;
        if request_id == 0 || file_id == 0 {
            return Err(DecodeError::Range);
        }
        Ok(Self {
            transfer_id,
            accept_hash,
            request_id,
            file_id,
            segment_index,
        })
    }

    /// Parses exactly [`CHUNK_REQUEST_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`] or as [`Self::new`].
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != CHUNK_REQUEST_LEN {
            return Err(DecodeError::Length);
        }
        let mut reader = Reader::new(bytes);
        let transfer_id = reader.array()?;
        let accept_hash = reader.array()?;
        let request_id = reader.u32()?;
        let file_id = reader.u32()?;
        let segment_index = reader.u32()?;
        reader.finish()?;
        Self::new(transfer_id, accept_hash, request_id, file_id, segment_index)
    }

    /// The exact [`CHUNK_REQUEST_LEN`]-byte body.
    #[must_use]
    pub fn encode(&self) -> [u8; CHUNK_REQUEST_LEN] {
        let mut out = [0; CHUNK_REQUEST_LEN];
        out[..16].copy_from_slice(&self.transfer_id);
        out[16..48].copy_from_slice(&self.accept_hash);
        out[48..52].copy_from_slice(&self.request_id.to_be_bytes());
        out[52..56].copy_from_slice(&self.file_id.to_be_bytes());
        out[56..].copy_from_slice(&self.segment_index.to_be_bytes());
        out
    }

    /// The authorized transfer.
    #[must_use]
    pub const fn transfer_id(&self) -> &TransferId {
        &self.transfer_id
    }

    /// The current session's Accept hash.
    #[must_use]
    pub const fn accept_hash(&self) -> &[u8; 32] {
        &self.accept_hash
    }

    /// The request ID, strictly increasing within the transfer and session.
    #[must_use]
    pub const fn request_id(&self) -> u32 {
        self.request_id
    }

    /// The selected regular file.
    #[must_use]
    pub const fn file_id(&self) -> u32 {
        self.file_id
    }

    /// The requested segment.
    #[must_use]
    pub const fn segment_index(&self) -> u32 {
        self.segment_index
    }
}

/// `Chunk` body (§7.4), borrowing its content ciphertext.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Chunk<'a> {
    transfer_id: TransferId,
    accept_hash: [u8; 32],
    request_id: u32,
    file_id: u32,
    segment_index: u32,
    content: &'a [u8],
}

impl<'a> Chunk<'a> {
    /// Assembles a record.
    ///
    /// # Errors
    ///
    /// [`DecodeError::ZeroIdentifier`] for a zero transfer ID;
    /// [`DecodeError::Range`] for request ID 0, file ID 0, or content
    /// outside 24..=32784 bytes.
    pub fn new(
        transfer_id: TransferId,
        accept_hash: [u8; 32],
        request_id: u32,
        file_id: u32,
        segment_index: u32,
        content: &'a [u8],
    ) -> Result<Self, DecodeError> {
        let transfer_id = check_id(transfer_id)?;
        if request_id == 0
            || file_id == 0
            || !(MIN_CONTENT_LEN..=MAX_CONTENT_LEN).contains(&content.len())
        {
            return Err(DecodeError::Range);
        }
        Ok(Self {
            transfer_id,
            accept_hash,
            request_id,
            file_id,
            segment_index,
            content,
        })
    }

    /// The transfer ID of a `Chunk` body, read without decoding anything
    /// else: the receiver decides from it alone whether the chunk may be
    /// processed at all (§7.2: forbidden chunks are discarded without
    /// further processing).
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`] for a body shorter than its fixed fields.
    pub fn peek_transfer_id(bytes: &[u8]) -> Result<TransferId, DecodeError> {
        if bytes.len() < CHUNK_HEADER_LEN {
            return Err(DecodeError::Length);
        }
        Reader::new(bytes).array()
    }

    /// Parses a body whose `content_len` must account for every remaining
    /// byte. The content is borrowed, not copied.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`] if `content_len` disagrees with the body
    /// length; otherwise as [`Self::new`].
    pub fn decode(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes);
        let transfer_id = reader.array()?;
        let accept_hash = reader.array()?;
        let request_id = reader.u32()?;
        let file_id = reader.u32()?;
        let segment_index = reader.u32()?;
        let content_len = usize::from(reader.u16()?);
        if reader.remaining() != content_len {
            return Err(DecodeError::Length);
        }
        let content = reader.take(content_len)?;
        Self::new(
            transfer_id,
            accept_hash,
            request_id,
            file_id,
            segment_index,
            content,
        )
    }

    /// The body: fixed fields and content.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CHUNK_HEADER_LEN + self.content.len());
        out.extend_from_slice(&self.transfer_id);
        out.extend_from_slice(&self.accept_hash);
        out.extend_from_slice(&self.request_id.to_be_bytes());
        out.extend_from_slice(&self.file_id.to_be_bytes());
        out.extend_from_slice(&self.segment_index.to_be_bytes());
        // `new` bounds the length by 32784.
        out.extend_from_slice(&u16::try_from(self.content.len()).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(self.content);
        out
    }

    /// The transfer.
    #[must_use]
    pub const fn transfer_id(&self) -> &TransferId {
        &self.transfer_id
    }

    /// The Accept hash.
    #[must_use]
    pub const fn accept_hash(&self) -> &[u8; 32] {
        &self.accept_hash
    }

    /// The outstanding request this answers.
    #[must_use]
    pub const fn request_id(&self) -> u32 {
        self.request_id
    }

    /// The requested file.
    #[must_use]
    pub const fn file_id(&self) -> u32 {
        self.file_id
    }

    /// The requested segment.
    #[must_use]
    pub const fn segment_index(&self) -> u32 {
        self.segment_index
    }

    /// The encrypted Bao slice, tag appended.
    #[must_use]
    pub const fn content(&self) -> &'a [u8] {
        self.content
    }
}

impl fmt::Debug for Chunk<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Chunk")
            .field("request_id", &self.request_id)
            .field("file_id", &self.file_id)
            .field("segment_index", &self.segment_index)
            .field("content_len", &self.content.len())
            .finish_non_exhaustive()
    }
}

/// `ResumeQuery` body (§7.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResumeQuery {
    transfer_id: TransferId,
    accept_hash: [u8; 32],
    file_id: u32,
    from_index: u32,
}

impl ResumeQuery {
    /// Assembles a record.
    ///
    /// # Errors
    ///
    /// [`DecodeError::ZeroIdentifier`] for a zero transfer ID;
    /// [`DecodeError::Range`] for file ID 0.
    pub fn new(
        transfer_id: TransferId,
        accept_hash: [u8; 32],
        file_id: u32,
        from_index: u32,
    ) -> Result<Self, DecodeError> {
        let transfer_id = check_id(transfer_id)?;
        if file_id == 0 {
            return Err(DecodeError::Range);
        }
        Ok(Self {
            transfer_id,
            accept_hash,
            file_id,
            from_index,
        })
    }

    /// Parses exactly [`RESUME_QUERY_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`] or as [`Self::new`].
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != RESUME_QUERY_LEN {
            return Err(DecodeError::Length);
        }
        let mut reader = Reader::new(bytes);
        let transfer_id = reader.array()?;
        let accept_hash = reader.array()?;
        let file_id = reader.u32()?;
        let from_index = reader.u32()?;
        reader.finish()?;
        Self::new(transfer_id, accept_hash, file_id, from_index)
    }

    /// The exact [`RESUME_QUERY_LEN`]-byte body.
    #[must_use]
    pub fn encode(&self) -> [u8; RESUME_QUERY_LEN] {
        let mut out = [0; RESUME_QUERY_LEN];
        out[..16].copy_from_slice(&self.transfer_id);
        out[16..48].copy_from_slice(&self.accept_hash);
        out[48..52].copy_from_slice(&self.file_id.to_be_bytes());
        out[52..].copy_from_slice(&self.from_index.to_be_bytes());
        out
    }

    /// The transfer.
    #[must_use]
    pub const fn transfer_id(&self) -> &TransferId {
        &self.transfer_id
    }

    /// The current Accept hash.
    #[must_use]
    pub const fn accept_hash(&self) -> &[u8; 32] {
        &self.accept_hash
    }

    /// The selected file.
    #[must_use]
    pub const fn file_id(&self) -> u32 {
        self.file_id
    }

    /// Where the page starts.
    #[must_use]
    pub const fn from_index(&self) -> u32 {
        self.from_index
    }
}

/// `ResumeStatus` body (§7.5): a page of verified segment ranges.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ResumeStatus {
    transfer_id: TransferId,
    accept_hash: [u8; 32],
    file_id: u32,
    from_index: u32,
    next_index: u32,
    ranges: Vec<(u32, u32)>,
}

impl ResumeStatus {
    /// Assembles a record. Whether `next_index` fits the file's segment
    /// count (and whether an empty page with `next_index == from_index` is
    /// the final one) is the state machine's check.
    ///
    /// # Errors
    ///
    /// [`DecodeError::ZeroIdentifier`] for a zero transfer ID;
    /// [`DecodeError::Range`] for file ID 0, `next_index < from_index`, more
    /// than 1024 ranges, a zero count, or a range outside
    /// `[from_index, next_index)`; [`DecodeError::Order`] for ranges that are
    /// not sorted, disjoint, and nonadjacent.
    pub fn new(
        transfer_id: TransferId,
        accept_hash: [u8; 32],
        file_id: u32,
        from_index: u32,
        next_index: u32,
        ranges: Vec<(u32, u32)>,
    ) -> Result<Self, DecodeError> {
        let transfer_id = check_id(transfer_id)?;
        if file_id == 0 || next_index < from_index || ranges.len() > MAX_RESUME_RANGES {
            return Err(DecodeError::Range);
        }
        let mut previous_end: Option<u32> = None;
        for &(start, count) in &ranges {
            let end = start.checked_add(count).ok_or(DecodeError::Range)?;
            if count == 0 || start < from_index || end > next_index {
                return Err(DecodeError::Range);
            }
            // Nonadjacent: a gap of at least one segment between ranges.
            if previous_end.is_some_and(|previous| start <= previous) {
                return Err(DecodeError::Order);
            }
            previous_end = Some(end);
        }
        Ok(Self {
            transfer_id,
            accept_hash,
            file_id,
            from_index,
            next_index,
            ranges,
        })
    }

    /// Parses a body of `62 + 8 × range_count` bytes; the count is checked
    /// against the length before any range is read.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`] or as [`Self::new`].
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes);
        let transfer_id = reader.array()?;
        let accept_hash = reader.array()?;
        let file_id = reader.u32()?;
        let from_index = reader.u32()?;
        let next_index = reader.u32()?;
        let count = usize::from(reader.u16()?);
        if count > MAX_RESUME_RANGES {
            return Err(DecodeError::Range);
        }
        if count.checked_mul(8) != Some(reader.remaining()) {
            return Err(DecodeError::Length);
        }
        let mut ranges = Vec::with_capacity(count);
        for _ in 0..count {
            ranges.push((reader.u32()?, reader.u32()?));
        }
        reader.finish()?;
        Self::new(
            transfer_id,
            accept_hash,
            file_id,
            from_index,
            next_index,
            ranges,
        )
    }

    /// The body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RESUME_STATUS_HEADER_LEN + 8 * self.ranges.len());
        out.extend_from_slice(&self.transfer_id);
        out.extend_from_slice(&self.accept_hash);
        out.extend_from_slice(&self.file_id.to_be_bytes());
        out.extend_from_slice(&self.from_index.to_be_bytes());
        out.extend_from_slice(&self.next_index.to_be_bytes());
        // `new` bounds the count by 1024.
        out.extend_from_slice(&u16::try_from(self.ranges.len()).unwrap_or(0).to_be_bytes());
        for (start, count) in &self.ranges {
            out.extend_from_slice(&start.to_be_bytes());
            out.extend_from_slice(&count.to_be_bytes());
        }
        out
    }

    /// The transfer.
    #[must_use]
    pub const fn transfer_id(&self) -> &TransferId {
        &self.transfer_id
    }

    /// The current Accept hash.
    #[must_use]
    pub const fn accept_hash(&self) -> &[u8; 32] {
        &self.accept_hash
    }

    /// The queried file.
    #[must_use]
    pub const fn file_id(&self) -> u32 {
        self.file_id
    }

    /// The query's `from_index`, echoed.
    #[must_use]
    pub const fn from_index(&self) -> u32 {
        self.from_index
    }

    /// Where the next page starts.
    #[must_use]
    pub const fn next_index(&self) -> u32 {
        self.next_index
    }

    /// `(start, count)` ranges of verified segments.
    #[must_use]
    pub fn ranges(&self) -> &[(u32, u32)] {
        &self.ranges
    }
}

/// `Cancel` reasons (§7.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CancelReason {
    /// The user cancelled.
    User,
    /// Authorization or the manifest expired.
    Expired,
    /// The peer or pairing was revoked.
    Revoked,
    /// Content failed verification.
    Integrity,
    /// Local storage failed.
    Storage,
    /// Local policy.
    Policy,
}

impl CancelReason {
    /// The wire value, 1..=6.
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        match self {
            Self::User => 1,
            Self::Expired => 2,
            Self::Revoked => 3,
            Self::Integrity => 4,
            Self::Storage => 5,
            Self::Policy => 6,
        }
    }

    /// Parses a wire value.
    ///
    /// # Errors
    ///
    /// [`DecodeError::UnknownEnum`] outside 1..=6.
    pub const fn from_u16(value: u16) -> Result<Self, DecodeError> {
        match value {
            1 => Ok(Self::User),
            2 => Ok(Self::Expired),
            3 => Ok(Self::Revoked),
            4 => Ok(Self::Integrity),
            5 => Ok(Self::Storage),
            6 => Ok(Self::Policy),
            _ => Err(DecodeError::UnknownEnum),
        }
    }
}

/// `Cancel` and `CancelAck` body (§7.6); both share this layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Cancel {
    transfer_id: TransferId,
    manifest_hash: [u8; 32],
    id: [u8; 16],
    reason: CancelReason,
}

impl Cancel {
    /// Assembles a record.
    ///
    /// # Errors
    ///
    /// [`DecodeError::ZeroIdentifier`] for a zero transfer or cancel ID.
    pub fn new(
        transfer_id: TransferId,
        manifest_hash: [u8; 32],
        cancel_id: [u8; 16],
        reason: CancelReason,
    ) -> Result<Self, DecodeError> {
        Ok(Self {
            transfer_id: check_id(transfer_id)?,
            manifest_hash,
            id: check_id(cancel_id)?,
            reason,
        })
    }

    /// Parses exactly [`CANCEL_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`], [`DecodeError::ZeroIdentifier`], or
    /// [`DecodeError::UnknownEnum`].
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != CANCEL_LEN {
            return Err(DecodeError::Length);
        }
        let mut reader = Reader::new(bytes);
        let transfer_id = nonzero_id(&mut reader)?;
        let manifest_hash = reader.array()?;
        let cancel_id = nonzero_id(&mut reader)?;
        let reason = CancelReason::from_u16(reader.u16()?)?;
        reader.finish()?;
        Self::new(transfer_id, manifest_hash, cancel_id, reason)
    }

    /// The exact [`CANCEL_LEN`]-byte body.
    #[must_use]
    pub fn encode(&self) -> [u8; CANCEL_LEN] {
        let mut out = [0; CANCEL_LEN];
        out[..16].copy_from_slice(&self.transfer_id);
        out[16..48].copy_from_slice(&self.manifest_hash);
        out[48..64].copy_from_slice(&self.id);
        out[64..].copy_from_slice(&self.reason.to_u16().to_be_bytes());
        out
    }

    /// The cancelled transfer.
    #[must_use]
    pub const fn transfer_id(&self) -> &TransferId {
        &self.transfer_id
    }

    /// Its manifest hash.
    #[must_use]
    pub const fn manifest_hash(&self) -> &[u8; 32] {
        &self.manifest_hash
    }

    /// The random cancel ID, echoed by the Ack.
    #[must_use]
    pub const fn cancel_id(&self) -> &[u8; 16] {
        &self.id
    }

    /// Why.
    #[must_use]
    pub const fn reason(&self) -> CancelReason {
        self.reason
    }
}

/// `Complete` body (§7.7). Not a signed receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Complete {
    transfer_id: TransferId,
    manifest_hash: [u8; 32],
    accept_hash: [u8; 32],
    completed_count: u32,
    total_plaintext_bytes: u64,
}

impl Complete {
    /// Assembles a record.
    ///
    /// # Errors
    ///
    /// [`DecodeError::ZeroIdentifier`] for a zero transfer ID;
    /// [`DecodeError::Range`] for a count outside 1..=10000 or a total above
    /// 16 TiB.
    pub fn new(
        transfer_id: TransferId,
        manifest_hash: [u8; 32],
        accept_hash: [u8; 32],
        completed_count: u32,
        total_plaintext_bytes: u64,
    ) -> Result<Self, DecodeError> {
        let transfer_id = check_id(transfer_id)?;
        if !(1..=MAX_ENTRIES).contains(&completed_count)
            || total_plaintext_bytes > MAX_TRANSFER_BYTES
        {
            return Err(DecodeError::Range);
        }
        Ok(Self {
            transfer_id,
            manifest_hash,
            accept_hash,
            completed_count,
            total_plaintext_bytes,
        })
    }

    /// Parses exactly [`COMPLETE_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`] or as [`Self::new`].
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != COMPLETE_LEN {
            return Err(DecodeError::Length);
        }
        let mut reader = Reader::new(bytes);
        let transfer_id = reader.array()?;
        let manifest_hash = reader.array()?;
        let accept_hash = reader.array()?;
        let completed_count = reader.u32()?;
        let total_plaintext_bytes = reader.u64()?;
        reader.finish()?;
        Self::new(
            transfer_id,
            manifest_hash,
            accept_hash,
            completed_count,
            total_plaintext_bytes,
        )
    }

    /// The exact [`COMPLETE_LEN`]-byte body.
    #[must_use]
    pub fn encode(&self) -> [u8; COMPLETE_LEN] {
        let mut out = [0; COMPLETE_LEN];
        out[..16].copy_from_slice(&self.transfer_id);
        out[16..48].copy_from_slice(&self.manifest_hash);
        out[48..80].copy_from_slice(&self.accept_hash);
        out[80..84].copy_from_slice(&self.completed_count.to_be_bytes());
        out[84..].copy_from_slice(&self.total_plaintext_bytes.to_be_bytes());
        out
    }

    /// The completed transfer.
    #[must_use]
    pub const fn transfer_id(&self) -> &TransferId {
        &self.transfer_id
    }

    /// Its manifest hash.
    #[must_use]
    pub const fn manifest_hash(&self) -> &[u8; 32] {
        &self.manifest_hash
    }

    /// The current Accept hash.
    #[must_use]
    pub const fn accept_hash(&self) -> &[u8; 32] {
        &self.accept_hash
    }

    /// How many selected files completed.
    #[must_use]
    pub const fn completed_count(&self) -> u32 {
        self.completed_count
    }

    /// The sum of the selected file sizes.
    #[must_use]
    pub const fn total_plaintext_bytes(&self) -> u64 {
        self.total_plaintext_bytes
    }
}

/// The signed fields of a `DeliveryReceipt` (§7.7). `status` is always 1
/// ("all selected files verified and published"); every other value is
/// reserved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReceiptBody {
    session_id: [u8; 32],
    transfer_id: TransferId,
    manifest_hash: [u8; 32],
    accept_hash: [u8; 32],
    sender_public: [u8; PUBLIC_KEY_LEN],
    receiver_public: [u8; PUBLIC_KEY_LEN],
    receipt_id: [u8; 16],
    completed_at: UnixTime,
    completed_count: u32,
    total_plaintext_bytes: u64,
}

impl ReceiptBody {
    /// Assembles the signed fields.
    ///
    /// # Errors
    ///
    /// [`DecodeError::ZeroIdentifier`] for a zero session, transfer, or
    /// receipt ID; [`DecodeError::Range`] for a count outside 1..=10000 or a
    /// total above 16 TiB.
    #[expect(
        clippy::too_many_arguments,
        reason = "one argument per signed field of the §7.7 layout"
    )]
    pub fn new(
        session_id: [u8; 32],
        transfer_id: TransferId,
        manifest_hash: [u8; 32],
        accept_hash: [u8; 32],
        sender_public: [u8; PUBLIC_KEY_LEN],
        receiver_public: [u8; PUBLIC_KEY_LEN],
        receipt_id: [u8; 16],
        completed_at: UnixTime,
        completed_count: u32,
        total_plaintext_bytes: u64,
    ) -> Result<Self, DecodeError> {
        if session_id == [0; 32] {
            return Err(DecodeError::ZeroIdentifier);
        }
        let transfer_id = check_id(transfer_id)?;
        let receipt_id = check_id(receipt_id)?;
        if !(1..=MAX_ENTRIES).contains(&completed_count)
            || total_plaintext_bytes > MAX_TRANSFER_BYTES
        {
            return Err(DecodeError::Range);
        }
        Ok(Self {
            session_id,
            transfer_id,
            manifest_hash,
            accept_hash,
            sender_public,
            receiver_public,
            receipt_id,
            completed_at,
            completed_count,
            total_plaintext_bytes,
        })
    }

    /// The exact signed bytes ([`RECEIPT_PREFIX_LEN`]), without the domain.
    #[must_use]
    pub fn encode(&self) -> [u8; RECEIPT_PREFIX_LEN] {
        let mut out = [0; RECEIPT_PREFIX_LEN];
        out[..2].copy_from_slice(&TRANSFER_VERSION.to_be_bytes());
        out[2..34].copy_from_slice(&self.session_id);
        out[34..50].copy_from_slice(&self.transfer_id);
        out[50..82].copy_from_slice(&self.manifest_hash);
        out[82..114].copy_from_slice(&self.accept_hash);
        out[114..146].copy_from_slice(&self.sender_public);
        out[146..178].copy_from_slice(&self.receiver_public);
        out[178..194].copy_from_slice(&self.receipt_id);
        out[194..202].copy_from_slice(&self.completed_at.seconds().to_be_bytes());
        out[202..206].copy_from_slice(&self.completed_count.to_be_bytes());
        out[206..214].copy_from_slice(&self.total_plaintext_bytes.to_be_bytes());
        out[214] = 1;
        out
    }

    /// The session the receipt is bound to.
    #[must_use]
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// The completed transfer.
    #[must_use]
    pub const fn transfer_id(&self) -> &TransferId {
        &self.transfer_id
    }

    /// Its manifest hash.
    #[must_use]
    pub const fn manifest_hash(&self) -> &[u8; 32] {
        &self.manifest_hash
    }

    /// The current Accept hash.
    #[must_use]
    pub const fn accept_hash(&self) -> &[u8; 32] {
        &self.accept_hash
    }

    /// The sender's full device key (unvalidated).
    #[must_use]
    pub const fn sender_public(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.sender_public
    }

    /// The receiver's full device key, the signer (unvalidated).
    #[must_use]
    pub const fn receiver_public(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.receiver_public
    }

    /// The fresh random receipt ID.
    #[must_use]
    pub const fn receipt_id(&self) -> &[u8; 16] {
        &self.receipt_id
    }

    /// When the receiver finished publication.
    #[must_use]
    pub const fn completed_at(&self) -> UnixTime {
        self.completed_at
    }

    /// How many selected files completed.
    #[must_use]
    pub const fn completed_count(&self) -> u32 {
        self.completed_count
    }

    /// The sum of the selected file sizes.
    #[must_use]
    pub const fn total_plaintext_bytes(&self) -> u64 {
        self.total_plaintext_bytes
    }
}

/// A complete `DeliveryReceipt` (§7.7): the body and the receiver's
/// signature over `todoke/v1/delivery-receipt\0 || body`. Unverified.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DeliveryReceipt {
    body: ReceiptBody,
    signature: [u8; SIGNATURE_LEN],
}

impl DeliveryReceipt {
    /// Attaches a signature to `body`.
    #[must_use]
    pub const fn new(body: ReceiptBody, signature: [u8; SIGNATURE_LEN]) -> Self {
        Self { body, signature }
    }

    /// Parses exactly [`DELIVERY_RECEIPT_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Length`], [`DecodeError::Version`],
    /// [`DecodeError::UnknownEnum`] for a status other than 1,
    /// [`DecodeError::Range`] for an out-of-range time, and every
    /// [`ReceiptBody::new`] error.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != DELIVERY_RECEIPT_LEN {
            return Err(DecodeError::Length);
        }
        let mut reader = Reader::new(bytes);
        version(&mut reader)?;
        let session_id = reader.array()?;
        let transfer_id = reader.array()?;
        let manifest_hash = reader.array()?;
        let accept_hash = reader.array()?;
        let sender_public = reader.array()?;
        let receiver_public = reader.array()?;
        let receipt_id = reader.array()?;
        let completed_at = unix_time(&mut reader)?;
        let completed_count = reader.u32()?;
        let total_plaintext_bytes = reader.u64()?;
        if reader.u8()? != 1 {
            return Err(DecodeError::UnknownEnum);
        }
        let signature = reader.array()?;
        reader.finish()?;
        let body = ReceiptBody::new(
            session_id,
            transfer_id,
            manifest_hash,
            accept_hash,
            sender_public,
            receiver_public,
            receipt_id,
            completed_at,
            completed_count,
            total_plaintext_bytes,
        )?;
        Ok(Self { body, signature })
    }

    /// The exact [`DELIVERY_RECEIPT_LEN`]-byte body.
    #[must_use]
    pub fn encode(&self) -> [u8; DELIVERY_RECEIPT_LEN] {
        let mut out = [0; DELIVERY_RECEIPT_LEN];
        out[..RECEIPT_PREFIX_LEN].copy_from_slice(&self.body.encode());
        out[RECEIPT_PREFIX_LEN..].copy_from_slice(&self.signature);
        out
    }

    /// The signed fields.
    #[must_use]
    pub const fn body(&self) -> &ReceiptBody {
        &self.body
    }

    /// The receiver's signature (unverified).
    #[must_use]
    pub const fn signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.signature
    }
}

#[cfg(test)]
mod tests;
