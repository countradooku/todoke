//! The canonical manifest (PROTOCOL §7.1): a fixed header followed by a
//! tree of entries in wire order. Folders are entries whose children name
//! them as parent; there is no archive format.
//!
//! Decoding validates the whole schema before returning: header fields,
//! consecutive IDs, parents that are preceding directories, names (UTF-8 in
//! NFC, no separators or reserved characters, no DOS device stems, distinct
//! siblings), MIME labels, sizes, roots, suites, depth, joined path length,
//! and the size and count limits. A violation is the `MANIFEST` error
//! (§12). Nothing is normalized or repaired: the bytes that were hashed are
//! the bytes that were checked.
//!
//! Names and MIME labels are untrusted display data. They grant no
//! filesystem authority (destination mapping and collision handling are
//! `todoke-fs`'s) and no execution or preview privilege. `Debug` output
//! prints neither.

use core::fmt;
use std::collections::BTreeSet;

use super::{
    MAX_ENTRIES, MAX_FILE_BYTES, MAX_MANIFEST_BYTES, MAX_TRANSFER_BYTES, Reader, TRANSFER_VERSION,
    TransferId,
};
use crate::identity::PUBLIC_KEY_LEN;
use crate::time::UnixTime;

/// Manifest magic, ASCII `TDKM`.
pub const MANIFEST_MAGIC: [u8; 4] = *b"TDKM";
/// Fixed manifest header length (§7.1).
pub const MANIFEST_HEADER_LEN: usize = 108;
/// Fixed bytes of each entry besides its name and MIME (§7.1).
pub const MANIFEST_ENTRY_FIXED_LEN: usize = 55;
/// Longest name component, in UTF-8 bytes (§7.1, §13).
pub const MAX_NAME_LEN: usize = 255;
/// Longest MIME label (§7.1, §13).
pub const MAX_MIME_LEN: usize = 127;
/// Deepest entry: a top-level entry has depth 1 (§7.1, §13).
pub const MAX_DEPTH: u32 = 64;
/// Longest joined relative path, separators included (§7.1, §13).
pub const MAX_PATH_LEN: usize = 4096;
/// Longest manifest lifetime: 7 days after `created_at` (§7.1).
pub const MAX_MANIFEST_LIFETIME_SECONDS: u64 = 7 * 86_400;

/// Why a manifest was rejected (§7.1). Carries no names or other peer data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ManifestError {
    /// The bytes end early, have trailing bytes, or exceed 4 MiB.
    Length,
    /// The magic is not `TDKM`.
    Magic,
    /// The version is not 1.
    Version,
    /// The transfer ID is zero.
    TransferId,
    /// `created_at`/`expires_at` out of range, not increasing, or more than
    /// seven days apart.
    Time,
    /// `entry_count` is zero or above the receiver's limit.
    EntryCount,
    /// `flags` is nonzero.
    Flags,
    /// An entry ID is not the next consecutive one.
    EntryId,
    /// A parent is neither 0 nor a preceding directory.
    Parent,
    /// The kind is neither 1 (file) nor 2 (directory).
    Kind,
    /// A name is empty, too long, not UTF-8 in NFC, `.`/`..`, contains a
    /// forbidden character, ends in a space or dot, or is a DOS device name.
    Name,
    /// A MIME label is malformed, or nonempty on a directory.
    Mime,
    /// A file is above the size limit, or a directory has a nonzero size.
    Size,
    /// A directory has a nonzero root, or a file the zero root.
    Root,
    /// A file's suite is not 1 or 2, or a directory's is not 0.
    Suite,
    /// Two siblings have the same exact name.
    DuplicateName,
    /// An entry is deeper than 64 levels.
    Depth,
    /// A joined path exceeds 4096 bytes.
    PathLength,
    /// The file sizes sum above the receiver's limit or 16 TiB.
    TotalSize,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Length => "manifest length is invalid",
            Self::Magic => "manifest magic is invalid",
            Self::Version => "unsupported manifest version",
            Self::TransferId => "manifest transfer ID is zero",
            Self::Time => "manifest times are invalid",
            Self::EntryCount => "manifest entry count is out of range",
            Self::Flags => "manifest flags are nonzero",
            Self::EntryId => "manifest entry IDs are not consecutive",
            Self::Parent => "manifest entry parent is invalid",
            Self::Kind => "manifest entry kind is invalid",
            Self::Name => "manifest entry name is invalid",
            Self::Mime => "manifest entry MIME type is invalid",
            Self::Size => "manifest entry size is invalid",
            Self::Root => "manifest entry root is invalid",
            Self::Suite => "manifest entry content suite is invalid",
            Self::DuplicateName => "manifest has duplicate sibling names",
            Self::Depth => "manifest is too deep",
            Self::PathLength => "manifest path is too long",
            Self::TotalSize => "manifest total size is too large",
        })
    }
}

impl std::error::Error for ManifestError {}

/// The receiver's limits for a manifest: its own advertised Capabilities
/// (§6), each at most the protocol maximum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ManifestLimits {
    entries: u32,
    file_bytes: u64,
    transfer_bytes: u64,
}

impl ManifestLimits {
    /// The protocol maximums: 10000 entries, 1 TiB per file, 16 TiB in all.
    pub const SPEC: Self = Self {
        entries: MAX_ENTRIES,
        file_bytes: MAX_FILE_BYTES,
        transfer_bytes: MAX_TRANSFER_BYTES,
    };

    /// Limits from advertised Capabilities, each clamped to the protocol
    /// maximum. A zero entry limit is raised to one.
    #[must_use]
    pub fn new(max_entries: u32, max_file_bytes: u64, max_transfer_bytes: u64) -> Self {
        Self {
            entries: max_entries.clamp(1, MAX_ENTRIES),
            file_bytes: max_file_bytes.min(MAX_FILE_BYTES),
            transfer_bytes: max_transfer_bytes.min(MAX_TRANSFER_BYTES),
        }
    }

    /// Most entries.
    #[must_use]
    pub const fn max_entries(&self) -> u32 {
        self.entries
    }

    /// Largest file.
    #[must_use]
    pub const fn max_file_bytes(&self) -> u64 {
        self.file_bytes
    }

    /// Largest sum of file sizes.
    #[must_use]
    pub const fn max_transfer_bytes(&self) -> u64 {
        self.transfer_bytes
    }
}

/// The header fields that are not derived from the entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ManifestHeader {
    /// The transfer ID (nonzero).
    pub transfer_id: TransferId,
    /// The authenticated sender's full device key.
    pub sender_public: [u8; PUBLIC_KEY_LEN],
    /// The receiver's full device key.
    pub recipient_public: [u8; PUBLIC_KEY_LEN],
    /// When the sender built the manifest.
    pub created_at: UnixTime,
    /// When the manifest stops being valid: after `created_at`, at most 7
    /// days later.
    pub expires_at: UnixTime,
}

/// An entry kind (§7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EntryKind {
    /// A regular file, with content.
    File,
    /// A directory: metadata only, no key or segment.
    Directory,
}

impl EntryKind {
    const fn to_u8(self) -> u8 {
        match self {
            Self::File => 1,
            Self::Directory => 2,
        }
    }

    const fn from_u8(value: u8) -> Result<Self, ManifestError> {
        match value {
            1 => Ok(Self::File),
            2 => Ok(Self::Directory),
            _ => Err(ManifestError::Kind),
        }
    }
}

/// One manifest entry (§7.1).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ManifestEntry {
    pub(crate) id: u32,
    pub(crate) parent: u32,
    pub(crate) kind: EntryKind,
    pub(crate) name: String,
    pub(crate) mime: String,
    pub(crate) size: u64,
    pub(crate) root: [u8; 32],
    pub(crate) content_suite: u16,
}

impl ManifestEntry {
    /// A directory entry. Validated when the manifest is assembled.
    #[must_use]
    pub fn directory(id: u32, parent: u32, name: String) -> Self {
        Self {
            id,
            parent,
            kind: EntryKind::Directory,
            name,
            mime: String::new(),
            size: 0,
            root: [0; 32],
            content_suite: 0,
        }
    }

    /// A regular-file entry. Validated when the manifest is assembled.
    #[must_use]
    pub fn file(
        id: u32,
        parent: u32,
        name: String,
        mime: String,
        size: u64,
        root: [u8; 32],
        content_suite: u16,
    ) -> Self {
        Self {
            id,
            parent,
            kind: EntryKind::File,
            name,
            mime,
            size,
            root,
            content_suite,
        }
    }

    /// The entry ID, 1..=`entry_count`.
    #[must_use]
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// The parent directory's ID, or 0 for the implicit root.
    #[must_use]
    pub const fn parent(&self) -> u32 {
        self.parent
    }

    /// File or directory.
    #[must_use]
    pub const fn kind(&self) -> EntryKind {
        self.kind
    }

    /// Whether this is a regular file.
    #[must_use]
    pub const fn is_file(&self) -> bool {
        matches!(self.kind, EntryKind::File)
    }

    /// The name component: untrusted display data.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The MIME label (empty for a directory): untrusted, grants nothing.
    #[must_use]
    pub fn mime(&self) -> &str {
        &self.mime
    }

    /// The file size in bytes (0 for a directory).
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// The BLAKE3 plaintext root (zero for a directory).
    #[must_use]
    pub const fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// The content suite: 1 AES, 2 `XChaCha`, 0 for a directory.
    #[must_use]
    pub const fn content_suite(&self) -> u16 {
        self.content_suite
    }

    fn encoded_len(&self) -> usize {
        MANIFEST_ENTRY_FIXED_LEN + self.name.len() + self.mime.len()
    }
}

impl fmt::Debug for ManifestEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManifestEntry")
            .field("id", &self.id)
            .field("parent", &self.parent)
            .field("kind", &self.kind)
            .field("size", &self.size)
            .field("content_suite", &self.content_suite)
            .finish_non_exhaustive()
    }
}

/// A validated canonical manifest (§7.1).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Manifest {
    header: ManifestHeader,
    entries: Vec<ManifestEntry>,
    file_count: u32,
    total_file_bytes: u64,
}

impl Manifest {
    /// Validates entries against `limits` and assembles a manifest. Entries
    /// must already be in wire order with consecutive IDs from 1.
    ///
    /// # Errors
    ///
    /// Any [`ManifestError`], including [`ManifestError::Length`] if the
    /// encoding would exceed 4 MiB.
    pub fn new(
        header: ManifestHeader,
        entries: Vec<ManifestEntry>,
        limits: &ManifestLimits,
    ) -> Result<Self, ManifestError> {
        check_header(&header)?;
        let count = u32::try_from(entries.len()).map_err(|_| ManifestError::EntryCount)?;
        if count == 0 || count > limits.entries {
            return Err(ManifestError::EntryCount);
        }
        let mut validator = Validator::new(limits);
        let mut length = MANIFEST_HEADER_LEN;
        for entry in &entries {
            validator.check(
                entry.id,
                entry.parent,
                entry.kind,
                entry.name.as_bytes(),
                entry.mime.as_bytes(),
                entry.size,
                &entry.root,
                entry.content_suite,
            )?;
            length = length
                .checked_add(entry.encoded_len())
                .ok_or(ManifestError::Length)?;
        }
        if length > MAX_MANIFEST_BYTES as usize {
            return Err(ManifestError::Length);
        }
        Ok(Self {
            header,
            entries,
            file_count: validator.file_count,
            total_file_bytes: validator.total_file_bytes,
        })
    }

    /// Parses and validates canonical manifest bytes against `limits` (the
    /// receiver's own Capabilities). Lengths and counts are checked before
    /// anything is allocated for them.
    ///
    /// # Errors
    ///
    /// Any [`ManifestError`].
    pub fn decode(bytes: &[u8], limits: &ManifestLimits) -> Result<Self, ManifestError> {
        if bytes.len() < MANIFEST_HEADER_LEN || bytes.len() > MAX_MANIFEST_BYTES as usize {
            return Err(ManifestError::Length);
        }
        let mut reader = Reader::new(bytes);
        let length = |_| ManifestError::Length;
        if reader.array::<4>().map_err(length)? != MANIFEST_MAGIC {
            return Err(ManifestError::Magic);
        }
        if reader.u16().map_err(length)? != TRANSFER_VERSION {
            return Err(ManifestError::Version);
        }
        let transfer_id = reader.array().map_err(length)?;
        let sender_public = reader.array().map_err(length)?;
        let recipient_public = reader.array().map_err(length)?;
        let created_at = UnixTime::new(reader.u64().map_err(length)?).ok_or(ManifestError::Time)?;
        let expires_at = UnixTime::new(reader.u64().map_err(length)?).ok_or(ManifestError::Time)?;
        let count = reader.u32().map_err(length)?;
        if reader.u16().map_err(length)? != 0 {
            return Err(ManifestError::Flags);
        }
        let header = ManifestHeader {
            transfer_id,
            sender_public,
            recipient_public,
            created_at,
            expires_at,
        };
        check_header(&header)?;
        if count == 0 || count > limits.entries {
            return Err(ManifestError::EntryCount);
        }
        // Each entry has at least 56 bytes (a one-byte name), so the count
        // also bounds the allocation by the input length.
        let count = usize::try_from(count).map_err(|_| ManifestError::EntryCount)?;
        if count.saturating_mul(MANIFEST_ENTRY_FIXED_LEN + 1) > reader.remaining() {
            return Err(ManifestError::Length);
        }
        let mut validator = Validator::new(limits);
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let id = reader.u32().map_err(length)?;
            let parent = reader.u32().map_err(length)?;
            let kind = EntryKind::from_u8(reader.u8().map_err(length)?)?;
            let name_len = usize::from(reader.u16().map_err(length)?);
            let name = reader.take(name_len).map_err(length)?;
            let mime_len = usize::from(reader.u16().map_err(length)?);
            let mime = reader.take(mime_len).map_err(length)?;
            let size = reader.u64().map_err(length)?;
            let root = reader.array().map_err(length)?;
            let content_suite = reader.u16().map_err(length)?;
            let (name, mime) =
                validator.check(id, parent, kind, name, mime, size, &root, content_suite)?;
            entries.push(ManifestEntry {
                id,
                parent,
                kind,
                name: name.to_owned(),
                mime: mime.to_owned(),
                size,
                root,
                content_suite,
            });
        }
        reader.finish().map_err(length)?;
        Ok(Self {
            header,
            entries,
            file_count: validator.file_count,
            total_file_bytes: validator.total_file_bytes,
        })
    }

    /// The canonical encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let length = self
            .entries
            .iter()
            .map(ManifestEntry::encoded_len)
            .sum::<usize>()
            + MANIFEST_HEADER_LEN;
        let mut out = Vec::with_capacity(length);
        out.extend_from_slice(&MANIFEST_MAGIC);
        out.extend_from_slice(&TRANSFER_VERSION.to_be_bytes());
        out.extend_from_slice(&self.header.transfer_id);
        out.extend_from_slice(&self.header.sender_public);
        out.extend_from_slice(&self.header.recipient_public);
        out.extend_from_slice(&self.header.created_at.seconds().to_be_bytes());
        out.extend_from_slice(&self.header.expires_at.seconds().to_be_bytes());
        // Validation bounds the count by 10000.
        let count = u32::try_from(self.entries.len()).unwrap_or(0);
        out.extend_from_slice(&count.to_be_bytes());
        out.extend_from_slice(&0_u16.to_be_bytes());
        for entry in &self.entries {
            out.extend_from_slice(&entry.id.to_be_bytes());
            out.extend_from_slice(&entry.parent.to_be_bytes());
            out.push(entry.kind.to_u8());
            // Validation bounds names by 255 and MIME labels by 127 bytes.
            let name_len = u16::try_from(entry.name.len()).unwrap_or(0);
            out.extend_from_slice(&name_len.to_be_bytes());
            out.extend_from_slice(entry.name.as_bytes());
            let mime_len = u16::try_from(entry.mime.len()).unwrap_or(0);
            out.extend_from_slice(&mime_len.to_be_bytes());
            out.extend_from_slice(entry.mime.as_bytes());
            out.extend_from_slice(&entry.size.to_be_bytes());
            out.extend_from_slice(&entry.root);
            out.extend_from_slice(&entry.content_suite.to_be_bytes());
        }
        out
    }

    /// The header fields.
    #[must_use]
    pub const fn header(&self) -> &ManifestHeader {
        &self.header
    }

    /// The entries in wire order; entry `id` is at index `id - 1`.
    #[must_use]
    pub fn entries(&self) -> &[ManifestEntry] {
        &self.entries
    }

    /// The entry with this ID.
    #[must_use]
    pub fn entry(&self, id: u32) -> Option<&ManifestEntry> {
        let index = usize::try_from(id.checked_sub(1)?).ok()?;
        self.entries.get(index)
    }

    /// The regular file with this ID.
    #[must_use]
    pub fn file(&self, id: u32) -> Option<&ManifestEntry> {
        self.entry(id).filter(|entry| entry.is_file())
    }

    /// The regular files in ID order.
    pub fn files(&self) -> impl Iterator<Item = &ManifestEntry> {
        self.entries.iter().filter(|entry| entry.is_file())
    }

    /// The number of regular files.
    #[must_use]
    pub const fn file_count(&self) -> u32 {
        self.file_count
    }

    /// The sum of all file sizes.
    #[must_use]
    pub const fn total_file_bytes(&self) -> u64 {
        self.total_file_bytes
    }

    /// The names from the implicit root down to entry `id`, for display or
    /// for `todoke-fs` to map onto a destination. Untrusted data.
    #[must_use]
    pub fn path_components(&self, id: u32) -> Option<Vec<&str>> {
        let mut components = Vec::new();
        let mut current = self.entry(id)?;
        loop {
            components.push(current.name());
            if current.parent == 0 {
                break;
            }
            // Validation guarantees parents precede children, so this ends.
            current = self.entry(current.parent)?;
        }
        components.reverse();
        Some(components)
    }
}

impl fmt::Debug for Manifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Manifest")
            .field("header", &self.header)
            .field("entries", &self.entries.len())
            .field("file_count", &self.file_count)
            .field("total_file_bytes", &self.total_file_bytes)
            .finish_non_exhaustive()
    }
}

fn check_header(header: &ManifestHeader) -> Result<(), ManifestError> {
    if header.transfer_id == [0; 16] {
        return Err(ManifestError::TransferId);
    }
    let created = header.created_at.seconds();
    let expires = header.expires_at.seconds();
    if expires <= created || expires - created > MAX_MANIFEST_LIFETIME_SECONDS {
        return Err(ManifestError::Time);
    }
    Ok(())
}

/// Where a directory sits in the tree.
#[derive(Clone, Copy)]
struct Directory {
    depth: u32,
    path_len: usize,
}

/// Running validation state over entries in wire order.
struct Validator<'l> {
    limits: &'l ManifestLimits,
    /// Directories by ID; `None` for files.
    directories: Vec<Option<Directory>>,
    siblings: BTreeSet<(u32, Vec<u8>)>,
    file_count: u32,
    total_file_bytes: u64,
}

impl<'l> Validator<'l> {
    fn new(limits: &'l ManifestLimits) -> Self {
        Self {
            limits,
            directories: Vec::new(),
            siblings: BTreeSet::new(),
            file_count: 0,
            total_file_bytes: 0,
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "one argument per §7.1 entry field"
    )]
    fn check<'a>(
        &mut self,
        id: u32,
        parent: u32,
        kind: EntryKind,
        name: &'a [u8],
        mime: &'a [u8],
        size: u64,
        root: &[u8; 32],
        content_suite: u16,
    ) -> Result<(&'a str, &'a str), ManifestError> {
        let expected = u32::try_from(self.directories.len())
            .ok()
            .and_then(|count| count.checked_add(1))
            .ok_or(ManifestError::EntryId)?;
        if id != expected {
            return Err(ManifestError::EntryId);
        }
        let (depth, parent_path_len) = if parent == 0 {
            (1, 0)
        } else {
            let index = usize::try_from(parent - 1).map_err(|_| ManifestError::Parent)?;
            match self.directories.get(index) {
                Some(Some(directory)) => (directory.depth + 1, directory.path_len + 1),
                _ => return Err(ManifestError::Parent),
            }
        };
        if depth > MAX_DEPTH {
            return Err(ManifestError::Depth);
        }
        let name = validate_name(name)?;
        let path_len = parent_path_len + name.len();
        if path_len > MAX_PATH_LEN {
            return Err(ManifestError::PathLength);
        }
        let mime = match kind {
            EntryKind::Directory => {
                if !mime.is_empty() {
                    return Err(ManifestError::Mime);
                }
                if size != 0 {
                    return Err(ManifestError::Size);
                }
                if *root != [0; 32] {
                    return Err(ManifestError::Root);
                }
                if content_suite != 0 {
                    return Err(ManifestError::Suite);
                }
                ""
            }
            EntryKind::File => {
                let mime = validate_mime(mime)?;
                if size > self.limits.file_bytes {
                    return Err(ManifestError::Size);
                }
                // An empty file has the BLAKE3 root of the empty input, never
                // zero; no file can have the zero root.
                if *root == [0; 32] {
                    return Err(ManifestError::Root);
                }
                if !matches!(content_suite, 1 | 2) {
                    return Err(ManifestError::Suite);
                }
                self.total_file_bytes = self
                    .total_file_bytes
                    .checked_add(size)
                    .filter(|&total| total <= self.limits.transfer_bytes)
                    .ok_or(ManifestError::TotalSize)?;
                self.file_count += 1;
                mime
            }
        };
        if !self.siblings.insert((parent, name.as_bytes().to_vec())) {
            return Err(ManifestError::DuplicateName);
        }
        self.directories.push(match kind {
            EntryKind::Directory => Some(Directory { depth, path_len }),
            EntryKind::File => None,
        });
        Ok((name, mime))
    }
}

/// DOS device stems, compared ASCII-case-insensitively before the first dot.
const DOS_DEVICES: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Checks one name component (§7.1) and returns it as `&str`.
///
/// # Errors
///
/// [`ManifestError::Name`] for any violation.
pub fn validate_name(bytes: &[u8]) -> Result<&str, ManifestError> {
    if bytes.is_empty() || bytes.len() > MAX_NAME_LEN {
        return Err(ManifestError::Name);
    }
    let name = core::str::from_utf8(bytes).map_err(|_| ManifestError::Name)?;
    if name == "." || name == ".." {
        return Err(ManifestError::Name);
    }
    let forbidden = |c: char| {
        c.is_ascii_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
    };
    if name.chars().any(forbidden) || name.ends_with([' ', '.']) {
        return Err(ManifestError::Name);
    }
    let stem = name.split('.').next().unwrap_or(name);
    if DOS_DEVICES
        .iter()
        .any(|device| stem.eq_ignore_ascii_case(device))
    {
        return Err(ManifestError::Name);
    }
    if !unicode_normalization::is_nfc(name) {
        return Err(ManifestError::Name);
    }
    Ok(name)
}

/// Checks a file's MIME label (§7.1): 1..=127 bytes, exactly one `/`,
/// nonempty type and subtype of `a-z`, `0-9`, and `!#$&^_.+-`.
///
/// # Errors
///
/// [`ManifestError::Mime`] for any violation.
pub fn validate_mime(bytes: &[u8]) -> Result<&str, ManifestError> {
    if bytes.is_empty() || bytes.len() > MAX_MIME_LEN {
        return Err(ManifestError::Mime);
    }
    let allowed = |&byte: &u8| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"!#$&^_.+-".contains(&byte)
    };
    let mut parts = bytes.split(|&byte| byte == b'/');
    let (Some(kind), Some(subtype), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(ManifestError::Mime);
    };
    if kind.is_empty()
        || subtype.is_empty()
        || !kind.iter().all(allowed)
        || !subtype.iter().all(allowed)
    {
        return Err(ManifestError::Mime);
    }
    // Every byte is ASCII.
    core::str::from_utf8(bytes).map_err(|_| ManifestError::Mime)
}
