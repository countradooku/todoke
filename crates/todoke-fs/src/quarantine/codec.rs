//! Local storage formats of the quarantine: the per-transfer journal and
//! the tombstone list. Not wire formats (PROTOCOL §1 does not cover them);
//! versioned, so a change is never silently reinterpreted. Every field is
//! bounded and checked before anything is allocated for it, and each
//! record carries a BLAKE3 check value that detects torn or damaged
//! writes. These checks detect accidents, not attackers: the quarantine is
//! private application storage, and every name read back is validated
//! again and only ever resolved below the destination root.

use crate::name::{MAX_COMPONENT_BYTES, acceptable};

/// `TDKJ`: a transfer journal.
const JOURNAL_MAGIC: [u8; 4] = *b"TDKJ";
/// `TDKT`: the tombstone list.
const TOMBSTONE_MAGIC: [u8; 4] = *b"TDKT";
const VERSION: u16 = 1;
const HEADER_DOMAIN: &[u8] = b"todoke/fs/v1/journal-header\0";
const ENTRY_DOMAIN: &[u8] = b"todoke/fs/v1/journal-entry\0";
const TOMBSTONE_DOMAIN: &[u8] = b"todoke/fs/v1/tombstones\0";
/// The fixed part of a journal header before the selection.
const HEADER_FIXED: usize = 4 + 2 + 16 + 32 + 32 + 8 + 32 + 4;
const CHECK_LEN: usize = 32;
const ENTRY_CHECK_LEN: usize = 16;
/// The most files one transfer can select (§7.3).
pub(crate) const MAX_SELECTION: usize = 10_000;
/// The most `TopDirectory` records per top-level directory: its creation
/// and up to three re-creations under a new name after the user removed it
/// and its name was taken. The sink then fails the transfer rather than
/// record more.
pub(crate) const MAX_TOP_DIRECTORY_RECORDS: usize = 4;
/// The most entries a journal holds. The sink writes at most one consented
/// name per manifest entry, one publication per file,
/// [`MAX_TOP_DIRECTORY_RECORDS`] per top-level directory, and the end
/// marker: with at most 10,000 entries, files and directories together,
/// that is at most 50,001. A journal with more intact entries is damaged
/// as a whole; it is never cut at the cap.
pub(crate) const MAX_JOURNAL_ENTRIES: usize = 4 * 20_000;
/// The most tombstones the list file holds.
pub(crate) const MAX_TOMBSTONES: usize = 65_536;

/// A journal record could not be decoded. No detail: the transfer's
/// quarantine is then discarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Corrupt;

/// What a transfer's journal starts with, written once when the Accept is
/// recorded.
#[derive(Clone, PartialEq, Eq)]
pub struct JournalHeader {
    /// The transfer.
    pub transfer_id: [u8; 16],
    /// The accepted manifest's hash.
    pub manifest_hash: [u8; 32],
    /// The sender's full device key.
    pub sender: [u8; 32],
    /// The manifest's expiry (Unix seconds): nothing is retained after it.
    pub expires_at: u64,
    /// Random, secret: derives this transfer's temporary file names.
    pub salt: [u8; 32],
    /// The accepted selection, strictly increasing file IDs.
    pub selection: Vec<u32>,
}

impl core::fmt::Debug for JournalHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("JournalHeader")
            .field("expires_at", &self.expires_at)
            .field("selection", &self.selection.len())
            .finish_non_exhaustive()
    }
}

/// One journal entry after the header.
#[derive(Clone, PartialEq, Eq)]
pub enum JournalEntry {
    /// Entry `id` (a selected file or one of its directories) was shown to
    /// the user as `name` before consent. Written with the header, once
    /// per entry, when the Accept is recorded: publication uses these
    /// names, never a mapping computed again later.
    Planned {
        /// The manifest entry ID.
        id: u32,
        /// The local name the user consented to.
        name: String,
    },
    /// Top-level directory `id` was created under `name`.
    TopDirectory {
        /// The manifest directory ID.
        id: u32,
        /// The local name it got.
        name: String,
    },
    /// File `id` was published under `name` in its planned directory.
    Published {
        /// The manifest file ID.
        id: u32,
        /// The local name it got.
        name: String,
    },
    /// Every selected file was published and the receipt sent.
    Finished,
}

impl core::fmt::Debug for JournalEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Planned { id, .. } => write!(f, "Planned({id})"),
            Self::TopDirectory { id, .. } => write!(f, "TopDirectory({id})"),
            Self::Published { id, .. } => write!(f, "Published({id})"),
            Self::Finished => f.write_str("Finished"),
        }
    }
}

fn check(domain: &[u8], body: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(body);
    *hasher.finalize().as_bytes()
}

/// A cursor over untrusted bytes; every read is bounds-checked.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Corrupt> {
        let end = self.at.checked_add(len).ok_or(Corrupt)?;
        let slice = self.bytes.get(self.at..end).ok_or(Corrupt)?;
        self.at = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Corrupt> {
        let mut out = [0; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u16(&mut self) -> Result<u16, Corrupt> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, Corrupt> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, Corrupt> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn rest(&self) -> &'a [u8] {
        self.bytes.get(self.at..).unwrap_or_default()
    }
}

impl JournalHeader {
    /// The encoded header, check value included.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_FIXED + 4 * self.selection.len() + CHECK_LEN);
        out.extend_from_slice(&JOURNAL_MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&self.transfer_id);
        out.extend_from_slice(&self.manifest_hash);
        out.extend_from_slice(&self.sender);
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.salt);
        let count = u32::try_from(self.selection.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&count.to_be_bytes());
        for id in &self.selection {
            out.extend_from_slice(&id.to_be_bytes());
        }
        let value = check(HEADER_DOMAIN, &out);
        out.extend_from_slice(&value);
        out
    }
}

/// Decodes a whole journal: the header, then entries up to the first one
/// that is incomplete or damaged (a write torn by a crash). Returns the
/// header, the entries, and how many bytes are valid, so the caller can
/// cut the damaged tail before appending again.
///
/// # Errors
///
/// [`Corrupt`] if the header is damaged or out of bounds.
pub fn decode_journal(bytes: &[u8]) -> Result<(JournalHeader, Vec<JournalEntry>, usize), Corrupt> {
    let mut reader = Reader::new(bytes);
    if reader.array::<4>()? != JOURNAL_MAGIC || reader.u16()? != VERSION {
        return Err(Corrupt);
    }
    let transfer_id = reader.array()?;
    let manifest_hash = reader.array()?;
    let sender = reader.array()?;
    let expires_at = reader.u64()?;
    let salt = reader.array()?;
    let count = usize::try_from(reader.u32()?).map_err(|_| Corrupt)?;
    if count == 0 || count > MAX_SELECTION {
        return Err(Corrupt);
    }
    let mut selection = Vec::with_capacity(count);
    for _ in 0..count {
        let id = reader.u32()?;
        if id == 0 || selection.last().is_some_and(|&last| id <= last) {
            return Err(Corrupt);
        }
        selection.push(id);
    }
    let body_len = reader.at;
    let stored: [u8; CHECK_LEN] = reader.array()?;
    if stored != check(HEADER_DOMAIN, bytes.get(..body_len).ok_or(Corrupt)?) {
        return Err(Corrupt);
    }
    if transfer_id == [0; 16] {
        return Err(Corrupt);
    }
    let header = JournalHeader {
        transfer_id,
        manifest_hash,
        sender,
        expires_at,
        salt,
        selection,
    };
    let mut entries = Vec::new();
    let mut valid = reader.at;
    while !reader.rest().is_empty() {
        match decode_entry(&mut reader) {
            // More intact entries than any journal the sink writes: the
            // whole journal is damaged. Cutting it here would make the
            // next append truncate the intact entries after the cap.
            Ok(_) if entries.len() == MAX_JOURNAL_ENTRIES => return Err(Corrupt),
            Ok(entry) => {
                entries.push(entry);
                valid = reader.at;
            }
            Err(Corrupt) => break,
        }
    }
    Ok((header, entries, valid))
}

fn decode_entry(reader: &mut Reader<'_>) -> Result<JournalEntry, Corrupt> {
    let start = reader.at;
    let kind = reader.take(1)?.first().copied().ok_or(Corrupt)?;
    let id = reader.u32()?;
    let name_len = usize::from(reader.u16()?);
    if name_len > MAX_COMPONENT_BYTES {
        return Err(Corrupt);
    }
    let name = reader.take(name_len)?;
    let body = reader.bytes.get(start..reader.at).ok_or(Corrupt)?;
    let expected = check(ENTRY_DOMAIN, body);
    let stored = reader.take(ENTRY_CHECK_LEN)?;
    if stored != &expected[..ENTRY_CHECK_LEN] {
        return Err(Corrupt);
    }
    let name = || -> Result<String, Corrupt> {
        let name = core::str::from_utf8(name).map_err(|_| Corrupt)?;
        if !acceptable(name) {
            return Err(Corrupt);
        }
        Ok(name.to_owned())
    };
    match (kind, id) {
        (1, 1..) => Ok(JournalEntry::TopDirectory { id, name: name()? }),
        (2, 1..) => Ok(JournalEntry::Published { id, name: name()? }),
        (3, 0) if name_len == 0 => Ok(JournalEntry::Finished),
        (4, 1..) => Ok(JournalEntry::Planned { id, name: name()? }),
        _ => Err(Corrupt),
    }
}

impl JournalEntry {
    /// The encoded entry, check value included.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let (kind, id, name) = match self {
            Self::TopDirectory { id, name } => (1_u8, *id, name.as_bytes()),
            Self::Published { id, name } => (2, *id, name.as_bytes()),
            Self::Finished => (3, 0, &[][..]),
            Self::Planned { id, name } => (4, *id, name.as_bytes()),
        };
        let name = &name[..name.len().min(MAX_COMPONENT_BYTES)];
        let mut out = Vec::with_capacity(7 + name.len() + ENTRY_CHECK_LEN);
        out.push(kind);
        out.extend_from_slice(&id.to_be_bytes());
        let len = u16::try_from(name.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(name);
        let value = check(ENTRY_DOMAIN, &out);
        out.extend_from_slice(&value[..ENTRY_CHECK_LEN]);
        out
    }
}

/// Encodes the tombstone list: transfer IDs with the time (Unix seconds)
/// until which each stays refused.
#[must_use]
pub fn encode_tombstones(tombstones: &[([u8; 16], u64)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + 24 * tombstones.len() + CHECK_LEN);
    out.extend_from_slice(&TOMBSTONE_MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    let count = u32::try_from(tombstones.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&count.to_be_bytes());
    for (id, until) in tombstones {
        out.extend_from_slice(id);
        out.extend_from_slice(&until.to_be_bytes());
    }
    let value = check(TOMBSTONE_DOMAIN, &out);
    out.extend_from_slice(&value);
    out
}

/// Decodes the tombstone list (IDs strictly increasing).
///
/// # Errors
///
/// [`Corrupt`] for anything but an exact, intact list.
pub fn decode_tombstones(bytes: &[u8]) -> Result<Vec<([u8; 16], u64)>, Corrupt> {
    let mut reader = Reader::new(bytes);
    if reader.array::<4>()? != TOMBSTONE_MAGIC || reader.u16()? != VERSION {
        return Err(Corrupt);
    }
    let count = usize::try_from(reader.u32()?).map_err(|_| Corrupt)?;
    if count > MAX_TOMBSTONES || reader.rest().len() != count * 24 + CHECK_LEN {
        return Err(Corrupt);
    }
    let mut tombstones = Vec::with_capacity(count);
    for _ in 0..count {
        let id: [u8; 16] = reader.array()?;
        let until = reader.u64()?;
        if tombstones.last().is_some_and(|(last, _)| id <= *last) {
            return Err(Corrupt);
        }
        tombstones.push((id, until));
    }
    let body_len = reader.at;
    let stored: [u8; CHECK_LEN] = reader.array()?;
    if stored != check(TOMBSTONE_DOMAIN, bytes.get(..body_len).ok_or(Corrupt)?) {
        return Err(Corrupt);
    }
    Ok(tombstones)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn header() -> JournalHeader {
        JournalHeader {
            transfer_id: [1; 16],
            manifest_hash: [2; 32],
            sender: [3; 32],
            expires_at: 1_760_000_000,
            salt: [4; 32],
            selection: vec![1, 5, 9],
        }
    }

    #[test]
    fn journals_round_trip_and_stop_at_a_torn_tail() -> TestResult {
        let entries = vec![
            JournalEntry::Planned {
                id: 1,
                name: "Photos".to_owned(),
            },
            JournalEntry::TopDirectory {
                id: 1,
                name: "Photos (2)".to_owned(),
            },
            JournalEntry::Published {
                id: 5,
                name: "a.jpg".to_owned(),
            },
            JournalEntry::Finished,
        ];
        let mut bytes = header().encode();
        for entry in &entries {
            bytes.extend_from_slice(&entry.encode());
        }
        let (decoded, decoded_entries, valid) = decode_journal(&bytes).map_err(|_| "decode")?;
        assert_eq!(decoded, header());
        assert_eq!(decoded_entries, entries);
        assert_eq!(valid, bytes.len());
        // Every truncation keeps the complete entries before it.
        let header_len = header().encode().len();
        for cut in header_len..bytes.len() {
            let (_, partial, valid) = decode_journal(&bytes[..cut]).map_err(|_| "decode")?;
            assert!(valid <= cut);
            assert_eq!(partial, entries[..partial.len()]);
        }
        for cut in 0..header_len {
            assert!(decode_journal(&bytes[..cut]).is_err());
        }
        // Any flipped bit in the header is fatal; in an entry, it ends the
        // journal there.
        for index in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] ^= 0x10;
            match decode_journal(&changed) {
                Err(Corrupt) => assert!(index < header_len, "{index}"),
                Ok((_, partial, _)) => {
                    assert!(index >= header_len);
                    assert!(partial.len() < entries.len());
                }
            }
        }
        Ok(())
    }

    #[test]
    fn journal_bounds_are_enforced() {
        let mut bad = header();
        bad.selection = vec![2, 2];
        assert!(decode_journal(&bad.encode()).is_err());
        bad.selection = vec![];
        assert!(decode_journal(&bad.encode()).is_err());
        bad.selection = vec![0];
        assert!(decode_journal(&bad.encode()).is_err());
        let mut zero = header();
        zero.transfer_id = [0; 16];
        assert!(decode_journal(&zero.encode()).is_err());
        // Names must be safe local names.
        let mut bytes = header().encode();
        let valid = bytes.len();
        bytes.extend_from_slice(
            &JournalEntry::Published {
                id: 5,
                name: "../escape".to_owned(),
            }
            .encode(),
        );
        assert_eq!(
            decode_journal(&bytes).map(|(_, e, v)| (e.len(), v)),
            Ok((0, valid))
        );
    }

    /// A journal with more intact entries than the cap is refused as a
    /// whole: it is never cut there, which would make the next append
    /// truncate the intact entries after the cap.
    #[test]
    fn a_journal_over_the_entry_cap_is_refused_not_cut() -> TestResult {
        let entry = JournalEntry::Published {
            id: 5,
            name: "a.jpg".to_owned(),
        }
        .encode();
        let mut bytes = header().encode();
        for _ in 0..MAX_JOURNAL_ENTRIES {
            bytes.extend_from_slice(&entry);
        }
        let (_, entries, valid) = decode_journal(&bytes).map_err(|_| "at the cap")?;
        assert_eq!((entries.len(), valid), (MAX_JOURNAL_ENTRIES, bytes.len()));
        // A torn entry after the cap is still a torn tail.
        let mut torn = bytes.clone();
        torn.extend_from_slice(&entry[..5]);
        assert_eq!(
            decode_journal(&torn).map(|(_, e, v)| (e.len(), v)),
            Ok((MAX_JOURNAL_ENTRIES, bytes.len()))
        );
        bytes.extend_from_slice(&entry);
        assert_eq!(decode_journal(&bytes).map(|_| ()), Err(Corrupt));
        Ok(())
    }

    /// What the sink can write stays within the cap: one consented name
    /// per entry, one publication per file, a bounded number of top-level
    /// directory records per directory, and the end marker.
    #[test]
    fn the_sink_writes_fewer_entries_than_the_cap() {
        const MAX_ENTRIES: usize = 10_000;
        let bound = MAX_ENTRIES + MAX_ENTRIES * MAX_TOP_DIRECTORY_RECORDS.max(1) + 1;
        assert!(bound <= MAX_JOURNAL_ENTRIES, "{bound}");
    }

    /// An entry with an intact check value but fields the sink never
    /// writes, built byte by byte.
    fn raw_entry(kind: u8, id: u32, name: &[u8]) -> Vec<u8> {
        let mut out = vec![kind];
        out.extend_from_slice(&id.to_be_bytes());
        let len = u16::try_from(name.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(name);
        let value = check(ENTRY_DOMAIN, &out);
        out.extend_from_slice(&value[..ENTRY_CHECK_LEN]);
        out
    }

    /// Every entry kind needs its own ID range and a safe local name; an
    /// entry that fails ends the journal there, like a torn one, whatever
    /// follows it.
    #[test]
    fn entries_with_invalid_fields_end_the_journal() -> TestResult {
        let good = JournalEntry::Planned {
            id: 1,
            name: "a".to_owned(),
        };
        assert_eq!(raw_entry(4, 1, b"a"), good.encode());
        assert_eq!(raw_entry(3, 0, b""), JournalEntry::Finished.encode());
        let alpha = "\u{1F82}".repeat(85);
        let bad: Vec<Vec<u8>> = vec![
            raw_entry(1, 0, b"a"),
            raw_entry(2, 0, b"a"),
            raw_entry(4, 0, b"a"),
            raw_entry(3, 0, b"x"),
            raw_entry(3, 1, b""),
            raw_entry(0, 1, b"a"),
            raw_entry(5, 1, b"a"),
            raw_entry(2, 1, b""),
            raw_entry(2, 1, &[0xff, 0xfe]),
            raw_entry(2, 1, b".."),
            raw_entry(2, 1, b"a/b"),
            raw_entry(2, 1, b"x."),
            raw_entry(2, 1, b"CON"),
            raw_entry(2, 1, "COM\u{B9}".as_bytes()),
            raw_entry(2, 1, b".todoke-0123.part"),
            raw_entry(2, 1, b"$MFT"),
            raw_entry(2, 1, "a\u{202E}b".as_bytes()),
            raw_entry(2, 1, "a\u{200B}b".as_bytes()),
            raw_entry(2, 1, "e\u{301}".as_bytes()),
            raw_entry(2, 1, alpha.as_bytes()),
            raw_entry(2, 1, "n".repeat(256).as_bytes()),
        ];
        let mut prefix = header().encode();
        prefix.extend_from_slice(&good.encode());
        for entry in &bad {
            let mut bytes = prefix.clone();
            bytes.extend_from_slice(entry);
            bytes.extend_from_slice(&good.encode());
            let (_, entries, valid) = decode_journal(&bytes).map_err(|_| "decode")?;
            assert_eq!(entries, core::slice::from_ref(&good), "{entry:?}");
            assert_eq!(valid, prefix.len(), "{entry:?}");
        }
        // The longest safe name is accepted.
        let mut bytes = prefix.clone();
        bytes.extend_from_slice(&raw_entry(2, 1, "n".repeat(255).as_bytes()));
        let (_, entries, _) = decode_journal(&bytes).map_err(|_| "decode")?;
        assert_eq!(entries.len(), 2);
        Ok(())
    }

    /// The header's version, selection bound, and order are checked even
    /// under an intact check value.
    #[test]
    fn header_fields_are_checked_under_an_intact_check_value() -> TestResult {
        let resealed = |mut body: Vec<u8>| {
            body.truncate(body.len() - CHECK_LEN);
            let value = check(HEADER_DOMAIN, &body);
            body.extend_from_slice(&value);
            body
        };
        let mut version = header().encode();
        version[5] = 2;
        assert_eq!(decode_journal(&resealed(version)).map(|_| ()), Err(Corrupt));
        let mut magic = header().encode();
        magic[3] = b'X';
        assert_eq!(decode_journal(&resealed(magic)).map(|_| ()), Err(Corrupt));
        let mut largest = header();
        largest.selection = (1..=10_000).collect();
        let (decoded, _, _) = decode_journal(&largest.encode()).map_err(|_| "decode")?;
        assert_eq!(decoded.selection.len(), MAX_SELECTION);
        largest.selection = (1..=10_001).collect();
        assert_eq!(decode_journal(&largest.encode()).map(|_| ()), Err(Corrupt));
        let mut decreasing = header();
        decreasing.selection = vec![5, 1];
        assert_eq!(
            decode_journal(&decreasing.encode()).map(|_| ()),
            Err(Corrupt)
        );
        Ok(())
    }

    /// A tombstone list with an intact check value but a wrong magic,
    /// version, count, or order is damaged.
    #[test]
    fn tombstone_fields_are_checked_under_an_intact_check_value() {
        let raw = |magic: &[u8; 4], version: u16, count: u32, ids: &[([u8; 16], u64)]| {
            let mut out = magic.to_vec();
            out.extend_from_slice(&version.to_be_bytes());
            out.extend_from_slice(&count.to_be_bytes());
            for (id, until) in ids {
                out.extend_from_slice(id);
                out.extend_from_slice(&until.to_be_bytes());
            }
            let value = check(TOMBSTONE_DOMAIN, &out);
            out.extend_from_slice(&value);
            out
        };
        let list = [([1; 16], 5)];
        assert_eq!(raw(b"TDKT", 1, 1, &list), encode_tombstones(&list));
        assert_eq!(decode_tombstones(&raw(b"TDKX", 1, 1, &list)), Err(Corrupt));
        assert_eq!(decode_tombstones(&raw(b"TDKT", 2, 1, &list)), Err(Corrupt));
        assert_eq!(decode_tombstones(&raw(b"TDKT", 1, 2, &list)), Err(Corrupt));
        assert_eq!(
            decode_tombstones(&raw(b"TDKT", 1, 2, &[([1; 16], 5), ([1; 16], 6)])),
            Err(Corrupt)
        );
        let ids = |count: usize| -> Vec<([u8; 16], u64)> {
            (0..count)
                .map(|n| {
                    let mut id = [0; 16];
                    id[8..].copy_from_slice(&(n as u64).to_be_bytes());
                    (id, 1)
                })
                .collect()
        };
        let most = ids(MAX_TOMBSTONES);
        assert_eq!(
            decode_tombstones(&encode_tombstones(&most)).map(|list| list.len()),
            Ok(MAX_TOMBSTONES)
        );
        let over = ids(MAX_TOMBSTONES + 1);
        assert_eq!(decode_tombstones(&encode_tombstones(&over)), Err(Corrupt));
    }

    #[test]
    fn tombstones_round_trip() -> TestResult {
        let list = vec![([1; 16], 5), ([2; 16], u64::MAX)];
        let bytes = encode_tombstones(&list);
        assert_eq!(decode_tombstones(&bytes).map_err(|_| "decode")?, list);
        assert_eq!(decode_tombstones(&encode_tombstones(&[])), Ok(Vec::new()));
        for cut in 0..bytes.len() {
            assert!(decode_tombstones(&bytes[..cut]).is_err());
        }
        let unsorted = encode_tombstones(&[([2; 16], 1), ([1; 16], 1)]);
        assert!(decode_tombstones(&unsorted).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_tombstones(&trailing).is_err());
        Ok(())
    }

    #[test]
    fn debug_output_hides_names_and_secrets() {
        let rendered = format!(
            "{:?} {:?}",
            header(),
            JournalEntry::Published {
                id: 1,
                name: "private-file-name.txt".to_owned()
            }
        );
        assert!(!rendered.contains("private-file-name.txt"));
        assert!(!rendered.contains("4, 4, 4"));
    }
}
