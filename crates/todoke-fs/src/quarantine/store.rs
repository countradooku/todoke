//! The quarantine's files in the application's private state directory.
//! Every path here is built from fixed names and hexadecimal transfer
//! IDs, never from a peer-supplied name.
//!
//! ```text
//! <state>/lock                  held exclusively while a sink is open
//! <state>/tombstones            cancelled transfer IDs (atomic replace)
//! <state>/transfers/<id>/journal     header + appended entries
//! <state>/transfers/<id>/manifest    the canonical manifest bytes
//! <state>/transfers/<id>/k<file>     the file's master, sealed
//! <state>/transfers/<id>/s<file>     verified content ciphertext, one slot per segment
//! ```

use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

use todoke_crypto::content::{MAX_CIPHERTEXT_LEN, MIN_CIPHERTEXT_LEN, SEGMENT_LEN, SegmentLayout};

/// The largest file read whole from the state directory (a manifest is at
/// most 4 MiB; a journal of 10,000 files with long names stays far below).
const MAX_READ: u64 = 64 << 20;

/// Lowercase hexadecimal.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0xf)]));
    }
    out
}

/// Parses 32 lowercase hexadecimal digits.
pub(crate) fn unhex16(text: &str) -> Option<[u8; 16]> {
    let bytes = text.as_bytes();
    if bytes.len() != 32 {
        return None;
    }
    let digit = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    let mut out = [0; 16];
    let (pairs, _) = bytes.as_chunks::<2>();
    for (slot, pair) in out.iter_mut().zip(pairs) {
        *slot = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Some(out)
}

fn private_dir(path: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(path)
}

fn private_file(options: &mut OpenOptions) -> &mut OpenOptions {
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(options, 0o600);
    options
}

/// Makes a directory's entries durable where the platform can.
#[cfg_attr(
    windows,
    expect(
        clippy::unnecessary_wraps,
        reason = "fallible on Unix; Windows has no directory flush"
    )
)]
pub(crate) fn sync_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        match File::open(path).and_then(|dir| dir.sync_all()) {
            Ok(()) => Ok(()),
            // Some filesystems cannot sync a directory.
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
    #[cfg(windows)]
    {
        // NTFS journals metadata; the standard library has no directory
        // flush.
        let _ = path;
        Ok(())
    }
}

/// The private state directory, held exclusively.
pub(crate) struct StateDir {
    root: PathBuf,
    /// Holds the exclusive lock for the sink's lifetime.
    _lock: File,
}

/// Opening the state directory failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateError {
    /// Another sink (in this or another process) holds the directory.
    InUse,
    /// The directory could not be created or read.
    Io(io::ErrorKind),
}

impl StateDir {
    pub(crate) fn open(root: &Path) -> Result<Self, StateError> {
        let io = |error: io::Error| StateError::Io(error.kind());
        private_dir(&root.join("transfers")).map_err(io)?;
        let lock = private_file(OpenOptions::new().read(true).write(true).create(true))
            .truncate(false)
            .open(root.join("lock"))
            .map_err(io)?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Err(StateError::InUse),
            Err(std::fs::TryLockError::Error(error)) => return Err(io(error)),
        }
        Ok(Self {
            root: root.to_owned(),
            _lock: lock,
        })
    }

    pub(crate) fn tombstones(&self) -> PathBuf {
        self.root.join("tombstones")
    }

    pub(crate) fn transfers(&self) -> PathBuf {
        self.root.join("transfers")
    }

    pub(crate) fn transfer(&self, id: &[u8; 16]) -> PathBuf {
        self.transfers().join(hex(id))
    }
}

/// Creates a transfer's directory.
pub(crate) fn create_transfer_dir(path: &Path) -> io::Result<()> {
    private_dir(path)
}

/// Replaces `path` with `bytes` atomically: a temporary file, synced, then
/// renamed over it, then the directory synced.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temp = path.with_extension("tmp");
    let mut file =
        private_file(OpenOptions::new().write(true).create(true).truncate(true)).open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temp, path)?;
    match path.parent() {
        Some(parent) => sync_dir(parent),
        None => Ok(()),
    }
}

/// Appends `bytes` to `path` durably, after cutting it to `valid` bytes
/// (dropping a tail a crash tore).
pub(crate) fn append(path: &Path, valid: u64, bytes: &[u8]) -> io::Result<u64> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    file.set_len(valid)?;
    file.seek(SeekFrom::Start(valid))?;
    file.write_all(bytes)?;
    file.sync_data()?;
    Ok(valid + u64::try_from(bytes.len()).map_err(|_| io::ErrorKind::InvalidInput)?)
}

/// Reads a whole state file of at most 64 MiB.
pub(crate) fn read_bounded(path: &Path) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let len = file.metadata()?.len();
    if len > MAX_READ {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    file.take(MAX_READ).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Removes a file; a missing one is fine.
pub(crate) fn remove(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// Removes a directory tree; a missing one is fine. The tree is this
/// crate's own private state (no peer-chosen names), and the standard
/// library removes links rather than following them.
pub(crate) fn remove_tree(path: &Path) -> io::Result<()> {
    match std::fs::remove_dir_all(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// An upper bound on one segment's content ciphertext for a file of
/// `size` bytes: the Bao header, the segment's data, every parent node on
/// its path and inside its 16-chunk subtree, and the AEAD tag. A segment
/// covers at most 16 chunks of 1 KiB, so it holds at most 15 parents of
/// its own subtree plus one per level above it, and the tree is at most
/// `ceil(log2(chunks))` levels deep.
pub(crate) fn max_ciphertext_len(size: u64) -> usize {
    let chunks = size.div_ceil(1024).max(1);
    let depth = u64::from(64 - (chunks - 1).leading_zeros());
    let data = size.min(u64::from(SEGMENT_LEN));
    let bound = 8 + data + 64 * (15 + depth) + 16;
    usize::try_from(bound)
        .unwrap_or(MAX_CIPHERTEXT_LEN)
        .clamp(MIN_CIPHERTEXT_LEN, MAX_CIPHERTEXT_LEN)
}

/// A file's ciphertext slots: one fixed-size slot per segment, holding a
/// two-byte length and the ciphertext. An unwritten (zero) length means
/// the segment is absent.
pub(crate) struct Slots {
    file: File,
    stride: u64,
    count: u32,
}

impl Slots {
    pub(crate) fn open(path: &Path, layout: &SegmentLayout, create: bool) -> io::Result<Self> {
        let file = private_file(OpenOptions::new().read(true).write(true).create(create))
            .truncate(false)
            .open(path)?;
        let stride = u64::try_from(max_ciphertext_len(layout.size()) + 2)
            .map_err(|_| io::ErrorKind::InvalidInput)?;
        Ok(Self {
            file,
            stride,
            count: layout.count(),
        })
    }

    /// The bytes all slots take.
    pub(crate) fn reservation(layout: &SegmentLayout) -> u64 {
        (max_ciphertext_len(layout.size()) as u64 + 2).saturating_mul(u64::from(layout.count()))
    }

    fn offset(&self, index: u32) -> io::Result<u64> {
        if index >= self.count {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(u64::from(index) * self.stride)
    }

    pub(crate) fn write(&mut self, index: u32, ciphertext: &[u8]) -> io::Result<()> {
        let len = u16::try_from(ciphertext.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
        if u64::from(len) + 2 > self.stride || ciphertext.len() < MIN_CIPHERTEXT_LEN {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let offset = self.offset(index)?;
        let mut record = Vec::with_capacity(ciphertext.len() + 2);
        record.extend_from_slice(&len.to_be_bytes());
        record.extend_from_slice(ciphertext);
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(&record)
    }

    pub(crate) fn clear(&mut self, index: u32) -> io::Result<()> {
        let offset = self.offset(index)?;
        if offset >= self.file.metadata()?.len() {
            return Ok(());
        }
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(&[0, 0])
    }

    /// The stored ciphertext of segment `index`, if present.
    pub(crate) fn read(&mut self, index: u32) -> io::Result<Option<Vec<u8>>> {
        let offset = self.offset(index)?;
        if offset >= self.file.metadata()?.len() {
            return Ok(None);
        }
        self.file.seek(SeekFrom::Start(offset))?;
        let mut len = [0; 2];
        match self.file.read_exact(&mut len) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error),
        }
        let len = usize::from(u16::from_be_bytes(len));
        if len < MIN_CIPHERTEXT_LEN || (len as u64) + 2 > self.stride {
            // Never written (zero), or damaged: absent either way; the
            // engine fetches it again.
            return Ok(None);
        }
        let mut ciphertext = vec![0; len];
        match self.file.read_exact(&mut ciphertext) {
            Ok(()) => Ok(Some(ciphertext)),
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Hands the written slots to the storage device: `fdatasync` on Linux
    /// and Android, `FlushFileBuffers` on Windows, and `fsync` on Apple
    /// platforms. Apple's `fsync` does not flush the drive's own cache
    /// (`F_FULLFSYNC` does, at about 4 ms per call, which would cap
    /// reception near 4 MB/s); publication and every state record use the
    /// full flush.
    pub(crate) fn sync(&self) -> io::Result<()> {
        #[cfg(target_vendor = "apple")]
        {
            rustix::fs::fsync(&self.file).map_err(io::Error::from)
        }
        #[cfg(not(target_vendor = "apple"))]
        {
            self.file.sync_data()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{TempDir, TestResult};

    #[test]
    fn hex_round_trips() {
        let id = [
            0x01, 0xab, 0xff, 0, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 0xfe,
        ];
        assert_eq!(unhex16(&hex(&id)), Some(id));
        assert_eq!(unhex16("00"), None);
        assert_eq!(unhex16(&"G".repeat(32)), None);
        assert_eq!(unhex16(&"A".repeat(32)), None);
    }

    #[test]
    fn the_slot_bound_covers_real_slices() {
        // Real Bao slice lengths for every segment of files whose trees
        // have different shapes (checked against todoke_crypto's outboard
        // through the tracker-independent formula in the sink tests too).
        for size in [
            0_u64,
            1,
            1023,
            1024,
            1025,
            16_384,
            16_385,
            300_000,
            1 << 20,
            (1 << 20) + 1,
        ] {
            let bound = max_ciphertext_len(size);
            assert!(bound >= MIN_CIPHERTEXT_LEN);
            assert!(bound <= MAX_CIPHERTEXT_LEN);
        }
        // 1 TiB: 30 levels.
        assert_eq!(max_ciphertext_len(1 << 40), 8 + 16_384 + 64 * 45 + 16);
        assert_eq!(
            max_ciphertext_len(0),
            MIN_CIPHERTEXT_LEN.max(8 + 64 * 15 + 16)
        );
    }

    /// Slot indices stop at the segment count, and slot records at the
    /// stride and the shortest ciphertext, so no write lands outside the
    /// space the quota reserved.
    #[test]
    fn slots_refuse_indices_and_lengths_outside_their_bounds() -> TestResult {
        let temp = TempDir::new()?;
        let path = temp.path().join("s1");
        let size = 3 * u64::from(SEGMENT_LEN) + 5;
        let layout = SegmentLayout::new(size)?;
        assert_eq!(layout.count(), 4);
        let mut slots = Slots::open(&path, &layout, true)?;
        let stride = max_ciphertext_len(size);
        let longest = vec![7; stride];
        slots.write(3, &longest)?;
        assert_eq!(slots.read(3)?, Some(longest.clone()));
        let invalid = |result: io::Result<()>| {
            result.is_err_and(|error| error.kind() == io::ErrorKind::InvalidInput)
        };
        assert!(invalid(slots.write(4, &longest)));
        assert!(slots.read(4).is_err());
        assert!(invalid(slots.clear(4)));
        assert!(invalid(slots.write(0, &vec![7; stride + 1])));
        assert!(invalid(slots.write(0, &[7; MIN_CIPHERTEXT_LEN - 1])));
        slots.write(0, &[9; MIN_CIPHERTEXT_LEN])?;
        assert_eq!(slots.read(0)?, Some(vec![9; MIN_CIPHERTEXT_LEN]));
        // Nothing was written past the last slot.
        let expected = 3 * (stride as u64 + 2) + 2 + stride as u64;
        assert_eq!(std::fs::metadata(&path)?.len(), expected);
        assert_eq!(Slots::reservation(&layout), 4 * (stride as u64 + 2));
        Ok(())
    }

    /// A slot whose stored length is zero, too short, too long, or longer
    /// than the file reads as absent; clearing past the end of the file
    /// writes nothing.
    #[test]
    fn damaged_slots_read_as_absent() -> TestResult {
        let temp = TempDir::new()?;
        let path = temp.path().join("s1");
        let size = 2 * u64::from(SEGMENT_LEN);
        let layout = SegmentLayout::new(size)?;
        let stride = max_ciphertext_len(size);
        let mut slots = Slots::open(&path, &layout, true)?;
        assert_eq!(slots.read(1)?, None);
        slots.clear(1)?;
        assert_eq!(std::fs::metadata(&path)?.len(), 0);
        slots.write(0, &[1; MIN_CIPHERTEXT_LEN])?;
        let lengths = [0, MIN_CIPHERTEXT_LEN - 1, stride + 1, u16::MAX.into()];
        for len in lengths {
            let mut bytes = std::fs::read(&path)?;
            let len = u16::try_from(len)?;
            bytes[..2].copy_from_slice(&len.to_be_bytes());
            std::fs::write(&path, &bytes)?;
            assert_eq!(slots.read(0)?, None, "{len}");
        }
        // A length the file cannot hold: a torn write.
        let mut bytes = (u16::try_from(stride)?).to_be_bytes().to_vec();
        bytes.extend_from_slice(&[1; 10]);
        std::fs::write(&path, &bytes)?;
        assert_eq!(slots.read(0)?, None);
        // A length cut in half.
        std::fs::write(&path, [0])?;
        assert_eq!(slots.read(0)?, None);
        slots.clear(0)?;
        assert_eq!(slots.read(0)?, None);
        Ok(())
    }

    /// State records over 64 MiB are refused as damaged without being
    /// read; up to it they are read whole.
    #[test]
    fn oversized_records_are_refused_unread() -> TestResult {
        let temp = TempDir::new()?;
        let path = temp.path().join("journal");
        let file = File::create(&path)?;
        file.set_len(MAX_READ + 1)?;
        assert_eq!(
            read_bounded(&path).map_err(|error| error.kind()),
            Err(io::ErrorKind::InvalidData)
        );
        file.set_len(MAX_READ)?;
        assert_eq!(read_bounded(&path)?.len(), 64 << 20);
        assert_eq!(
            read_bounded(&temp.path().join("missing")).map_err(|error| error.kind()),
            Err(io::ErrorKind::NotFound)
        );
        Ok(())
    }

    /// Appends first cut a torn tail; atomic writes leave no temporary.
    #[test]
    fn appends_cut_the_torn_tail_first() -> TestResult {
        let temp = TempDir::new()?;
        let path = temp.path().join("journal");
        write_atomic(&path, b"abcdef")?;
        assert_eq!(append(&path, 3, b"XY")?, 5);
        assert_eq!(std::fs::read(&path)?, b"abcXY");
        write_atomic(&path, b"new")?;
        assert_eq!(std::fs::read(&path)?, b"new");
        assert!(!temp.path().join("journal.tmp").exists());
        Ok(())
    }

    /// Removing a missing file or tree is fine; any other failure is
    /// reported.
    #[test]
    fn removal_reports_failures_other_than_absence() -> TestResult {
        let temp = TempDir::new()?;
        remove(&temp.path().join("missing"))?;
        remove_tree(&temp.path().join("missing"))?;
        std::fs::create_dir(temp.path().join("dir"))?;
        assert!(remove(&temp.path().join("dir")).is_err());
        std::fs::write(temp.path().join("file"), b"x")?;
        assert!(remove_tree(&temp.path().join("file")).is_err());
        assert!(temp.path().join("file").exists());
        Ok(())
    }

    /// The quarantine is private: directories `0700`, files `0600`.
    #[cfg(unix)]
    #[test]
    fn state_files_are_private() -> TestResult {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = TempDir::new()?;
        let state = StateDir::open(temp.path()).map_err(|error| format!("{error:?}"))?;
        let transfer = state.transfer(&[1; 16]);
        create_transfer_dir(&transfer)?;
        write_atomic(&transfer.join("journal"), b"x")?;
        let layout = SegmentLayout::new(1)?;
        Slots::open(&transfer.join("s1"), &layout, true)?;
        for (path, mode) in [
            (state.transfers(), 0o700),
            (transfer.clone(), 0o700),
            (temp.path().join("lock"), 0o600),
            (transfer.join("journal"), 0o600),
            (transfer.join("s1"), 0o600),
        ] {
            let actual = std::fs::metadata(&path)?.permissions().mode() & 0o777;
            assert_eq!(actual & 0o077, 0, "{actual:o}");
            assert_eq!(actual & !mode, 0, "{actual:o}");
        }
        Ok(())
    }
}
