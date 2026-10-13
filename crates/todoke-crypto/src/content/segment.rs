//! Segment arithmetic (§7.4, §8).

use super::ContentError;

/// Logical plaintext bytes per segment; the last segment may be shorter
/// (§7.4).
pub const SEGMENT_LEN: u32 = 16_384;
/// The largest file: 1 TiB (§6, §13).
pub const MAX_FILE_SIZE: u64 = 1 << 40;
/// Segments in a 1 TiB file (§7.4).
pub const MAX_SEGMENT_COUNT: u32 = 67_108_864;
/// Segments per content epoch, each a separate STREAM instance (§8).
pub const EPOCH_SEGMENTS: u32 = 65_536;
/// The largest Bao slice, the content plaintext (§7.4, §13).
pub const MAX_SLICE_LEN: usize = 32_768;
/// The AEAD tag length for both suites (§8).
pub const TAG_LEN: usize = 16;
/// The smallest content ciphertext: the empty file's eight-byte slice plus
/// the tag (§7.4).
pub const MIN_CIPHERTEXT_LEN: usize = BAO_HEADER_LEN + TAG_LEN;
/// The largest content ciphertext (§7.4, §13).
pub const MAX_CIPHERTEXT_LEN: usize = MAX_SLICE_LEN + TAG_LEN;

/// The Bao length header: a little-endian u64 (§7.4).
pub(crate) const BAO_HEADER_LEN: usize = 8;

const SEGMENT_LEN_U64: u64 = SEGMENT_LEN as u64;

/// A file's segmentation: `ceil(size / 16384)` segments, or exactly one
/// empty segment for an empty file (§7.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SegmentLayout {
    size: u64,
    count: u32,
}

impl SegmentLayout {
    /// The layout of a `size`-byte file.
    ///
    /// # Errors
    ///
    /// [`ContentError::InvalidFile`] above 1 TiB.
    pub fn new(size: u64) -> Result<Self, ContentError> {
        if size > MAX_FILE_SIZE {
            return Err(ContentError::InvalidFile);
        }
        let count = if size == 0 {
            1
        } else {
            size.div_ceil(SEGMENT_LEN_U64)
        };
        let count = u32::try_from(count).map_err(|_| ContentError::InvalidFile)?;
        Ok(Self { size, count })
    }

    /// The file size in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// The number of segments, at least 1.
    #[must_use]
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Segment `index`, with checked range arithmetic.
    ///
    /// # Errors
    ///
    /// [`ContentError::SegmentOutOfRange`] unless `index < count()`.
    pub fn segment(&self, index: u32) -> Result<Segment, ContentError> {
        if index >= self.count {
            return Err(ContentError::SegmentOutOfRange);
        }
        let start = u64::from(index)
            .checked_mul(SEGMENT_LEN_U64)
            .ok_or(ContentError::SegmentOutOfRange)?;
        let remaining = self
            .size
            .checked_sub(start)
            .ok_or(ContentError::SegmentOutOfRange)?;
        let len = u32::try_from(remaining.min(SEGMENT_LEN_U64))
            .map_err(|_| ContentError::SegmentOutOfRange)?;
        let last = index == self.count - 1;
        Ok(Segment {
            index,
            start,
            len,
            is_final: last || index % EPOCH_SEGMENTS == EPOCH_SEGMENTS - 1,
        })
    }
}

/// One segment of a file: its byte range, epoch, and STREAM position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Segment {
    index: u32,
    start: u64,
    len: u32,
    is_final: bool,
}

impl Segment {
    /// The global segment index.
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// The first logical byte: `index × 16384`.
    #[must_use]
    pub const fn start(&self) -> u64 {
        self.start
    }

    /// The logical length: `min(16384, size − start)`; zero only for the
    /// empty file.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.len
    }

    /// Whether the segment carries no logical bytes (the empty file's only
    /// segment).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// `content_epoch = floor(index / 65536)` (§8).
    #[must_use]
    pub const fn epoch(&self) -> u32 {
        self.index / EPOCH_SEGMENTS
    }

    /// `local_index = index mod 65536`, the STREAM counter (§8).
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the remainder is below 65536"
    )]
    pub const fn local_index(&self) -> u16 {
        (self.index % EPOCH_SEGMENTS) as u16
    }

    /// The STREAM final flag: the file's last segment, or the last segment
    /// of an epoch (§8). No synthetic terminator follows an exact epoch
    /// boundary.
    #[must_use]
    pub const fn is_final(&self) -> bool {
        self.is_final
    }

    /// The same segment with the final flag forced, to build forgeries.
    #[cfg(test)]
    pub(crate) const fn with_final(mut self, is_final: bool) -> Self {
        self.is_final = is_final;
        self
    }
}
