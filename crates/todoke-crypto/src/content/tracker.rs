//! The receiver's record of verified, stored segments, for requesting only
//! what is missing and answering resume queries (§7.4, §7.5).

use core::fmt;
use std::collections::BTreeMap;

use super::{FileBinding, VerifiedSegment};

/// The most disjoint verified ranges one tracker holds. §7.5 forbids an
/// unbounded full bitmap per file; ranges are 8 bytes of payload each, so
/// this caps a tracker near 100 KiB including map overhead. A receiver
/// that requests the lowest missing segments first keeps at most about as
/// many ranges as it has requests outstanding (at most 16, §7.4).
pub const MAX_TRACKED_RANGES: usize = 4096;
/// The most ranges in one `ResumeStatus` page (§7.5).
pub const MAX_RESUME_RANGES: usize = 1024;

/// Why a tracker refused an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrackerError {
    /// The segment belongs to another transfer or file (§7.5: progress is
    /// never transferred between them).
    ForeignSegment,
    /// Recording the segment would exceed [`MAX_TRACKED_RANGES`]. The
    /// segment stays missing and is requested again later.
    TooFragmented,
    /// A resume page was asked to start past the last segment.
    FromIndexOutOfRange,
}

impl fmt::Display for TrackerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ForeignSegment => "segment belongs to another transfer or file",
            Self::TooFragmented => "too many disjoint verified ranges",
            Self::FromIndexOutOfRange => "resume page starts past the last segment",
        })
    }
}

impl std::error::Error for TrackerError {}

/// Which segments of one file are verified and durably stored, as sorted,
/// disjoint, nonadjacent ranges.
///
/// It can only learn about a segment from a [`VerifiedSegment`] of the same
/// transfer and file, so neither peer claims nor disk metadata can mark a
/// segment present. After a restart, rebuild it by reopening each stored
/// ciphertext (or re-verifying each stored slice) and recording the result
/// (§7.5: revalidate before advertising). Record a segment only after it
/// has been durably stored.
#[derive(Clone, PartialEq, Eq)]
pub struct SegmentTracker {
    transfer_id: [u8; 16],
    file_id: u32,
    count: u32,
    /// Range start → end (exclusive).
    ranges: BTreeMap<u32, u32>,
    verified: u32,
}

impl SegmentTracker {
    /// An empty tracker for `binding`'s file: every segment is missing.
    #[must_use]
    pub fn new(binding: &FileBinding) -> Self {
        Self {
            transfer_id: *binding.transfer_id(),
            file_id: binding.file_id(),
            count: binding.layout().count(),
            ranges: BTreeMap::new(),
            verified: 0,
        }
    }

    /// Records a verified, stored segment. Returns whether it was new.
    ///
    /// # Errors
    ///
    /// [`TrackerError::ForeignSegment`] for another transfer or file;
    /// [`TrackerError::TooFragmented`] if it would start a new range past
    /// the cap.
    pub fn record(&mut self, segment: &VerifiedSegment) -> Result<bool, TrackerError> {
        if segment.transfer_id() != &self.transfer_id || segment.file_id() != self.file_id {
            return Err(TrackerError::ForeignSegment);
        }
        let index = segment.segment().index();
        if index >= self.count {
            return Err(TrackerError::ForeignSegment);
        }
        let before = self
            .ranges
            .range(..=index)
            .next_back()
            .map(|(&start, &end)| (start, end));
        if before.is_some_and(|(_, end)| index < end) {
            return Ok(false);
        }
        let joins_before = before.filter(|&(_, end)| end == index);
        let after = index
            .checked_add(1)
            .and_then(|next| self.ranges.get(&next).map(|&end| (next, end)));
        match (joins_before, after) {
            (Some((start, _)), Some((next, end))) => {
                self.ranges.remove(&next);
                self.ranges.insert(start, end);
            }
            (Some((start, _)), None) => {
                self.ranges.insert(start, index + 1);
            }
            (None, Some((next, end))) => {
                self.ranges.remove(&next);
                self.ranges.insert(index, end);
            }
            (None, None) => {
                if self.ranges.len() >= MAX_TRACKED_RANGES {
                    return Err(TrackerError::TooFragmented);
                }
                self.ranges.insert(index, index + 1);
            }
        }
        self.verified += 1;
        Ok(true)
    }

    /// Whether segment `index` is recorded.
    #[must_use]
    pub fn contains(&self, index: u32) -> bool {
        self.ranges
            .range(..=index)
            .next_back()
            .is_some_and(|(_, &end)| index < end)
    }

    /// The file's segment count.
    #[must_use]
    pub const fn segment_count(&self) -> u32 {
        self.count
    }

    /// How many segments are recorded.
    #[must_use]
    pub const fn verified_count(&self) -> u32 {
        self.verified
    }

    /// How many disjoint ranges are held.
    #[must_use]
    pub fn range_count(&self) -> usize {
        self.ranges.len()
    }

    /// Whether every segment is recorded. The receiver still checks the
    /// whole-file length and BLAKE3 hash before publication (§7.7).
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.verified == self.count
    }

    /// The missing segments in ascending order: what to request next.
    #[must_use]
    pub fn missing(&self) -> MissingSegments<'_> {
        self.missing_from(0)
    }

    /// The missing segments at or after `from`, ascending.
    #[must_use]
    pub fn missing_from(&self, from: u32) -> MissingSegments<'_> {
        MissingSegments {
            tracker: self,
            next: from,
        }
    }

    /// The recorded segments as `(start, count)` ranges, ascending, disjoint,
    /// and nonadjacent.
    pub fn verified_ranges(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        self.ranges
            .iter()
            .map(|(&start, &end)| (start, end - start))
    }

    /// One `ResumeStatus` page starting at `from_index` (§7.5): up to
    /// [`MAX_RESUME_RANGES`] ranges of recorded segments, each within
    /// `[from_index, next_index)`, sorted, disjoint, and nonadjacent;
    /// `next_index > from_index`, or both equal the segment count for the
    /// empty final page. A range straddling `from_index` is clipped to it.
    ///
    /// # Errors
    ///
    /// [`TrackerError::FromIndexOutOfRange`] if `from_index` exceeds the
    /// segment count.
    pub fn resume_page(&self, from_index: u32) -> Result<ResumePage, TrackerError> {
        if from_index > self.count {
            return Err(TrackerError::FromIndexOutOfRange);
        }
        let mut ranges = Vec::new();
        let mut next_index = self.count;
        let straddling = self
            .ranges
            .range(..from_index)
            .next_back()
            .filter(|&(_, &end)| end > from_index)
            .map(|(_, &end)| (from_index, end));
        let later = self
            .ranges
            .range(from_index..)
            .map(|(&start, &end)| (start, end));
        for (start, end) in straddling.into_iter().chain(later) {
            if ranges.len() == MAX_RESUME_RANGES {
                // The previous range ended before this one starts, so the
                // page boundary falls in a gap.
                next_index = ranges
                    .last()
                    .map_or(self.count, |&(start, count): &(u32, u32)| start + count);
                break;
            }
            ranges.push((start, end - start));
        }
        Ok(ResumePage {
            from_index,
            next_index,
            ranges,
        })
    }
}

impl fmt::Debug for SegmentTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SegmentTracker")
            .field("file_id", &self.file_id)
            .field("segment_count", &self.count)
            .field("verified", &self.verified)
            .field("ranges", &self.ranges.len())
            .finish_non_exhaustive()
    }
}

/// Missing segment indices in ascending order; see
/// [`SegmentTracker::missing`].
#[derive(Clone, Debug)]
pub struct MissingSegments<'a> {
    tracker: &'a SegmentTracker,
    next: u32,
}

impl Iterator for MissingSegments<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        while self.next < self.tracker.count {
            let covering = self
                .tracker
                .ranges
                .range(..=self.next)
                .next_back()
                .map(|(_, &end)| end)
                .filter(|&end| self.next < end);
            if let Some(end) = covering {
                self.next = end;
            } else {
                let index = self.next;
                self.next += 1;
                return Some(index);
            }
        }
        None
    }
}

/// One page of verified ranges for `ResumeStatus` (§7.5). Encoding it on
/// the wire is the transfer layer's job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumePage {
    from_index: u32,
    next_index: u32,
    ranges: Vec<(u32, u32)>,
}

impl ResumePage {
    /// The query's `from_index`, echoed.
    #[must_use]
    pub const fn from_index(&self) -> u32 {
        self.from_index
    }

    /// Where the next page starts; the segment count ends pagination.
    #[must_use]
    pub const fn next_index(&self) -> u32 {
        self.next_index
    }

    /// `(start, count)` ranges of verified segments in this page.
    #[must_use]
    pub fn ranges(&self) -> &[(u32, u32)] {
        &self.ranges
    }
}
