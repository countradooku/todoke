//! The sender's record of which segments it sealed and queued in this
//! session, for progress and `FileCompleted` (§7.4, §7.5).
//!
//! Each segment counts once however often the receiver requests it, and
//! only segments actually sent count: a receiver's `ResumeStatus` is a
//! claim, not proof (§7.5), so it never marks a file as sent.
//!
//! Per file the record is a list of disjoint, nonadjacent index ranges;
//! a fully sent file keeps no ranges. A receiver chooses which segments it
//! requests, so the ranges of one transfer are capped at
//! [`MAX_SERVED_RANGES`]: a segment that would need a range beyond the cap
//! is still sent but not counted, so progress can only undercount.

use std::collections::BTreeMap;

/// Ranges one outgoing transfer may keep: 16384 (128 KiB). An honest
/// receiver requests the lowest missing segments of at most two active
/// files (§7.4, §13), which needs a handful of ranges; after a resume, the
/// gaps between its retained segments, which its segment tracker caps at
/// 4096 ranges per file, so two such files need at most 8194.
pub(super) const MAX_SERVED_RANGES: usize = 16_384;

enum File {
    /// Sent ranges `[start, end)`, sorted, disjoint, and nonadjacent.
    Partial(Vec<(u32, u32)>),
    /// Every segment was sent.
    Complete,
}

/// What recording one sent segment changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Recorded {
    /// The segment counts now; the file is not complete yet.
    New,
    /// The segment counts now and completes the file.
    Completed,
    /// Already counted, or not countable within the cap: nothing changes.
    Unchanged,
}

/// The segments of one outgoing transfer sent in this session.
#[derive(Default)]
pub(super) struct Served {
    files: BTreeMap<u32, File>,
    /// Ranges held by partial files.
    ranges: usize,
}

impl Served {
    /// Records that segment `index` of file `file_id` (of `count`
    /// segments) was sealed and queued.
    pub(super) fn record(&mut self, file_id: u32, index: u32, count: u32) -> Recorded {
        if index >= count {
            return Recorded::Unchanged;
        }
        let file = self
            .files
            .entry(file_id)
            .or_insert_with(|| File::Partial(Vec::new()));
        let File::Partial(ranges) = file else {
            return Recorded::Unchanged;
        };
        // The first range that ends at or after `index`.
        let at = ranges.partition_point(|&(_, end)| end < index);
        let next = index + 1;
        match ranges.get(at).copied() {
            Some((start, end)) if start <= index && index < end => return Recorded::Unchanged,
            Some((start, end)) if end == index => {
                // Extends the range on the left; may join the next one.
                let merged = match ranges.get(at + 1).copied() {
                    Some((following, last)) if following == next => {
                        ranges.remove(at + 1);
                        self.ranges -= 1;
                        last
                    }
                    _ => next,
                };
                if let Some(range) = ranges.get_mut(at) {
                    *range = (start, merged);
                }
            }
            Some((start, end)) if start == next => {
                if let Some(range) = ranges.get_mut(at) {
                    *range = (index, end);
                }
            }
            _ => {
                if self.ranges >= MAX_SERVED_RANGES {
                    return Recorded::Unchanged;
                }
                ranges.insert(at, (index, next));
                self.ranges += 1;
            }
        }
        if ranges.as_slice() == [(0, count)] {
            self.ranges -= 1;
            *file = File::Complete;
            Recorded::Completed
        } else {
            Recorded::New
        }
    }

    /// Files every segment of which was sent.
    pub(super) fn files_complete(&self) -> u32 {
        let complete = self
            .files
            .values()
            .filter(|file| matches!(file, File::Complete))
            .count();
        u32::try_from(complete).unwrap_or(u32::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_SERVED_RANGES, Recorded, Served};

    #[test]
    fn segments_count_once_and_complete_files() {
        let mut served = Served::default();
        assert_eq!(served.record(1, 0, 3), Recorded::New);
        assert_eq!(served.record(1, 0, 3), Recorded::Unchanged);
        assert_eq!(served.record(1, 2, 3), Recorded::New);
        assert_eq!(served.record(1, 2, 3), Recorded::Unchanged);
        assert_eq!(served.files_complete(), 0);
        // Joins both neighbours.
        assert_eq!(served.record(1, 1, 3), Recorded::Completed);
        assert_eq!(served.record(1, 1, 3), Recorded::Unchanged);
        assert_eq!(served.files_complete(), 1);
        assert_eq!(served.ranges, 0);
        // Out of range never counts; an empty file has one segment.
        assert_eq!(served.record(2, 1, 1), Recorded::Unchanged);
        assert_eq!(served.record(2, 0, 1), Recorded::Completed);
        assert_eq!(served.files_complete(), 2);
    }

    #[test]
    fn any_order_completes_exactly_once() {
        for order in [
            [3, 1, 0, 2, 4],
            [4, 3, 2, 1, 0],
            [0, 4, 2, 1, 3],
            [2, 0, 4, 3, 1],
        ] {
            let mut served = Served::default();
            let mut completed = 0;
            for _ in 0..2 {
                for index in order {
                    if served.record(7, index, 5) == Recorded::Completed {
                        completed += 1;
                    }
                }
            }
            assert_eq!(completed, 1, "{order:?}");
            assert_eq!(served.ranges, 0);
        }
    }

    #[test]
    fn ranges_are_capped_per_transfer() {
        let mut served = Served::default();
        let count = u32::try_from(MAX_SERVED_RANGES * 2 + 2).unwrap_or(u32::MAX);
        // Every other segment: one range each, up to the cap.
        let mut new = 0;
        for index in (0..count).step_by(2) {
            if served.record(1, index, count) == Recorded::New {
                new += 1;
            }
        }
        assert_eq!(new, MAX_SERVED_RANGES);
        assert_eq!(served.ranges, MAX_SERVED_RANGES);
        // A segment that extends an existing range still counts.
        assert_eq!(served.record(1, 1, count), Recorded::New);
        assert_eq!(served.ranges, MAX_SERVED_RANGES - 1);
    }
}
