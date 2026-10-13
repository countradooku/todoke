//! The receiver's segment tracker: boundaries, and a proptest state
//! machine against a set model.

use std::collections::BTreeSet;

use proptest::prelude::*;

use super::{AnyResult, MANIFEST_HASH, TRANSFER_ID, TestResult};
use crate::content::{
    ContentSuite, FileBinding, MAX_RESUME_RANGES, MAX_TRACKED_RANGES, ResumePage, SEGMENT_LEN,
    SegmentTracker, TrackerError, VerifiedSegment,
};

fn binding(segments: u32, file_id: u32) -> AnyResult<FileBinding> {
    let size = u64::from(segments) * u64::from(SEGMENT_LEN);
    Ok(FileBinding::new(
        TRANSFER_ID,
        MANIFEST_HASH,
        file_id,
        ContentSuite::XChaCha20Poly1305Stream,
        size,
        [0; 32],
    )?)
}

fn record(
    tracker: &mut SegmentTracker,
    binding: &FileBinding,
    index: u32,
) -> AnyResult<Result<bool, TrackerError>> {
    Ok(tracker.record(&VerifiedSegment::for_tests(binding, index)?))
}

/// Checks every §7.5 rule for one page against the model.
fn check_page(
    page: &ResumePage,
    from: u32,
    count: u32,
    model: &BTreeSet<u32>,
) -> Result<(), TestCaseError> {
    prop_assert_eq!(page.from_index(), from);
    let next = page.next_index();
    prop_assert!(next > from || (next == count && from == count));
    prop_assert!(next <= count);
    prop_assert!(page.ranges().len() <= MAX_RESUME_RANGES);
    let mut previous_end: Option<u32> = None;
    let mut covered = BTreeSet::new();
    for &(start, len) in page.ranges() {
        prop_assert!(len >= 1);
        prop_assert!(start >= from);
        let end = start
            .checked_add(len)
            .ok_or_else(|| TestCaseError::fail("overflow"))?;
        prop_assert!(end <= next);
        if let Some(previous) = previous_end {
            // Sorted, disjoint, and nonadjacent.
            prop_assert!(start > previous);
        }
        previous_end = Some(end);
        covered.extend(start..end);
    }
    let expected: BTreeSet<u32> = model.range(from..next).copied().collect();
    prop_assert_eq!(covered, expected);
    Ok(())
}

#[test]
fn records_merge_into_ranges() -> TestResult {
    let file = binding(10, 1)?;
    let mut tracker = SegmentTracker::new(&file);
    assert_eq!(tracker.segment_count(), 10);
    assert_eq!(
        tracker.missing().collect::<Vec<_>>(),
        (0..10).collect::<Vec<_>>()
    );
    for index in [3, 5, 4, 9, 0] {
        assert_eq!(record(&mut tracker, &file, index)?, Ok(true));
    }
    assert_eq!(record(&mut tracker, &file, 4)?, Ok(false));
    assert_eq!(tracker.verified_count(), 5);
    assert_eq!(
        tracker.verified_ranges().collect::<Vec<_>>(),
        [(0, 1), (3, 3), (9, 1)]
    );
    assert_eq!(tracker.missing().collect::<Vec<_>>(), [1, 2, 6, 7, 8]);
    assert_eq!(tracker.missing_from(4).collect::<Vec<_>>(), [6, 7, 8]);
    assert_eq!(tracker.missing_from(10).count(), 0);
    let page = tracker.resume_page(4)?;
    assert_eq!((page.from_index(), page.next_index()), (4, 10));
    assert_eq!(page.ranges(), [(4, 2), (9, 1)]);
    for index in [1, 2, 6, 7, 8] {
        assert_eq!(record(&mut tracker, &file, index)?, Ok(true));
    }
    assert!(tracker.is_complete());
    assert_eq!(tracker.verified_ranges().collect::<Vec<_>>(), [(0, 10)]);
    assert_eq!(tracker.range_count(), 1);
    let last = tracker.resume_page(10)?;
    assert_eq!((last.next_index(), last.ranges()), (10, &[][..]));
    assert_eq!(
        tracker.resume_page(11).err(),
        Some(TrackerError::FromIndexOutOfRange)
    );
    Ok(())
}

/// Progress from another transfer or file is never accepted (§7.5).
#[test]
fn foreign_segments_are_refused() -> TestResult {
    let file = binding(4, 1)?;
    let mut tracker = SegmentTracker::new(&file);
    let other_file = binding(4, 2)?;
    let other_transfer = FileBinding::new(
        [0xb4; 16],
        MANIFEST_HASH,
        1,
        ContentSuite::XChaCha20Poly1305Stream,
        4 * u64::from(SEGMENT_LEN),
        [0; 32],
    )?;
    assert_eq!(
        record(&mut tracker, &other_file, 0)?,
        Err(TrackerError::ForeignSegment)
    );
    assert_eq!(
        record(&mut tracker, &other_transfer, 0)?,
        Err(TrackerError::ForeignSegment)
    );
    // A longer file with the same IDs (a different manifest) cannot add an
    // index past this file's end.
    assert_eq!(
        record(&mut tracker, &binding(8, 1)?, 6)?,
        Err(TrackerError::ForeignSegment)
    );
    assert_eq!(tracker.verified_count(), 0);
    Ok(())
}

/// Range cap and resume pagination at their limits.
#[test]
fn fragmentation_cap_and_page_limit() -> TestResult {
    let segments = 2 * u32::try_from(MAX_TRACKED_RANGES)? + 10;
    let file = binding(segments, 1)?;
    let mut tracker = SegmentTracker::new(&file);
    let mut model = BTreeSet::new();
    for index in (0..segments).step_by(2) {
        let result = record(&mut tracker, &file, index)?;
        if model.len() < MAX_TRACKED_RANGES {
            assert_eq!(result, Ok(true));
            model.insert(index);
        } else {
            assert_eq!(result, Err(TrackerError::TooFragmented));
        }
    }
    assert_eq!(tracker.range_count(), MAX_TRACKED_RANGES);
    // Filling gaps still works at the cap.
    assert_eq!(record(&mut tracker, &file, 1)?, Ok(true));
    model.insert(1);
    // Pages hold at most 1024 ranges and together cover exactly the model.
    let mut from = 0;
    let mut pages = 0;
    let mut covered = BTreeSet::new();
    loop {
        let page = tracker.resume_page(from)?;
        check_page(&page, from, segments, &model).map_err(|e| e.to_string())?;
        for &(start, len) in page.ranges() {
            covered.extend(start..start + len);
        }
        pages += 1;
        if page.next_index() == segments {
            break;
        }
        assert_eq!(page.ranges().len(), MAX_RESUME_RANGES);
        from = page.next_index();
    }
    assert_eq!(covered, model);
    assert_eq!(pages, MAX_TRACKED_RANGES.div_ceil(MAX_RESUME_RANGES));
    // A page starting inside a range clips it.
    let clipped = tracker.resume_page(1)?;
    assert_eq!(clipped.ranges().first(), Some(&(1, 2)));
    Ok(())
}

/// `can_record` answers before the caller stores anything, so a verified
/// segment is never durably stored and then refused as too fragmented; and
/// `record` agrees with it at the cap.
#[test]
fn can_record_predicts_the_cap_before_storage() -> TestResult {
    let segments = 2 * u32::try_from(MAX_TRACKED_RANGES)? + 10;
    let file = binding(segments, 1)?;
    let mut tracker = SegmentTracker::new(&file);
    // One range short of the cap: even indices 0, 2, .., 2 * (cap - 2).
    let below = u32::try_from(MAX_TRACKED_RANGES - 1)?;
    for index in (0..below).map(|i| 2 * i) {
        assert_eq!(tracker.can_record(index), Ok(true));
        assert_eq!(record(&mut tracker, &file, index)?, Ok(true));
    }
    assert_eq!(tracker.range_count(), MAX_TRACKED_RANGES - 1);
    // The last new range still fits.
    let last = 2 * below;
    assert_eq!(tracker.can_record(last), Ok(true));
    assert_eq!(record(&mut tracker, &file, last)?, Ok(true));
    assert_eq!(tracker.range_count(), MAX_TRACKED_RANGES);
    // At the cap: a new isolated range is refused before storage, and
    // record agrees without changing anything.
    let isolated = last + 2;
    assert_eq!(
        tracker.can_record(isolated),
        Err(TrackerError::TooFragmented)
    );
    let before = tracker.clone();
    assert_eq!(
        record(&mut tracker, &file, isolated)?,
        Err(TrackerError::TooFragmented)
    );
    assert_eq!(tracker, before);
    // Extending a range (after it, or before the next one) and filling a
    // gap still fit; a recorded segment is not new; a past-the-end index
    // is not this file's.
    assert_eq!(tracker.can_record(last + 1), Ok(true));
    assert_eq!(tracker.can_record(1), Ok(true));
    assert_eq!(tracker.can_record(0), Ok(false));
    assert_eq!(
        tracker.can_record(segments),
        Err(TrackerError::ForeignSegment)
    );
    assert_eq!(record(&mut tracker, &file, 1)?, Ok(true));
    assert_eq!(tracker.range_count(), MAX_TRACKED_RANGES - 1);
    // Merging two ranges freed one slot.
    assert_eq!(tracker.can_record(isolated), Ok(true));
    Ok(())
}

/// Errors have distinct messages, and `Debug` shows counts only: no
/// transfer ID and no segment indices.
#[test]
fn errors_and_debug_output() -> TestResult {
    let messages: BTreeSet<String> = [
        TrackerError::ForeignSegment,
        TrackerError::TooFragmented,
        TrackerError::FromIndexOutOfRange,
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    assert_eq!(messages.len(), 3);
    assert!(messages.iter().all(|message| !message.is_empty()));
    let file = binding(1000, 7)?;
    let mut tracker = SegmentTracker::new(&file);
    for index in [612, 613, 900] {
        assert_eq!(record(&mut tracker, &file, index)?, Ok(true));
    }
    let debug = format!("{tracker:?}");
    for expected in [
        "file_id: 7",
        "segment_count: 1000",
        "verified: 3",
        "ranges: 2",
    ] {
        assert!(debug.contains(expected), "{debug}");
    }
    // TRANSFER_ID is 0xa3 = 163 repeated; the indices are not shown.
    for hidden in ["163", "a3", "612", "900"] {
        assert!(!debug.contains(hidden), "{debug}");
    }
    Ok(())
}

#[derive(Clone, Debug)]
enum Op {
    Record(u32),
    RecordForeign(u32),
    Missing(u32, usize),
    Page(u32),
    Contains(u32),
}

fn op(count: u32) -> impl Strategy<Value = Op> {
    prop_oneof![
        8 => (0..count).prop_map(Op::Record),
        1 => (0..count).prop_map(Op::RecordForeign),
        2 => (0..=count, 0..40_usize).prop_map(|(from, n)| Op::Missing(from, n)),
        2 => (0..=count + 2).prop_map(Op::Page),
        2 => (0..count + 2).prop_map(Op::Contains),
    ]
}

fn scenario() -> impl Strategy<Value = (u32, Vec<Op>)> {
    (1..300_u32).prop_flat_map(|count| (Just(count), proptest::collection::vec(op(count), 1..200)))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// The tracker against a set model: recording is idempotent and only
    /// for this file, missing segments are the exact complement in order,
    /// ranges stay sorted, disjoint, and nonadjacent, every resume page
    /// obeys §7.5 and reports exactly the recorded segments in its window,
    /// and completion means every segment is recorded.
    #[test]
    fn tracker_matches_the_model((count, ops) in scenario()) {
        let to_fail = |e: Box<dyn std::error::Error>| TestCaseError::fail(e.to_string());
        let file = binding(count, 1).map_err(to_fail)?;
        let foreign = binding(count, 2).map_err(to_fail)?;
        let mut tracker = SegmentTracker::new(&file);
        let mut model = BTreeSet::new();
        for op in ops {
            match op {
                Op::Record(index) => {
                    let predicted = tracker.can_record(index);
                    let result = record(&mut tracker, &file, index).map_err(to_fail)?;
                    prop_assert_eq!(result, predicted);
                    prop_assert_eq!(result, Ok(model.insert(index)));
                }
                Op::RecordForeign(index) => {
                    let result = record(&mut tracker, &foreign, index).map_err(to_fail)?;
                    prop_assert_eq!(result, Err(TrackerError::ForeignSegment));
                }
                Op::Missing(from, n) => {
                    let missing: Vec<u32> = tracker.missing_from(from).take(n).collect();
                    let expected: Vec<u32> = (from..count).filter(|i| !model.contains(i)).take(n).collect();
                    prop_assert_eq!(missing, expected);
                }
                Op::Page(from) => match tracker.resume_page(from) {
                    Ok(page) => check_page(&page, from, count, &model)?,
                    Err(error) => {
                        prop_assert!(from > count);
                        prop_assert_eq!(error, TrackerError::FromIndexOutOfRange);
                    }
                },
                Op::Contains(index) => prop_assert_eq!(tracker.contains(index), model.contains(&index)),
            }
            prop_assert_eq!(tracker.verified_count(), u32::try_from(model.len()).map_err(|e| TestCaseError::fail(e.to_string()))?);
            prop_assert_eq!(tracker.is_complete(), model.len() == count as usize);
            let ranges: Vec<(u32, u32)> = tracker.verified_ranges().collect();
            prop_assert_eq!(ranges.len(), tracker.range_count());
            let mut flattened = BTreeSet::new();
            for pair in ranges.windows(2) {
                prop_assert!(pair[0].0 + pair[0].1 < pair[1].0);
            }
            for (start, len) in ranges {
                prop_assert!(len >= 1);
                flattened.extend(start..start + len);
            }
            prop_assert_eq!(&flattened, &model);
        }
    }
}
