//! Checks of the crate's own oracles against ground truth: collision keys
//! against what the filesystem under the test's temporary directory
//! actually merges, and the quarantine's slot size against real Bao
//! slices (and, for files too large to build here, against an independent
//! model of the Bao tree that the real slices validate).

use std::fs::OpenOptions;

use super::support::*;
use super::*;
use crate::name::fold::collision_key;
use crate::quarantine::store::max_ciphertext_len;

/// Pairs that some supported filesystem treats as one name: case (NTFS,
/// APFS and HFS+ in their default case-insensitive modes, exFAT, FAT),
/// Unicode normalization (APFS, HFS+), German sharp s, Turkish dotless and
/// dotted i, Greek sigmas, and the Kelvin and Angstrom signs.
const PAIRS: [(&str, &str); 12] = [
    ("report.pdf", "REPORT.PDF"),
    ("\u{E9}t\u{E9}", "e\u{301}te\u{301}"),
    ("\u{C5}", "A\u{30A}"),
    ("Stra\u{DF}e", "STRASSE"),
    ("\u{DF}", "ss"),
    ("\u{131}", "I"),
    ("\u{131}", "i"),
    ("\u{130}", "i\u{307}"),
    ("\u{3A3}", "\u{3C3}"),
    ("\u{3C3}", "\u{3C2}"),
    ("K", "\u{212A}"),
    ("\u{C5}", "\u{212B}"),
];

/// Creates `a`, then tries to create `b` exclusively in a fresh directory:
/// `Some(true)` if the filesystem says `b` already exists, `Some(false)`
/// if it made a second entry, `None` if it refused the name itself.
fn merged(base: &std::path::Path, a: &str, b: &str) -> AnyResult<Option<bool>> {
    std::fs::create_dir(base)?;
    if std::fs::write(base.join(a), b"a").is_err() {
        return Ok(None);
    }
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(base.join(b))
    {
        Ok(_) => Ok(Some(std::fs::read_dir(base)?.count() < 2)),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(Some(true)),
        Err(_) => Ok(None),
    }
}

/// Whatever the filesystem holding the temporary directory merges, the
/// collision key merges too (it is meant as a superset of every supported
/// filesystem). Pairs this filesystem keeps apart are reported, not
/// failed: the key is deliberately more conservative than any one of them.
#[test]
fn collision_keys_merge_whatever_this_filesystem_merges() -> TestResult {
    let temp = TempDir::new()?;
    for (index, (a, b)) in PAIRS.iter().enumerate() {
        let keys_equal = collision_key(a) == collision_key(b);
        assert!(
            keys_equal,
            "{} / {}",
            a.escape_unicode(),
            b.escape_unicode()
        );
        match merged(&temp.path().join(index.to_string()), a, b)? {
            Some(true) => assert!(keys_equal),
            Some(false) => eprintln!(
                "note: this filesystem keeps {} and {} apart; the collision key merges them anyway",
                a.escape_unicode(),
                b.escape_unicode()
            ),
            None => eprintln!(
                "skipping {} / {}: this filesystem refuses one of the names",
                a.escape_unicode(),
                b.escape_unicode()
            ),
        }
    }
    // And names no filesystem merges are kept apart by the key.
    for (a, b) in [("a", "b"), ("e", "\u{E9}"), ("1", "\u{661}")] {
        assert_ne!(collision_key(a), collision_key(b));
    }
    Ok(())
}

/// The length of the Bao 0.13.1 combined slice of segment `index` (16
/// chunks of 1 KiB) of a file of `size` bytes, from the format alone: an
/// 8-byte length header, then a pre-order walk of the left-balanced tree
/// (a left subtree holds the largest power of two of chunks smaller than
/// its parent's) that emits a 64-byte parent node for every subtree
/// overlapping the range and every chunk in it.
fn bao_slice_len(size: u64, index: u64) -> u64 {
    fn walk(first: u64, count: u64, start: u64, end: u64, size: u64) -> u64 {
        if count == 1 {
            return size.saturating_sub(first * 1024).min(1024);
        }
        // The largest power of two smaller than `count`.
        let left = 1_u64 << (count - 1).ilog2();
        let mut total = 64;
        if start < first + left {
            total += walk(first, left, start, end.min(first + left), size);
        }
        if end > first + left {
            total += walk(
                first + left,
                count - left,
                start.max(first + left),
                end,
                size,
            );
        }
        total
    }
    let chunks = size.div_ceil(1024).max(1);
    let start = index * 16;
    let end = (start + 16).min(chunks);
    8 + walk(0, chunks, start, end, size)
}

/// The model matches real slices (the content layer's, through the sealer)
/// for every segment of files of many tree shapes.
#[test]
fn the_bao_model_matches_real_slices() -> TestResult {
    let fixture = fixture()?;
    let sizes: [usize; 10] = [
        0,
        1,
        1023,
        1024,
        1025,
        16_384,
        16_385,
        40_000,
        300_000,
        (1 << 20) + 1,
    ];
    let files: Vec<Entry> = sizes
        .iter()
        .enumerate()
        .map(|(k, &size)| file_entry(&format!("f{k}"), 0, content(size, 7)))
        .collect();
    let selection: Vec<u32> = (1..=u32::try_from(sizes.len())?).collect();
    let manifest = build_manifest(&fixture, [34; 16], &files, 3600)?;
    let consented = Consented::new(&fixture, &manifest, &files, &selection, false, 34)?;
    for (&file_id, &size) in selection.iter().zip(&sizes) {
        for index in 0..consented.count(file_id)? {
            let real = consented.ciphertext(file_id, index)?.len() - 16;
            assert_eq!(
                bao_slice_len(size as u64, u64::from(index)),
                real as u64,
                "size {size}, segment {index}"
            );
        }
    }
    Ok(())
}

/// The slot size bounds every segment's ciphertext for files whose trees
/// are deeper than 20 levels (over 1 GiB, too large to build here), up to
/// the 1 TiB limit, using the validated model.
#[test]
fn the_slot_bound_covers_deep_trees() {
    for size in [
        (1_u64 << 30) + 1,
        (1 << 30) + 16_385,
        (1 << 32) - 1,
        (1 << 33) + 12_345,
        (1 << 35) + 1,
        (1 << 40) - 16_384 * 3 + 7,
        (1 << 40) - 1,
        1 << 40,
    ] {
        let segments = size.div_ceil(16_384);
        let bound = max_ciphertext_len(size) as u64;
        for index in [
            0,
            1,
            2,
            segments / 2,
            segments / 2 + 1,
            segments - 2,
            segments - 1,
        ] {
            let slice = bao_slice_len(size, index);
            assert!(
                slice + 16 <= bound,
                "size {size}, segment {index}: {slice} + 16 > {bound}"
            );
        }
    }
}
