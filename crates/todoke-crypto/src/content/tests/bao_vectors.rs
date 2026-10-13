//! The `bao` crate against Bao 0.13.1 reference outputs, and the strict
//! slice verifier against reference and hostile slices. Provenance:
//! `testdata/bao/README.md`.

use std::io::{Cursor, Read as _};

use super::{AnyResult, TestResult, counter_input, testdata};
use crate::content::slice::{extract_slice, verify_range, verify_slice};
use crate::content::{
    ContentError, ContentSuite, FileBinding, SEGMENT_LEN, SegmentLayout, outboard, write_outboard,
};
use crate::session::test_vectors::{Vector, hex_array_at, json_at};

fn array<'a>(value: &'a Vector, pointer: &str) -> AnyResult<&'a Vec<Vector>> {
    json_at(value, pointer)?
        .as_array()
        .ok_or_else(|| format!("{pointer} is not an array").into())
}

fn number(value: &Vector, pointer: &str) -> AnyResult<u64> {
    json_at(value, pointer)?
        .as_u64()
        .ok_or_else(|| format!("{pointer} is not a number").into())
}

fn length(value: &Vector, pointer: &str) -> AnyResult<usize> {
    Ok(usize::try_from(number(value, pointer)?)?)
}

fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn text<'a>(value: &'a Vector, pointer: &str) -> AnyResult<&'a str> {
    json_at(value, pointer)?
        .as_str()
        .ok_or_else(|| format!("{pointer} is not a string").into())
}

/// Hashes, combined encodings, and outboard encodings from the `bao` crate
/// are byte-identical to the Bao 0.13.1 reference vectors.
#[test]
fn bao_crate_reproduces_reference_encodings() -> TestResult {
    let vectors = testdata("bao/test_vectors.json")?;
    for case in array(&vectors, "/hash")? {
        let input = counter_input(length(case, "/input_len")?)?;
        assert_eq!(blake3_hex(&input), text(case, "/bao_hash")?);
        assert_eq!(hex::encode(outboard(&input).1), text(case, "/bao_hash")?);
    }
    for case in array(&vectors, "/encode")? {
        let input = counter_input(length(case, "/input_len")?)?;
        let (encoded, hash) = bao::encode::encode(&input);
        assert_eq!(encoded.len(), length(case, "/output_len")?);
        assert_eq!(hash.to_hex().as_str(), text(case, "/bao_hash")?);
        assert_eq!(blake3_hex(&encoded), text(case, "/encoded_blake3")?);
    }
    for case in array(&vectors, "/outboard")? {
        let input = counter_input(length(case, "/input_len")?)?;
        let (tree, root) = outboard(&input);
        assert_eq!(tree.len(), length(case, "/output_len")?);
        assert_eq!(hex::encode(root), text(case, "/bao_hash")?);
        assert_eq!(blake3_hex(&tree), text(case, "/encoded_blake3")?);
        // The streaming encoder writes the same outboard.
        let mut streamed = Cursor::new(Vec::new());
        let (streamed_root, len) = write_outboard(input.as_slice(), &mut streamed)?;
        assert_eq!(streamed_root, root);
        assert_eq!(len, u64::try_from(input.len())?);
        assert_eq!(streamed.into_inner(), tree);
    }
    Ok(())
}

/// Every reference slice: the `bao` extractor reproduces it byte for byte
/// from both the combined and the outboard encoding, its decoder rejects
/// every reference corruption point, and the strict verifier accepts it
/// exactly when the range lies inside the file, returning the right bytes.
/// That rejects the decoder's lenient cases: zero-length slices of
/// nonempty files, ranges that cross the end of the file (short reads),
/// and ranges past it (no bytes, final chunk only).
#[test]
fn slices_match_reference_and_strict_rules() -> TestResult {
    let vectors = testdata("bao/test_vectors.json")?;
    let mut lenient = 0;
    for file in array(&vectors, "/slice")? {
        let len = length(file, "/input_len")?;
        let input = counter_input(len)?;
        let size = u64::try_from(len)?;
        let (encoded, hash) = bao::encode::encode(&input);
        let (tree, _) = outboard(&input);
        let root = *hash.as_bytes();
        assert_eq!(hash.to_hex().as_str(), text(file, "/bao_hash")?);
        for case in array(file, "/slices")? {
            let start = number(case, "/start")?;
            let count = number(case, "/len")?;
            let mut slice = Vec::new();
            bao::encode::SliceExtractor::new(Cursor::new(&encoded), start, count)
                .read_to_end(&mut slice)?;
            assert_eq!(slice.len(), length(case, "/output_len")?);
            assert_eq!(blake3_hex(&slice), text(case, "/output_blake3")?);
            let mut from_outboard = Vec::new();
            bao::encode::SliceExtractor::new_outboard(
                Cursor::new(&input),
                Cursor::new(&tree),
                start,
                count,
            )
            .read_to_end(&mut from_outboard)?;
            assert_eq!(from_outboard, slice);

            for point in array(case, "/corruptions")? {
                let point = usize::try_from(point.as_u64().ok_or("corruption point")?)?;
                let mut corrupt = slice.clone();
                *corrupt.get_mut(point).ok_or("corruption point")? ^= 1;
                let mut decoder =
                    bao::decode::SliceDecoder::new(corrupt.as_slice(), &hash, start, count);
                assert!(decoder.read_to_end(&mut Vec::new()).is_err());
                assert_eq!(
                    verify_range(&corrupt, size, &root, start, count).err(),
                    Some(ContentError::Integrity)
                );
            }

            let inside = if count == 0 {
                size == 0 && start == 0
            } else {
                start + count <= size
            };
            let strict = verify_range(&slice, size, &root, start, count);
            if inside {
                let begin = usize::try_from(start)?;
                let end = begin + usize::try_from(count)?;
                assert_eq!(strict?.as_slice(), &input[begin..end]);
            } else {
                assert_eq!(strict.err(), Some(ContentError::Integrity));
                // The bao decoder alone accepts these.
                let mut decoder =
                    bao::decode::SliceDecoder::new(slice.as_slice(), &hash, start, count);
                let mut output = Vec::new();
                decoder.read_to_end(&mut output)?;
                assert!(u64::try_from(output.len())? < count.max(1));
                lenient += 1;
            }
        }
    }
    assert!(lenient > 40, "only {lenient} lenient cases exercised");
    Ok(())
}

/// Slices of todoke's 16384-byte segments, from the pure-Python Bao 0.13.1
/// reference (`testdata/bao/segment_slices.json`): the sender's extraction
/// is byte-identical and the receiver's verifier returns the segment.
#[test]
fn segment_slices_match_reference_implementation() -> TestResult {
    let vectors = testdata("bao/segment_slices.json")?;
    assert_eq!(number(&vectors, "/segment_len")?, u64::from(SEGMENT_LEN));
    let files = array(&vectors, "/files")?;
    assert_eq!(files.len(), 14);
    for file in files {
        let len = length(file, "/size")?;
        let input = counter_input(len)?;
        let (tree, root) = outboard(&input);
        assert_eq!(root, hex_array_at::<32>(file, "/root_hex")?);
        assert_eq!(
            bao::encode::encode(&input).0.len(),
            length(file, "/encoded_len")?
        );
        let layout = SegmentLayout::new(u64::try_from(len)?)?;
        let segments = array(file, "/segments")?;
        assert_eq!(segments.len(), usize::try_from(layout.count())?);
        for case in segments {
            let index = u32::try_from(number(case, "/index")?)?;
            let segment = layout.segment(index)?;
            assert_eq!(segment.start(), number(case, "/start")?);
            assert_eq!(u64::from(segment.len()), number(case, "/len")?);
            let slice = extract_slice(
                Cursor::new(&input),
                Cursor::new(&tree),
                &layout,
                &segment,
                &root,
            )?;
            assert_eq!(slice.len(), length(case, "/slice_len")?);
            assert_eq!(blake3_hex(&slice), text(case, "/slice_blake3_hex")?);
            if let Ok(full) = text(case, "/slice_hex") {
                assert_eq!(hex::encode(&slice), full);
            }
            let data = verify_slice(&slice, &layout, &segment, &root)?;
            let begin = usize::try_from(segment.start())?;
            assert_eq!(
                data.as_slice(),
                &input[begin..begin + usize::try_from(segment.len())?]
            );
        }
    }
    Ok(())
}

struct Sliced {
    input: Vec<u8>,
    layout: SegmentLayout,
    root: [u8; 32],
    slices: Vec<Vec<u8>>,
}

fn sliced(len: usize) -> AnyResult<Sliced> {
    let input = counter_input(len)?;
    let (tree, root) = outboard(&input);
    let layout = SegmentLayout::new(u64::try_from(len)?)?;
    let mut slices = Vec::new();
    for index in 0..layout.count() {
        let segment = layout.segment(index)?;
        slices.push(extract_slice(
            Cursor::new(&input),
            Cursor::new(&tree),
            &layout,
            &segment,
            &root,
        )?);
    }
    Ok(Sliced {
        input,
        layout,
        root,
        slices,
    })
}

fn rejects(file: &Sliced, index: u32, slice: &[u8]) -> AnyResult<bool> {
    let segment = file.layout.segment(index)?;
    Ok(
        verify_slice(slice, &file.layout, &segment, &file.root).err()
            == Some(ContentError::Integrity),
    )
}

/// Flipping any bit of any slice byte (header, parent node, or content) is
/// rejected.
#[test]
fn every_single_bit_flip_is_rejected() -> TestResult {
    for len in [1, 1025, 2 * 16384 + 3] {
        let file = sliced(len)?;
        for (index, slice) in file.slices.iter().enumerate() {
            let index = u32::try_from(index)?;
            for position in 0..slice.len() {
                // Sample large slices; cover small ones fully.
                if slice.len() > 4096 && position % 31 != 0 && position >= 8 + 64 * 16 {
                    continue;
                }
                for bit in [0, 7] {
                    let mut corrupt = slice.clone();
                    corrupt[position] ^= 1 << bit;
                    assert!(
                        rejects(&file, index, &corrupt)?,
                        "len {len} index {index} byte {position}"
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn wrong_root_wrong_segment_truncation_and_trailing_bytes_are_rejected() -> TestResult {
    let file = sliced(3 * 16384 + 1000)?;
    let last = file.layout.count() - 1;
    for index in 0..file.layout.count() {
        let slice = &file.slices[usize::try_from(index)?];
        let segment = file.layout.segment(index)?;
        let mut root = file.root;
        root[31] ^= 1;
        assert_eq!(
            verify_slice(slice, &file.layout, &segment, &root).err(),
            Some(ContentError::Integrity)
        );
        // Another segment's slice, at this index.
        let other = &file.slices[usize::try_from((index + 1) % file.layout.count())?];
        assert!(rejects(&file, index, other)?);
        // Truncated by one byte, one parent, or to the header.
        for cut in [1, 64, slice.len() - 8] {
            assert!(rejects(&file, index, &slice[..slice.len() - cut])?);
        }
        // Trailing bytes: one byte, a fake parent, a whole extra chunk.
        for extra in [1, 64, 1024] {
            let mut longer = slice.clone();
            longer.resize(slice.len() + extra, 0);
            assert!(rejects(&file, index, &longer)?);
        }
        // Concatenated with the next slice.
        if index < last {
            let mut both = slice.clone();
            both.extend_from_slice(other);
            assert!(rejects(&file, index, &both)?);
        }
    }
    Ok(())
}

/// Bao authenticates the length header only through the final chunk. For a
/// slice that does not reach it, the `bao` decoder alone accepts some wrong
/// headers; the strict verifier compares the header with the manifest size
/// first.
#[test]
fn wrong_length_headers_are_rejected_even_where_bao_alone_accepts_them() -> TestResult {
    let file = sliced(3 * 16384 + 1000)?;
    let hash = bao::Hash::from_bytes(file.root);
    let size = file.layout.size();
    let mut bao_alone_accepted = 0;
    for index in 0..file.layout.count() {
        let slice = &file.slices[usize::try_from(index)?];
        let segment = file.layout.segment(index)?;
        for claimed in [
            size + 1,
            size - 1,
            size + 1024,
            0,
            u64::MAX,
            size | (1 << 56),
        ] {
            let mut forged = slice.clone();
            forged[..8].copy_from_slice(&claimed.to_le_bytes());
            assert!(
                rejects(&file, index, &forged)?,
                "index {index} header {claimed}"
            );
            let mut decoder = bao::decode::SliceDecoder::new(
                forged.as_slice(),
                &hash,
                segment.start(),
                u64::from(segment.len()),
            );
            let mut output = Vec::new();
            if decoder.read_to_end(&mut output).is_ok() && output.len() == 16384 {
                bao_alone_accepted += 1;
            }
        }
    }
    // E.g. size + 1 keeps the left subtrees, so segment 0 still decodes.
    assert!(bao_alone_accepted > 0);
    Ok(())
}

#[test]
fn the_empty_file_is_exactly_eight_zero_bytes() -> TestResult {
    let file = sliced(0)?;
    assert_eq!(file.layout.count(), 1);
    assert_eq!(file.slices, [vec![0; 8]]);
    assert_eq!(file.root, *blake3::hash(b"").as_bytes());
    let segment = file.layout.segment(0)?;
    assert_eq!(
        verify_slice(&[0; 8], &file.layout, &segment, &file.root)?.len(),
        0
    );
    assert!(rejects(&file, 0, &[0; 9])?);
    assert!(rejects(&file, 0, &[0; 7])?);
    assert!(rejects(&file, 0, &[])?);
    assert!(rejects(&file, 0, &[1, 0, 0, 0, 0, 0, 0, 0])?);
    // Another file's root, and a one-byte file's slice.
    let other = sliced(1)?;
    assert_eq!(
        verify_slice(&[0; 8], &file.layout, &segment, &other.root).err(),
        Some(ContentError::Integrity)
    );
    assert!(rejects(&file, 0, &other.slices[0])?);
    // The empty root is not the zero root (§7.1).
    assert_eq!(
        verify_slice(&[0; 8], &file.layout, &segment, &[0; 32]).err(),
        Some(ContentError::Integrity)
    );
    Ok(())
}

/// Ranges the protocol never produces are refused before decoding.
#[test]
fn strict_range_rules() -> TestResult {
    let file = sliced(2 * 16384)?;
    let size = file.layout.size();
    let slice = &file.slices[0];
    assert_eq!(
        verify_range(slice, size, &file.root, 0, 16384)?.as_slice(),
        &file.input[..16384]
    );
    for (start, len) in [
        (0, 0),
        (size, 0),
        (size, 1),
        (size - 1, 2),
        (0, 16385),
        (u64::MAX, 1),
        (16384, u64::MAX),
    ] {
        assert_eq!(
            verify_range(slice, size, &file.root, start, len).err(),
            Some(ContentError::Integrity),
            "{start} {len}"
        );
    }
    // Oversized slices are refused before parsing.
    let mut huge = slice.clone();
    huge.resize(32_769, 0);
    assert!(rejects(&file, 0, &huge)?);
    Ok(())
}

/// The sender detects a source or outboard that no longer matches the
/// manifest root and size.
#[test]
fn extraction_detects_source_mutation() -> TestResult {
    let file = sliced(3 * 16384 + 1000)?;
    let (tree, _) = outboard(&file.input);
    let binding = FileBinding::new(
        [1; 16],
        [2; 32],
        1,
        ContentSuite::XChaCha20Poly1305Stream,
        file.layout.size(),
        file.root,
    )?;
    let layout = binding.layout();
    let extract =
        |content: &[u8], tree: &[u8], index: u32| -> AnyResult<Result<Vec<u8>, ContentError>> {
            let segment = layout.segment(index)?;
            Ok(extract_slice(
                Cursor::new(content),
                Cursor::new(tree),
                layout,
                &segment,
                binding.root(),
            ))
        };
    // One changed byte in segment 1 affects segment 1 only.
    let mut changed = file.input.clone();
    changed[16384 + 5] ^= 1;
    assert_eq!(
        extract(&changed, &tree, 1)?.err(),
        Some(ContentError::SourceChanged)
    );
    assert_eq!(
        extract(&changed, &tree, 0)?.ok(),
        Some(file.slices[0].clone())
    );
    // A truncated or extended source.
    let short = &file.input[..file.input.len() - 1];
    assert_eq!(
        extract(short, &tree, 3)?.err(),
        Some(ContentError::SourceChanged)
    );
    let mut long = file.input.clone();
    long.push(0);
    let (long_tree, _) = outboard(&long);
    assert_eq!(
        extract(&long, &long_tree, 0)?.err(),
        Some(ContentError::SourceChanged)
    );
    // An outboard rebuilt from the changed file no longer matches the root.
    let (changed_tree, _) = outboard(&changed);
    assert_eq!(
        extract(&changed, &changed_tree, 0)?.err(),
        Some(ContentError::SourceChanged)
    );
    // A corrupted or truncated outboard.
    let mut bad_tree = tree.clone();
    bad_tree[8] ^= 1;
    assert_eq!(
        extract(&file.input, &bad_tree, 0)?.err(),
        Some(ContentError::SourceChanged)
    );
    // The outboard's last parents belong to segment 2's subtree (pre-order).
    assert_eq!(
        extract(&file.input, &tree[..tree.len() - 1], 2)?.err(),
        Some(ContentError::SourceChanged)
    );
    Ok(())
}
