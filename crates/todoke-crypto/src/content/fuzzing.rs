//! Entry points for `cargo fuzz` harnesses; compiled only with `--cfg fuzzing`
//! and the `insecure-content-without-accept` feature, because the harnesses
//! stand in for a verified Accept through that feature's constructor.
//!
//! The files are deterministic and public: a byte pattern of a
//! fuzzer-chosen size, a fixed transfer, manifest hash, and master. Each
//! entry point asserts the strongest property it can check, so a wrong
//! acceptance fails like a crash.

use std::io::Cursor;

use zeroize::Zeroizing;

use super::slice::verify_slice;
use super::{
    AcceptedFile, ContentOpener, ContentSealer, ContentSuite, ContentSuites, FileBinding,
    FileKeyBody, FileMaster, SegmentLayout, outboard,
};

/// Up to five segments plus a partial one keeps each input fast while
/// covering multi-level trees and a short last segment.
const MAX_FUZZ_SIZE: u64 = 5 * 16_384 + 1500;

/// A deterministic file of `size` bytes and its Bao outboard and root.
fn file(size: u64) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    let content: Vec<u8> = (0..size)
        .map(|i| i.to_le_bytes()[0] ^ i.to_le_bytes()[1].rotate_left(3))
        .collect();
    let (tree, root) = outboard(&content);
    (content, tree, root)
}

/// Splits `data` into (size, index, rest): a 3-byte little-endian size
/// reduced modulo `MAX_FUZZ_SIZE + 1`, and a 1-byte segment index reduced
/// modulo the segment count.
fn header(data: &[u8]) -> Option<(SegmentLayout, u32, &[u8])> {
    let (head, rest) = data.split_first_chunk::<4>()?;
    let size = u64::from(u32::from_le_bytes([head[0], head[1], head[2], 0])) % (MAX_FUZZ_SIZE + 1);
    let layout = SegmentLayout::new(size).ok()?;
    let index = u32::from(head[3]) % layout.count();
    Some((layout, index, rest))
}

/// Builds a fuzz input for [`bao_slice`] or [`open_segment`]: the header
/// followed by `body`. Used to write seeds.
#[must_use]
pub fn input(size: u32, index: u8, body: &[u8]) -> Vec<u8> {
    let mut data = size.to_le_bytes()[..3].to_vec();
    data.push(index);
    data.extend_from_slice(body);
    data
}

/// Strict Bao slice verification (§7.4) of fuzzer bytes as the decrypted
/// slice of a segment of a known file. The verifier must either reject the
/// slice or return exactly that segment's bytes.
///
/// # Panics
///
/// If a slice is accepted with wrong content, which is a bug.
pub fn bao_slice(data: &[u8]) {
    let Some((layout, index, slice)) = header(data) else {
        return;
    };
    let (content, _, root) = file(layout.size());
    let Ok(segment) = layout.segment(index) else {
        return;
    };
    if let Ok(bytes) = verify_slice(slice, &layout, &segment, &root) {
        let start = usize::try_from(segment.start()).unwrap_or(usize::MAX);
        let end = start.saturating_add(bytes.len());
        assert_eq!(Some(bytes.as_slice()), content.get(start..end));
        assert_eq!(
            u64::try_from(bytes.len()).ok(),
            Some(u64::from(segment.len()))
        );
    }
}

/// The honest slice for a segment of the fuzzing file, for seeds.
#[must_use]
pub fn honest_slice(size: u32, index: u8) -> Option<Vec<u8>> {
    let (layout, index, _) = header(&input(size, index, &[]))?;
    let (content, tree, root) = file(layout.size());
    let segment = layout.segment(index).ok()?;
    super::slice::extract_slice(
        Cursor::new(&content),
        Cursor::new(&tree),
        &layout,
        &segment,
        &root,
    )
    .ok()
}

fn binding(layout: &SegmentLayout, suite: ContentSuite, root: [u8; 32]) -> Option<FileBinding> {
    FileBinding::new([0xa3; 16], [0x59; 32], 1, suite, layout.size(), root).ok()
}

fn master() -> FileMaster {
    FileMaster::from_secret(Zeroizing::new([0xa5; 32]))
}

/// `XChaCha` always; AES too where this device advertises it, chosen by the
/// low bit of the size byte so seeds can target either.
fn suite(data: &[u8]) -> ContentSuite {
    let aes = data.first().is_some_and(|byte| byte & 1 == 1)
        && ContentSuites::local().contains(ContentSuite::Aes256GcmStream);
    if aes {
        ContentSuite::Aes256GcmStream
    } else {
        ContentSuite::XChaCha20Poly1305Stream
    }
}

/// [`ContentOpener::open_segment`] on fuzzer bytes as the content
/// ciphertext of a segment of a known file. It must reject everything except
/// the honest ciphertext, which opens to exactly the segment's bytes.
///
/// # Panics
///
/// If a forged ciphertext opens, or the honest one does not, which is a bug.
pub fn open_segment(data: &[u8]) {
    let Some((layout, index, ciphertext)) = header(data) else {
        return;
    };
    let (content, tree, root) = file(layout.size());
    let Some(binding) = binding(&layout, suite(data), root) else {
        return;
    };
    let file = AcceptedFile::assume_accepted_without_verification(binding);
    let (Ok(opener), Ok(sealer)) = (
        ContentOpener::new(&file, &master()),
        ContentSealer::new(&file, &master()),
    ) else {
        return;
    };
    let honest = sealer.seal_segment(index, Cursor::new(&content), Cursor::new(&tree));
    match opener.open_segment(index, ciphertext) {
        Ok(segment) => {
            assert_eq!(honest.as_deref().ok(), Some(ciphertext));
            let start = usize::try_from(segment.segment().start()).unwrap_or(usize::MAX);
            let end = start.saturating_add(segment.data().len());
            assert_eq!(Some(segment.data()), content.get(start..end));
        }
        Err(_) => assert_ne!(honest.as_deref().ok(), Some(ciphertext)),
    }
}

/// The honest ciphertext for a segment of the fuzzing file, for seeds.
#[must_use]
pub fn honest_ciphertext(size: u32, index: u8) -> Option<Vec<u8>> {
    let data = input(size, index, &[]);
    let (layout, index, _) = header(&data)?;
    let (content, tree, root) = file(layout.size());
    let file =
        AcceptedFile::assume_accepted_without_verification(binding(&layout, suite(&data), root)?);
    ContentSealer::new(&file, &master())
        .ok()?
        .seal_segment(index, Cursor::new(&content), Cursor::new(&tree))
        .ok()
}

/// Decodes a `FileKey` body (§8) and returns its re-encoding, which must
/// equal the input.
///
/// # Panics
///
/// If an accepted body does not re-encode to the input, which is a bug.
pub fn file_key_body(data: &[u8]) {
    if let Ok(body) = FileKeyBody::decode(data) {
        assert_eq!(body.encode().as_slice(), data);
    }
}
