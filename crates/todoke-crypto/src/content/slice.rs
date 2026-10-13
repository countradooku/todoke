//! Bao 0.13.1 combined slices (§7.4) through the `bao` crate, which
//! implements that exact format (docs/adr/0003-bao.md). This module adds
//! only the strictness the protocol requires on top of its decoder.

use std::io::{self, Cursor, Read, Seek, Write};

use zeroize::Zeroizing;

use super::segment::BAO_HEADER_LEN;
use super::{ContentError, MAX_SLICE_LEN, SEGMENT_LEN, Segment, SegmentLayout};

/// The BLAKE3 root and Bao outboard tree of `content`, in memory.
///
/// The root is the manifest entry's `root` (§7.1); the outboard (the Bao
/// 0.13.1 tree without the content, about 6% of the file) lets the sender
/// extract any segment's slice ([`ContentSealer`](super::ContentSealer)).
/// For large files use [`write_outboard`].
#[must_use]
pub fn outboard(content: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let (tree, root) = bao::encode::outboard(content);
    (tree, *root.as_bytes())
}

/// Streams `content` into a Bao outboard tree written to `outboard`, which
/// must be empty and positioned at its start (the encoder rewrites it in
/// place). Returns the BLAKE3 root and the number of content bytes.
///
/// # Errors
///
/// Any I/O error from either side.
pub fn write_outboard<R: Read, W: Read + Write + Seek>(
    mut content: R,
    outboard: W,
) -> io::Result<([u8; 32], u64)> {
    let mut encoder = bao::encode::Encoder::new_outboard(outboard);
    let size = io::copy(&mut content, &mut encoder)?;
    let root = encoder.finalize()?;
    Ok((*root.as_bytes(), size))
}

/// Extracts the canonical combined slice for `segment` from the source
/// file and its outboard, then checks it against the manifest root and
/// size exactly as a receiver would. A source that changed since the
/// manifest was built (§8) yields [`ContentError::SourceChanged`].
pub(crate) fn extract_slice<C: Read + Seek, O: Read + Seek>(
    content: C,
    outboard: O,
    layout: &SegmentLayout,
    segment: &Segment,
    root: &[u8; 32],
) -> Result<Vec<u8>, ContentError> {
    let extractor = bao::encode::SliceExtractor::new_outboard(
        content,
        outboard,
        segment.start(),
        u64::from(segment.len()),
    );
    let mut slice = Vec::new();
    let limit = u64::try_from(MAX_SLICE_LEN + 1).map_err(|_| ContentError::SourceChanged)?;
    extractor
        .take(limit)
        .read_to_end(&mut slice)
        .map_err(|error| match error.kind() {
            io::ErrorKind::UnexpectedEof => ContentError::SourceChanged,
            kind => ContentError::SourceIo(kind),
        })?;
    verify_slice(&slice, layout, segment, root).map_err(|_| ContentError::SourceChanged)?;
    Ok(slice)
}

/// Strictly verifies a decrypted slice for `segment` (§7.4) and returns the
/// segment's logical bytes; see [`verify_range`].
pub(crate) fn verify_slice(
    slice: &[u8],
    layout: &SegmentLayout,
    segment: &Segment,
    root: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, ContentError> {
    verify_range(
        slice,
        layout.size(),
        root,
        segment.start(),
        u64::from(segment.len()),
    )
}

/// Strictly verifies a Bao combined slice of `len` bytes at `start` in a
/// `size`-byte file with BLAKE3 root `root`, and returns those bytes:
///
/// 1. The range lies inside the file and is at most one segment long; a
///    zero length is legal only as the empty file's single segment. (The
///    decoder would otherwise verify the last chunk and return nothing for
///    a slice past the end, or a short read for one crossing it.)
/// 2. The slice is 8..=32768 bytes and its little-endian length header
///    equals `size`. Bao authenticates the header only through the final
///    chunk, which most slices do not contain.
/// 3. The decoder yields exactly `len` bytes verified against `root`; for
///    the empty file it verifies the empty root chunk.
/// 4. The decoder consumed every byte: no trailing data.
pub(crate) fn verify_range(
    slice: &[u8],
    size: u64,
    root: &[u8; 32],
    start: u64,
    len: u64,
) -> Result<Zeroizing<Vec<u8>>, ContentError> {
    let in_file = if len == 0 {
        size == 0 && start == 0
    } else {
        start.checked_add(len).is_some_and(|end| end <= size)
    };
    if !in_file || len > u64::from(SEGMENT_LEN) {
        return Err(ContentError::Integrity);
    }
    if !(BAO_HEADER_LEN..=MAX_SLICE_LEN).contains(&slice.len()) {
        return Err(ContentError::Integrity);
    }
    let header: [u8; BAO_HEADER_LEN] = slice[..BAO_HEADER_LEN]
        .try_into()
        .map_err(|_| ContentError::Integrity)?;
    if u64::from_le_bytes(header) != size {
        return Err(ContentError::Integrity);
    }
    let out_len = usize::try_from(len).map_err(|_| ContentError::Integrity)?;
    let mut data = Zeroizing::new(vec![0; out_len]);
    let mut decoder = bao::decode::SliceDecoder::new(
        Cursor::new(slice),
        &bao::Hash::from_bytes(*root),
        start,
        len,
    );
    if out_len == 0 {
        // A zero-length slice decoder verifies one chunk and outputs
        // nothing. The output buffer only needs to be nonempty.
        let read = decoder
            .read(&mut [0; 1])
            .map_err(|_| ContentError::Integrity)?;
        if read != 0 {
            return Err(ContentError::Integrity);
        }
    } else {
        decoder
            .read_exact(data.as_mut_slice())
            .map_err(|_| ContentError::Integrity)?;
    }
    let consumed = decoder.into_inner().position();
    if usize::try_from(consumed).ok() != Some(slice.len()) {
        return Err(ContentError::Integrity);
    }
    Ok(data)
}
