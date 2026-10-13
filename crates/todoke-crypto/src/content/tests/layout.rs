//! Segment arithmetic, suites, and bindings.

use super::TestResult;
use crate::content::{
    ContentError, ContentSuite, ContentSuites, EPOCH_SEGMENTS, FileBinding, MAX_FILE_SIZE,
    MAX_SEGMENT_COUNT, SEGMENT_LEN, SegmentLayout,
};

#[test]
fn segment_counts_and_ranges() -> TestResult {
    for (size, count, last_len) in [
        (0, 1, 0),
        (1, 1, 1),
        (16_383, 1, 16_383),
        (16_384, 1, 16_384),
        (16_385, 2, 1),
        (32_768, 2, 16_384),
        (MAX_FILE_SIZE - 1, MAX_SEGMENT_COUNT, 16_383),
        (MAX_FILE_SIZE, MAX_SEGMENT_COUNT, 16_384),
    ] {
        let layout = SegmentLayout::new(size)?;
        assert_eq!(layout.size(), size);
        assert_eq!(layout.count(), count, "{size}");
        let last = layout.segment(count - 1)?;
        assert_eq!(last.len(), last_len);
        assert!(last.is_final());
        assert_eq!(last.start() + u64::from(last.len()), size);
        assert_eq!(last.is_empty(), size == 0);
        assert_eq!(
            layout.segment(count).err(),
            Some(ContentError::SegmentOutOfRange)
        );
        assert_eq!(
            layout.segment(u32::MAX).err(),
            Some(ContentError::SegmentOutOfRange)
        );
        if count > 1 {
            let first = layout.segment(0)?;
            assert_eq!((first.start(), first.len()), (0, SEGMENT_LEN));
            assert!(!first.is_final());
        }
    }
    assert_eq!(
        SegmentLayout::new(MAX_FILE_SIZE + 1).err(),
        Some(ContentError::InvalidFile)
    );
    assert_eq!(
        SegmentLayout::new(u64::MAX).err(),
        Some(ContentError::InvalidFile)
    );
    Ok(())
}

/// Epochs, local indices, and the final flag across a 1 TiB file: final at
/// the end of every epoch and at the end of the file, nowhere else.
#[test]
fn epochs_and_final_flags() -> TestResult {
    let layout = SegmentLayout::new(MAX_FILE_SIZE)?;
    for index in [
        0,
        1,
        EPOCH_SEGMENTS - 2,
        EPOCH_SEGMENTS - 1,
        EPOCH_SEGMENTS,
        EPOCH_SEGMENTS + 1,
        5 * EPOCH_SEGMENTS + 77,
        MAX_SEGMENT_COUNT - EPOCH_SEGMENTS,
        MAX_SEGMENT_COUNT - 2,
        MAX_SEGMENT_COUNT - 1,
    ] {
        let segment = layout.segment(index)?;
        assert_eq!(segment.index(), index);
        assert_eq!(segment.epoch(), index / EPOCH_SEGMENTS);
        assert_eq!(u32::from(segment.local_index()), index % EPOCH_SEGMENTS);
        assert_eq!(segment.start(), u64::from(index) * 16_384);
        assert_eq!(segment.len(), SEGMENT_LEN);
        assert_eq!(
            segment.is_final(),
            segment.local_index() == u16::MAX || index == MAX_SEGMENT_COUNT - 1
        );
    }
    assert_eq!(layout.segment(MAX_SEGMENT_COUNT - 1)?.epoch(), 1023);
    // An exact epoch boundary: the last real segment is final and nothing
    // follows it.
    let exact = SegmentLayout::new(u64::from(EPOCH_SEGMENTS) * 16_384)?;
    assert_eq!(exact.count(), EPOCH_SEGMENTS);
    assert!(exact.segment(EPOCH_SEGMENTS - 1)?.is_final());
    assert!(exact.segment(EPOCH_SEGMENTS).is_err());
    Ok(())
}

#[test]
fn suite_ids_bits_and_selection() -> TestResult {
    use ContentSuite::{Aes256GcmStream as Aes, XChaCha20Poly1305Stream as XChaCha};
    assert_eq!(ContentSuite::from_id(1), Some(Aes));
    assert_eq!(ContentSuite::from_id(2), Some(XChaCha));
    for id in [0, 3, 4, 0x0101, u16::MAX] {
        assert_eq!(ContentSuite::from_id(id), None);
    }
    assert_eq!((Aes.id(), XChaCha.id()), (1, 2));
    assert_eq!((Aes.nonce_len(), XChaCha.nonce_len()), (12, 24));
    for bits in 0..=0b11 {
        assert_eq!(
            ContentSuites::from_bits(bits).map(ContentSuites::bits),
            Some(bits)
        );
    }
    for bits in 0b100..=u16::MAX {
        assert_eq!(ContentSuites::from_bits(bits), None);
    }
    let set = |bits| ContentSuites::from_bits(bits);
    let expected = [
        // (local, peer, selected)
        (0b11, 0b11, Some(Aes)),
        (0b11, 0b10, Some(XChaCha)),
        (0b10, 0b11, Some(XChaCha)),
        (0b10, 0b10, Some(XChaCha)),
        (0b01, 0b01, Some(Aes)),
        (0b01, 0b10, None),
        (0b11, 0b00, None),
        (0b00, 0b00, None),
    ];
    for (local, peer, selected) in expected {
        let (local, peer) = (set(local).ok_or("bits")?, set(peer).ok_or("bits")?);
        assert_eq!(local.select(peer), selected);
        assert_eq!(peer.select(local), selected);
    }
    let local = ContentSuites::local();
    assert!(local.contains(XChaCha));
    assert_eq!(local.bits() & !0b11, 0);
    // The advertisement is stable within a process.
    assert_eq!(ContentSuites::local(), local);
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    assert!(local.contains(Aes), "Apple silicon has AES and PMULL");
    Ok(())
}

#[test]
fn file_binding_validation() -> TestResult {
    let suite = ContentSuite::XChaCha20Poly1305Stream;
    assert!(FileBinding::new([1; 16], [2; 32], 1, suite, MAX_FILE_SIZE, [3; 32]).is_ok());
    for (transfer_id, file_id, size) in [
        ([0; 16], 1, 0),
        ([1; 16], 0, 0),
        ([1; 16], 1, MAX_FILE_SIZE + 1),
    ] {
        assert_eq!(
            FileBinding::new(transfer_id, [2; 32], file_id, suite, size, [3; 32]).err(),
            Some(ContentError::InvalidFile)
        );
    }
    let binding = FileBinding::new([1; 16], [2; 32], 9, suite, 5, [3; 32])?;
    assert_eq!(binding.transfer_id(), &[1; 16]);
    assert_eq!(binding.manifest_hash(), &[2; 32]);
    assert_eq!(binding.file_id(), 9);
    assert_eq!(binding.suite(), suite);
    assert_eq!(binding.layout().size(), 5);
    assert_eq!(binding.root(), &[3; 32]);
    Ok(())
}

#[test]
fn errors_display_without_detail() {
    for error in [
        ContentError::InvalidFile,
        ContentError::SuiteUnavailable,
        ContentError::SegmentOutOfRange,
        ContentError::CiphertextLength,
        ContentError::Authentication,
        ContentError::Integrity,
        ContentError::SourceChanged,
        ContentError::SourceIo(std::io::ErrorKind::PermissionDenied),
        ContentError::KeyDerivation,
    ] {
        assert_ne!(error.to_string(), "");
    }
}
