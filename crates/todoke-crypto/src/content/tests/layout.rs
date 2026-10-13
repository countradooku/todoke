//! Segment arithmetic, suites, and bindings.

use super::TestResult;
use crate::content::keys::{AAD_LEN, CONTEXT_LEN};
use crate::content::{
    ContentError, ContentSuite, ContentSuites, EPOCH_SEGMENTS, FILE_KEY_BODY_LEN, FileBinding,
    MAX_CIPHERTEXT_LEN, MAX_FILE_SIZE, MAX_RESUME_RANGES, MAX_SEGMENT_COUNT, MAX_SLICE_LEN,
    MAX_TRACKED_RANGES, MIN_CIPHERTEXT_LEN, SEGMENT_LEN, SegmentLayout, TAG_LEN,
};

/// The limits are the spec's literal numbers, not values derived from
/// each other, so that changing one fails here.
#[test]
fn constants_are_the_spec_values() {
    // §7.4: 16384-byte segments, at most 67108864 of them for 1 TiB
    // (§6 max_file_bytes 1099511627776), and a slice of at most 32768
    // bytes; Chunk content_len is 24..=32784.
    assert_eq!(SEGMENT_LEN, 16_384);
    assert_eq!(MAX_FILE_SIZE, 1_099_511_627_776);
    assert_eq!(MAX_SEGMENT_COUNT, 67_108_864);
    assert_eq!(MAX_SLICE_LEN, 32_768);
    assert_eq!((MIN_CIPHERTEXT_LEN, MAX_CIPHERTEXT_LEN), (24, 32_784));
    // §8: 65536 segments per epoch, a 16-byte tag, the 86-byte FileKey
    // body, the 26-byte HKDF context, and the 123-byte AAD.
    assert_eq!(EPOCH_SEGMENTS, 65_536);
    assert_eq!(TAG_LEN, 16);
    assert_eq!(FILE_KEY_BODY_LEN, 86);
    assert_eq!(CONTEXT_LEN, 26);
    assert_eq!(AAD_LEN, 123);
    // §7.5: range_count is 0..1024. The per-file range cap is todoke's
    // (docs/DESIGN.md).
    assert_eq!(MAX_RESUME_RANGES, 1024);
    assert_eq!(MAX_TRACKED_RANGES, 4096);
}

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
    for id in 0..=u16::MAX {
        let parsed = ContentSuite::from_id(id);
        assert_eq!(
            parsed.map(ContentSuite::id),
            (id == 1 || id == 2).then_some(id)
        );
    }
    assert_eq!((Aes.id(), XChaCha.id()), (1, 2));
    assert_eq!((Aes.nonce_len(), XChaCha.nonce_len()), (12, 24));
    // §6: every v1 peer supports XChaCha (bit 1), with or without AES.
    for bits in [0b10, 0b11] {
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
        (0b11, 0b11, Aes),
        (0b11, 0b10, XChaCha),
        (0b10, 0b11, XChaCha),
        (0b10, 0b10, XChaCha),
    ];
    for (local, peer, selected) in expected {
        let (local, peer) = (set(local).ok_or("bits")?, set(peer).ok_or("bits")?);
        assert_eq!(local.select(peer), Some(selected));
        assert_eq!(peer.select(local), Some(selected));
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

/// §6: "V1 implementations MUST support `XChaCha`", and "a peer advertising
/// an unsupported version/suite MUST be rejected". A set without `XChaCha`
/// (AES only, or empty) is refused when parsed, so it can never be selected
/// against, and AES is never chosen with a peer that lacks `XChaCha`.
#[test]
fn a_suite_set_without_xchacha_is_rejected() {
    use ContentSuite::{Aes256GcmStream as Aes, XChaCha20Poly1305Stream as XChaCha};
    assert_eq!(ContentSuites::from_bits(0b01), None, "AES only");
    assert_eq!(ContentSuites::from_bits(0b00), None, "no suite");
    // Every set that does parse contains XChaCha, so selection with this
    // device always succeeds.
    for bits in 0..=u16::MAX {
        if let Some(peer) = ContentSuites::from_bits(bits) {
            assert!(peer.contains(XChaCha));
            let selected = ContentSuites::local().select(peer);
            assert!(matches!(selected, Some(Aes | XChaCha)));
        }
    }
}

/// ADR 0004: AES is advertised only where libcrux-aes runs its hardware
/// path. Checked with the standard library's CPU detection, not
/// libcrux-platform's: an advertising device has the instructions that
/// path needs, and targets where libcrux-platform cannot detect them
/// (aarch64 outside Linux and macOS, other architectures) never advertise.
#[test]
fn aes_is_advertised_only_with_hardware_aes() {
    let advertised = ContentSuites::local().contains(ContentSuite::Aes256GcmStream);
    #[cfg(target_arch = "x86_64")]
    if advertised {
        assert!(std::arch::is_x86_feature_detected!("aes"));
        assert!(std::arch::is_x86_feature_detected!("pclmulqdq"));
        assert!(std::arch::is_x86_feature_detected!("avx"));
        assert!(std::arch::is_x86_feature_detected!("avx2"));
        assert!(std::arch::is_x86_feature_detected!("movbe"));
    }
    #[cfg(target_arch = "aarch64")]
    if advertised {
        assert!(std::arch::is_aarch64_feature_detected!("neon"));
        assert!(std::arch::is_aarch64_feature_detected!("aes"));
        assert!(std::arch::is_aarch64_feature_detected!("pmull"));
    }
    #[cfg(any(
        all(
            target_arch = "aarch64",
            not(any(target_os = "linux", target_os = "macos"))
        ),
        not(any(target_arch = "x86_64", target_arch = "aarch64"))
    ))]
    assert!(!advertised);
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
