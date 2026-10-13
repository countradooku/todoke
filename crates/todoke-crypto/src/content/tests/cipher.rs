//! The seal/open pipeline: round trips, determinism, and every
//! substitution the AAD and key schedule must defeat.

use zeroize::Zeroizing;

use super::{
    AnyResult, MANIFEST_HASH, Source, TRANSFER_ID, TestResult, aes_available, counter_input,
    local_suites, master,
};
use crate::content::{
    AcceptedFile, ContentError, ContentOpener, ContentSealer, ContentSuite, EPOCH_SEGMENTS,
    FileBinding, FileMaster, MAX_CIPHERTEXT_LEN, MIN_CIPHERTEXT_LEN, SEGMENT_LEN, TAG_LEN,
};

const SIZES: [usize; 7] = [0, 1, 1024, 16_383, 16_384, 16_385, 3 * 16_384 + 1000];

fn other_suite(suite: ContentSuite) -> ContentSuite {
    match suite {
        ContentSuite::Aes256GcmStream => ContentSuite::XChaCha20Poly1305Stream,
        ContentSuite::XChaCha20Poly1305Stream => ContentSuite::Aes256GcmStream,
    }
}

#[test]
fn every_segment_round_trips_in_every_local_suite() -> TestResult {
    for suite in local_suites() {
        for len in SIZES {
            let source = Source::new(counter_input(len)?, suite)?;
            let (sealer, opener) = (source.sealer()?, source.opener()?);
            let mut rebuilt = Vec::new();
            for index in 0..source.binding.layout().count() {
                let ciphertext = source.seal(&sealer, index)?;
                assert!((MIN_CIPHERTEXT_LEN..=MAX_CIPHERTEXT_LEN).contains(&ciphertext.len()));
                let verified = opener.open_segment(index, &ciphertext)?;
                assert_eq!(verified.segment().index(), index);
                assert_eq!(verified.file_id(), 1);
                assert_eq!(verified.transfer_id(), &TRANSFER_ID);
                assert_eq!(verified.data(), source.segment_bytes(index)?);
                rebuilt.extend_from_slice(&verified.into_data());
            }
            assert_eq!(rebuilt, source.content);
        }
    }
    Ok(())
}

/// Taking the verified bytes out of the segment keeps them in a buffer that
/// is wiped when dropped (§14.2), rather than in a plain `Vec`.
#[test]
fn into_data_keeps_the_plaintext_in_a_wiping_buffer() -> TestResult {
    let source = Source::new(counter_input(1000)?, ContentSuite::XChaCha20Poly1305Stream)?;
    let ciphertext = source.seal(&source.sealer()?, 0)?;
    let verified = source.opener()?.open_segment(0, &ciphertext)?;
    let data: Zeroizing<Vec<u8>> = verified.into_data();
    assert_eq!(data.as_slice(), source.segment_bytes(0)?);
    Ok(())
}

#[test]
fn the_empty_file_seals_to_24_bytes() -> TestResult {
    for suite in local_suites() {
        let source = Source::new(Vec::new(), suite)?;
        let ciphertext = source.seal(&source.sealer()?, 0)?;
        assert_eq!(ciphertext.len(), 8 + TAG_LEN);
        let verified = source.opener()?.open_segment(0, &ciphertext)?;
        assert_eq!(verified.data().len(), 0);
        assert_eq!(
            source
                .seal(&source.sealer()?, 1)
                .err()
                .map(|e| e.to_string()),
            Some(ContentError::SegmentOutOfRange.to_string())
        );
    }
    Ok(())
}

/// Repeated requests return identical ciphertext (§8); a different master
/// gives different ciphertext.
#[test]
fn sealing_is_deterministic_per_master() -> TestResult {
    for suite in local_suites() {
        let source = Source::new(counter_input(2 * 16_384 + 7)?, suite)?;
        let sealer = source.sealer()?;
        let other = ContentSealer::new(
            &source.accepted(),
            &FileMaster::from_secret(Zeroizing::new([0x5a; 32])),
        )?;
        for index in 0..3 {
            let first = source.seal(&sealer, index)?;
            assert_eq!(source.seal(&sealer, index)?, first);
            assert_eq!(source.seal(&source.sealer()?, index)?, first);
            assert_ne!(source.seal(&other, index)?, first);
        }
    }
    Ok(())
}

#[test]
fn a_changed_source_is_refused_not_resealed() -> TestResult {
    for suite in local_suites() {
        let mut source = Source::new(counter_input(2 * 16_384 + 7)?, suite)?;
        let sealer = source.sealer()?;
        let before = source.seal(&sealer, 2)?;
        source.content[2 * 16_384] ^= 0x80;
        assert_eq!(
            sealer
                .seal_segment(
                    2,
                    std::io::Cursor::new(&source.content),
                    std::io::Cursor::new(&source.outboard)
                )
                .err(),
            Some(ContentError::SourceChanged)
        );
        source.content[2 * 16_384] ^= 0x80;
        assert_eq!(source.seal(&sealer, 2)?, before);
    }
    Ok(())
}

#[test]
fn ciphertext_length_bounds() -> TestResult {
    for suite in local_suites() {
        let source = Source::new(counter_input(16_384)?, suite)?;
        let opener = source.opener()?;
        for len in [0, 1, MIN_CIPHERTEXT_LEN - 1, MAX_CIPHERTEXT_LEN + 1, 70_000] {
            assert_eq!(
                opener.open_segment(0, &vec![0; len]).err(),
                Some(ContentError::CiphertextLength)
            );
        }
        for len in [MIN_CIPHERTEXT_LEN, MAX_CIPHERTEXT_LEN] {
            assert_eq!(
                opener.open_segment(0, &vec![0; len]).err(),
                Some(ContentError::Authentication)
            );
        }
        assert_eq!(
            opener.open_segment(1, &[0; 100]).err(),
            Some(ContentError::SegmentOutOfRange)
        );
    }
    Ok(())
}

/// Truncated, extended, or bit-flipped ciphertext never opens.
#[test]
fn tampered_ciphertext_is_rejected() -> TestResult {
    for suite in local_suites() {
        let source = Source::new(counter_input(16_384 + 10)?, suite)?;
        let (sealer, opener) = (source.sealer()?, source.opener()?);
        let ciphertext = source.seal(&sealer, 1)?;
        for cut in 1..=TAG_LEN + 1 {
            assert_eq!(
                opener
                    .open_segment(1, &ciphertext[..ciphertext.len() - cut])
                    .err(),
                Some(ContentError::Authentication)
            );
        }
        let mut longer = ciphertext.clone();
        longer.push(0);
        assert_eq!(
            opener.open_segment(1, &longer).err(),
            Some(ContentError::Authentication)
        );
        for position in 0..ciphertext.len() {
            let mut flipped = ciphertext.clone();
            flipped[position] ^= 1;
            assert_eq!(
                opener.open_segment(1, &flipped).err(),
                Some(ContentError::Authentication)
            );
        }
    }
    Ok(())
}

/// A segment's ciphertext never opens as another segment of the same file.
#[test]
fn reordered_segments_are_rejected() -> TestResult {
    for suite in local_suites() {
        let source = Source::new(counter_input(4 * 16_384)?, suite)?;
        let (sealer, opener) = (source.sealer()?, source.opener()?);
        let ciphertexts: Vec<Vec<u8>> = (0..4)
            .map(|index| source.seal(&sealer, index))
            .collect::<AnyResult<_>>()?;
        for (from, ciphertext) in ciphertexts.iter().enumerate() {
            for to in 0..4 {
                let result = opener.open_segment(to, ciphertext);
                if usize::try_from(to)? == from {
                    assert!(result.is_ok());
                } else {
                    assert_eq!(result.err(), Some(ContentError::Authentication));
                }
            }
        }
    }
    Ok(())
}

/// Bindings that differ in one field each from `base`.
fn variants(base: &FileBinding) -> AnyResult<Vec<(&'static str, FileBinding)>> {
    let size = base.layout().size();
    let mut root = *base.root();
    root[0] ^= 1;
    let mut manifest_hash = *base.manifest_hash();
    manifest_hash[0] ^= 1;
    let rebind = |transfer_id, manifest_hash, file_id, suite, size, root| {
        FileBinding::new(transfer_id, manifest_hash, file_id, suite, size, root)
    };
    let transfer = *base.transfer_id();
    let manifest = *base.manifest_hash();
    let file = base.file_id();
    let suite = base.suite();
    let honest_root = *base.root();
    Ok(vec![
        (
            "transfer",
            rebind([0xb4; 16], manifest, file, suite, size, honest_root)?,
        ),
        (
            "manifest",
            rebind(transfer, manifest_hash, file, suite, size, honest_root)?,
        ),
        (
            "file",
            rebind(transfer, manifest, file + 1, suite, size, honest_root)?,
        ),
        (
            "suite",
            rebind(
                transfer,
                manifest,
                file,
                other_suite(suite),
                size,
                honest_root,
            )?,
        ),
        ("root", rebind(transfer, manifest, file, suite, size, root)?),
    ])
}

/// The same bindings with only the size changed. A real manifest hash
/// commits to the size, so this cannot happen without a different hash;
/// the size is not in the AAD, and the Bao length header alone still
/// catches it after authentication.
fn size_variants(base: &FileBinding) -> AnyResult<Vec<FileBinding>> {
    let size = base.layout().size();
    let rebind = |size| {
        FileBinding::new(
            *base.transfer_id(),
            *base.manifest_hash(),
            base.file_id(),
            base.suite(),
            size,
            *base.root(),
        )
    };
    Ok(vec![rebind(size + 1)?, rebind(size - 1)?])
}

/// Cross-transfer, cross-manifest, cross-file, cross-suite, cross-root and
/// cross-size substitution: each binding is in the key schedule or the
/// AAD, so a segment never opens under a different one.
#[test]
fn substitution_across_bindings_is_rejected() -> TestResult {
    for suite in local_suites() {
        let source = Source::new(counter_input(2 * 16_384 + 100)?, suite)?;
        let sealer = source.sealer()?;
        for (name, binding) in variants(&source.binding)? {
            let file = AcceptedFile::assume_accepted_without_verification(binding);
            let opener = match ContentOpener::new(&file, &master()) {
                Ok(opener) => opener,
                Err(ContentError::SuiteUnavailable) if !aes_available() => continue,
                Err(error) => return Err(error.into()),
            };
            for index in 0..3 {
                let ciphertext = source.seal(&sealer, index)?;
                assert_eq!(
                    opener.open_segment(index, &ciphertext).err(),
                    Some(ContentError::Authentication),
                    "{name} segment {index}"
                );
            }
        }
        for binding in size_variants(&source.binding)? {
            let file = AcceptedFile::assume_accepted_without_verification(binding);
            let opener = ContentOpener::new(&file, &master())?;
            // Segment 0 is full and not final in every variant.
            let ciphertext = source.seal(&sealer, 0)?;
            assert_eq!(
                opener.open_segment(0, &ciphertext).err(),
                Some(ContentError::Integrity)
            );
        }
        // Same file and manifest, another master.
        let other = ContentOpener::new(
            &source.accepted(),
            &FileMaster::from_secret(Zeroizing::new([0x5a; 32])),
        )?;
        let ciphertext = source.seal(&sealer, 0)?;
        assert_eq!(
            other.open_segment(0, &ciphertext).err(),
            Some(ContentError::Authentication)
        );
    }
    Ok(())
}

/// A file of `segments` full segments. Tests use the AEAD layer directly,
/// so no content exists. The manifest hash and root depend on the size, as
/// real ones would.
fn huge(
    suite: ContentSuite,
    segments: u32,
) -> AnyResult<(ContentSealer, ContentOpener, FileBinding)> {
    let size = u64::from(segments) * u64::from(SEGMENT_LEN);
    let mut manifest_hash = MANIFEST_HASH;
    manifest_hash[..4].copy_from_slice(&segments.to_be_bytes());
    let root = *blake3::hash(&size.to_le_bytes()).as_bytes();
    let binding = FileBinding::new(TRANSFER_ID, manifest_hash, 7, suite, size, root)?;
    let file = AcceptedFile::assume_accepted_without_verification(binding);
    Ok((
        ContentSealer::new(&file, &master())?,
        ContentOpener::new(&file, &master())?,
        binding,
    ))
}

/// Each epoch is its own STREAM instance with its own key and prefix: a
/// ciphertext never opens in another epoch, including at the same local
/// index, and the last segment of an epoch is final.
#[test]
fn cross_epoch_substitution_is_rejected() -> TestResult {
    let slice = [0x42; 64];
    for suite in local_suites() {
        let (sealer, opener, binding) = huge(suite, 2 * EPOCH_SEGMENTS + 5)?;
        let layout = binding.layout();
        let indices = [
            0,
            1,
            EPOCH_SEGMENTS - 1,
            EPOCH_SEGMENTS,
            EPOCH_SEGMENTS + 1,
            2 * EPOCH_SEGMENTS - 1,
            2 * EPOCH_SEGMENTS,
            2 * EPOCH_SEGMENTS + 4,
        ];
        for &from in &indices {
            let segment = layout.segment(from)?;
            assert_eq!(
                segment.is_final(),
                from % EPOCH_SEGMENTS == EPOCH_SEGMENTS - 1 || from == layout.count() - 1
            );
            let ciphertext = sealer.seal_raw(&segment, &slice)?;
            for &to in &indices {
                let decrypted = opener.decrypt_raw(&layout.segment(to)?, &ciphertext);
                if to == from {
                    assert_eq!(decrypted?.as_slice(), slice.as_slice());
                } else {
                    assert_eq!(
                        decrypted.err(),
                        Some(ContentError::Authentication),
                        "{from} as {to}"
                    );
                }
            }
        }
    }
    Ok(())
}

/// The final flag is derived from the manifest size and the index, never
/// chosen by the peer: a ciphertext sealed with the flag flipped never
/// opens, and v1 refuses an epoch's last segment without it.
#[test]
fn last_flag_forgery_is_rejected() -> TestResult {
    for suite in local_suites() {
        let source = Source::new(counter_input(3 * 16_384 + 5)?, suite)?;
        let (sealer, opener) = (source.sealer()?, source.opener()?);
        let layout = source.binding.layout();
        for index in 0..layout.count() {
            let honest = source.seal(&sealer, index)?;
            let segment = layout.segment(index)?;
            let slice = opener.decrypt_raw(&segment, &honest)?;
            let forged = sealer.seal_raw(&segment.with_final(!segment.is_final()), &slice)?;
            assert_ne!(forged, honest);
            assert_eq!(
                opener.open_segment(index, &forged).err(),
                Some(ContentError::Authentication)
            );
        }
        let (huge_sealer, _, binding) = huge(suite, EPOCH_SEGMENTS + 1)?;
        let epoch_end = binding.layout().segment(EPOCH_SEGMENTS - 1)?;
        assert!(epoch_end.is_final());
        assert_eq!(
            huge_sealer
                .seal_raw(&epoch_end.with_final(false), &[0; 8])
                .err(),
            Some(ContentError::SegmentOutOfRange)
        );
    }
    Ok(())
}

/// Truncating a file by substituting a final segment fails: the last
/// segment of a shorter or longer version of the file, an epoch-final
/// segment of a longer file, or another file's final segment never opens
/// as this file's segment.
#[test]
fn final_segment_substitution_is_rejected() -> TestResult {
    for suite in local_suites() {
        let long = Source::new(counter_input(3 * 16_384)?, suite)?;
        let short = Source::new(counter_input(2 * 16_384)?, suite)?;
        let other = Source::with_ids(counter_input(3 * 16_384)?, suite, TRANSFER_ID, 2)?;
        let short_final = short.seal(&short.sealer()?, 1)?;
        let long_final = long.seal(&long.sealer()?, 2)?;
        let other_final = other.seal(&other.sealer()?, 2)?;
        let long_opener = long.opener()?;
        assert_eq!(
            long_opener.open_segment(1, &short_final).err(),
            Some(ContentError::Authentication)
        );
        assert_eq!(
            long_opener.open_segment(2, &short_final).err(),
            Some(ContentError::Authentication)
        );
        assert_eq!(
            short.opener()?.open_segment(1, &long_final).err(),
            Some(ContentError::Authentication)
        );
        assert_eq!(
            long_opener.open_segment(2, &other_final).err(),
            Some(ContentError::Authentication)
        );
        // At an epoch boundary: segment 65535 is final in both a
        // 65536-segment and a 65537-segment file, but their manifests
        // differ, so neither opens as the other.
        let (exact_sealer, exact_opener, exact) = huge(suite, EPOCH_SEGMENTS)?;
        let (more_sealer, more_opener, more) = huge(suite, EPOCH_SEGMENTS + 1)?;
        let exact_end = exact.layout().segment(EPOCH_SEGMENTS - 1)?;
        let more_end = more.layout().segment(EPOCH_SEGMENTS - 1)?;
        assert!(exact_end.is_final() && more_end.is_final());
        let slice = [0x11; 40];
        let from_exact = exact_sealer.seal_raw(&exact_end, &slice)?;
        let from_more = more_sealer.seal_raw(&more_end, &slice)?;
        assert_eq!(
            more_opener.decrypt_raw(&more_end, &from_exact).err(),
            Some(ContentError::Authentication)
        );
        assert_eq!(
            exact_opener.decrypt_raw(&exact_end, &from_more).err(),
            Some(ContentError::Authentication)
        );
    }
    Ok(())
}

/// Without approved hardware AES, this device refuses AES files instead of
/// running the slow portable implementation; `XChaCha` is always available.
#[test]
fn suite_availability_is_enforced() -> TestResult {
    let binding = |suite| FileBinding::new(TRANSFER_ID, MANIFEST_HASH, 1, suite, 0, [0; 32]);
    let xchacha = AcceptedFile::assume_accepted_without_verification(binding(
        ContentSuite::XChaCha20Poly1305Stream,
    )?);
    assert!(ContentSealer::new(&xchacha, &master()).is_ok());
    let aes =
        AcceptedFile::assume_accepted_without_verification(binding(ContentSuite::Aes256GcmStream)?);
    assert_eq!(ContentSealer::new(&aes, &master()).is_ok(), aes_available());
    assert_eq!(ContentOpener::new(&aes, &master()).is_ok(), aes_available());
    if !aes_available() {
        assert_eq!(
            ContentOpener::new(&aes, &master()).err(),
            Some(ContentError::SuiteUnavailable)
        );
    }
    Ok(())
}

#[test]
fn debug_output_hides_secrets_and_content() -> TestResult {
    let source = Source::new(
        b"secret file contents".to_vec(),
        ContentSuite::XChaCha20Poly1305Stream,
    )?;
    let sealer = source.sealer()?;
    let opener = source.opener()?;
    let ciphertext = source.seal(&sealer, 0)?;
    let verified = opener.open_segment(0, &ciphertext)?;
    let root_hex = hex::encode(source.binding.root());
    for text in [
        format!("{:?}", master()),
        format!("{sealer:?}"),
        format!("{opener:?}"),
        format!("{verified:?}"),
        format!("{:?}", source.binding),
        format!("{:?}", source.accepted()),
    ] {
        assert!(!text.contains("a5"), "{text}");
        assert!(!text.contains("165"), "{text}");
        assert!(!text.contains("secret"), "{text}");
        assert!(!text.contains(&root_hex[..8]), "{text}");
        assert!(!text.contains("89"), "{text}");
    }
    Ok(())
}
