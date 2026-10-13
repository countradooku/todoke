//! The committed §8 fixtures: `stream-nonces.json` (STREAM BE32 layouts and
//! `content_key_schedule`) and `manifest-hash.json` (the `hello.txt` file).

use std::io::Cursor;

use super::{AnyResult, TestResult, aes_available, master};
use crate::content::keys::test_hooks::nonce_layout;
use crate::content::keys::{
    AAD_LEN, CONTEXT_LEN, KeySchedule, content_aad, stream_nonce, v1_counter_permitted,
};
use crate::content::{
    AcceptedFile, ContentError, ContentOpener, ContentSealer, ContentSuite, EPOCH_SEGMENTS,
    FileBinding, FileMaster, SEGMENT_LEN, aead, outboard,
};
use crate::session::test_vectors::{Vector, hex_array_at, hex_at, json_at, load};

fn number(value: &Vector, pointer: &str) -> AnyResult<u64> {
    json_at(value, pointer)?
        .as_u64()
        .ok_or_else(|| format!("{pointer} is not a number").into())
}

fn flag(value: &Vector, pointer: &str) -> AnyResult<bool> {
    json_at(value, pointer)?
        .as_bool()
        .ok_or_else(|| format!("{pointer} is not a boolean").into())
}

fn suite(value: &Vector, pointer: &str) -> AnyResult<ContentSuite> {
    let id = u16::try_from(number(value, pointer)?)?;
    Ok(ContentSuite::from_id(id).ok_or("suite")?)
}

#[test]
fn stream_nonce_layouts_match_every_fixture_case() -> TestResult {
    let vector = load("stream-nonces.json")?;
    assert_eq!(
        json_at(&vector, "/construction")?.as_str(),
        Some("STREAM-BE32")
    );
    let cases = json_at(&vector, "/cases")?
        .as_array()
        .ok_or("cases is not an array")?;
    assert_eq!(cases.len(), 16);
    for case in cases {
        let suite = suite(case, "/content_suite")?;
        let prefix = hex_at(case, "/prefix_hex")?;
        assert_eq!(prefix.len(), suite.prefix_len());
        let counter = u32::try_from(number(case, "/counter")?)?;
        let is_final = flag(case, "/final_segment")?;
        let expected = hex_at(case, "/nonce_hex")?;
        assert_eq!(expected.len(), suite.nonce_len());
        let layout = nonce_layout(&prefix, counter, is_final);
        assert_eq!(layout.as_slice(), expected.as_slice());
        let permitted = flag(case, "/v1_counter_and_final_permitted")?;
        assert_eq!(v1_counter_permitted(counter, is_final), permitted);
        // The checked constructor produces the same bytes exactly when v1
        // permits the combination.
        match stream_nonce(&prefix, counter, is_final) {
            Ok(nonce) => {
                assert!(permitted);
                assert_eq!(nonce.as_slice(), expected.as_slice());
            }
            Err(error) => {
                assert!(!permitted);
                assert_eq!(error, ContentError::SegmentOutOfRange);
            }
        }
    }
    Ok(())
}

/// The checked constructor takes prefixes up to the `XChaCha` length (19
/// bytes, a 24-byte nonce) and refuses longer ones instead of writing past
/// the nonce buffer.
#[test]
fn stream_nonce_refuses_an_overlong_prefix() -> TestResult {
    let nonce = stream_nonce(&[0x19; 19], 1, false)?;
    assert_eq!(nonce.as_slice().len(), 24);
    assert_eq!(&nonce.as_slice()[19..], &[0, 0, 0, 1, 0]);
    assert_eq!(
        stream_nonce(&[0x20; 20], 1, false).err(),
        Some(ContentError::SegmentOutOfRange)
    );
    Ok(())
}

/// A file large enough that epoch 1's first segment exists and is not the
/// last one.
fn schedule_binding(schedule: &Vector, suite: ContentSuite) -> AnyResult<FileBinding> {
    let size = u64::from(EPOCH_SEGMENTS + 2) * u64::from(SEGMENT_LEN);
    Ok(FileBinding::new(
        hex_array_at(schedule, "/transfer_id_hex")?,
        hex_array_at(schedule, "/manifest_hash_hex")?,
        u32::try_from(number(schedule, "/file_id")?)?,
        suite,
        size,
        [0x77; 32],
    )?)
}

#[test]
fn content_key_schedule_matches_every_fixture_case() -> TestResult {
    let vector = load("stream-nonces.json")?;
    let schedule = json_at(&vector, "/content_key_schedule")?;
    assert_eq!(
        json_at(schedule, "/algorithm")?.as_str(),
        Some("HKDF-SHA-256, salt = manifest_hash, IKM = file_master")
    );
    let master = FileMaster::from_secret(hex_array_at::<32>(schedule, "/file_master_hex")?.into());
    let cases = json_at(schedule, "/cases")?
        .as_array()
        .ok_or("cases is not an array")?;
    assert_eq!(cases.len(), 4);
    for case in cases {
        let suite = suite(case, "/content_suite")?;
        let binding = schedule_binding(schedule, suite)?;
        let keys = KeySchedule::new(&binding, &master)?;
        let epoch = u32::try_from(number(case, "/content_epoch")?)?;
        let context = keys.context(epoch);
        assert_eq!(context.len(), CONTEXT_LEN);
        assert_eq!(context, hex_array_at::<CONTEXT_LEN>(case, "/context_hex")?);
        let key_info = hex_at(case, "/key_info_hex")?;
        assert_eq!(&key_info[..22], b"todoke/v1/content-key\0");
        assert_eq!(&key_info[22..], context.as_slice());
        let nonce_info = hex_at(case, "/nonce_info_hex")?;
        assert_eq!(&nonce_info[..24], b"todoke/v1/content-nonce\0");
        assert_eq!(&nonce_info[24..], context.as_slice());
        let epoch_keys = keys.epoch_keys(epoch)?;
        assert_eq!(
            *epoch_keys.key(),
            hex_array_at::<32>(case, "/content_key_hex")?
        );
        assert_eq!(epoch_keys.prefix(), hex_at(case, "/nonce_prefix_hex")?);
        // The epoch's first segment is not the file's last, so not final.
        let first = u32::try_from(number(case, "/first_segment_index")?)?;
        assert_eq!(first, epoch * EPOCH_SEGMENTS);
        let segment = binding.layout().segment(first)?;
        assert!(!segment.is_final());
        assert_eq!(
            epoch_keys.nonce(&segment)?.as_slice(),
            hex_at(case, "/first_nonce_nonfinal_hex")?
        );
    }
    Ok(())
}

/// The §8 AAD table written out field by field, independently of
/// `content_aad`: domain, version 1, transfer ID, manifest hash, file ID,
/// suite, epoch, global segment index, logical length, final, root.
fn spec_aad(binding: &FileBinding, epoch: u32, index: u32, len: u32, is_final: bool) -> Vec<u8> {
    let mut aad = b"todoke/v1/content-aad\0".to_vec();
    aad.extend_from_slice(&[0, 1]);
    aad.extend_from_slice(binding.transfer_id());
    aad.extend_from_slice(binding.manifest_hash());
    aad.extend_from_slice(&binding.file_id().to_be_bytes());
    aad.extend_from_slice(&binding.suite().id().to_be_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&len.to_be_bytes());
    aad.push(u8::from(is_final));
    aad.extend_from_slice(binding.root());
    aad
}

/// Every sealed segment uses exactly its epoch's fixture key, a nonce built
/// from that epoch's fixture prefix, its local index, and its final flag,
/// and the §8 AAD with the global index and its epoch. The sealer's output
/// opens under those independently assembled parameters, and the opener
/// accepts what they seal. Segments 65535 and 65536 straddle the epoch
/// boundary, so reusing one epoch's key or nonce for another, putting the
/// local index or a constant final flag in the AAD, or swapping AAD fields
/// all fail here.
#[test]
fn sealed_segments_use_the_fixture_epoch_keys_nonces_and_aad() -> TestResult {
    let vector = load("stream-nonces.json")?;
    let schedule = json_at(&vector, "/content_key_schedule")?;
    let master = FileMaster::from_secret(hex_array_at::<32>(schedule, "/file_master_hex")?.into());
    let cases = json_at(schedule, "/cases")?
        .as_array()
        .ok_or("cases is not an array")?;
    // (index, epoch, local index, final) in a file of 65538 full segments.
    let segments = [
        (0, 0, 0, false),
        (1, 0, 1, false),
        (65_535, 0, 65_535, true),
        (65_536, 1, 0, false),
        (65_537, 1, 1, true),
    ];
    let mut checked = 0;
    for suite in [
        ContentSuite::Aes256GcmStream,
        ContentSuite::XChaCha20Poly1305Stream,
    ] {
        let binding = schedule_binding(schedule, suite)?;
        assert_eq!(binding.layout().count(), EPOCH_SEGMENTS + 2);
        let file = AcceptedFile::assume_accepted_without_verification(binding);
        let (sealer, opener) = match (
            ContentSealer::new(&file, &master),
            ContentOpener::new(&file, &master),
        ) {
            (Ok(sealer), Ok(opener)) => (sealer, opener),
            (Err(ContentError::SuiteUnavailable), Err(ContentError::SuiteUnavailable))
                if !aes_available() && suite == ContentSuite::Aes256GcmStream =>
            {
                continue;
            }
            _ => return Err("cipher setup failed".into()),
        };
        for (index, epoch, local, is_final) in segments {
            let case = cases
                .iter()
                .find(|case| {
                    number(case, "/content_suite").ok() == Some(u64::from(suite.id()))
                        && number(case, "/content_epoch").ok() == Some(u64::from(epoch))
                })
                .ok_or("no fixture case for this suite and epoch")?;
            let key = hex_array_at::<32>(case, "/content_key_hex")?;
            let mut nonce = hex_at(case, "/nonce_prefix_hex")?;
            nonce.extend_from_slice(&u32::to_be_bytes(local));
            nonce.push(u8::from(is_final));
            if local == 0 && !is_final {
                assert_eq!(nonce, hex_at(case, "/first_nonce_nonfinal_hex")?);
            }
            let segment = binding.layout().segment(index)?;
            assert_eq!(
                (segment.epoch(), u32::from(segment.local_index())),
                (epoch, local)
            );
            assert_eq!(segment.is_final(), is_final);
            let aad = spec_aad(&binding, epoch, index, SEGMENT_LEN, is_final);
            assert_eq!(aad.len(), AAD_LEN);
            assert_eq!(content_aad(&binding, &segment).as_slice(), aad.as_slice());

            let slice: Vec<u8> = (0..40_u8)
                .map(|byte| byte ^ index.to_be_bytes()[3])
                .collect();
            let ciphertext = sealer.seal_raw(&segment, &slice)?;
            let plaintext = aead::open(suite, &key, &nonce, &aad, &ciphertext)
                .map_err(|_| format!("segment {index} is not sealed under the fixture"))?;
            assert_eq!(plaintext.as_slice(), slice.as_slice());
            let independent = aead::seal(suite, &key, &nonce, &aad, &slice)?;
            assert_eq!(independent, ciphertext);
            assert_eq!(
                opener.decrypt_raw(&segment, &independent)?.as_slice(),
                slice.as_slice()
            );
            checked += 1;
        }
    }
    assert!(checked >= segments.len());
    Ok(())
}

#[test]
fn aad_and_nonce_for_the_manifest_fixture_segment() -> TestResult {
    let vector = load("stream-nonces.json")?;
    let schedule = json_at(&vector, "/content_key_schedule")?;
    let example = json_at(schedule, "/aad_example")?;
    let manifest = load("manifest-hash.json")?;
    let content = hex_at(&manifest, "/entries/0/content_hex")?;
    let (_, root) = outboard(&content);
    assert_eq!(root, hex_array_at::<32>(example, "/root_hex")?);
    // The example is the manifest fixture's file: same transfer, manifest
    // hash, entry ID, and suite.
    let transfer_id = hex_array_at::<16>(schedule, "/transfer_id_hex")?;
    let manifest_hash = hex_array_at::<32>(schedule, "/manifest_hash_hex")?;
    assert_eq!(
        transfer_id,
        hex_array_at::<16>(&manifest, "/transfer_id_hex")?
    );
    assert_eq!(
        manifest_hash,
        hex_array_at::<32>(&manifest, "/manifest_hash_hex")?
    );
    let file_id = u32::try_from(number(&manifest, "/entries/0/id")?)?;
    assert_eq!(u64::from(file_id), number(schedule, "/file_id")?);
    assert_eq!(
        suite(example, "/content_suite")?,
        suite(&manifest, "/entries/0/content_suite")?
    );
    let binding = FileBinding::new(
        transfer_id,
        manifest_hash,
        file_id,
        suite(example, "/content_suite")?,
        u64::try_from(content.len())?,
        root,
    )?;
    let index = u32::try_from(number(example, "/segment_index")?)?;
    let segment = binding.layout().segment(index)?;
    assert_eq!(binding.layout().count(), 1);
    assert_eq!(
        u64::from(segment.epoch()),
        number(example, "/content_epoch")?
    );
    assert_eq!(
        u64::from(segment.len()),
        number(example, "/logical_length")?
    );
    assert_eq!(segment.is_final(), flag(example, "/final_segment")?);
    let aad = content_aad(&binding, &segment);
    assert_eq!(aad.len(), AAD_LEN);
    assert_eq!(usize::try_from(number(example, "/aad_length")?)?, AAD_LEN);
    assert_eq!(aad.as_slice(), hex_at(example, "/aad_hex")?);
    let master = FileMaster::from_secret(hex_array_at::<32>(schedule, "/file_master_hex")?.into());
    let keys = KeySchedule::new(&binding, &master)?.epoch_keys(0)?;
    assert_eq!(
        keys.nonce(&segment)?.as_slice(),
        hex_at(example, "/nonce_hex")?
    );
    Ok(())
}

#[test]
fn manifest_fixture_file_root_and_round_trip() -> TestResult {
    let manifest = load("manifest-hash.json")?;
    let content = hex_at(&manifest, "/entries/0/content_hex")?;
    assert_eq!(content, b"hello\n");
    let root = hex_array_at::<32>(&manifest, "/entries/0/plaintext_blake3_root_hex")?;
    let (tree, computed) = outboard(&content);
    assert_eq!(computed, root);
    assert_eq!(*blake3::hash(&content).as_bytes(), root);
    // One chunk: the outboard is the length header alone.
    assert_eq!(tree, 6_u64.to_le_bytes());
    assert_eq!(
        u64::try_from(content.len())?,
        number(&manifest, "/entries/0/size")?
    );
    // The manifest hash itself (§7.1).
    let mut hasher = blake3::Hasher::new();
    hasher.update(&hex_at(&manifest, "/hash_domain_hex")?);
    hasher.update(&hex_at(&manifest, "/canonical_hex")?);
    let manifest_hash = hex_array_at::<32>(&manifest, "/manifest_hash_hex")?;
    assert_eq!(*hasher.finalize().as_bytes(), manifest_hash);

    let binding = FileBinding::new(
        hex_array_at(&manifest, "/transfer_id_hex")?,
        manifest_hash,
        1,
        suite(&manifest, "/entries/0/content_suite")?,
        6,
        root,
    )?;
    let file = AcceptedFile::assume_accepted_without_verification(binding);
    if !aes_available() {
        assert_eq!(
            ContentSealer::new(&file, &master()).err(),
            Some(ContentError::SuiteUnavailable)
        );
        return Ok(());
    }
    let sealer = ContentSealer::new(&file, &master())?;
    let ciphertext = sealer.seal_segment(0, Cursor::new(&content), Cursor::new(&tree))?;
    // Header (8) + one 6-byte chunk + tag (16).
    assert_eq!(ciphertext.len(), 8 + 6 + 16);
    let opened = ContentOpener::new(&file, &master())?.open_segment(0, &ciphertext)?;
    assert_eq!(opened.data(), b"hello\n");
    Ok(())
}
