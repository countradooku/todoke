//! The 86-byte `FileKey` body (§8) and file masters.

use zeroize::Zeroizing;

use super::{MASTER, TRANSFER_ID, TestResult, master};
use crate::content::{ContentSuite, FILE_KEY_BODY_LEN, FileKeyBody, FileKeyError, FileMaster};

const ACCEPT_HASH: [u8; 32] = [0x6e; 32];

fn body() -> Result<FileKeyBody, FileKeyError> {
    FileKeyBody::new(
        TRANSFER_ID,
        ACCEPT_HASH,
        0x0102_0304,
        ContentSuite::XChaCha20Poly1305Stream,
        master(),
    )
}

#[test]
fn layout_and_round_trip() -> TestResult {
    let body = body()?;
    let encoded = body.encode();
    let mut expected = Vec::new();
    expected.extend_from_slice(&TRANSFER_ID);
    expected.extend_from_slice(&ACCEPT_HASH);
    expected.extend_from_slice(&[1, 2, 3, 4]);
    expected.extend_from_slice(&[0, 2]);
    expected.extend_from_slice(&MASTER);
    assert_eq!(expected.len(), FILE_KEY_BODY_LEN);
    assert_eq!(encoded.as_slice(), expected.as_slice());
    assert_eq!(
        FileKeyBody::peek_transfer_id(encoded.as_slice()),
        Ok(TRANSFER_ID)
    );
    let decoded = FileKeyBody::decode(encoded.as_slice())?;
    assert_eq!(decoded.transfer_id(), &TRANSFER_ID);
    assert_eq!(decoded.accept_hash(), &ACCEPT_HASH);
    assert_eq!(decoded.file_id(), 0x0102_0304);
    assert_eq!(decoded.suite(), ContentSuite::XChaCha20Poly1305Stream);
    assert!(decoded.master().ct_eq(&master()));
    assert_eq!(decoded.encode().as_slice(), encoded.as_slice());
    assert!(decoded.into_master().ct_eq(&master()));
    Ok(())
}

#[test]
fn malformed_bodies_are_rejected() -> TestResult {
    let encoded = body()?.encode();
    for len in [0, 1, 85, 87, 172] {
        let mut bytes = encoded.to_vec();
        bytes.resize(len, 0);
        assert_eq!(
            FileKeyBody::decode(&bytes).err(),
            Some(FileKeyError::Length)
        );
        assert_eq!(
            FileKeyBody::peek_transfer_id(&bytes),
            Err(FileKeyError::Length)
        );
    }
    let with = |range: core::ops::Range<usize>, value: &[u8]| {
        let mut bytes = *encoded;
        bytes[range].copy_from_slice(value);
        FileKeyBody::decode(&bytes).err()
    };
    assert_eq!(with(0..16, &[0; 16]), Some(FileKeyError::TransferId));
    let mut zero_id = *encoded;
    zero_id[..16].copy_from_slice(&[0; 16]);
    assert_eq!(
        FileKeyBody::peek_transfer_id(&zero_id),
        Err(FileKeyError::TransferId)
    );
    // The peek reads the transfer ID only: bodies that fail to decode for
    // another reason still peek.
    let mut bad_suite = *encoded;
    bad_suite[52..54].copy_from_slice(&[0, 0]);
    assert_eq!(FileKeyBody::peek_transfer_id(&bad_suite), Ok(TRANSFER_ID));
    assert_eq!(with(48..52, &[0; 4]), Some(FileKeyError::FileId));
    for suite in [0_u16, 3, 0x0100, u16::MAX] {
        assert_eq!(
            with(52..54, &suite.to_be_bytes()),
            Some(FileKeyError::Suite)
        );
    }
    assert_eq!(with(52..54, &[0, 1]), None);
    // Any accept hash and master decode; their checks are the transfer
    // layer's.
    assert_eq!(with(16..48, &[0; 32]), None);
    assert_eq!(with(54..86, &[0; 32]), None);
    assert_eq!(
        FileKeyBody::new(
            [0; 16],
            ACCEPT_HASH,
            1,
            ContentSuite::Aes256GcmStream,
            master()
        )
        .err(),
        Some(FileKeyError::TransferId)
    );
    assert_eq!(
        FileKeyBody::new(
            TRANSFER_ID,
            ACCEPT_HASH,
            0,
            ContentSuite::Aes256GcmStream,
            master()
        )
        .err(),
        Some(FileKeyError::FileId)
    );
    for error in [
        FileKeyError::Length,
        FileKeyError::TransferId,
        FileKeyError::FileId,
        FileKeyError::Suite,
    ] {
        assert_ne!(error.to_string(), "");
    }
    Ok(())
}

#[test]
fn masters_are_fresh_comparable_and_redacted() -> TestResult {
    let first = FileMaster::generate()?;
    let second = FileMaster::generate()?;
    assert!(!first.ct_eq(&second));
    assert!(first.ct_eq(&first));
    let mut other = MASTER;
    other[31] ^= 1;
    assert!(!master().ct_eq(&FileMaster::from_secret(Zeroizing::new(other))));
    assert_eq!(format!("{first:?}"), "FileMaster([REDACTED])");
    let debug = format!("{:?}", body()?);
    assert!(!debug.contains("165") && !debug.contains("a5"), "{debug}");
    Ok(())
}
