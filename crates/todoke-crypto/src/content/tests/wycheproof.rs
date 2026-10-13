//! Wycheproof AEAD vectors for both content suites, run through the same
//! wrappers the content layer uses. Provenance: `testdata/wycheproof/README.md`.

use super::{AnyResult, TestResult, testdata};
use crate::content::{ContentSuite, TAG_LEN, aead};
use crate::session::test_vectors::{Vector, hex_at, json_at};

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

/// Counts of (run, skipped) tests.
fn run(file: &str, suite: ContentSuite) -> AnyResult<(usize, usize)> {
    let vectors = testdata(file)?;
    let (mut ran, mut skipped) = (0, 0);
    for group in array(&vectors, "/testGroups")? {
        let applicable = number(group, "/keySize")? == 256
            && number(group, "/tagSize")? == 128
            && usize::try_from(number(group, "/ivSize")?)? == suite.nonce_len() * 8;
        for test in array(group, "/tests")? {
            let id = number(test, "/tcId")?;
            let key: [u8; 32] = match hex_at(test, "/key")?.try_into() {
                Ok(key) if applicable => key,
                _ => {
                    skipped += 1;
                    continue;
                }
            };
            let nonce = hex_at(test, "/iv")?;
            let aad = hex_at(test, "/aad")?;
            let message = hex_at(test, "/msg")?;
            let mut sealed = hex_at(test, "/ct")?;
            sealed.extend_from_slice(&hex_at(test, "/tag")?);
            let valid = match json_at(test, "/result")?.as_str() {
                Some("valid") => true,
                Some("invalid") => false,
                other => return Err(format!("tcId {id}: unexpected result {other:?}").into()),
            };
            let opened = aead::open(suite, &key, &nonce, &aad, &sealed);
            if valid {
                let produced = aead::seal(suite, &key, &nonce, &aad, &message)?;
                assert_eq!(produced, sealed, "tcId {id}: seal");
                let opened = opened.map_err(|e| format!("tcId {id}: open: {e}"))?;
                assert_eq!(opened.as_slice(), message.as_slice(), "tcId {id}: open");
            } else {
                assert!(opened.is_err(), "tcId {id}: accepted an invalid case");
            }
            ran += 1;
        }
    }
    Ok((ran, skipped))
}

/// All AES-256-GCM cases with 96-bit nonces and 128-bit tags (the only
/// parameters suite 1 uses) pass; other key and nonce sizes are skipped.
#[test]
fn aes_256_gcm_wycheproof() -> TestResult {
    let (ran, skipped) = run(
        "wycheproof/aes_gcm_test.json",
        ContentSuite::Aes256GcmStream,
    )?;
    assert_eq!((ran, skipped), (66, 250));
    Ok(())
}

/// The wrappers fail closed on inputs the content layer never passes: an
/// AES nonce that is not 12 bytes, and sealed input shorter than the tag,
/// for both suites. Nothing is returned on failure.
#[test]
fn wrappers_refuse_wrong_nonces_and_short_input() -> TestResult {
    let aes = ContentSuite::Aes256GcmStream;
    for nonce_len in [0, 8, 11, 13, 16, 24] {
        let nonce = vec![0; nonce_len];
        assert!(aead::seal(aes, &[0; 32], &nonce, &[], b"data").is_err());
        assert!(aead::open(aes, &[0; 32], &nonce, &[], &[0; 20]).is_err());
    }
    for suite in [aes, ContentSuite::XChaCha20Poly1305Stream] {
        let nonce = vec![0; suite.nonce_len()];
        let sealed = aead::seal(suite, &[0; 32], &nonce, &[], &[])?;
        assert_eq!(sealed.len(), TAG_LEN);
        assert!(aead::open(suite, &[0; 32], &nonce, &[], &sealed)?.is_empty());
        for len in [0, 1, TAG_LEN - 1] {
            assert!(aead::open(suite, &[0; 32], &nonce, &[], &sealed[..len]).is_err());
        }
    }
    Ok(())
}

/// All XChaCha20-Poly1305 cases with 192-bit nonces pass. The nine cases
/// with other nonce sizes are invalid by construction; the wrapper refuses
/// those nonce lengths outright.
#[test]
fn xchacha20_poly1305_wycheproof() -> TestResult {
    let (ran, skipped) = run(
        "wycheproof/xchacha20_poly1305_test.json",
        ContentSuite::XChaCha20Poly1305Stream,
    )?;
    assert_eq!((ran, skipped), (306, 9));
    for nonce_len in [0, 8, 12, 16, 23, 25, 32] {
        let nonce = vec![0; nonce_len];
        let suite = ContentSuite::XChaCha20Poly1305Stream;
        assert!(aead::seal(suite, &[0; 32], &nonce, &[], &[]).is_err());
        assert!(aead::open(suite, &[0; 32], &nonce, &[], &[0; 16]).is_err());
    }
    Ok(())
}
