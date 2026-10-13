//! The two content AEADs (§8), both from libcrux: AES-256-GCM
//! (libcrux-aes, multiplexed between its hardware and bit-sliced
//! implementations) and XChaCha20-Poly1305 (libcrux-chacha20poly1305's
//! HACL ChaCha20-Poly1305 with an `HChaCha20` subkey). The tag is appended.

use libcrux_aes::{Aead as _, AesGcm256};
use libcrux_chacha20poly1305::xchacha20_poly1305;
use libcrux_secrets::{ClassifyRef as _, ClassifyRefMut as _};
use zeroize::Zeroizing;

use super::{ContentError, ContentSuite, TAG_LEN};

/// Encrypts `plaintext` and returns `ciphertext || tag`.
///
/// `nonce` must have the suite's length (12 or 24 bytes).
pub(crate) fn seal(
    suite: ContentSuite,
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, ContentError> {
    let mut sealed = vec![0; plaintext.len() + TAG_LEN];
    match suite {
        ContentSuite::Aes256GcmStream => {
            let algorithm = AesGcm256;
            let key = algorithm
                .new_key(key.as_slice().classify_ref())
                .map_err(|_| ContentError::Authentication)?;
            let nonce = algorithm
                .new_nonce(nonce.classify_ref())
                .map_err(|_| ContentError::Authentication)?;
            let (ciphertext, tag) = sealed.split_at_mut(plaintext.len());
            let tag = algorithm
                .new_tag_mut(tag.classify_ref_mut())
                .map_err(|_| ContentError::Authentication)?;
            key.encrypt(ciphertext, tag, nonce, aad, plaintext.classify_ref())
                .map_err(|_| ContentError::Authentication)?;
        }
        ContentSuite::XChaCha20Poly1305Stream => {
            let nonce: &[u8; xchacha20_poly1305::NONCE_LEN] =
                nonce.try_into().map_err(|_| ContentError::Authentication)?;
            xchacha20_poly1305::encrypt(key, plaintext, &mut sealed, aad, nonce)
                .map_err(|_| ContentError::Authentication)?;
        }
    }
    Ok(sealed)
}

/// Authenticates and decrypts `ciphertext || tag`. The plaintext is
/// zeroized when dropped; nothing is returned on failure.
pub(crate) fn open(
    suite: ContentSuite,
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ContentError> {
    let len = sealed
        .len()
        .checked_sub(TAG_LEN)
        .ok_or(ContentError::Authentication)?;
    let mut plaintext = Zeroizing::new(vec![0; len]);
    match suite {
        ContentSuite::Aes256GcmStream => {
            let algorithm = AesGcm256;
            let key = algorithm
                .new_key(key.as_slice().classify_ref())
                .map_err(|_| ContentError::Authentication)?;
            let nonce = algorithm
                .new_nonce(nonce.classify_ref())
                .map_err(|_| ContentError::Authentication)?;
            let (ciphertext, tag) = sealed.split_at(len);
            let tag = algorithm
                .new_tag(tag.classify_ref())
                .map_err(|_| ContentError::Authentication)?;
            key.decrypt(
                plaintext.as_mut_slice().classify_ref_mut(),
                nonce,
                aad,
                ciphertext,
                tag,
            )
            .map_err(|_| ContentError::Authentication)?;
        }
        ContentSuite::XChaCha20Poly1305Stream => {
            let nonce: &[u8; xchacha20_poly1305::NONCE_LEN] =
                nonce.try_into().map_err(|_| ContentError::Authentication)?;
            xchacha20_poly1305::decrypt(key, plaintext.as_mut_slice(), sealed, aad, nonce)
                .map_err(|_| ContentError::Authentication)?;
        }
    }
    Ok(plaintext)
}
