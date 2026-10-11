//! Sealing of local secret state at rest: the platform hook for key and
//! contact storage.
//!
//! Local storage formats are not wire formats and are not part of PROTOCOL v1.
//! They are versioned so they can change without silent reinterpretation.

use core::fmt;

use libcrux_chacha20poly1305::{KEY_LEN, NONCE_LEN, TAG_LEN};
use zeroize::Zeroizing;

use crate::rng::{self, RandomError};

/// Authenticated encryption of local secret blobs under a key the backend
/// protects.
///
/// A software implementation holds the key in process memory. A platform
/// implementation can keep it in hardware or an OS secret service. `context`
/// is associated data: `open` must fail unless it matches the `seal` call.
pub trait Sealer {
    /// Encrypts and authenticates `plaintext`, binding `context`.
    ///
    /// # Errors
    ///
    /// [`SealError`] on backend or randomness failure.
    fn seal(&self, context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SealError>;

    /// Authenticates and decrypts `sealed`.
    ///
    /// # Errors
    ///
    /// [`SealError`] on wrong key, wrong context, tampering, or truncation.
    fn open(&self, context: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError>;
}

/// A 256-bit symmetric key for local storage. Zeroized on drop; `Debug` is
/// redacted.
pub struct StorageKey(Zeroizing<[u8; KEY_LEN]>);

impl StorageKey {
    /// Generates a key from the OS CSPRNG.
    ///
    /// # Errors
    ///
    /// [`RandomError`] if randomness is unavailable.
    pub fn generate() -> Result<Self, RandomError> {
        let mut key = Zeroizing::new([0; KEY_LEN]);
        rng::fill(key.as_mut())?;
        Ok(Self(key))
    }

    /// Wraps caller-held key bytes, for example a key released by a platform
    /// secret store. Never pass these across FFI.
    #[must_use]
    pub fn from_bytes(bytes: Zeroizing<[u8; KEY_LEN]>) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for StorageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StorageKey([REDACTED])")
    }
}

/// [`Sealer`] using libcrux ChaCha20-Poly1305 with a fresh random 96-bit nonce
/// per call. Output: `nonce[12] || ciphertext || tag[16]`.
///
/// Random nonces are safe here because a storage key seals few messages over
/// its lifetime (one per persisted change), far below the collision bound.
///
/// Libcrux's internal scratch state is not covered by an audited zeroization
/// guarantee (O6).
pub struct SoftwareSealer {
    key: StorageKey,
}

impl SoftwareSealer {
    /// Overhead added by [`Sealer::seal`].
    pub const OVERHEAD: usize = NONCE_LEN + TAG_LEN;

    /// Creates a sealer that owns `key`.
    #[must_use]
    pub fn new(key: StorageKey) -> Self {
        Self { key }
    }
}

impl fmt::Debug for SoftwareSealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SoftwareSealer([REDACTED])")
    }
}

impl Sealer for SoftwareSealer {
    fn seal(&self, context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        seal_with(&self.key, context, plaintext)
    }

    fn open(&self, context: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
        open_with(&self.key, context, sealed)
    }
}

pub(crate) fn seal_with(
    key: &StorageKey,
    context: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, SealError> {
    let total = plaintext
        .len()
        .checked_add(SoftwareSealer::OVERHEAD)
        .ok_or(SealError)?;
    let mut nonce = [0; NONCE_LEN];
    rng::fill(&mut nonce).map_err(|_| SealError)?;
    let mut out = vec![0; total];
    let (head, body) = out.split_at_mut(NONCE_LEN);
    head.copy_from_slice(&nonce);
    libcrux_chacha20poly1305::encrypt(&key.0, plaintext, body, context, &nonce)
        .map_err(|_| SealError)?;
    Ok(out)
}

pub(crate) fn open_with(
    key: &StorageKey,
    context: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let (nonce, body) = sealed.split_first_chunk::<NONCE_LEN>().ok_or(SealError)?;
    let length = body.len().checked_sub(TAG_LEN).ok_or(SealError)?;
    let mut plaintext = Zeroizing::new(vec![0; length]);
    libcrux_chacha20poly1305::decrypt(&key.0, &mut plaintext, body, context, nonce)
        .map_err(|_| SealError)?;
    Ok(plaintext)
}

/// Sealing or unsealing failed. Deliberately indistinguishable causes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealError;

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sealing failed")
    }
}

impl std::error::Error for SealError {}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn round_trip_and_context_binding() -> TestResult {
        let software = SoftwareSealer::new(StorageKey::generate()?);
        let sealed = software.seal(b"ctx", b"secret bytes")?;
        assert_eq!(sealed.len(), 12 + SoftwareSealer::OVERHEAD);
        assert_eq!(software.open(b"ctx", &sealed)?.as_slice(), b"secret bytes");
        assert_eq!(software.open(b"other", &sealed), Err(SealError));
        Ok(())
    }

    #[test]
    fn nonces_are_fresh() -> TestResult {
        let software = SoftwareSealer::new(StorageKey::generate()?);
        assert_ne!(software.seal(b"", b"x")?, software.seal(b"", b"x")?);
        Ok(())
    }

    #[test]
    fn rejects_tampering_truncation_and_wrong_key() -> TestResult {
        let software = SoftwareSealer::new(StorageKey::generate()?);
        let sealed = software.seal(b"ctx", b"payload")?;
        for index in 0..sealed.len() {
            let mut changed = sealed.clone();
            changed[index] ^= 1;
            assert_eq!(software.open(b"ctx", &changed), Err(SealError));
        }
        for length in 0..sealed.len() {
            assert_eq!(software.open(b"ctx", &sealed[..length]), Err(SealError));
        }
        let other = SoftwareSealer::new(StorageKey::generate()?);
        assert_eq!(other.open(b"ctx", &sealed), Err(SealError));
        Ok(())
    }

    #[test]
    fn empty_plaintext_is_supported() -> TestResult {
        let software = SoftwareSealer::new(StorageKey::generate()?);
        let sealed = software.seal(b"", b"")?;
        assert!(software.open(b"", &sealed)?.is_empty());
        Ok(())
    }

    #[test]
    fn debug_is_redacted() {
        let key = Zeroizing::new([0x42; 32]);
        let rendered = format!("{:?}", SoftwareSealer::new(StorageKey::from_bytes(key)));
        assert!(!rendered.contains("42"));
        assert!(rendered.contains("REDACTED"));
    }
}
