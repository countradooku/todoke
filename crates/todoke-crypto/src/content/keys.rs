//! The §8 key schedule: file masters, per-epoch keys and nonce prefixes,
//! STREAM BE32 nonces, and the 123-byte AAD.

use core::fmt;

use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use super::{ContentError, ContentSuite, FileBinding, Segment};
use crate::rng::{self, RandomError};
use crate::session::kdf::{hkdf_sha256_expand, hkdf_sha256_extract};

const KEY_DOMAIN: &[u8] = b"todoke/v1/content-key\0";
const NONCE_DOMAIN: &[u8] = b"todoke/v1/content-nonce\0";
const AAD_DOMAIN: &[u8] = b"todoke/v1/content-aad\0";

/// The §8 HKDF context: `transfer_id || file_id:u32 || content_suite:u16 ||
/// content_epoch:u32`.
pub(crate) const CONTEXT_LEN: usize = 26;
/// The §8 associated data length.
pub(crate) const AAD_LEN: usize = 123;
/// The longest nonce prefix (`XChaCha`, 19 bytes).
const MAX_PREFIX_LEN: usize = 19;
/// The longest nonce (`XChaCha`, 24 bytes).
pub(crate) const MAX_NONCE_LEN: usize = MAX_PREFIX_LEN + 5;
/// The largest STREAM counter v1 uses: `local_index` stays below 65536 (§8).
const MAX_V1_COUNTER: u32 = super::EPOCH_SEGMENTS - 1;

/// A regular file's fresh 32-byte random master key (§8). One per file;
/// never reused across files, recipients, or transfer IDs. Zeroized on drop
/// and never printed.
pub struct FileMaster(Zeroizing<[u8; 32]>);

impl FileMaster {
    /// Draws a new master from the OS CSPRNG.
    ///
    /// # Errors
    ///
    /// [`RandomError`] if randomness is unavailable.
    pub fn generate() -> Result<Self, RandomError> {
        let mut master = Zeroizing::new([0; 32]);
        rng::fill(master.as_mut_slice())?;
        Ok(Self(master))
    }

    /// Wraps a master restored from the platform's sealed secret storage
    /// (§8). The caller must keep its own copy, if any, zeroizing.
    #[must_use]
    pub fn from_secret(secret: Zeroizing<[u8; 32]>) -> Self {
        Self(secret)
    }

    /// Constant-time equality, for the transfer layer's "an identical
    /// `FileKey` is idempotent, a different one is fatal" rule (§8).
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.as_slice().ct_eq(other.0.as_slice()).into()
    }

    pub(crate) fn secret(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for FileMaster {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FileMaster([REDACTED])")
    }
}

/// One file's derivation state. HKDF-Extract does not depend on the epoch,
/// so the pseudorandom key `HMAC-SHA-256(manifest_hash, file_master)` is
/// computed once and each epoch only runs Expand.
pub(crate) struct KeySchedule {
    prk: Zeroizing<[u8; 32]>,
    transfer_id: [u8; 16],
    file_id: u32,
    suite: ContentSuite,
}

impl KeySchedule {
    pub(crate) fn new(binding: &FileBinding, master: &FileMaster) -> Result<Self, ContentError> {
        let prk = hkdf_sha256_extract(binding.manifest_hash(), master.secret())
            .map_err(|_| ContentError::KeyDerivation)?;
        Ok(Self {
            prk,
            transfer_id: *binding.transfer_id(),
            file_id: binding.file_id(),
            suite: binding.suite(),
        })
    }

    /// `transfer_id || file_id:u32 || content_suite:u16 || content_epoch:u32`.
    pub(crate) fn context(&self, epoch: u32) -> [u8; CONTEXT_LEN] {
        let mut context = [0; CONTEXT_LEN];
        context[..16].copy_from_slice(&self.transfer_id);
        context[16..20].copy_from_slice(&self.file_id.to_be_bytes());
        context[20..22].copy_from_slice(&self.suite.id().to_be_bytes());
        context[22..].copy_from_slice(&epoch.to_be_bytes());
        context
    }

    /// `key = HKDF(manifest_hash, file_master, "todoke/v1/content-key\0" ||
    /// context, 32)` and `prefix = HKDF(…, "todoke/v1/content-nonce\0" ||
    /// context, N)`, N = 7 (AES) or 19 (`XChaCha`).
    pub(crate) fn epoch_keys(&self, epoch: u32) -> Result<EpochKeys, ContentError> {
        let context = self.context(epoch);
        let mut info = [0; NONCE_DOMAIN.len() + CONTEXT_LEN];
        let key_info = labeled(&mut info, KEY_DOMAIN, &context);
        let mut key = Zeroizing::new([0; 32]);
        hkdf_sha256_expand(&self.prk, key_info, key.as_mut_slice())
            .map_err(|_| ContentError::KeyDerivation)?;
        let nonce_info = labeled(&mut info, NONCE_DOMAIN, &context);
        let mut prefix = Zeroizing::new([0; MAX_PREFIX_LEN]);
        let prefix_len = self.suite.prefix_len();
        hkdf_sha256_expand(&self.prk, nonce_info, &mut prefix[..prefix_len])
            .map_err(|_| ContentError::KeyDerivation)?;
        Ok(EpochKeys {
            suite: self.suite,
            key,
            prefix,
        })
    }
}

/// Writes `domain || context` into `buffer` and returns that prefix.
fn labeled<'a>(buffer: &'a mut [u8], domain: &[u8], context: &[u8]) -> &'a [u8] {
    let len = domain.len() + context.len();
    buffer[..domain.len()].copy_from_slice(domain);
    buffer[domain.len()..len].copy_from_slice(context);
    &buffer[..len]
}

/// One epoch's STREAM instance: key and nonce prefix.
pub(crate) struct EpochKeys {
    suite: ContentSuite,
    key: Zeroizing<[u8; 32]>,
    prefix: Zeroizing<[u8; MAX_PREFIX_LEN]>,
}

impl EpochKeys {
    pub(crate) fn key(&self) -> &[u8; 32] {
        &self.key
    }

    #[cfg(test)]
    pub(crate) fn prefix(&self) -> &[u8] {
        &self.prefix[..self.suite.prefix_len()]
    }

    /// The nonce for `segment` in this epoch.
    pub(crate) fn nonce(&self, segment: &Segment) -> Result<StreamNonce, ContentError> {
        stream_nonce(
            &self.prefix[..self.suite.prefix_len()],
            u32::from(segment.local_index()),
            segment.is_final(),
        )
    }
}

/// A STREAM BE32 nonce: `prefix || counter:u32 BE || final:u8` (12 or 24
/// bytes). Public, but derived from the secret schedule.
pub(crate) struct StreamNonce {
    bytes: [u8; MAX_NONCE_LEN],
    len: usize,
}

impl StreamNonce {
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// `RustCrypto` STREAM BE32 nonce layout (§8). v1 uses counters 0..=65535
/// only, and counter 65535 only as a final segment; anything else fails.
pub(crate) fn stream_nonce(
    prefix: &[u8],
    counter: u32,
    is_final: bool,
) -> Result<StreamNonce, ContentError> {
    if !v1_counter_permitted(counter, is_final) || prefix.len() > MAX_PREFIX_LEN {
        return Err(ContentError::SegmentOutOfRange);
    }
    Ok(stream_nonce_layout(prefix, counter, is_final))
}

/// The primitive layout for any counter, including ones v1 forbids.
fn stream_nonce_layout(prefix: &[u8], counter: u32, is_final: bool) -> StreamNonce {
    let mut bytes = [0; MAX_NONCE_LEN];
    let len = prefix.len() + 5;
    bytes[..prefix.len()].copy_from_slice(prefix);
    bytes[prefix.len()..len - 1].copy_from_slice(&counter.to_be_bytes());
    bytes[len - 1] = u8::from(is_final);
    StreamNonce { bytes, len }
}

/// Whether v1 may use this counter/final combination (§8): the counter
/// stays within one epoch, and an epoch's last counter is always final.
pub(crate) const fn v1_counter_permitted(counter: u32, is_final: bool) -> bool {
    counter < MAX_V1_COUNTER || (counter == MAX_V1_COUNTER && is_final)
}

/// The §8 associated data, rebuilt from the accepted manifest and the
/// requested segment, never taken from the peer.
pub(crate) fn content_aad(binding: &FileBinding, segment: &Segment) -> [u8; AAD_LEN] {
    let mut aad = [0; AAD_LEN];
    let mut at = 0;
    let mut put = |bytes: &[u8]| {
        aad[at..at + bytes.len()].copy_from_slice(bytes);
        at += bytes.len();
    };
    put(AAD_DOMAIN);
    put(&1_u16.to_be_bytes());
    put(binding.transfer_id());
    put(binding.manifest_hash());
    put(&binding.file_id().to_be_bytes());
    put(&binding.suite().id().to_be_bytes());
    put(&segment.epoch().to_be_bytes());
    put(&segment.index().to_be_bytes());
    put(&segment.len().to_be_bytes());
    put(&[u8::from(segment.is_final())]);
    put(binding.root());
    aad
}

#[cfg(test)]
pub(crate) mod test_hooks {
    //! Unchecked layouts for the fixture tests, which include counters v1
    //! forbids.
    use super::{StreamNonce, stream_nonce_layout};

    pub(crate) fn nonce_layout(prefix: &[u8], counter: u32, is_final: bool) -> StreamNonce {
        stream_nonce_layout(prefix, counter, is_final)
    }
}
