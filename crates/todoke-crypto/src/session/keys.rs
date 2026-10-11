//! Session secrets supplied by callers: the device's X25519 Noise static key
//! and pairing PSKs (PROTOCOL §2, §3, §4.2.2).

use core::fmt;

use zeroize::Zeroizing;

use crate::identity::binding::noise_static_is_valid;
use crate::rng::{self, RandomError};

/// This device's X25519 Noise static key pair (§2: generated independently,
/// never converted from Ed25519). The secret is zeroized on drop and never
/// appears in `Debug` output.
///
/// Durable custody of this key in a [`KeyStore`](crate::identity::KeyStore)
/// backend is not implemented yet; callers hold it in their own protected
/// storage until then.
pub struct NoiseStaticKey {
    secret: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl NoiseStaticKey {
    /// Generates a key from the OS CSPRNG.
    ///
    /// # Errors
    ///
    /// [`RandomError`] if randomness is unavailable.
    pub fn generate() -> Result<Self, RandomError> {
        // A clamped scalar never yields a small-order public key; the loop
        // only guards against a broken source, which then fails closed.
        for _ in 0..4 {
            let mut secret = Zeroizing::new([0; 32]);
            rng::fill(secret.as_mut_slice())?;
            if let Ok(key) = Self::from_secret(secret) {
                return Ok(key);
            }
        }
        Err(RandomError)
    }

    /// Wraps a stored secret and derives its public key.
    ///
    /// # Errors
    ///
    /// [`InvalidNoiseKey`] if the public key is all zero or of small order.
    pub fn from_secret(secret: Zeroizing<[u8; 32]>) -> Result<Self, InvalidNoiseKey> {
        let mut public = [0; 32];
        libcrux_curve25519::secret_to_public(&mut public, &secret);
        if !noise_static_is_valid(&public) {
            return Err(InvalidNoiseKey);
        }
        Ok(Self { secret, public })
    }

    /// The public key, as certified in `DeviceBinding.noise_static`.
    #[must_use]
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public
    }

    pub(crate) fn secret(&self) -> &[u8; 32] {
        &self.secret
    }
}

impl fmt::Debug for NoiseStaticKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NoiseStaticKey([REDACTED])")
    }
}

/// The X25519 secret does not produce a usable public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidNoiseKey;

impl fmt::Display for InvalidNoiseKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid Noise static key")
    }
}

impl std::error::Error for InvalidNoiseKey {}

/// A 32-byte pairing PSK: a QR one-time PSK (§3.1) or a CPace-derived PSK
/// (§3.2). Zeroized on drop; `Debug` is redacted; there is no accessor.
///
/// Contact sessions never use this type: their PSK stays inside the
/// [`ContactStore`](crate::identity::ContactStore).
pub struct PairingPsk(pub(crate) Zeroizing<[u8; 32]>);

impl PairingPsk {
    /// Wraps PSK bytes obtained from a QR payload or the PAKE layer.
    #[must_use]
    pub fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for PairingPsk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingPsk([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_key_validation_and_redaction() -> Result<(), Box<dyn std::error::Error>> {
        let key = NoiseStaticKey::generate()?;
        assert!(noise_static_is_valid(key.public_key()));
        let again = NoiseStaticKey::from_secret(Zeroizing::new(*key.secret()))?;
        assert_eq!(again.public_key(), key.public_key());
        assert_eq!(format!("{key:?}"), "NoiseStaticKey([REDACTED])");
        let psk = PairingPsk::from_bytes(Zeroizing::new([0x55; 32]));
        assert_eq!(format!("{psk:?}"), "PairingPsk([REDACTED])");
        assert_eq!(InvalidNoiseKey.to_string(), "invalid Noise static key");
        Ok(())
    }
}
