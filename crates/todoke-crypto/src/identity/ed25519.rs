//! Validated Ed25519 public keys, signatures, and signing domains (PROTOCOL §1).

use core::fmt;

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::VerifyingKey;
use todoke_proto::identity::{DEVICE_BINDING_DOMAIN, DEVICE_POSSESSION_DOMAIN, REVOKE_DOMAIN};

use super::Hex;
use super::keystore::KeyRole;

/// An Ed25519 public key that passed the §1 checks: canonical point encoding
/// and not of small order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ed25519PublicKey([u8; 32]);

impl Ed25519PublicKey {
    /// Validates a peer-supplied or stored public key.
    ///
    /// Constructing a dalek `VerifyingKey` alone does not establish canonical
    /// encoding, so this decompresses and re-compresses the point and requires
    /// identical bytes. Small-order points are rejected.
    ///
    /// # Errors
    ///
    /// [`InvalidPublicKey`] for any non-canonical, undecodable, or small-order
    /// encoding.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, InvalidPublicKey> {
        let point = CompressedEdwardsY(*bytes)
            .decompress()
            .ok_or(InvalidPublicKey)?;
        if point.compress().to_bytes() != *bytes || point.is_small_order() {
            return Err(InvalidPublicKey);
        }
        Ok(Self(*bytes))
    }

    /// The 32-byte encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Verifies `signature` over `domain || message` with strict rules.
    ///
    /// # Errors
    ///
    /// [`SignatureError`] if verification fails for any reason.
    pub fn verify(
        &self,
        domain: SigningDomain,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        let mut input = Vec::with_capacity(domain.bytes().len() + message.len());
        input.extend_from_slice(domain.bytes());
        input.extend_from_slice(message);
        self.verify_input(&input, signature)
    }

    /// Strict verification of a complete signature input that already starts
    /// with its domain. Rejects non-canonical `s` and `R`, small-order `R`, and
    /// small-order keys (`verify_strict`), in addition to [`Self::from_bytes`].
    pub(crate) fn verify_input(
        &self,
        input: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        let key = VerifyingKey::from_bytes(&self.0).map_err(|_| SignatureError)?;
        if key.is_weak() {
            return Err(SignatureError);
        }
        key.verify_strict(input, &ed25519_dalek::Signature::from_bytes(&signature.0))
            .map_err(|_| SignatureError)
    }
}

impl fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519PublicKey({:?})", Hex(&self.0))
    }
}

/// A 64-byte pure Ed25519 signature (RFC 8032). Public data.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    /// Wraps signature bytes without validating them; validation happens in
    /// [`Ed25519PublicKey::verify`].
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// The 64-byte encoding.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 64] {
        self.0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({:?})", Hex(&self.0))
    }
}

/// Every signature domain defined by PROTOCOL v1. A key store prepends the
/// domain itself, so a caller cannot produce an undomained signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SigningDomain {
    /// `todoke/v1/device-binding\0`, root signature (§2).
    DeviceBinding,
    /// `todoke/v1/device-possession\0`, device signature (§2).
    DevicePossession,
    /// `todoke/v1/revoke\0`, root signature (§2).
    Revoke,
    /// `todoke/v1/identity\0`, device signature (§4.3).
    Identity,
    /// `todoke/v1/accept\0`, receiver device signature (§7.3).
    Accept,
    /// `todoke/v1/delivery-receipt\0`, receiver device signature (§7.7).
    DeliveryReceipt,
}

impl SigningDomain {
    /// The exact domain bytes, including the terminating NUL.
    #[must_use]
    pub const fn bytes(self) -> &'static [u8] {
        match self {
            Self::DeviceBinding => DEVICE_BINDING_DOMAIN,
            Self::DevicePossession => DEVICE_POSSESSION_DOMAIN,
            Self::Revoke => REVOKE_DOMAIN,
            Self::Identity => b"todoke/v1/identity\0",
            Self::Accept => b"todoke/v1/accept\0",
            Self::DeliveryReceipt => b"todoke/v1/delivery-receipt\0",
        }
    }

    /// Whether a key of `role` may sign in this domain. The spec assigns
    /// binding and revocation signatures to the person root and every other
    /// signature to the device key.
    #[must_use]
    pub const fn permits(self, role: KeyRole) -> bool {
        matches!(
            (self, role),
            (Self::DeviceBinding | Self::Revoke, KeyRole::PersonRoot)
                | (
                    Self::DevicePossession | Self::Identity | Self::Accept | Self::DeliveryReceipt,
                    KeyRole::Device
                )
        )
    }
}

/// A public key failed validation. Carries no detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidPublicKey;

impl fmt::Display for InvalidPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid public key")
    }
}

impl std::error::Error for InvalidPublicKey {}

/// A signature failed verification. Carries no detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureError;

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("signature verification failed")
    }
}

impl std::error::Error for SignatureError {}
