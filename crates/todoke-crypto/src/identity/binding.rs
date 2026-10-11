//! Person roots and the device bindings they sign (PROTOCOL §2).

use core::fmt;
use core::num::NonZeroU64;

use libcrux_ml_kem::mlkem768::{self, MlKem768PublicKey};
use todoke_proto::identity::{DeviceBinding, DeviceBindingBody, KEM_STATIC_LEN};
use todoke_proto::time::UnixTime;

use super::ed25519::{Ed25519PublicKey, Signature, SigningDomain};
use super::ids::{DeviceId, PersonId};
use super::keystore::{KeyId, KeyRole, KeyStore, KeyStoreError};
use super::revocation::RevocationSet;

/// Maximum clock skew tolerated in validity comparisons (§1).
pub const CLOCK_SKEW_SECONDS: u64 = 120;

/// A person's Ed25519 root public key that the caller already trusts.
///
/// Trust must originate in an authenticated pairing or an explicit local
/// enrollment, never in a self-signature (§2). Constructing this value is the
/// caller's assertion of that trust.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PersonIdentity {
    root: Ed25519PublicKey,
}

impl PersonIdentity {
    /// Wraps a trusted root key.
    #[must_use]
    pub const fn new(root: Ed25519PublicKey) -> Self {
        Self { root }
    }

    /// The full root public key.
    #[must_use]
    pub fn root(&self) -> &Ed25519PublicKey {
        &self.root
    }

    /// The truncated person ID.
    #[must_use]
    pub fn id(&self) -> PersonId {
        PersonId::of(&self.root)
    }

    /// Validates a device binding (a per-device subkey certificate) against
    /// this root at `now`.
    ///
    /// Checks, in order: the binding names this exact root; every key is valid
    /// (Ed25519 canonical and not small order, ML-KEM-768 FIPS 203 input check);
    /// both signatures verify strictly; `now` is within
    /// `[not_before, not_after)` allowing [`CLOCK_SKEW_SECONDS`]; the root is
    /// not disabled; and no retained revocation covers the binding's serial.
    ///
    /// `now` must come from a trusted clock. An unknown or regressed clock
    /// requires local confirmation instead (§1).
    ///
    /// # Errors
    ///
    /// The first failed check, as a [`BindingError`].
    pub fn verify_binding(
        &self,
        binding: &DeviceBinding,
        now: UnixTime,
        revocations: &RevocationSet,
    ) -> Result<VerifiedDeviceBinding, BindingError> {
        let verified = self.verify_binding_signatures(binding)?;
        check_validity(binding.body(), now)?;
        if revocations.is_root_disabled(&self.root) {
            return Err(BindingError::RootDisabled);
        }
        if revocations.is_revoked(&self.root, &verified.device_public, verified.serial()) {
            return Err(BindingError::Revoked);
        }
        Ok(verified)
    }

    /// Structure and signature checks only: no time or revocation policy.
    pub(crate) fn verify_binding_signatures(
        &self,
        binding: &DeviceBinding,
    ) -> Result<VerifiedDeviceBinding, BindingError> {
        let body = binding.body();
        if body.person_root() != self.root.as_bytes() {
            return Err(BindingError::UntrustedRoot);
        }
        let device_public = Ed25519PublicKey::from_bytes(body.device_public())
            .map_err(|_| BindingError::InvalidKey)?;
        if !kem_static_is_valid(body.kem_static()) {
            return Err(BindingError::InvalidKey);
        }
        self.root
            .verify_input(
                &body.root_signing_input(),
                &Signature::from_bytes(*binding.root_signature()),
            )
            .map_err(|_| BindingError::InvalidSignature)?;
        device_public
            .verify_input(
                &body.possession_signing_input(binding.root_signature()),
                &Signature::from_bytes(*binding.device_signature()),
            )
            .map_err(|_| BindingError::InvalidSignature)?;
        Ok(VerifiedDeviceBinding {
            binding: binding.clone(),
            person_root: self.root,
            device_public,
        })
    }
}

fn kem_static_is_valid(kem_static: &[u8; KEM_STATIC_LEN]) -> bool {
    mlkem768::validate_public_key(&MlKem768PublicKey::from(kem_static))
}

fn check_validity(body: &DeviceBindingBody, now: UnixTime) -> Result<(), BindingError> {
    let now = now.seconds();
    if now.saturating_add(CLOCK_SKEW_SECONDS) < body.not_before().seconds() {
        return Err(BindingError::NotYetValid);
    }
    if now
        >= body
            .not_after()
            .seconds()
            .saturating_add(CLOCK_SKEW_SECONDS)
    {
        return Err(BindingError::Expired);
    }
    Ok(())
}

/// A [`DeviceBinding`] whose keys and signatures were verified against a
/// trusted [`PersonIdentity`]. It can only be obtained through verification
/// or issuance.
///
/// Time and revocation were checked at verification time only; long-lived
/// holders must recheck (§2: active sessions close on expiry or revocation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDeviceBinding {
    binding: DeviceBinding,
    person_root: Ed25519PublicKey,
    device_public: Ed25519PublicKey,
}

impl VerifiedDeviceBinding {
    /// The underlying wire record.
    #[must_use]
    pub fn binding(&self) -> &DeviceBinding {
        &self.binding
    }

    /// The exact 1438-byte encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.binding.encode()
    }

    /// The validated person root.
    #[must_use]
    pub fn person_root(&self) -> &Ed25519PublicKey {
        &self.person_root
    }

    /// The validated device key.
    #[must_use]
    pub fn device_public(&self) -> &Ed25519PublicKey {
        &self.device_public
    }

    /// The device ID derived from the device key.
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        DeviceId::of(&self.device_public)
    }

    /// The person ID derived from the root.
    #[must_use]
    pub fn person_id(&self) -> PersonId {
        PersonId::of(&self.person_root)
    }

    /// The certified X25519 Noise static key. PROTOCOL v1 defines no validity
    /// check for it beyond rejecting all-zero DH output in the handshake.
    #[must_use]
    pub fn noise_static(&self) -> &[u8; 32] {
        self.binding.body().noise_static()
    }

    /// The certified ML-KEM-768 credential (validated; unused by HFS, O11).
    #[must_use]
    pub fn kem_static(&self) -> &[u8; KEM_STATIC_LEN] {
        self.binding.body().kem_static()
    }

    /// The binding serial.
    #[must_use]
    pub fn serial(&self) -> NonZeroU64 {
        self.binding.body().serial()
    }
}

/// Fields of a new binding, apart from the two keys taken from the store.
#[derive(Clone, Debug)]
pub struct BindingRequest {
    /// The device's independently generated X25519 Noise static public key.
    pub noise_static: [u8; 32],
    /// The device's ML-KEM-768 encapsulation key (retained credential, O11).
    pub kem_static: Box<[u8; KEM_STATIC_LEN]>,
    /// Unique, increasing serial for this root and device.
    pub serial: NonZeroU64,
    /// Start of validity.
    pub not_before: UnixTime,
    /// End of validity; at most 366 days after `not_before`.
    pub not_after: UnixTime,
}

/// Issues a `DeviceBinding` when the person root and the device key are in
/// the same key store: a first device, or explicit local enrollment (§2).
/// Remote enrollment of a device whose key lives elsewhere is not enabled (O4).
///
/// The caller is responsible for serial uniqueness; renewal must keep the
/// device, Noise, and KEM keys unchanged (§2).
///
/// # Errors
///
/// [`IssueError`] if either key is missing or has the wrong role, the KEM key
/// is invalid, the validity window is empty or too long, or signing fails.
pub fn issue_device_binding<K: KeyStore>(
    store: &K,
    root: &KeyId,
    device: &KeyId,
    request: BindingRequest,
) -> Result<VerifiedDeviceBinding, IssueError> {
    if store.role(root)? != KeyRole::PersonRoot || store.role(device)? != KeyRole::Device {
        return Err(IssueError::WrongRole);
    }
    if !kem_static_is_valid(&request.kem_static) {
        return Err(IssueError::InvalidKey);
    }
    let root_public = store.public_key(root)?;
    let device_public = store.public_key(device)?;
    let body = DeviceBindingBody::new(
        *root_public.as_bytes(),
        *device_public.as_bytes(),
        request.noise_static,
        request.kem_static,
        request.serial,
        request.not_before,
        request.not_after,
    )
    .map_err(|_| IssueError::InvalidValidity)?;
    let encoded = body.encode();
    let root_signature = store
        .sign(root, SigningDomain::DeviceBinding, &encoded)?
        .to_bytes();
    let mut possession = encoded;
    possession.extend_from_slice(&root_signature);
    let device_signature = store
        .sign(device, SigningDomain::DevicePossession, &possession)?
        .to_bytes();
    let binding = DeviceBinding::from_parts(body, root_signature, device_signature);
    PersonIdentity::new(root_public)
        .verify_binding_signatures(&binding)
        .map_err(|_| IssueError::SelfCheck)
}

/// Why a binding was rejected. Local diagnostics only: what a peer may be
/// told is decided by the session (§12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BindingError {
    /// The binding names a different person root.
    UntrustedRoot,
    /// A device or KEM key is invalid.
    InvalidKey,
    /// A signature does not verify.
    InvalidSignature,
    /// `not_before` is in the future beyond the skew allowance.
    NotYetValid,
    /// `not_after` has passed beyond the skew allowance.
    Expired,
    /// A retained revocation covers this binding.
    Revoked,
    /// The root is disabled by conflicting revocations or quota exhaustion.
    RootDisabled,
}

impl fmt::Display for BindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UntrustedRoot => "binding names an untrusted root",
            Self::InvalidKey => "binding contains an invalid key",
            Self::InvalidSignature => "binding signature is invalid",
            Self::NotYetValid => "binding is not yet valid",
            Self::Expired => "binding has expired",
            Self::Revoked => "binding is revoked",
            Self::RootDisabled => "person root is disabled",
        })
    }
}

impl std::error::Error for BindingError {}

/// Issuance failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IssueError {
    /// A key has the wrong role.
    WrongRole,
    /// A supplied public key is invalid.
    InvalidKey,
    /// The validity window is empty or longer than 366 days.
    InvalidValidity,
    /// The freshly signed record failed verification.
    SelfCheck,
    /// OS randomness was unavailable.
    Random,
    /// The key store failed.
    KeyStore(KeyStoreError),
}

impl fmt::Display for IssueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongRole => f.write_str("key has the wrong role"),
            Self::InvalidKey => f.write_str("invalid public key"),
            Self::InvalidValidity => f.write_str("invalid validity window"),
            Self::SelfCheck => f.write_str("issued record failed verification"),
            Self::Random => f.write_str("randomness unavailable"),
            Self::KeyStore(error) => write!(f, "key store: {error}"),
        }
    }
}

impl std::error::Error for IssueError {}

impl From<KeyStoreError> for IssueError {
    fn from(error: KeyStoreError) -> Self {
        Self::KeyStore(error)
    }
}
