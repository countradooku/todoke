//! Device and person identity, signing-key custody, and contacts
//! (PROTOCOL §1–§2, §4.3).
//!
//! | Concept | Type |
//! | --- | --- |
//! | Validated Ed25519 key, strict verification | [`Ed25519PublicKey`], [`Signature`], [`SigningDomain`] |
//! | Device key and its truncated ID | [`DeviceIdentity`], [`DeviceId`] |
//! | Person root and per-device subkey certificates | [`PersonIdentity`], [`VerifiedDeviceBinding`], [`issue_device_binding`] |
//! | Revocation | [`RevocationRecord`], [`RevocationSet`], [`issue_revocation`] |
//! | Private-key custody | [`KeyStore`], [`SoftwareKeyStore`], [`Sealer`] |
//! | Pinned contacts | [`ContactStore`], [`Contact`] |
//!
//! Wire layouts and their decoders live in [`todoke_proto::identity`]; this
//! module adds key validation, signatures, and policy.
//!
//! # Secret handling
//!
//! Ed25519 seeds, storage keys, wrapping keys, and pair PSKs live in
//! `Zeroizing` buffers, have redacted `Debug` output, and appear in no error.
//! Upstream library scratch state is not covered by an audited zeroization
//! guarantee (O6). The local storage formats in [`keystore`] and [`contacts`]
//! are versioned and sealed; they are not protocol wire formats.

pub(crate) mod binding;
mod codec;
pub mod contacts;
mod ed25519;
#[cfg(fuzzing)]
pub mod fuzzing;
mod ids;
pub mod keystore;
mod revocation;
pub mod sealing;
pub mod storage;

use core::fmt;

pub use binding::{
    BindingError, BindingRequest, CLOCK_SKEW_SECONDS, IssueError, PersonIdentity,
    VerifiedDeviceBinding, issue_device_binding,
};
pub use contacts::{
    Contact, ContactError, ContactStore, IdentityError, TrustOrigin, VerificationState,
};
pub use ed25519::{Ed25519PublicKey, InvalidPublicKey, Signature, SignatureError, SigningDomain};
pub use ids::{DeviceId, DeviceIdentity, PersonId};
pub use keystore::{
    EncryptedKeyStore, ExportPolicy, KeyId, KeyRole, KeyStore, KeyStoreError, SoftwareKeyStore,
    WrappedKey, WrappingKey,
};
pub use revocation::{
    ApplyOutcome, MAX_RECORDS_PER_ROOT, MAX_TOTAL_RECORDS, RevocationError, RevocationRecord,
    RevocationRequest, RevocationSet, issue_revocation,
};
pub use sealing::{Sealer, SoftwareSealer, StorageKey};
pub use storage::{BlobStorage, FileStorage, MemoryStorage};

pub use crate::rng::RandomError;

/// Lowercase hex for `Debug` output of public values.
struct Hex<'a>(&'a [u8]);

impl fmt::Debug for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;
