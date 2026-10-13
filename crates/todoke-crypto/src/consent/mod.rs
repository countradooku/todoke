//! Cryptographic consent: canonical manifests, the signed `Accept`
//! (`AcceH`), and the signed `DeliveryReceipt` (PROTOCOL §7.1–§7.3, §7.7).
//!
//! This module is the **only** source of
//! [`AcceptedFile`](crate::content::AcceptedFile) values in a shipped
//! build, and therefore the only way to seal or open file content (§7.2).
//! An `AcceptedFile` comes out of a [`VerifiedAccept`], which exists only
//! after this crate has checked a signed Accept record against:
//!
//! - the established session it arrived on ([`SessionBinding`], obtainable
//!   only from [`Session::transfer_binding`](crate::session::Session::transfer_binding));
//! - the canonical manifest it names ([`CanonicalManifest`]: the hash is
//!   computed here from the exact bytes, never taken from the peer);
//! - its expiry against the caller's trusted time; and
//! - the receiver's strict Ed25519 signature.
//!
//! Each `AcceptedFile` carries the manifest's binding (transfer, manifest
//! hash, file ID, suite, size, root) of exactly one **selected** regular
//! file. Nothing outside this crate can build one: the content layer's
//! constructor is crate-private, and the test bypass
//! (`AcceptedFile::assume_accepted_without_verification`) exists only with
//! the non-default `insecure-content-without-accept` feature, which CI keeps
//! out of every shipped graph.
//!
//! | Piece | Who calls it | Spec |
//! | --- | --- | --- |
//! | [`CanonicalManifest`] | Sender after building, receiver after assembling `ManifestPart`s | §7.1 |
//! | [`sign_accept`] | Receiver, on locally authorized user intent | §7.2, §7.3 |
//! | [`verify_accept`] | Sender, before any `FileKey` or content | §7.3 |
//! | [`sign_receipt`] | Receiver, after every selected file is published | §7.7 |
//! | [`verify_receipt`] | Sender, before showing confirmed delivery | §7.7 |
//!
//! What this module does not decide: whether the user really intended the
//! selection (the caller of [`sign_accept`] is the core acting on local
//! intent, §7.2), replay of an Accept within a session (the transfer engine
//! tracks nonces and transfer state), revocation status (the session layer
//! closes revoked sessions; the transfer engine cancels), and when expiry
//! pauses content (the transfer engine checks each operation against
//! [`VerifiedAccept::expires_at`]). A `VerifiedAccept` and its
//! `AcceptedFile`s do not expire by themselves; the engine must drop them
//! when the authorization ends.

mod accept;
// Decoders and signature checks against fixed public keys only: no gate to
// bypass, so the cfg alone (scripts/ci/fuzzing-gates.test.sh).
#[cfg(fuzzing)]
pub mod fuzzing;
mod manifest;
mod receipt;

#[cfg(test)]
mod tests;

use core::fmt;

use todoke_proto::time::UnixTime;

use crate::identity::Ed25519PublicKey;
use crate::rng::{self, RandomError};

pub use accept::{
    ACCEPT_LIFETIME_SECONDS, AcceptError, VerifiedAccept, accept_hash, sign_accept, verify_accept,
};
pub use manifest::{CanonicalManifest, ManifestCheckError, manifest_hash};
pub use receipt::{ReceiptError, VerifiedReceipt, sign_receipt, verify_receipt};

/// The clock skew §1 tolerates in expiry comparisons: 120 seconds.
pub const CLOCK_SKEW_SECONDS: u64 = crate::identity::CLOCK_SKEW_SECONDS;

/// What a transfer binds to its authenticated session (§7.3, §7.7): the
/// session ID, this device's and the peer's full device keys, and the
/// trusted wall-clock time the ratchet gate opened.
///
/// Only an established session hands one out
/// ([`Session::transfer_binding`](crate::session::Session::transfer_binding)),
/// so a transfer cannot verify an Accept or receipt against a session it is
/// not running on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionBinding {
    session_id: [u8; 32],
    local_device: Ed25519PublicKey,
    peer_device: Ed25519PublicKey,
    established_at: UnixTime,
}

impl SessionBinding {
    pub(crate) const fn new(
        session_id: [u8; 32],
        local_device: Ed25519PublicKey,
        peer_device: Ed25519PublicKey,
        established_at: UnixTime,
    ) -> Self {
        Self {
            session_id,
            local_device,
            peer_device,
            established_at,
        }
    }

    /// `B3("todoke/v1/session\0" || h)` of the session (§4.2.6).
    #[must_use]
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// This device's full device key.
    #[must_use]
    pub const fn local_device(&self) -> &Ed25519PublicKey {
        &self.local_device
    }

    /// The authenticated peer's full device key.
    #[must_use]
    pub const fn peer_device(&self) -> &Ed25519PublicKey {
        &self.peer_device
    }

    /// When the session's ratchet gate opened, on this device's trusted
    /// clock.
    #[must_use]
    pub const fn established_at(&self) -> UnixTime {
        self.established_at
    }
}

/// A random 16-byte identifier for a transfer, cancel, Accept nonce, or
/// receipt: from the OS CSPRNG, never all zero (§1, §7).
///
/// # Errors
///
/// [`RandomError`] if randomness is unavailable.
pub fn random_id() -> Result<[u8; 16], RandomError> {
    rng::nonzero_id()
}

/// Which side of the transfer a check runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    /// This device sends the files and verifies the peer's records.
    Sender,
    /// This device receives the files and signs the records.
    Receiver,
}

impl Side {
    /// `(sender, receiver)` keys for this side of `session`.
    const fn keys(self, session: &SessionBinding) -> (&Ed25519PublicKey, &Ed25519PublicKey) {
        match self {
            Self::Sender => (&session.local_device, &session.peer_device),
            Self::Receiver => (&session.peer_device, &session.local_device),
        }
    }
}

impl fmt::Display for Side {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Sender => "sender",
            Self::Receiver => "receiver",
        })
    }
}

fn add_seconds(time: UnixTime, seconds: u64) -> u64 {
    time.seconds().saturating_add(seconds)
}
