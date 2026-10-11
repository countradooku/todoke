//! Entry points for `cargo fuzz` harnesses; compiled only with `--cfg fuzzing`.
//!
//! Each function runs the real decoder on arbitrary bytes. Where a decoder
//! accepts, it returns the re-encoding so the harness can assert canonicality.

use zeroize::Zeroizing;

use super::codec::Envelope;
use super::sealing::{SoftwareSealer, StorageKey};
use super::{Ed25519PublicKey, PersonIdentity, contacts, keystore};

/// Key store blob plaintext decoder.
#[must_use]
pub fn keystore_plaintext(data: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    keystore::software::decode(data)
        .ok()
        .map(|keys| keystore::software::encode(&keys))
}

/// Contact store blob plaintext decoder.
#[must_use]
pub fn contact_store_plaintext(data: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    contacts::decode(data)
        .ok()
        .map(|decoded| contacts::reencode(&decoded))
}

/// Envelope header parsing and authenticated opening under a fixed public
/// test key. Returns whether opening succeeded (it should not for random input).
#[must_use]
pub fn sealed_envelope(data: &[u8]) -> bool {
    let sealer = SoftwareSealer::new(StorageKey::from_bytes(Zeroizing::new([0x5a; 32])));
    let envelope = Envelope {
        magic: *b"TDKF",
        version: 1,
        context: b"todoke/local/fuzz\0",
    };
    envelope.open(&sealer, data).is_ok()
}

/// Ed25519 public-key validation and, for valid keys, binding verification
/// against that key as a trusted root (key, ML-KEM, and signature checks).
pub fn binding_verification(data: &[u8]) {
    let Some((root, rest)) = data.split_first_chunk::<32>() else {
        return;
    };
    let Ok(root) = Ed25519PublicKey::from_bytes(root) else {
        return;
    };
    if let Ok(binding) = todoke_proto::identity::DeviceBinding::decode(rest) {
        let _ = PersonIdentity::new(root).verify_binding_signatures(&binding);
    }
}
