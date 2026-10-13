//! Entry points for `cargo fuzz` harnesses; compiled only with `--cfg
//! fuzzing`. They verify records against fixed public inputs and need no
//! gate feature: nothing here bypasses consent or signs with a live key.
//!
//! The fixed inputs are the committed §7.1/§7.3 fixtures
//! (`spec/test-vectors/manifest-hash.json` and `accept-signature.json`):
//! the one-file manifest, the session ID `a4…a4`, the sender key `d04a…`,
//! and the receiver key `a09a…` derived from the public seed `22…22`. A
//! delivery receipt for that Accept is signed once at start-up with the same
//! public seed. Each entry point asserts that only the one honest record
//! can verify, so a forgery that passes fails like a crash.

use std::sync::OnceLock;

use ed25519_dalek::Signer as _;
use todoke_proto::time::UnixTime;
use todoke_proto::transfer::{DeliveryReceipt, ManifestLimits, ReceiptBody};

use super::{
    CanonicalManifest, SessionBinding, VerifiedAccept, manifest_hash, verify_accept, verify_receipt,
};
use crate::identity::{Ed25519PublicKey, SigningDomain};

/// The canonical manifest of `manifest-hash.json`.
pub const MANIFEST_HEX: &str = "54444b4d0001a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f00000000068e778000000000068e7792c000000010000000000010000000001000968656c6c6f2e747874000a746578742f706c61696e00000000000000068e4c7c1b99dbfd50e7a95185fead5ee1448fa904a2fdd778eaf5f2dbfd629a990001";
/// The signed Accept of `accept-signature.json`.
pub const ACCEPT_HEX: &str = "0001a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a359f4396e85f74e2aeaebba081533117e86457efa4571718ab7108bdbf373d25ed04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a20000000068e7792c0000000100000001c460eab4a1083c4b71c95229d854352dbc79d3e835c59b73be1322dfc4cb313ebb8c38632260aa48765ecd98b31fc896ba43d07f15bd82050f60d36694cb6105";
/// The receiver's public fixture seed.
const RECEIVER_SEED: [u8; 32] = [0x22; 32];
/// The fixture session ID.
const SESSION_ID: [u8; 32] = [0xa4; 32];
/// Session establishment: the manifest's `created_at`.
const ESTABLISHED: u64 = 1_760_000_000;
/// The verifier's clock: ten seconds into the session, before the
/// Accept's expiry (`1760000300`).
const NOW: u64 = ESTABLISHED + 10;
/// The fixture receipt's completion time and ID.
const COMPLETED_AT: u64 = ESTABLISHED + 5;
const RECEIPT_ID: [u8; 16] = [0xa5; 16];

/// Lowercase hex to bytes; `None` for anything else.
#[must_use]
pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?))
        .collect()
}

struct Fixture {
    manifest: CanonicalManifest,
    session: SessionBinding,
    accept: VerifiedAccept,
    accept_record: Vec<u8>,
    receipt_record: Vec<u8>,
}

fn fixture() -> Option<&'static Fixture> {
    static FIXTURE: OnceLock<Option<Fixture>> = OnceLock::new();
    FIXTURE.get_or_init(build).as_ref()
}

fn build() -> Option<Fixture> {
    let manifest = CanonicalManifest::parse(from_hex(MANIFEST_HEX)?, &ManifestLimits::SPEC).ok()?;
    let signer = ed25519_dalek::SigningKey::from_bytes(&RECEIVER_SEED);
    let receiver = Ed25519PublicKey::from_bytes(&signer.verifying_key().to_bytes()).ok()?;
    let session = SessionBinding::new(
        SESSION_ID,
        *manifest.sender(),
        receiver,
        UnixTime::new(ESTABLISHED)?,
    );
    let accept_record = from_hex(ACCEPT_HEX)?;
    let now = UnixTime::new(NOW)?;
    let accept = verify_accept(&accept_record, &session, &manifest, now).ok()?;
    let body = ReceiptBody::new(
        SESSION_ID,
        *accept.transfer_id(),
        *accept.manifest_hash(),
        *accept.accept_hash(),
        *manifest.sender().as_bytes(),
        *receiver.as_bytes(),
        RECEIPT_ID,
        UnixTime::new(COMPLETED_AT)?,
        accept.selected_count(),
        accept.selected_bytes(),
    )
    .ok()?;
    let mut message = SigningDomain::DeliveryReceipt.bytes().to_vec();
    message.extend_from_slice(&body.encode());
    let signature = signer.sign(&message).to_bytes();
    let receipt_record = DeliveryReceipt::new(body, signature).encode().to_vec();
    Some(Fixture {
        manifest,
        session,
        accept,
        accept_record,
        receipt_record,
    })
}

/// The fixture records, for writing seeds: `(name, bytes)`.
#[must_use]
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    fixture().map_or_else(Vec::new, |fixture| {
        vec![
            ("manifest", fixture.manifest.bytes().to_vec()),
            ("accept", fixture.accept_record.clone()),
            ("receipt", fixture.receipt_record.clone()),
        ]
    })
}

/// [`CanonicalManifest::parse`] (§7.1) on arbitrary bytes with the
/// protocol limits. An accepted manifest keeps the exact input and hashes
/// it.
///
/// # Panics
///
/// If an accepted manifest differs from its input, which is a bug.
pub fn manifest(data: &[u8]) {
    if let Ok(manifest) = CanonicalManifest::parse(data.to_vec(), &ManifestLimits::SPEC) {
        assert_eq!(manifest.bytes(), data);
        assert_eq!(manifest.hash(), &manifest_hash(data));
        assert_eq!(manifest.files().len(), manifest.manifest().files().count());
    }
}

/// [`verify_accept`] (§7.3) of arbitrary bytes on the fixture's sender.
///
/// # Panics
///
/// If anything but the fixture Accept verifies, which is a bug.
pub fn accept(data: &[u8]) {
    let Some(fixture) = fixture() else {
        return;
    };
    let Some(now) = UnixTime::new(NOW) else {
        return;
    };
    if let Ok(accept) = verify_accept(data, &fixture.session, &fixture.manifest, now) {
        assert_eq!(data, fixture.accept_record.as_slice());
        assert_eq!(accept.encoded(), data);
        assert!(accept.file(1).is_some());
    }
}

/// [`verify_receipt`] (§7.7) of arbitrary bytes against the fixture
/// Accept.
///
/// # Panics
///
/// If anything but the fixture receipt verifies, which is a bug.
pub fn receipt(data: &[u8]) {
    let Some(fixture) = fixture() else {
        return;
    };
    let Some(now) = UnixTime::new(NOW) else {
        return;
    };
    if let Ok(receipt) = verify_receipt(data, &fixture.session, &fixture.accept, now) {
        assert_eq!(data, fixture.receipt_record.as_slice());
        assert_eq!(receipt.encode().as_slice(), data);
    }
}
