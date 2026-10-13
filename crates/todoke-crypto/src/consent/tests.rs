//! Consent tests: the committed §7.1/§7.3 fixtures at runtime, every
//! binding and window of `verify_accept` and `verify_receipt`, and the
//! accepted-file gate.

use ed25519_dalek::Signer as _;
use todoke_proto::time::UnixTime;
use todoke_proto::transfer::{
    Accept, AcceptBody, DeliveryReceipt, Manifest, ManifestEntry, ManifestHeader, ManifestLimits,
    ReceiptBody,
};

use super::accept::sign_accept_with_nonce;
use super::*;
use crate::content::ContentSuite;
use crate::identity::{
    ExportPolicy, KeyRole, KeyStoreError, Signature, SigningDomain, WrappedKey, WrappingKey,
};
use crate::identity::{KeyId, KeyStore};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture(name: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/test-vectors")
        .join(name);
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

fn hex_field(
    value: &serde_json::Value,
    pointer: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let text = value
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .ok_or("missing fixture field")?;
    Ok(hex::decode(text)?)
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Box<dyn std::error::Error>> {
    Ok(bytes.try_into()?)
}

fn time(seconds: u64) -> Result<UnixTime, &'static str> {
    UnixTime::new(seconds).ok_or("time")
}

/// A key store holding one device key from a public seed.
struct FixedKeys(ed25519_dalek::SigningKey);

const KEY: [u8; 16] = [1; 16];

impl FixedKeys {
    fn new(seed: u8) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
    }

    fn id() -> Result<KeyId, &'static str> {
        KeyId::from_bytes(KEY).ok_or("key id")
    }

    fn public(&self) -> Result<Ed25519PublicKey, Box<dyn std::error::Error>> {
        Ok(Ed25519PublicKey::from_bytes(
            &self.0.verifying_key().to_bytes(),
        )?)
    }
}

impl KeyStore for FixedKeys {
    fn generate(&mut self, _: KeyRole, _: ExportPolicy) -> Result<KeyId, KeyStoreError> {
        Err(KeyStoreError::Capacity)
    }

    fn role(&self, key: &KeyId) -> Result<KeyRole, KeyStoreError> {
        if key.to_bytes() == KEY {
            Ok(KeyRole::Device)
        } else {
            Err(KeyStoreError::UnknownKey)
        }
    }

    fn public_key(&self, key: &KeyId) -> Result<Ed25519PublicKey, KeyStoreError> {
        self.role(key)?;
        Ed25519PublicKey::from_bytes(&self.0.verifying_key().to_bytes())
            .map_err(|_| KeyStoreError::Corrupt)
    }

    fn sign(
        &self,
        key: &KeyId,
        domain: SigningDomain,
        message: &[u8],
    ) -> Result<Signature, KeyStoreError> {
        if !domain.permits(self.role(key)?) {
            return Err(KeyStoreError::DomainNotPermitted);
        }
        let mut input = domain.bytes().to_vec();
        input.extend_from_slice(message);
        Ok(Signature::from_bytes(self.0.sign(&input).to_bytes()))
    }

    fn export_wrapped(&self, _: &KeyId, _: &WrappingKey) -> Result<WrappedKey, KeyStoreError> {
        Err(KeyStoreError::NotExportable)
    }

    fn delete(&mut self, _: &KeyId) -> Result<(), KeyStoreError> {
        Err(KeyStoreError::UnknownKey)
    }
}

/// The fixtures' public seeds: the sender key is `d04a…` and the receiver
/// key `a09a…`.
const SENDER_SEED: u8 = 0x11;
const RECEIVER_SEED: u8 = 0x22;
const SESSION_ID: [u8; 32] = [0xa4; 32];
const T0: u64 = 1_760_000_000;

struct Fixture {
    manifest: CanonicalManifest,
    record: Vec<u8>,
    accept_hash: Vec<u8>,
    nonce: [u8; 16],
    expires_at: UnixTime,
    sender: FixedKeys,
    receiver: FixedKeys,
}

impl Fixture {
    fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let manifest_vector = fixture("manifest-hash.json")?;
        let manifest = CanonicalManifest::parse(
            hex_field(&manifest_vector, "/canonical_hex")?,
            &ManifestLimits::SPEC,
        )?;
        let vector = fixture("accept-signature.json")?;
        let sender = FixedKeys::new(SENDER_SEED);
        let receiver = FixedKeys::new(RECEIVER_SEED);
        assert_eq!(
            sender.public()?.as_bytes().as_slice(),
            hex_field(&vector, "/sender_ed25519_public_key_hex")?
        );
        assert_eq!(
            receiver.0.to_bytes().as_slice(),
            hex_field(&vector, "/receiver_ed25519_seed_hex")?
        );
        Ok(Self {
            manifest,
            record: hex_field(&vector, "/signed_record_hex")?,
            accept_hash: hex_field(&vector, "/accept_hash_hex")?,
            nonce: array(&hex_field(&vector, "/accept_nonce_hex")?)?,
            expires_at: time(
                vector
                    .pointer("/expires_at")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or("expires_at")?,
            )?,
            sender,
            receiver,
        })
    }

    /// The session as the sender sees it.
    fn sender_session(&self) -> Result<SessionBinding, Box<dyn std::error::Error>> {
        Ok(SessionBinding::new(
            SESSION_ID,
            self.sender.public()?,
            self.receiver.public()?,
            time(T0)?,
        ))
    }

    /// The session as the receiver sees it.
    fn receiver_session(&self) -> Result<SessionBinding, Box<dyn std::error::Error>> {
        Ok(SessionBinding::new(
            SESSION_ID,
            self.receiver.public()?,
            self.sender.public()?,
            time(T0)?,
        ))
    }

    fn accept(&self) -> Result<VerifiedAccept, Box<dyn std::error::Error>> {
        Ok(verify_accept(
            &self.record,
            &self.sender_session()?,
            &self.manifest,
            time(T0 + 10)?,
        )?)
    }
}

/// `manifest-hash.json` (§7.1): the runtime manifest hash and file binding.
#[test]
fn manifest_fixture_hash_and_binding() -> TestResult {
    let vector = fixture("manifest-hash.json")?;
    let canonical = hex_field(&vector, "/canonical_hex")?;
    let manifest = CanonicalManifest::parse(canonical.clone(), &ManifestLimits::SPEC)?;
    assert_eq!(manifest.bytes(), canonical.as_slice());
    assert_eq!(
        manifest.hash().as_slice(),
        hex_field(&vector, "/manifest_hash_hex")?
    );
    assert_eq!(
        manifest_hash(&canonical).as_slice(),
        manifest.hash().as_slice()
    );
    let file = manifest.file(1).ok_or("file 1")?;
    assert_eq!(file.manifest_hash(), manifest.hash());
    assert_eq!(file.suite(), ContentSuite::Aes256GcmStream);
    assert_eq!(file.layout().size(), 6);
    assert_eq!(
        file.root().as_slice(),
        hex_field(&vector, "/entries/0/plaintext_blake3_root_hex")?
    );
    // The root is the BLAKE3 hash of the fixture content.
    let content = hex_field(&vector, "/entries/0/content_hex")?;
    assert_eq!(blake3::hash(&content).as_bytes(), file.root());
    assert!(manifest.file(2).is_none());
    assert_eq!(manifest.created_at().seconds(), T0);
    let debug = format!("{manifest:?}");
    assert!(!debug.contains("hello") && !debug.contains("text/plain"));
    Ok(())
}

/// `accept-signature.json` (§7.3): the receiver's runtime signing path
/// reproduces the record, signature, and Accept hash byte for byte, and the
/// sender's verifier accepts it.
#[test]
fn accept_fixture_signs_and_verifies() -> TestResult {
    let fixture = Fixture::load()?;
    let signed = sign_accept_with_nonce(
        &fixture.receiver,
        &FixedKeys::id()?,
        &fixture.receiver_session()?,
        &fixture.manifest,
        vec![1],
        fixture.nonce,
        fixture.expires_at,
        time(T0)?,
    )?;
    assert_eq!(signed.encoded(), fixture.record.as_slice());
    assert_eq!(
        signed.accept_hash().as_slice(),
        fixture.accept_hash.as_slice()
    );
    assert_eq!(
        accept_hash(&fixture.record).as_slice(),
        fixture.accept_hash.as_slice()
    );
    let vector = fixture_signature()?;
    assert_eq!(signed.record().signature().as_slice(), vector.as_slice());

    let verified = fixture.accept()?;
    assert_eq!(verified.encoded(), fixture.record.as_slice());
    assert_eq!(verified.accept_hash(), signed.accept_hash());
    assert_eq!(verified.selection(), &[1]);
    assert_eq!(verified.selected_count(), 1);
    assert_eq!(verified.selected_bytes(), 6);
    assert_eq!(verified.nonce(), &fixture.nonce);
    assert_eq!(verified.expires_at(), fixture.expires_at);
    let accepted = verified.file(1).ok_or("file 1")?;
    assert_eq!(
        accepted.binding(),
        fixture.manifest.file(1).ok_or("binding")?
    );
    assert!(verified.file(2).is_none() && verified.file(0).is_none());
    assert_eq!(verified.files().len(), 1);
    assert!(format!("{verified:?}").contains("VerifiedAccept"));
    Ok(())
}

fn fixture_signature() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    hex_field(&fixture("accept-signature.json")?, "/signature_hex")
}

/// Every single-byte change to the signed record is refused.
#[test]
fn every_accept_mutation_is_refused() -> TestResult {
    let fixture = Fixture::load()?;
    let session = fixture.sender_session()?;
    let now = time(T0 + 10)?;
    for index in 0..fixture.record.len() {
        for flip in [0x01, 0x80] {
            let mut record = fixture.record.clone();
            record[index] ^= flip;
            assert!(
                verify_accept(&record, &session, &fixture.manifest, now).is_err(),
                "byte {index} flip {flip:#x}"
            );
        }
    }
    let mut longer = fixture.record.clone();
    longer.push(0);
    assert!(matches!(
        verify_accept(&longer, &session, &fixture.manifest, now),
        Err(AcceptError::Malformed(_))
    ));
    assert!(matches!(
        verify_accept(&fixture.record[..241], &session, &fixture.manifest, now),
        Err(AcceptError::Malformed(_))
    ));
    Ok(())
}

/// The bindings: session, transfer, manifest, both parties, expiry.
#[test]
fn accept_bindings() -> TestResult {
    let fixture = Fixture::load()?;
    let session = fixture.sender_session()?;
    let now = time(T0 + 10)?;
    let verify = |session: &SessionBinding, now| {
        verify_accept(&fixture.record, session, &fixture.manifest, now)
    };
    assert!(verify(&session, now).is_ok());
    // Another session (a reconnect needs a fresh Accept).
    let other = SessionBinding::new(
        [0xa5; 32],
        *session.local_device(),
        *session.peer_device(),
        time(T0)?,
    );
    assert_eq!(verify(&other, now).err(), Some(AcceptError::Session));
    // Roles swapped: the receiver cannot verify as if it were the sender.
    assert_eq!(
        verify(&fixture.receiver_session()?, now).err(),
        Some(AcceptError::Sender)
    );
    // A third device as the peer.
    let stranger = FixedKeys::new(0x33).public()?;
    let wrong_peer = SessionBinding::new(SESSION_ID, *session.local_device(), stranger, time(T0)?);
    assert_eq!(verify(&wrong_peer, now).err(), Some(AcceptError::Receiver));
    // Expiry: valid up to one second before; refused at and after.
    let expiry = fixture.expires_at.seconds();
    assert!(verify(&session, time(expiry - 1)?).is_ok());
    assert_eq!(
        verify(&session, time(expiry)?).err(),
        Some(AcceptError::Expiry)
    );
    assert_eq!(
        verify(&session, time(expiry + 500)?).err(),
        Some(AcceptError::Expiry)
    );
    // Expiry more than 24 hours (+120 s skew) ahead of the verifier's clock.
    let early = expiry - ACCEPT_LIFETIME_SECONDS - CLOCK_SKEW_SECONDS - 1;
    assert_eq!(
        verify(&session, time(early)?).err(),
        Some(AcceptError::Expiry)
    );
    assert!(verify(&session, time(early + 1)?).is_ok());
    // Another manifest: a different transfer, and the same transfer with a
    // different hash.
    let manifests = Manifests::new(&fixture)?;
    let other_transfer = manifests.build([0xa6; 16], &[("x", 6)])?;
    assert_eq!(
        verify_accept(&fixture.record, &session, &other_transfer, now).err(),
        Some(AcceptError::Transfer)
    );
    let other_hash = manifests.build([0xa3; 16], &[("y", 6)])?;
    assert_eq!(
        verify_accept(&fixture.record, &session, &other_hash, now).err(),
        Some(AcceptError::ManifestHash)
    );
    Ok(())
}

/// Builds manifests between the fixture devices.
struct Manifests {
    sender: [u8; 32],
    recipient: [u8; 32],
}

impl Manifests {
    fn new(fixture: &Fixture) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            sender: *fixture.sender.public()?.as_bytes(),
            recipient: *fixture.receiver.public()?.as_bytes(),
        })
    }

    /// Files at the root, plus one directory (the last entry).
    fn build(
        &self,
        transfer_id: [u8; 16],
        files: &[(&str, u64)],
    ) -> Result<CanonicalManifest, Box<dyn std::error::Error>> {
        let mut entries = Vec::new();
        for (index, &(name, size)) in files.iter().enumerate() {
            let id = u32::try_from(index + 1)?;
            let root = if size == 0 {
                *blake3::hash(&[]).as_bytes()
            } else {
                [u8::try_from(index + 1)?; 32]
            };
            entries.push(ManifestEntry::file(
                id,
                0,
                name.to_owned(),
                "application/octet-stream".to_owned(),
                size,
                root,
                2,
            ));
        }
        let dir_id = u32::try_from(files.len() + 1)?;
        entries.push(ManifestEntry::directory(dir_id, 0, "dir".to_owned()));
        let header = ManifestHeader {
            transfer_id,
            sender_public: self.sender,
            recipient_public: self.recipient,
            created_at: time(T0)?,
            expires_at: time(T0 + 3 * 86_400)?,
        };
        Ok(CanonicalManifest::from_manifest(Manifest::new(
            header,
            entries,
            &ManifestLimits::SPEC,
        )?)?)
    }
}

/// Partial selection: only selected files are accepted; a directory or
/// unknown ID cannot be selected; the receiver signs only as itself.
#[test]
fn selection_and_signing_rules() -> TestResult {
    let fixture = Fixture::load()?;
    let manifests = Manifests::new(&fixture)?;
    let manifest = manifests.build([0x77; 16], &[("a", 10), ("b", 0), ("c", 20)])?;
    let receiver_session = fixture.receiver_session()?;
    let sender_session = fixture.sender_session()?;
    let id = FixedKeys::id()?;
    let now = time(T0 + 10)?;
    let expires = time(T0 + 3600)?;
    let sign = |selection: Vec<u32>| {
        sign_accept(
            &fixture.receiver,
            &id,
            &receiver_session,
            &manifest,
            selection,
            expires,
            now,
        )
    };
    let accept = sign(vec![2, 3])?;
    assert_eq!(accept.selected_bytes(), 20);
    assert!(accept.file(1).is_none());
    assert_eq!(accept.file(2).ok_or("2")?.binding().layout().size(), 0);
    assert!(accept.file(3).is_some() && accept.file(4).is_none());
    // The sender verifies the same record.
    let verified = verify_accept(accept.encoded(), &sender_session, &manifest, now)?;
    assert_eq!(verified.accept_hash(), accept.accept_hash());
    // Directory 4, unknown 5, unsorted, empty.
    assert_eq!(sign(vec![4]).err(), Some(AcceptError::Selection));
    assert_eq!(sign(vec![1, 5]).err(), Some(AcceptError::Selection));
    assert!(matches!(sign(vec![3, 1]), Err(AcceptError::Malformed(_))));
    assert!(matches!(sign(vec![]), Err(AcceptError::Malformed(_))));
    // Fresh nonces: two Accepts for the same selection differ.
    let again = sign(vec![2, 3])?;
    assert_ne!(again.nonce(), accept.nonce());
    assert_ne!(again.accept_hash(), accept.accept_hash());
    // Expiry beyond the manifest, too far ahead, or already passed.
    let sign_until = |expires_at| {
        sign_accept(
            &fixture.receiver,
            &id,
            &receiver_session,
            &manifest,
            vec![1],
            expires_at,
            now,
        )
    };
    assert_eq!(
        sign_until(time(T0 + 3 * 86_400 + 1)?).err(),
        Some(AcceptError::Expiry)
    );
    assert_eq!(
        sign_until(time(T0 + 10 + 86_400 + 121)?).err(),
        Some(AcceptError::Expiry)
    );
    assert_eq!(sign_until(now).err(), Some(AcceptError::Expiry));
    // The sender cannot issue an Accept, nor can a key that is not this
    // session's local device.
    assert_eq!(
        sign_accept(
            &fixture.sender,
            &id,
            &sender_session,
            &manifest,
            vec![1],
            expires,
            now
        )
        .err(),
        Some(AcceptError::Role)
    );
    let stranger = FixedKeys::new(0x33);
    assert_eq!(
        sign_accept(
            &stranger,
            &id,
            &receiver_session,
            &manifest,
            vec![1],
            expires,
            now
        )
        .err(),
        Some(AcceptError::Role)
    );
    Ok(())
}

/// Signatures by the wrong key, in the wrong domain, or over a body that
/// names the wrong sender are refused.
#[test]
fn forged_accepts_are_refused() -> TestResult {
    let fixture = Fixture::load()?;
    let manifest =
        Manifests::new(&fixture)?.build([0x77; 16], &[("a", 10), ("b", 0), ("c", 20)])?;
    let sender_session = fixture.sender_session()?;
    let id = FixedKeys::id()?;
    let now = time(T0 + 10)?;
    let accept = sign_accept(
        &fixture.receiver,
        &id,
        &fixture.receiver_session()?,
        &manifest,
        vec![2, 3],
        time(T0 + 3600)?,
        now,
    )?;
    let stranger = FixedKeys::new(0x33);
    // A signature by another key over a correct body is refused.
    let body = accept.record().body().clone();
    let forged = Accept::new(
        body.clone(),
        stranger
            .sign(&id, SigningDomain::Accept, &body.encode())?
            .to_bytes(),
    );
    assert_eq!(
        verify_accept(&forged.encode(), &sender_session, &manifest, now).err(),
        Some(AcceptError::Signature)
    );
    // The right key in the wrong domain.
    let wrong_domain = Accept::new(
        body.clone(),
        fixture
            .receiver
            .sign(&id, SigningDomain::DeliveryReceipt, &body.encode())?
            .to_bytes(),
    );
    assert_eq!(
        verify_accept(&wrong_domain.encode(), &sender_session, &manifest, now).err(),
        Some(AcceptError::Signature)
    );
    // A validly signed record that names the wrong sender.
    let swapped = AcceptBody::new(
        *body.session_id(),
        *body.transfer_id(),
        *body.manifest_hash(),
        *body.receiver_public(),
        *body.receiver_public(),
        *body.accept_nonce(),
        body.expires_at(),
        body.selection().to_vec(),
    )?;
    let signed = Accept::new(
        swapped.clone(),
        fixture
            .receiver
            .sign(&id, SigningDomain::Accept, &swapped.encode())?
            .to_bytes(),
    );
    assert_eq!(
        verify_accept(&signed.encode(), &sender_session, &manifest, now).err(),
        Some(AcceptError::Sender)
    );
    Ok(())
}

/// Manifest checks beyond the schema: valid keys and the empty-file root.
#[test]
fn manifest_key_and_empty_root_checks() -> TestResult {
    let fixture = Fixture::load()?;
    let manifests = Manifests::new(&fixture)?;
    let good = manifests.build([0x78; 16], &[("e", 0)])?;
    let parsed = CanonicalManifest::parse(good.bytes().to_vec(), &ManifestLimits::SPEC)?;
    assert_eq!(parsed, good);
    // An empty file with any other root.
    let mut bytes = good.bytes().to_vec();
    let root_at = bytes.len() - (55 + 3) - 34; // the file entry's root
    bytes[root_at] ^= 1;
    assert_eq!(
        CanonicalManifest::parse(bytes, &ManifestLimits::SPEC).err(),
        Some(ManifestCheckError::EmptyFileRoot)
    );
    // Small-order or noncanonical keys.
    let mut bad_sender = good.bytes().to_vec();
    bad_sender[22..54].fill(0);
    assert_eq!(
        CanonicalManifest::parse(bad_sender, &ManifestLimits::SPEC).err(),
        Some(ManifestCheckError::SenderKey)
    );
    let mut bad_recipient = good.bytes().to_vec();
    bad_recipient[54..86].fill(0xff);
    assert_eq!(
        CanonicalManifest::parse(bad_recipient, &ManifestLimits::SPEC).err(),
        Some(ManifestCheckError::RecipientKey)
    );
    assert!(matches!(
        CanonicalManifest::parse(vec![0; 10], &ManifestLimits::SPEC),
        Err(ManifestCheckError::Manifest(_))
    ));
    Ok(())
}

fn receipt_parts(
    fixture: &Fixture,
) -> Result<
    (
        SessionBinding,
        SessionBinding,
        VerifiedAccept,
        VerifiedAccept,
    ),
    Box<dyn std::error::Error>,
> {
    let receiver_session = fixture.receiver_session()?;
    let sender_session = fixture.sender_session()?;
    let now = time(T0 + 10)?;
    let receiver_accept = sign_accept(
        &fixture.receiver,
        &FixedKeys::id()?,
        &receiver_session,
        &fixture.manifest,
        vec![1],
        fixture.expires_at,
        now,
    )?;
    let sender_accept = verify_accept(
        receiver_accept.encoded(),
        &sender_session,
        &fixture.manifest,
        now,
    )?;
    Ok((
        receiver_session,
        sender_session,
        receiver_accept,
        sender_accept,
    ))
}

/// The delivery receipt (§7.7): sign, verify, and every binding and window.
#[test]
fn receipt_bindings_and_windows() -> TestResult {
    let fixture = Fixture::load()?;
    let (receiver_session, sender_session, receiver_accept, sender_accept) =
        receipt_parts(&fixture)?;
    let id = FixedKeys::id()?;
    let now = time(T0 + 20)?;
    let receipt = sign_receipt(
        &fixture.receiver,
        &id,
        &receiver_session,
        &receiver_accept,
        time(T0 + 15)?,
        now,
    )?;
    let encoded = receipt.encode();
    let verified = verify_receipt(&encoded, &sender_session, &sender_accept, now)?;
    assert_eq!(verified, receipt);
    assert_eq!(verified.completed_at(), time(T0 + 15)?);
    assert_eq!(verified.transfer_id(), fixture.manifest.transfer_id());
    assert_ne!(verified.receipt_id(), &[0; 16]);
    let body = receipt.record().body();
    assert_eq!(body.completed_count(), 1);
    assert_eq!(body.total_plaintext_bytes(), 6);
    assert!(format!("{verified:?}").contains("VerifiedReceipt"));

    // Every single-byte change is refused.
    for index in 0..encoded.len() {
        let mut record = encoded;
        record[index] ^= 0x01;
        assert!(
            verify_receipt(&record, &sender_session, &sender_accept, now).is_err(),
            "byte {index}"
        );
    }
    // Another session, or an Accept from another session.
    let other = SessionBinding::new(
        [0xa5; 32],
        *sender_session.local_device(),
        *sender_session.peer_device(),
        time(T0)?,
    );
    assert_eq!(
        verify_receipt(&encoded, &other, &sender_accept, now).err(),
        Some(ReceiptError::Binding)
    );
    // The receiver cannot verify its own receipt as a sender.
    assert_eq!(
        verify_receipt(&encoded, &receiver_session, &receiver_accept, now).err(),
        Some(ReceiptError::Parties)
    );
    // Only the session's local device signs.
    assert_eq!(
        sign_receipt(
            &fixture.sender,
            &id,
            &receiver_session,
            &receiver_accept,
            time(T0 + 15)?,
            now
        )
        .err(),
        Some(ReceiptError::Role)
    );

    Ok(())
}

/// `completed_at` must be no earlier than establishment less 120 s and no
/// later than the Accept's expiry or the verifier's clock plus 120 s; the
/// totals must match the selection; only the receiver's key signs.
#[test]
fn receipt_time_window_and_totals() -> TestResult {
    let fixture = Fixture::load()?;
    let (_, sender_session, _, sender_accept) = receipt_parts(&fixture)?;
    let id = FixedKeys::id()?;
    let now = time(T0 + 20)?;
    let resign = |completed_at: u64,
                  counts: Option<(u32, u64)>|
     -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let (count, total) = counts.unwrap_or((1, 6));
        let body = ReceiptBody::new(
            SESSION_ID,
            *sender_accept.transfer_id(),
            *sender_accept.manifest_hash(),
            *sender_accept.accept_hash(),
            *sender_session.local_device().as_bytes(),
            *sender_session.peer_device().as_bytes(),
            [9; 16],
            time(completed_at)?,
            count,
            total,
        )?;
        let signature =
            fixture
                .receiver
                .sign(&id, SigningDomain::DeliveryReceipt, &body.encode())?;
        Ok(DeliveryReceipt::new(body, signature.to_bytes())
            .encode()
            .to_vec())
    };
    let late_now = time(fixture.expires_at.seconds() - 1)?;
    for (completed, at, ok) in [
        (T0 - 120, now, true),
        (T0 - 121, now, false),
        (now.seconds() + 120, now, true),
        (now.seconds() + 121, now, false),
        (fixture.expires_at.seconds(), late_now, true),
        (fixture.expires_at.seconds() + 1, late_now, false),
    ] {
        let record = resign(completed, None)?;
        let result = verify_receipt(&record, &sender_session, &sender_accept, at);
        assert_eq!(result.is_ok(), ok, "completed_at {completed}");
        if !ok {
            assert_eq!(result.err(), Some(ReceiptError::Time));
        }
    }
    for counts in [(2, 6), (1, 7), (1, 0)] {
        let record = resign(T0 + 15, Some(counts))?;
        assert_eq!(
            verify_receipt(&record, &sender_session, &sender_accept, now).err(),
            Some(ReceiptError::Totals)
        );
    }
    // Signed by another key.
    let body = *DeliveryReceipt::decode(&resign(T0 + 15, None)?)?.body();
    let forged = DeliveryReceipt::new(
        body,
        FixedKeys::new(0x33)
            .sign(&id, SigningDomain::DeliveryReceipt, &body.encode())?
            .to_bytes(),
    );
    assert_eq!(
        verify_receipt(&forged.encode(), &sender_session, &sender_accept, now).err(),
        Some(ReceiptError::Signature)
    );
    Ok(())
}

#[test]
fn random_ids_are_nonzero_and_fresh() -> TestResult {
    let a = random_id()?;
    let b = random_id()?;
    assert_ne!(a, [0; 16]);
    assert_ne!(a, b);
    Ok(())
}
