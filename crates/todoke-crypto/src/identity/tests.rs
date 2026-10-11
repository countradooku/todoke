//! Identity known-answer, negative, and property tests.

use proptest::prelude::*;
use todoke_proto::identity::{DeviceBinding, RevocationReason, Revoke};

use super::test_support::{DAY, Enrolled, T0, TestResult, kem_static, nz, request, time};
use super::{
    ApplyOutcome, BindingError, CLOCK_SKEW_SECONDS, DeviceId, DeviceIdentity, Ed25519PublicKey,
    ExportPolicy, IssueError, KeyRole, KeyStore, KeyStoreError, PersonId, PersonIdentity,
    RevocationError, RevocationRecord, RevocationRequest, RevocationSet, Signature, SigningDomain,
    issue_device_binding, issue_revocation,
};

fn bytes<const N: usize>(text: &str) -> Result<[u8; N], Box<dyn std::error::Error>> {
    hex::decode(text)?
        .try_into()
        .map_err(|_| "wrong length".into())
}

// RFC 8032 §7.1, TEST 1–3 (pure Ed25519).
const RFC8032: [(&str, &str, &str, &str); 3] = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
];

#[test]
fn rfc8032_sign_and_verify_vectors() -> TestResult {
    for (seed, public, message, signature) in RFC8032 {
        let seed = bytes::<32>(seed)?;
        let message = hex::decode(message)?;
        let mut derived = [0; 32];
        libcrux_ed25519::secret_to_public(&mut derived, &seed);
        assert_eq!(derived, bytes::<32>(public)?);
        let expected = bytes::<64>(signature)?;
        let signed = libcrux_ed25519::sign(&message, &seed).map_err(|_| "signing failed")?;
        assert_eq!(signed, expected);
        let key = Ed25519PublicKey::from_bytes(&derived)?;
        key.verify_input(&message, &Signature::from_bytes(expected))?;
        let mut tampered = message.clone();
        tampered.push(0);
        assert!(
            key.verify_input(&tampered, &Signature::from_bytes(expected))
                .is_err()
        );
    }
    Ok(())
}

/// The committed `accept-signature.json` fixture, produced by the vector
/// generator, must match the key store's domain handling and verification.
#[test]
fn accept_fixture_matches_key_store_signing() -> TestResult {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../spec/test-vectors/accept-signature.json"
    ))?;
    let field = |name: &str| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(hex::decode(fixture[name].as_str().ok_or("missing field")?)?)
    };
    assert_eq!(field("signing_domain_hex")?, SigningDomain::Accept.bytes());
    let seed: [u8; 32] = field("receiver_ed25519_seed_hex")?
        .try_into()
        .map_err(|_| "seed length")?;
    let payload = field("signed_payload_hex")?;
    let expected: [u8; 64] = field("signature_hex")?
        .try_into()
        .map_err(|_| "signature length")?;

    let mut store = super::test_support::memory_keystore()?;
    let key = store.insert_fixed_seed(KeyRole::Device, seed)?;
    assert_eq!(
        store.public_key(&key)?.as_bytes().as_slice(),
        field("receiver_ed25519_public_key_hex")?
    );
    let signature = store.sign(&key, SigningDomain::Accept, &payload)?;
    assert_eq!(signature.to_bytes(), expected);
    store
        .public_key(&key)?
        .verify(SigningDomain::Accept, &payload, &signature)?;
    // The same bytes under another domain must not verify.
    assert!(
        store
            .public_key(&key)?
            .verify(SigningDomain::DeliveryReceipt, &payload, &signature)
            .is_err()
    );
    Ok(())
}

#[test]
fn signature_mutations_are_rejected() -> TestResult {
    let enrolled = Enrolled::new()?;
    let public = enrolled.store.public_key(&enrolled.device)?;
    let message = b"todoke identity test message";
    let signature = enrolled
        .store
        .sign(&enrolled.device, SigningDomain::Identity, message)?
        .to_bytes();
    for index in 0..64 {
        for bit in 0..8 {
            let mut changed = signature;
            changed[index] ^= 1 << bit;
            assert!(
                public
                    .verify(
                        SigningDomain::Identity,
                        message,
                        &Signature::from_bytes(changed)
                    )
                    .is_err()
            );
        }
    }
    for index in 0..message.len() {
        let mut changed = *message;
        changed[index] ^= 1;
        assert!(
            public
                .verify(
                    SigningDomain::Identity,
                    &changed,
                    &Signature::from_bytes(signature)
                )
                .is_err()
        );
    }
    Ok(())
}

/// Adds the group order to `s`, giving the same value mod l in a
/// noncanonical encoding.
#[test]
fn noncanonical_scalar_is_rejected() -> TestResult {
    const ORDER: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let enrolled = Enrolled::new()?;
    let public = enrolled.store.public_key(&enrolled.device)?;
    let mut signature = enrolled
        .store
        .sign(&enrolled.device, SigningDomain::Accept, b"m")?
        .to_bytes();
    let mut carry = 0u16;
    for (byte, order) in signature[32..].iter_mut().zip(ORDER) {
        let sum = u16::from(*byte) + u16::from(order) + carry;
        *byte = sum.to_le_bytes()[0];
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    assert!(
        public
            .verify(
                SigningDomain::Accept,
                b"m",
                &Signature::from_bytes(signature)
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn small_order_and_noncanonical_keys_are_rejected() {
    // Identity point and its noncanonical "negative zero" encoding.
    let mut identity = [0; 32];
    identity[0] = 1;
    assert!(Ed25519PublicKey::from_bytes(&identity).is_err());
    identity[31] = 0x80;
    assert!(Ed25519PublicKey::from_bytes(&identity).is_err());
    // The order-2 point (0, -1).
    let mut minus_one = [0xff; 32];
    minus_one[0] = 0xec;
    minus_one[31] = 0x7f;
    assert!(Ed25519PublicKey::from_bytes(&minus_one).is_err());

    // y + p for small y: decodable by some libraries, never canonical.
    let mut decodable_by_dalek = 0;
    for y in 0..19u8 {
        for sign in [0, 0x80] {
            let mut encoding = [0xff; 32];
            encoding[0] = 0xed + y;
            encoding[31] = 0x7f | sign;
            assert!(Ed25519PublicKey::from_bytes(&encoding).is_err());
            if ed25519_dalek::VerifyingKey::from_bytes(&encoding).is_ok() {
                decodable_by_dalek += 1;
            }
        }
    }
    // Shows why §1 requires the extra canonical-encoding check.
    assert!(decodable_by_dalek > 0);
}

#[test]
fn ids_are_truncated_blake3() -> TestResult {
    let enrolled = Enrolled::new()?;
    let device = DeviceIdentity::load(&enrolled.store, enrolled.device)?;
    let digest = blake3::hash(device.public_key().as_bytes());
    assert_eq!(device.id().as_bytes(), &digest.as_bytes()[..16]);
    assert_eq!(device.id(), DeviceId::of(device.public_key()));
    let root = enrolled.store.public_key(&enrolled.root)?;
    let person = PersonIdentity::new(root);
    assert_eq!(
        person.id().as_bytes(),
        &blake3::hash(root.as_bytes()).as_bytes()[..16]
    );
    assert_eq!(person.id(), PersonId::of(&root));
    assert_eq!(
        DeviceIdentity::load(&enrolled.store, enrolled.root),
        Err(KeyStoreError::WrongRole)
    );
    Ok(())
}

#[test]
fn device_identity_generation_is_non_exportable() -> TestResult {
    let mut store = super::test_support::memory_keystore()?;
    let device = DeviceIdentity::generate(&mut store)?;
    assert_eq!(store.role(&device.key())?, KeyRole::Device);
    assert_eq!(
        store.export_wrapped(&device.key(), &super::WrappingKey::generate()?),
        Err(KeyStoreError::NotExportable)
    );
    Ok(())
}

#[test]
fn issued_binding_verifies_and_round_trips() -> TestResult {
    let enrolled = Enrolled::new()?;
    let verified = enrolled.bind(1)?;
    let root = PersonIdentity::new(enrolled.store.public_key(&enrolled.root)?);
    let decoded = DeviceBinding::decode(&verified.encode())?;
    let again = root.verify_binding(&decoded, time(T0)?, &RevocationSet::new())?;
    assert_eq!(again, verified);
    assert_eq!(
        verified.device_public(),
        &enrolled.store.public_key(&enrolled.device)?
    );
    assert_eq!(verified.person_root(), root.root());
    assert_eq!(verified.noise_static(), &[0x33; 32]);
    assert_eq!(verified.kem_static(), &*kem_static(0x44));
    assert_eq!(verified.serial(), nz(1)?);
    Ok(())
}

#[test]
fn binding_chain_rejects_wrong_root_and_any_tampering() -> TestResult {
    let enrolled = Enrolled::new()?;
    let other = Enrolled::new()?;
    let encoded = enrolled.bind(1)?.encode();
    let root = PersonIdentity::new(enrolled.store.public_key(&enrolled.root)?);
    let now = time(T0)?;
    let revocations = RevocationSet::new();

    let stranger = PersonIdentity::new(other.store.public_key(&other.root)?);
    assert_eq!(
        stranger.verify_binding(&DeviceBinding::decode(&encoded)?, now, &revocations),
        Err(BindingError::UntrustedRoot)
    );
    // Flip one bit in every byte that decoding still accepts: device key,
    // Noise key, KEM key, serial, times, and both signatures.
    for index in 2..encoded.len() {
        let mut changed = encoded.clone();
        changed[index] ^= 0x01;
        let Ok(binding) = DeviceBinding::decode(&changed) else {
            continue;
        };
        let result = root.verify_binding(&binding, now, &revocations);
        if index < 34 {
            assert_eq!(result, Err(BindingError::UntrustedRoot), "byte {index}");
        } else {
            assert!(
                matches!(
                    result,
                    Err(BindingError::InvalidSignature | BindingError::InvalidKey)
                ),
                "byte {index}: {result:?}"
            );
        }
    }
    Ok(())
}

/// A root signature cannot be reused to certify a key whose holder did not
/// sign possession.
#[test]
fn possession_signature_must_come_from_the_certified_device() -> TestResult {
    let enrolled = Enrolled::new()?;
    let other = Enrolled::new()?;
    let genuine = enrolled.bind(1)?;
    let body = genuine.binding().body().clone();
    let forged_possession = other
        .store
        .sign(
            &other.device,
            SigningDomain::DevicePossession,
            &[body.encode(), genuine.binding().root_signature().to_vec()].concat(),
        )?
        .to_bytes();
    let forged =
        DeviceBinding::from_parts(body, *genuine.binding().root_signature(), forged_possession);
    let root = PersonIdentity::new(enrolled.store.public_key(&enrolled.root)?);
    assert_eq!(
        root.verify_binding(&forged, time(T0)?, &RevocationSet::new()),
        Err(BindingError::InvalidSignature)
    );
    Ok(())
}

#[test]
fn binding_validity_window_and_skew() -> TestResult {
    let enrolled = Enrolled::new()?;
    let binding = enrolled.bind(1)?.binding().clone();
    let root = PersonIdentity::new(enrolled.store.public_key(&enrolled.root)?);
    let revocations = RevocationSet::new();
    let not_after = T0 + 30 * DAY;
    let check = |now: u64| -> Result<Result<(), BindingError>, &'static str> {
        Ok(root
            .verify_binding(&binding, time(now)?, &revocations)
            .map(|_| ()))
    };
    assert_eq!(
        check(T0 - CLOCK_SKEW_SECONDS - 1)?,
        Err(BindingError::NotYetValid)
    );
    assert_eq!(check(T0 - CLOCK_SKEW_SECONDS)?, Ok(()));
    assert_eq!(check(T0)?, Ok(()));
    assert_eq!(check(not_after - 1)?, Ok(()));
    assert_eq!(check(not_after + CLOCK_SKEW_SECONDS - 1)?, Ok(()));
    assert_eq!(
        check(not_after + CLOCK_SKEW_SECONDS)?,
        Err(BindingError::Expired)
    );
    Ok(())
}

#[test]
fn issuance_validates_roles_keys_and_window() -> TestResult {
    let enrolled = Enrolled::new()?;
    let issue =
        |root, device, request| issue_device_binding(&enrolled.store, root, device, request);
    assert_eq!(
        issue(
            &enrolled.device,
            &enrolled.device,
            request(1, 2, 1, T0, T0 + DAY)?
        ),
        Err(IssueError::WrongRole)
    );
    assert_eq!(
        issue(
            &enrolled.root,
            &enrolled.root,
            request(1, 2, 1, T0, T0 + DAY)?
        ),
        Err(IssueError::WrongRole)
    );
    let mut bad_kem = request(1, 2, 1, T0, T0 + DAY)?;
    // Coefficients must be < q = 3329; 0xff bytes encode 4095.
    bad_kem.kem_static[..384].fill(0xff);
    assert_eq!(
        issue(&enrolled.root, &enrolled.device, bad_kem),
        Err(IssueError::InvalidKey)
    );
    assert_eq!(
        issue(&enrolled.root, &enrolled.device, request(1, 2, 1, T0, T0)?),
        Err(IssueError::InvalidValidity)
    );
    assert_eq!(
        issue(
            &enrolled.root,
            &enrolled.device,
            request(1, 2, 1, T0, T0 + 366 * DAY + 1)?
        ),
        Err(IssueError::InvalidValidity)
    );
    assert!(
        issue(
            &enrolled.root,
            &enrolled.device,
            request(1, 2, 1, T0, T0 + 366 * DAY)?
        )
        .is_ok()
    );
    Ok(())
}

/// The canonical small-order X25519 u-coordinates (as in libsodium) plus
/// their encodings with the ignored high bit set. Independently checked
/// against libcrux X25519 in `noise_static_blocklist_matches_x25519`.
fn small_order_encodings() -> Vec<[u8; 32]> {
    let mut canonical = vec![[0; 32], [0; 32]];
    canonical[1][0] = 1;
    canonical.push(
        bytes::<32>("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")
            .unwrap_or_default(),
    );
    canonical.push(
        bytes::<32>("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157")
            .unwrap_or_default(),
    );
    for low in [0xec, 0xed, 0xee] {
        let mut value = [0xff; 32];
        value[0] = low;
        value[31] = 0x7f;
        canonical.push(value);
    }
    let mut all = canonical.clone();
    for mut value in canonical {
        value[31] |= 0x80;
        all.push(value);
    }
    all
}

/// Signs a binding body directly, bypassing issuance checks.
fn sign_binding_with_noise(
    enrolled: &Enrolled,
    noise_static: [u8; 32],
) -> Result<DeviceBinding, Box<dyn std::error::Error>> {
    let body = todoke_proto::identity::DeviceBindingBody::new(
        *enrolled.store.public_key(&enrolled.root)?.as_bytes(),
        *enrolled.store.public_key(&enrolled.device)?.as_bytes(),
        noise_static,
        kem_static(0x44),
        nz(1)?,
        time(T0)?,
        time(T0 + DAY)?,
    )?;
    let root_signature = enrolled
        .store
        .sign(&enrolled.root, SigningDomain::DeviceBinding, &body.encode())?
        .to_bytes();
    let possession = enrolled
        .store
        .sign(
            &enrolled.device,
            SigningDomain::DevicePossession,
            &[body.encode(), root_signature.to_vec()].concat(),
        )?
        .to_bytes();
    Ok(DeviceBinding::from_parts(body, root_signature, possession))
}

/// §1 "Public keys MUST be validated before use"; §2 `noise_static` is a
/// valid X25519 public key. All-zero and small-order points are not.
#[test]
fn small_order_noise_static_is_rejected() -> TestResult {
    let enrolled = Enrolled::new()?;
    let root = PersonIdentity::new(enrolled.store.public_key(&enrolled.root)?);
    let encodings = small_order_encodings();
    assert_eq!(encodings.len(), 14);
    for noise in encodings {
        let mut request = request(1, 2, 1, T0, T0 + DAY)?;
        request.noise_static = noise;
        assert_eq!(
            issue_device_binding(&enrolled.store, &enrolled.root, &enrolled.device, request),
            Err(IssueError::InvalidKey),
            "{noise:02x?}"
        );
        let binding = sign_binding_with_noise(&enrolled, noise)?;
        assert_eq!(
            root.verify_binding(&binding, time(T0)?, &RevocationSet::new()),
            Err(BindingError::InvalidKey),
            "{noise:02x?}"
        );
    }
    // A real X25519 public key is accepted on both paths.
    let mut public = [0; 32];
    libcrux_curve25519::secret_to_public(&mut public, &[0x42; 32]);
    let binding = sign_binding_with_noise(&enrolled, public)?;
    assert!(
        root.verify_binding(&binding, time(T0)?, &RevocationSet::new())
            .is_ok()
    );
    Ok(())
}

/// The blocklist agrees with an independent X25519 implementation: with a
/// clamped scalar (a multiple of the cofactor 8) the shared output is all zero
/// exactly for small-order inputs, which libcrux reports as an error.
#[test]
fn noise_static_blocklist_matches_x25519() {
    let mut shared = [0; 32];
    for noise in small_order_encodings() {
        assert!(!super::binding::noise_static_is_valid(&noise));
        assert!(libcrux_curve25519::ecdh(&mut shared, &noise, &[0x42; 32]).is_err());
    }
    // Generated public keys, and their high-bit variants, are valid.
    for seed in 0..=255u8 {
        let mut public = [0; 32];
        libcrux_curve25519::secret_to_public(&mut public, &[seed; 32]);
        for high in [0, 0x80] {
            let mut encoding = public;
            encoding[31] |= high;
            assert!(super::binding::noise_static_is_valid(&encoding));
            assert!(libcrux_curve25519::ecdh(&mut shared, &encoding, &[0x42; 32]).is_ok());
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn noise_static_validity_is_x25519_nonzero_output(noise in any::<[u8; 32]>()) {
        let mut shared = [0; 32];
        prop_assert_eq!(
            super::binding::noise_static_is_valid(&noise),
            libcrux_curve25519::ecdh(&mut shared, &noise, &[0x42; 32]).is_ok()
        );
    }
}

fn revoke(
    enrolled: &Enrolled,
    sequence: u64,
    through_serial: u64,
) -> Result<RevocationRecord, Box<dyn std::error::Error>> {
    Ok(issue_revocation(
        &enrolled.store,
        &enrolled.root,
        RevocationRequest {
            device_public: enrolled.store.public_key(&enrolled.device)?,
            sequence: nz(sequence)?,
            issued_at: time(T0 + DAY)?,
            through_serial: nz(through_serial)?,
            reason: RevocationReason::Compromised,
        },
    )?)
}

#[test]
fn revocation_rejects_old_subkeys_but_not_renewals() -> TestResult {
    let enrolled = Enrolled::new()?;
    let root = PersonIdentity::new(enrolled.store.public_key(&enrolled.root)?);
    let old = enrolled.bind(1)?.binding().clone();
    let middle = enrolled.bind(2)?.binding().clone();
    let renewed = enrolled.bind(3)?.binding().clone();
    let now = time(T0 + DAY)?;
    let mut revocations = RevocationSet::new();
    assert_eq!(
        revocations.apply(revoke(&enrolled, 1, 2)?),
        ApplyOutcome::Added
    );
    assert_eq!(
        root.verify_binding(&old, now, &revocations),
        Err(BindingError::Revoked)
    );
    assert_eq!(
        root.verify_binding(&middle, now, &revocations),
        Err(BindingError::Revoked)
    );
    assert!(root.verify_binding(&renewed, now, &revocations).is_ok());
    Ok(())
}

#[test]
fn revocation_verification_failures() -> TestResult {
    let enrolled = Enrolled::new()?;
    let other = Enrolled::new()?;
    let record = revoke(&enrolled, 1, 1)?.record().clone();
    let root = PersonIdentity::new(enrolled.store.public_key(&enrolled.root)?);
    let stranger = PersonIdentity::new(other.store.public_key(&other.root)?);
    assert_eq!(
        RevocationRecord::verify(record.clone(), &stranger),
        Err(RevocationError::UntrustedRoot)
    );
    let encoded = record.encode();
    for index in 34..encoded.len() {
        let mut changed = encoded.clone();
        changed[index] ^= 0x01;
        if let Ok(changed) = Revoke::decode(&changed) {
            assert!(
                RevocationRecord::verify(changed, &root).is_err(),
                "byte {index}"
            );
        }
    }
    assert!(RevocationRecord::verify(record, &root).is_ok());
    // A device key cannot sign revocations.
    assert!(matches!(
        issue_revocation(
            &enrolled.store,
            &enrolled.device,
            RevocationRequest {
                device_public: enrolled.store.public_key(&enrolled.device)?,
                sequence: nz(1)?,
                issued_at: time(T0)?,
                through_serial: nz(1)?,
                reason: RevocationReason::Lost,
            },
        ),
        Err(IssueError::WrongRole)
    ));
    Ok(())
}

#[test]
fn duplicate_conflict_and_out_of_order_records() -> TestResult {
    let enrolled = Enrolled::new()?;
    let root = enrolled.store.public_key(&enrolled.root)?;
    let device = enrolled.store.public_key(&enrolled.device)?;
    let first = revoke(&enrolled, 5, 1)?;
    let older = revoke(&enrolled, 2, 4)?;
    let mut set = RevocationSet::new();
    assert_eq!(set.apply(first.clone()), ApplyOutcome::Added);
    assert_eq!(set.apply(first.clone()), ApplyOutcome::Duplicate);
    // A valid older record must still be applied.
    assert_eq!(set.apply(older), ApplyOutcome::Added);
    assert!(set.is_revoked(&root, &device, nz(4)?));
    assert!(!set.is_revoked(&root, &device, nz(5)?));
    assert!(!set.is_root_disabled(&root));
    assert_eq!(set.len(), 2);
    // Same sequence, different body: conflict disables the root.
    let conflicting = revoke(&enrolled, 5, 9)?;
    assert_eq!(set.apply(conflicting), ApplyOutcome::Conflict);
    assert!(set.is_root_disabled(&root));
    assert_eq!(set.records_for(&root).count(), 2);
    let binding = enrolled.bind(10)?.binding().clone();
    assert_eq!(
        PersonIdentity::new(root).verify_binding(&binding, time(T0)?, &set),
        Err(BindingError::RootDisabled)
    );
    Ok(())
}

/// §2: records are irrevocable and retained; a conflict needs local
/// resolution, so both signed records must survive as evidence.
#[test]
fn conflicting_records_are_retained_as_evidence() -> TestResult {
    let enrolled = Enrolled::new()?;
    let root = enrolled.store.public_key(&enrolled.root)?;
    let device = enrolled.store.public_key(&enrolled.device)?;
    let first = revoke(&enrolled, 5, 1)?;
    let conflicting = revoke(&enrolled, 5, 9)?;
    let third = revoke(&enrolled, 5, 3)?;
    let mut set = RevocationSet::new();
    assert_eq!(set.apply(first.clone()), ApplyOutcome::Added);
    assert_eq!(set.apply(conflicting.clone()), ApplyOutcome::Conflict);
    assert_eq!(set.len(), 2);
    assert_eq!(set.records_for(&root).collect::<Vec<_>>(), [first.record()]);
    assert_eq!(
        set.conflicting_records_for(&root).collect::<Vec<_>>(),
        [conflicting.record()]
    );
    // Receiving retained evidence again is idempotent.
    assert_eq!(set.apply(conflicting.clone()), ApplyOutcome::Duplicate);
    assert_eq!(set.len(), 2);
    // Further distinct records for the same sequence are kept too.
    assert_eq!(set.apply(third.clone()), ApplyOutcome::Conflict);
    assert_eq!(set.len(), 3);
    let mut evidence: Vec<_> = set.conflicting_records_for(&root).cloned().collect();
    evidence.sort_by_key(todoke_proto::identity::Revoke::encode);
    let mut expected = vec![conflicting.record().clone(), third.record().clone()];
    expected.sort_by_key(todoke_proto::identity::Revoke::encode);
    assert_eq!(evidence, expected);
    assert!(set.is_root_disabled(&root));
    // Every root-signed record is honoured (fail closed).
    assert!(set.is_revoked(&root, &device, nz(9)?));
    assert!(set.conflicting_records_for(&device).next().is_none());
    Ok(())
}

/// Conflict evidence counts toward the per-root quota; when the quota is
/// full the root is still disabled but the extra record is not retained.
#[test]
fn conflict_evidence_is_bounded_by_quota() -> TestResult {
    let enrolled = Enrolled::new()?;
    let root = enrolled.store.public_key(&enrolled.root)?;
    let mut set = RevocationSet::new();
    let quota = super::MAX_RECORDS_PER_ROOT as u64;
    for sequence in 1..quota {
        assert_eq!(
            set.apply(revoke(&enrolled, sequence, 1)?),
            ApplyOutcome::Added
        );
    }
    assert_eq!(set.apply(revoke(&enrolled, 1, 2)?), ApplyOutcome::Conflict);
    assert_eq!(set.len(), super::MAX_RECORDS_PER_ROOT);
    assert_eq!(set.apply(revoke(&enrolled, 1, 3)?), ApplyOutcome::Conflict);
    assert_eq!(set.len(), super::MAX_RECORDS_PER_ROOT);
    assert_eq!(set.conflicting_records_for(&root).count(), 1);
    assert!(set.is_root_disabled(&root));
    Ok(())
}

#[test]
fn revocation_quota_disables_root() -> TestResult {
    let enrolled = Enrolled::new()?;
    let root = enrolled.store.public_key(&enrolled.root)?;
    let mut set = RevocationSet::new();
    for sequence in 1..=super::MAX_RECORDS_PER_ROOT as u64 {
        assert_eq!(
            set.apply(revoke(&enrolled, sequence, 1)?),
            ApplyOutcome::Added
        );
    }
    assert!(!set.is_root_disabled(&root));
    let extra = revoke(&enrolled, super::MAX_RECORDS_PER_ROOT as u64 + 1, 1)?;
    assert_eq!(set.apply(extra), ApplyOutcome::QuotaExceeded);
    assert!(set.is_root_disabled(&root));
    Ok(())
}

#[test]
fn person_root_export_policy() -> TestResult {
    let mut store = super::test_support::memory_keystore()?;
    let root = store.generate(KeyRole::PersonRoot, ExportPolicy::Exportable)?;
    assert!(
        store
            .export_wrapped(&root, &super::WrappingKey::generate()?)
            .is_ok()
    );
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Applying the same non-conflicting records in any order yields the same
    /// revocation decisions (§2: older records still apply).
    #[test]
    fn revocation_order_does_not_matter(
        throughs in proptest::collection::vec(1..20u64, 1..8),
        order in any::<proptest::sample::Index>(),
        rotate in any::<proptest::sample::Index>(),
    ) {
        let enrolled = Enrolled::new().map_err(|error| TestCaseError::fail(error.to_string()))?;
        let root = enrolled.store.public_key(&enrolled.root)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let device = enrolled.store.public_key(&enrolled.device)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let mut records = Vec::new();
        for (index, through) in throughs.iter().enumerate() {
            let sequence = u64::try_from(index).unwrap_or(u64::MAX) + 1;
            records.push(revoke(&enrolled, sequence, *through)
                .map_err(|error| TestCaseError::fail(error.to_string()))?);
        }
        let mut forward = RevocationSet::new();
        for record in &records {
            prop_assert_eq!(forward.apply(record.clone()), ApplyOutcome::Added);
        }
        let mut shuffled = records.clone();
        let len = shuffled.len();
        shuffled.swap(order.index(len), 0);
        shuffled.rotate_left(rotate.index(len));
        let mut other = RevocationSet::new();
        for record in shuffled {
            prop_assert_eq!(other.apply(record), ApplyOutcome::Added);
        }
        let max = throughs.iter().copied().max().unwrap_or(0);
        for serial in 1..25u64 {
            let serial = nz(serial).map_err(TestCaseError::fail)?;
            prop_assert_eq!(
                forward.is_revoked(&root, &device, serial),
                other.is_revoked(&root, &device, serial)
            );
            prop_assert_eq!(forward.is_revoked(&root, &device, serial), serial.get() <= max);
        }
    }
}
