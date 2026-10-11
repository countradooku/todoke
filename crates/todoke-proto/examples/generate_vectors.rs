//! Regenerate public, deterministic protocol fixtures. Never supply real secrets.
//!
//! This offline example is not a protocol implementation or a production crypto wrapper.

#![forbid(unsafe_code)]

use std::{error::Error, fs, path::PathBuf};

use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{KeyInit, Mac, SimpleHmac};
use libcrux_hkdf::{Hkdf, Sha2_256};
use libcrux_secrets::{ClassifyRef, ClassifyRefMut};
use serde_json::{Value, json};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const CREATED_AT: u64 = 1_760_000_000;
const EXPIRES_AT: u64 = CREATED_AT + 300;
const TRANSFER_ID: [u8; 16] = [0xa3; 16];
const SESSION_ID: [u8; 32] = [0xa4; 32];
const RATCHET_INFO: &[u8] = b"todoke/v1/psk-ratchet\0";
const MANIFEST_DOMAIN: &[u8] = b"todoke/v1/manifest\0";
const ACCEPT_DOMAIN: &[u8] = b"todoke/v1/accept\0";
const ACCEPT_HASH_DOMAIN: &[u8] = b"todoke/v1/accept-hash\0";
const PUBLIC_FIXTURE_NOTICE: &str = "PUBLIC TEST FIXTURE: all seeds, PSKs, and derived values are fixed and must never be used in production";

fn main() -> Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let check = match arguments.as_slice() {
        [] => false,
        [argument] if argument == "--check" => true,
        _ => {
            return Err(
                "usage: cargo run -p todoke-proto --example generate_vectors -- [--check]".into(),
            );
        }
    };
    let directory = fixture_directory();
    if !check {
        fs::create_dir_all(&directory)?;
    }
    for (name, contents) in encoded_vectors()? {
        let path = directory.join(name);
        if check {
            if fs::read(&path)? != contents {
                return Err(format!("fixture differs: {}", path.display()).into());
            }
        } else {
            fs::write(path, contents)?;
        }
    }
    println!(
        "{} six public fixture files",
        if check { "Verified" } else { "Wrote" }
    );
    Ok(())
}

/// Cargo sets the manifest directory at run time for `cargo run` and `cargo test`.
/// Prefer it so a reused target directory from another checkout cannot point the
/// tool at that checkout's fixtures; fall back to the compile-time value.
fn fixture_directory() -> PathBuf {
    std::env::var_os("CARGO_MANIFEST_DIR")
        .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")), PathBuf::from)
        .join("../../spec/test-vectors")
}

fn encoded_vectors() -> Result<Vec<(&'static str, Vec<u8>)>> {
    let sender_seed = Zeroizing::new([0x11; 32]);
    let receiver_seed = Zeroizing::new([0x22; 32]);
    let sender = public_key(&sender_seed);
    let receiver = public_key(&receiver_seed);
    let manifest = manifest_bytes(&sender, &receiver)?;
    let manifest_hash = domain_hash(MANIFEST_DOMAIN, &manifest);
    let vectors = [
        ("qr-payload.json", qr_vector(&sender)?),
        ("discovery-token.json", discovery_vectors()?),
        ("psk-ratchet.json", ratchet_vector()?),
        ("stream-nonces.json", nonce_vectors()),
        (
            "manifest-hash.json",
            manifest_vector(&sender, &receiver, &manifest, &manifest_hash),
        ),
        (
            "accept-signature.json",
            accept_vector(&sender, &receiver, &receiver_seed, &manifest_hash)?,
        ),
    ];
    vectors
        .into_iter()
        .map(|(name, value)| {
            let mut bytes = serde_json::to_vec_pretty(&value)?;
            bytes.push(b'\n');
            Ok((name, bytes))
        })
        .collect()
}

fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    let mut public = [0; 32];
    libcrux_ed25519::secret_to_public(&mut public, seed);
    public
}

fn domain_hash(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(domain);
    hash.update(payload);
    *blake3::Hasher::finalize(&hash).as_bytes()
}

fn qr_vector(device_key: &[u8; 32]) -> Result<Value> {
    let noise_seed = Zeroizing::new([0x33; 32]);
    let kem_seed = Zeroizing::new([0x44; 64]);
    let psk = Zeroizing::new([0x55; 32]);
    let mut noise_public = [0; 32];
    libcrux_curve25519::secret_to_public(&mut noise_public, &noise_seed);
    let (private, public) = libcrux_ml_kem::mlkem768::generate_key_pair(*kem_seed).into_parts();
    let _private_bytes = Zeroizing::new(<[u8; 2400]>::from(private));
    if !libcrux_ml_kem::mlkem768::validate_public_key(&public) {
        return Err("reference ML-KEM fixture public-key validation failed".into());
    }
    let mut binary = Zeroizing::new(Vec::with_capacity(1312));
    binary.extend_from_slice(b"TDKQ");
    binary.extend_from_slice(&1_u16.to_be_bytes());
    binary.extend_from_slice(&1_u16.to_be_bytes());
    binary.extend_from_slice(&[0xa1; 16]);
    binary.extend_from_slice(&EXPIRES_AT.to_be_bytes());
    binary.extend_from_slice(device_key);
    binary.extend_from_slice(&noise_public);
    binary.extend_from_slice(public.as_slice());
    binary.extend_from_slice(psk.as_slice());
    let base45 = base45::encode(binary.as_slice());
    Ok(json!({
        "fixture_notice": PUBLIC_FIXTURE_NOTICE,
        "protocol_version": 1,
        "hybrid_suite": 1,
        "hybrid_suite_status": "assigned-unreleased; encoding fixture, not a deployable handshake",
        "device_ed25519_seed_hex": hex::encode([0x11; 32]),
        "noise_x25519_seed_hex": hex::encode(noise_seed.as_slice()),
        "mlkem768_keygen_seed_hex": hex::encode(kem_seed.as_slice()),
        "pairing_id_hex": hex::encode([0xa1; 16]),
        "expires_at": EXPIRES_AT,
        "device_ed25519_public_key_hex": hex::encode(device_key),
        "device_id_hex": hex::encode(&blake3::hash(device_key).as_bytes()[..16]),
        "noise_x25519_public_key_hex": hex::encode(noise_public),
        "mlkem768_encapsulation_key_hex": hex::encode(public.as_slice()),
        "one_time_psk_hex": hex::encode(psk.as_slice()),
        "binary_length": binary.len(),
        "binary_hex": hex::encode(binary.as_slice()),
        "base45": base45,
        "qr_text": format!("TODOKE:{base45}")
    }))
}

fn discovery_mac(key: &[u8], epoch: u64) -> Result<[u8; 32]> {
    let mut mac = SimpleHmac::<blake3::Hasher>::new_from_slice(key)?;
    mac.update(&epoch.to_be_bytes());
    Ok(mac.finalize().into_bytes().into())
}

fn discovery_vectors() -> Result<Value> {
    let pair_key = Zeroizing::new([0x66; 32]);
    let mut cases = Vec::new();
    for unix_seconds in [0, 899, 900, 1799, 1800, CREATED_AT] {
        let epoch = unix_seconds / 900;
        let mac = Zeroizing::new(discovery_mac(pair_key.as_slice(), epoch)?);
        cases.push(json!({
            "unix_seconds": unix_seconds,
            "epoch": epoch,
            "epoch_be_hex": hex::encode(epoch.to_be_bytes()),
            "hmac_blake3_hex": hex::encode(mac.as_slice()),
            "token_hex": hex::encode(&mac[..8])
        }));
    }
    Ok(json!({
        "fixture_notice": PUBLIC_FIXTURE_NOTICE,
        "algorithm": "HMAC-BLAKE3 (unkeyed BLAKE3, output 32 bytes, block 64 bytes)",
        "pair_key_hex": hex::encode(pair_key.as_slice()),
        "cases": cases
    }))
}

fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], output: &mut [u8]) -> Result<()> {
    let mut extracted = Zeroizing::new([0; 32]);
    Hkdf::<Sha2_256>::extract(
        extracted.as_mut_slice().classify_ref_mut(),
        salt.classify_ref(),
        ikm.classify_ref(),
    )
    .map_err(|_| "HKDF extraction failed")?;
    Hkdf::<Sha2_256>::expand(
        output.classify_ref_mut(),
        extracted.as_slice().classify_ref(),
        info,
    )
    .map_err(|_| "HKDF expansion failed")?;
    Ok(())
}

fn ratchet_vector() -> Result<Value> {
    let psk = Zeroizing::new([0x55; 32]);
    let handshake_hash = [0x77; 32];
    let mut next_psk = Zeroizing::new([0; 32]);
    hkdf_sha256(
        &handshake_hash,
        psk.as_slice(),
        RATCHET_INFO,
        next_psk.as_mut_slice(),
    )?;
    Ok(json!({
        "fixture_notice": PUBLIC_FIXTURE_NOTICE,
        "algorithm": "HKDF-SHA-256",
        "psk_hex": hex::encode(psk.as_slice()),
        "handshake_hash_and_extract_salt_hex": hex::encode(handshake_hash),
        "expand_info_hex": hex::encode(RATCHET_INFO),
        "output_length": 32,
        "next_psk_hex": hex::encode(next_psk.as_slice())
    }))
}

fn stream_nonce(prefix: &[u8], counter: u32, final_segment: bool) -> Vec<u8> {
    let mut nonce = prefix.to_vec();
    nonce.extend_from_slice(&counter.to_be_bytes());
    nonce.push(u8::from(final_segment));
    nonce
}

fn nonce_vectors() -> Value {
    let mut cases = Vec::new();
    for (suite, prefix) in [(1, vec![0x88; 7]), (2, vec![0x99; 19])] {
        for counter in [0, 1, 65535, u32::MAX] {
            for final_segment in [false, true] {
                // Descriptive fixture metadata, not full file/epoch validation.
                let v1_counter_and_final_permitted =
                    counter <= 65535 && (counter != 65535 || final_segment);
                cases.push(json!({
                    "content_suite": suite,
                    "prefix_hex": hex::encode(&prefix),
                    "counter": counter,
                    "final_segment": final_segment,
                    "v1_counter_and_final_permitted": v1_counter_and_final_permitted,
                    "nonce_hex": hex::encode(stream_nonce(&prefix, counter, final_segment)),
                    "note": if counter == u32::MAX {
                        "primitive nonce-layout example only; counter is forbidden by todoke v1"
                    } else if counter == 65535 && !final_segment {
                        "forbidden in todoke v1: the last segment of an epoch must be final"
                    } else if counter == 0 && final_segment {
                        "nonce for an empty file's sole authenticated final segment"
                    } else { "counter/final combination permitted; actual file length, epoch, and final-position checks still apply" }
                }));
            }
        }
    }
    json!({"fixture_notice": PUBLIC_FIXTURE_NOTICE, "construction": "STREAM-BE32", "cases": cases})
}

fn manifest_bytes(sender: &[u8; 32], receiver: &[u8; 32]) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"TDKM");
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&TRANSFER_ID);
    bytes.extend_from_slice(sender);
    bytes.extend_from_slice(receiver);
    bytes.extend_from_slice(&CREATED_AT.to_be_bytes());
    bytes.extend_from_slice(&EXPIRES_AT.to_be_bytes());
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    bytes.push(1);
    for field in [b"hello.txt".as_slice(), b"text/plain".as_slice()] {
        bytes.extend_from_slice(&u16::try_from(field.len())?.to_be_bytes());
        bytes.extend_from_slice(field);
    }
    bytes.extend_from_slice(&6_u64.to_be_bytes());
    bytes.extend_from_slice(blake3::hash(b"hello\n").as_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    Ok(bytes)
}

fn manifest_vector(sender: &[u8; 32], receiver: &[u8; 32], bytes: &[u8], hash: &[u8; 32]) -> Value {
    json!({
        "fixture_notice": PUBLIC_FIXTURE_NOTICE,
        "version": 1,
        "transfer_id_hex": hex::encode(TRANSFER_ID),
        "sender_ed25519_public_key_hex": hex::encode(sender),
        "recipient_ed25519_public_key_hex": hex::encode(receiver),
        "created_at": CREATED_AT,
        "expires_at": EXPIRES_AT,
        "flags": 0,
        "entries": [{
            "id": 1, "parent": 0, "kind": 1, "name": "hello.txt", "mime": "text/plain", "size": 6,
            "content_hex": hex::encode(b"hello\n"),
            "plaintext_blake3_root_hex": blake3::hash(b"hello\n").to_hex().to_string(),
            "content_suite": 1
        }],
        "hash_domain_hex": hex::encode(MANIFEST_DOMAIN),
        "canonical_length": bytes.len(),
        "canonical_hex": hex::encode(bytes),
        "manifest_hash_hex": hex::encode(hash)
    })
}

fn accept_payload(sender: &[u8; 32], receiver: &[u8; 32], manifest_hash: &[u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&SESSION_ID);
    bytes.extend_from_slice(&TRANSFER_ID);
    bytes.extend_from_slice(manifest_hash);
    bytes.extend_from_slice(sender);
    bytes.extend_from_slice(receiver);
    bytes.extend_from_slice(&[0xa2; 16]);
    bytes.extend_from_slice(&EXPIRES_AT.to_be_bytes());
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes
}

fn sign_accept(payload: &[u8], seed: &[u8; 32]) -> Result<(Vec<u8>, [u8; 64])> {
    let mut message = ACCEPT_DOMAIN.to_vec();
    message.extend_from_slice(payload);
    let signature = libcrux_ed25519::sign(&message, seed).map_err(|_| "Ed25519 signing failed")?;
    let public = public_key(seed);
    libcrux_ed25519::verify(&message, &public, &signature)
        .map_err(|_| "libcrux signature verification failed")?;
    verify_strict(&message, &public, &signature)?;
    Ok((message, signature))
}

// Fixture keys are reference-generated canonical encodings. This helper is not a
// peer-key parser: production also needs the protocol's canonical-key check.
fn verify_strict(message: &[u8], public: &[u8; 32], signature: &[u8; 64]) -> Result<()> {
    let key = VerifyingKey::from_bytes(public).map_err(|_| "invalid Ed25519 public key")?;
    key.verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| "strict Ed25519 verification failed")?;
    Ok(())
}

fn accept_vector(
    sender: &[u8; 32],
    receiver: &[u8; 32],
    seed: &[u8; 32],
    manifest_hash: &[u8; 32],
) -> Result<Value> {
    let payload = accept_payload(sender, receiver, manifest_hash);
    let (message, signature) = sign_accept(&payload, seed)?;
    let mut wire = payload.clone();
    wire.extend_from_slice(&signature);
    Ok(json!({
        "fixture_notice": PUBLIC_FIXTURE_NOTICE,
        "version": 1,
        "session_id_hex": hex::encode(SESSION_ID),
        "transfer_id_hex": hex::encode(TRANSFER_ID),
        "manifest_hash_hex": hex::encode(manifest_hash),
        "sender_ed25519_public_key_hex": hex::encode(sender),
        "receiver_ed25519_public_key_hex": hex::encode(receiver),
        "receiver_ed25519_seed_hex": hex::encode(seed),
        "accept_nonce_hex": hex::encode([0xa2; 16]),
        "expires_at": EXPIRES_AT,
        "selected_ids": [1],
        "signed_payload_hex": hex::encode(&payload),
        "signing_domain_hex": hex::encode(ACCEPT_DOMAIN),
        "signing_message_hex": hex::encode(message),
        "signature_hex": hex::encode(signature),
        "signed_record_length": wire.len(),
        "signed_record_hex": hex::encode(&wire),
        "accept_hash_domain_hex": hex::encode(ACCEPT_HASH_DOMAIN),
        "accept_hash_hex": hex::encode(domain_hash(ACCEPT_HASH_DOMAIN, &wire))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base45_matches_rfc9285_examples() -> Result<()> {
        for (plain, encoded) in [
            ("AB", "BB8"),
            ("Hello!!", "%69 VD92EX0"),
            ("base-45", "UJCLQE7W581"),
        ] {
            assert_eq!(base45::encode(plain), encoded);
            assert_eq!(base45::decode(encoded)?, plain.as_bytes());
        }
        Ok(())
    }

    #[test]
    fn hkdf_matches_rfc5869_case_one() -> Result<()> {
        let ikm = Zeroizing::new([0x0b; 22]);
        let salt = hex::decode("000102030405060708090a0b0c")?;
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9")?;
        let mut output = Zeroizing::new([0; 42]);
        hkdf_sha256(&salt, ikm.as_slice(), &info, output.as_mut_slice())?;
        assert_eq!(
            hex::encode(output.as_slice()),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
        Ok(())
    }

    #[test]
    fn ed25519_matches_rfc8032_empty_message() -> Result<()> {
        let seed = Zeroizing::new(hex::decode(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        )?);
        let seed_array = seed.as_slice().try_into()?;
        let public = public_key(seed_array);
        let signature =
            libcrux_ed25519::sign(b"", seed_array).map_err(|_| "RFC Ed25519 signing failed")?;
        assert_eq!(
            hex::encode(public),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        assert_eq!(
            hex::encode(signature),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        verify_strict(b"", &public, &signature)
    }

    #[test]
    fn qr_fixture_has_exact_length_and_base45_roundtrips() -> Result<()> {
        let seed = Zeroizing::new([0x11; 32]);
        let fixture = qr_vector(&public_key(&seed))?;
        let encoded = fixture["base45"].as_str().ok_or("missing Base45 fixture")?;
        let binary = base45::decode(encoded)?;
        assert_eq!(binary.len(), 1312);
        assert_eq!(&binary[..8], b"TDKQ\x00\x01\x00\x01");
        assert_eq!(hex::encode(binary), fixture["binary_hex"]);
        Ok(())
    }

    #[test]
    fn qr_x25519_public_key_supports_matching_key_agreement() -> Result<()> {
        let device_seed = Zeroizing::new([0x11; 32]);
        let fixture = qr_vector(&public_key(&device_seed))?;
        let fixture_public = hex::decode(
            fixture["noise_x25519_public_key_hex"]
                .as_str()
                .ok_or("missing X25519 fixture")?,
        )?;
        let fixture_public = fixture_public.as_slice().try_into()?;
        let fixture_seed = Zeroizing::new([0x33; 32]);
        let other_seed = Zeroizing::new([0xab; 32]);
        let mut other_public = [0; 32];
        libcrux_curve25519::secret_to_public(&mut other_public, &other_seed);
        let mut first_shared = Zeroizing::new([0; 32]);
        let mut second_shared = Zeroizing::new([0; 32]);
        libcrux_curve25519::ecdh(&mut first_shared, fixture_public, &other_seed)
            .map_err(|_| "fixture X25519 agreement failed")?;
        libcrux_curve25519::ecdh(&mut second_shared, &other_public, &fixture_seed)
            .map_err(|_| "peer X25519 agreement failed")?;
        // Keep even synthetic shared-key bytes out of failure diagnostics.
        if first_shared.as_slice() != second_shared.as_slice() {
            return Err("X25519 fixture shared keys differ".into());
        }
        assert!(first_shared.iter().any(|byte| *byte != 0));
        assert!(libcrux_curve25519::ecdh(&mut second_shared, &[0; 32], &fixture_seed).is_err());
        Ok(())
    }

    #[test]
    fn qr_mlkem_public_key_encapsulates_to_matching_private_key() -> Result<()> {
        use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768PublicKey};

        let device_seed = Zeroizing::new([0x11; 32]);
        let fixture = qr_vector(&public_key(&device_seed))?;
        let fixture_public = hex::decode(
            fixture["mlkem768_encapsulation_key_hex"]
                .as_str()
                .ok_or("missing ML-KEM fixture")?,
        )?;
        let fixture_public = MlKem768PublicKey::try_from(fixture_public.as_slice())?;
        assert!(mlkem768::validate_public_key(&fixture_public));
        let keygen_seed = Zeroizing::new([0x44; 64]);
        let encapsulation_seed = Zeroizing::new([0xab; 32]);
        let (private, _) = mlkem768::generate_key_pair(*keygen_seed).into_parts();
        let (ciphertext, shared) = mlkem768::encapsulate(&fixture_public, *encapsulation_seed);
        let shared = Zeroizing::new(shared);
        let recovered = Zeroizing::new(mlkem768::decapsulate(&private, &ciphertext));
        let mut altered_ciphertext: [u8; 1088] = ciphertext.into();
        altered_ciphertext[0] ^= 1;
        let rejected = Zeroizing::new(mlkem768::decapsulate(
            &private,
            &MlKem768Ciphertext::from(altered_ciphertext),
        ));
        let _private_bytes = Zeroizing::new(<[u8; 2400]>::from(private));
        if shared.as_slice() != recovered.as_slice() {
            return Err("ML-KEM fixture shared keys differ".into());
        }
        if shared.as_slice() == rejected.as_slice() {
            return Err("ML-KEM fixture did not reject altered ciphertext".into());
        }
        Ok(())
    }

    #[test]
    fn accept_rejects_tampering_wrong_key_and_domain() -> Result<()> {
        let seed = Zeroizing::new([0x22; 32]);
        let receiver = public_key(&seed);
        let sender_seed = Zeroizing::new([0x11; 32]);
        let sender = public_key(&sender_seed);
        let payload = accept_payload(&sender, &receiver, &[0x33; 32]);
        let (message, signature) = sign_accept(&payload, &seed)?;
        for index in 0..message.len() {
            let mut changed = message.clone();
            changed[index] ^= 1;
            assert!(verify_strict(&changed, &receiver, &signature).is_err());
        }
        assert!(verify_strict(&payload, &receiver, &signature).is_err());
        assert!(verify_strict(&message, &sender, &signature).is_err());
        let mut changed_signature = signature;
        changed_signature[63] |= 0xe0;
        assert!(verify_strict(&message, &receiver, &changed_signature).is_err());
        Ok(())
    }

    #[test]
    fn strict_verification_rejects_small_order_key() {
        let mut identity = [0; 32];
        identity[0] = 1;
        let mut forged = [0; 64];
        forged[..32].copy_from_slice(&identity);
        assert!(verify_strict(b"public low-order forgery", &identity, &forged).is_err());
    }

    #[test]
    fn discovery_rotates_exactly_at_epoch_boundary() -> Result<()> {
        let key = Zeroizing::new([0x66; 32]);
        assert_ne!(
            discovery_mac(key.as_slice(), 0)?,
            discovery_mac(key.as_slice(), 1)?
        );
        Ok(())
    }

    #[test]
    fn committed_vectors_match_regeneration() -> Result<()> {
        let directory = fixture_directory();
        for (name, bytes) in encoded_vectors()? {
            assert_eq!(
                fs::read(directory.join(name))?,
                bytes,
                "fixture mismatch: {name}"
            );
        }
        Ok(())
    }
}
