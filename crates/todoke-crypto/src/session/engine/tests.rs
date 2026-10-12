//! Conformance of the runtime engine with the committed §4.2 transcripts,
//! the published classical Noise vectors, and NIST's ML-KEM-768 vectors.

use super::*;
use crate::session::test_vectors::{Vector, hex_array_at, hex_at, json_at, load};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const PROFILES: [(&str, Pattern); 3] = [
    ("handshake-ikpsk2.json", Pattern::IkPsk2),
    ("handshake-kkpsk2.json", Pattern::KkPsk2),
    ("handshake-xxpsk3.json", Pattern::XxPsk3),
];

fn public_of(private: &[u8; 32]) -> [u8; 32] {
    let mut public = [0; 32];
    libcrux_curve25519::secret_to_public(&mut public, private);
    public
}

/// Both peers of one fixture, with fixture randomness scripted in the order
/// Snow consumes it: X25519 ephemeral, then ML-KEM `d || z` (initiator) or
/// encapsulation `m` (responder).
struct FixturePeers {
    initiator: NoiseHandshake,
    responder: NoiseHandshake,
}

fn fixture_peers(
    vector: &Vector,
    pattern: Pattern,
    responder_psk: Option<[u8; 32]>,
    prologue_override: Option<&[u8]>,
) -> Result<FixturePeers, Box<dyn std::error::Error>> {
    let init_static = hex_array_at::<32>(vector, "/inputs/initiator_static_private_hex")?;
    let resp_static = hex_array_at::<32>(vector, "/inputs/responder_static_private_hex")?;
    let init_ephemeral = hex_at(vector, "/inputs/initiator_ephemeral_private_hex")?;
    let resp_ephemeral = hex_at(vector, "/inputs/responder_ephemeral_private_hex")?;
    let kem_seed = hex_at(vector, "/inputs/initiator_mlkem_keygen_d_then_z_hex")?;
    let encaps_seed = hex_at(vector, "/inputs/responder_mlkem_encapsulation_m_hex")?;
    let psk = hex_array_at::<32>(vector, "/inputs/psk_hex")?;
    let prologue = hex_at(vector, "/inputs/prelude/prologue_hex")?;
    let prologue = prologue_override.unwrap_or(&prologue);
    let init_public = public_of(&init_static);
    let resp_public = public_of(&resp_static);
    let responder_psk = responder_psk.unwrap_or(psk);
    let initiator = NoiseHandshake::new(&HandshakeInputs {
        pattern,
        initiator: true,
        prologue,
        psk: &psk,
        local_static: &init_static,
        remote_static: pattern.needs_remote_static(true).then_some(&resp_public),
        entropy: Entropy::scripted(vec![init_ephemeral, kem_seed]),
    })?;
    let responder = NoiseHandshake::new(&HandshakeInputs {
        pattern,
        initiator: false,
        prologue,
        psk: &responder_psk,
        local_static: &resp_static,
        remote_static: pattern.needs_remote_static(false).then_some(&init_public),
        entropy: Entropy::scripted(vec![resp_ephemeral, encaps_seed]),
    })?;
    Ok(FixturePeers {
        initiator,
        responder,
    })
}

/// The primary conformance test: the runtime engine (Snow 0.10.0 + libcrux
/// resolver) reproduces the committed reference transcripts (first generated
/// with Snow 0.9.6, regenerated unchanged with 0.10.0 through the generator's
/// separate adapter) byte for byte, including every intermediate hash, the
/// session ID, and the transport KATs that exercise both Split keys.
#[test]
fn reproduces_committed_handshake_transcripts() -> TestResult {
    for (file, pattern) in PROFILES {
        let vector = load(file)?;
        assert_eq!(
            json_at(&vector, "/protocol_name")?.as_str(),
            Some(pattern.protocol_name())
        );
        let FixturePeers {
            mut initiator,
            mut responder,
        } = fixture_peers(&vector, pattern, None, None)?;
        let messages = json_at(&vector, "/messages")?
            .as_array()
            .ok_or("messages")?;
        assert_eq!(messages.len(), pattern.message_lens().len());
        for (position, expected) in messages.iter().enumerate() {
            let (sender, receiver) = if position % 2 == 0 {
                (&mut initiator, &mut responder)
            } else {
                (&mut responder, &mut initiator)
            };
            assert!(sender.is_our_turn() && !receiver.is_our_turn());
            assert_eq!(sender.next_index(), position + 1);
            let message = sender.write_message()?;
            assert_eq!(
                message,
                hex_at(expected, "/noise_message_hex")?,
                "{file} {position}"
            );
            receiver.read_message(&message)?;
            let hash = hex_at(expected, "/handshake_hash_after_hex")?;
            assert_eq!(sender.handshake_hash().as_slice(), hash.as_slice());
            assert_eq!(receiver.handshake_hash().as_slice(), hash.as_slice());
        }
        assert!(initiator.is_finished() && responder.is_finished());
        let mut initiator = initiator.into_transport()?;
        let mut responder = responder.into_transport()?;
        let final_hash = hex_array_at::<32>(&vector, "/final_handshake_hash_hex")?;
        assert_eq!(initiator.handshake_hash(), &final_hash);
        assert_eq!(responder.handshake_hash(), &final_hash);
        assert_eq!(
            crate::session::session_id(&final_hash),
            hex_array_at::<32>(&vector, "/session_id_hex")?
        );
        let init_static = hex_array_at::<32>(&vector, "/inputs/initiator_static_private_hex")?;
        let resp_static = hex_array_at::<32>(&vector, "/inputs/responder_static_private_hex")?;
        assert_eq!(initiator.remote_static(), &public_of(&resp_static));
        assert_eq!(responder.remote_static(), &public_of(&init_static));
        for direction in ["initiator_to_responder", "responder_to_initiator"] {
            let (sender, receiver) = if direction == "initiator_to_responder" {
                (&mut initiator, &mut responder)
            } else {
                (&mut responder, &mut initiator)
            };
            let base = format!("/initial_transport/{direction}");
            let plaintext = hex_at(&vector, &format!("{base}/plaintext_hex"))?;
            let ciphertext = sender.encrypt(&plaintext)?;
            assert_eq!(
                ciphertext,
                hex_at(&vector, &format!("{base}/ciphertext_hex"))?
            );
            assert_eq!(
                receiver.decrypt(&ciphertext)?.as_slice(),
                plaintext.as_slice()
            );
        }
        assert_eq!(initiator.sending_nonce(), 1);
        assert_eq!(initiator.receiving_nonce(), 1);
    }
    Ok(())
}

#[test]
fn kem_adapter_matches_fixture_kem_outputs() -> TestResult {
    let vector = load("handshake-kkpsk2.json")?;
    let seed = hex_at(&vector, "/inputs/initiator_mlkem_keygen_d_then_z_hex")?;
    let encaps = hex_at(&vector, "/inputs/responder_mlkem_encapsulation_m_hex")?;
    let failed = Arc::new(AtomicBool::new(false));
    let mut kem = MlKem768 {
        entropy: Entropy::scripted(vec![encaps]),
        failed: Arc::clone(&failed),
        private: Zeroizing::new([0; KEM_PRIVATE_LEN]),
        public: Box::new([0; KEM_PUBLIC_LEN]),
    };
    kem.generate(&mut SnowRandom(Entropy::scripted(vec![seed])));
    assert!(!failed.load(Ordering::SeqCst));
    assert_eq!(
        kem.pubkey(),
        hex_at(&vector, "/kem/public_key_hex")?.as_slice()
    );
    let mut shared = [0; 32];
    let mut ciphertext = [0; KEM_CIPHERTEXT_LEN];
    let public = kem.public.to_vec();
    assert_eq!(
        kem.encapsulate(&public, &mut shared, &mut ciphertext)?,
        (32, 1088)
    );
    assert_eq!(
        ciphertext.as_slice(),
        hex_at(&vector, "/kem/ciphertext_hex")?.as_slice()
    );
    assert_eq!(
        shared.as_slice(),
        hex_at(&vector, "/kem/shared_secret_hex")?.as_slice()
    );
    let mut decapsulated = [0; 32];
    assert_eq!(kem.decapsulate(&ciphertext, &mut decapsulated)?, 32);
    assert_eq!(decapsulated, shared);
    // Implicit rejection: a modified ciphertext gives a different secret, not
    // an error (§4.2.6).
    ciphertext[0] ^= 1;
    assert_eq!(kem.decapsulate(&ciphertext, &mut decapsulated)?, 32);
    assert_ne!(decapsulated, shared);
    // An encapsulation key that fails the FIPS 203 input check is refused.
    let mut invalid = public;
    invalid[..2].fill(0xff);
    assert!(
        kem.encapsulate(&invalid, &mut shared, &mut ciphertext)
            .is_err()
    );
    assert!(
        kem.encapsulate(&invalid[1..], &mut shared, &mut ciphertext)
            .is_err()
    );
    Ok(())
}

#[test]
fn kem_keygen_without_randomness_poisons_the_handshake() -> TestResult {
    let vector = load("handshake-kkpsk2.json")?;
    let init_static = hex_array_at::<32>(&vector, "/inputs/initiator_static_private_hex")?;
    let resp_public = public_of(&hex_array_at::<32>(
        &vector,
        "/inputs/responder_static_private_hex",
    )?);
    let ephemeral = hex_at(&vector, "/inputs/initiator_ephemeral_private_hex")?;
    for script in [
        vec![ephemeral.clone()],
        vec![ephemeral, vec![0; 63]],
        vec![],
    ] {
        let mut initiator = NoiseHandshake::new(&HandshakeInputs {
            pattern: Pattern::KkPsk2,
            initiator: true,
            prologue: b"p",
            psk: &[0x55; 32],
            local_static: &init_static,
            remote_static: Some(&resp_public),
            entropy: Entropy::scripted(script),
        })?;
        assert_eq!(initiator.write_message(), Err(NoiseError::Random));
        assert_eq!(initiator.write_message(), Err(NoiseError::State));
        assert_eq!(initiator.next_index(), 1);
    }
    Ok(())
}

#[test]
fn wrong_psk_prologue_or_static_key_fails_without_detail() -> TestResult {
    for (file, pattern) in PROFILES {
        let vector = load(file)?;
        // Wrong PSK: IK and KK fail when the initiator reads message 2, XX
        // when the responder reads message 3.
        let mut peers = fixture_peers(&vector, pattern, Some([0x56; 32]), None)?;
        let mut failure = None;
        for position in 0..pattern.message_lens().len() {
            let (sender, receiver) = if position % 2 == 0 {
                (&mut peers.initiator, &mut peers.responder)
            } else {
                (&mut peers.responder, &mut peers.initiator)
            };
            let message = sender.write_message()?;
            if let Err(error) = receiver.read_message(&message) {
                failure = Some((position, error));
                break;
            }
        }
        let last = pattern.message_lens().len() - 1;
        assert_eq!(failure, Some((last, NoiseError::Authentication)), "{file}");
        // Changed prologue: the first message no longer authenticates.
        let mut peers = fixture_peers(&vector, pattern, None, Some(b"other prologue"))?;
        let message = peers.initiator.write_message()?;
        let mut honest = fixture_peers(&vector, pattern, None, None)?;
        assert_eq!(
            honest.responder.read_message(&message),
            Err(NoiseError::Authentication),
            "{file}"
        );
    }
    // A wrong pinned static key fails at the first message for IK and KK.
    let vector = load("handshake-kkpsk2.json")?;
    let wrong = public_of(&[0x78; 32]);
    let init_static = hex_array_at::<32>(&vector, "/inputs/initiator_static_private_hex")?;
    let resp_static = hex_array_at::<32>(&vector, "/inputs/responder_static_private_hex")?;
    let mut initiator = NoiseHandshake::new(&HandshakeInputs {
        pattern: Pattern::KkPsk2,
        initiator: true,
        prologue: b"p",
        psk: &[0x55; 32],
        local_static: &init_static,
        remote_static: Some(&wrong),
        entropy: Entropy::Os,
    })?;
    let mut responder = NoiseHandshake::new(&HandshakeInputs {
        pattern: Pattern::KkPsk2,
        initiator: false,
        prologue: b"p",
        psk: &[0x55; 32],
        local_static: &resp_static,
        remote_static: Some(&public_of(&init_static)),
        entropy: Entropy::Os,
    })?;
    let message = initiator.write_message()?;
    assert_eq!(
        responder.read_message(&message),
        Err(NoiseError::Authentication)
    );
    Ok(())
}

/// Every single-bit change of every handshake message, at a spread of byte
/// positions covering each field, is rejected by the receiver.
#[test]
fn modified_messages_never_authenticate() -> TestResult {
    for (file, pattern) in PROFILES {
        let vector = load(file)?;
        let messages = json_at(&vector, "/messages")?
            .as_array()
            .ok_or("messages")?;
        for (position, expected) in messages.iter().enumerate() {
            let honest = hex_at(expected, "/noise_message_hex")?;
            let positions = [0, 1, 31, 32, 33, 600, 1231, 1232, 1247, honest.len() - 1];
            for byte in positions.into_iter().filter(|&byte| byte < honest.len()) {
                let mut peers = fixture_peers(&vector, pattern, None, None)?;
                for previous in 0..position {
                    let (sender, receiver) = if previous % 2 == 0 {
                        (&mut peers.initiator, &mut peers.responder)
                    } else {
                        (&mut peers.responder, &mut peers.initiator)
                    };
                    receiver.read_message(&sender.write_message()?)?;
                }
                let receiver = if position % 2 == 0 {
                    &mut peers.responder
                } else {
                    &mut peers.initiator
                };
                let mut changed = honest.clone();
                changed[byte] ^= 0x80;
                assert_eq!(
                    receiver.read_message(&changed),
                    Err(NoiseError::Authentication),
                    "{file} message {position} byte {byte}"
                );
                // Poisoned: even the honest bytes are refused afterwards.
                assert!(receiver.read_message(&honest).is_err());
            }
        }
    }
    Ok(())
}

#[test]
fn truncated_extended_and_out_of_turn_messages_are_rejected() -> TestResult {
    let vector = load("handshake-ikpsk2.json")?;
    let honest = hex_at(&vector, "/messages/0/noise_message_hex")?;
    for changed in [
        honest[..honest.len() - 1].to_vec(),
        [honest.as_slice(), &[0]].concat(),
        Vec::new(),
    ] {
        let mut peers = fixture_peers(&vector, Pattern::IkPsk2, None, None)?;
        assert_eq!(
            peers.responder.read_message(&changed),
            Err(NoiseError::Authentication)
        );
    }
    let mut peers = fixture_peers(&vector, Pattern::IkPsk2, None, None)?;
    assert_eq!(peers.responder.write_message(), Err(NoiseError::State));
    assert_eq!(
        peers.initiator.read_message(&honest),
        Err(NoiseError::State)
    );
    let first = peers.initiator.write_message()?;
    assert_eq!(peers.initiator.write_message(), Err(NoiseError::State));
    // Replay of message 1 to a responder that already read it.
    peers.responder.read_message(&first)?;
    assert_eq!(peers.responder.read_message(&first), Err(NoiseError::State));
    assert!(peers.responder.into_transport().is_err());
    // A poisoned attempt never yields a transport.
    let mut peers = fixture_peers(&vector, Pattern::IkPsk2, None, None)?;
    assert_eq!(
        peers.responder.read_message(&honest[1..]),
        Err(NoiseError::Authentication)
    );
    assert_eq!(
        peers.responder.into_transport().map(|_| ()),
        Err(NoiseError::State)
    );
    Ok(())
}

/// §5: a transport ciphertext is at most 65535 bytes; a larger plaintext is
/// refused before encryption and uses no nonce. A ciphertext shorter than
/// its tag never authenticates.
#[test]
fn transport_messages_respect_the_ciphertext_bounds() -> TestResult {
    let vector = load("handshake-kkpsk2.json")?;
    let mut peers = fixture_peers(&vector, Pattern::KkPsk2, None, None)?;
    let first = peers.initiator.write_message()?;
    peers.responder.read_message(&first)?;
    let second = peers.responder.write_message()?;
    peers.initiator.read_message(&second)?;
    let mut initiator = peers.initiator.into_transport()?;
    let mut responder = peers.responder.into_transport()?;
    let largest = vec![0; MAX_CIPHERTEXT_LEN - TAG_LEN];
    assert_eq!(
        initiator.encrypt(&[largest.as_slice(), &[0]].concat()),
        Err(NoiseError::State)
    );
    assert_eq!(initiator.sending_nonce(), 0);
    let ciphertext = initiator.encrypt(&largest)?;
    assert_eq!(ciphertext.len(), MAX_CIPHERTEXT_LEN);
    assert_eq!(
        responder.decrypt(&ciphertext)?.as_slice(),
        largest.as_slice()
    );
    assert_eq!(
        responder.decrypt(&[0; TAG_LEN - 1]).map(|_| ()),
        Err(NoiseError::Authentication)
    );
    Ok(())
}

/// An all-zero (or other small-order) ephemeral makes the X25519 output zero,
/// which libcrux rejects; the receiver reports a generic failure (§4.2.6).
#[test]
fn small_order_ephemeral_is_rejected() -> TestResult {
    let vector = load("handshake-kkpsk2.json")?;
    let honest = hex_at(&vector, "/messages/0/noise_message_hex")?;
    for point in [[0_u8; 32], {
        let mut one = [0; 32];
        one[0] = 1;
        one
    }] {
        let mut changed = honest.clone();
        changed[..32].copy_from_slice(&point);
        let mut peers = fixture_peers(&vector, Pattern::KkPsk2, None, None)?;
        assert_eq!(
            peers.responder.read_message(&changed),
            Err(NoiseError::Authentication)
        );
    }
    let dh = {
        let mut dh = X25519::new();
        dh.set(&[0x11; 32]);
        dh
    };
    let mut out = [0xaa; 32];
    assert!(dh.dh(&[0; 32], &mut out).is_err());
    assert_eq!(out, [0; 32]);
    assert!(dh.dh(&[9; 31], &mut out).is_err());
    Ok(())
}

#[test]
fn missing_or_unexpected_remote_static_is_a_local_error() {
    static REMOTE: [u8; 32] = [9; 32];
    let inputs = |pattern, initiator, remote: Option<&'static [u8; 32]>| HandshakeInputs {
        pattern,
        initiator,
        prologue: b"",
        psk: &[1; 32],
        local_static: &[2; 32],
        remote_static: remote,
        entropy: Entropy::Os,
    };
    for (pattern, initiator, remote) in [
        (Pattern::IkPsk2, true, None),
        (Pattern::IkPsk2, false, Some(&REMOTE)),
        (Pattern::KkPsk2, true, None),
        (Pattern::KkPsk2, false, None),
        (Pattern::XxPsk3, true, Some(&REMOTE)),
        (Pattern::XxPsk3, false, Some(&REMOTE)),
    ] {
        assert_eq!(
            NoiseHandshake::new(&inputs(pattern, initiator, remote)).map(|_| ()),
            Err(NoiseError::State)
        );
    }
}

/// Noise `REKEY` is `ENCRYPT(k, 2^64-1, empty, zeros)[..32]`; the override
/// computes exactly that.
#[test]
fn rekey_matches_the_noise_definition() {
    let key = [0x42; 32];
    let mut cipher = ChaChaPoly(Zeroizing::new(key));
    let mut expected = [0; 48];
    let written = cipher.encrypt(u64::MAX, &[], &[0; 32], &mut expected);
    assert_eq!(written, 48);
    cipher.rekey();
    assert_eq!(cipher.0.as_slice(), &expected[..32]);
    let mut short = [0; 47];
    assert_eq!(cipher.encrypt(0, &[], &[0; 32], &mut short), 0);
}

/// Independent classical vectors (Cacophony via Snow's test suite) for the
/// same three base patterns. They check the libcrux adapters and Snow's PSK
/// handling; classical Noise is test-only (see the engine docs).
#[test]
fn libcrux_adapters_match_cacophony_classical_vectors() -> TestResult {
    let document = load_testdata("noise-classical-cacophony.json")?;
    let vectors = json_at(&document, "/vectors")?
        .as_array()
        .ok_or("vectors")?;
    assert_eq!(vectors.len(), 3);
    for (vector, pattern) in vectors
        .iter()
        .zip([Pattern::IkPsk2, Pattern::KkPsk2, Pattern::XxPsk3])
    {
        let name = json_at(vector, "/protocol_name")?.as_str().ok_or("name")?;
        let prologue = hex_at(vector, "/init_prologue")?;
        let psk = hex_array_at::<32>(vector, "/init_psks/0")?;
        let init_static = hex_array_at::<32>(vector, "/init_static")?;
        let resp_static = hex_array_at::<32>(vector, "/resp_static")?;
        let init_public = public_of(&init_static);
        let resp_public = public_of(&resp_static);
        let mut initiator = NoiseHandshake::classical_for_tests(
            name,
            &HandshakeInputs {
                pattern,
                initiator: true,
                prologue: &prologue,
                psk: &psk,
                local_static: &init_static,
                remote_static: pattern.needs_remote_static(true).then_some(&resp_public),
                entropy: Entropy::scripted(vec![hex_at(vector, "/init_ephemeral")?]),
            },
        )?;
        let mut responder = NoiseHandshake::classical_for_tests(
            name,
            &HandshakeInputs {
                pattern,
                initiator: false,
                prologue: &prologue,
                psk: &hex_array_at::<32>(vector, "/resp_psks/0")?,
                local_static: &resp_static,
                remote_static: pattern.needs_remote_static(false).then_some(&init_public),
                entropy: Entropy::scripted(vec![hex_at(vector, "/resp_ephemeral")?]),
            },
        )?;
        if let Some(remote) = vector.pointer("/init_remote_static") {
            assert_eq!(
                hex::decode(remote.as_str().ok_or("remote")?)?,
                resp_public.to_vec()
            );
        }
        let messages = json_at(vector, "/messages")?.as_array().ok_or("messages")?;
        let handshake_len = pattern.message_lens().len();
        let mut buffer = vec![0; 65_535];
        let mut payload = vec![0; 65_535];
        for (position, message) in messages.iter().take(handshake_len).enumerate() {
            let expected_payload = hex_at(message, "/payload")?;
            let expected = hex_at(message, "/ciphertext")?;
            let (sender, receiver) = if position % 2 == 0 {
                (&mut initiator, &mut responder)
            } else {
                (&mut responder, &mut initiator)
            };
            let written = sender
                .write_message(&expected_payload, &mut buffer)
                .map_err(|error| format!("{error:?}"))?;
            assert_eq!(&buffer[..written], expected.as_slice(), "{name} {position}");
            let read = receiver
                .read_message(&expected, &mut payload)
                .map_err(|error| format!("{error:?}"))?;
            assert_eq!(&payload[..read], expected_payload.as_slice());
        }
        let expected_hash = hex_at(vector, "/handshake_hash")?;
        assert_eq!(initiator.get_handshake_hash(), expected_hash.as_slice());
        assert_eq!(responder.get_handshake_hash(), expected_hash.as_slice());
        let mut initiator = initiator
            .into_transport_mode()
            .map_err(|error| format!("{error:?}"))?;
        let mut responder = responder
            .into_transport_mode()
            .map_err(|error| format!("{error:?}"))?;
        for (offset, message) in messages.iter().enumerate().skip(handshake_len) {
            let expected_payload = hex_at(message, "/payload")?;
            let expected = hex_at(message, "/ciphertext")?;
            let (sender, receiver) = if offset % 2 == 0 {
                (&mut initiator, &mut responder)
            } else {
                (&mut responder, &mut initiator)
            };
            let written = sender
                .write_message(&expected_payload, &mut buffer)
                .map_err(|error| format!("{error:?}"))?;
            assert_eq!(
                &buffer[..written],
                expected.as_slice(),
                "{name} transport {offset}"
            );
            let read = receiver
                .read_message(&expected, &mut payload)
                .map_err(|error| format!("{error:?}"))?;
            assert_eq!(&payload[..read], expected_payload.as_slice());
        }
    }
    Ok(())
}

fn load_testdata(name: &str) -> Result<Vector, Box<dyn std::error::Error>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(name);
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

fn acvp_groups<'a>(
    document: &'a Vector,
    section: &str,
    function: Option<&str>,
) -> Result<Vec<&'a Vector>, Box<dyn std::error::Error>> {
    let groups = json_at(document, &format!("/{section}"))?
        .as_array()
        .ok_or("groups")?;
    let mut tests = Vec::new();
    for group in groups {
        assert_eq!(
            group.pointer("/parameterSet").and_then(Vector::as_str),
            Some("ML-KEM-768")
        );
        if function.is_none_or(|function| {
            group.pointer("/function").and_then(Vector::as_str) == Some(function)
        }) {
            tests.extend(
                group
                    .pointer("/tests")
                    .and_then(Vector::as_array)
                    .ok_or("tests")?,
            );
        }
    }
    Ok(tests)
}

/// NIST ACVP ML-KEM-768 vectors (FIPS 203), run through the exact libcrux
/// entry points the engine uses. Provenance is recorded in the data file.
#[test]
fn libcrux_ml_kem_768_passes_nist_acvp_vectors() -> TestResult {
    let document = load_testdata("acvp-mlkem768.json")?;
    let key_gen = acvp_groups(&document, "keyGen", None)?;
    assert_eq!(key_gen.len(), 25);
    for test in key_gen {
        let mut seed = [0; 64];
        seed[..32].copy_from_slice(&hex_at(test, "/d")?);
        seed[32..].copy_from_slice(&hex_at(test, "/z")?);
        let pair = mlkem768::generate_key_pair(seed);
        assert_eq!(
            pair.public_key().as_slice(),
            hex_at(test, "/ek")?.as_slice()
        );
        assert_eq!(
            pair.private_key().as_slice(),
            hex_at(test, "/dk")?.as_slice()
        );
    }
    let encapsulation = acvp_groups(&document, "encapDecap", Some("encapsulation"))?;
    assert_eq!(encapsulation.len(), 25);
    for test in encapsulation {
        let public = MlKem768PublicKey::try_from(hex_at(test, "/ek")?.as_slice())?;
        assert!(mlkem768::validate_public_key(&public));
        let (ciphertext, shared) = mlkem768::encapsulate(&public, hex_array_at::<32>(test, "/m")?);
        assert_eq!(ciphertext.as_slice(), hex_at(test, "/c")?.as_slice());
        assert_eq!(shared.as_slice(), hex_at(test, "/k")?.as_slice());
    }
    let decapsulation = acvp_groups(&document, "encapDecap", Some("decapsulation"))?;
    assert_eq!(decapsulation.len(), 10);
    let mut rejected = 0;
    for test in decapsulation {
        let private = MlKem768PrivateKey::try_from(hex_at(test, "/dk")?.as_slice())?;
        let ciphertext = MlKem768Ciphertext::try_from(hex_at(test, "/c")?.as_slice())?;
        let shared = mlkem768::decapsulate(&private, &ciphertext);
        assert_eq!(shared.as_slice(), hex_at(test, "/k")?.as_slice());
        if test.pointer("/reason").and_then(Vector::as_str) == Some("modified ciphertext") {
            rejected += 1;
        }
    }
    assert!(rejected > 0, "implicit-rejection cases present");
    for (function, check) in [("encapsulationKeyCheck", 0), ("decapsulationKeyCheck", 1)] {
        let tests = acvp_groups(&document, "encapDecap", Some(function))?;
        assert_eq!(tests.len(), 10);
        let mut outcomes = [0; 2];
        for test in tests {
            let expected = test
                .pointer("/testPassed")
                .and_then(Vector::as_bool)
                .ok_or("testPassed")?;
            let valid = if check == 0 {
                MlKem768PublicKey::try_from(hex_at(test, "/ek")?.as_slice())
                    .is_ok_and(|key| mlkem768::validate_public_key(&key))
            } else {
                MlKem768PrivateKey::try_from(hex_at(test, "/dk")?.as_slice())
                    .is_ok_and(|key| mlkem768::portable::validate_private_key_only(&key))
            };
            assert_eq!(valid, expected, "{function}");
            outcomes[usize::from(valid)] += 1;
        }
        assert!(
            outcomes[0] > 0 && outcomes[1] > 0,
            "{function} covers both outcomes"
        );
    }
    Ok(())
}

#[test]
fn debug_output_names_no_secret() -> TestResult {
    let vector = load("handshake-kkpsk2.json")?;
    let peers = fixture_peers(&vector, Pattern::KkPsk2, None, None)?;
    let debug = format!("{:?}", peers.initiator);
    assert!(debug.contains("KkPsk2") && debug.contains("position: 0"));
    assert!(!debug.contains("55"));
    assert_eq!(format!("{:?}", Entropy::Os), "Entropy::Os");
    assert_eq!(
        format!("{:?}", Entropy::scripted(vec![vec![0x55; 32]])),
        "Entropy::Scripted"
    );
    // The completed transport prints only its role, never a key.
    let mut peers = fixture_peers(&vector, Pattern::KkPsk2, None, None)?;
    let first = peers.initiator.write_message()?;
    peers.responder.read_message(&first)?;
    let second = peers.responder.write_message()?;
    peers.initiator.read_message(&second)?;
    let initiator = peers.initiator.into_transport()?;
    let responder = peers.responder.into_transport()?;
    assert_eq!(
        format!("{initiator:?}"),
        "NoiseTransport { initiator: true, .. }"
    );
    assert_eq!(
        format!("{responder:?}"),
        "NoiseTransport { initiator: false, .. }"
    );
    Ok(())
}

/// §4.2.2: every attempt draws fresh X25519 ephemerals, a fresh ML-KEM key
/// pair, and fresh encapsulation randomness from the OS CSPRNG. Two attempts
/// with identical static inputs send different `e_i` and `e_r`, and the
/// ML-KEM adapter on the OS source never repeats a key pair or ciphertext.
#[test]
fn every_attempt_uses_fresh_ephemeral_material() -> TestResult {
    let initiator_static = [0x11; 32];
    let responder_static = [0x33; 32];
    let responder_public = public_of(&responder_static);
    let initiator_public = public_of(&initiator_static);
    let attempt = || -> Result<(Vec<u8>, Vec<u8>), NoiseError> {
        let mut initiator = NoiseHandshake::new(&HandshakeInputs {
            pattern: Pattern::KkPsk2,
            initiator: true,
            prologue: b"fresh",
            psk: &[0x55; 32],
            local_static: &initiator_static,
            remote_static: Some(&responder_public),
            entropy: Entropy::Os,
        })?;
        let mut responder = NoiseHandshake::new(&HandshakeInputs {
            pattern: Pattern::KkPsk2,
            initiator: false,
            prologue: b"fresh",
            psk: &[0x55; 32],
            local_static: &responder_static,
            remote_static: Some(&initiator_public),
            entropy: Entropy::Os,
        })?;
        let first = initiator.write_message()?;
        responder.read_message(&first)?;
        let second = responder.write_message()?;
        initiator.read_message(&second)?;
        Ok((first, second))
    };
    let (first_a, second_a) = attempt()?;
    let (first_b, second_b) = attempt()?;
    // e_i and e_r are the first 32 bytes of KK messages 1 and 2 (§4.2.5).
    assert_ne!(first_a.get(..32), first_b.get(..32));
    assert_ne!(second_a.get(..32), second_b.get(..32));
    // The KEM adapter alone, so X25519 freshness cannot mask a repeat.
    let kem = || MlKem768 {
        entropy: Entropy::Os,
        failed: Arc::new(AtomicBool::new(false)),
        private: Zeroizing::new([0; KEM_PRIVATE_LEN]),
        public: Box::new([0; KEM_PUBLIC_LEN]),
    };
    let (mut one, mut two) = (kem(), kem());
    one.generate(&mut SnowRandom(Entropy::Os));
    two.generate(&mut SnowRandom(Entropy::Os));
    assert!(!one.failed.load(Ordering::SeqCst) && !two.failed.load(Ordering::SeqCst));
    assert_ne!(one.pubkey(), two.pubkey());
    assert_ne!(one.private.as_slice(), two.private.as_slice());
    let public = one.pubkey().to_vec();
    let mut shared = [[0; 32]; 2];
    let mut ciphertext = [[0; KEM_CIPHERTEXT_LEN]; 2];
    for (shared, ciphertext) in shared.iter_mut().zip(ciphertext.iter_mut()) {
        two.encapsulate(&public, shared, ciphertext)?;
    }
    assert_ne!(ciphertext[0], ciphertext[1]);
    assert_ne!(shared[0], shared[1]);
    Ok(())
}

/// Engine errors render as fixed, distinct messages with no peer detail.
#[test]
fn noise_errors_render_fixed_messages() {
    assert_eq!(
        [
            NoiseError::Authentication,
            NoiseError::Random,
            NoiseError::State
        ]
        .map(|error| error.to_string()),
        [
            "handshake authentication failed",
            "randomness unavailable",
            "handshake state error"
        ]
    );
}

/// The engine wipes libcrux's ML-KEM key objects in place through
/// `IndexMut<RangeFrom<usize>>` instead of copying them out by value; check
/// that this reaches every byte of the 2400-byte key.
#[test]
fn mlkem_private_key_wipe_covers_the_whole_key() {
    let mut private = MlKem768PrivateKey::from(&[0x5a; KEM_PRIVATE_LEN]);
    assert_eq!(private.as_slice(), &[0x5a; KEM_PRIVATE_LEN]);
    private[0..].zeroize();
    assert_eq!(private.as_slice(), &[0; KEM_PRIVATE_LEN]);
}
