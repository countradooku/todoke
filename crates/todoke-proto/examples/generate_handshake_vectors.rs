//! Deterministic, public Noise-HFS handshake fixtures. Never use live credentials.
//!
//! Snow owns every handshake/token/KDF operation; libcrux owns the primitives.
//! This offline adapter is not a production protocol or a reviewed integration.

#![forbid(unsafe_code)]

use std::{
    error::Error,
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768PrivateKey, MlKem768PublicKey};
use libcrux_sha2::Digest;
use rand_core::RngCore;
use serde_json::{Value, json};
use snow::{
    Builder, HandshakeState,
    params::{BaseChoice, CipherChoice, DHChoice, HashChoice, KemChoice, NoiseParams},
    resolvers::CryptoResolver,
    types::{Cipher, Dh, Hash, Kem, Random},
};
use zeroize::{Zeroize, Zeroizing};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const NOTICE: &str =
    "PUBLIC TEST FIXTURE: fixed seeds, PSKs and derived keys; never use in production";
const AUDIT_COMMIT: &str = "009411d2035a77ece57b0a6873169de7693a0aa0";
const ENGINE_COMMIT: &str = "a4be73faa042c5967f39662aa66919f774831a9a";
const PSK: [u8; 32] = [0x55; 32];
const INIT_STATIC: [u8; 32] = [0x11; 32];
const RESP_STATIC: [u8; 32] = [0x33; 32];
const INIT_EPHEMERAL: [u8; 32] = [0x61; 32];
const RESP_EPHEMERAL: [u8; 32] = [0x62; 32];
const KEM_KEY_SEED: [u8; 64] = [0x63; 64];
const KEM_ENCAP_SEED: [u8; 32] = [0x64; 32];

#[derive(Clone, Copy)]
struct Profile {
    file: &'static str,
    pattern: &'static str,
    mode: u8,
    psk_position: u8,
    sizes: &'static [usize],
    tokens: &'static [&'static str],
}

const PROFILES: [Profile; 3] = [
    Profile {
        file: "handshake-ikpsk2.json",
        pattern: "IKpsk2+hfs",
        mode: 1,
        psk_position: 2,
        sizes: &[1296, 1152],
        tokens: &["e, es, e1, s, ss", "e, ee, ekem1, se, psk"],
    },
    Profile {
        file: "handshake-xxpsk3.json",
        pattern: "XXpsk3+hfs",
        mode: 2,
        psk_position: 3,
        sizes: &[1248, 1200, 64],
        tokens: &["e, e1", "e, ee, ekem1, s, es", "s, se, psk"],
    },
    Profile {
        file: "handshake-kkpsk2.json",
        pattern: "KKpsk2+hfs",
        mode: 3,
        psk_position: 2,
        sizes: &[1248, 1152],
        tokens: &["e, es, e1, ss", "e, ee, ekem1, se, psk"],
    },
];

// Snow requires an RNG object even when all fixture randomness is supplied.
// This delegates to a reference OS RNG and records any accidental use; generation
// fails if the counter is nonzero, so output never depends on OS randomness.
struct ObservedRandom(Arc<AtomicUsize>);

impl rand_core::CryptoRng for ObservedRandom {}
impl Random for ObservedRandom {}

impl RngCore for ObservedRandom {
    fn next_u32(&mut self) -> u32 {
        self.0.fetch_add(1, Ordering::Relaxed);
        rand_core::OsRng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed);
        rand_core::OsRng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fetch_add(1, Ordering::Relaxed);
        rand_core::OsRng.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
        self.0.fetch_add(1, Ordering::Relaxed);
        rand_core::OsRng.try_fill_bytes(dest)
    }
}

struct FixtureDh {
    private: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl Default for FixtureDh {
    fn default() -> Self {
        Self {
            private: Zeroizing::new([0; 32]),
            public: [0; 32],
        }
    }
}

impl Dh for FixtureDh {
    fn name(&self) -> &'static str {
        "25519"
    }
    fn pub_len(&self) -> usize {
        32
    }
    fn priv_len(&self) -> usize {
        32
    }
    fn set(&mut self, private: &[u8]) {
        if let Ok(private) = <&[u8; 32]>::try_from(private) {
            self.private.copy_from_slice(private);
            libcrux_curve25519::secret_to_public(&mut self.public, &self.private);
        }
    }
    fn generate(&mut self, rng: &mut dyn Random) {
        rng.fill_bytes(self.private.as_mut_slice());
        libcrux_curve25519::secret_to_public(&mut self.public, &self.private);
    }
    fn pubkey(&self) -> &[u8] {
        &self.public
    }
    fn privkey(&self) -> &[u8] {
        self.private.as_slice()
    }
    fn dh(&self, public: &[u8], out: &mut [u8]) -> std::result::Result<(), snow::Error> {
        // Snow passes its fixed-size MAXDHLEN storage, not a DHLEN slice.
        let public = public
            .get(..32)
            .ok_or(snow::Error::Input)?
            .try_into()
            .map_err(|_| snow::Error::Input)?;
        let mut shared = Zeroizing::new([0; 32]);
        libcrux_curve25519::ecdh(&mut shared, public, &self.private)
            .map_err(|_| snow::Error::Dh)?;
        out.get_mut(..32)
            .ok_or(snow::Error::Input)?
            .copy_from_slice(shared.as_slice());
        Ok(())
    }
}

struct FixtureKem {
    private: Zeroizing<[u8; 2400]>,
    public: [u8; 1184],
}

impl Default for FixtureKem {
    fn default() -> Self {
        Self {
            private: Zeroizing::new([0; 2400]),
            public: [0; 1184],
        }
    }
}

impl Kem for FixtureKem {
    fn name(&self) -> &'static str {
        "MLKEM768"
    }
    fn pub_len(&self) -> usize {
        1184
    }
    fn ciphertext_len(&self) -> usize {
        1088
    }
    fn shared_secret_len(&self) -> usize {
        32
    }
    fn generate(&mut self, _rng: &mut dyn Random) {
        let seed = Zeroizing::new(KEM_KEY_SEED);
        let (private, public) = mlkem768::generate_key_pair(*seed).into_parts();
        *self.private = private.into();
        self.public = public.into();
    }
    fn pubkey(&self) -> &[u8] {
        &self.public
    }
    fn encapsulate(
        &self,
        public: &[u8],
        shared_out: &mut [u8],
        ciphertext_out: &mut [u8],
    ) -> std::result::Result<(usize, usize), ()> {
        let public = MlKem768PublicKey::try_from(public).map_err(|_| ())?;
        if !mlkem768::validate_public_key(&public) {
            return Err(());
        }
        // Snow 0.9.6 has no RNG argument for encapsulation. This is an explicit
        // FIPS 203 public fixture input, never a live encapsulation adapter.
        let seed = Zeroizing::new(KEM_ENCAP_SEED);
        let (ciphertext, shared) = mlkem768::encapsulate(&public, *seed);
        let shared = Zeroizing::new(shared);
        shared_out
            .get_mut(..32)
            .ok_or(())?
            .copy_from_slice(shared.as_slice());
        ciphertext_out
            .get_mut(..1088)
            .ok_or(())?
            .copy_from_slice(ciphertext.as_slice());
        Ok((32, 1088))
    }
    fn decapsulate(&self, ciphertext: &[u8], out: &mut [u8]) -> std::result::Result<usize, ()> {
        let ciphertext = MlKem768Ciphertext::try_from(ciphertext).map_err(|_| ())?;
        let private = MlKem768PrivateKey::from(*self.private);
        let shared = Zeroizing::new(mlkem768::decapsulate(&private, &ciphertext));
        let _private = Zeroizing::new(<[u8; 2400]>::from(private));
        out.get_mut(..32)
            .ok_or(())?
            .copy_from_slice(shared.as_slice());
        Ok(32)
    }
}

struct FixtureCipher(Zeroizing<[u8; 32]>);

fn noise_nonce(nonce: u64) -> [u8; 12] {
    let mut bytes = [0; 12];
    bytes[4..].copy_from_slice(&nonce.to_le_bytes());
    bytes
}

impl Cipher for FixtureCipher {
    fn name(&self) -> &'static str {
        "ChaChaPoly"
    }
    fn set(&mut self, key: &[u8]) {
        if let Ok(key) = <&[u8; 32]>::try_from(key) {
            self.0.copy_from_slice(key);
        }
    }
    fn encrypt(&self, nonce: u64, aad: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize {
        libcrux_chacha20poly1305::encrypt(&self.0, plaintext, out, aad, &noise_nonce(nonce))
            .map_or(0, |(ciphertext, tag)| ciphertext.len() + tag.len())
    }
    fn decrypt(
        &self,
        nonce: u64,
        aad: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> std::result::Result<usize, snow::Error> {
        libcrux_chacha20poly1305::decrypt(&self.0, out, ciphertext, aad, &noise_nonce(nonce))
            .map(<[u8]>::len)
            .map_err(|_| snow::Error::Decrypt)
    }
}

#[derive(Default)]
struct FixtureHash(libcrux_sha2::Sha256);

impl Hash for FixtureHash {
    fn name(&self) -> &'static str {
        "SHA256"
    }
    fn block_len(&self) -> usize {
        64
    }
    fn hash_len(&self) -> usize {
        32
    }
    fn reset(&mut self) {
        self.0.reset();
    }
    fn input(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn result(&mut self, out: &mut [u8]) {
        let mut digest = Zeroizing::new([0; 32]);
        self.0.finish(&mut digest);
        if let Some(out) = out.get_mut(..32) {
            out.copy_from_slice(digest.as_slice());
        }
    }
}

struct FixtureResolver(Arc<AtomicUsize>);

impl CryptoResolver for FixtureResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(ObservedRandom(Arc::clone(&self.0))))
    }
    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        (*choice == DHChoice::Curve25519).then(|| Box::new(FixtureDh::default()) as Box<dyn Dh>)
    }
    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        (*choice == HashChoice::SHA256).then(|| Box::new(FixtureHash::default()) as Box<dyn Hash>)
    }
    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        (*choice == CipherChoice::ChaChaPoly)
            .then(|| Box::new(FixtureCipher(Zeroizing::new([0; 32]))) as Box<dyn Cipher>)
    }
    fn resolve_kem(&self, _choice: &KemChoice) -> Option<Box<dyn Kem>> {
        Some(Box::new(FixtureKem::default()))
    }
}

fn protocol_name(profile: Profile) -> String {
    format!("Noise_{}_25519+MLKEM768_ChaChaPoly_SHA256", profile.pattern)
}

fn build_peer(
    profile: Profile,
    initiator: bool,
    prologue: &[u8],
    psk: &[u8; 32],
    calls: &Arc<AtomicUsize>,
    remote_public_override: Option<&[u8; 32]>,
) -> Result<HandshakeState> {
    // Kyber1024 is ONLY an internal resolver slot: no Kyber operation runs.
    // Snow initializes h/ck from `name` verbatim, which must say MLKEM768.
    let parameters = NoiseParams::new(
        protocol_name(profile),
        BaseChoice::Noise,
        profile.pattern.parse()?,
        DHChoice::Curve25519,
        Some(KemChoice::Kyber1024),
        CipherChoice::ChaChaPoly,
        HashChoice::SHA256,
    );
    let private = Zeroizing::new(if initiator { INIT_STATIC } else { RESP_STATIC });
    let ephemeral = Zeroizing::new(if initiator {
        INIT_EPHEMERAL
    } else {
        RESP_EPHEMERAL
    });
    let remote_private = Zeroizing::new(if initiator { RESP_STATIC } else { INIT_STATIC });
    let mut remote_public = [0; 32];
    libcrux_curve25519::secret_to_public(&mut remote_public, &remote_private);
    let mut builder =
        Builder::with_resolver(parameters, Box::new(FixtureResolver(Arc::clone(calls))))
            .local_private_key(private.as_slice())
            .fixed_ephemeral_key_for_testing_only(ephemeral.as_slice())
            .psk(profile.psk_position, psk)
            .prologue(prologue);
    if profile.mode == 3 || (profile.mode == 1 && initiator) {
        builder = builder.remote_public_key(remote_public_override.unwrap_or(&remote_public));
    }
    Ok(if initiator {
        builder.build_initiator()?
    } else {
        builder.build_responder()?
    })
}

fn hello(profile: Profile, responder: bool) -> Vec<u8> {
    let mut body = b"TDKE\0\x01\0\x01".to_vec();
    body.extend_from_slice(&[profile.mode, 0]);
    body.extend_from_slice(&(if profile.mode == 3 { 7_u64 } else { 0 }).to_be_bytes());
    body.extend_from_slice(&[0xa1; 16]);
    body.extend_from_slice(&[0xa5; 16]);
    body.extend_from_slice(&[if responder { 0xa6 } else { 0 }; 16]);
    body
}

fn fixture_prologue(profile: Profile) -> (Vec<u8>, Value) {
    let client = hello(profile, false);
    let server = hello(profile, true);
    let mut prologue = b"todoke/v1/noise-prologue\0".to_vec();
    // O2 remains open: this input intentionally does not invent CPace shares or
    // claim that the synthetic PSK was derived by the pending CPace profile.
    if profile.mode == 2 {
        prologue.extend_from_slice(b"PUBLIC SYNTHETIC CODE PRELUDE\0");
    }
    prologue.extend_from_slice(&client);
    prologue.extend_from_slice(&server);
    let metadata = json!({
        "client_hello_body_hex": hex::encode(client),
        "server_hello_body_hex": hex::encode(server),
        "scope": if profile.mode == 2 {
            "Noise-only synthetic prologue and PSK; NOT a valid code prelude or CPace conformance vector"
        } else {
            "Exact todoke Hello body encodings; locator and generation are public fixture state"
        },
        "prologue_hex": hex::encode(&prologue)
    });
    (prologue, metadata)
}

fn prelude_message(index: u8, message: &[u8]) -> Result<Vec<u8>> {
    let mut framed = u16::try_from(message.len() + 2)?.to_be_bytes().to_vec();
    framed.extend_from_slice(&[0x05, index]);
    framed.extend_from_slice(message);
    Ok(framed)
}

struct Exchange {
    initiator: HandshakeState,
    responder: HandshakeState,
    messages: Vec<Vec<u8>>,
    hashes: Vec<String>,
}

fn exchange(profile: Profile, prologue: &[u8], responder_psk: &[u8; 32]) -> Result<Exchange> {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut initiator = build_peer(profile, true, prologue, &PSK, &calls, None)?;
    let mut responder = build_peer(profile, false, prologue, responder_psk, &calls, None)?;
    let mut messages = Vec::new();
    let mut hashes = Vec::new();
    for (position, expected_size) in profile.sizes.iter().enumerate() {
        let (sender, receiver) = if position % 2 == 0 {
            (&mut initiator, &mut responder)
        } else {
            (&mut responder, &mut initiator)
        };
        let mut bytes = vec![0; 8192];
        let written = sender.write_message(&[], &mut bytes)?;
        if written != *expected_size {
            return Err("unexpected handshake length".into());
        }
        bytes.truncate(written);
        let mut payload = [0; 8192];
        if receiver.read_message(&bytes, &mut payload)? != 0 {
            return Err("handshake payload was not empty".into());
        }
        if sender.get_handshake_hash() != receiver.get_handshake_hash() {
            return Err("peer transcript hashes differ".into());
        }
        hashes.push(hex::encode(sender.get_handshake_hash()));
        messages.push(bytes);
    }
    if !initiator.is_handshake_finished() || !responder.is_handshake_finished() {
        return Err("handshake unfinished".into());
    }
    for (peer, remote_seed) in [(&initiator, RESP_STATIC), (&responder, INIT_STATIC)] {
        let mut expected_remote = [0; 32];
        libcrux_curve25519::secret_to_public(&mut expected_remote, &remote_seed);
        if peer.get_remote_static() != Some(expected_remote.as_slice()) {
            return Err("handshake remote static key mismatch".into());
        }
    }
    if calls.load(Ordering::Relaxed) != 0 {
        return Err("fixture used OS randomness".into());
    }
    Ok(Exchange {
        initiator,
        responder,
        messages,
        hashes,
    })
}

fn transport_fixture(
    sender: &mut snow::TransportState,
    receiver: &mut snow::TransportState,
    plaintext: &[u8],
) -> Result<Value> {
    let mut ciphertext = vec![0; plaintext.len() + 16];
    let size = sender.write_message(plaintext, &mut ciphertext)?;
    ciphertext.truncate(size);
    let mut decoded = Zeroizing::new(vec![0; plaintext.len()]);
    let plaintext_len = receiver.read_message(&ciphertext, &mut decoded)?;
    if decoded.get(..plaintext_len) != Some(plaintext) {
        return Err("transport mismatch".into());
    }
    let mut framed = u16::try_from(size)?.to_be_bytes().to_vec();
    framed.extend_from_slice(&ciphertext);
    Ok(json!({
        "scope": "Noise cipher test only; this payload is NOT a todoke Identity/application frame",
        "nonce": 0,
        "nonce_hex": hex::encode(noise_nonce(0)),
        "plaintext_hex": hex::encode(plaintext),
        "ciphertext_hex": hex::encode(ciphertext),
        "framed_hex": hex::encode(framed)
    }))
}

fn vector(profile: Profile) -> Result<Value> {
    let (prologue, prelude) = fixture_prologue(profile);
    let mut exchanged = exchange(profile, &prologue, &PSK)?;
    let mut first_keys = exchanged.initiator.dangerously_get_raw_split();
    let mut second_keys = exchanged.responder.dangerously_get_raw_split();
    if first_keys != second_keys {
        return Err("peer Split keys differ".into());
    }
    let split = json!({
        "initiator_to_responder_key_hex": hex::encode(first_keys.0),
        "responder_to_initiator_key_hex": hex::encode(first_keys.1)
    });
    first_keys.zeroize();
    second_keys.zeroize();
    let final_hash = exchanged.initiator.get_handshake_hash().to_vec();
    let mut session_input = b"todoke/v1/session\0".to_vec();
    session_input.extend_from_slice(&final_hash);
    let messages: Vec<Value> = exchanged.messages.iter().enumerate().map(|(position, bytes)| {
        Ok(json!({
            "message_index": position + 1,
            "direction": if position % 2 == 0 { "initiator_to_responder" } else { "responder_to_initiator" },
            "tokens": profile.tokens[position],
            "payload_hex": "",
            "noise_message_length": bytes.len(),
            "noise_message_hex": hex::encode(bytes),
            "prelude_record_hex": hex::encode(prelude_message(u8::try_from(position + 1)?, bytes)?),
            "handshake_hash_after_hex": exchanged.hashes[position]
        }))
    }).collect::<Result<_>>()?;
    let mut initiator = exchanged.initiator.into_transport_mode()?;
    let mut responder = exchanged.responder.into_transport_mode()?;
    let first = transport_fixture(
        &mut initiator,
        &mut responder,
        b"public initiator transport fixture",
    )?;
    let second = transport_fixture(
        &mut responder,
        &mut initiator,
        b"public responder transport fixture",
    )?;
    let mut kem = FixtureKem::default();
    let calls = Arc::new(AtomicUsize::new(0));
    kem.generate(&mut ObservedRandom(calls));
    let mut ciphertext = [0; 1088];
    let mut shared = Zeroizing::new([0; 32]);
    kem.encapsulate(kem.pubkey(), shared.as_mut_slice(), &mut ciphertext)
        .map_err(|()| "reference KEM encapsulation failed")?;
    Ok(json!({
        "fixture_notice": NOTICE,
        "protocol_name": protocol_name(profile),
        "profile": profile.pattern,
        "provenance": {
            "engine": "snow 0.9.6; no default crypto resolver; hfs + risky-raw-split",
            "engine_release_commit": ENGINE_COMMIT,
            "audit_source_commit": AUDIT_COMMIT,
            "audit_scope": "Trail of Bits Snow review, 2024; NOT an audit of ML-KEM adapter or todoke",
            "successful_handshake_equivalence": "HFS transform, token processing and symmetric state preserved from audited source; 0.9.6 adds validation/failure handling",
            "primitives": "libcrux-curve25519 0.0.9; libcrux-ml-kem 0.0.11; libcrux-chacha20poly1305 0.0.10; libcrux-sha2 0.0.9",
            "internal_kem_enum_alias": "Kyber1024 resolver slot ONLY; actual primitive and transcript protocol name are MLKEM768"
        },
        "inputs": {
            "initiator_static_private_hex": hex::encode(INIT_STATIC),
            "responder_static_private_hex": hex::encode(RESP_STATIC),
            "initiator_ephemeral_private_hex": hex::encode(INIT_EPHEMERAL),
            "responder_ephemeral_private_hex": hex::encode(RESP_EPHEMERAL),
            "initiator_mlkem_keygen_d_then_z_hex": hex::encode(KEM_KEY_SEED),
            "responder_mlkem_encapsulation_m_hex": hex::encode(KEM_ENCAP_SEED),
            "psk_hex": hex::encode(PSK),
            "prelude": prelude
        },
        "kem": {
            "public_key_hex": hex::encode(kem.pubkey()),
            "ciphertext_hex": hex::encode(ciphertext),
            "shared_secret_hex": hex::encode(shared.as_slice())
        },
        "messages": messages,
        "final_handshake_hash_hex": hex::encode(final_hash),
        "session_id_hex": blake3::hash(&session_input).to_hex().to_string(),
        "split": split,
        "initial_transport": {"initiator_to_responder": first, "responder_to_initiator": second}
    }))
}

fn encoded_vectors() -> Result<Vec<(&'static str, Vec<u8>)>> {
    PROFILES
        .into_iter()
        .map(|profile| {
            let mut bytes = serde_json::to_vec_pretty(&vector(profile)?)?;
            bytes.push(b'\n');
            Ok((profile.file, bytes))
        })
        .collect()
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let check = match args.as_slice() {
        [] => false,
        [arg] if arg == "--check" => true,
        _ => return Err("usage: generate_handshake_vectors [--check]".into()),
    };
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/test-vectors");
    for (name, bytes) in encoded_vectors()? {
        let path = directory.join(name);
        if check {
            if fs::read(&path)? != bytes {
                return Err(format!("fixture differs: {name}").into());
            }
        } else {
            fs::write(path, bytes)?;
        }
    }
    println!(
        "{} three public handshake fixtures",
        if check { "Verified" } else { "Wrote" }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn libcrux_adapters_match_published_cacophony_classical_transcripts() -> Result<()> {
        // Independent expected outputs, not generated by this tool:
        // https://github.com/mcginty/snow/blob/a4be73faa042c5967f39662aa66919f774831a9a/tests/vectors/cacophony.txt
        // This checks the adapters and classical PSK semantics, not hybrid review.
        let static_keys = [
            hex::decode("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1")?,
            hex::decode("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893")?,
        ];
        let ephemeral_keys = [
            hex::decode("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a")?,
            hex::decode("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b")?,
        ];
        let psk = hex::decode("54686973206973206d7920417573747269616e20706572737065637469766521")?;
        let payloads: [&[u8]; 3] = [b"Ludwig von Mises", b"Murray Rothbard", b"F. A. Hayek"];
        let expected_hashes = [
            "8310f86394dc0dabb40beb8210031556db4403ab1202db7034c526232147a700",
            "a477edf6a131bbdb54707f6ea30eab6cd935d9b560f0e5fd1f053a95a99669fb",
            "7f3c5fdcdd3767e2835473a2683971490339f5bbeee82c3690bc606e14db70ed",
        ];
        for (profile, expected) in PROFILES.into_iter().zip(expected_hashes) {
            let pattern = profile
                .pattern
                .strip_suffix("+hfs")
                .ok_or("missing modifier")?;
            let name = format!("Noise_{pattern}_25519_ChaChaPoly_SHA256");
            let calls = Arc::new(AtomicUsize::new(0));
            let mut peers = Vec::new();
            for side in 0..2 {
                let mut remote = [0; 32];
                libcrux_curve25519::secret_to_public(
                    &mut remote,
                    static_keys[1 - side].as_slice().try_into()?,
                );
                let mut builder = Builder::with_resolver(
                    name.parse()?,
                    Box::new(FixtureResolver(Arc::clone(&calls))),
                )
                .local_private_key(&static_keys[side])
                .fixed_ephemeral_key_for_testing_only(&ephemeral_keys[side])
                .psk(profile.psk_position, &psk)
                .prologue(b"John Galt");
                if profile.mode == 3 || (profile.mode == 1 && side == 0) {
                    builder = builder.remote_public_key(&remote);
                }
                peers.push(if side == 0 {
                    builder.build_initiator()?
                } else {
                    builder.build_responder()?
                });
            }
            for (position, payload) in payloads.iter().take(profile.sizes.len()).enumerate() {
                let mut message = [0; 8192];
                let size = peers[position % 2].write_message(payload, &mut message)?;
                let mut decoded = [0; 8192];
                let size = peers[1 - position % 2].read_message(&message[..size], &mut decoded)?;
                assert_eq!(&decoded[..size], *payload);
            }
            for peer in peers {
                assert_eq!(hex::encode(peer.get_handshake_hash()), expected);
            }
            assert_eq!(calls.load(Ordering::Relaxed), 0);
        }
        Ok(())
    }

    #[test]
    fn committed_vectors_match_reference_regeneration() -> Result<()> {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/test-vectors");
        for (name, bytes) in encoded_vectors()? {
            assert_eq!(
                fs::read(directory.join(name))?,
                bytes,
                "fixture differs: {name}"
            );
        }
        Ok(())
    }

    #[test]
    fn wrong_psk_rejects_handshake() {
        for profile in PROFILES {
            let (prologue, _) = fixture_prologue(profile);
            assert!(exchange(profile, &prologue, &[0x56; 32]).is_err());
        }
    }

    #[test]
    fn altered_handshake_records_and_prologue_are_rejected() -> Result<()> {
        for profile in PROFILES {
            let (prologue, _) = fixture_prologue(profile);
            let correct = exchange(profile, &prologue, &PSK)?;
            for (position, message) in correct.messages.iter().enumerate() {
                // Sample public-key, ciphertext and tag byte positions without
                // claiming exhaustive fuzzing or a production parser.
                for byte in [0, 31, 32, message.len() / 2, message.len() - 1] {
                    let calls = Arc::new(AtomicUsize::new(0));
                    let mut peer =
                        build_peer(profile, position % 2 != 0, &prologue, &PSK, &calls, None)?;
                    let mut buffer = [0; 8192];
                    for previous in 0..position {
                        if previous % 2 == position % 2 {
                            peer.read_message(&correct.messages[previous], &mut buffer)?;
                        } else {
                            peer.write_message(&[], &mut buffer)?;
                        }
                    }
                    let mut changed = message.clone();
                    changed[byte] ^= 1;
                    assert!(peer.read_message(&changed, &mut buffer).is_err());
                }
            }
            let mut changed_prologue = prologue.clone();
            changed_prologue[0] ^= 1;
            let calls = Arc::new(AtomicUsize::new(0));
            let mut peer = build_peer(profile, false, &changed_prologue, &PSK, &calls, None)?;
            assert!(
                peer.read_message(&correct.messages[0], &mut [0; 8192])
                    .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn incorrect_known_static_keys_reject_ik_and_kk() -> Result<()> {
        let mut wrong_public = [0; 32];
        libcrux_curve25519::secret_to_public(&mut wrong_public, &[0x78; 32]);
        for (profile, initiator_wrong) in [
            (PROFILES[0], true),
            (PROFILES[2], true),
            (PROFILES[2], false),
        ] {
            let (prologue, _) = fixture_prologue(profile);
            let calls = Arc::new(AtomicUsize::new(0));
            let mut initiator = build_peer(
                profile,
                true,
                &prologue,
                &PSK,
                &calls,
                initiator_wrong.then_some(&wrong_public),
            )?;
            let mut responder = build_peer(
                profile,
                false,
                &prologue,
                &PSK,
                &calls,
                (!initiator_wrong).then_some(&wrong_public),
            )?;
            let mut message = [0; 8192];
            let size = initiator.write_message(&[], &mut message)?;
            assert!(
                responder
                    .read_message(&message[..size], &mut [0; 8192])
                    .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn x25519_adapter_rejects_all_zero_shared_secret() {
        let mut dh = FixtureDh::default();
        dh.set(&INIT_STATIC);
        assert!(dh.dh(&[0; 32], &mut [0; 32]).is_err());
    }
}
