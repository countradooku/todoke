//! The suite 0x0001 Noise engine: Snow's reviewed HFS+PSK state machine with
//! every primitive supplied by libcrux (PROTOCOL §4.2, O1,
//! `docs/adr/0001-noise-crate.md`).
//!
//! Snow owns token processing, `MixHash`/`MixKey`/`Split`, and nonces. This
//! module supplies X25519, ML-KEM-768, ChaCha20-Poly1305, SHA-256, and OS
//! randomness, and enforces todoke's exact message sizes around it. Snow
//! 0.10.0 has no ML-KEM variant: its only HFS KEM slot is named `Kyber1024`.
//! [`Resolver::resolve_kem`] answers that slot with ML-KEM-768. The slot name
//! never reaches the transcript: Snow hashes [`Pattern::protocol_name`]
//! verbatim, and every length comes from [`MlKem768`].
//!
//! Classical (non-HFS) Noise cannot be built here outside tests: the only
//! constructor is [`NoiseHandshake::new`], whose parameters always carry the
//! HFS modifier and the ML-KEM-768 name.

use core::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768PrivateKey, MlKem768PublicKey};
use libcrux_sha2::Digest as _;
use snow::params::{
    BaseChoice, CipherChoice, DHChoice, HandshakeChoice, HashChoice, KemChoice, NoiseParams,
};
use snow::resolvers::CryptoResolver;
use snow::types::{Cipher, Dh, Hash, Kem, Random};
use todoke_proto::session::{MAX_CIPHERTEXT_LEN, SessionMode, TAG_LEN};
use zeroize::{Zeroize, Zeroizing};

use crate::rng;

/// X25519 key and DH output length.
pub(crate) const DH_LEN: usize = 32;
/// PSK, `h`, `ck`, and split key length (§4.2.2).
pub(crate) const KEY_LEN: usize = 32;
const KEM_PUBLIC_LEN: usize = 1184;
const KEM_PRIVATE_LEN: usize = 2400;
const KEM_CIPHERTEXT_LEN: usize = 1088;
const KEM_SHARED_LEN: usize = 32;
const KEM_KEYGEN_SEED_LEN: usize = 64;
const KEM_ENCAPS_SEED_LEN: usize = 32;

/// The three suite 0x0001 patterns (§4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Pattern {
    /// QR pairing.
    IkPsk2,
    /// Existing contact.
    KkPsk2,
    /// Code pairing.
    XxPsk3,
}

impl Pattern {
    pub(crate) const fn for_mode(mode: SessionMode) -> Self {
        match mode {
            SessionMode::Qr => Self::IkPsk2,
            SessionMode::Contact => Self::KkPsk2,
            SessionMode::Code => Self::XxPsk3,
        }
    }

    pub(crate) const fn mode(self) -> SessionMode {
        match self {
            Self::IkPsk2 => SessionMode::Qr,
            Self::KkPsk2 => SessionMode::Contact,
            Self::XxPsk3 => SessionMode::Code,
        }
    }

    /// Exact §4.2.2 protocol name; hashed verbatim into `h`.
    pub(crate) const fn protocol_name(self) -> &'static str {
        match self {
            Self::IkPsk2 => "Noise_IKpsk2+hfs_25519+MLKEM768_ChaChaPoly_SHA256",
            Self::KkPsk2 => "Noise_KKpsk2+hfs_25519+MLKEM768_ChaChaPoly_SHA256",
            Self::XxPsk3 => "Noise_XXpsk3+hfs_25519+MLKEM768_ChaChaPoly_SHA256",
        }
    }

    const fn handshake(self) -> &'static str {
        match self {
            Self::IkPsk2 => "IKpsk2+hfs",
            Self::KkPsk2 => "KKpsk2+hfs",
            Self::XxPsk3 => "XXpsk3+hfs",
        }
    }

    const fn psk_position(self) -> u8 {
        match self {
            Self::IkPsk2 | Self::KkPsk2 => 2,
            Self::XxPsk3 => 3,
        }
    }

    /// Whether `initiator` must know the peer's static key beforehand.
    pub(crate) const fn needs_remote_static(self, initiator: bool) -> bool {
        match self {
            Self::IkPsk2 => initiator,
            Self::KkPsk2 => true,
            Self::XxPsk3 => false,
        }
    }

    /// Exact inner message sizes, in order (§4.2.5).
    pub(crate) const fn message_lens(self) -> &'static [usize] {
        self.mode().noise_message_lens()
    }
}

/// A Noise failure. Peer-caused failures are deliberately indistinguishable
/// (§4.2.6): DH, KEM, PSK, AEAD, and pinned-key mismatches are all
/// [`Self::Authentication`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NoiseError {
    /// The peer's message did not authenticate or was malformed.
    Authentication,
    /// OS randomness was unavailable; nothing was sent.
    Random,
    /// A local precondition failed (wrong turn, exhausted nonce, internal
    /// size mismatch).
    State,
}

impl fmt::Display for NoiseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Authentication => "handshake authentication failed",
            Self::Random => "randomness unavailable",
            Self::State => "handshake state error",
        })
    }
}

impl std::error::Error for NoiseError {}

/// Where randomness comes from. Production is always the OS CSPRNG; tests
/// may script exact bytes to reproduce the public fixtures.
#[derive(Clone)]
pub(crate) enum Entropy {
    /// `getrandom` (§1: random values come from an OS CSPRNG).
    Os,
    /// Exact byte strings, consumed in order; any other request fails.
    /// Test and fuzzing builds only: never reachable from a release build.
    #[cfg(any(test, fuzzing))]
    Scripted(Arc<std::sync::Mutex<std::collections::VecDeque<Vec<u8>>>>),
}

impl Entropy {
    #[cfg(any(test, fuzzing))]
    pub(crate) fn scripted(chunks: Vec<Vec<u8>>) -> Self {
        Self::Scripted(Arc::new(std::sync::Mutex::new(chunks.into())))
    }

    pub(crate) fn fill(&self, dest: &mut [u8]) -> Result<(), rng::RandomError> {
        match self {
            Self::Os => rng::fill(dest),
            #[cfg(any(test, fuzzing))]
            Self::Scripted(chunks) => {
                let mut chunks = chunks.lock().map_err(|_| rng::RandomError)?;
                match chunks.pop_front() {
                    Some(chunk) if chunk.len() == dest.len() => {
                        dest.copy_from_slice(&chunk);
                        Ok(())
                    }
                    _ => Err(rng::RandomError),
                }
            }
        }
    }
}

impl fmt::Debug for Entropy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Os => f.write_str("Entropy::Os"),
            #[cfg(any(test, fuzzing))]
            Self::Scripted(_) => f.write_str("Entropy::Scripted"),
        }
    }
}

struct SnowRandom(Entropy);

impl Random for SnowRandom {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), snow::Error> {
        self.0.fill(dest).map_err(|_| snow::Error::Rng)
    }
}

/// X25519 via libcrux. HACL's `ecdh` rejects an all-zero shared secret
/// (§1, §4.2.6), which covers every small-order peer key.
struct X25519 {
    private: Zeroizing<[u8; DH_LEN]>,
    public: [u8; DH_LEN],
}

impl X25519 {
    fn new() -> Self {
        Self {
            private: Zeroizing::new([0; DH_LEN]),
            public: [0; DH_LEN],
        }
    }
}

impl Dh for X25519 {
    fn name(&self) -> &'static str {
        "25519"
    }

    fn pub_len(&self) -> usize {
        DH_LEN
    }

    fn priv_len(&self) -> usize {
        DH_LEN
    }

    fn set(&mut self, private: &[u8]) {
        // Snow passes exactly priv_len() bytes; anything else leaves an
        // all-zero key whose public value fails every later DH.
        if let Ok(private) = <&[u8; DH_LEN]>::try_from(private) {
            self.private.copy_from_slice(private);
            libcrux_curve25519::secret_to_public(&mut self.public, &self.private);
        }
    }

    fn generate(&mut self, rng: &mut dyn Random) -> Result<(), snow::Error> {
        rng.try_fill_bytes(self.private.as_mut_slice())?;
        libcrux_curve25519::secret_to_public(&mut self.public, &self.private);
        Ok(())
    }

    fn pubkey(&self) -> &[u8] {
        &self.public
    }

    fn privkey(&self) -> &[u8] {
        self.private.as_slice()
    }

    fn dh(&self, public: &[u8], out: &mut [u8]) -> Result<(), snow::Error> {
        // Snow passes its MAXDHLEN buffers, not DH_LEN slices.
        let public: &[u8; DH_LEN] = public
            .get(..DH_LEN)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(snow::Error::Dh)?;
        let out: &mut [u8; DH_LEN] = out
            .get_mut(..DH_LEN)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(snow::Error::Dh)?;
        libcrux_curve25519::ecdh(out, public, &self.private).map_err(|_| {
            out.zeroize();
            snow::Error::Dh
        })
    }
}

fn noise_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// Noise `ChaChaPoly` via libcrux: nonce `0x00000000 || LE64(counter)` (§4.2.3).
struct ChaChaPoly(Zeroizing<[u8; KEY_LEN]>);

impl Cipher for ChaChaPoly {
    fn name(&self) -> &'static str {
        "ChaChaPoly"
    }

    fn set(&mut self, key: &[u8; KEY_LEN]) {
        self.0.copy_from_slice(key);
    }

    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize {
        // A short `out` makes libcrux fail; 0 then fails the caller's exact
        // length check, so nothing short is ever sent.
        libcrux_chacha20poly1305::encrypt(&self.0, plaintext, out, authtext, &noise_nonce(nonce))
            .map_or(0, |(ciphertext, tag)| ciphertext.len() + tag.len())
    }

    fn decrypt(
        &self,
        nonce: u64,
        authtext: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, snow::Error> {
        libcrux_chacha20poly1305::decrypt(&self.0, out, ciphertext, authtext, &noise_nonce(nonce))
            .map(<[u8]>::len)
            .map_err(|_| snow::Error::Decrypt)
    }

    /// Noise `REKEY(k)`: the first 32 bytes of `ENCRYPT(k, 2^64-1, empty,
    /// zeros)`. Same operation as Snow's default, with wiped temporaries.
    fn rekey(&mut self) {
        let mut ciphertext = Zeroizing::new([0; KEY_LEN + TAG_LEN]);
        let written = self.encrypt(u64::MAX, &[], &[0; KEY_LEN], ciphertext.as_mut_slice());
        if written == KEY_LEN + TAG_LEN {
            self.0.copy_from_slice(&ciphertext[..KEY_LEN]);
        } else {
            // Unreachable with correct buffer sizes. Failing closed: an
            // all-zero key cannot decrypt anything the peer sends.
            self.0.zeroize();
        }
    }
}

/// SHA-256 via libcrux. Snow builds HMAC and HKDF on top of this (§4.2.3).
#[derive(Default)]
struct Sha256(libcrux_sha2::Sha256);

impl Hash for Sha256 {
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

/// FIPS 203 ML-KEM-768 via libcrux, in Snow's HFS KEM slot.
struct MlKem768 {
    entropy: Entropy,
    /// Set when key generation could not get randomness. Snow 0.10's
    /// `Kem::generate` cannot return an error, so the engine checks this
    /// after every message and discards the message if set.
    failed: Arc<AtomicBool>,
    private: Zeroizing<[u8; KEM_PRIVATE_LEN]>,
    public: Box<[u8; KEM_PUBLIC_LEN]>,
}

impl Kem for MlKem768 {
    fn name(&self) -> &'static str {
        "MLKEM768"
    }

    fn pub_len(&self) -> usize {
        KEM_PUBLIC_LEN
    }

    fn ciphertext_len(&self) -> usize {
        KEM_CIPHERTEXT_LEN
    }

    fn shared_secret_len(&self) -> usize {
        KEM_SHARED_LEN
    }

    fn generate(&mut self, rng: &mut dyn Random) {
        // FIPS 203 KeyGen: independent 32-byte d and z from the CSPRNG
        // (§4.2.2); libcrux takes them as one 64-byte `d || z` seed.
        let mut seed = Zeroizing::new([0; KEM_KEYGEN_SEED_LEN]);
        if rng.try_fill_bytes(seed.as_mut_slice()).is_err() {
            self.failed.store(true, Ordering::SeqCst);
            return;
        }
        let pair = mlkem768::generate_key_pair(*seed);
        let (private, public) = pair.into_parts();
        let mut private_bytes: [u8; KEM_PRIVATE_LEN] = private.into();
        self.private.copy_from_slice(&private_bytes);
        private_bytes.zeroize();
        *self.public = public.into();
    }

    fn pubkey(&self) -> &[u8] {
        self.public.as_slice()
    }

    fn encapsulate(
        &self,
        public: &[u8],
        shared_out: &mut [u8],
        ciphertext_out: &mut [u8],
    ) -> Result<(usize, usize), snow::Error> {
        let public = MlKem768PublicKey::try_from(public).map_err(|_| snow::Error::Kem)?;
        // §4.2.3: the responder validates the decrypted `e1` (FIPS 203 input
        // check) before encapsulating.
        if !mlkem768::validate_public_key(&public) {
            return Err(snow::Error::Kem);
        }
        let mut randomness = Zeroizing::new([0; KEM_ENCAPS_SEED_LEN]);
        self.entropy
            .fill(randomness.as_mut_slice())
            .map_err(|_| snow::Error::Rng)?;
        let (ciphertext, shared) = mlkem768::encapsulate(&public, *randomness);
        let shared = Zeroizing::new(shared);
        shared_out
            .get_mut(..KEM_SHARED_LEN)
            .ok_or(snow::Error::Kem)?
            .copy_from_slice(shared.as_slice());
        ciphertext_out
            .get_mut(..KEM_CIPHERTEXT_LEN)
            .ok_or(snow::Error::Kem)?
            .copy_from_slice(ciphertext.as_slice());
        Ok((KEM_SHARED_LEN, KEM_CIPHERTEXT_LEN))
    }

    fn decapsulate(&self, ciphertext: &[u8], shared_out: &mut [u8]) -> Result<usize, snow::Error> {
        let ciphertext = MlKem768Ciphertext::try_from(ciphertext).map_err(|_| snow::Error::Kem)?;
        // Constant-time implicit rejection: a bad ciphertext yields an
        // unrelated secret and the following payload tag fails (§4.2.6).
        let private = MlKem768PrivateKey::from(*self.private);
        let shared = Zeroizing::new(mlkem768::decapsulate(&private, &ciphertext));
        let mut private_bytes: [u8; KEM_PRIVATE_LEN] = private.into();
        private_bytes.zeroize();
        shared_out
            .get_mut(..KEM_SHARED_LEN)
            .ok_or(snow::Error::Kem)?
            .copy_from_slice(shared.as_slice());
        Ok(KEM_SHARED_LEN)
    }
}

struct Resolver {
    entropy: Entropy,
    kem_failed: Arc<AtomicBool>,
}

impl CryptoResolver for Resolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(SnowRandom(self.entropy.clone())))
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        (*choice == DHChoice::Curve25519).then(|| Box::new(X25519::new()) as Box<dyn Dh>)
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        (*choice == HashChoice::SHA256).then(|| Box::new(Sha256::default()) as Box<dyn Hash>)
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        (*choice == CipherChoice::ChaChaPoly)
            .then(|| Box::new(ChaChaPoly(Zeroizing::new([0; KEY_LEN]))) as Box<dyn Cipher>)
    }

    /// Snow's only HFS slot is named `Kyber1024`; it is answered with
    /// ML-KEM-768 and nothing else. No Kyber code exists in this build.
    fn resolve_kem(&self, choice: &KemChoice) -> Option<Box<dyn Kem>> {
        (*choice == KemChoice::Kyber1024).then(|| {
            Box::new(MlKem768 {
                entropy: self.entropy.clone(),
                failed: Arc::clone(&self.kem_failed),
                private: Zeroizing::new([0; KEM_PRIVATE_LEN]),
                public: Box::new([0; KEM_PUBLIC_LEN]),
            }) as Box<dyn Kem>
        })
    }
}

/// The secret and public inputs to one handshake attempt.
pub(crate) struct HandshakeInputs<'a> {
    pub(crate) pattern: Pattern,
    pub(crate) initiator: bool,
    pub(crate) prologue: &'a [u8],
    pub(crate) psk: &'a [u8; KEY_LEN],
    pub(crate) local_static: &'a [u8; DH_LEN],
    pub(crate) remote_static: Option<&'a [u8; DH_LEN]>,
    pub(crate) entropy: Entropy,
}

/// One handshake attempt. Any failure poisons it: no retry, no fallback
/// (§4.2.6).
pub(crate) struct NoiseHandshake {
    state: snow::HandshakeState,
    pattern: Pattern,
    initiator: bool,
    /// Messages processed so far (sent or received).
    position: usize,
    kem_failed: Arc<AtomicBool>,
    poisoned: bool,
}

impl NoiseHandshake {
    pub(crate) fn new(inputs: &HandshakeInputs<'_>) -> Result<Self, NoiseError> {
        let pattern = inputs.pattern;
        if pattern.needs_remote_static(inputs.initiator) != inputs.remote_static.is_some() {
            return Err(NoiseError::State);
        }
        let handshake: HandshakeChoice =
            pattern.handshake().parse().map_err(|_| NoiseError::State)?;
        let params = NoiseParams::new(
            pattern.protocol_name().to_owned(),
            BaseChoice::Noise,
            handshake,
            DHChoice::Curve25519,
            Some(KemChoice::Kyber1024),
            CipherChoice::ChaChaPoly,
            HashChoice::SHA256,
        );
        Self::build(params, inputs, pattern)
    }

    fn build(
        params: NoiseParams,
        inputs: &HandshakeInputs<'_>,
        pattern: Pattern,
    ) -> Result<Self, NoiseError> {
        let kem_failed = Arc::new(AtomicBool::new(false));
        let resolver = Resolver {
            entropy: inputs.entropy.clone(),
            kem_failed: Arc::clone(&kem_failed),
        };
        let mut builder = snow::Builder::with_resolver(params, Box::new(resolver))
            .local_private_key(inputs.local_static)
            .and_then(|builder| builder.psk(pattern.psk_position(), inputs.psk))
            .and_then(|builder| builder.prologue(inputs.prologue))
            .map_err(|_| NoiseError::State)?;
        if let Some(remote) = inputs.remote_static {
            builder = builder
                .remote_public_key(remote)
                .map_err(|_| NoiseError::State)?;
        }
        let state = if inputs.initiator {
            builder.build_initiator()
        } else {
            builder.build_responder()
        }
        .map_err(|_| NoiseError::State)?;
        Ok(Self {
            state,
            pattern,
            initiator: inputs.initiator,
            position: 0,
            kem_failed,
            poisoned: false,
        })
    }

    /// Builds a classical (non-HFS) handshake for the published classical
    /// vectors. Test-only: unreachable from any runtime path.
    #[cfg(test)]
    pub(crate) fn classical_for_tests(
        name: &str,
        inputs: &HandshakeInputs<'_>,
    ) -> Result<snow::HandshakeState, NoiseError> {
        let params: NoiseParams = name.parse().map_err(|_| NoiseError::State)?;
        Ok(Self::build(params, inputs, inputs.pattern)?.state)
    }

    /// The 1-based index of the next message.
    pub(crate) fn next_index(&self) -> usize {
        self.position + 1
    }

    /// Whether this side sends the next message.
    pub(crate) fn is_our_turn(&self) -> bool {
        (self.position % 2 == 0) == self.initiator
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.position == self.pattern.message_lens().len()
    }

    fn expected_len(&self) -> Result<usize, NoiseError> {
        self.pattern
            .message_lens()
            .get(self.position)
            .copied()
            .ok_or(NoiseError::State)
    }

    /// Writes the next message with an empty payload (§4.2.5).
    pub(crate) fn write_message(&mut self) -> Result<Vec<u8>, NoiseError> {
        if self.poisoned || !self.is_our_turn() {
            return Err(NoiseError::State);
        }
        let expected = self.expected_len()?;
        let mut message = vec![0; expected];
        let result = self.state.write_message(&[], &mut message);
        if self.kem_failed.load(Ordering::SeqCst) {
            self.poisoned = true;
            message.zeroize();
            return Err(NoiseError::Random);
        }
        match result {
            Ok(written) if written == expected => {
                self.position += 1;
                Ok(message)
            }
            Ok(_) => {
                self.poisoned = true;
                Err(NoiseError::State)
            }
            Err(snow::Error::Rng) => {
                self.poisoned = true;
                Err(NoiseError::Random)
            }
            // A KEM error while writing comes from validating the peer's
            // `e1` (§4.2.6: malformed ML-KEM public key closes).
            Err(_) => {
                self.poisoned = true;
                Err(NoiseError::Authentication)
            }
        }
    }

    /// Reads the next message; its exact size is checked before Snow sees it
    /// and its payload must be empty.
    pub(crate) fn read_message(&mut self, message: &[u8]) -> Result<(), NoiseError> {
        if self.poisoned || self.is_our_turn() {
            return Err(NoiseError::State);
        }
        if message.len() != self.expected_len()? {
            self.poisoned = true;
            return Err(NoiseError::Authentication);
        }
        // An empty payload decrypts to zero bytes; any room here would only
        // matter for a payload, which the exact size already excludes.
        let mut payload = [0_u8; 0];
        if let Ok(0) = self.state.read_message(message, &mut payload) {
            self.position += 1;
            Ok(())
        } else {
            self.poisoned = true;
            Err(NoiseError::Authentication)
        }
    }

    pub(crate) fn handshake_hash(&self) -> [u8; KEY_LEN] {
        let mut hash = [0; KEY_LEN];
        let current = self.state.get_handshake_hash();
        if let Some(current) = current.get(..KEY_LEN) {
            hash.copy_from_slice(current);
        }
        hash
    }

    /// Completes the handshake: `Split` happened inside Snow on the last
    /// message; the transport keys never leave it.
    pub(crate) fn into_transport(self) -> Result<NoiseTransport, NoiseError> {
        if self.poisoned || !self.is_finished() {
            return Err(NoiseError::State);
        }
        let handshake_hash = self.handshake_hash();
        let mut remote_static = [0; DH_LEN];
        let remote = self.state.get_remote_static().ok_or(NoiseError::State)?;
        remote_static.copy_from_slice(remote.get(..DH_LEN).ok_or(NoiseError::State)?);
        let initiator = self.initiator;
        let state = self
            .state
            .into_transport_mode()
            .map_err(|_| NoiseError::State)?;
        Ok(NoiseTransport {
            state,
            initiator,
            handshake_hash,
            remote_static,
        })
    }
}

impl fmt::Debug for NoiseHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoiseHandshake")
            .field("pattern", &self.pattern)
            .field("initiator", &self.initiator)
            .field("position", &self.position)
            .finish_non_exhaustive()
    }
}

/// The post-`Split` transport `CipherState` pair, owned by Snow.
pub(crate) struct NoiseTransport {
    state: snow::TransportState,
    initiator: bool,
    handshake_hash: [u8; KEY_LEN],
    remote_static: [u8; DH_LEN],
}

impl NoiseTransport {
    pub(crate) fn handshake_hash(&self) -> &[u8; KEY_LEN] {
        &self.handshake_hash
    }

    pub(crate) fn remote_static(&self) -> &[u8; DH_LEN] {
        &self.remote_static
    }

    /// Encrypts one transport message with empty AAD (§5).
    pub(crate) fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let length = plaintext.len() + TAG_LEN;
        if length > MAX_CIPHERTEXT_LEN {
            return Err(NoiseError::State);
        }
        let mut ciphertext = vec![0; length];
        match self.state.write_message(plaintext, &mut ciphertext) {
            Ok(written) if written == length => Ok(ciphertext),
            _ => Err(NoiseError::State),
        }
    }

    /// Decrypts one transport message. Any failure is fatal to the session.
    pub(crate) fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, NoiseError> {
        let length = ciphertext
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(NoiseError::Authentication)?;
        let mut plaintext = Zeroizing::new(vec![0; length]);
        match self.state.read_message(ciphertext, &mut plaintext) {
            Ok(read) if read == length => Ok(plaintext),
            _ => Err(NoiseError::Authentication),
        }
    }

    /// Noise `REKEY` of the sending direction; the nonce is not reset (§5).
    pub(crate) fn rekey_outgoing(&mut self) {
        self.state.rekey_outgoing();
    }

    /// Noise `REKEY` of the receiving direction.
    pub(crate) fn rekey_incoming(&mut self) {
        self.state.rekey_incoming();
    }

    #[cfg(test)]
    pub(crate) fn sending_nonce(&self) -> u64 {
        self.state.sending_nonce()
    }

    #[cfg(test)]
    pub(crate) fn receiving_nonce(&self) -> u64 {
        self.state.receiving_nonce()
    }
}

impl fmt::Debug for NoiseTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoiseTransport")
            .field("initiator", &self.initiator)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
