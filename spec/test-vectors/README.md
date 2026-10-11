# todoke v1 deterministic test vectors

These JSON files are generated from [the normative protocol](../PROTOCOL.md) by
[`generate_vectors.rs`](../../crates/todoke-proto/examples/generate_vectors.rs) and
[`generate_handshake_vectors.rs`](../../crates/todoke-proto/examples/generate_handshake_vectors.rs).
All signing seeds, PSKs, and derived values are **public, fixed test fixtures**.
Never use them in production. The timestamps deliberately remain fixed; an
expired fixture does not authorize bypassing expiry validation.

From the repository root:

```sh
cargo run --locked -p todoke-proto --example generate_vectors
cargo run --locked -p todoke-proto --example generate_vectors -- --check
cargo test --locked -p todoke-proto --example generate_vectors
cargo run --locked -p todoke-proto --example generate_handshake_vectors
cargo run --locked -p todoke-proto --example generate_handshake_vectors -- --check
cargo test --locked -p todoke-proto --example generate_handshake_vectors
```

Each generator's command without `--check` replaces its own JSON files (six
standalone fixtures or three handshake fixtures). `--check` regenerates them in
memory and compares every byte, including formatting and the final newline,
without writing files. Missing or changed files fail the check. There is no
clock, network access, or platform-dependent serialization in generation. The
handshake generator rejects accidental RNG use; all randomness inputs are fixed.
Cargo may need network access to download the locked dependencies on first use.
The only accepted argument is `--check`; the tool takes no keys or peer input.

| File | Contents |
| --- | --- |
| `qr-payload.json` | A 1,312-byte QR payload, RFC 9285 Base45 text, Ed25519 device ID, actual X25519/ML-KEM-768 public keys derived from fixed seeds, and the QR pairing rendezvous token (PROTOCOL §10). Suite 1 is **assigned but unreleased**; this fixture verifies QR encoding, not an interoperable hybrid handshake. |
| `discovery-token.json` | HMAC-BLAKE3 full outputs and eight-byte tokens at epoch boundaries, including two timestamps within each of the first two 15-minute epochs. This is standard HMAC over unkeyed BLAKE3, with a 64-byte block and 32-byte digest; it is not BLAKE3 keyed mode. `derived_chain` starts from the `psk-ratchet.json` output and gives the pair secret, discovery key, and for the previous/current/next epoch the token, 19-byte DiscoveryRecord, mDNS TXT string, rendezvous token, and 16-byte contact locator. |
| `psk-ratchet.json` | HKDF-SHA-256 inputs, domain bytes, and 32-byte output with the handshake hash as Extract salt. The handshake hash is a fixed fixture, not a generated hybrid transcript. |
| `stream-nonces.json` | AES and XChaCha STREAM-BE32 nonce layouts for counters 0, 1, 65,535, and `u32::MAX`, each with both final-flag values. `v1_counter_and_final_permitted` is false for counter 65,535 without final and for all wider counters. True only permits that counter/flag combination; file length, epoch, and final-position checks still apply. `u32::MAX` cases describe the primitive layout only and are forbidden in live v1. Counter 0/final 1 is the empty-file final segment nonce. `content_key_schedule` derives the §8 26-byte context, epoch key, and nonce prefix for both suites and epochs 0 and 1 from a public file master and the manifest fixture hash, plus the 123-byte AAD and nonce for the manifest's sole segment. It contains no ciphertext. |
| `manifest-hash.json` | Canonical 182-byte one-file manifest (108-byte header), the six public bytes `hello\n`, plaintext root, domain, and manifest hash. |
| `accept-signature.json` | 178-byte Accept payload, signature input including the domain, 64-byte receiver signature, complete 242-byte signed record, and Accept hash. |
| `handshake-ikpsk2.json` | Exact IKpsk2+hfs Noise transcript: inner messages of 1296 and 1152 bytes, todoke Hello/prologue bytes, framed handshake records, public seeds, per-message/final hashes, Split keys, and initial bidirectional transport KATs. |
| `handshake-kkpsk2.json` | Exact KKpsk2+hfs Noise transcript: 1248 and 1152 bytes, with both static X25519 keys pinned and public fixture generation 7. Includes the same kinds of outputs as the IK fixture. |
| `handshake-xxpsk3.json` | Exact XXpsk3+hfs Noise-layer transcript: 1248, 1200, and 64 bytes. Uses a clearly marked **synthetic prologue and PSK**, not a valid todoke CPace/code prelude or a code-pairing integration vector. |

`*_hex` fields use lowercase hexadecimal without separators. JSON numbers are
decimal. Protocol integers use unsigned big-endian encoding except the Noise
AEAD nonce's little-endian u64 counter. Literal
domain strings end in a single NUL byte; their hex forms remove ambiguity.
The JSON wrapper is descriptive metadata, not a wire format.

The generator uses pinned reference implementations:

- [libcrux Ed25519 0.0.10](https://docs.rs/libcrux-ed25519/0.0.10/),
  [X25519 0.0.9](https://docs.rs/libcrux-curve25519/0.0.9/),
  [ML-KEM 0.0.11](https://docs.rs/libcrux-ml-kem/0.0.11/), and
  [HKDF 0.0.9](https://docs.rs/libcrux-hkdf/0.0.9/).
- [BLAKE3 1.8.7](https://docs.rs/blake3/1.8.7/) with
  [RustCrypto HMAC 0.13.0](https://docs.rs/hmac/0.13.0/) `SimpleHmac`.
- [Base45 3.2.0](https://docs.rs/base45/3.2.0/) for QR encoding.
- [dalek 3.0.0 strict verification](https://docs.rs/ed25519-dalek/3.0.0/ed25519_dalek/struct.VerifyingKey.html#method.verify_strict)
  additionally rejects small-order keys and signature malleability. Signing and
  initial verification use libcrux. Fixture keys come from reference key generation
  and have canonical encodings. The helper is not a peer-key parser: production
  must additionally enforce the protocol's canonical public-key encoding check;
  `VerifyingKey::from_bytes` plus `verify_strict` alone is not claimed to cover it.

Self-tests check RFC 9285 Base45 examples, RFC 5869 HKDF case 1, RFC 8032's
empty-message Ed25519 example, QR length/round-trip, discovery rotation, every
single-byte mutation of an Accept signing message, wrong signer/domain,
noncanonical signature scalar, a small-order-key forgery, and committed fixtures.
The QR public keys also undergo X25519 agreement and ML-KEM encapsulation /
decapsulation checks, including all-zero X25519 peer rejection and ML-KEM
implicit rejection after ciphertext tampering.
No protocol parser or state machine is implemented here; their required fuzz and
state-machine tests belong with their future implementations.

Caller-owned synthetic private buffers use `Zeroizing`. Published JSON fixture
values are intentionally public. This example does not establish production
secret erasure: upstream HMAC state and some libcrux internal temporaries do not
provide an audited zeroization guarantee. A production wrapper must resolve that
requirement before processing real secrets. The tool logs only completion or
file/error information, never key bytes.

## Handshake reference engine

The handshake example uses [Snow 0.9.6](https://docs.rs/snow/0.9.6/) with
`default-features = false`, `hfs`, and `risky-raw-split`, solely as a development
dependency. The last feature exposes public-fixture Split outputs; production
code MUST NOT expose traffic keys. All primitives are provided by libcrux through
its public resolver interface, including
[ChaCha20-Poly1305 0.0.10](https://docs.rs/libcrux-chacha20poly1305/0.0.10/) and
[SHA-256 0.0.9](https://docs.rs/libcrux-sha2/0.0.9/). The example implements no
cryptographic primitive or replacement Noise state machine.

The [O1 decision](../decisions/O1-HYBRID-NOISE.md) pins the construction to the
Trail of Bits–reviewed Snow revision `009411d2035a77ece57b0a6873169de7693a0aa0`.
The release used by the tool is `a4be73faa042c5967f39662aa66919f774831a9a` (0.9.6).
Its successful handshake operations, HFS insertion rule, and symmetric state match
the reviewed source; later changes include validation and failed-decrypt nonce
handling. That audit did not cover this ML-KEM adapter or todoke integration.

Snow 0.9.6 predates an MLKEM768 enum variant. The fixture's public `NoiseParams`
constructor sets the **actual MLKEM768 protocol name**, which Snow hashes verbatim,
and uses `KemChoice::Kyber1024` only to route to our libcrux ML-KEM-768 resolver.
There is no Kyber algorithm call, Kyber protocol-name alias, or runtime negotiation.
This offline workaround is not a proposed production API.

Static and ephemeral X25519 inputs, ML-KEM `d || z` and `m`, PSK, and prologue are
published in each JSON. The fixture adapter supplies them directly. Any unexpected
Snow RNG call makes generation fail. Both peers verify every message and transcript
hash. Tests include wrong PSKs, corrupted key/ciphertext/tag bytes, changed prologues,
all-zero X25519 outputs, and independent upstream classical PSK known-answer hashes
for the primitive adapters. The synthetic initial transport plaintexts test Noise
AEAD only: they are not valid todoke Identity records and authorize nothing.

Snow owns additional secret state that lacks the required production zeroization
guarantee. Public-fixture tests do not certify erasure, constant-time behavior,
hostile-input robustness, CPace, or the new backend integration. No production
parser/state machine is introduced; fuzzing and state-machine property tests remain
mandatory when those implementations are added.

The nine fixture groups do not provide independent hybrid interoperability,
CPace integration, content-encryption/Bao, or ratchet crash-recovery conformance.
These remain release gates. O1 now selects the reviewed construction; it does not
claim that the whole protocol is implemented or audited.
