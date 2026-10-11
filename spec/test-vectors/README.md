# todoke v1 deterministic test vectors

These JSON files are generated from [the normative protocol](../PROTOCOL.md) by
[`generate_vectors.rs`](../../crates/todoke-proto/examples/generate_vectors.rs).
All signing seeds, PSKs, and derived values are **public, fixed test fixtures**.
Never use them in production. The timestamps deliberately remain fixed; an
expired fixture does not authorize bypassing expiry validation.

From the repository root:

```sh
cargo run --locked -p todoke-proto --example generate_vectors
cargo run --locked -p todoke-proto --example generate_vectors -- --check
cargo test --locked -p todoke-proto --example generate_vectors
```

The first command replaces the six JSON files. `--check` regenerates them in
memory and compares every byte, including formatting and the final newline,
without writing files. Missing or changed files fail the check. There is no
clock, RNG, network access, or platform-dependent serialization in generation.
Cargo may need network access to download the locked dependencies on first use.
The only accepted argument is `--check`; the tool takes no keys or peer input.

| File | Contents |
| --- | --- |
| `qr-payload.json` | A 1,312-byte QR payload, RFC 9285 Base45 text, Ed25519 device ID, and actual X25519/ML-KEM-768 public keys derived from fixed seeds. Suite 1 remains **reserved and unreleased**; this verifies encoding, not an interoperable hybrid handshake. |
| `discovery-token.json` | HMAC-BLAKE3 full outputs and eight-byte tokens at epoch boundaries, including two timestamps within each of the first two 15-minute epochs. This is standard HMAC over unkeyed BLAKE3, with a 64-byte block and 32-byte digest; it is not BLAKE3 keyed mode. |
| `psk-ratchet.json` | HKDF-SHA-256 inputs, domain bytes, and 32-byte output with the handshake hash as Extract salt. The handshake hash is a fixed fixture, not a generated hybrid transcript. |
| `stream-nonces.json` | AES and XChaCha STREAM-BE32 nonce layouts for counters 0, 1, 65,535, and `u32::MAX`, each with both final-flag values. `v1_counter_and_final_permitted` is false for counter 65,535 without final and for all wider counters. True only permits that counter/flag combination; file length, epoch, and final-position checks still apply. `u32::MAX` cases describe the primitive layout only and are forbidden in live v1. Counter 0/final 1 is the empty-file final segment nonce. |
| `manifest-hash.json` | Canonical 182-byte one-file manifest (108-byte header), the six public bytes `hello\n`, plaintext root, domain, and manifest hash. |
| `accept-signature.json` | 178-byte Accept payload, signature input including the domain, 64-byte receiver signature, complete 242-byte signed record, and Accept hash. |

`*_hex` fields use lowercase hexadecimal without separators. JSON numbers are
decimal. All protocol integers use unsigned big-endian encoding. Literal
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

These six fixture groups do not settle the open hybrid Noise/PAKE profiles and do
not provide handshake, AEAD ciphertext, Bao proof, or ratchet crash-recovery
interoperability vectors. Those are separate release gates in the protocol.
