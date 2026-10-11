# todoke protocol baseline

## Status

This is a requirements baseline, **not an implementable wire specification**. There are no assigned message types, field layouts, numeric identifiers, canonical encodings, cryptographic test vectors, or interoperable implementations. Do not invent any of them in code.

Read this document and [docs/DESIGN.md](../docs/DESIGN.md) before changing behavior. If the specification and code disagree, stop and report the disagreement. Resolve the relevant open decision through specification review before implementing the affected behavior.

## Required invariants

1. Rust owns all protocol, cryptographic, and file logic; presentation layers cannot override protocol policy.
2. Every session is authenticated with Noise IKpsk2, KKpsk2, or XXpsk3, using hybrid X25519 + ML-KEM-768 and a pairing PSK ratcheted per session.
3. BLE, Wi-Fi P2P, AWDL, USB, LAN, and QUIC relay are untrusted pipes. Switching pipes cannot remove authentication, encryption, integrity, or consent requirements.
4. Content encryption is per file: AES-256-GCM STREAM, with XChaCha20-Poly1305 fallback. BLAKE3/bao provides verified chunks.
5. Consent is enforced in the core: **no file byte is accepted before a signed AcceH**.
6. Cryptographic primitives come from libcrux where it covers, otherwise RustCrypto/dalek crates. No custom primitives are permitted.
7. All secrets must be zeroized; no secrets may be logged or cross FFI. No telemetry is collected.
8. Unsafe code is forbidden outside the FFI and platform crates. Untrusted input must not cause panics.

These invariants constrain the future specification. They do not define missing wire semantics.

## Open decisions

All entries below block implementation of the corresponding protocol behavior.

| Area | Required decision |
| --- | --- |
| Noise construction | Specify the exact hybrid X25519 + ML-KEM-768 composition, approved library coverage, full protocol name, transcript binding, algorithm negotiation, downgrade protection, and test vectors. Listing both algorithms does not define their secure composition. |
| Handshake selection | Define when IKpsk2, KKpsk2, and XXpsk3 apply, what prior identity/pairing state each requires, how identities are verified, and how first pairing obtains a PSK. Do not infer modes from connection type. |
| Pairing PSK ratchet | Define derivation, session binding, commit/acknowledgment rules, durable storage, secret destruction, concurrency, crash recovery, interrupted sessions, rollback prevention, and resynchronization. A per-session ratchet alone does not define a recoverable protocol. |
| Per-file encryption | Specify the exact AES-256-GCM STREAM construction, key derivation and separation, segment layout, nonce allocation and exhaustion, associated data, final-segment handling, resume behavior, and error handling. |
| Fallback | Specify XChaCha20-Poly1305 framing and nonce rules, conditions for selecting it, authenticated negotiation, and downgrade resistance. There is no implemented fallback path. |
| Chunk verification | Specify BLAKE3/bao versions and encodings, chunk sizes and boundaries, root authentication, proof validation, ciphertext/plaintext coverage, resource limits, truncation/reordering handling, and resume behavior. |
| Signed AcceH | Define what the name denotes; the exact schema and canonical bytes; signing algorithm and key authority; recipient, sender, session, file, and content bindings; verification rules; replay prevention; expiry/revocation; and behavior after reconnect, resume, or crash. No meaning is inferred from the abbreviated name. |
| Acceptance boundary | Define the operational meaning of accepting a file byte across transport buffers, transfer state, preview, and persistence, while preserving the strict rule that no file byte is accepted before a signed AcceH. |
| Message framing | Define versioning, bounded encodings, message sizes, validation order, resource budgets, invalid-state behavior, and extensibility before adding any parser. |
| File semantics | Define manifests, path/name rules, filesystem race handling, quotas, partial-file cleanup, completion, cancellation, retries, and verified publication. |
| Discovery and transport | Specify the minimum exposed metadata, trust validation, transport migration, connection multiplexing, relay abuse controls, and binding to authenticated session state. |
| Bindings | Verify BoltFFI support for mobile and web targets and define APIs that expose no secrets. A `wasm32-unknown-unknown` compile check is not verification of a web binding. |

No algorithm fallback, test fixture, or dummy message in this scaffold resolves these decisions. A future protocol specification must include interoperability vectors, negative cases, and reviewed state transitions before the corresponding implementation is considered complete.

## Required evidence with implementation

Every parser must have a cargo-fuzz target and bounded-input failure behavior. Every state machine must have proptest state-machine tests with explicit invariants and meaningful valid and invalid transitions. Include regression tests for any discovered failures. Formal models should cover consent gating, session authentication, ratchet recovery, and relevant concurrency once the transitions are specified.

The current empty workspace has no parser, protocol state machine, cryptographic code, or wire compatibility claim.
