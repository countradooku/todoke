# ADR 0001: Noise engine for suite 0x0001

- **Status:** accepted for the unaudited implementation; production use stays
  disabled (PROTOCOL §16, gates O6 and O10). Needs maintainer review.
- **Date:** 2026-10-11
- **Scope:** the runtime Noise state machine behind `todoke_crypto::session`,
  the async I/O interface, and the production gate. The hybrid construction
  itself is not decided here: [decision O1](../../spec/decisions/O1-HYBRID-NOISE.md)
  and [PROTOCOL §4.2](../../spec/PROTOCOL.md) pin it.

## Context

O1 selects the HFS+PSK state machine in Snow commit
`009411d2035a77ece57b0a6873169de7693a0aa0` (the revision Trail of Bits
reviewed, report dated 2024-03-29), instantiated with X25519, FIPS 203
ML-KEM-768, ChaChaPoly, and SHA-256, with the exact token schedules of §4.2.4
(KK is `e, es, e1, ss`). The committed fixtures
`spec/test-vectors/handshake-{ikpsk2,kkpsk2,xxpsk3}.json` were produced by
Snow 0.9.6 through an offline adapter. Any runtime choice must reproduce those
transcripts exactly. Classical Noise must not be selectable at runtime.

Requirements for the runtime engine:

1. `IKpsk2`, `KKpsk2`, and `XXpsk3` with the HFS modifier and exactly the
   §4.2 transcript (names, prologue, token order, PSK `e` rule).
2. ML-KEM-768 from libcrux (the project prefers libcrux primitives), with
   FIPS 203 input validation and implicit rejection.
3. No traffic-key export; secrets zeroized where the code is ours; residues
   documented (O6).
4. Permissive license, pinned exact version published at least two weeks ago,
   no new duplicate or license exceptions in shipped code.
5. Compiles on the 1.85 MSRV and every CI target, including
   `wasm32-unknown-unknown`.

## Candidates

Facts below were checked on 2026-10-11 against crates.io, the upstream
repositories, and the published crate sources.

### Snow

| Item | Finding |
| --- | --- |
| Releases | 0.9.6 (2024-01-26, release commit `a4be73f`) and 0.10.0 (2025-07-19, tag commit `4bb43f5`, edition 2024, `rust-version = 1.85`). No later release. `main` was last changed 2026-03-25. |
| Patterns | IK, KK, XX with `psk0..3` and `hfs` modifiers through `HandshakeChoice`; the HFS insertion rule is the one O1 pins. |
| ML-KEM | **No released version supports ML-KEM-768.** `KemChoice` has one variant, `Kyber1024`, behind the `hfs` feature. [PR #210](https://github.com/mcginty/snow/pull/210) "Add ML-KEM-768 (FIPS 203) to the HFS extension" was opened 2026-06-14 and is still open (last updated 2026-10-10). |
| Audit | The Trail of Bits review covers commit `009411d`, not 0.10.0, not the HFS cases specifically, and not any ML-KEM backend (O1 records these limits). |
| Changes since 0.9.6 that matter here | `Random`, `Dh::generate`, and KEM errors return `Result`; `Cipher::set` takes a fixed-size key; `no_std` + `alloc`. A diff of `handshakestate.rs`, `symmetricstate.rs`, `cipherstate.rs`, and `params/patterns.rs` shows refactoring and error propagation, not a changed token schedule or KDF. |
| Dependencies with `default-features = false, features = ["hfs"]` | `subtle` (already a runtime dependency), and `rustc_version`/`semver` at build time (already in the graph). |
| Unsafe | The crate sets `unsafe_code = "forbid"`. |
| Zeroization | None: Snow 0.10.0 has no `zeroize` dependency and no `Drop` impl for its secret state (see O6 residues below). |
| License | Apache-2.0 OR MIT. |

### Clatter

| Item | Finding |
| --- | --- |
| Releases | 2.3.0 (2026-08-30, MIT, `rust-version = 1.81`). |
| Construction | PQNoise KEM patterns and its own "hybrid" family named `Noise_hybrid<pattern>_<DH>+<KEM>_…`, which sends DH and KEM public keys together at `e`. It has no HFS `e1`/`ekem1` tokens and no `IKpsk2+hfs`-style schedules. |
| ML-KEM | RustCrypto `ml-kem` 0.2 or PQClean; not libcrux. |
| Audit | Its README states that it "has not received any formal audit". |

Clatter cannot produce the §4.2 transcripts. Choosing it would contradict O1,
so it is rejected on that ground alone.

### A new state machine over libcrux

Writing the Noise state machine in todoke would give full control over
zeroization, but it would be new, unreviewed protocol code, which is exactly
what O1 avoids by reusing reviewed source. Not chosen; kept as the fallback
if the Snow residues below cannot be fixed upstream (O6).

## Decision

Use **Snow 0.10.0** (`default-features = false`, `features = ["hfs"]`) as the
runtime state machine, with every primitive supplied by a todoke
`CryptoResolver` backed by libcrux:

| Noise primitive | Implementation |
| --- | --- |
| `25519` | `libcrux-curve25519` 0.0.9; HACL rejects an all-zero shared secret |
| KEM | `libcrux-ml-kem` 0.0.11 ML-KEM-768: `validate_public_key` before encapsulation, implicit-rejection decapsulation |
| `ChaChaPoly` | `libcrux-chacha20poly1305` 0.0.10, nonce `0x00000000 ‖ LE64(n)` |
| `SHA256` | `libcrux-sha2` 0.0.9; Snow builds Noise's HMAC/HKDF on it |
| Randomness | OS CSPRNG through `getrandom` |

The todoke-specific KDFs (§4.4 ratchet HKDF, confirmation HMAC) use
`libcrux-hkdf`/`libcrux-hmac` 0.0.9 directly.

### Resolver integration, assessed honestly

- **The `Kyber1024` slot.** Snow's only HFS slot is named `Kyber1024`. The
  resolver answers it with ML-KEM-768 and nothing else; Snow's PQClean
  feature is not enabled, so no Kyber code is compiled. The transcript never
  contains the slot name: Snow initializes `h` from `NoiseParams.name`, which
  todoke sets to the exact §4.2.2 name through the public `NoiseParams::new`,
  and every length comes from the ML-KEM object. This is a workaround for a
  missing upstream variant, not an intended Snow API. When a Snow release adds
  an ML-KEM-768 choice, switch to it and re-run the fixture conformance tests.
- **RNG failure in KEM key generation.** `Kem::generate` cannot return an
  error in Snow 0.10.0. The adapter records a failure flag; the engine checks
  it after every message and discards the message, so a key generated without
  randomness is never sent.
- **Encapsulation randomness.** `Kem::encapsulate` takes no RNG; the adapter
  draws the 32-byte `m` from the OS CSPRNG itself.
- **Raw split.** `risky-raw-split` is not enabled for `todoke-crypto`. The
  transport keys stay inside Snow's `TransportState` (fixture tests verify
  them through the published transport KATs instead).
- **Classical Noise.** The only runtime constructor always builds the HFS
  pattern with the ML-KEM name. A classical builder exists under `cfg(test)`
  only, for the published classical vectors.

### Conformance evidence (all in `cargo test --workspace`)

1. The runtime engine reproduces all three committed transcripts byte for
   byte: every message, every intermediate and final handshake hash, the
   session ID, and both initial transport KATs (which pin both Split keys).
   They were generated with a different Snow release (0.9.6) and a separate
   adapter, so this also checks that 0.10.0 did not change the construction.
2. The handshake driver reproduces the IK and KK fixture prelude records
   (Hellos, prologue construction, framing) byte for byte.
3. The same resolver passes the Cacophony classical vectors for `IKpsk2`,
   `KKpsk2`, and `XXpsk3`, including transport messages
   (`crates/todoke-crypto/testdata/noise-classical-cacophony.json`, copied from
   Snow's test suite with provenance).
4. libcrux ML-KEM-768 passes NIST's ACVP vectors for FIPS 203: 25 key
   generation, 25 encapsulation, 10 decapsulation (including implicit
   rejection), 10 encapsulation-key and 10 decapsulation-key checks
   (`crates/todoke-crypto/testdata/acvp-mlkem768.json`, from
   `usnistgov/ACVP-Server` commit `975de31`, hashes recorded in the file).

Not done: an interoperability run against Snow's own default resolver. It
needs `curve25519-dalek` 4.x and RustCrypto AEAD/hash crates, which would add
duplicate-version and license exceptions for a dev-only check. The Cacophony
vectors come from an independent implementation and cover the same classical
ground. Independent hybrid interoperability remains gate O10.

### Async I/O interface

The session core is sans-IO: it takes complete records and returns records to
send, which is what the fuzz target and the proptest state machine drive. The
async adapter uses the `futures-io` 0.3.34 `AsyncRead`/`AsyncWrite` traits:
trait definitions only, no dependencies, MIT OR Apache-2.0, and implemented
or adaptable by every major runtime (Tokio users wrap their streams with
`tokio-util`'s `compat`). Tokio's own traits would pull Tokio into
`todoke-crypto`. Deadlines (§13) come from a caller-supplied `Timer` trait
(`now` plus `sleep_until`), so the crate reads no clock and needs no runtime;
`std::time::Instant` would also panic on `wasm32-unknown-unknown`. Tests use
an in-memory pipe, a manual clock, and a small executor written in the test
module.

### Production gate

Every session entry point takes an `UnauditedSuite0001` value, built only by
`UnauditedSuite0001::acknowledge_not_production_ready()`. A cargo feature was
considered and rejected: `cargo test --workspace` must run every session test
without extra flags, dev-dependency feature unification would switch such a
feature on in test builds anyway, and an explicit value makes each enabling
call site visible in review. No production code in this repository constructs
it. Enabling suite 0x0001 for real users requires closing O6 and O10 and a
maintainer decision, not a code change alone.

## O6: secret residues

Everything todoke owns is in `Zeroizing` buffers: static and ephemeral X25519
secrets, the ML-KEM decapsulation key and seeds, cipher keys (Snow stores them
in todoke's `ChaChaPoly` objects), the PSK and `psk_next`, ratchet MAC keys,
and decrypted frames. The following are **not** wiped and keep this suite
gated:

- **Snow 0.10.0:** the chaining key `ck` and `h` in `SymmetricState`; the PSK
  copy in `HandshakeState::psks`; the default `Hash::hmac`/`hkdf` pads and
  intermediate outputs; `Split` temporaries; DH output arrays; the KEM
  shared-secret buffer in `Ekem1` processing. None has a `Drop` that zeroizes.
- **libcrux:** stack copies made when passing the ML-KEM private key and
  seeds by value; HACL SHA-256, HMAC, HKDF, and ChaCha20-Poly1305 internal
  state.

Recommended path: propose zeroization upstream to Snow (alongside PR #210),
then re-evaluate; if that does not land, decide between a reviewed fork and a
todoke state machine. Either way the result needs review before O6 closes.

## Consequences

- Packages new to `todoke-crypto`'s runtime graph: `snow` 0.10.0,
  `futures-io` 0.3.34, `libcrux-curve25519` 0.0.9 (previously dev-only),
  `libcrux-sha2` 0.0.9, `libcrux-hkdf` 0.0.9, and `libcrux-hmac` 0.0.9. All
  were already in the lock file except `snow` 0.10.0 and `futures-io`.
  `libcrux-secrets` 0.0.7 and `subtle` 2.6.1 were already transitive runtime
  dependencies and are now direct pins. No new license exception.
- One new dev-only duplicate skip: `snow@0.9.6` (the fixture generator),
  pending maintainer sign-off. Migrating the generator to 0.10.0 would remove
  it and the `rand_core 0.6.4`/`getrandom 0.2.17` skips, but would change the
  fixtures' provenance fields, so it is left as a separate decision.
- The Kyber-slot workaround must be revisited on every Snow upgrade.

## Open questions

1. Accept the `snow@0.9.6` dev-only skip, or migrate the fixture generator?
   Recommended: accept now, migrate in a separate change that regenerates the
   fixture provenance.
2. O6: which route for Snow's residues (upstream, fork, own state machine)?
   Recommended: upstream first.
3. O10: which independent implementation reproduces the hybrid transcripts?
   Unchanged by this ADR.
