# Parser fuzzing

`fuzz/` is an isolated cargo-fuzz workspace. Each target runs a real decoder on
arbitrary bytes. Where a decoder accepts the input, the target asserts that
re-encoding reproduces it exactly, so accepted encodings are canonical.

| Target | Decoder |
| --- | --- |
| `proto_device_binding` | `todoke_proto::identity::DeviceBinding::decode` (PROTOCOL §2) |
| `proto_revoke` | `todoke_proto::identity::Revoke::decode` (PROTOCOL §2) |
| `crypto_binding_verification` | Ed25519 public-key validation, then binding key (Ed25519, X25519 small-order, ML-KEM) and strict signature checks under that key as root |
| `crypto_keystore_plaintext` | Software key store blob plaintext (local format) |
| `crypto_contact_store_plaintext` | Contact store blob plaintext, including retained revocations (local format) |
| `crypto_sealed_envelope` | Local storage envelope header and authenticated opening; asserts unauthenticated input never opens |
| `proto_session_prelude` | Prelude length prefix and record split, `ClientHello`/`ServerHello` (echo check on a split input), and `NoiseHandshake` records for every mode (PROTOCOL §4.1, §4.2.5) |
| `proto_session_frames` | Transport length prefix, decrypted frame header, and `Identity`, ratchet, `Error`, `KeyUpdate`, and `Ping` bodies (PROTOCOL §4.3, §4.4, §5, §12, §13) |

The `crypto_*` targets call `todoke_crypto::identity::fuzzing`, which exists
only under `--cfg fuzzing` (set by cargo-fuzz). Each of its functions wraps the
same decoder that production code uses.

Committed seeds live in `fuzz/seeds/<target>/`: small valid and malformed
inputs built from public RFC 8032 test keys and fixed bytes. `fuzz/corpus/` is
generated and ignored by git. `scripts/ci/fuzz-smoke.sh` passes both
directories, with the generated corpus first, so libFuzzer writes new inputs
there and only reads the seeds.

The harness graph uses the root `deny.toml`. It contains todoke-crypto's
runtime libcrux dependencies, so the root advisory ignore still matches. The
dev-only duplicate skips are reported as unmatched warnings, which that CI step
does not deny. `libfuzzer-sys` has an NCSA license exception because it bundles
LLVM libFuzzer, and it is never shipped. `fuzz/supply-chain` was initialized with
`cargo vet init`, and every generated exemption was removed, matching the root
store: `cargo vet` fails until real audits exist.

Every parser must gain a `cargo-fuzz` target in the same pull request that adds
the parser, including protocol framing, discovery, manifests, archive metadata,
and platform input. Use the real public parser entry point, arbitrary bytes,
deterministic execution, bounded resource use, and no real filesystem or network
side effects. Expected parse failures are normal results; crashes and panics are
failures. Add small valid and malformed seed inputs without personal data or
secrets. Each state machine also needs independent `proptest` state-machine
tests in its owning crate; fuzzing does not replace them.

When adding a parser:

1. Read `docs/DESIGN.md` and `spec/PROTOCOL.md` before changing behavior. Stop
   and report any mismatch between implementation and specification.
2. Add a target under `fuzz_targets/` and declare it in `fuzz/Cargo.toml` as a
   `[[bin]]` with `test = false`, `doc = false`, and `bench = false`. Keep
   `fuzz/Cargo.toml` an isolated workspace (its own `[workspace]`), excluded
   from the root workspace. Add seeds under `fuzz/seeds/<target>/`.
3. Pin and review any new harness dependency, commit `fuzz/Cargo.lock`, and use
   versioned path dependencies for the todoke crates under test. Seed the lock
   from the root `Cargo.lock` so both graphs use the same versions. Record real
   audits or justified, narrowly scoped, reviewed exemptions in
   `fuzz/supply-chain`; never record an audit not performed. (`cargo vet init`
   rejects `--manifest-path`; run it from inside `fuzz/` if the store is ever
   recreated, then remove its blanket exemptions.)
4. Run both dependency checks from the repository root:

   ```sh
   cargo deny --manifest-path fuzz/Cargo.toml --locked --config deny.toml check
   cargo vet --manifest-path fuzz/Cargo.toml --locked
   ```

5. Run the target on the same pinned nightly and cargo-fuzz version as
   `.github/workflows/ci.yml`. CI discovers and runs each registered target for
   60 seconds with AddressSanitizer enabled. For a local smoke run:

   ```sh
   cargo +nightly-2026-08-20 fuzz run --fuzz-dir fuzz PARSER_TARGET fuzz/corpus/PARSER_TARGET fuzz/seeds/PARSER_TARGET -- -max_total_time=60
   bash scripts/ci/fuzz-smoke.sh
   ```

   If `cargo` on `PATH` is not the rustup proxy (for example a Homebrew
   install), the `+nightly` selector and `-Z` sanitizer flags fail; put the
   nightly toolchain's `bin` directory first on `PATH`.

Keep longer fuzz campaigns separate from the smoke check. Minimize failures,
add a regression test, and preserve sanitized reproductions. Do not add dummy
targets to make CI appear to cover a parser that has not been implemented.

See the [Rust Fuzz Book](https://rust-fuzz.github.io/book/cargo-fuzz.html) for
harness, corpus, minimization, and reproduction commands.
