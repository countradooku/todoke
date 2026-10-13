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
| `crypto_contact_store_plaintext` | Contact store blob plaintext, including retained revocations and the pairing section (pending-pairing journal and burned pairing ledger) (local format) |
| `crypto_sealed_envelope` | Local storage envelope header and authenticated opening; asserts unauthenticated input never opens |
| `crypto_qr_payload` | `QrPayload::from_bytes` and `QrPayload::from_text`: exact lengths, `TODOKE:` prefix, canonical RFC 9285 Base45, magic, version, suite, pairing ID, Ed25519/X25519/ML-KEM key validation, and expiry, checked at the expiry the input claims so that expiry never masks the other checks (PROTOCOL §3.1) |
| `proto_session_prelude` | Prelude length prefix and record split, `ClientHello`/`ServerHello` (echo check on a split input), and `NoiseHandshake` records for every mode (PROTOCOL §4.1, §4.2.5) |
| `crypto_session_handshake` | Session handshake driver (responder and initiator, all three modes) fed fuzzer-supplied prelude records, set up deterministically from the public §4.2 fixture inputs so mutated fixture records reach the Noise layer (PROTOCOL §4.1, §4.2) |
| `crypto_session_establishment` | `Establishment::receive`: identity confirmation and the PSK ratchet transaction against an honest peer, with fuzzer-chosen wire operations (deliver, corrupt, replay, drop, swap, raw bytes, clock jumps, deadline checks) after a deterministic contact handshake between fixed public test identities (PROTOCOL §4.3, §4.4, §13) |
| `crypto_session_transport` | `SessionCore::receive` and its timers on an established session: peer frames of any type, `KeyUpdate`, Ping/Pong, `Error`, corrupted and raw records, clock jumps, and local sends, optionally under a small byte budget (PROTOCOL §5, §12, §13) |
| `crypto_session_record_stream` | The async adapter's incremental length-prefixed record reader (prelude and transport framing) on arbitrary bytes delivered in short reads with `Pending` in between; checked against a direct split of the same bytes (PROTOCOL §4.1, §5, §13) |
| `proto_session_frames` | Transport length prefix, decrypted frame header, and `Identity`, ratchet, `Error`, `KeyUpdate`, and `Ping` bodies (PROTOCOL §4.3, §4.4, §5, §12, §13) |
| `crypto_human_code` | `HumanCode::parse_and_wipe` and `HumanCode::parse` on typed code input: exactly ten ASCII digits, both agree, and the buffer is wiped (PROTOCOL §3.2) |
| `crypto_code_pairing` | Human-code pairing handshake driver (responder and initiator, right or wrong code): the `CodeShareA`/`CodeShareB` exchange through `CPace` and then the `XXpsk3` messages, with fixed public inputs and scripted randomness (PROTOCOL §3.2, §4.2) |
| `proto_code_pairing` | `todoke_proto::pairing` bodies: `CodeOfferRequest`, `CodeOffer` (alone and as the echoing reply to a request), and `CodeShareA`/`CodeShareB` (PROTOCOL §3.2, §4.1) |
| `crypto_content_bao_slice` | Strict Bao 0.13.1 slice verification (the receiver's parser for decrypted content): fuzzer bytes as the slice of a chosen segment of a known file of up to five and a half segments; an accepted slice must yield exactly that segment's bytes (PROTOCOL §7.4) |
| `crypto_content_segment` | `ContentOpener::open_segment`: ciphertext length, AEAD authentication (either suite), then Bao verification, for a chosen segment of a known file; only the honest ciphertext may open (PROTOCOL §7.4, §8) |
| `crypto_content_file_key` | `FileKeyBody::decode`: exactly 86 bytes, nonzero transfer and file IDs, suite 1 or 2; accepted bodies re-encode to the input (PROTOCOL §8) |

The `crypto_*` targets call `todoke_crypto::identity::fuzzing`,
`todoke_crypto::pairing::fuzzing`, `todoke_crypto::session::fuzzing`, or
`todoke_crypto::content::fuzzing`, which exist only under `--cfg fuzzing` (set
by cargo-fuzz). The content harnesses stand in for a verified Accept
through a fuzzing-only constructor; they use fixed public keys and files. Each of their functions wraps the same decoder or state machine
that production code uses. Under `--cfg fuzzing` the session engine may use
scripted (fixture) randomness, as in unit tests; release builds cannot. The
session harnesses need the suite 0x0001 acknowledgement and the code-pairing
harness needs `CPace`, so `fuzz/Cargo.toml` enables `todoke-crypto`'s
`unaudited-code-pairing` feature (which implies `unaudited-suite-0001`);
shipped graphs never do (`scripts/ci/deny-exceptions-dev-only.sh` checks this).

Committed seeds live in `fuzz/seeds/<target>/`: small valid and malformed
inputs built from public RFC 8032 test keys and fixed bytes. `fuzz/corpus/` is
generated and ignored by git. `scripts/ci/fuzz-smoke.sh` passes both
directories, with the generated corpus first, so libFuzzer writes new inputs
there and only reads the seeds.

The harness graph uses the root `deny.toml`. It contains todoke-crypto's
runtime libcrux dependencies, so the root advisory ignore still matches. Since
2026-10-12 every duplicate skip also matches the harness graph; a future skip
that only the root graph needs would be reported as an unmatched warning, which
that CI step does not deny. `libfuzzer-sys` has an NCSA license exception because it bundles
LLVM libFuzzer, and it is never shipped. `fuzz/supply-chain` was initialized with
`cargo vet init`. Like the root store, it imports trusted organisations' audits
and exempts every other package at its exact version with a "Not yet reviewed"
note (see supply-chain/README.md, "cargo-vet adoption").

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
   `fuzz/supply-chain`; never record an audit not performed. New versions need
   an audit, an import, or a new exemption with a reason. (`cargo vet` store
   commands such as `init`, `import` and `regenerate` reject `--manifest-path`;
   run them from inside `fuzz/`.)
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
