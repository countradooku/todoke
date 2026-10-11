# Parser fuzzing

The scaffold contains no parsers and therefore no fuzz targets. CI reports this
explicitly. A successful scaffold build is not evidence that a protocol parser
has been fuzzed.

Every parser must gain a `cargo-fuzz` target in the same pull request that adds
the parser, including protocol framing, discovery, manifests, archive metadata,
and platform input. Use the real public parser entry point, arbitrary bytes,
deterministic execution, bounded resource use, and no real filesystem or network
side effects. Expected parse failures are normal results; crashes and panics are
failures. Add small valid and malformed seed inputs without personal data or
secrets. Each state machine also needs independent `proptest` state-machine
tests in its owning crate; fuzzing does not replace them.

When adding the first parser:

1. Read `docs/DESIGN.md` and `spec/PROTOCOL.md` before changing behavior. Stop
   and report any mismatch between implementation and specification.
2. Initialize the cargo-fuzz project in this directory, replacing its generated
   sample target with a target for the actual parser. Keep `fuzz/Cargo.toml` as
   an isolated workspace (its own `[workspace]`), excluded from the root
   workspace. Set `package.metadata.cargo-fuzz = true` and declare every target
   as a `[[bin]]` with `test = false`, `doc = false`, and `bench = false`.
3. Pin and review the harness dependencies, commit `fuzz/Cargo.lock`, and use
   versioned path dependencies for the todoke crates under test. Initialize
   `fuzz/supply-chain` with `cargo vet --manifest-path fuzz/Cargo.toml init`, then
   review its generated exemptions. Replace them with real audits or justified,
   narrowly scoped, reviewed exemptions; never record an audit not performed.
4. Run both dependency checks from the repository root:

   ```sh
   cargo deny --manifest-path fuzz/Cargo.toml --locked --config deny.toml check
   cargo vet --manifest-path fuzz/Cargo.toml --locked
   ```

5. Run the target on the same pinned nightly and cargo-fuzz version as
   `.github/workflows/ci.yml`. CI discovers and runs each registered target for
   60 seconds with AddressSanitizer enabled. For a local smoke run:

   ```sh
   cargo +nightly-2026-08-20 fuzz run PARSER_TARGET -- -max_total_time=60
   ```

Keep longer fuzz campaigns separate from the smoke check. Minimize failures,
add a regression test, and preserve sanitized reproductions. Do not add dummy
targets to make CI appear to cover a parser that has not been implemented.

See the [Rust Fuzz Book](https://rust-fuzz.github.io/book/cargo-fuzz.html) for
harness, corpus, minimization, and reproduction commands.
