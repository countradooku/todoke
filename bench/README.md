# Benchmarks

Reproducible measurements live in the `todoke-bench` crate (`bench/`), an
isolated cargo workspace like `fuzz/`. Its library is empty; each benchmark
is a [criterion](https://docs.rs/criterion/0.8.2/) target in
`bench/benches/`. On wasm32 the benchmark is an empty program.

The benchmarks need the content consent bypass
(`todoke-crypto/insecure-content-without-accept`). Cargo unifies a
dev-dependency's features across every package of a workspace build
(`cargo test --workspace`, `--all-targets`), so as a root workspace member
`bench/` would compile every shipped crate's tests against the bypass. It
is therefore its own workspace, excluded from the root one, and
`scripts/ci/deny-exceptions-dev-only.sh` fails if any root graph, dev
edges included, enables the feature.

## Workspace and dependency checks

- `bench/Cargo.toml` has its own `[workspace]`, repeats the root lints, and
  uses a versioned path dependency on `todoke-crypto` with the bypass
  feature. Every dependency is a development dependency.
- `bench/Cargo.lock` is committed and was seeded from the root `Cargo.lock`,
  so both graphs use the same versions; keep it in step when the root lock
  changes.
- `bench/supply-chain` is its own cargo-vet store, created with
  `cargo vet init` inside `bench/`, importing the same six audit sets as the
  root store, with exact-version "Not yet reviewed" exemptions for the rest
  (see `supply-chain/README.md`). Store commands such as `init`, `import`,
  and `regenerate` reject `--manifest-path`; run them from inside `bench/`.
- From the repository root (CI runs these too):

  ```sh
  cargo fmt --all --manifest-path bench/Cargo.toml -- --check
  cargo clippy --manifest-path bench/Cargo.toml --all-targets --locked -- -D warnings -W clippy::pedantic
  cargo deny --manifest-path bench/Cargo.toml --locked --config deny.toml check
  cargo vet --manifest-path bench/Cargo.toml --locked
  cargo bench --manifest-path bench/Cargo.toml --locked --no-run
  cargo test --manifest-path bench/Cargo.toml --locked --benches  # each benchmark once
  ```

  cargo-deny's license check skips development dependencies, so it checks
  no licenses in this graph (all of them are development dependencies).

Record the revision, hardware, OS, Rust version, workload, and procedure
with every result. Use synthetic data only; never collect telemetry or
personal file contents. Use release builds (`cargo bench` does) and report
uncertainty and limitations alongside results.

## Content layer (`benches/content.rs`)

PROTOCOL §7.4 and §8, per content suite on a full 16384-byte segment (a
middle segment of an eight-segment file, so its slice carries a typical
proof):

- `content-segment/seal/<suite>`: extract the Bao slice from the source and
  its outboard, verify it against the manifest root (source-mutation check),
  derive the epoch key, and encrypt.
- `content-segment/open/<suite>`: derive the epoch key, authenticate and
  decrypt, then strictly verify the Bao slice.
- `content-outboard/outboard-1MiB`: BLAKE3 root and Bao outboard of 1 MiB,
  the sender's one-time cost per file.

Throughput counts logical file bytes. A suite this device does not advertise
(AES without hardware AES) is skipped with a message.

Run (short, as used for the numbers below; keep parallelism modest):

```sh
CARGO_BUILD_JOBS=4 cargo bench --manifest-path bench/Cargo.toml --locked --bench content -- \
  --warm-up-time 1 --measurement-time 3
```

### Results

**aarch64 (measured 2026-10-13).** Apple M5 Pro, 48 GB, macOS 27.0.1;
rustc 1.99.0; revision `9cf0b5c` plus the `feat/content-layer` changes;
the command above, with no other heavy work running. Ranges are criterion's
95% confidence intervals:

| Benchmark | Time per segment | Throughput |
| --- | --- | --- |
| seal, AES-256-GCM | 30.6–31.5 µs | 496–511 MiB/s |
| open, AES-256-GCM | 33.2–33.5 µs | 466–471 MiB/s |
| seal, XChaCha20-Poly1305 | 46.6–47.6 µs | 328–335 MiB/s |
| open, XChaCha20-Poly1305 | 49.5–51.2 µs | 305–315 MiB/s |
| outboard, 1 MiB | 884–904 µs | 1.08–1.10 GiB/s |

Bao hashing dominates: the `bao` crate hashes one 1024-byte chunk at a time
(about 1.1 GiB/s here), and both seal and open hash the whole slice once.
These are single-thread numbers for one segment; a transfer may seal or
open several segments in parallel.

**x86_64: not measured.** This machine cannot run x86_64 benchmarks
natively, and emulated numbers would be meaningless. Run the command above
on an x86_64 machine with AVX2 and AES-NI (for example a CI runner or a
developer PC) and add the results here with the same details. Without those
CPU features AES is not advertised and is skipped.

## Future measurements

The eventual suite should also measure connection and consent latency,
memory use, and CPU/energy costs across representative device pairs, file
sizes, transports, and failure conditions, without weakening correctness or
security checks.
