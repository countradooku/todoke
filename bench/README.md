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

Results: [RESULTS.md](RESULTS.md#content-layer).

## LAN (`benches/lan.rs`)

PROTOCOL §5 on a TCP link from `todoke-transport`: raw TCP, then an
authenticated suite 0x0001 session (QR pairing, then data frames of the
largest body, 65515 bytes, with transport encryption and the automatic
rekey every GiB). The receiver acknowledges every 4 MiB and the sender
stays at most 16 MiB ahead, as the transfer engine's pipelined requests
would keep it, so both ends read and write throughout and keepalives work
at any speed. Each size is sent once per phase; the clock stops when the
receiver confirms the last byte. `cargo test --benches` (CI) sends 1 MiB
instead. No manifest, consent, content
encryption, or disk I/O: this is the transport and session ceiling.

The sessions need `todoke-crypto/unaudited-suite-0001` (PROTOCOL §16 keeps
the suite out of production), which, like the content bypass, is enabled
only in this isolated workspace.

On one machine (both ends over loopback, each on its own thread):

```sh
CARGO_BUILD_JOBS=4 cargo bench --manifest-path bench/Cargo.toml --locked --bench lan
```

On two machines on the same network (the receiver first; the sender then
pairs with the receiver's in-band QR offer, throwaway identities, in the
clear, which is acceptable only for a benchmark):

```sh
cargo bench --manifest-path bench/Cargo.toml --locked --bench lan -- --listen 47100
cargo bench --manifest-path bench/Cargo.toml --locked --bench lan -- --connect 192.168.1.20:47100
```

`--bytes 1G --bytes 10G` (the default) chooses the sizes. The receiver's
address must be private or link-local (the LAN policy), and its firewall
must allow the port.

Results: [RESULTS.md](RESULTS.md#lan).

## Discovery matching (`benches/discovery.rs`)

PROTOCOL §9, on the receiving device, with 1,000 contacts (the store holds
1,024; P15's target is 1,000), each with a random pair PSK:

- `discovery/1000-contacts/table-build`: the discovery table (each
  contact's tokens and locators for the previous, current, and next
  epochs, and its rendezvous token), built at every 15-minute epoch and
  after every committed session.
- `discovery/1000-contacts/match-contact`: one contact's record against
  the table.
- `discovery/1000-contacts/match-unknown`: a record with a random token,
  which matches nobody (most of a busy network).
- `discovery/1000-contacts/observe-sighting`: a whole sighting as mDNS
  delivers it: the TXT string and address checks, the match, and storing
  it in the directory.

The tables come from `DiscoveryTable::from_pair_psks`, which only
todoke-crypto's `bench-support` feature exposes (the guard keeps it out of
every shipped graph).

Run:

```sh
CARGO_BUILD_JOBS=4 cargo bench --manifest-path bench/Cargo.toml --locked --bench discovery
```

Results: [RESULTS.md](RESULTS.md#discovery-matching).

## Future measurements

The eventual suite should also measure connection and consent latency,
memory use, and CPU/energy costs across representative device pairs, file
sizes, transports, and failure conditions, without weakening correctness or
security checks.
