# todoke

todoke aims to be the best free, open-source, cross-platform file transfer app: phones and PCs, any to any, with end-to-end security. Adoption takes priority over revenue.

**Status: runtime scaffold with a normative protocol draft and deterministic reference vectors.** The workspace compiles, but no transfer protocol, cryptography, transport, app, daemon, relay, or command-line interface is implemented. The requirements below describe the intended system, not security guarantees of a working product.

## Security model — five lines

1. Every session must authenticate with Noise IKpsk2 / KKpsk2 / XXpsk3, hybrid X25519 + ML-KEM-768, and a pairing PSK ratcheted per session.
2. BLE, Wi-Fi P2P, AWDL, USB, LAN, and QUIC relay are untrusted pipes; transport access never establishes identity or consent.
3. Each file must use AES-256-GCM STREAM encryption (XChaCha20-Poly1305 fallback) and BLAKE3/bao verified chunks.
4. The Rust core must enforce consent: no file byte is accepted before a signed AcceH.
5. Use libcrux where it covers, otherwise RustCrypto/dalek; zeroize secrets, expose none through logs or FFI, forbid unsafe outside FFI/platform crates, reject hostile input without panics, and collect no telemetry.

The unresolved protocol details are recorded in [spec/PROTOCOL.md](spec/PROTOCOL.md). Read it and [docs/DESIGN.md](docs/DESIGN.md) before changing behavior. If specification and code disagree, stop and report the disagreement.

## Build and check

Install [Rust through rustup](https://www.rust-lang.org/tools/install). The repository pins Rust 1.99.0 and declares Rust 1.94.0 as its minimum supported version (MSRV). All crates use edition 2024.

```sh
cargo build --workspace --locked
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings -W clippy::pedantic
cargo test --workspace --locked
```

Install the policy tools once, then run the dependency checks:

```sh
cargo install --locked cargo-deny --version 0.20.2
cargo install --locked cargo-vet --version 0.10.2
cargo deny check
cargo vet
```

The runtime crates have no implemented application behavior. The offline protocol-vector example uses pinned reference development dependencies; see [its instructions](spec/test-vectors/README.md) and [dependency review status](supply-chain/README.md). Passing these checks verifies the scaffold, not the intended security properties. Native and cross-target checks are configured in [GitHub Actions](.github/workflows/); results require running the workflows on a hosted repository.

## Layout

| Path | Purpose |
| --- | --- |
| `crates/` | Sixteen Rust crate boundaries; see the [responsibility map](docs/DESIGN.md#crate-responsibilities-and-trust-boundaries). |
| `apps/android/`, `apps/ios/` | Reserved for thin Jetpack Compose and SwiftUI clients using BoltFFI. |
| `web/` | Reserved for web bindings through BoltFFI, subject to verified support. |
| `spec/`, `docs/`, `formal/` | Protocol requirements, architecture, and future formal models. |
| `fuzz/`, `bench/` | Fuzzing infrastructure and future performance measurements. |

Desktop presentation belongs in `todoke-desktop` using GPUI. Rust owns all protocol, cryptographic, and file logic across every client. Native UI frameworks and BoltFFI are not dependencies of this initial scaffold.

See [CONTRIBUTING.md](CONTRIBUTING.md) for development rules and [SECURITY.md](SECURITY.md) for private vulnerability reporting and the disclosure policy.

Licensed under [Apache-2.0](LICENSE-APACHE) OR [MIT](LICENSE-MIT), at your option.
