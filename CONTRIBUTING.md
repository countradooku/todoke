# Contributing to todoke

todoke prioritizes broad adoption, usability, interoperability, and security. Keep contributions small enough to review thoroughly. Include relevant tests and documentation in the same pull request as a behavior change.

## Before changing behavior

Read [docs/DESIGN.md](docs/DESIGN.md) and [spec/PROTOCOL.md](spec/PROTOCOL.md). If the code and specification disagree, stop the behavior change and report the discrepancy. Do not silently resolve the disagreement in code. Resolve any relevant open protocol decision in the specification before implementing it.

The runtime workspace contains documented crate boundaries. Offline vector examples provide fixed public encodings and complete Noise-layer reference exchanges, using existing library state machines and primitives. They are not production parsers, protocol state machines, or complete todoke session implementations.

## Required boundaries

- Rust owns all protocol, cryptographic, and file logic. SwiftUI, Jetpack Compose, and GPUI clients remain thin. Mobile and web bindings use BoltFFI once its target support is verified.
- The core enforces authenticated sessions and consent. UI state, discovery results, relay claims, and transport connections are not authority to accept a file.
- Never implement cryptographic primitives. Use libcrux where it covers the requirement; otherwise use appropriate RustCrypto or dalek crates after checking official documentation.
- Zeroize all secrets. Do not include secrets in logs or send them across FFI. Do not add telemetry.
- Do not panic on untrusted input. Validate lengths, bounds, resource limits, and state transitions at their boundaries.
- Standard crates inherit the workspace lint policy and declare `#![forbid(unsafe_code)]`. Only `todoke-ffi` and `todoke-sys-*` may eventually contain narrowly scoped, reviewed unsafe code.

The FFI/platform crates currently contain no unsafe code. Their local lint tables match the workspace policy except that `unsafe_code` is `deny`, allowing a future reviewed exception on the smallest necessary item. Cargo cannot combine an inherited workspace lint table with a per-crate override, so keep these explicit tables synchronized. A future unsafe block must document its safety contract and have appropriate tests.

When a platform API, crate version, or binding capability is uncertain, say so and check its official documentation. Record compatibility constraints rather than guessing.

## Tests and verification

Every parser must have a cargo-fuzz target, added in the same pull request. Every state machine must have proptest state-machine tests covering its invariants and relevant invalid transitions. The empty scaffold has no parsers or state machines, so neither requirement is satisfied by a dummy target or a test with no behavior under test.

Run the required checks before submitting:

```sh
cargo fmt
cargo clippy --all-targets -- -D warnings -W clippy::pedantic
cargo test
cargo deny check
cargo vet
```

CI also checks Linux, macOS, Windows, the MSRV, cross-compilation, fuzz smoke runs, and a nightly scheduled mutation run. Keep the lockfile in version control. Update dependency policy and cargo-vet evidence with dependency changes; a blanket exemption is not a review.

Rust 1.99.0 is pinned in `rust-toolchain.toml`; Rust 1.85.0 is the MSRV. Install the versions of additional tools declared by CI. To check the MSRV locally after installing that toolchain:

```sh
cargo +1.85.0 check --workspace --all-targets --locked
```

Cross-target checking requires the Rust target component and an appropriate host toolchain. iOS checks run on macOS. A successful check of an empty library is not proof that a future transport or UI supports that platform.

## Pull requests

Explain the problem, resulting behavior, verification, and material limitations. Identify changes to the protocol or trust boundary. Keep commits small and reviewable; include tests and documentation with the code they describe. End the contribution summary with what was built, what was not built, open questions, and how to verify it.

Contributions are licensed under Apache-2.0 OR MIT, matching this repository. Do not add third-party code without preserving its license and attribution requirements.
