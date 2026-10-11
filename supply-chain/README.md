# Dependency review

This store was initialized with `cargo-vet 0.10.2` against the scaffold's empty
third-party dependency graph. The protocol-vector examples now introduce pinned
reference development dependencies. `audits.toml` and `imports.lock` remain empty;
`config.toml` contains no exemptions or trusted publishers. These new dependencies
have not received cargo-vet audits. Running reference vectors does not certify
todoke's security or approve these crates for production secrets.

Run the same tool versions as CI:

```sh
cargo install --locked cargo-deny --version 0.20.2
cargo install --locked cargo-vet --version 0.10.2
cargo deny --locked check -D unmatched-skip
bash scripts/ci/deny-exceptions-dev-only.sh
cargo vet --locked
```

`deny.toml` checks advisories, licenses, duplicate versions, wildcard requirements,
and sources across all resolved platforms and features, including development
dependencies. Only crates.io sources and Apache-2.0 or MIT licenses are initially
allowed. Any new source, license, or exception requires a documented reason in
the dependency change; never silence the policy broadly to get a passing build.

Add dependency reviews and any supporting, explicitly trusted imported audits in
the same pull request as a dependency change. Record only reviews actually
performed. If an exemption is necessary, scope it to the exact package version,
explain the reason, and track the outstanding review. Do not re-run `cargo vet
init` to blanket-exempt new dependencies. Commit the root `Cargo.lock` and all
generated store files, including `imports.lock`.

When an isolated fuzz workspace is introduced, its dependency graph and lockfile
must receive the same checks and their own audit store; see
[`fuzz/README.md`](../fuzz/README.md).

References: [cargo-deny configuration](https://embarkstudios.github.io/cargo-deny/checks/cfg.html),
[cargo-vet setup](https://mozilla.github.io/cargo-vet/setup.html), and
[cargo-vet CI](https://mozilla.github.io/cargo-vet/configuring-ci.html).

## Protocol-vector dependency check status

On 2026-10-11, the locked vector-tool graph passed cargo-deny's license and
source checks but not its advisory or duplicate-version policies:

- [RUSTSEC-2026-0173](https://rustsec.org/advisories/RUSTSEC-2026-0173.html):
  unmaintained `proc-macro-error2 2.0.1`, with no patched version. The path includes
  `libcrux-intrinsics 0.0.9` → `core-models 0.0.7` → `hax-lib 0.3.7` →
  `hax-lib-macros`. The `cfg(hax)` dependency is still part of the all-target audit
  graph even though the fixture executable does not enable that verification mode.
- Conflicting versions of `hax-lib`, `hax-lib-macros`, `hax-lib-macros-types`
  (0.3.7 / 0.4.2), `syn` (2.0.119 / 3.0.7), `shlex` (1.3.0 / 2.0.1),
  `getrandom` (0.2.17 / 0.4.3), and `rand_core` (0.6.4 / 0.10.1).
- `cargo vet --locked` reports 115 dependencies missing `safe-to-run` evidence.
  The handshake fixture tool adds six packages to the previous 109-package graph:
  `snow 0.9.6`, `rand_core 0.6.4`, `getrandom 0.2.17`,
  `wasi 0.11.1+wasi-snapshot-preview1`, `libcrux-chacha20poly1305 0.0.10`, and
  `libcrux-poly1305 0.0.7`. `libcrux-sha2 0.0.9` was already transitive and is now
  also a direct development dependency.

Current upstream features/releases were inspected; disabling ML-KEM default/SIMD
features does not remove the older verification graph.

The maintainer accepted narrow cargo-deny exceptions for these findings, also on
2026-10-11: one advisory ignore by ID and one skip per exact older duplicate
version, each with its reason in `deny.toml`. No version range, `skip-tree`,
wildcard, `multiple-versions-include-dev = false`, or `exclude-dev` was used, so
any new duplicate or advisory still fails. Because cargo-deny cannot scope an
exception by dependency kind, `scripts/ci/deny-exceptions-dev-only.sh` fails CI
if an exempted package becomes reachable through a normal or build dependency on
any target. CI passes `-D unmatched-skip`, and `unused-ignored-advisory = "deny"`
is already set, so each exception must be deleted once upstream no longer needs it.

No blanket vet exemption or dependency source patch was added: `cargo vet --locked`
still fails until actual audit evidence exists. The generator takes
only public fixed fixtures and is not a production secret-handling approval.

The [O1 decision](../spec/decisions/O1-HYBRID-NOISE.md) cites a real independent
review of an older Snow revision as evidence for the existing HFS+PSK construction.
That is not a cargo-vet audit of the current resolved packages, this adapter, or
the whole dependency graph. No audit-store entries or exemptions were fabricated.
Snow's raw Split export and the KEM resolver compatibility slot are confined to
the public-fixture example; production integration and zeroization remain open.

## Identity runtime dependency status

The identity work (PROTOCOL §1–§2) makes these pinned crates **runtime**
dependencies of `todoke-crypto`: `ed25519-dalek 3.0.0` and `curve25519-dalek 5.0.0`
(§1 strict verification and canonical point check), `libcrux-ed25519 0.0.10`
(signing), `libcrux-ml-kem 0.0.11` (FIPS 203 input check of the retained
`kem_static`), `libcrux-chacha20poly1305 0.0.10` (sealing local secret state),
`blake3 1.8.7`, `zeroize 1.9.1`, and `getrandom 0.4.3`, the last with `wasm_js`
on `wasm32-unknown-unknown` only. Pins shared with `todoke-proto` moved to
`[workspace.dependencies]`, as cargo-deny's `workspace-duplicate` rule requires.
`proptest 1.11.0` is a new development dependency of both crates. 1.12 would
avoid duplicate rand versions, but it requires Rust 1.88, above the 1.85 MSRV.

The maintainer approved re-scoping the dev-only guard on 2026-10-11. The policy
changes are:

- `scripts/ci/deny-exceptions-dev-only.sh` resolves the graph per supported
  target triple instead of `--target all`. hax-lib 0.3.7, core-models,
  proc-macro-error2, crabgrind, bindgen, and shlex 1.3.0 reach runtime libcrux
  crates only through `cfg(hax)` / `cfg(valgrind_ct_test)` edges, which no todoke
  build sets. They still fail the guard if any real target compiles them.
- `syn 2.0.119` has an explicit build-time-only allowance. It is compiled for
  `curve25519-dalek-derive`, the proc macro of dalek's x86_64 SIMD backend. The
  guard fails if it is linked into any target artifact.
- Exact-version license exceptions: BSD-3-Clause for `ed25519-dalek`,
  `curve25519-dalek`, and `subtle`; Unicode-3.0 for `unicode-ident` (build
  time); BSD-3-Clause / ISC for never-compiled `bindgen` / `libloading`; NCSA for
  the fuzz-only `libfuzzer-sys`. cargo-deny's license check ignores
  dev-dependencies, so dalek's license was not checked while it was dev-only.
- New dev-only duplicate skips for proptest's `rand 0.9.5`, `rand_core 0.9.5`,
  `getrandom 0.3.4`, and `r-efi 5.3.0`.

The fuzz workspace (`fuzz/`) uses the root `deny.toml`. Its graph includes the
runtime libcrux crates, so the advisory ignore stays matched and no separate
policy file is needed. Its lock was seeded from the root lock and adds only
`libfuzzer-sys 0.4.13`, `arbitrary 1.5.0`, and `jobserver 0.1.35`.

On 2026-10-11, `cargo deny --locked check -D unmatched-skip`, the guard script,
and the fuzz-workspace deny check passed. `cargo vet --locked` reports 128
unvetted packages at the root, now including `safe-to-deploy` requirements for
the runtime crates above, and fails in the same way for `fuzz/`. No audits or
exemptions were recorded. Reference-fixture use and passing tests are not a
review of these crates for production secrets (O6).
