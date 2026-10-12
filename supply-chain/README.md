# Dependency review

This store was initialized with `cargo-vet 0.10.2` against the scaffold's empty
third-party dependency graph. Since 2026-10-13 it imports the published audits
of six organisations and records an exact-version exemption, labelled "Not yet
reviewed", for every other package (see "cargo-vet adoption" below). Exemptions
are not reviews: `cargo vet` passing does not certify todoke's security or
approve any crate for production secrets.

Run the same tool versions as CI:

```sh
cargo install --locked cargo-deny --version 0.20.2
cargo install --locked cargo-vet --version 0.10.2
cargo deny --locked check -D unmatched-skip
bash scripts/ci/deny-exceptions-dev-only.sh
bash scripts/ci/deny-exceptions-dev-only.test.sh
cargo vet --locked
```

`deny.toml` checks advisories, licenses, duplicate versions, wildcard requirements,
and sources across all resolved platforms and features, including development
dependencies. Only crates.io sources and Apache-2.0 or MIT licenses are initially
allowed. Any new source, license, or exception requires a documented reason in
the dependency change; never silence the policy broadly to get a passing build.

Add dependency reviews and any supporting, explicitly trusted imported audits in
the same pull request as a dependency change. Record only reviews actually
performed. Every new package or version needs an audit, an imported audit, or a
new exact-version exemption with a reason, added in the same pull request, so it
is visible in review. The one-time exemption of the existing graph at adoption
(2026-10-13) does not extend to later additions. Commit the root `Cargo.lock`
and all generated store files, including `imports.lock`.

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
dependencies of `todoke-crypto`: `ed25519-dalek 3.0.0` (signing, and §1 strict
verification) and `curve25519-dalek 5.0.0` (canonical point check),
`libcrux-ml-kem 0.0.11` (FIPS 203 input check of the retained
`kem_static`), `libcrux-chacha20poly1305 0.0.10` (sealing local secret state),
`blake3 1.8.7`, `zeroize 1.9.1`, and `getrandom 0.4.3`, the last with `wasm_js`
on `wasm32-unknown-unknown` only. Pins shared with `todoke-proto` moved to
`[workspace.dependencies]`, as cargo-deny's `workspace-duplicate` rule requires.
`proptest 1.11.0` is a new development dependency of both crates. 1.12 would
avoid duplicate rand versions, but it requires Rust 1.88, above the 1.85 MSRV.

Signing uses ed25519-dalek, not `libcrux-ed25519 0.0.10`: the libcrux (HACL\*)
signer expands the seed into a 96-byte stack array that it never wipes, while
dalek's `SigningKey` and `ExpandedSecretKey` are `ZeroizeOnDrop` with its default
`zeroize` feature (§14.2). dalek 3.0.0 still leaves some scratch unwiped (the
SHA-512 output it expands the seed from, hasher states, and the nonce scalar),
so library zeroization review remains open (O6). `libcrux-ed25519` is now only a
development dependency of `todoke-crypto` (an independent reference in signing
tests) and of `todoke-proto` (vector tools).

`noise_static` is checked against libsodium's list of small-order X25519
encodings, so no runtime X25519 dependency is needed. `libcrux-curve25519 0.0.9`
moved to `[workspace.dependencies]` because it is now a development dependency
of both crates; `todoke-crypto`'s tests use it to check that list against
X25519 output.

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
  `curve25519-dalek`, and `subtle`; Unicode-3.0 for `unicode-ident`;
  BSD-3-Clause / ISC for never-compiled `bindgen` / `libloading`; NCSA for
  the fuzz-only `libfuzzer-sys`. cargo-deny's license check ignores
  dev-dependencies, so dalek's license was not checked while it was dev-only.
- The guard also reads the comment above each license exception: entries
  marked "Never compiled" fail if any target compiles them, dev-dependencies
  included, and entries marked "Build-time only" fail if linked into any
  target. It also fails if a target in the CI cross job is missing from its
  target list. `scripts/ci/deny-exceptions-dev-only.test.sh` checks these rules
  against mutated copies of `deny.toml` and the CI workflow.
- `unicode-ident` was originally recorded as build-time only. The extended
  guard showed that `getrandom`'s `wasm_js` backend links it into
  `wasm32-unknown-unknown` artifacts (`wasm-bindgen` → `wasm-bindgen-shared`),
  so its `deny.toml` reason now says so. The exception itself is unchanged.
- On 2026-10-11 the maintainer approved every license exception above,
  including `unicode-ident` in wasm artifacts. Binary distributions must retain
  the BSD-3-Clause, ISC, and Unicode-3.0 notices of the crates they include.
- New dev-only duplicate skips for proptest's `rand 0.9.5`, `rand_core 0.9.5`,
  `getrandom 0.3.4`, and `r-efi 5.3.0`.

The fuzz workspace (`fuzz/`) uses the root `deny.toml`. Its graph includes the
runtime libcrux crates, so the advisory ignore stays matched and no separate
policy file is needed. Its lock was seeded from the root lock and adds only
`libfuzzer-sys 0.4.13`, `arbitrary 1.5.0`, and `jobserver 0.1.35`. Moving
`libcrux-ed25519` to a development dependency removed it and `libcrux-sha2` from
the fuzz lock.

On 2026-10-11, `cargo deny --locked check -D unmatched-skip`, the guard script,
and the fuzz-workspace deny check passed. `cargo vet --locked` reports 128
unvetted packages at the root, now including `safe-to-deploy` requirements for
the runtime crates above, and fails in the same way for `fuzz/`. No audits or
exemptions were recorded. Reference-fixture use and passing tests are not a
review of these crates for production secrets (O6).

## Session runtime dependency status

The session work (PROTOCOL §4–§5, [ADR 0001](../docs/adr/0001-noise-crate.md))
adds these packages to `todoke-crypto`'s **runtime** graph, each pinned to an
exact version published more than two weeks before 2026-10-11:

| Package | Why | Notes |
| --- | --- | --- |
| `snow 0.10.0` (2025-07-19) | Reviewed HFS+PSK Noise state machine (O1) | `default-features = false`, `hfs` only: no Snow crypto, no RNG, no raw split. Its only other dependencies are `subtle` and, at build time, `rustc_version`/`semver`, all already present. Apache-2.0 OR MIT. |
| `futures-io 0.3.34` (2026-08-11) | `AsyncRead`/`AsyncWrite` traits for the session adapter | Trait definitions only, no dependencies. MIT OR Apache-2.0. |
| `libcrux-curve25519 0.0.9` | X25519 for Noise | Previously a development dependency only. |
| `libcrux-sha2 0.0.9` | SHA-256 for Noise | Previously development/transitive only. |
| `libcrux-hkdf 0.0.9`, `libcrux-hmac 0.0.9` | §4.4 ratchet HKDF and confirmation HMAC | Previously development only. |

`libcrux-secrets 0.0.7` and `subtle 2.6.1` were already transitive runtime
dependencies and are now direct pins. Pins shared with `todoke-proto`
(`libcrux-hkdf`, `libcrux-sha2`, `libcrux-secrets`) moved to
`[workspace.dependencies]`. No new license, source, or advisory exception was
needed.

At the time, `todoke-proto`'s offline handshake fixture generator still pinned
`snow 0.9.6`, so `deny.toml` gained a dev-only `snow@0.9.6` skip pending
maintainer sign-off. On 2026-10-12 the generator moved to 0.10.0 instead (see
"Latest-version upgrade" below), which removed that skip together with the
`rand_core 0.6.4` and `getrandom 0.2.17` skips.

Test data added with provenance recorded inside each file:
`crates/todoke-crypto/testdata/acvp-mlkem768.json` (NIST ACVP-Server ML-KEM
vectors, ML-KEM-768 groups) and `noise-classical-cacophony.json` (three
Cacophony vectors from Snow's test suite). They are test inputs, not code.

On 2026-10-11, `cargo deny --locked check -D unmatched-skip`, the guard
script and its tests, and the fuzz-workspace deny check passed. `cargo vet
--locked` reports 130 unvetted packages at the root and 110 in `fuzz/`; no
audits or exemptions were recorded. The fuzz lock was updated from the root
lock and adds no package the root lock lacks.

Two pre-existing CI failures were observed and not changed here: the MSRV job
(`cargo check --workspace --all-targets` on 1.85) fails in the `base45 3.2.0`
development dependency, which uses `slice::as_chunks` (stable since 1.88), and
`--all-targets` on `wasm32-unknown-unknown` fails in the development-only
`getrandom 0.2`/`0.3` copies. Both reproduce on the base commit. The library
targets and every `todoke-crypto` target pass on 1.85 and wasm32.

## Latest-version upgrade (2026-10-12)

The maintainer asked to keep every crate at its latest stable release, with no
release-age cooling-off period, preferring upgrades over duplicate-version
exceptions for old versions and raising the MSRV where needed.

- `proptest` 1.11.0 → 1.12.0 (published 2026-10-10). It moves to `rand 0.10`,
  the version libcrux already uses, which removed the dev-only `rand@0.9.5`,
  `rand_core@0.9.5`, `getrandom@0.3.4`, and `r-efi@5.3.0` skips (and
  `rand_chacha`, `ppv-lite86`, `zerocopy`, `wasip2`, and `wit-bindgen` left the
  lock). proptest 1.12 declares `rust-version = 1.88`.
- MSRV 1.85 → 1.88. `base45 3.2.0` (already the latest release) uses
  `slice::as_chunks`, stable since 1.88, without declaring a `rust-version`, so
  the 1.85 MSRV job already failed; proptest 1.12 now also requires 1.88. The
  CI `msrv` job, `CONTRIBUTING.md`, and `README.md` were updated.
- `snow` 0.9.6 → 0.10.0 in `todoke-proto`'s handshake fixture generator, the
  release `todoke-crypto` already used; `snow` is now a workspace dependency.
  The generator's RNG adapter implements Snow's own `Random` trait, so
  `rand_core 0.6.4` is no longer a dependency. Regenerated fixtures differ only
  in their `provenance` fields. Removed skips: `snow@0.9.6`,
  `rand_core@0.6.4`, and `getrandom@0.2.17`; `wasi 0.11.1` also left the lock.
- `serde_json` 1.0.152 → 1.0.154 (published 2026-10-11; development only).
- Transitive refresh with `cargo update`: `cc` 1.7.0 → 1.8.0, `ctutils`
  0.4.2 → 0.4.3, `syn` 3.0.7 → 3.0.9, `unicode-ident` 1.0.26 → 1.0.27 (its
  exact-version Unicode-3.0 license exception moved with it; same license
  expression), and `uuid` 1.26.1 → 1.28.0.
- MSRV 1.88 → 1.89. `uuid` 1.27 and later declare `rust-version = 1.89`.
  `uuid` is reached only through libcrux's never-compiled `cfg(hax)` edge
  (`hax-lib-macros-types`), so no real build compiles it, but Cargo's
  MSRV-aware resolver holds it at 1.26.1 for any lower MSRV. Raising the MSRV
  keeps every crate in the lock at its latest release.

Every other direct dependency was already at its latest release. Several
releases are less than 14 days old (no cooling-off period was applied):
`proptest 1.12.0` (2026-10-10), `serde_json 1.0.154` (2026-10-11), `uuid
1.28.0` (2026-10-10), `cc 1.8.0` (2026-10-11), `ctutils 0.4.3` (2026-10-05),
`syn 3.0.9` and `unicode-ident 1.0.27` (2026-10-12), and the already-pinned
`libcrux-*` releases (2026-10-07) and `zeroize 1.9.1` (2026-10-06).
`ctutils 0.4.3` is a constant-time helper under the runtime `digest` crate; its
diff from 0.4.2 only replaces casts with `cast_signed`/`cast_unsigned`, makes
`to_bool`/`to_u8` `const`, and routes the deprecated `*_vartime` helpers
through the `black_box` versions.

No new advisory ignore, duplicate skip, or license exception was added. The
remaining skips are the never-compiled `cfg(hax)` / `cfg(valgrind_ct_test)`
duplicates and the build-time `syn 2.0.119`. Both pre-existing CI failures
noted above are resolved: the MSRV job now passes on 1.89.0, and
`cargo check --workspace --all-targets --locked --target wasm32-unknown-unknown`
passes on 1.99.0, because the development-only `getrandom 0.2`/`0.3` copies are
gone. The fuzz lock was re-seeded from the root lock and still adds only
`libfuzzer-sys`, `arbitrary`, and `jobserver`. On 2026-10-12, `cargo deny
--locked check -D unmatched-skip`, the guard script and its tests, the
fuzz-workspace deny check, both vector generators' `--check`, and a 30-second
run of every fuzz target passed. `cargo vet --locked` reports 117 unvetted
packages at the root and 110 in `fuzz/`; no audits or exemptions were recorded.

## Feature guard (2026-10-12)

`scripts/ci/deny-exceptions-dev-only.sh` also fails if, on any supported
target, the non-dev graph (`cargo tree -e no-dev --format '{p}|{f}'`) enables
`todoke-crypto`'s `unaudited-suite-0001` feature (the PROTOCOL §16 gate, see
[ADR 0001](../docs/adr/0001-noise-crate.md)) or Snow's `risky-raw-split`
feature (enabled only by the fixture generator's development dependency), or
if either package is missing from that graph. The fuzz workspace enables
`unaudited-suite-0001`; it is never shipped. No dependency changed.

## Independent layout-test dependencies (2026-10-12)

`todoke-crypto` gains two **development** dependencies for byte-layout tests
of the §4.3 `Identity` signature input and the §4.4 ratchet confirmation, so
that those tests recompute HMAC-SHA-256 with a different implementation from
the libcrux code under test:

| Package | Notes |
| --- | --- |
| `hmac 0.13.0` | Already a development dependency of `todoke-proto` (fixture generator); the pin moved to `[workspace.dependencies]` (cargo-deny `workspace-duplicate`). Latest release. |
| `sha2 0.11.0` | `default-features = false`. Already in the lock through `ed25519-dalek`; latest release. |

No package was added to the lock, and no exception was added.

## MSRV 1.94 (2026-10-13)

The first CI run of this branch showed that `libcrux-platform 0.0.4`, the
latest release, does not compile on x86_64 before Rust 1.94. It calls
`core::arch::x86_64::__cpuid` without `unsafe`, which older compilers reject
(E0133). The local MSRV check ran on Apple Silicon, which never compiles that
code. Checking `-p libcrux-platform --target x86_64-unknown-linux-gnu` with
each toolchain fails on 1.89 through 1.93 and passes on 1.94.0. The
workspace and fuzz `rust-version`, the CI `msrv` job, `README.md`,
`CONTRIBUTING.md`, and ADR 0001 now say 1.94.0. Local MSRV checks must cover
an x86_64 target as well as the host.

## cargo-vet adoption (2026-10-13)

The maintainer chose to make `cargo vet --locked` pass instead of leaving it
permanently failing. Both stores (`supply-chain/` and `fuzz/supply-chain/`)
now:

- **Import trusted audits** from the cargo-vet registry: Mozilla, Google,
  Bytecode Alliance, ISRG, Zcash, and Embark Studios. Their audits are real
  reviews by those organisations, pinned in `imports.lock`. They fully cover 21
  root packages (18 in `fuzz/`) and partly cover 5 more.
- **Exempt everything else** at its exact current version: 96 root entries and
  92 fuzz entries, generated with `cargo vet regenerate exemptions`. Each carries
  `notes = "Not yet reviewed. …"`. They include all libcrux crates, the dalek
  crates, and snow. No audit was recorded for work not performed.

This reverses the earlier rule against blanket exemptions, once, for the graph
as it stood at adoption. It follows cargo-vet's documented way of adopting
cargo-vet in an existing project. From now on, `cargo vet --locked` fails for
any new package or version until it is audited, covered by an import, or
exempted in a reviewed change. Because the project always moves to the latest
releases, each upgrade must update the stores (`cargo vet regenerate exemptions`
only for versions nobody has reviewed, keeping the notes). Replacing the
exemptions for runtime cryptography (libcrux, dalek, snow, blake3, zeroize)
with real audits remains part of production gate O6.

## Pairing dependencies (2026-10-13)

QR pairing (PROTOCOL §3.1) adds no runtime dependency: the Base45 codec is
a small fixed-purpose function in `todoke-crypto`. The `base45 3.2.0` pin
moved to `[workspace.dependencies]` because `todoke-crypto` now uses it as
a development dependency for the cross-check (it was already one of
`todoke-proto`).

Human-code pairing (§3.2) uses CPace from the `pakery` crates, selected in
[ADR 0002](../docs/adr/0002-cpace.md). They are **optional** dependencies of
`todoke-crypto`, compiled only with the non-default `unaudited-code-pairing`
feature (and in its unit tests through the development dependencies):

| Package | Why | Notes |
| --- | --- | --- |
| `pakery-cpace 0.6.0` (2026-09-22) | CPACE-RISTR255-SHA512, draft-irtf-cfrg-cpace-21 | MIT OR Apache-2.0, `forbid(unsafe_code)`. Latest release. Passes the draft's Appendix A and B.3 vectors through todoke's adapter. |
| `pakery-crypto 0.6.0` | Ristretto255 group and SHA-512 for that suite | `default-features = false`, `ristretto255` only. Uses the `curve25519-dalek 5.0.0` and `sha2 0.11.0` already in the graph. |
| `pakery-core 0.6.0` | Encoding helpers and traits used by both | Its `__ctgrind` feature (Valgrind) is never enabled. |
| `hkdf 0.13.0`, `const-oid 0.10.2`, `zeroize_derive 1.5.0` | Transitive: `pakery-crypto`'s `ristretto255` feature, and `pakery-core`'s `Zeroize` derive | Latest releases. `hmac 0.13.0` was already in the lock as a development dependency. |
| `rand_core 0.10.1` | The RNG trait pakery's API takes | Already in the lock; now a direct optional pin. |

The pakery pins and `rand_core` are workspace dependencies because
`todoke-crypto` names them both as optional normal and as development
dependencies (cargo-deny `workspace-duplicate`). No new license, source,
advisory, or duplicate-version exception was needed. `const-oid` enters
through `digest`'s `oid` feature, which the pakery graph turns on.

`scripts/ci/deny-exceptions-dev-only.sh` now also fails if any shipped
(non-dev) graph enables `todoke-crypto/unaudited-code-pairing`, and its
test script covers that with a mutated workspace copy. The fuzz workspace
enables the feature for its code-pairing harness, so its lock gained the
same packages (versions identical to the root lock).

cargo-vet: each new package has an exact-version exemption with a "Not yet
reviewed" note naming code pairing, in both stores. `hmac 0.13.0`'s root
exemption was raised from `safe-to-run` to `safe-to-deploy` because
`pakery-crypto` uses it at runtime; the fuzz store also exempts `cmov
0.5.4` and `ctutils 0.4.3`, which the feature brings into that graph. No audit was recorded; replacing these exemptions with real reviews
is part of gate O2.

## sha2 0.11.1 (2026-10-13)

`sha2` 0.11.0 → 0.11.1 (published 2026-10-12, one day old), the only crate
in the lock behind its latest release (`cargo update --dry-run --verbose`).
It is a development dependency of `todoke-crypto`, a runtime dependency of
`ed25519-dalek`, and of `pakery-crypto` under `unaudited-code-pairing`. The
release removes a riscv-zknh workaround, fixes AArch64 round-constant
loading under Stacked Borrows, and raises its MSRV to 1.88 (below ours).
Both lock files and both vet stores moved to the new version; its exemption
keeps the "Not yet reviewed" note. No exception changed.
