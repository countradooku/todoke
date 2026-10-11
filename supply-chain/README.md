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
still fails until actual audit evidence exists. The shared `deny.toml` is also used
for the future fuzz workspace, whose graph will not contain these dev-only crates;
its unused advisory ignore would then fail, so introducing that workspace requires
a decision on a separate fuzz policy file. The generator takes
only public fixed fixtures and is not a production secret-handling approval.

The [O1 decision](../spec/decisions/O1-HYBRID-NOISE.md) cites a real independent
review of an older Snow revision as evidence for the existing HFS+PSK construction.
That is not a cargo-vet audit of the current resolved packages, this adapter, or
the whole dependency graph. No audit-store entries or exemptions were fabricated.
Snow's raw Split export and the KEM resolver compatibility slot are confined to
the public-fixture example; production integration and zeroization remain open.
