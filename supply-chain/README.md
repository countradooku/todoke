# Dependency review

This store was initialized with `cargo-vet 0.10.2` against the scaffold's empty
third-party dependency graph. The protocol-vector example now introduces pinned
reference development dependencies. `audits.toml` and `imports.lock` remain empty;
`config.toml` contains no exemptions or trusted publishers. These new dependencies
have not received cargo-vet audits. Running reference vectors does not certify
todoke's security or approve these crates for production secrets.

Run the same tool versions as CI:

```sh
cargo install --locked cargo-deny --version 0.20.2
cargo install --locked cargo-vet --version 0.10.2
cargo deny --locked check
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

On 2026-10-11, the locked vector-tool graph passes cargo-deny's license and
source checks but does **not** pass its advisory or duplicate-version policies:

- [RUSTSEC-2026-0173](https://rustsec.org/advisories/RUSTSEC-2026-0173.html):
  unmaintained `proc-macro-error2 2.0.1`, with no patched version. The path includes
  `libcrux-intrinsics 0.0.9` → `core-models 0.0.7` → `hax-lib 0.3.7` →
  `hax-lib-macros`. The `cfg(hax)` dependency is still part of the all-target audit
  graph even though the fixture executable does not enable that verification mode.
- Conflicting versions of `hax-lib`, `hax-lib-macros`, `hax-lib-macros-types`
  (0.3.7 / 0.4.2), `syn` (2.0.119 / 3.0.7), and `shlex` (1.3.0 / 2.0.1).
- `cargo vet --locked` reports 109 dependencies missing `safe-to-run` evidence.

Current upstream features/releases were inspected; disabling ML-KEM default/SIMD
features does not remove the older verification graph. No advisory ignore, version
skip, blanket vet exemption, or dependency source patch was added. CI supply-chain
checks therefore remain failing until upstream resolution and actual audit evidence
are available, or narrowly justified exceptions receive review. The generator takes
only public fixed fixtures and is not a production secret-handling approval.
