# Dependency review

This store was initialized with `cargo-vet 0.10.2` against the scaffold's empty
third-party dependency graph. `audits.toml` and `imports.lock` are intentionally
empty; `config.toml` contains no exemptions or trusted publishers. Successful
vetting at this stage means there are no third-party dependencies to review.
It does not certify todoke's own security.

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
