#!/usr/bin/env bash
# Tests for deny-exceptions-dev-only.sh: the real configuration passes, and
# each mutated copy of deny.toml or the CI workflow makes the guard fail.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

guard=scripts/ci/deny-exceptions-dev-only.sh
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
failures=0

expect() {
    local outcome="$1" name="$2" deny="$3" workflow="$4" pattern="${5:-}" output
    if output="$(DENY_CONFIG="$deny" CI_WORKFLOW="$workflow" bash "$guard" 2>&1)"; then
        result=pass
    else
        result=fail
    fi
    if [[ "$result" != "$outcome" ]] || { [[ -n "$pattern" ]] && ! grep -qF -- "$pattern" <<< "$output"; }; then
        echo "not ok - ${name}: expected ${outcome}${pattern:+ with \"${pattern}\"}, got ${result}:" >&2
        sed 's/^/    /' <<< "$output" >&2
        failures=$((failures + 1))
    else
        echo "ok - ${name}"
    fi
}

# Replaces the first line matching a fixed string with the given lines.
mutate() {
    local source="$1" target="$2" match="$3" replacement="$4"
    MATCH_TEXT="$match" REPLACEMENT="$replacement" awk '
        !done && index($0, ENVIRON["MATCH_TEXT"]) { print ENVIRON["REPLACEMENT"]; done = 1; next }
        { print }
        END { if (!done) exit 1 }
    ' "$source" > "$target"
}

deny=deny.toml
workflow=.github/workflows/ci.yml

expect pass "current configuration" "$deny" "$workflow"

# A cross target missing from the guard's list.
mutate "$workflow" "$scratch/extra-target.yml" '- target: wasm32-unknown-unknown' \
    '          - target: wasm32-unknown-unknown
            os: ubuntu-24.04
          - target: riscv64gc-unknown-linux-gnu'
expect fail "CI cross target missing from the guard" "$deny" "$scratch/extra-target.yml" \
    'riscv64gc-unknown-linux-gnu is missing'

# A literal --target in the cross job counts too.
mutate "$workflow" "$scratch/literal-target.yml" 'run: cargo check --workspace --all-targets --locked --target "$CHECK_TARGET"' \
    '        run: cargo check --workspace --all-targets --locked --target "$CHECK_TARGET" && cargo check --target i686-unknown-linux-gnu'
expect fail "literal --target missing from the guard" "$deny" "$scratch/literal-target.yml" \
    'i686-unknown-linux-gnu is missing'

# No cross job: fail closed rather than vacuously pass.
mutate "$workflow" "$scratch/no-cross.yml" '  cross:' '  renamed:'
expect fail "cross job not found" "$deny" "$scratch/no-cross.yml" 'refusing to pass vacuously'

# A license exception marked "Never compiled" that every target compiles.
mutate "$deny" "$scratch/never-compiled.toml" '# Constant-time primitives used by curve25519-dalek.' \
    '    # Never compiled (deliberately false, for this test).'
expect fail "never-compiled license exception that is compiled" "$scratch/never-compiled.toml" "$workflow" \
    'subtle@2.6.1 is marked never compiled'

# A license exception marked "Build-time only" that is linked everywhere.
mutate "$deny" "$scratch/build-time.toml" '# PROTOCOL §1 requires strict dalek Ed25519 verification and a canonical' \
    '    # Build-time only (deliberately false, for this test).'
expect fail "build-time-only license exception that is linked" "$scratch/build-time.toml" "$workflow" \
    'ed25519-dalek@3.0.0 is marked build-time only'

# The marker applies to every entry until the next comment block.
mutate "$deny" "$scratch/grouped.toml" '{ crate = "libloading@0.8.9", allow = ["ISC"] },' \
    '    { crate = "libloading@0.8.9", allow = ["ISC"] },
    { crate = "zeroize@1.9.1", allow = ["ISC"] },'
expect fail "grouped never-compiled entries" "$scratch/grouped.toml" "$workflow" \
    'zeroize@1.9.1 is marked never compiled'

# No classified license exceptions: fail closed.
grep -v 'Never compiled: libcrux-secrets' "$deny" > "$scratch/unclassified.toml"
expect fail "no classified license exceptions" "$scratch/unclassified.toml" "$workflow" \
    'refusing to pass vacuously'

# Forbidden features in the shipped (non-dev) graph. These mutate a copy of the
# workspace manifests, since features come from Cargo.toml, not deny.toml.
workspace_copy() {
    local copy="$1"
    mkdir -p "$copy"
    git ls-files -co --exclude-standard -- Cargo.toml Cargo.lock crates \
        | tar -cf - -T - | tar -xf - -C "$copy"
}

expect_manifest() {
    local name="$1" manifest="$2" pattern="$3" output
    if output="$(CARGO_MANIFEST="$manifest" bash "$guard" 2>&1)"; then
        result=pass
    else
        result=fail
    fi
    if [[ "$result" != fail ]] || ! grep -qF -- "$pattern" <<< "$output"; then
        echo "not ok - ${name}: expected fail with \"${pattern}\", got ${result}:" >&2
        sed 's/^/    /' <<< "$output" >&2
        failures=$((failures + 1))
    else
        echo "ok - ${name}"
    fi
}

# A shipped crate enabling the unaudited suite gate.
workspace_copy "$scratch/gate"
cat >> "$scratch/gate/crates/todoke-core/Cargo.toml" <<'TOML'

[dependencies]
todoke-crypto = { path = "../todoke-crypto", version = "0.1.0", features = ["unaudited-suite-0001"] }
TOML
# Record the new path edge in the copied lock; no registry package changes.
cargo metadata --offline --format-version 1 --manifest-path "$scratch/gate/Cargo.toml" > /dev/null
expect_manifest "unaudited suite feature in a shipped graph" "$scratch/gate/Cargo.toml" \
    'todoke-crypto feature unaudited-suite-0001 is enabled outside dev-dependencies'

# A shipped crate enabling the unaudited code-pairing gate (PROTOCOL §16, O2).
workspace_copy "$scratch/code-gate"
cat >> "$scratch/code-gate/crates/todoke-core/Cargo.toml" <<'TOML'

[dependencies]
todoke-crypto = { path = "../todoke-crypto", version = "0.1.0", features = ["unaudited-code-pairing"] }
TOML
cargo metadata --offline --format-version 1 --manifest-path "$scratch/code-gate/Cargo.toml" > /dev/null
expect_manifest "unaudited code-pairing feature in a shipped graph" "$scratch/code-gate/Cargo.toml" \
    'todoke-crypto feature unaudited-code-pairing is enabled outside dev-dependencies'

# A shipped crate enabling the content consent bypass (PROTOCOL §7.2).
workspace_copy "$scratch/consent"
cat >> "$scratch/consent/crates/todoke-core/Cargo.toml" <<'TOML'

[dependencies]
todoke-crypto = { path = "../todoke-crypto", version = "0.1.0", features = ["insecure-content-without-accept"] }
TOML
cargo metadata --offline --format-version 1 --manifest-path "$scratch/consent/Cargo.toml" > /dev/null
expect_manifest "content consent bypass in a shipped graph" "$scratch/consent/Cargo.toml" \
    'todoke-crypto feature insecure-content-without-accept is enabled outside dev-dependencies'

# A workspace member enabling the content consent bypass for its own tests:
# feature unification would compile every shipped crate's tests against it.
workspace_copy "$scratch/consent-dev"
cat >> "$scratch/consent-dev/crates/todoke-core/Cargo.toml" <<'TOML'

[dev-dependencies]
todoke-crypto = { path = "../todoke-crypto", version = "0.1.0", features = ["insecure-content-without-accept"] }
TOML
cargo metadata --offline --format-version 1 --manifest-path "$scratch/consent-dev/Cargo.toml" > /dev/null
expect_manifest "content consent bypass in the root development graph" "$scratch/consent-dev/Cargo.toml" \
    "todoke-crypto feature insecure-content-without-accept is enabled in the root workspace's development graph"

# The runtime Noise engine with Snow's raw traffic-key export.
workspace_copy "$scratch/raw-split"
mutate crates/todoke-crypto/Cargo.toml "$scratch/raw-split/crates/todoke-crypto/Cargo.toml" \
    'snow.workspace = true' 'snow = { workspace = true, features = ["risky-raw-split"] }'
expect_manifest "Snow raw split in a shipped graph" "$scratch/raw-split/Cargo.toml" \
    'snow feature risky-raw-split is enabled outside dev-dependencies'

if [[ $failures -ne 0 ]]; then
    echo "${failures} guard test(s) failed." >&2
    exit 1
fi
echo 'All guard tests passed.'
