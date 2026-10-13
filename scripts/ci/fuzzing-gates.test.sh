#!/usr/bin/env bash
# cargo-fuzz builds every crate with `--cfg fuzzing`, and anyone can pass that
# cfg through RUSTFLAGS. The deny-exception guard checks features, not cfgs,
# so this test checks that `--cfg fuzzing` alone exposes no gate bypass:
# todoke-crypto's fuzzing modules that bypass a production or consent gate
# also need the feature that guards that gate, and the crate builds without
# warnings for each combination.
#
# - `content::fuzzing` seals and opens without a signed Accept:
#   `insecure-content-without-accept`.
# - `session::fuzzing` runs suite 0x0001 with scripted randomness:
#   `unaudited-suite-0001`; its code-pairing harness also needs
#   `unaudited-code-pairing`.
# - `identity::fuzzing` and `pairing::fuzzing` only decode (local storage
#   plaintext, a fixed-key envelope, binding signatures, QR payloads, typed
#   codes), and `consent::fuzzing` only verifies manifests, Accepts, and
#   receipts against fixed public fixture keys, so plain `--cfg fuzzing` is
#   enough.
#
# The cfg goes to todoke-crypto only (`cargo rustc`/`cargo rustdoc` pass
# trailing flags to the final crate), and the module list comes from the
# generated documentation of each build.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
export CARGO_TARGET_DIR="$scratch/target"
failures=0

# expect FEATURES PRESENT... -- ABSENT...: paths are relative to the crate's
# documentation root.
expect() {
    local features="$1" path missing=0 output
    shift
    local feature_args=()
    if [[ -n "$features" ]]; then
        feature_args=(--features "$features")
    fi
    local name="--cfg fuzzing${features:+ with ${features}}"
    if ! output="$(cargo rustc -p todoke-crypto --lib --locked --profile check \
        ${feature_args[@]+"${feature_args[@]}"} -- --cfg fuzzing -D warnings 2>&1)"; then
        echo "not ok - ${name}: does not build without warnings:" >&2
        sed 's/^/    /' <<< "$output" >&2
        failures=$((failures + 1))
        return
    fi
    rm -rf "$CARGO_TARGET_DIR/doc/todoke_crypto"
    if ! output="$(cargo rustdoc -p todoke-crypto --lib --locked \
        ${feature_args[@]+"${feature_args[@]}"} -- --cfg fuzzing 2>&1)"; then
        echo "not ok - ${name}: documentation does not build:" >&2
        sed 's/^/    /' <<< "$output" >&2
        failures=$((failures + 1))
        return
    fi
    local docs="$CARGO_TARGET_DIR/doc/todoke_crypto" absent=0
    for path in "$@"; do
        if [[ "$path" == -- ]]; then
            absent=1
            continue
        fi
        if [[ $absent -eq 0 && ! -e "$docs/$path" ]]; then
            echo "not ok - ${name}: ${path} is missing" >&2
            missing=1
        elif [[ $absent -eq 1 && -e "$docs/$path" ]]; then
            echo "not ok - ${name}: ${path} is exposed" >&2
            missing=1
        fi
    done
    if [[ $missing -ne 0 ]]; then
        failures=$((failures + 1))
    else
        echo "ok - ${name}"
    fi
}

content=content/fuzzing/index.html
session=session/fuzzing/index.html
code=session/fuzzing/fn.code_pairing_records.html
identity=identity/fuzzing/index.html
pairing=pairing/fuzzing/index.html
consent=consent/fuzzing/index.html

expect "" "$identity" "$pairing" "$consent" -- "$content" "$session"
expect unaudited-suite-0001 "$identity" "$pairing" "$consent" "$session" -- "$content" "$code"
expect unaudited-code-pairing "$identity" "$pairing" "$consent" "$session" "$code" -- "$content"
expect insecure-content-without-accept "$identity" "$pairing" "$consent" "$content" -- "$session"
# The fuzz workspace's features (fuzz/Cargo.toml): every harness module.
expect unaudited-code-pairing,insecure-content-without-accept \
    "$identity" "$pairing" "$consent" "$content" "$session" "$code"

if [[ $failures -ne 0 ]]; then
    echo "${failures} fuzzing gate test(s) failed." >&2
    exit 1
fi
echo 'All fuzzing gate tests passed.'
