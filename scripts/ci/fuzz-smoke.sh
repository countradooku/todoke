#!/usr/bin/env bash
# Discover harnesses rather than maintaining a second list in CI.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

if [[ ! -f fuzz/Cargo.toml ]]; then
    if compgen -G 'fuzz/fuzz_targets/*.rs' > /dev/null; then
        echo 'Fuzz harnesses exist without fuzz/Cargo.toml.' >&2
        exit 1
    fi
    message='Fuzz smoke skipped: the scaffold has no parsers or fuzz targets yet.'
    echo "$message"
    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        echo "$message" >> "$GITHUB_STEP_SUMMARY"
    fi
    exit 0
fi

if [[ ! -f fuzz/Cargo.lock ]]; then
    echo 'Commit fuzz/Cargo.lock before running the fuzz smoke check.' >&2
    exit 1
fi

fuzz_toolchain="${FUZZ_TOOLCHAIN:-nightly-2026-08-20}"
# Capture separately: failures from discovery must not be lost in a pipeline.
targets="$(rustup run "$fuzz_toolchain" cargo fuzz list --fuzz-dir fuzz)"
if [[ -z "$targets" ]]; then
    echo 'fuzz/Cargo.toml exists but cargo fuzz reports no targets.' >&2
    exit 1
fi

while IFS= read -r target; do
    if [[ -z "$target" ]]; then
        continue
    fi
    echo "Fuzzing $target for 60 seconds"
    # The generated corpus (ignored by git) comes first so libFuzzer writes new
    # inputs there; committed seeds in fuzz/seeds are read only.
    corpora=("fuzz/corpus/$target")
    mkdir -p "fuzz/corpus/$target"
    if [[ -d "fuzz/seeds/$target" ]]; then
        corpora+=("fuzz/seeds/$target")
    fi
    # Cargo-fuzz does not expose --locked; reject changes to its committed lock
    # after running, and make the dependency policy/audit CI job check it too.
    rustup run "$fuzz_toolchain" cargo fuzz run --fuzz-dir fuzz "$target" "${corpora[@]}" -- \
        -max_total_time=60 -timeout=10
done <<< "$targets"

git diff --exit-code -- fuzz/Cargo.lock
