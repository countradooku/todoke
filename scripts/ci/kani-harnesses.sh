#!/usr/bin/env bash
# The CI `kani` job names every proof harness explicitly (`cargo kani
# --exact --harness ...`) and requires Kani's summary to report that many
# verified harnesses, so a harness that is gated out, renamed, or never
# compiled fails the job instead of passing with "No proof harnesses were
# found". This check keeps that list in step with the code: the harnesses
# in .github/workflows/ci.yml must be exactly the `#[kani::proof]`
# functions, by their crate-relative paths (Kani's harness names), and the
# job must use `--exact` and check the summary count.
#
# It runs without Kani (Kani is not run locally).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

proofs_file=crates/todoke-transfer/src/gate_proofs.rs
module=gate_proofs::kani_harnesses
workflow=.github/workflows/ci.yml
failures=0

fail() {
    echo "not ok - $*" >&2
    failures=$((failures + 1))
}

# Every #[kani::proof] in the workspace must be in the one harness module
# the job runs; another location needs this check and the job extended.
while IFS= read -r file; do
    if [[ "$file" != "$proofs_file" ]]; then
        fail "$file has #[kani::proof] functions; only $proofs_file is checked by CI"
    fi
done < <(grep -rl --include='*.rs' '#\[kani::proof\]' crates || true)

if ! grep -q '^mod kani_harnesses {' "$proofs_file"; then
    fail "$proofs_file has no top-level 'mod kani_harnesses' (harness names would differ)"
fi

# The function after each #[kani::proof], skipping other attributes.
code_harnesses="$(awk -v prefix="$module" '
    /#\[kani::proof\]/ { want = 1; next }
    want && /^[[:space:]]*#\[/ { next }
    want && match($0, /fn [A-Za-z_][A-Za-z0-9_]*/) {
        print prefix "::" substr($0, RSTART + 3, RLENGTH - 3)
        want = 0
    }
' "$proofs_file" | sort)"

# The entries of the job's `harnesses=( ... )` array.
ci_harnesses="$(awk '
    /^[[:space:]]*harnesses=\($/ { inside = 1; next }
    inside && /^[[:space:]]*\)$/ { inside = 0; next }
    inside { gsub(/[[:space:]]/, ""); if ($0 != "") print }
' "$workflow" | sort)"

if [[ -z "$code_harnesses" ]]; then
    fail "no #[kani::proof] functions found in $proofs_file"
fi
if [[ -z "$ci_harnesses" ]]; then
    fail "$workflow has no harnesses=( ... ) list for the kani job"
fi
if [[ "$code_harnesses" != "$ci_harnesses" ]]; then
    fail "harnesses differ between $proofs_file (<) and $workflow (>):"
    diff <(echo "$code_harnesses") <(echo "$ci_harnesses") | sed 's/^/    /' >&2 || true
fi
duplicates="$(uniq -d <<< "$ci_harnesses")"
if [[ -n "$duplicates" ]]; then
    fail "$workflow lists a harness twice: $duplicates"
fi

job="$(awk '/^  kani:$/ { inside = 1; print; next } inside && /^  [a-z][a-z0-9-]*:$/ { exit } inside { print }' "$workflow")"
if ! grep -q 'cargo kani -p todoke-transfer --exact' <<< "$job"; then
    fail "the kani job does not run 'cargo kani -p todoke-transfer --exact'"
fi
if ! grep -qF 'count=${#harnesses[@]}' <<< "$job" \
    || ! grep -qF '"Complete - $count successfully verified harnesses, 0 failures, $count total."' <<< "$job"; then
    fail "the kani job does not check that every listed harness was verified"
fi

if (( failures > 0 )); then
    echo "$failures Kani harness check(s) failed." >&2
    exit 1
fi
echo "All $(wc -l <<< "$code_harnesses" | tr -d ' ') Kani harnesses are listed in the CI job, which requires each to verify."
