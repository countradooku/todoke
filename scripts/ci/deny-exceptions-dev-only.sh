#!/usr/bin/env bash
# cargo-deny cannot scope skips, advisory ignores, or license exceptions by
# dependency kind or cfg. This guard keeps deny.toml's exceptions out of what
# todoke actually compiles and ships:
#
# - No exempted duplicate or advisory package may be compiled for any supported
#   target outside dev-dependencies (normal and build edges, including proc
#   macros).
# - Packages listed in build_time_only may additionally be compiled as build
#   scripts or proc macros, but never linked into a target binary.
# - License exceptions whose deny.toml comment says "Never compiled" may not be
#   compiled for any target at all, dev-dependencies included; those marked
#   "Build-time only" may not be linked into a target binary.
# - Every target checked by the CI cross job must be in the target list below.
# - No target's non-dev graph may enable a feature in forbidden_features:
#   todoke-crypto's `unaudited-suite-0001` and `unaudited-code-pairing` (the
#   PROTOCOL §16 production gates for suite 0x0001 and, through O2, human-code
#   pairing) and `insecure-content-without-accept` (seals and opens content
#   without a signed Accept, bypassing the PROTOCOL §7.2 consent gate; used
#   only by benchmarks), or Snow's `risky-raw-split` (traffic-key export, used
#   only by the offline fixture generator), and todoke-desktop's `mock` (a
#   scripted core and GPUI test support, for screenshots). Under resolver 2/3, dev-dependency features are only
#   unified into builds of targets that need them (Cargo book, "Feature
#   resolver version 2"), and `cargo tree -e no-dev` reports that non-dev
#   feature resolution.
# - No target's full graph, dev-dependencies included, may enable a feature in
#   forbidden_dev_features: `insecure-content-without-accept`. `cargo test
#   --workspace` and `--all-targets` builds unify every member's
#   dev-dependency features, so one member enabling it would compile every
#   shipped crate's tests against the consent bypass. The benchmarks that
#   need it live in the isolated `bench/` workspace.
# - Neither LIBCRUX_DISABLE_SIMD256 nor LIBCRUX_DISABLE_SIMD128 may be set in
#   this environment or in any repository workflow or `.cargo/config*` file.
#   libcrux-aes's build script then aliases its hardware AES-GCM to the
#   portable implementation while libcrux-platform still reports the CPU
#   features, so todoke would advertise AES (§6) and run bit-sliced AES
#   (docs/adr/0004-content-aead.md).
#
# Crates in deny.toml's [graph] exclude (the desktop app, which has its own
# policy in deny-desktop.toml) are left out of the exception checks, as
# cargo-deny leaves them out, but never out of the forbidden-feature checks:
# no shipped graph, the desktop's included, may enable a gate.
#
# The graph is resolved per real target triple rather than with --target all:
# libcrux declares some crates only under cfg(hax) or cfg(valgrind_ct_test), which
# no todoke build sets, so they appear in the all-target graph but never compile.
# Fails closed if any graph or configuration cannot be resolved.
#
# DENY_CONFIG, CI_WORKFLOW, CARGO_MANIFEST, and SCAN_ROOT (the directory
# searched for workflows and Cargo configs) override the inputs (for the
# guard's own tests).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

deny_config="${DENY_CONFIG:-deny.toml}"
ci_workflow="${CI_WORKFLOW:-.github/workflows/ci.yml}"
manifest="${CARGO_MANIFEST:-Cargo.toml}"
scan_root="${SCAN_ROOT:-.}"

# Supported and CI-checked targets. Add new release targets here.
targets=(
    x86_64-unknown-linux-gnu
    aarch64-unknown-linux-gnu
    x86_64-apple-darwin
    aarch64-apple-darwin
    x86_64-pc-windows-msvc
    aarch64-pc-windows-msvc
    aarch64-linux-android
    armv7-linux-androideabi
    x86_64-linux-android
    aarch64-apple-ios
    aarch64-apple-ios-sim
    x86_64-apple-ios
    wasm32-unknown-unknown
)

# Exempted packages permitted as build-time-only dependencies. Each needs a
# matching "Build-time only" reason in deny.toml.
build_time_only=("syn@2.0.119")

# Features no shipped graph may enable, as package:feature.
forbidden_features=(
    "todoke-crypto:unaudited-suite-0001"
    "todoke-crypto:unaudited-code-pairing"
    "todoke-crypto:insecure-content-without-accept"
    "snow:risky-raw-split"
    "todoke-core:unaudited-dev"
    "todoke-desktop:mock"
)

# Features the root workspace may not enable even through dev-dependencies.
forbidden_dev_features=(
    "todoke-crypto:insecure-content-without-accept"
)

# Workspace members excluded from deny.toml's graph, as cargo tree arguments.
excluded=()
while IFS= read -r member; do
    [[ -n "$member" ]] && excluded+=(--exclude "$member")
done < <(awk '
    /^\[graph\]/ { section = 1; next }
    /^\[/ { section = 0 }
    section && /^exclude[[:space:]]*=/ {
        while (match($0, /"[^"]+"/)) {
            print substr($0, RSTART + 1, RLENGTH - 2)
            $0 = substr($0, RSTART + RLENGTH)
        }
    }
' "$deny_config")

# Skipped duplicate versions, read from deny.toml as name@version.
# A read loop rather than mapfile keeps this runnable on macOS's bash 3.2.
exempt=()
while IFS= read -r package; do
    exempt+=("$package")
done < <(grep -oE 'crate = "[A-Za-z0-9_-]+@[0-9][^"]*", reason' "$deny_config" | sed -E 's/crate = "(.*)", reason/\1/')
# Crates covered by ignored advisories. Keep in sync with [advisories] ignore.
exempt+=("proc-macro-error2@2.0.1")

if [[ ${#exempt[@]} -lt 2 ]]; then
    echo 'No deny.toml exceptions were parsed; refusing to pass vacuously.' >&2
    exit 1
fi

# License exceptions classified by the comment block above them, as
# "never name@version" or "build name@version". Other exceptions (runtime
# crates, the fuzz-only harness) are not restricted here.
license_never=()
license_build=()
license_entries=0
while IFS=' ' read -r class package; do
    license_entries=$((license_entries + 1))
    case "$class" in
        never) license_never+=("$package") ;;
        build) license_build+=("$package") ;;
    esac
done < <(awk '
    /^\[licenses\]/ { section = 1; next }
    /^\[/ { section = 0 }
    !section { next }
    /^[[:space:]]*#/ {
        if (!in_comment) { class = "-" }
        in_comment = 1
        if ($0 ~ /Never compiled/) { class = "never" }
        else if ($0 ~ /Build-time only/) { class = "build" }
        next
    }
    /crate = "/ {
        match($0, /crate = "[^"]+"/)
        print (class == "" ? "-" : class), substr($0, RSTART + 9, RLENGTH - 10)
    }
    { in_comment = 0 }
' "$deny_config")

if [[ $license_entries -eq 0 || ${#license_never[@]} -eq 0 ]]; then
    echo 'No classified deny.toml license exceptions were parsed; refusing to pass vacuously.' >&2
    exit 1
fi

# Targets checked by the CI cross job: matrix "target:" entries and any literal
# "--target <triple>" in that job.
cross_targets=()
while IFS= read -r target; do
    cross_targets+=("$target")
done < <(awk '
    /^  [A-Za-z0-9_-]+:/ { job = $1 }
    job == "cross:" { print }
' "$ci_workflow" | grep -oE '(target:|--target)[[:space:]=]+"?[A-Za-z0-9_.-]+' | sed -E 's/^(target:|--target)[[:space:]=]+"?//' | sort -u)

if [[ ${#cross_targets[@]} -eq 0 ]]; then
    echo "No targets parsed from the cross job in ${ci_workflow}; refusing to pass vacuously." >&2
    exit 1
fi

status=0
for target in "${cross_targets[@]}"; do
    found=0
    for known in "${targets[@]}"; do
        if [[ "$target" == "$known" ]]; then
            found=1
        fi
    done
    if [[ $found -eq 0 ]]; then
        echo "CI cross target ${target} is missing from this guard's target list." >&2
        status=1
    fi
done

# libcrux build-time SIMD overrides that would make ContentSuites::local
# advertise AES while libcrux-aes runs its portable implementation.
simd_overrides=(LIBCRUX_DISABLE_SIMD256 LIBCRUX_DISABLE_SIMD128)
for variable in "${simd_overrides[@]}"; do
    if printenv "$variable" > /dev/null; then
        echo "${variable} is set in the environment; libcrux-aes would run portable AES while todoke advertises hardware AES (docs/adr/0004-content-aead.md)." >&2
        status=1
    fi
done
while IFS= read -r file; do
    for variable in "${simd_overrides[@]}"; do
        if grep -qF "$variable" "$file"; then
            echo "${file} sets ${variable}; libcrux-aes would run portable AES while todoke advertises hardware AES (docs/adr/0004-content-aead.md)." >&2
            status=1
        fi
    done
done < <({
    find "$scan_root" \( -name target -o -name .git \) -prune -o -type f \
        \( -path '*/.cargo/config' -o -path '*/.cargo/config*.toml' -o -path '*/.github/workflows/*' \) -print
    echo "$ci_workflow"
} | sort -u)

is_build_time_only() {
    local candidate="$1" allowed
    for allowed in "${build_time_only[@]}"; do
        if [[ "$candidate" == "$allowed" ]]; then
            return 0
        fi
    done
    return 1
}

# Exit 0 if the "{p}|{f}" graph enables package:feature, 1 if the package is
# present without it, and 2 if the package is absent (a vacuous check).
feature_outcome() {
    local graph="$1" forbidden="$2"
    awk -F'|' -v name="${forbidden%%:*}" -v feature="${forbidden#*:}" '
        { split($1, words, " "); count = split($2, enabled, ",") }
        words[1] == name {
            seen = 1
            for (i = 1; i <= count; i++) if (enabled[i] == feature) found = 1
        }
        END { exit found ? 0 : (seen ? 1 : 2) }
    ' <<< "$graph"
}

contains() {
    local graph="$1" package="$2"
    local name="${package%@*}" version="${package#*@}"
    grep -qE "^${name} v${version//./\\.}( |$)" <<< "$graph"
}

for target in "${targets[@]}"; do
    # Everything compiled for a non-dev build: normal, build, and proc-macro edges.
    compiled="$(cargo tree --manifest-path "$manifest" --workspace ${excluded[@]+"${excluded[@]}"} --locked -e no-dev --target "$target" --prefix none --format '{p}')"
    # Everything compiled at all, including tests, examples, and benches.
    compiled_any="$(cargo tree --manifest-path "$manifest" --workspace ${excluded[@]+"${excluded[@]}"} --locked -e normal,build,dev --target "$target" --prefix none --format '{p}')"
    # Enabled features of every non-dev package, as "name vX (source)|f1,f2".
    features="$(cargo tree --manifest-path "$manifest" --workspace --locked -e no-dev --target "$target" --prefix none --format '{p}|{f}')"
    # The same for everything compiled at all, dev-dependencies included.
    features_any="$(cargo tree --manifest-path "$manifest" --workspace --locked -e normal,build,dev --target "$target" --prefix none --format '{p}|{f}')"
    # Only what is linked into target artifacts.
    linked="$(cargo tree --manifest-path "$manifest" --workspace ${excluded[@]+"${excluded[@]}"} --locked -e normal,no-proc-macro --target "$target" --prefix none --format '{p}')"
    for package in "${exempt[@]}"; do
        if is_build_time_only "$package"; then
            if contains "$linked" "$package"; then
                echo "deny.toml exception ${package} is linked into ${target} artifacts." >&2
                status=1
            fi
        elif contains "$compiled" "$package"; then
            echo "deny.toml exception ${package} is compiled outside dev-dependencies for ${target}." >&2
            status=1
        fi
    done
    for forbidden in "${forbidden_features[@]}"; do
        outcome=0
        feature_outcome "$features" "$forbidden" || outcome=$?
        case "$outcome" in
            0)
                echo "${forbidden%%:*} feature ${forbidden#*:} is enabled outside dev-dependencies for ${target}." >&2
                status=1
                ;;
            1) ;;
            *)
                echo "${forbidden%%:*} is not in the non-dev graph for ${target}; refusing to pass vacuously." >&2
                status=1
                ;;
        esac
    done
    for forbidden in "${forbidden_dev_features[@]}"; do
        outcome=0
        feature_outcome "$features_any" "$forbidden" || outcome=$?
        case "$outcome" in
            0)
                echo "${forbidden%%:*} feature ${forbidden#*:} is enabled in the root workspace's development graph for ${target}; only isolated workspaces such as bench/ may enable it." >&2
                status=1
                ;;
            1) ;;
            *)
                echo "${forbidden%%:*} is not in the development graph for ${target}; refusing to pass vacuously." >&2
                status=1
                ;;
        esac
    done
    for package in ${license_never[@]+"${license_never[@]}"}; do
        if contains "$compiled_any" "$package"; then
            echo "deny.toml license exception ${package} is marked never compiled but is compiled for ${target}." >&2
            status=1
        fi
    done
    for package in ${license_build[@]+"${license_build[@]}"}; do
        if contains "$linked" "$package"; then
            echo "deny.toml license exception ${package} is marked build-time only but is linked into ${target} artifacts." >&2
            status=1
        fi
    done
done

if [[ $status -eq 0 ]]; then
    echo "All ${#exempt[@]} deny.toml exceptions and ${license_entries} license exceptions (${#license_never[@]} never compiled, ${#license_build[@]} build-time only) stay out of shipped code on ${#targets[@]} targets (${build_time_only[*]} build-time only); no shipped graph enables ${forbidden_features[*]}; no root development graph enables ${forbidden_dev_features[*]}; ${simd_overrides[*]} are unset; CI cross targets (${cross_targets[*]}) are covered."
fi
exit "$status"
