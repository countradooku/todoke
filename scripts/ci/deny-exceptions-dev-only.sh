#!/usr/bin/env bash
# cargo-deny cannot scope skips or advisory ignores by dependency kind or cfg. This
# guard keeps deny.toml's exceptions out of what todoke actually compiles and ships:
#
# - No exempted package may be compiled for any supported target outside
#   dev-dependencies (normal and build edges, including proc macros).
# - Packages listed in build_time_only may additionally be compiled as build
#   scripts or proc macros, but never linked into a target binary.
#
# The graph is resolved per real target triple rather than with --target all:
# libcrux declares some crates only under cfg(hax) or cfg(valgrind_ct_test), which
# no todoke build sets, so they appear in the all-target graph but never compile.
# Fails closed if any graph cannot be resolved.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

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

# Skipped duplicate versions, read from deny.toml as name@version.
# A read loop rather than mapfile keeps this runnable on macOS's bash 3.2.
exempt=()
while IFS= read -r package; do
    exempt+=("$package")
done < <(grep -oE 'crate = "[A-Za-z0-9_-]+@[0-9][^"]*", reason' deny.toml | sed -E 's/crate = "(.*)", reason/\1/')
# Crates covered by ignored advisories. Keep in sync with [advisories] ignore.
exempt+=("proc-macro-error2@2.0.1")

if [[ ${#exempt[@]} -lt 2 ]]; then
    echo 'No deny.toml exceptions were parsed; refusing to pass vacuously.' >&2
    exit 1
fi

is_build_time_only() {
    local candidate="$1" allowed
    for allowed in "${build_time_only[@]}"; do
        if [[ "$candidate" == "$allowed" ]]; then
            return 0
        fi
    done
    return 1
}

contains() {
    local graph="$1" package="$2"
    local name="${package%@*}" version="${package#*@}"
    grep -qE "^${name} v${version//./\\.}( |$)" <<< "$graph"
}

status=0
for target in "${targets[@]}"; do
    # Everything compiled for a non-dev build: normal, build, and proc-macro edges.
    compiled="$(cargo tree --workspace --locked -e no-dev --target "$target" --prefix none --format '{p}')"
    # Only what is linked into target artifacts.
    linked="$(cargo tree --workspace --locked -e normal,no-proc-macro --target "$target" --prefix none --format '{p}')"
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
done

if [[ $status -eq 0 ]]; then
    echo "All ${#exempt[@]} deny.toml exceptions stay out of shipped code on ${#targets[@]} targets (${build_time_only[*]} build-time only)."
fi
exit "$status"
