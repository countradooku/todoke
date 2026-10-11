#!/usr/bin/env bash
# cargo-deny cannot scope skips or advisory ignores by dependency kind. This guard
# keeps deny.toml's exceptions limited to development dependencies: none of the
# exempted packages may appear in the workspace's normal or build graph on any
# target. Fails closed if the graph cannot be resolved.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

# Skipped duplicate versions, read from deny.toml as name@version.
# A read loop rather than mapfile keeps this runnable on macOS's bash 3.2.
exempt=()
while IFS= read -r package; do
    exempt+=("$package")
done < <(grep -oE 'crate = "[A-Za-z0-9_-]+@[0-9][^"]*"' deny.toml | sed -E 's/crate = "(.*)"/\1/')
# Crates covered by ignored advisories. Keep in sync with [advisories] ignore.
exempt+=("proc-macro-error2@2.0.1")

if [[ ${#exempt[@]} -lt 2 ]]; then
    echo 'No deny.toml exceptions were parsed; refusing to pass vacuously.' >&2
    exit 1
fi

graph="$(cargo tree --workspace --locked -e no-dev --target all --prefix none --format '{p}')"

status=0
for package in "${exempt[@]}"; do
    name="${package%@*}"
    version="${package#*@}"
    if grep -qE "^${name} v${version//./\\.}( |$)" <<< "$graph"; then
        echo "deny.toml exception ${package} is reachable outside dev-dependencies." >&2
        status=1
    fi
done

if [[ $status -eq 0 ]]; then
    echo "All ${#exempt[@]} deny.toml exceptions are confined to dev-dependencies."
fi
exit "$status"
