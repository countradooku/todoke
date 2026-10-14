#!/usr/bin/env bash
# Prints the workspace version ([workspace.package] in Cargo.toml). The
# packaging scripts read it from here; no cargo or network needed.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

version="$(awk '
    /^\[/ { section = $0; next }
    section == "[workspace.package]" && $1 == "version" && $2 == "=" {
        gsub(/"/, "", $3)
        print $3
        exit
    }
' "$root/Cargo.toml")"

# SemVer without build metadata: packaging formats disagree about "+".
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; then
    echo "no usable [workspace.package] version in $root/Cargo.toml: '$version'" >&2
    exit 1
fi
printf '%s\n' "$version"
