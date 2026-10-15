#!/usr/bin/env bash
# Builds the BoltFFI CLI from its crates.io source, pinned to the version
# todoke-ffi's boltffi dependency pins (Cargo.toml), and puts it on PATH.
# No prebuilt binary is downloaded.
set -euo pipefail

version="$(sed -n 's/^boltffi = { version = "=\([0-9.]*\)".*/\1/p' Cargo.toml)"
if [[ -z "$version" ]]; then
    echo 'cannot read the pinned boltffi version from Cargo.toml' >&2
    exit 1
fi
root="${RUNNER_TEMP:-/tmp}/boltffi-$version"
cargo install boltffi_cli --version "=$version" --locked --root "$root"
"$root/bin/boltffi" --version
if [[ -n "${GITHUB_PATH:-}" ]]; then
    echo "$root/bin" >> "$GITHUB_PATH"
fi
