#!/usr/bin/env bash
# Points apps/ios/Bindings at a BoltFFI Swift package: `dev` (development
# sessions and loopback, the iOS slices of boltffi.ios.toml) or `release`
# (the shipped package, sessions disabled). Packs it first unless --no-pack.
set -euo pipefail
kind="${1:-dev}"
here="$(cd "$(dirname "$0")/.." && pwd)"
ffi="$here/../../crates/todoke-ffi"
export IPHONEOS_DEPLOYMENT_TARGET=17.0
case "$kind" in
    dev) out="target-tests/ios"; args=(--overlay boltffi.ios.toml pack apple) ;;
    release) out="dist/apple"; args=(pack apple --release) ;;
    *) echo "usage: $0 dev|release [--no-pack]" >&2; exit 2 ;;
esac
if [[ "${2:-}" != "--no-pack" ]]; then
    (cd "$ffi" && boltffi "${args[@]}")
fi
ln -sfn "../../crates/todoke-ffi/$out" "$here/Bindings"
echo "Bindings -> crates/todoke-ffi/$out"
