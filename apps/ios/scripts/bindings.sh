#!/usr/bin/env bash
# Points apps/ios/Bindings at a BoltFFI Swift package: `dev` (development
# sessions and loopback, the iOS slices of boltffi.ios.toml) or `release`
# (the shipped package, sessions disabled). Packs it first unless --no-pack.
# `dev --optimized` packs the development package with the release profile:
# for trying the app on a device (an unoptimized core encrypts and hashes
# several times slower); the tests keep the debug build and its checks.
set -euo pipefail
kind="${1:-dev}"
here="$(cd "$(dirname "$0")/.." && pwd)"
ffi="$here/../../crates/todoke-ffi"
export IPHONEOS_DEPLOYMENT_TARGET=17.0
pack=true
optimized=false
for flag in "${@:2}"; do
    case "$flag" in
        --no-pack) pack=false ;;
        --optimized) optimized=true ;;
        *) echo "usage: $0 dev|release [--optimized] [--no-pack]" >&2; exit 2 ;;
    esac
done
case "$kind" in
    dev) out="target-tests/ios"; args=(--overlay boltffi.ios.toml pack apple) ;;
    release) out="dist/apple"; args=(pack apple --release) ;;
    *) echo "usage: $0 dev|release [--optimized] [--no-pack]" >&2; exit 2 ;;
esac
if [[ "$optimized" == true && "$kind" == dev ]]; then
    args+=(--release)
fi
# In CI, the compiler's output too: boltffi otherwise names only the
# target that failed.
if [[ -n "${CI:-}" ]]; then
    args+=(--verbose)
fi
if [[ "$pack" == true ]]; then
    (cd "$ffi" && boltffi "${args[@]}")
fi
ln -sfn "../../crates/todoke-ffi/$out" "$here/Bindings"
echo "Bindings -> crates/todoke-ffi/$out"
