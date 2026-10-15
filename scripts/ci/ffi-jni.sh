#!/usr/bin/env bash
# The Kotlin bindings on a desktop JVM: todoke-ffi's static library (with
# development sessions, as the tests need), BoltFFI's generated Kotlin and
# JNI glue, and the glue linked into libtodoke_jni. Prints the two
# directories the Gradle build takes (-Ptodoke.generated, -Ptodoke.natives).
# SANITIZE=1 builds the glue with AddressSanitizer and UBSan.
set -euo pipefail

out="${1:?usage: ffi-jni.sh OUTPUT_DIR}"
mkdir -p "$out/generated" "$out/natives"
cargo build --locked -p todoke-ffi --features unaudited-dev
(cd crates/todoke-ffi && boltffi generate kotlin -o "$out/generated")
java_home="${JAVA_HOME:?JAVA_HOME must name a JDK}"
case "$(uname -s)" in
    Linux) platform=linux library=libtodoke_jni.so system=(-lpthread -ldl -lm) ;;
    Darwin) platform=darwin library=libtodoke_jni.dylib system=(-framework Security -framework CoreFoundation -framework SystemConfiguration) ;;
    *) echo "unsupported host" >&2; exit 1 ;;
esac
flags=(-shared -fPIC -O1 -Wall -Werror)
if [[ "${SANITIZE:-0}" == 1 ]]; then
    flags+=("-fsanitize=address,undefined" -fno-omit-frame-pointer)
fi
cc "${flags[@]}" -o "$out/natives/$library" \
    "$out/generated/jni/jni_glue.c" -I"$out/generated/jni" \
    -I"$java_home/include" -I"$java_home/include/$platform" \
    target/debug/libtodoke_ffi.a "${system[@]}"
echo "generated=$out/generated"
echo "natives=$out/natives"
