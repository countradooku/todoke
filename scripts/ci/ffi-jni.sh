#!/usr/bin/env bash
# The Kotlin bindings on a desktop JVM: todoke-ffi's static library, BoltFFI's
# generated Kotlin and JNI glue (the test overlay: the library is loaded from
# java.library.path), and the glue linked into libtodoke_ffi. Prints the two
# directories the Gradle build takes (-Ptodoke.generated, -Ptodoke.natives).
#
# By default the library has development sessions and loopback, as the tests
# need. RELEASE=1 builds it as shipped (sessions disabled: the release check).
# SANITIZE=1 builds the Rust library (nightly SANITIZER_TOOLCHAIN) and the
# glue with AddressSanitizer, the glue with UBSan too (Linux, clang); run
# the JVM with clang's ASan runtime preloaded (its path is written to
# OUTPUT_DIR/asan-runtime).
set -euo pipefail

out="${1:?usage: ffi-jni.sh OUTPUT_DIR}"
mkdir -p "$out/generated" "$out/natives"
features=(--features "unaudited-dev,test-support")
profile=debug
build=(--locked)
if [[ "${RELEASE:-0}" == 1 ]]; then
    features=()
    profile=release
    build+=(--release)
fi
if [[ "${SANITIZE:-0}" == 1 ]]; then
    # Apple clang's ASan runtime checks an Apple-specific version that
    # Rust's instrumentation does not emit: Linux only.
    [[ "$(uname -s)" == Linux ]] || { echo "SANITIZE=1 runs on Linux only" >&2; exit 1; }
    host="$(rustc -vV | sed -n 's/^host: //p')"
    RUSTFLAGS="-Zsanitizer=address" cargo +"${SANITIZER_TOOLCHAIN:?}" build "${build[@]}" \
        -Zbuild-std --target "$host" -p todoke-ffi ${features[@]+"${features[@]}"}
    library_dir="target/$host/$profile"
else
    cargo build "${build[@]}" -p todoke-ffi ${features[@]+"${features[@]}"}
    library_dir="target/$profile"
fi
(cd crates/todoke-ffi && boltffi --overlay boltffi.test.toml generate kotlin -o "$out/generated")
java_home="${JAVA_HOME:?JAVA_HOME must name a JDK}"
case "$(uname -s)" in
    Linux) platform=linux library=libtodoke_ffi.so system=(-lpthread -ldl -lm) ;;
    Darwin) platform=darwin library=libtodoke_ffi.dylib system=(-framework Security -framework CoreFoundation -framework SystemConfiguration) ;;
    *) echo "unsupported host" >&2; exit 1 ;;
esac
compiler="${CC:-cc}"
flags=(-shared -fPIC -O1 -Wall -Werror)
if [[ "${SANITIZE:-0}" == 1 ]]; then
    compiler=clang
    flags+=("-fsanitize=address,undefined" -shared-libasan -fno-omit-frame-pointer)
fi
"$compiler" "${flags[@]}" -o "$out/natives/$library" \
    "$out/generated/jni/jni_glue.c" -I"$out/generated/jni" \
    -I"$java_home/include" -I"$java_home/include/$platform" \
    "$library_dir/libtodoke_ffi.a" "${system[@]}"
if [[ "${SANITIZE:-0}" == 1 ]]; then
    # The runtime the JVM preloads: named per target since clang 15.
    runtime=""
    for name in libclang_rt.asan.so libclang_rt.asan-x86_64.so; do
        candidate="$(clang -print-runtime-dir)/$name"
        [[ -f "$candidate" ]] && { runtime="$candidate"; break; }
        candidate="$(clang -print-file-name="$name")"
        [[ -f "$candidate" ]] && { runtime="$candidate"; break; }
    done
    [[ -n "$runtime" ]] || { echo "clang's ASan runtime was not found" >&2; exit 1; }
    echo "$runtime" > "$out/asan-runtime"
fi
echo "generated=$out/generated"
echo "natives=$out/natives"
