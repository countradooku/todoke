#!/usr/bin/env bash
# Builds dist/todoke-<version>-<arch>.AppImage with a pinned appimagetool
# and runtime (downloaded once into target/packaging/tools, checked by
# SHA-256). The image links the system's libraries like the deb does; its
# glibc floor is the build machine's.
#
# Environment (all optional):
#   TODOKE_BIN_DIR          prebuilt todoke-desktop and todoke (default:
#                           cargo build --release into target/release)
#   TODOKE_PACKAGE_VERSION  version in the file name (default: the workspace's)
#   TODOKE_ARCH             x86_64 or aarch64 (default: this machine's)
#   TODOKE_DIST             output directory (default: dist)
set -euo pipefail
umask 022

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
linux="$root/packaging/linux"
icons="$root/packaging/icons"
cd "$root"

die() {
    echo "build-appimage.sh: $*" >&2
    exit 1
}

# appimagetool 1.9.1 and type2-runtime 20251108; the digests are the ones
# GitHub publishes for these release assets.
APPIMAGETOOL_VERSION=1.9.1
RUNTIME_VERSION=20251108
case "${TODOKE_ARCH:-$(uname -m)}" in
    x86_64 | amd64)
        arch=x86_64
        APPIMAGETOOL_SHA256=ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0
        RUNTIME_SHA256=2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d
        ;;
    aarch64 | arm64)
        arch=aarch64
        APPIMAGETOOL_SHA256=f0837e7448a0c1e4e650a93bb3e85802546e60654ef287576f46c71c126a9158
        RUNTIME_SHA256=00cbdfcf917cc6c0ff6d3347d59e0ca1f7f45a6df1a428a0d6d8a78664d87444
        ;;
    *) die "unsupported architecture: ${TODOKE_ARCH:-$(uname -m)}" ;;
esac

version="${TODOKE_PACKAGE_VERSION:-$("$root/scripts/packaging/version.sh")}"
dist="${TODOKE_DIST:-$root/dist}"

if [[ -n "${TODOKE_BIN_DIR:-}" ]]; then
    bin_dir="$TODOKE_BIN_DIR"
else
    cargo build --release --locked -p todoke-desktop -p todoke-cli
    bin_dir="$root/target/release"
fi
for bin in todoke-desktop todoke; do
    [[ -x "$bin_dir/$bin" ]] || die "no $bin in $bin_dir"
done

# fetch URL SHA256 FILE: downloads unless FILE already has the digest.
fetch() {
    if [[ -f "$3" ]] && echo "$2  $3" | sha256sum --check --status; then
        return
    fi
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        --user-agent todoke-dev --output "$3.part" "$1"
    if ! echo "$2  $3.part" | sha256sum --check --status; then
        rm -f "$3.part"
        die "$1 does not have the pinned SHA-256"
    fi
    mv "$3.part" "$3"
}

tools="$root/target/packaging/tools"
mkdir -p "$tools"
tool="$tools/appimagetool-$APPIMAGETOOL_VERSION-$arch.AppImage"
runtime="$tools/runtime-$RUNTIME_VERSION-$arch"
fetch "https://github.com/AppImage/appimagetool/releases/download/$APPIMAGETOOL_VERSION/appimagetool-$arch.AppImage" \
    "$APPIMAGETOOL_SHA256" "$tool"
fetch "https://github.com/AppImage/type2-runtime/releases/download/$RUNTIME_VERSION/runtime-$arch" \
    "$RUNTIME_SHA256" "$runtime"
chmod +x "$tool"

work="$root/target/packaging/appimage"
appdir="$work/todoke.AppDir"
rm -rf "$work"
mkdir -p "$appdir" "$dist"

install -Dm755 "$bin_dir/todoke-desktop" "$appdir/usr/bin/todoke-desktop"
install -Dm755 "$bin_dir/todoke" "$appdir/usr/bin/todoke"
install -Dm644 "$linux/org.todoke.todoke.desktop" "$appdir/usr/share/applications/org.todoke.todoke.desktop"
install -Dm644 "$linux/org.todoke.todoke.metainfo.xml" "$appdir/usr/share/metainfo/org.todoke.todoke.appdata.xml"
for size in 16 24 32 48 64 128 256 512; do
    install -Dm644 "$icons/todoke-$size.png" \
        "$appdir/usr/share/icons/hicolor/${size}x${size}/apps/org.todoke.todoke.png"
done
install -Dm644 "$icons/todoke.svg" "$appdir/usr/share/icons/hicolor/scalable/apps/org.todoke.todoke.svg"
install -Dm644 "$root/LICENSE-APACHE" "$appdir/usr/share/licenses/todoke/LICENSE-APACHE"
install -Dm644 "$root/LICENSE-MIT" "$appdir/usr/share/licenses/todoke/LICENSE-MIT"
cp "$linux/org.todoke.todoke.desktop" "$appdir/org.todoke.todoke.desktop"
cp "$icons/todoke-256.png" "$appdir/org.todoke.todoke.png"
ln -s org.todoke.todoke.png "$appdir/.DirIcon"

# The app; the command line when the image is started as "todoke" (a
# symbolic link named todoke; the runtime sets ARGV0).
cat > "$appdir/AppRun" << 'EOF'
#!/bin/sh
here="$(dirname "$(readlink -f "$0")")"
case "${ARGV0##*/}" in
    todoke) exec "$here/usr/bin/todoke" "$@" ;;
esac
exec "$here/usr/bin/todoke-desktop" "$@"
EOF
chmod 755 "$appdir/AppRun"

out="$dist/todoke-$version-$arch.AppImage"
rm -f "$out"
# Extract-and-run: no FUSE needed on the build machine. AppStream is
# validated separately (appstreamcli in CI).
ARCH="$arch" APPIMAGE_EXTRACT_AND_RUN=1 "$tool" --no-appstream --runtime-file "$runtime" "$appdir" "$out"
echo "$out"
