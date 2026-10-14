#!/usr/bin/env bash
# Builds dist/todoke_<version>_<arch>.deb from release binaries and the
# static files in packaging/linux.
#
# Environment (all optional):
#   TODOKE_BIN_DIR          prebuilt todoke-desktop and todoke (default:
#                           cargo build --release into target/release)
#   TODOKE_PACKAGE_VERSION  package version (default: the workspace's)
#   TODOKE_ARCH             x86_64 or aarch64 (default: this machine's)
#   TODOKE_DIST             output directory (default: dist)
#   DEB_MAINTAINER          the Maintainer field
set -euo pipefail
umask 022

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
linux="$root/packaging/linux"
icons="$root/packaging/icons"
cd "$root"

die() {
    echo "build-deb.sh: $*" >&2
    exit 1
}

version="${TODOKE_PACKAGE_VERSION:-$("$root/scripts/packaging/version.sh")}"
# SemVer pre-releases sort before the release with "~".
deb_version="${version//-/\~}"
case "${TODOKE_ARCH:-$(uname -m)}" in
    x86_64 | amd64) deb_arch=amd64 ;;
    aarch64 | arm64) deb_arch=arm64 ;;
    *) die "unsupported architecture: ${TODOKE_ARCH:-$(uname -m)}" ;;
esac
dist="${TODOKE_DIST:-$root/dist}"
maintainer="${DEB_MAINTAINER:-todoke maintainers <countradooku@users.noreply.github.com>}"

if [[ -n "${TODOKE_BIN_DIR:-}" ]]; then
    bin_dir="$TODOKE_BIN_DIR"
else
    cargo build --release --locked -p todoke-desktop -p todoke-cli
    bin_dir="$root/target/release"
fi
for bin in todoke-desktop todoke; do
    [[ -x "$bin_dir/$bin" ]] || die "no $bin in $bin_dir"
done

work="$root/target/packaging/deb"
stage="$work/root"
rm -rf "$work"
mkdir -p "$stage/DEBIAN" "$dist"

install -Dm755 "$bin_dir/todoke-desktop" "$stage/usr/bin/todoke-desktop"
install -Dm755 "$bin_dir/todoke" "$stage/usr/bin/todoke"
install -Dm644 "$linux/org.todoke.todoke.desktop" "$stage/usr/share/applications/org.todoke.todoke.desktop"
install -Dm644 "$linux/org.todoke.todoke.metainfo.xml" "$stage/usr/share/metainfo/org.todoke.todoke.metainfo.xml"
for size in 16 24 32 48 64 128 256 512; do
    install -Dm644 "$icons/todoke-$size.png" \
        "$stage/usr/share/icons/hicolor/${size}x${size}/apps/org.todoke.todoke.png"
done
install -Dm644 "$icons/todoke.svg" "$stage/usr/share/icons/hicolor/scalable/apps/org.todoke.todoke.svg"
install -Dm644 "$linux/dolphin/org.todoke.todoke.desktop" "$stage/usr/share/kio/servicemenus/org.todoke.todoke.desktop"
install -Dm644 "$linux/nemo/todoke.nemo_action" "$stage/usr/share/nemo/actions/todoke.nemo_action"
install -Dm644 "$linux/nautilus/todoke.py" "$stage/usr/share/nautilus-python/extensions/todoke.py"

# Machine-readable copyright (Debian policy 12.5).
doc="$stage/usr/share/doc/todoke"
mkdir -p "$doc"
{
    printf '%s\n' \
        'Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/' \
        'Upstream-Name: todoke' \
        'Source: https://github.com/countradooku/todoke' \
        '' \
        'Files: *' \
        'Copyright: the todoke contributors' \
        'License: Apache-2.0 or MIT' \
        '' \
        'License: Apache-2.0' \
        ' On Debian systems, the full text of the Apache License 2.0 is in' \
        ' /usr/share/common-licenses/Apache-2.0.' \
        '' \
        'License: MIT'
    sed -e 's/^[[:space:]]*$/./' -e 's/^/ /' "$root/LICENSE-MIT"
} > "$doc/copyright"
chmod 644 "$doc/copyright"

installed_size="$(du -sk --exclude=DEBIAN "$stage" | cut -f1)"
cat > "$stage/DEBIAN/control" << EOF
Package: todoke
Version: $deb_version
Architecture: $deb_arch
Maintainer: $maintainer
Installed-Size: $installed_size
Section: net
Priority: optional
Homepage: https://github.com/countradooku/todoke
Depends: libc6, libgcc-s1, libfontconfig1, libfreetype6, libwayland-client0, libx11-xcb1, libxcb1, libxkbcommon0, libxkbcommon-x11-0, libvulkan1 | libegl1
Recommends: mesa-vulkan-drivers, python3-nautilus, gnome-keyring | kwalletmanager
Description: End-to-end encrypted file transfer between your devices
 todoke sends files and folders between your phones and computers. Devices
 pair once, and every transfer is end-to-end encrypted.
 .
 This package holds the desktop app (todoke-desktop), the command line
 (todoke), and "Send with todoke" for Dolphin, Nemo, and Files (Nautilus,
 with python3-nautilus).
EOF
(cd "$stage" && find usr -type f -print0 | sort -z | xargs -0 md5sum) > "$stage/DEBIAN/md5sums"

out="$dist/todoke_${deb_version}_${deb_arch}.deb"
dpkg-deb -Zxz --build --root-owner-group "$stage" "$out"
echo "$out"
