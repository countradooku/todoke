#!/usr/bin/env bash
# Builds dist/todoke-<version>-<release>.<arch>.rpm from release binaries
# with packaging/linux/rpm/todoke.spec (which builds nothing itself).
#
# Environment (all optional):
#   TODOKE_BIN_DIR          prebuilt todoke-desktop and todoke (default:
#                           cargo build --release into target/release)
#   TODOKE_PACKAGE_VERSION  package version (default: the workspace's)
#   TODOKE_RPM_RELEASE      package release (default: 1)
#   TODOKE_ARCH             x86_64 or aarch64 (default: this machine's)
#   TODOKE_DIST             output directory (default: dist)
set -euo pipefail
umask 022

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

die() {
    echo "build-rpm.sh: $*" >&2
    exit 1
}

version="${TODOKE_PACKAGE_VERSION:-$("$root/scripts/packaging/version.sh")}"
# RPM versions hold no "-"; pre-releases sort before the release with "~".
rpm_version="${version//-/\~}"
release="${TODOKE_RPM_RELEASE:-1}"
[[ "$release" =~ ^[0-9]+$ ]] || die "not a release number: $release"
case "${TODOKE_ARCH:-$(uname -m)}" in
    x86_64 | amd64) arch=x86_64 ;;
    aarch64 | arm64) arch=aarch64 ;;
    *) die "unsupported architecture: ${TODOKE_ARCH:-$(uname -m)}" ;;
esac
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

work="$root/target/packaging/rpm"
top="$work/rpmbuild"
src="$work/todoke-$rpm_version"
rm -rf "$work"
mkdir -p "$top/SOURCES" "$top/BUILD" "$top/RPMS" "$top/SRPMS" "$src/linux" "$src/icons" "$dist"

# Source0: the binaries and the files the spec installs.
cp "$bin_dir/todoke-desktop" "$bin_dir/todoke" "$root/LICENSE-APACHE" "$root/LICENSE-MIT" "$src/"
cp -R "$root/packaging/linux/org.todoke.todoke.desktop" "$root/packaging/linux/org.todoke.todoke.metainfo.xml" \
    "$root/packaging/linux/dolphin" "$root/packaging/linux/nemo" "$root/packaging/linux/nautilus" "$src/linux/"
cp "$root"/packaging/icons/todoke-*.png "$root/packaging/icons/todoke.svg" "$src/icons/"
tar -C "$work" -cf "$top/SOURCES/todoke-$rpm_version.tar" "todoke-$rpm_version"

rpmbuild -bb --quiet --target "$arch" \
    --define "_topdir $top" \
    --define "todoke_version $rpm_version" \
    --define "todoke_release $release" \
    "$root/packaging/linux/rpm/todoke.spec"

out="$dist/todoke-$rpm_version-$release.$arch.rpm"
cp "$top/RPMS/$arch/todoke-$rpm_version-$release.$arch.rpm" "$out"
echo "$out"
