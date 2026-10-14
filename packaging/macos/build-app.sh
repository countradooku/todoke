#!/usr/bin/env bash
# Builds todoke.app (the app, the todoke command, the login agent, and the
# Share extension), signs it, notarizes it when an API key is given, and
# writes dist/todoke-<version>-macos-<arch>.zip and .dmg.
#
# Usage: packaging/macos/build-app.sh [aarch64-apple-darwin | x86_64-apple-darwin | universal]
# Default: universal when both targets are installed, else the host.
#
# Environment (all optional):
#   MACOS_SIGNING_IDENTITY      Developer ID Application identity (hardened
#                               runtime, timestamp); ad-hoc without it.
#   MACOS_TEAM_ID               team ID for todoke.entitlements, applied only
#   MACOS_PROVISIONING_PROFILE  with this Developer ID profile (.provisionprofile).
#   MACOS_NOTARY_KEY_ID         App Store Connect API key ID,
#   MACOS_NOTARY_ISSUER         its issuer ID,
#   MACOS_NOTARY_KEY            and the path to its .p8 file: all three notarize.
#   TODOKE_PACKAGE_VERSION      bundle version (default: the workspace's).
#   TODOKE_DIST                 output directory (default: dist).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
here="$root/packaging/macos"
cd "$root"

die() {
    echo "build-app.sh: $*" >&2
    exit 1
}

[[ "$(uname -s)" == Darwin ]] || die "builds on macOS only"

version="${TODOKE_PACKAGE_VERSION:-$("$root/scripts/packaging/version.sh")}"
# CFBundleShortVersionString: up to three integers.
[[ "$version" =~ ^[0-9]+(\.[0-9]+){0,2}$ ]] || die "not a bundle version: $version"
dist="${TODOKE_DIST:-$root/dist}"
work="$root/target/packaging/macos"
identity="${MACOS_SIGNING_IDENTITY:-}"

# Targets (rust-toolchain.toml's toolchain).
installed="$(rustup target list --installed)"
has_target() {
    grep -qx "$1" <<< "$installed"
}
target="${1:-}"
if [[ -z "$target" ]]; then
    if has_target aarch64-apple-darwin && has_target x86_64-apple-darwin; then
        target=universal
    else
        target="$(rustc -vV | sed -n 's/^host: //p')"
    fi
fi
case "$target" in
    universal)
        targets=(aarch64-apple-darwin x86_64-apple-darwin)
        arch=universal
        ;;
    aarch64-apple-darwin)
        targets=("$target")
        arch=arm64
        ;;
    x86_64-apple-darwin)
        targets=("$target")
        arch=x86_64
        ;;
    *) die "unsupported target: $target" ;;
esac
for t in "${targets[@]}"; do
    has_target "$t" || die "target $t is not installed (rustup target add $t)"
done

# Release binaries; sessions stay disabled (no unaudited-dev).
export MACOSX_DEPLOYMENT_TARGET=13.0
for t in "${targets[@]}"; do
    cargo build --release --locked --target "$t" -p todoke-desktop -p todoke-cli
done

rm -rf "$work"
app="$work/todoke.app"
contents="$app/Contents"
mkdir -p "$contents/MacOS" "$contents/Resources" "$contents/Library/LaunchAgents" "$dist"

for bin in todoke-desktop todoke; do
    slices=()
    for t in "${targets[@]}"; do
        slices+=("$root/target/$t/release/$bin")
    done
    lipo -create -output "$contents/MacOS/$bin" "${slices[@]}"
done

sed "s/@VERSION@/$version/g" "$here/Info.plist" > "$contents/Info.plist"
printf 'APPL????' > "$contents/PkgInfo"
cp "$root/packaging/icons/todoke.icns" "$contents/Resources/todoke.icns"
cp "$here/org.todoke.todoke.agent.plist" "$contents/Library/LaunchAgents/"
cp "$root/LICENSE-APACHE" "$root/LICENSE-MIT" "$contents/Resources/"

# The Share extension: an executable whose entry point is NSExtensionMain.
appex="$contents/PlugIns/TodokeShare.appex"
mkdir -p "$appex/Contents/MacOS"
sed "s/@VERSION@/$version/g" "$here/ShareExtension/Info.plist" > "$appex/Contents/Info.plist"
sdk="$(xcrun --sdk macosx --show-sdk-path)"
swift_slices=()
for t in "${targets[@]}"; do
    swift_arch="${t%%-*}"
    [[ "$swift_arch" == aarch64 ]] && swift_arch=arm64
    out="$work/TodokeShare-$swift_arch"
    xcrun --sdk macosx swiftc -O -whole-module-optimization -parse-as-library \
        -application-extension -swift-version 5 -module-name TodokeShare \
        -target "$swift_arch-apple-macos13.0" -sdk "$sdk" -framework AppKit \
        -Xlinker -application_extension -Xlinker -e -Xlinker _NSExtensionMain \
        -o "$out" "$here/ShareExtension/ShareViewController.swift"
    swift_slices+=("$out")
done
lipo -create -output "$appex/Contents/MacOS/TodokeShare" "${swift_slices[@]}"

for plist in "$contents/Info.plist" "$appex/Contents/Info.plist" \
    "$contents/Library/LaunchAgents/org.todoke.todoke.agent.plist"; do
    plutil -lint -s "$plist"
done

# Entitlements: the keychain access group only with a profile authorising it.
app_entitlements=()
if [[ -n "$identity" && -n "${MACOS_TEAM_ID:-}" && -n "${MACOS_PROVISIONING_PROFILE:-}" ]]; then
    [[ "$MACOS_TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] || die "MACOS_TEAM_ID is not a team ID"
    cp "$MACOS_PROVISIONING_PROFILE" "$contents/embedded.provisionprofile"
    sed -e "s/\$(TeamIdentifierPrefix)/$MACOS_TEAM_ID./g" \
        -e "s/\$(TeamIdentifier)/$MACOS_TEAM_ID/g" \
        "$here/todoke.entitlements" > "$work/todoke.entitlements"
    plutil -lint -s "$work/todoke.entitlements"
    app_entitlements=(--entitlements "$work/todoke.entitlements")
elif [[ -n "$identity" ]]; then
    echo "warning: no MACOS_TEAM_ID and MACOS_PROVISIONING_PROFILE: signing without the keychain access group" >&2
fi

sign() {
    local args=(--force --sign "${identity:--}")
    if [[ -n "$identity" ]]; then
        args+=(--options runtime --timestamp)
    fi
    codesign "${args[@]}" "$@"
}

# Inner-most first: the extension, the command, then the app.
sign --entitlements "$here/ShareExtension/TodokeShare.entitlements" "$appex"
sign --identifier org.todoke.todoke.cli "$contents/MacOS/todoke"
sign ${app_entitlements[@]+"${app_entitlements[@]}"} "$app"
codesign --verify --deep --strict "$app"

notarize() {
    local result
    result="$work/notary-${1##*/}.json"
    xcrun notarytool submit "$1" --key "$MACOS_NOTARY_KEY" --key-id "$MACOS_NOTARY_KEY_ID" \
        --issuer "$MACOS_NOTARY_ISSUER" --wait --output-format json > "$result" || true
    if [[ "$(plutil -extract status raw -o - "$result" 2> /dev/null)" != Accepted ]]; then
        cat "$result" >&2
        local id
        if id="$(plutil -extract id raw -o - "$result" 2> /dev/null)"; then
            xcrun notarytool log "$id" --key "$MACOS_NOTARY_KEY" --key-id "$MACOS_NOTARY_KEY_ID" \
                --issuer "$MACOS_NOTARY_ISSUER" >&2 || true
        fi
        die "notarization of $(basename "$1") failed"
    fi
}

notarizing=false
if [[ -n "${MACOS_NOTARY_KEY_ID:-}" && -n "${MACOS_NOTARY_ISSUER:-}" && -n "${MACOS_NOTARY_KEY:-}" ]]; then
    [[ -n "$identity" ]] || die "notarization needs MACOS_SIGNING_IDENTITY"
    notarizing=true
    ditto -c -k --sequesterRsrc --keepParent "$app" "$work/notarize.zip"
    notarize "$work/notarize.zip"
    xcrun stapler staple "$app"
fi

zip="$dist/todoke-$version-macos-$arch.zip"
dmg="$dist/todoke-$version-macos-$arch.dmg"
rm -f "$zip" "$dmg"
ditto -c -k --sequesterRsrc --keepParent "$app" "$zip"

staging="$work/dmg"
mkdir -p "$staging"
ditto "$app" "$staging/todoke.app"
ln -s /Applications "$staging/Applications"
hdiutil create -quiet -volname todoke -srcfolder "$staging" -fs HFS+ -format UDZO -ov "$dmg"
if [[ -n "$identity" ]]; then
    codesign --force --sign "$identity" --timestamp "$dmg"
fi
if [[ "$notarizing" == true ]]; then
    notarize "$dmg"
    xcrun stapler staple "$dmg"
fi

echo "$zip"
echo "$dmg"
