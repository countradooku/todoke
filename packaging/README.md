# Packaging

Every way todoke is installed: the desktop app (`todoke-desktop`) and the
command line (`todoke`), built from this workspace with
`cargo build --release --locked -p todoke-desktop -p todoke-cli`. Release
builds keep sessions disabled (PROTOCOL §16); no package enables the
`unaudited-dev` feature.

`.github/workflows/packaging.yml` builds each package and installs,
upgrades, and uninstalls it on a fresh runner (the profile is kept), on
pull requests that touch packaging or the desktop crates, on `v*` tags, and
on demand. With the installed app running, a second launch with `--send`
must reach its window (`TODOKE_HANDOFF_LOG` records what arrives). Its
packages are ad-hoc or test-signed and kept as workflow artifacts for 14
days.

The scripts read the version from `Cargo.toml` (`scripts/packaging/version.sh`)
and write to `dist/` (`TODOKE_DIST` overrides). `TODOKE_PACKAGE_VERSION`
overrides the package version, for upgrade tests.

## Layout

| Directory | What it holds |
| --- | --- |
| `icons/` | The mark at 16 to 1024 pixels, `todoke.ico`, `todoke.icns`, `todoke.svg`. Regenerate with `cargo run -p todoke-desktop --example icons --features mock`. |
| `macos/` | `Info.plist`, the login agent, entitlements, the Share extension (Swift), and `build-app.sh`. |
| `homebrew/` | The cask template. |
| `windows/` | `AppxManifest.xml`, `build-msix.ps1`, `build-zip.ps1`, and the winget and Scoop manifests. |
| `linux/` | The desktop entry, AppStream metadata, file-manager items, `build-deb.sh`, `build-rpm.sh`, `build-appimage.sh`, the RPM spec, the Flatpak manifest, and the AUR `PKGBUILD`. |
| `nix/` | `package.nix` (`rustPlatform.buildRustPackage`) and `default.nix`. |

## macOS

```sh
rustup target add aarch64-apple-darwin x86_64-apple-darwin   # for a universal build
packaging/macos/build-app.sh            # universal if both targets are installed, else the host
packaging/macos/build-app.sh aarch64-apple-darwin
```

The script builds `target/packaging/macos/todoke.app`, then
`dist/todoke-<version>-macos-<arch>.zip` and `.dmg` (`arch` is `arm64`,
`x86_64`, or `universal`). The bundle holds:

- `Contents/MacOS/todoke-desktop` and `Contents/MacOS/todoke`;
- `Contents/Library/LaunchAgents/org.todoke.todoke.agent.plist`, the login
  item the app registers with `SMAppService` (macOS 13);
- `Contents/PlugIns/TodokeShare.appex`, the Share menu extension. It opens
  the shared files with the containing app. macOS loads it only when it is
  signed.

`Info.plist` declares the Finder Quick Action and Services menu items
(`NSServices`), and lists the app in Open With for every file and folder
without claiming any.

Signing, innermost first (the extension, the command, the app):

| Variable | Effect |
| --- | --- |
| none | Ad-hoc signature (`codesign -s -`); runs on the machine that built it. |
| `MACOS_SIGNING_IDENTITY` | Developer ID Application signature, hardened runtime, secure timestamp. The dmg is signed too. |
| `MACOS_TEAM_ID` and `MACOS_PROVISIONING_PROFILE` | With the identity: applies `todoke.entitlements` (the keychain access group for the data-protection keychain) and embeds the Developer ID provisioning profile that authorises it. Without them the app uses the file-based keychain. |
| `MACOS_NOTARY_KEY_ID`, `MACOS_NOTARY_ISSUER`, `MACOS_NOTARY_KEY` | An App Store Connect API key (the last is the path to the `.p8`): notarizes the app with `notarytool submit --wait` and staples it, then the dmg. |

Homebrew: `homebrew/todoke.rb` is a cask template for the universal zip.
Fill `@VERSION@` and `@SHA256@` (`shasum -a 256`).

## Windows

```powershell
cargo build --release --locked -p todoke-desktop -p todoke-cli -p todoke-shell-windows
./packaging/windows/build-msix.ps1 -Arch x64     # dist\todoke-<version>-windows-x64.msix
./packaging/windows/build-zip.ps1 -Arch x64      # dist\todoke-<version>-windows-x64.zip
```

`build-msix.ps1` needs the Windows SDK (`makeappx`, `signtool`). The MSIX
holds both executables, aliased as `todoke-desktop.exe` and `todoke.exe`;
a startup task (off until the app's settings turn it on); a share target;
and, when `todoke_shell.dll` is built, "Send with todoke" in Explorer (an
`IExplorerCommand` COM server, Windows 10 2004 and later). Without the DLL
the package is built without the Explorer command, with a warning.

The portable zip (Scoop, winget's portable installer) has no COM command:
unpackaged, the app writes per-user registry verbs (HKCU) itself.

Signing:

| Variable | Effect |
| --- | --- |
| `WINDOWS_CERT_PFX`, `WINDOWS_CERT_PASSWORD` | A code-signing `.pfx` and its password: signs the executables, the DLL, and the package, timestamped (`WINDOWS_TIMESTAMP_URL`, default DigiCert's). The package's Publisher becomes the certificate's subject. |
| `WINDOWS_PUBLISHER` | Overrides the Publisher (it must equal the certificate's subject). |
| none | The MSIX is signed with a throwaway self-signed certificate for `CN=todoke`, exported as `dist\todoke-test-signing.cer`. Installing it requires trusting that certificate in `Cert:\LocalMachine\TrustedPeople` (admin): for CI and local tests only. The zip's executables are unsigned. |

The certificate is imported into the user's store for the build and
removed, with its private key, afterwards.

Manifests: `winget/` (ManifestVersion 1.10.0; fill `@VERSION@`,
`@SHA256_MSIX_X64@`, `@SHA256_ZIP_X64@`, then `winget validate --manifest
packaging/windows/winget`) and `scoop/todoke.json` (fill `version` and
`hash`; `checkver` and `autoupdate` keep it current in a bucket). The
profile lives in `%APPDATA%\todoke` and `%LOCALAPPDATA%\todoke`, outside
Scoop's directories, so nothing is persisted by Scoop.

## Linux

```sh
bash scripts/ci/install-desktop-deps.sh          # build libraries (Ubuntu)
sudo apt-get install clang cmake rpm             # aws-lc-sys needs a C toolchain and cmake
cargo build --release --locked -p todoke-desktop -p todoke-cli
export TODOKE_BIN_DIR=target/release             # else each script runs cargo itself
packaging/linux/build-deb.sh                     # dist/todoke_<version>_<arch>.deb
packaging/linux/build-rpm.sh                     # dist/todoke-<version>-1.<arch>.rpm
packaging/linux/build-appimage.sh                # dist/todoke-<version>-<arch>.AppImage
```

System packages (deb, rpm, AUR, Nix) install:

| Path | What |
| --- | --- |
| `/usr/bin/todoke-desktop`, `/usr/bin/todoke` | The binaries. |
| `/usr/share/applications/org.todoke.todoke.desktop` | The desktop entry (with a "Send Clipboard" action). |
| `/usr/share/metainfo/org.todoke.todoke.metainfo.xml` | AppStream metadata. |
| `/usr/share/icons/hicolor/*/apps/org.todoke.todoke.*` | Icons, 16 to 512 pixels and scalable. |
| `/usr/share/kio/servicemenus/org.todoke.todoke.desktop` | Dolphin: "Send with todoke". |
| `/usr/share/nemo/actions/todoke.nemo_action` | Nemo. |
| `/usr/share/nautilus-python/extensions/todoke.py` | Files (Nautilus), with nautilus-python. |

Installs without a package (an AppImage, a bare binary) add the same
file-manager items for the user from the app's settings
(`todoke-sys-linux`). The AppImage links the system's libraries, like the
deb; its glibc floor is the build machine's. Started through a symbolic
link named `todoke`, it runs the command line.

`build-rpm.sh` packages the prebuilt binaries with `rpm/todoke.spec`
(`rpmbuild` builds nothing and needs no network). `build-appimage.sh`
downloads appimagetool 1.9.1 and the type2 runtime 20251108 once into
`target/packaging/tools`, and refuses them unless their SHA-256 matches the
pinned digests.

Flatpak (`linux/flatpak/org.todoke.todoke.yml`, freedesktop 26.08 with the
rust-stable extension) builds offline from `cargo-sources.json`, which is
generated, not committed:

```sh
python3 flatpak-cargo-generator.py Cargo.lock -o packaging/linux/flatpak/cargo-sources.json
flatpak-builder --user --install-deps-from=flathub --install --force-clean \
    build-dir packaging/linux/flatpak/org.todoke.todoke.yml
flatpak run --command=todoke org.todoke.todoke --version
```

The generator is flatpak-builder-tools' `cargo/flatpak-cargo-generator.py`;
the workflow pins its commit and SHA-256. In the sandbox the app uses
portals (file chooser, Background for autostart, GlobalShortcuts), and
talks to the tray watcher, the Secret Service, and notifications.

AUR: `linux/aur/PKGBUILD` builds the tagged source tarball with
`cargo build --frozen --release`; run `updpkgsums` and
`makepkg --printsrcinfo > .SRCINFO` for each release.

Nix: `nix-build packaging/nix`. The wrapper puts Vulkan, EGL, Wayland, and
xkbcommon on `LD_LIBRARY_PATH`; the renderer loads them at run time.

## Not automated

- No release is published by CI, and the packaging workflow uses no
  signing secrets. Signed packages come from running the scripts with the
  variables above (a maintainer, or a release job that holds the secrets),
  and are attached to the GitHub release by hand.
- No store or repository submission is made. Flathub (a PR to
  `flathub/flathub` with a manifest using the tag's git source), winget (a
  PR to `microsoft/winget-pkgs`, e.g. with `wingetcreate update`),
  Homebrew (a PR to a tap or `homebrew/cask`), Scoop (a bucket), and the
  AUR (a push of `PKGBUILD` and `.SRCINFO`) are manual, by a maintainer.
- Microsoft Store and Mac App Store: not prepared.
