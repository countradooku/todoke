# todoke for Nix: the desktop app, the command line, and the Linux
# desktop integration. Build with `nix-build packaging/nix`.
{
  lib,
  rustPlatform,
  pkg-config,
  cmake,
  makeWrapper,
  fontconfig,
  freetype,
  libxkbcommon,
  wayland,
  xorg,
  vulkan-loader,
  libGL,
}:

let
  workspace = (lib.importTOML ../../Cargo.toml).workspace.package;
in
rustPlatform.buildRustPackage {
  pname = "todoke";
  inherit (workspace) version;

  src = lib.fileset.toSource {
    root = ../..;
    fileset = lib.fileset.unions [
      ../../Cargo.toml
      ../../Cargo.lock
      ../../crates
      ../../packaging/icons
      ../../packaging/linux
      ../../LICENSE-APACHE
      ../../LICENSE-MIT
    ];
  };

  cargoLock.lockFile = ../../Cargo.lock;
  # Release build: sessions stay disabled (no unaudited-dev).
  cargoBuildFlags = [
    "-p"
    "todoke-desktop"
    "-p"
    "todoke-cli"
  ];
  # The workspace's tests run in CI; they read spec/ vectors outside this source.
  doCheck = false;

  # cmake builds aws-lc-sys from its build script, not this package.
  dontUseCmakeConfigure = true;
  nativeBuildInputs = [
    pkg-config
    cmake
    makeWrapper
  ];
  buildInputs = [
    fontconfig
    freetype
    libxkbcommon
    wayland
    xorg.libX11
    xorg.libxcb
  ];

  postInstall = ''
    install -Dm644 packaging/linux/org.todoke.todoke.desktop $out/share/applications/org.todoke.todoke.desktop
    install -Dm644 packaging/linux/org.todoke.todoke.metainfo.xml $out/share/metainfo/org.todoke.todoke.metainfo.xml
    for size in 16 24 32 48 64 128 256 512; do
      install -Dm644 packaging/icons/todoke-$size.png \
        $out/share/icons/hicolor/''${size}x''${size}/apps/org.todoke.todoke.png
    done
    install -Dm644 packaging/icons/todoke.svg $out/share/icons/hicolor/scalable/apps/org.todoke.todoke.svg
    install -Dm644 packaging/linux/dolphin/org.todoke.todoke.desktop $out/share/kio/servicemenus/org.todoke.todoke.desktop
    install -Dm644 packaging/linux/nemo/todoke.nemo_action $out/share/nemo/actions/todoke.nemo_action
    install -Dm644 packaging/linux/nautilus/todoke.py $out/share/nautilus-python/extensions/todoke.py
  '';

  # The renderer (wgpu) loads Vulkan or EGL, and the Wayland client and
  # keymap libraries, at run time.
  postFixup = ''
    wrapProgram $out/bin/todoke-desktop \
      --prefix LD_LIBRARY_PATH : ${
        lib.makeLibraryPath [
          vulkan-loader
          libGL
          wayland
          libxkbcommon
        ]
      }
  '';

  meta = {
    description = "End-to-end encrypted file transfer between your devices";
    homepage = "https://github.com/countradooku/todoke";
    license = with lib.licenses; [
      asl20
      mit
    ];
    mainProgram = "todoke-desktop";
    platforms = lib.platforms.linux;
  };
}
