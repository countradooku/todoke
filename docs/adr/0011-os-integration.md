# ADR 0011: Desktop OS integration and packaging

- **Status:** accepted on 2026-10-14. The maintainer delegated the design
  with the standing priority of maximum security first, then performance.
  Where the P13 build prompt and PROTOCOL differ, PROTOCOL wins.
- **Date:** 2026-10-14
- **Scope:**
  - `todoke-sys-macos`, `todoke-sys-windows`, `todoke-sys-linux` (the OS
    bindings), and the new `todoke-shell-windows` (the Explorer command)
  - the platform key store in `todoke-core` (`storage_key`, §16 O9) and its
    adapters in `todoke-daemon` (`keys`)
  - the handoff endpoint (`todoke-daemon::handoff`)
  - in `todoke-desktop`: launching, the "Send to…" picker, the tray,
    notifications, the global shortcut, Settings → This computer, the icons
  - `packaging/`, `.github/workflows/packaging.yml`, `deny-desktop.toml`,
    the supply-chain store

## Context

The P13 prompt asks to integrate the desktop app with each OS through the
three platform crates:

- Windows: an Explorer context menu (`IExplorerCommand`), a Share target, a
  tray icon, toast notifications, autostart, and a signed MSIX with winget
  and Scoop manifests.
- macOS: a Share extension, a Finder Quick Action, a menu-bar item,
  notifications, a login item, a notarised `.app`, and a Homebrew cask.
- Linux: Nautilus, Dolphin, and Nemo actions, a StatusNotifierItem tray,
  notifications, XDG portals for file access, a Flathub-ready Flatpak, an
  AppImage, `.deb` and `.rpm`, an AUR `PKGBUILD`, and a nix expression.
- A global shortcut that sends the clipboard or the selection to a
  contact.
- Platform key stores: the Keychain (wrapped by a Secure Enclave key where
  present), DPAPI and the TPM, and the Secret Service.

Acceptance: install, uninstall, and upgrade tested in CI VMs per OS; the
context-menu send works end to end; no admin rights for normal use.

The window is a client of the core and makes no consent decision (ADR
0010). Every integration below only *asks* the window to send something;
the user still chooses who receives it, and nothing is ever received
without the receive sheet.

## Decisions

### Where the code lives

- **The platform crates are OS bindings only.** They do not depend on the
  core (so they cross-compile and lint from any host: the core needs
  AWS-LC's C build). The daemon adapts the key stores (`keys.rs`); the
  desktop adapts the rest (`system.rs`).
- **A `desktop` feature** in each platform crate holds what only the app
  needs (login items, file-manager items, portals, Services, the Share
  target). The daemon and the CLI build the key store alone: the code that
  holds the storage key links no AppKit class, WinRT projection, or portal
  client.
- **Cross-platform pieces stay in the desktop crate:** the tray
  (`tray-icon`, with its `ksni` backend on Linux, no GTK) and the global
  shortcut (`global-hotkey`). Splitting one crate's use across three
  platform crates would only copy it.
- **The Explorer command is its own crate** (`todoke-shell-windows`, a
  `cdylib` loaded by Explorer's COM surrogate): it must not link the app.

### The storage key in the platform's store (§16 O9)

- `Selected` in the core chooses where the storage key lives, per the
  `key_storage` setting (`auto`, the default; `platform`; `file`). A
  marker beside the state (`storage.backend`, `file` or `platform`) makes
  the choice sticky: once a key is in the platform store it never moves
  back to a file, and a later failure of the store is an error, never a
  silent fallback to a new key.
- **Migration** from an existing key file: store in the platform, read it
  back, compare, and record the marker; the move is then done. The file is
  renamed aside (so its name never holds a partly wiped key), overwritten,
  and deleted; if that fails, the next start finishes it (a leftover file
  that holds the same key goes; any other stays, unused). A wiped
  (all-zero) key file is never taken for a key, and nothing reads the file
  once the marker says "platform". A key already in the store that differs
  from the file's is never overwritten: under `auto` the profile keeps its
  key file, under `platform` the start fails.
- **The stores name the key by the profile's ID** (`storage.id`: 32 random
  hexadecimal digits beside the state, made once), not by the state
  directory's path: moving or renaming the directory keeps its key.
- Every write that matters is durable: files are synced, then their
  directory (Unix), before the next step.
- The Keychain store adds items only (`SecItemAdd`), never updating one;
  DPAPI's blob is written aside and linked into place (never torn, never
  replaced).
- **macOS:** the data-protection keychain, readable only while the Mac is
  unlocked and never synchronised or migrated, the key wrapped by a P-256
  key in the Secure Enclave (ECIES, X9.63 SHA-256, AES-GCM) when the build
  is entitled to a keychain access group. Unsigned builds fall back to the
  login keychain (its access list names the binary).
- **Windows:** DPAPI under the user's logon (`CRYPTPROTECT_UI_FORBIDDEN`,
  entropy naming the profile), wrapped first by a non-exportable RSA-2048
  key of the TPM's Platform Crypto Provider (OAEP SHA-256) where present.
- **Linux:** the Secret Service (GNOME Keyring, KWallet, KeePassXC) over the
  session bus, through `zbus` 6 (its async API, each call run to
  completion by `zbus::block_on`: 6.0 has no blocking API; the desktop
  graph also has zbus 5 through GPUI and the tray and notification crates
  until they move to 6; `oo7` would duplicate RustCrypto crates). A keyring with no default collection uses GNOME's
  login keyring or creates one, as libsecret does. A prompt (unlocking,
  creating) waits at most two minutes, then is dismissed and the store
  counts as unavailable. Signals are matched against the service's unique
  bus name. Without a session bus (a server) the store is unavailable and
  `auto` keeps the key file.
- **Flatpak:** the sandbox gets no access to the keyring (no
  `org.freedesktop.secrets`, which would expose every item in it). The
  storage key is sealed in a file beside the state (ChaCha20-Poly1305,
  the profile's ID as associated data) under the app's own secret from the
  Secret portal, which the desktop's keyring keeps and gives only to this
  app (`KeyProtection::Portal`).
- The status reports what protects the key (`key_protection`); the CLI and
  Settings show it.
- The core's, daemon's, CLI's, and desktop's tests never touch the
  developer's keyring: they set `key_storage = File`. The platform crates'
  own tests use a throwaway item of their own (a random name) in the real
  store, and remove it.

### One window per profile, and the handoff

- A launch first tries the running window's **handoff endpoint**
  (`paths.handoff_endpoint()`), authenticated like the daemon's: the
  socket or pipe is the user's alone, and a token from the private state
  directory proves the caller is this user. It sends its request (show;
  send these absolute paths, at most 10,000, in parts under the message
  limit that the window gathers; send the clipboard) and exits. Only when
  no window listens does it open one, after taking the profile's instance
  lock (`desktop.lock`, held for the window's life): concurrent cold
  starts (Explorer starts one per selected file) wait for the first
  window and hand over to it. A window that does not take a request is
  reported, never answered with a second window.
- The endpoint serves up to eight connections at once (more are closed),
  each authenticated within two seconds and finished within five: a
  silent or hostile local client cannot hold it.
- Bare paths on the command line are sends too, as "Open With" passes
  them (Finder, the Linux desktop entry, Flatpak).
- File managers, the Explorer command, the Quick Action, the Share target,
  the tray, the Dock, and notifications all end up as such requests.
- **Every send asks.** A handed-over send opens the "Send to…" picker: the
  user picks contacts (those selected on Home are preselected) and presses
  Send. The picker shows the first paths (escaped) and how many more and,
  for text, its length and start. Send stays disabled for the decision
  delay after the picker opens or changes, and whenever the window comes
  to the front (under the pointer); the receive sheet's decisions re-arm
  the same way. Closing the window drops an open picker and what it held.
- **Requests are taken when the picker opens.** The clipboard is read then,
  not when Send is pressed: what the user sees is what is sent.
- Explorer starts one process per selected item for registry verbs; paths
  handed over while a picker of paths is open join it (and re-arm the
  delay).
- `--send-stdin` reads NUL-terminated UTF-8 paths from standard input (at
  most 8 MiB): the Explorer command uses it, so no command-line limit and no
  temporary file.

### Running in the background

- The **tray** (Windows), **menu-bar item** (macOS), or **StatusNotifierItem**
  (Linux): Open, Send clipboard…, Quit. While it exists, closing the window
  keeps the view and the core it hosts running; a request reopens the
  window. Without it (a Linux session with no StatusNotifierItem host,
  checked on the bus before showing one) closing quits, as before: an app
  that runs with nothing to show it would be lost to the user.
- **Notifications** (GPUI's system notifications: Notification Center,
  Windows toasts, the freedesktop service) while the window is not in
  front: an offer waiting (sender's fingerprint name and counts, never a
  file name, since lock screens show them), and a transfer's end. They
  have no buttons: an offer is decided in the window. A notification goes
  when its offer does. Activating one shows the window.
- `--background` starts without showing the window (login items use it).

### Starting at login (no admin rights)

- **macOS:** a launch agent inside the bundle
  (`Contents/Library/LaunchAgents/org.todoke.todoke.agent.plist`, running
  `todoke-desktop --background`), registered with `SMAppService` (macOS 13).
  The user sees and can remove it in System Settings → Login Items; when
  macOS wants approval, the app opens that pane.
- **Windows:** the package's startup task (`windows.startupTask`, off until
  the user turns it on; enabling goes through `StartupTask`; it cannot pass
  `--background`, so the app reads its activation kind), or for
  unpackaged installs this user's `Run` key. Both honour Task Manager's
  Startup apps switch.
- **Linux:** an XDG autostart entry in `~/.config/autostart` (an AppImage
  starts its image, not its mount), or inside Flatpak the Background portal
  (the desktop asks the user and keeps the entry; the app cannot read it
  back, so Settings says so).

### Sending from the file manager

- **macOS:** the bundle declares two services (`NSServices`): "Send with
  todoke" for files and folders (Finder's Quick Actions and context menu)
  and for selected text in any app (the Services menu); a provider object
  answers them in the running app (macOS starts it first). A Share
  extension (`TodokeShare.appex`, sandboxed, read-only access to what is
  shared) opens the shared files with the app.
- **Windows:** the MSIX declares an Explorer command (`IExplorerCommand`,
  `desktop4:FileExplorerContextMenus`, a COM surrogate), at the top of the
  Windows 11 menu, and a Share target (`windows.shareTarget`, any file).
  Unpackaged installs (Scoop, the zip) offer per-user registry verbs in
  Settings (in Windows 11's "Show more options").
- **Linux:** packages install a Dolphin service menu, a Nemo action, and a
  Nautilus extension (`nautilus-python`) for every user. Without a package
  (an AppImage, a binary), Settings adds a Dolphin service menu, a Nemo
  action, and a Nautilus script for this user. Inside Flatpak no app may
  add them: the app is an "Open With" choice instead.
- Desktop-entry `Exec` values are quoted and escaped per the specification
  (`desktop_entry::quote`), shell ones single-quoted; a path with a control
  character is refused.

### The global shortcut

- ⌃⌥⌘T on macOS, Ctrl+Alt+Shift+T elsewhere; on by default except on
  Wayland, where turning it on asks the desktop. Settings switches it.
- macOS, Windows, and X11 register it with the system (`global-hotkey`:
  Carbon hot keys, `RegisterHotKey`, an X11 grab): no accessibility
  permission and no view of other keystrokes. Wayland lets no app grab
  keys: there it is bound through the `GlobalShortcuts` portal (KDE Plasma,
  GNOME 48 and later), which asks the user and may let them choose other
  keys.
- It opens the picker with the clipboard, or on Linux the text selected
  anywhere (the primary selection) when there is some. On macOS the
  selection is sent through the Services menu instead (above).

### XDG portals

- File access goes through portals where the app is sandboxed: GPUI's file
  chooser uses the FileChooser portal, dropped files arrive through the
  Documents portal, autostart through Background, the shortcut through
  GlobalShortcuts.
- Portal requests subscribe to the answer before calling, use the
  `handle_token` path, and run on the background executor (a dialog may
  wait for the user).

### Packaging

- Formats: a notarised `.app` (zip and DMG) and a Homebrew cask; a signed
  MSIX, a portable zip, winget and Scoop manifests; a Flathub-ready
  Flatpak manifest, an AppImage, `.deb`, `.rpm`, an AUR `PKGBUILD`, and a
  nix expression. Sources and how to build each: `packaging/README.md`.
- The app ID is `org.todoke.todoke` everywhere. Icons are generated from
  the mark drawn in code (`cargo run -p todoke-desktop --example icons
  --features mock`), the same drawing as the tray.
- Signing happens only where a maintainer runs the scripts with the
  signing variables (Developer ID, a provisioning profile for the keychain
  access group, and notarytool on macOS; a code-signing certificate on
  Windows). CI holds no signing secret: its builds are ad-hoc (macOS) or
  test-signed (Windows) and fit only for CI. The keychain entitlement is
  applied only with a provisioning profile, since macOS kills an app whose
  restricted entitlements no profile authorises.
- **No store or registry submission is made by CI.** Flathub, winget,
  Homebrew, and AUR updates are pull requests a maintainer opens.
- `.github/workflows/packaging.yml` builds each package and, per OS in the
  runner VM, installs it, upgrades it to a higher version, and uninstalls
  it (user data kept), where the format allows: the deb, the rpm (in a
  Fedora container), the MSIX, and the macOS bundle and cask are
  installed, upgraded, and removed; the Flatpak is built, installed, run,
  and removed; the AppImage is run; the winget and Scoop manifests are
  validated against the built packages. End to end, it checks that each installed
  integration reaches the running window (`TODOKE_HANDOFF_LOG`, below):
  the Dolphin and Nemo `Exec` lines and the Nautilus extension on Linux,
  the "Send with todoke" service on macOS (`NSPerformService`), and the
  Explorer command through COM on Windows.
- `TODOKE_HANDOFF_LOG`, when set for the first launch, makes the window
  append each request it receives (its kind and paths, never text) to that
  file, owner-only: the end-to-end tests read it.

- Release Windows builds are GUI-subsystem binaries (no console window);
  inside the MSIX, the profile lives in the package's redirected AppData
  and goes with the package on uninstall.
- macOS asks for local-network access (macOS 15): `Info.plist` gives the
  reason and declares the Bonjour service (`_todoke._tcp`).

### No admin rights

Nothing in normal use needs them: the key stores are the user's; login
items, registry verbs, autostart entries, and file-manager items are per
user; the MSIX, the AppImage, the zip, and the `.app` copied to
`~/Applications` install per user. System packages (`.deb`, `.rpm`, AUR,
Homebrew into `/Applications`) need them only to install.

### Supply chain

New crates, all in the desktop graph only (the daemon and the CLI do not
build the `desktop` features): `tray-icon` 0.26.1 and its `muda`, `ksni`,
`dpi`, `keyboard-types`, `crossbeam-channel`, `task-local`;
`global-hotkey` 0.8.0 (it pins `keyboard-types` 0.7 and `windows-sys`
0.59: skipped duplicates in `deny-desktop.toml`);
`objc2-service-management` 0.3.2. `windows` 0.62.2 and `windows-registry`
0.6.1 were already in the desktop graph through GPUI; `objc2` 0.6 through
`tray-icon`. Each is exempted in `supply-chain/config.toml` pending an
audit.

**License exception (needs the maintainer's approval):** `ksni` 0.3.6 is
under the Unlicense (a public-domain dedication, OSI approved), allowed for
that exact version in `deny-desktop.toml` only.

## Residual risks

- **The Secure Enclave path is not exercised in CI.** Only a build signed
  with a keychain access group reaches the data-protection keychain; CI
  builds are unsigned and use the login keychain, where any app the user
  approves ("Always Allow") can read the item. Fix: a signed CI build with
  the entitlement on an Apple-silicon runner running the keychain test.
- **The TPM path is not exercised in CI** (hosted runners have no TPM):
  DPAPI alone is tested. Fix: a runner with a (virtual) TPM.
- **The Secret Service session is "plain":** the key crosses the session
  bus unencrypted. A process of the same user could ask the keyring for it
  anyway, but a bus monitor sees it without asking. Fix: the
  `dh-ietf1024-sha256_aes128_cbc_pkcs7` session (needs a DH and AES-CBC
  implementation in the graph).
- **Any program of this user can open the picker** with paths of its
  choosing (the handoff endpoint, the Services menu, the registry verbs).
  The user still chooses the recipients and presses Send after the delay;
  a program running as the user could read the files itself anyway. Fix
  (defence in depth): mark requests from outside the window in the picker
  ("from another app").
- **The picker shows the start of clipboard text,** so a copied password
  is on screen for a moment. Fix: honour concealed clipboard markers
  (`org.nspasteboard.ConcealedType`, Windows'
  `ExcludeClipboardContentFromMonitorProcessing`, KDE's
  `x-kde-passwordManagerHint`) by hiding the preview.
- **Registry verbs start one process per selected item** (unpackaged
  Windows): selecting thousands of files starts thousands of processes.
  Fix: register the Explorer command for unpackaged installs too (a sparse
  package with external location).
- **Wayland's shortcut needs the GlobalShortcuts portal**; GNOME before 48
  has none, so there is no shortcut there.
- **Closing the window on Linux without a tray host quits** (GNOME without
  the AppIndicator extension): receiving then stops with the window. Fix:
  a background portal request plus a notification-only presence, or the
  daemon as a user service.
- **The Share extension and the Explorer command load only when signed**
  (macOS) or packaged (Windows): CI builds them and checks their bundles
  and manifests, and drives the Explorer command's COM entry and the
  Services provider, but no CI test clicks Finder's Share menu or
  Explorer's context menu. Fix: UI automation on signed builds.
- **Uninstalling the MSIX deletes the profile** (Windows removes the
  package's redirected AppData): contacts and history go with it. Fix:
  `desktop6` unvirtualized resources (a restricted capability) or an
  export before uninstall.
- **The handoff log is production code** behind an environment variable:
  it writes paths (never text) only to a file the person starting the app
  names, owner-only and never through a link.
- **macOS: the app and the command line cannot share a Secure Enclave
  wrapped key.** The keychain access group belongs to the signed app; the
  `todoke` command in the bundle (and `todoke daemon run`) has no
  entitlement, so it cannot read a key the app keeps in the
  data-protection keychain: with the marker at "platform" it refuses to
  start rather than make a new key. Fix: one process hosts the core (the
  app, or a launch agent signed with the same entitlement) and the command
  always attaches.
- **The daemon and the CLI now link `zbus` on Linux** (the Secret Service
  and the Secret portal), about 60 crates under the stricter `deny.toml`,
  exempted in cargo-vet pending audits. Since 2026-10-19 that is zbus 6.0.0
  and its new runtime `zruntime` 0.2.0, released three days earlier: zbus
  5's `zvariant`, `zvariant_derive`, and `zbus_names` became unmaintained
  (RUSTSEC-2026-0370..0372) when they were merged into it. Fix: audits of
  `zbus` and `zruntime`, or a smaller D-Bus client.
- **Two zbus versions in the desktop app on Linux.** GPUI's accessibility
  and portals, `ksni`, `notify-rust`, and `oo7` still use zbus 5.19.0;
  `deny-desktop.toml` ignores the three advisories and skips the duplicate
  until they move to zbus 6. Fix: upgrade them when they do.
- **The tray, menu, and shortcut crates run in the process that holds the
  storage key** (the desktop hosts the core): `tray-icon`, `muda`, `ksni`,
  and `global-hotkey` are exempted, not audited. Fix: audit those four
  first; or the daemon hosts the core and the app only attaches.
- **A released global shortcut's listener thread lingers** until the
  portal's connection closes (switching the shortcut off and on leaves one
  idle thread each time). Fix: a stoppable signal stream.
- **Received files go anywhere in `~/Downloads` in Flatpak**
  (`--filesystem=xdg-download`, read-write). Fix: a `todoke` subfolder
  (`xdg-download/todoke:create`) as the Flatpak's default.

## Known test gaps

- macOS: the login item is registered only from an installed, signed
  bundle; CI checks the plist and the bundle's layout, not the
  registration.
- Windows: the startup task and share activation need the installed MSIX
  and a desktop session; CI installs the package but does not log in again.
- Linux: the portals are tested where the runner's desktop lacks them only
  for their refusal; GNOME Keyring under `dbus-run-session` covers the
  Secret Service.

## Not here

- Store submissions (Flathub, winget, Homebrew, AUR) are maintainer pull
  requests, not CI steps.
- Mobile platforms (later prompts).
