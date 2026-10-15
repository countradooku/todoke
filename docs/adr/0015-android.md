# ADR 0015: The Android app

- **Status:** accepted on 2026-10-15. The maintainer chose Material 3
  Expressive although it is in beta ("use expressive even if it's in beta")
  and approved installing the Android SDK (accepting Google's licence); the
  rest of the design was delegated with the standing priority of maximum
  security first, then performance. Where the P16 build prompt and
  PROTOCOL differ, PROTOCOL wins (below).
- **Date:** 2026-10-15
- **Scope:**
  - `apps/android` (the app, its tests, and the `baselineprofile` module)
    and `.github/workflows/android.yml`
  - `todoke-ffi`: files handed over open (`ContactHandle::send_files`,
    `fds.rs`), the Android API level (`android.rs`), the AAR's Kotlin
    sources
  - `todoke-fs::platform` and Android publication; `todoke-core`'s
    `write_new` for `storage.id` and the sealed key file

## Context

The P16 prompt asks for `apps/android` in Kotlin and Jetpack Compose
(Material 3 Expressive) on the BoltFFI AAR, minSdk 24, 32-bit ARM, APKs
under 15 MB, with:

- the desktop's screens (P12) and the mockup's settings screen;
- a share target with Direct Share shortcuts, a Quick Settings tile, a
  widget;
- a foreground service for active transfers with an ongoing notification,
  WorkManager for resumes;
- QR scanning with CameraX and a decoder without Google Play Services;
- the Android Keystore (StrongBox, else the TEE) with BiometricPrompt;
- storage through SAF, quarantine in app-private storage;
- `play` and `fdroid` flavors, nothing proprietary in `fdroid`;
- acceptance: Compose UI tests for every flow, Baseline Profiles, a cold
  start under 1 s on a mid-range device, a TalkBack pass, and a run on a
  de-Googled ROM.

## Decisions

### Toolchain and targets

| | |
| --- | --- |
| Build | Gradle 9.8.1, AGP 9.4.1 (built-in Kotlin), Kotlin 2.4.21, Java 17 bytecode |
| UI | Compose BOM 2026.09.00, Material 3 1.5.0-beta01: `MaterialExpressiveTheme` with `MotionScheme.expressive()`, dynamic colour on Android 12 and later |
| SDK | minSdk 24 (Android 7), compileSdk and targetSdk 37: Compose 1.12 needs compileSdk 37; targeting 37 brings Android 17's local-network permission |
| ABIs | one APK per ABI: arm64-v8a, armeabi-v7a, x86_64 (the AAR also carries x86) |
| Size | release APKs 8.7 MB (armeabi-v7a) to 9.8 MB (arm64-v8a), the Baseline Profile included; native libraries uncompressed and page-aligned (16 KB) |

Every dependency is pinned in `gradle/libs.versions.toml`, and
`gradle/verification-metadata.xml` checks each artifact's SHA-256
(generated from an empty Gradle home).

### Screens: where PROTOCOL differs from the prompt

| Prompt (P12 screens) | Android | Why |
| --- | --- | --- |
| visibility "everyone, 10 min" | "Everyone, for 5 minutes (pair with a code)" | §9 caps stranger mode at 300 seconds and requires pairing |
| "emoji verification" | none | §3 has no comparison step: a one-time QR secret or a CPace code |
| receive sheet | 700 ms arm delay whenever the offer shown changes; programs and scripts flagged with the desktop's lists; Accept all / Choose / Decline; a resumed offer can only repeat its selection | §7.2 (nothing before consent), §7.5 |

Pairing screens set `FLAG_SECURE` (no screenshots, no recents
thumbnail). The QR is drawn from the core's module matrix with the
4-module quiet zone ISO/IEC 18004 asks for; no offer text crosses to show
it.

### System integration

- **Share target:** `SEND` and `SEND_MULTIPLE` for any type. A share
  intent is untrusted (any app can send one, naming any URI, and todoke
  opens it with its own rights): only content URIs of other apps'
  providers are taken, never a file URI or one of todoke's own providers,
  and the share sheet lists the names before anything is sent. Direct Share
  publishes at most four long-lived sharing shortcuts (reachable contacts
  first). The system keeps their labels (the contact's name) and IDs; an ID
  is HMAC-SHA-256 of the fingerprint under a random key of this install,
  128 bits, so the system's shortcut store never holds a fingerprint; the
  cached shortcuts of contacts no longer shown are removed.
- **Quick Settings tile:** toggles hidden; shows the visibility only.
- **Widget (Glance):** the visibility and a way into the app; no names,
  counts, or transfers on the home screen.
- **Foreground service** (`connectedDevice`): started only from a user
  action (Android 12 forbids starting one from the background), an ongoing
  notification with the total progress, stopped when nothing moves.
- **WorkManager:** a periodic job (15 minutes, network required) starts
  the core so it reconnects and resumes interrupted transfers; it does
  nothing while the key is gated and the app locked.
- **Notifications:** an offer shows the sender's name and counts, with
  `VISIBILITY_PRIVATE` (hidden on a secure lock screen); never file names.
- **Permissions:** `INTERNET`, network and Wi-Fi state, multicast (mDNS
  needs a `MulticastLock`), `ACCESS_LOCAL_NETWORK` (asked before the core
  starts on Android 17), notifications, the foreground service, the camera
  (scanning only), and biometrics. No location, no Bluetooth, no storage
  permission (ADR 0014: no radios but the LAN).

### QR scanning

CameraX 1.6.2 feeds ZXing core 3.5.4 (Apache-2.0, pure Java), which reads
only QR codes and passes on only text starting with `TODOKE:`. No Play
Services, no ML Kit, in either flavor. The camera is released as soon as
the scanner leaves the screen.

**Conflict with §16 O5 (recorded, not resolved):** the scanned text, the
QR's one-time secret included, exists as a Kotlin `String` before
`Core::pair_scan_qr` takes it, and a `String` cannot be wiped. The
camera's decoder runs in the app, so the text must cross; showing a QR
needs no text.

### Keys: Keystore and BiometricPrompt

The core's 32-byte storage key (ADR 0012: the one secret that crosses) is
wrapped by an AES-256-GCM key in the Android Keystore, StrongBox when the
device has it, else the TEE; the blob (version, IV, ciphertext and tag,
the profile's ID as associated data) lives in `noBackupFilesDir`.

When the device has a secure lock screen at the app's first launch, the key
is gated (decided once, then kept): BIOMETRIC_STRONG or the device
credential, valid for 30 seconds, through BiometricPrompt before the core
starts. The key is not invalidated when a biometric is enrolled:
invalidation would make the sealed state, the identity and every pairing,
unreadable for good, a loss the user cannot undo; the lock screen still
guards enrolment. Removing the screen lock does invalidate it (Android's
rule for keys that need authentication); the app then says the key is
gone instead of asking to unlock again, as it does for a missing or
damaged blob or Keystore key. Settings reports StrongBox only when the
key is known to be there (Android 12 and later can say; the generator
falls back to the TEE).

### Storage

- **Sending:** the user picks documents (`OpenMultipleDocuments`); the app
  opens each and hands the descriptor to the core
  (`ParcelFileDescriptor.detachFd`, `ContactHandle::send_files`). The core
  adopts them after checking each is open, not a standard stream, and
  given once (`fds.rs`), hashes and serves the open file, and never sees a
  path or a copy. Whatever is opened, shared or picked, is refused when
  the open descriptor is one of the app's own files (`/proc/self/fd`
  against the app's data directories, under each of their names).
- **Receiving:** the core receives and publishes into app-private storage
  (`filesDir/received`), with its quarantine in its state directory, as on
  any POSIX system. If the user chose a folder (`OpenDocumentTree`, a
  persisted grant), the app moves what was published there through
  `DocumentsContract` whenever nothing is being received: when the core
  starts, when an incoming transfer ends, and when a folder is chosen. It
  checks the transfers before each file and holds a lock while the file
  moves, which accepting an offer takes too, so an accept never lands
  between the check and the move; before Android 11 it also waits out
  interrupted transfers and keeps a file whose size, time, or inode
  changed during the copy.
  Staged files (`.todoke-` names, which the core never gives a received
  file) and links stay; providers never overwrite (they pick a free name);
  folders are made there only when something moves into them; a file is
  removed here only after its copy there was written and closed, and a
  copy that fails for any reason (a revoked grant included) is removed
  there. Choosing another folder gives the previous grant up. A
  `Destination` over SAF (ADR 0006's plan) was not needed: naming,
  verification, and publication stay in `todoke-fs`, and SAF only ever
  sees finished files.
- **No backups:** `allowBackup="false"` and data-extraction rules that
  exclude everything from cloud backup and device transfer.

### Publication on Android (a defect found here)

The core could not start on Android: `storage.id` and every received file
were put in place with a hard link, and Android's SELinux policy refuses
apps hard links in their own data (`EACCES`; seen on Android 7, 10, 11,
and 16). Now:

- `todoke-fs` renames without replacing (`renameat2(RENAME_NOREPLACE)`) on
  Android 11 and later only: the app seccomp filter allows what bionic's
  `SYSCALLS.TXT` lists, `renameat2` is there from API level 30, and a call
  the filter refuses kills the process. `todoke-ffi` reads
  `ro.build.version.sdk` (one reviewed unsafe call to bionic's
  `__system_property_get`) when a core starts; until it is known,
  `renameat2` is never called.
- A hard link refused with `EACCES` on Android counts as "no hard links":
  Android 7 to 10 publish by the exclusive copy (ADR 0006), and
  `storage.id` and the sealed key file are created exclusively and written
  in place.

### Flavors

`play` and `fdroid` are the same app today. CI fails if the `fdroid`
runtime classpath contains Play Services, Firebase, ML Kit, or a Play
library.

### Startup

A `baselineprofile` module (androidx.baselineprofile and Macrobenchmark
1.5.0, UiAutomator 2.4.0) generates the Baseline Profile and the startup
profile from the first-use journey (open the app, every tab), merged into
`src/main` for both flavors; ProfileInstaller installs it where the store
does not. The app reports itself fully drawn at its first screen that
needs nothing more (Home, an unlock request, or why the core did not
start). Ten cold starts each, with the development libraries in release
mode, on the Android 16 emulator (Apple M5 Pro host):

| | first frame (median) | fully drawn (median, range) |
| --- | --- | --- |
| Baseline Profile | 121 ms | 221 ms (185 to 331) |
| no compilation | 135 ms | 306 ms (222 to 370) |

The benchmark also found a start-up defect, fixed: the core was started
from an effect of the locked screen, which left composition as soon as
the state became Starting, so the start was cancelled half done and the
app stayed on "Opening todoke…". The start now runs once in the
application's scope; callers wait for it and share it.

### Testing

- **UI flows:** Compose tests of every flow (home, accepting whole,
  choosing, declining, programs and resumed offers, pairing by QR and by
  code, cancelling a transfer, hiding) against a scripted backend, with
  the Accessibility Test Framework's checks on every screen (touch targets,
  labels, contrast). They found three touch targets under 48 dp, now fixed.
- **Screenshots** of every screen in both themes (Android 8 and later).
- **Export:** moving, nested folders, staged files and links left alone, a
  free name taken, a failed copy and a revoked grant, nothing moving while
  a file is received, and an accept arriving during the export.
- **Shared documents:** file URIs and todoke's own providers refused,
  private files recognised by their open descriptor (also through the
  data directory's other name); the real-core test checks that sending one
  of the app's own files is refused.
- **Keystore:** a key stored once comes back and is never replaced, the
  given key is wiped, a damaged blob, a gone Keystore key, or another
  profile's blob fails with a reason (not as a refusal), and protection is
  reported from where the key is.
- **Direct Share:** names and opaque IDs only, IDs map back, removed
  contacts leave.
- **The real core in the app's sandbox:** two cores (development
  libraries with loopback discovery) pair by QR, one sends a document
  handed over open, the other publishes it; the sending core's key is in
  the Android Keystore.
- **De-Googled devices:** the whole suite passed on AOSP emulator images
  without Google services: Android 7 (API 24, screenshots skipped), 10,
  11, and 16. CI runs it on AOSP x86_64 emulators of Android 7, 10, and
  16.

## Consequences

- A release build (sessions disabled, PROTOCOL §16) shows why it cannot
  transfer; only development builds move files, as on the desktop.
- Received files sit in app-private storage until the user chooses a
  folder; uninstalling the app deletes those not yet moved.
- On Android 7 to 10 a received file is visible under its name while it is
  copied into place, and a crash can leave a truncated file or a torn
  `storage.id` (which then refuses to start the profile).

## Residual risks

- **Key material in Kotlin memory:** the storage key crosses as a
  `ByteArray` (zeroed after `store`, but the array `load` returns is
  BoltFFI's to copy and the garbage collector's to free), and the scanned
  QR text is a `String`. Fix: a BoltFFI path that wraps and unwraps the key
  in Rust through the Keystore's JNI interface, and scanning that hands the
  core bytes it can wipe.
- **Time-based gate:** after an unlock the key can be used for 30 seconds
  by anything in the process. Fix: per-use authentication
  (`CryptoObject`) for the unwrap, at the cost of a prompt on every start.
- **Non-atomic publication on Android 7 to 10** (above). Fix: none on
  those releases (no rename-without-replace, no links for apps); the
  export already waits for quiet moments.
- **The seccomp threshold is from bionic's sources and four emulators**,
  not from every vendor's filter. Fix: a device farm run on vendor builds
  of Android 11 and later.
- **Export failures are silent:** a revoked grant or a missing folder
  leaves files in the app and retries later without telling the user.
  Fix: a notice in Settings with the reason and a way to choose again.
- **A folder split between exports:** a folder still being received when
  the app exports (a transfer interrupted mid-folder, on Android 11 and
  later) is moved in parts, the later part under a free name such as
  `photos (1)`.
- **The export's view of the core is from outside:** it relies on the
  transfer states and on accepts going through the app. Fix: the core
  reporting what it published, per transfer, so the app moves exactly
  those files.
- **Startup was measured on an emulator**, not on a mid-range phone, and
  32-bit ARM was built but not run (no 32-bit ARM emulator on Apple
  silicon). Fix: run the benchmark and the suite on a mid-range arm64
  phone and a 32-bit ARM device.
- **No manual TalkBack pass:** the AOSP images have no TalkBack (it is a
  Google app), so screen-reader support rests on the semantics the tests
  check. Fix: a TalkBack pass on a device that has it.
- **Material 3 Expressive is beta** (1.5.0-beta01); its APIs and looks may
  change before 1.5.0. Fix: move to 1.5.0 when it is released.
- **Contact names in the system:** Direct Share labels are names the
  system's shortcut and sharing services keep. Fix: an opt-out in
  Settings.
