# Android client

The todoke app for Android 7 and later: Kotlin and Jetpack Compose
(Material 3 Expressive) over the core through the BoltFFI AAR
(`crates/todoke-ffi/android`). Rust owns all protocol, cryptographic, and
file logic, consent included; the app presents state and submits the
user's intent. See [ADR 0015](../../docs/adr/0015-android.md) for the design
and its residual risks, [the design](../../docs/DESIGN.md), and
[the protocol](../../spec/PROTOCOL.md).

| Path | What |
| --- | --- |
| `app/src/main/kotlin/org/todoke/android/core` | the core behind `Backend`, the Keystore, notifications, the transfer service, the resume worker, Direct Share, the export to the chosen folder |
| `app/src/main/kotlin/org/todoke/android/ui` | the screens |
| `app/src/androidTest` | UI flows with accessibility checks, screenshots, the export, two real cores |
| `baselineprofile` | the Baseline Profile generator and the cold-start benchmark |

## Build

The app builds against libraries packed by BoltFFI, passed with
`-Ptodoke.android`. Release libraries start no core (PROTOCOL §16); the
development ones (the test overlay) do.

```bash
cd crates/todoke-ffi && boltffi pack android --release
```

```bash
gradle -p apps/android :app:assemblePlayRelease :app:assembleFdroidRelease -Ptodoke.android="$PWD/crates/todoke-ffi/dist/android"
```

## Test

On a connected device or emulator, with the development libraries:

```bash
cd crates/todoke-ffi && boltffi --overlay boltffi.test.toml pack android
```

```bash
gradle -p apps/android :app:connectedPlayDebugAndroidTest -Ptodoke.android="$PWD/crates/todoke-ffi/target-tests/android"
```

Screenshots land in
`app/build/outputs/connected_android_test_additional_output`.

## Startup

The Baseline Profile is generated on a device or an Android 13+ emulator
(release-mode development libraries, so the journey reaches Home), and the
benchmark compares cold starts with and without it:

```bash
gradle -p apps/android :app:generateBaselineProfile -Ptodoke.android="$PWD/crates/todoke-ffi/target-tests/android"
```

```bash
gradle -p apps/android :baselineprofile:connectedPlayBenchmarkReleaseAndroidTest -Ptodoke.android="$PWD/crates/todoke-ffi/target-tests/android"
```

On an emulator, add
`-Pandroid.testInstrumentationRunnerArguments.androidx.benchmark.suppressErrors=EMULATOR`
(emulator numbers are indicative only).
