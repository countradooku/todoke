# ADR 0012: The binding surface (BoltFFI)

- **Status:** accepted on 2026-10-15. The maintainer chose BoltFFI ("I will
  use this", after a review of the library); the rest of the design was
  delegated with the standing priority of maximum security first, then
  performance.
- **Date:** 2026-10-15
- **Scope:**
  - `todoke-ffi` (the boundary) and its generated Swift package, Android
    AAR, and npm package
  - their tests: Rust, Swift (XCTest), Kotlin (JUnit), TypeScript (Node),
    the C ABI under Miri, sanitizers, and the `ffi_commands` fuzz target
  - two Android values in `todoke-core`'s `KeyProtection` (`StrongBox`,
    `Tee`)
  - `.github/workflows/bindings.yml`, `deny.toml` and its guard, the
    supply-chain stores

## Context

The P14 prompt asks for `crates/xfer-ffi` exposing the core to Swift,
Kotlin, and WASM/TypeScript with BoltFFI:

- the BoltFFI version pinned, the choice recorded in
  `docs/adr/0003-bindings.md`;
- opaque handles and commands only (`Core`, `TransferHandle`,
  `ContactHandle`); no key material, PSKs, or session state across the
  boundary, and no file bytes (the core reads and writes through paths or
  handles the platform passes in);
- async commands, an event stream for transfer events, typed errors with
  human messages;
- platform hooks the core calls back: a KeyStore backend, radio links
  (BLE, Wi-Fi P2P, AWDL, USB) as byte pipes, notifications;
- a Swift package, an Android AAR, and an npm package;
- tests: binding smoke tests in Swift, Kotlin, and TypeScript; the FFI
  boundary fuzzed with random command sequences; Miri and sanitizers on
  the unsafe glue.

Deviations:

- The crate is `todoke-ffi` (the project's name), and the ADR is 0012
  (0003 is the Bao ADR).
- **Commands block instead of being async**, and events are read from a
  subscription instead of a BoltFFI stream (below): BoltFFI 0.31.1's async
  and stream glue is unsafe to use here.

## Decisions

### BoltFFI, pinned

- **BoltFFI 0.31.1**, exactly (`boltffi = "=0.31.1"`, the CLI built from
  the same crates.io source with `--locked` in CI, never a prebuilt
  binary; `boltffi.toml` passes `--locked` to every cargo build it runs).
  It is MIT, about ten months old, with one main maintainer; it passes
  primitives directly and only encodes strings and collections, far faster
  than UniFFI. It has no audit; its runtime has about 200 unsafe sites and
  its generated glue about 500, which is why the glue is tested under Miri
  and sanitizers here. Every upgrade is a review of the generated code.
- Its npm runtime (`@boltffi/runtime` 0.31.1) and the TypeScript compiler
  the pack type-checks with (5.9.3: the generated code assumes TypeScript
  5's defaults) are pinned in `crates/todoke-ffi/package-lock.json`.
- **BoltFFI's AI policy** forbids AI-written issues, comments, and pull
  requests: problems found here are written up for a maintainer to report
  in their own words, never filed by tooling.

### No async, no BoltFFI streams

A review of the generated glue found two defects that rule out BoltFFI's
async methods and streams for todoke:

- **Swift cancellation can poll a freed future.** The Swift poll driver
  schedules `Task { yield; start() }` without re-checking whether the task
  was cancelled, while `onCancel` frees the Rust future: a cancelled call
  can poll freed memory.
- **Streams drop the newest events silently and never close.**
  `StreamProducer::push` discards an event when the ring is full, with no
  signal to the reader, and a stream outlives its producer.

So no Rust future crosses the boundary. Commands block the calling thread
until the core answers (most answer at once; offering a large folder
hashes it first) and the apps call them off the UI thread (Swift
`Task.detached`, Kotlin `Dispatchers.IO`). Cancelling the caller does not
cancel a command already sent. Inside, `block_on` parks the calling
thread on the core's reply channel, so no async runtime runs in the app's
threads.

### What crosses the boundary

- **Opaque handles:** `Core`, `ContactHandle`, `TransferHandle`,
  `QrOffer` (a shown QR offer), `CodeOffer` (a shown pairing code), and
  `Events` (a subscription). A handle holds public IDs and a reference to
  the core, never a key. Each contact and transfer handle keeps its core
  running until it is released, so a call through one never finds the
  core gone; a subscription does not keep the core running.
- **Commands** are `Core` and handle methods. Records (`Status`, `Contact`,
  `Transfer`, `Offer`, `HistoryItem`, …) carry plain values. Peer-chosen
  names and messages are escaped (`todoke_core::api::escape`) before they
  cross, core error messages included, so no app can show a name that
  hides or reorders text.
- **Events:** `Core::subscribe` returns an `Events` subscription with its
  own queue, filled by one thread per core that converts the core's
  broadcast events:
  - each queue holds 4096 events; when full, the oldest go, and the next
    read starts with `Missed { events }` (also when the core's own channel
    lagged), after which the app reads the offers and transfers again;
  - `next(max, timeout_ms)` returns at most 1024 events and waits at most
    60 seconds; after the core stops it returns what is queued, then fails
    with `TodokeError::State`; `stop()` ends a subscription at once (the
    name avoids Kotlin's freeing `close()`);
  - at most 16 subscriptions live at once per core; a stopped one gives
    its place up.
  The Kotlin AAR adds `Guarded<Core>.events()`, a `Flow` that reads on
  `Dispatchers.IO`, yields between reads, and stops and frees its
  subscription when collection ends.
- **Errors** are `TodokeError`, one variant per kind (Disabled,
  Unsupported, Invalid, Ambiguous, Unreachable, State, Pairing, Source,
  KeyStore, Profile, Internal), each with a message for people and never
  a secret.
- **Files** cross as absolute paths the app may read (sending; a relative
  path is refused) and a downloads directory (receiving). File bytes never
  cross.
- **What does cross, explicitly:**
  - the 32-byte storage key, between the core and the app's `KeyStore`
    (below);
  - a QR pairing offer: its text only when the app calls `QrOffer::text`
    (to share it as text), and always as the module grid the app draws
    (which encodes the same offer: whoever sees the QR holds it, as
    PROTOCOL §3.1 intends);
  - a pairing code, only through `CodeOffer::code` (the user must see it).
  No identity key, pairing PSK, or session state crosses.
- **A panic aborts the app.** Exported functions are `extern "C"`: a
  panic cannot unwind into foreign code, so the process stops instead of
  continuing with broken state. The crate denies `unwrap`, `expect`, and
  `panic!`; the notifier runs under `catch_unwind` on the event thread, so
  a panicking app callback loses its event, not the thread.

### Platform hooks

- **`KeyStore`** (the app implements it): `load(profile)`,
  `store(profile, key)` (never replace), `protection`. It is the only way
  to keep the storage key in Android's Keystore, so the key crosses here
  and only here; the app must keep it encrypted under a non-exportable
  hardware key and must not copy or log it. `profile` is the profile's
  random ID, so one app can hold several profiles, each with its own key.
  The core's policy (`Selected`, ADR 0011: sticky, verified, one-way
  migration) is unchanged, and the binding narrows what an app may ask:
  - with a `KeyStore`, only `KeyStoragePolicy::Platform` (the key lives
    there and nowhere else); `File` or `Auto` is refused as `Invalid`;
  - on Android and iOS without one, only an explicit `File`;
  - a stored key of the wrong length or all zeros (a wiped slot) is
    refused, never used;
  - a failing or refusing store is `TodokeError::KeyStore`.
  The core calls the store on its own thread while `with_key_store` blocks
  its caller, so the store must not wait for the caller's thread (on
  Android, the main thread). Without a store, the macOS build keeps the
  key in the Keychain natively (nothing crosses); elsewhere a private file,
  as `key_storage` allows. The profile's ID is never skipped: a profile
  that cannot be named does not start, rather than falling back to a file.
- **`Notifier`:** offers (sender and counts, never file names), offers
  gone, endings, and `missed` (events were lost: the app settles its
  notifications from `Core::offers`), called from the event thread; an
  offer is decided only in the app. Replacing or clearing it releases the
  old one outside the lock, since releasing calls into the app.
- **`WifiLinks`** (since [ADR 0019](0019-android-radios.md), replacing
  the reserved `RadioLink`): the app hosts and joins direct Wi-Fi links the
  core asks for and binds sockets to them (`Core::set_links`; PROTOCOL
  §10.2).
- **Loopback discovery** (`Settings::allow_loopback`, so two cores on one
  machine find each other) is refused unless the crate is built with its
  `test-support` feature, which only the binding tests enable;
  `scripts/ci/deny-exceptions-dev-only.sh` fails if a shipped graph enables
  it or `unaudited-dev`.

### Lifetimes and threads

- Swift releases a class when its last reference goes, and a call keeps
  its object alive: no use after free.
- Kotlin's generated `close()` frees the object at once, and its methods
  read the raw handle without retaining it: `close()` on one thread can
  free an object another thread is calling (upstream issue #664).
  `Guarded` (Kotlin, in the AAR) is how the Android app holds shared
  objects:
  - it counts calls in progress and refuses new ones once closing;
  - `close()` waits for the last call, then frees; a second `close()`
    waits for that free; an interrupt does not cut the wait short (the
    interrupt stays set);
  - `close()` from inside a call on the same object (same thread, or same
    coroutine through `callSuspending`) throws instead of waiting for
    itself;
  - `closeSuspending()` closes on `Dispatchers.IO` and completes even if
    its caller is cancelled. `close()` blocks, so never on the main thread.
- TypeScript is single-threaded: `dispose()` cannot race a call's start.

### Packaging

- **Swift:** `boltffi pack apple` (iOS device, simulator, macOS; deployment
  target iOS 16) → an XCFramework and `Package.swift`.
- **Android:** `boltffi pack android` (four ABIs, minSdk 33 since ADR 0019) gives Kotlin
  and `jniLibs`, linked with `-z max-page-size=16384` (16 KB pages; CI
  checks every LOAD segment's alignment). `crates/todoke-ffi/android` (AGP
  9.4.1) packs them with `Guarded.kt` and `Subscriptions.kt` into the AAR,
  with a keep rule for the classes the JNI glue calls by name. The AAR has
  no desktop loader; kotlinx-coroutines is an `api` dependency (it is in
  `Guarded`'s and `events()`'s signatures).
- **npm:** `boltffi pack wasm` (`@todoke/core`, never published). The core
  does not run in a browser yet (browser mode is P21): `Core::new` refuses
  there.
- Release builds keep sessions disabled (PROTOCOL §16). The test overlay
  (`boltffi.test.toml`) builds the host's slice with `unaudited-dev` and
  `test-support`, and a Kotlin desktop loader that reads
  `java.library.path`.

### Tests

- Rust: two cores pair by QR, offer, accept, and receive through the
  binding's API, and the subscription ends after the core is released;
  releasing a core while another thread reads a subscription; malformed
  requests are typed errors; the key store policy and wiped keys;
  subscriptions are bounded; notifications carry no names and settle after
  `missed`; the queue's drop-oldest, `Missed`, stop, and close semantics.
- Swift (XCTest on macOS against the generated package): the same flow,
  the key store hook and policy, pairing codes, bounded subscriptions,
  typed errors, handles keeping their core. Against the release package
  (`TODOKE_RELEASE=1`), every start is `Disabled`.
- Kotlin (JUnit on a desktop JVM, the generated JNI glue linked with the
  library): the same flow over the events `Flow`, the flow ending with its
  core, closing a core freeing its profile, the key store policy, bounded
  subscriptions, and `Guarded` (closing with calls in flight, a second
  close, close from inside a call, an interrupt during close). Against a
  library built as shipped, every start is `Disabled`. CI runs them again
  with the Rust library and the C glue under AddressSanitizer (the glue
  under UBSan too). The Kotlin test project verifies its Gradle
  dependencies by SHA-256 (`gradle/verification-metadata.xml`).
- TypeScript (Node): the module loads; a core is refused.
- The generated C entry points under Miri: buffers returned and freed,
  records decoded from malformed foreign bytes without a core; the
  binding's unit tests (queue, `block_on`) under Miri too.
- AddressSanitizer over `todoke-ffi`'s Rust tests (two cores end to end).
- `ffi_commands` (fuzz): random command sequences against one core in a
  scratch profile: malformed IDs, QR text, codes, absolute and relative
  paths, stale handles, pairing (QR and code) started and stopped,
  subscriptions opened, read, and stopped, the notifier set and cleared,
  and second profiles started with key stores that fail, refuse, or hand
  back short or all-zero keys.

### Supply chain

`todoke-ffi` brings BoltFFI's crates and, through BoltFFI's runtime (which
always enables its `url` feature), `url` and ICU's Unicode-3.0 crates.
`todoke-ffi` is held to `deny.toml` with the 18 ICU crates allowed by
exact version; the guard checks its features. New crates are exempted in
both cargo-vet stores pending audits.

## Residual risks

- **BoltFFI is young and unaudited**, and its generated glue is unsafe
  code the project did not write. Fix: an audit of `boltffi_core` and the
  generated wrappers for the shapes todoke uses; keep the version pinned.
- **The generated glue is not snapshotted**, and the tools that generate
  it (`boltffi_cli` and the `wasm-bindgen-cli` it installs) are built from
  crates.io with `--locked` but not vetted: a changed generator would go
  unnoticed until review. Fix: commit the generated Swift, Kotlin, C, and
  TypeScript and fail CI on a diff, or vet both tools' graphs.
- **The storage key crosses into the app's memory** (Kotlin `ByteArray`,
  Swift `Data`), where it cannot be reliably wiped, on every start with a
  `KeyStore`. On the Rust side the binding wipes its own copies, but the
  buffers BoltFFI encodes and decodes the key through are freed unwiped.
  Fix: Android Keystore through JNI from Rust (no crossing), and the iOS
  Keychain natively from Rust as on macOS.
- **Kotlin's generated `close()` can free an object during a call**
  (BoltFFI #664) unless the app goes through `Guarded`; nothing enforces
  that. Fix: upstream closing semantics (retain per call), or generate the
  guard.
- **Blocking commands hold a thread** for as long as the core takes (up to
  minutes while a large folder is hashed), and cancelling the caller does
  not cancel the command. Fix: async commands once BoltFFI's Swift
  cancellation re-checks before polling (and its streams signal loss and
  close), or a cancellable command handle.
- **TypeScript loses constructor errors:** a fallible constructor returns
  `null` (BoltFFI 0.31.1), so `Core.new` cannot say why it refused. Fix:
  a factory that throws, when browser mode (P21) makes the core run there.
- **The AAR's Gradle dependencies are not verified:** its metadata needs
  the Linux `aapt2` artifacts, which only a machine with the Android SDK
  resolves. Fix: generate `android/gradle/verification-metadata.xml` on
  Linux with the SDK (or from CI's report) and commit it.
- **The sanitized Kotlin run is Linux only**, with clang 18's ASan runtime
  under Rust nightly's instrumentation (the same `v8` interface, different
  LLVM versions); Apple clang's runtime cannot link Rust's instrumentation.
  Fix: a clang matching Rust's LLVM in CI.
- **Android shared storage is not reachable yet:** the core reads paths,
  and Android's Storage Access Framework hands out content URIs. Fix: file
  descriptors through the boundary (P16).
- **`url` and ICU are linked into every mobile and web library** only
  because BoltFFI's runtime enables them, adding size and Unicode tables
  todoke does not use. Fix: upstream feature forwarding.
- **Radio links are an interface only** (§16 O7).
- **The Kotlin tests run on a desktop JVM**, not an Android device or
  emulator: the AAR is built, not exercised. Fix: the emulator lab (T01).

## Known test gaps

- No test runs the iOS slices (only macOS runs XCTest in CI).
- The npm package's browser entry is not loaded in a browser.
- Miri covers the C entry points that need no core and the binding's unit
  tests; the glue that drives a core runs under AddressSanitizer, not Miri
  (the core calls into C crypto).
- The Android libraries' release check (`Disabled`) runs on the desktop
  JVM's library, not on the AAR's.
