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
  - `.github/workflows/bindings.yml`, `deny.toml`, the supply-chain stores

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

Deviations: the crate is `todoke-ffi` (the project's name), and the ADR is
0012 (0003 is the Bao ADR).

## Decisions

### BoltFFI, pinned

- **BoltFFI 0.31.1**, exactly (`boltffi = "=0.31.1"`, the CLI built from
  the same crates.io source with `--locked` in CI, never a prebuilt
  binary). It is MIT, about ten months old, with one main maintainer; it
  passes primitives directly and only encodes strings and collections,
  far faster than UniFFI. It has no audit; its runtime has about 200
  unsafe sites and its generated glue about 500, which is why the glue is
  tested under Miri and sanitizers here. Every upgrade is a review of the
  generated code.
- Its npm runtime (`@boltffi/runtime` 0.31.1) and the TypeScript compiler
  the pack type-checks with (5.9.3: the generated code assumes TypeScript
  5's defaults) are pinned in `crates/todoke-ffi/package-lock.json`.
- **BoltFFI's AI policy** forbids AI-written issues, comments, and pull
  requests: problems found here are written up for a maintainer to report
  in their own words, never filed by tooling.

### What crosses the boundary

- **Opaque handles:** `Core`, `ContactHandle`, `TransferHandle`, and
  `QrOffer` (a shown pairing offer). A handle holds public IDs and a
  reference to the core, never a key. Each handle keeps its core running
  until it is released, so a call through a handle never finds the core
  gone.
- **Commands** are `Core` and handle methods; the ones that ask the core
  are async (Swift `async throws`, Kotlin `suspend`, TypeScript
  `Promise`). Records (`Status`, `Contact`, `Transfer`, `Offer`,
  `HistoryItem`, …) carry plain values. Peer-chosen names and messages are
  escaped (`todoke_core::api::escape`) before they cross, so no app can
  show a name that hides or reorders text.
- **Events:** `Core::events()` is a stream (Swift `AsyncStream`, Kotlin
  `Flow`), fed by a thread that converts the core's broadcast events; a
  slow subscriber loses the oldest and sees `Missed`.
- **Errors** are `TodokeError`, one variant per kind (Disabled,
  Unsupported, Invalid, Ambiguous, Unreachable, State, Pairing, Source,
  KeyStore, Profile, Internal), each with a message for people and never
  a secret.
- **Files** cross as absolute paths the app may read (sending) and a
  downloads directory (receiving). File bytes never cross.
- **What does cross, explicitly:**
  - the 32-byte storage key, between the core and the app's `KeyStore`
    (below);
  - a QR pairing offer's text, only when the app calls `QrOffer::text`
    (to share it as text); the QR itself crosses as a module grid drawn
    in Rust;
  - a pairing code, which the user must see.
  No identity key, pairing PSK, or session state crosses.

### Platform hooks

- **`KeyStore`** (the app implements it): `load`, `store` (never replace),
  `protection`. It is the only way to keep the storage key in Android's
  Keystore, so the key crosses here and only here; the app must keep it
  encrypted under a non-exportable hardware key and must not copy or log
  it. The core's policy (`Selected`, ADR 0011: sticky, verified, one-way
  migration) is unchanged. Without one, the macOS build keeps the key in
  the Keychain natively (nothing crosses); elsewhere a private file, as
  `key_storage` allows.
- **`Notifier`:** offers (sender and counts, never file names) and
  endings, called from the core's event thread; an offer is decided only
  in the app.
- **`RadioLink`** (BLE, Wi-Fi P2P, AWDL, USB as byte pipes): the shape is
  fixed, and `Core::attach_link` refuses every link while PROTOCOL §16 O7
  keeps those transports disabled.

### Lifetimes and threads

- Swift releases a class when its last reference goes, and a call keeps
  its object alive: no use after free.
- BoltFFI retains a class for the whole of an async call, but Kotlin's
  `close()` can still race the start of a call from another thread
  (upstream issue #664). `Guarded` (Kotlin, in the AAR) counts calls in
  progress, refuses calls after `close()`, and frees only after the last
  one finishes; the Android app holds shared objects through it.
- TypeScript is single-threaded: `dispose()` cannot race a call's start.

### Packaging

- **Swift:** `boltffi pack apple` (iOS device, simulator, macOS; deployment
  target iOS 16) → an XCFramework and `Package.swift`.
- **Android:** `boltffi pack android` (four ABIs, minSdk 24) gives Kotlin
  and `jniLibs`; `crates/todoke-ffi/android` (AGP 9.4.1) packs them with
  `Guarded.kt` into the AAR, with a keep rule for the classes the JNI glue
  calls by name.
- **npm:** `boltffi pack wasm` (`@todoke/core`, never published). The core
  does not run in a browser yet (browser mode is P21): `Core::new` refuses
  there.
- Release builds keep sessions disabled (PROTOCOL §16); the tests build
  with the development gates.

### Tests

- Rust: two cores pair by QR, offer, accept, and receive through the
  binding's API; malformed requests are typed errors; notifications carry
  no names.
- Swift (XCTest on macOS against the generated package): the same flow,
  the key store hook, typed errors, handles keeping their core.
- Kotlin (JUnit on a desktop JVM, the generated JNI glue linked with the
  library): the same flow over `Flow` events, and `Guarded` closing a core
  with calls in flight. CI runs it again with the C glue under
  AddressSanitizer and UBSan.
- TypeScript (Node): the module loads; a core is refused.
- The generated C entry points under Miri: buffers returned and freed,
  records decoded from malformed foreign bytes without a core.
- AddressSanitizer over `todoke-ffi`'s Rust tests (two cores end to end).
- `ffi_commands` (fuzz): random command sequences against one core in a
  scratch profile: malformed IDs, QR text, codes, paths, stale handles,
  pairing started and stopped, the notifier set and cleared.

### Supply chain

`todoke-ffi` brings BoltFFI's crates and, through BoltFFI's runtime (which
always enables its `url` feature), `url` and ICU's Unicode-3.0 crates. Like
the desktop app, `todoke-ffi` is excluded from `deny.toml` and held to
`deny-desktop.toml`, which covers the whole graph and already allows those
exact versions. New crates are exempted in both cargo-vet stores pending
audits.

## Residual risks

- **BoltFFI is young and unaudited**, and its generated glue is unsafe
  code the project did not write. Fix: an audit of `boltffi_core` and the
  generated wrappers for the shapes todoke uses; keep the version pinned.
- **The storage key crosses into the app's memory** (Kotlin `ByteArray`,
  Swift `Data`), where it cannot be reliably wiped, on every start with a
  `KeyStore`. Fix: Android Keystore through JNI from Rust (no crossing),
  and the iOS Keychain natively from Rust as on macOS.
- **Kotlin's generated `close()` can race a call** (BoltFFI #664) unless
  the app goes through `Guarded`; nothing enforces that. Fix: upstream
  closing semantics, or generate the guard.
- **TypeScript loses constructor errors:** a fallible constructor returns
  `null` (BoltFFI 0.31.1), so `Core.new` cannot say why it refused. Fix:
  a factory that throws, when browser mode (P21) makes the core run there.
- **Android shared storage is not reachable yet:** the core reads paths,
  and Android's Storage Access Framework hands out content URIs. Fix:
  file descriptors through the boundary (P16).
- **`url` and ICU are linked into every mobile and web library** only
  because BoltFFI's runtime enables them, adding size and Unicode tables
  todoke does not use. Fix: upstream feature forwarding.
- **Radio links are an interface only** (§16 O7).
- **The Kotlin tests run on a desktop JVM**, not an Android device or
  emulator: the AAR is built, not exercised. Fix: the emulator lab (T01).

## Known test gaps

- No test runs the iOS slices (only macOS runs XCTest in CI).
- The npm package's browser entry is not loaded in a browser.
- Miri covers the C entry points that need no core; the async glue runs
  under AddressSanitizer, not Miri (the core calls into C crypto).
