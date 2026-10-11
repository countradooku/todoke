# todoke design baseline

## Status and scope

This document records architectural requirements for a free, open-source, cross-platform, end-to-end secure file transfer app. The goal is any-to-any transfers between phones and PCs, with adoption ahead of revenue and the ambition to outperform existing solutions across usability, reliability, performance, and security.

The runtime crates remain a compiling scaffold with no transfer implementation, platform integration, or usable application. The repository also contains an offline Rust tool and reference cryptographic development dependencies for deterministic protocol fixtures. Requirements here are not claims about implemented runtime behavior. [The normative v1 draft](../spec/PROTOCOL.md) specifies wire records and identifies release blockers, including the unassigned hybrid Noise construction.

Read both documents before changing behavior. If specification and implementation disagree, stop and report the disagreement.

## Ownership and presentation

Rust owns all protocol, cryptographic, and file logic. The public entry point is `todoke-core`. SwiftUI on iOS, Jetpack Compose on Android, and GPUI on desktop present state and submit user intent. The core decides whether an operation is authorized. UI confirmation alone cannot bypass the signed AcceH requirement.

Mobile and web bindings are to use BoltFFI. Its exact supported targets, packaging, generated API, and suitability for the web target require verification before integration. No binding API exists in this scaffold, and no secrets may cross it.

## Crate responsibilities and trust boundaries

The table assigns future responsibilities. Every crate currently contains documentation only; it does not provide the APIs described here.

| Crate | Responsibility | Trust boundary |
| --- | --- | --- |
| `todoke-proto` | Protocol representations, bounded parsing, and encoding of specified wire messages. | All peer-controlled bytes and decoded fields remain untrusted until the appropriate authentication and validation succeeds. |
| `todoke-crypto` | Use approved libraries for authenticated sessions, per-file encryption, verification, and secret lifecycle. | Isolate secret material; transport or UI input cannot select an unauthenticated or weaker security mode. No custom primitives. |
| `todoke-transfer` | Transfer state, consent enforcement, progress, and verified chunk orchestration. | Reject file bytes before a valid signed AcceH; authentication and integrity do not substitute for consent. |
| `todoke-fs` | File access, destination handling, and persistence of authorized transfer data. | Peer names and metadata are not filesystem authority; the local filesystem can change or fail during operations. |
| `todoke-transport` | Common byte-pipe interfaces and orchestration of BLE, Wi-Fi P2P, AWDL, USB, LAN, and QUIC relay. | Every transport is untrusted; connectivity provides neither authentication nor consent. |
| `todoke-discovery` | Discover candidate peers and routes. | Discovery records identify candidates, not authenticated identities or authorized recipients. |
| `todoke-core` | Public facade joining Rust protocol, crypto, transfer, file, and discovery logic. | Validate caller intent and enforce policy independently of every UI, binding, and service caller. |
| `todoke-ffi` | BoltFFI boundary for mobile and web clients. | Foreign callers and foreign memory are untrusted; validate inputs and expose no secrets across the boundary. |
| `todoke-cli` | Command-line presentation and conversion of user intent into core calls. | Arguments, terminal input, and local callers do not bypass core policy. No CLI exists yet. |
| `todoke-daemon` | Background lifecycle and service integration using the core. | Process/service requests do not confer peer authentication, file access, or transfer consent. |
| `todoke-relay` | Relay service for forwarding opaque encrypted traffic. | Treat connected clients as hostile and the relay itself as untrusted by endpoints; it receives no endpoint secrets. |
| `todoke-preview` | Bounded, isolated handling of previews derived from authorized content. | Received content and metadata can be malicious even when sent by an authenticated peer; preview paths cannot bypass consent. |
| `todoke-desktop` | Thin GPUI desktop presentation over the core. | UI state and callbacks express intent; the core remains the authority for protocol and file operations. |
| `todoke-sys-windows` | Narrow Windows operating-system integration. | OS API results, handles, and callbacks must be validated; keep any necessary unsafe code inside this boundary. |
| `todoke-sys-macos` | Narrow macOS operating-system integration. | OS API results, handles, and callbacks must be validated; keep any necessary unsafe code inside this boundary. |
| `todoke-sys-linux` | Narrow Linux operating-system integration. | OS API results, descriptors, and callbacks must be validated; keep any necessary unsafe code inside this boundary. |

This is an ownership map, not a dependency graph. Concrete APIs, dependency edges, service IPC, mobile OS adapters, and preview isolation must be designed with their associated implementation. In particular, `todoke-sys-macos` does not establish that an API is available on iOS.

## Security requirements

Every session must authenticate with Noise using IKpsk2, KKpsk2, or XXpsk3, hybrid X25519 + ML-KEM-768, and a pairing PSK ratcheted per session. The protocol draft assigns pattern selection, transcript requirements, and a conservative ratchet transaction. Its exact hybrid construction remains a blocking open decision; suite 0x0001 is disabled. Do not interpret the algorithm names as a complete protocol.

Per-file content must use AES-256-GCM STREAM encryption, with XChaCha20-Poly1305 as the fallback, and BLAKE3/bao verified chunks. The protocol draft specifies STREAM BE32 substreams, nonce allocation, authenticated suite selection, encrypted Bao slices, and chunk framing. Authenticate and validate according to that specification before treating data as trusted; standalone nonce vectors are not complete content-encryption conformance evidence.

Consent is enforced in the core: no file byte is accepted before a signed AcceH. The protocol now defines AcceH as the session-bound, Ed25519-signed Accept record and specifies its authority, canonical bytes, selection, expiry, and replay rules. No pre-consent preview or alternate transport may evade it.

Use libcrux wherever it covers the requirements, otherwise appropriate RustCrypto/dalek crates. Never implement cryptographic primitives. Zeroize all secrets, never log them, and never pass them across FFI. Do not collect telemetry. These requirements also apply to diagnostics, errors, examples, tests, and future platform integrations.

All crates outside `todoke-ffi` and `todoke-sys-*` forbid unsafe code. The exception crates initially deny it and contain none. Any future exception must be narrow, reviewed, and documented. Untrusted inputs must produce recoverable errors rather than panics. The protocol assigns wire budgets and failure rules; platform resource management and crash behavior still need implementation evidence before network-facing features are added.

An encrypted authenticated session does not make peer-supplied paths, content, or resource requests safe. The protocol and file boundaries must account for malicious authenticated peers as well as hostile transports. This baseline makes no anonymity or traffic-analysis-resistance claim.

## Verification and change discipline

Every parser receives a cargo-fuzz target; every state machine receives proptest state-machine tests. Add meaningful tests alongside the implementation and keep documentation in the same pull request. Formal models belong in `formal/`, and reproducible performance measurements belong in `bench/`.

The scaffold's build and policy checks establish repository hygiene only. Cross-target checks of empty libraries do not establish that native APIs, BoltFFI, transports, or applications work on those targets. Native OS checks, mobile/web integration checks, adversarial testing, and security review must grow with functionality.

## Decisions required before implementation

The authoritative list is in [spec/PROTOCOL.md](../spec/PROTOCOL.md#open-decisions). Architecture additionally needs explicit choices for preview isolation, platform permission handling, daemon IPC authorization, secret storage, and dependency/API boundaries. The protocol draft resolves wire choices where stated and explicitly gates unresolved construction, platform, and secret-lifecycle questions.
