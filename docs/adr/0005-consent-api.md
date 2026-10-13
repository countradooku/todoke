# ADR 0005: Cross-crate consent API and the transfer engine's shape

- **Status:** proposed (needs maintainer acceptance).
- **Date:** 2026-10-13
- **Scope:** how `todoke-transfer` obtains the right to seal or open file
  content, where the signed `Accept` (`AcceH`) and `DeliveryReceipt` are
  issued and verified, how the receiver's consent invariant is enforced and
  checked, and the shape of the transfer engine (PROTOCOL §6, §7, §11–§13).
  The wire formats and rules are fixed by the spec; this ADR records the
  code structure that enforces them.

## Context

PROTOCOL §7.2 makes consent a core invariant: before the receiver durably
records and queues its own verified Accept, it must not process a
`FileKey`, decrypt content, verify Bao slices, or store file bytes; before
the sender verifies that Accept against the authenticated receiver and the
current session, it must not send a file key or content. A valid signature
for another sender, session, or manifest is useless (§14.2).

The content layer (P06, ADR 0003/0004) already refuses to seal or open
without an `AcceptedFile`, whose constructor `from_verified_accept` was left
crate-private in `todoke-crypto` for "P07's verified-Accept path". The
maintainer asked that, in a shipped build, the only way to obtain an
`AcceptedFile` be `todoke-crypto` verifying a signed Accept that matches the
session, manifest, and selection, so that `todoke-transfer` cannot forge one.

## Decision

### 1. Consent lives in `todoke_crypto::consent`

| Item | Role |
| --- | --- |
| `SessionBinding` | Session ID, both full device keys, and the trusted time the ratchet gate opened. Its constructor is crate-private; outside `todoke-crypto` it comes only from `Session::transfer_binding()` on an established session. |
| `CanonicalManifest` | The exact manifest bytes, their §7.1 hash computed here, the schema checked by `todoke_proto::transfer::Manifest`, both device keys validated as Ed25519 keys, the empty-file root checked, and each regular file's `FileBinding`. |
| `verify_accept(record, session, manifest, now)` | The sender's check: layout, session ID, transfer ID, manifest hash, sender and receiver keys against both the session and the manifest, expiry (future, ≤ manifest expiry, ≤ now + 24 h + 120 s skew), selection (regular files of the manifest), and the receiver's strict Ed25519 signature. Returns a `VerifiedAccept`. |
| `sign_accept(keys, key, session, manifest, selection, expires_at, now)` | The receiver's issuance: refuses unless the key is the session's local device key and the manifest's recipient; checks everything the sender will check; signs through the `KeyStore` (`SigningDomain::Accept`, fresh nonce from the OS CSPRNG); then runs the same verification on its own record and returns a `VerifiedAccept`. |
| `VerifiedAccept::file(id)` | The **only** source of `AcceptedFile` in a shipped build: one per selected regular file, with exactly the manifest's binding; `None` for anything else. |
| `sign_receipt` / `verify_receipt` | The §7.7 receipt (`SigningDomain::DeliveryReceipt`) with every binding, the totals of the accepted selection, and the completion-time window. |

`AcceptedFile::from_verified_accept` stays crate-private and is now called
only from `consent`. The `insecure-content-without-accept` bypass is
unchanged (benchmarks and fuzzing only; CI keeps it out of every shipped
graph). `todoke-transfer` depends on `todoke-crypto` without any gate
feature.

What `consent` deliberately does not decide: user intent (the caller of
`sign_accept` is the core acting on local intent; a UI boolean is not a
signature), nonce replay and conflicting Accepts within a session, when
expiry pauses content, and revocation (the session layer closes revoked
sessions). The transfer engine owns those.

### 2. The receiver's consent gate, model-checked

In `todoke-transfer`, every incoming `FileKey` and `Chunk` passes a small
`ConsentGate` before anything else: closed until a `VerifiedAccept` opens it
(once), keys only for selected files under that Accept's hash, content only
for keyed selected files, nothing after it closes. A chunk for a transfer
without an open gate is refused from its transfer ID alone, before its body
is decoded (§7.2: discard without processing). The gate is generic over the
proof so that Kani harnesses can check it for every proof and operation
sequence; the same harness bodies run exhaustively over short sequences in
the unit tests, so the logic is exercised locally too. Below the gate the
type system enforces the rest: decryption needs an `AcceptedFile`.

### 3. A sans-IO engine per session, plus a thin async driver

`TransferEngine` takes complete frames and the monotonic time, and queues
frames and events; `pump` runs it over a `Session`. This matches the
session layer's design (sans-IO cores, a thin adapter), keeps the
adversarial tests and proofs free of I/O, and lets the core interleave user
intent between frames. To support it, `Session` gained `recv_until`
(receive with a caller deadline; a partly read record stays buffered) and
`now`.

Capabilities (§6) are exchanged at the engine's entry: the session layer
documents this as the caller's job, and the engine is that caller. It
queues its own record first and refuses every other frame until the peer's
arrives (within 5 seconds).

### 4. Storage behind traits

`SendSource` and `ReceiveSink` are where `todoke-fs` (P08) plugs in real
files: immutable sources and outboards; durable segment storage that keeps
each verified segment's ciphertext for revalidation on resume; durable
recording of the Accept; publication with length and whole-file BLAKE3
checks; tombstones; and revocation. `MemorySource`/`MemorySink` implement
them in memory.

## Alternatives considered

- **Verify in `todoke-transfer`, make `from_verified_accept` public.** Any
  caller could then create an `AcceptedFile` from any binding; rejected by
  the maintainer's requirement.
- **A public `SessionBinding::new`.** Simpler tests, but a transfer-layer
  bug could then verify an Accept against a session it is not running on.
  Tests use real sessions instead (QR pairing, then a contact session).
- **A `Kani` proof of the whole engine.** The engine calls Ed25519, AEADs,
  and Bao; model checking them is far beyond Kani's practical bounds. The
  consent decision is isolated in the gate instead, and the engine is
  covered by adversarial proptest state machines.

## Consequences

- Shipped code cannot seal or open content without a session-bound,
  signature-verified Accept that selects the file.
- Each proof run in CI covers the gate only; the rest of the consent path is
  covered by types, unit tests, adversarial proptests, and fuzzing.
- `SessionBinding` gained two `SessionInfo` fields (the local device key and
  the establishment time), which the receipt check needs.
- The receiver keeps no file masters across sessions: a resumed transfer
  gets its `FileKey`s again (the spec requires the same masters), and
  retained segments count only after they open under them.
