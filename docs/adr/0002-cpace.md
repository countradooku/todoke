# ADR 0002: CPace library for human-code pairing

- **Status:** accepted for the unaudited implementation; code pairing stays
  disabled for production (PROTOCOL §16, gate O2). Needs maintainer review.
- **Date:** 2026-10-13
- **Scope:** the `CPace` backend behind `todoke_crypto::pairing` and its
  production gate. The protocol choice itself (balanced
  `CPACE-RISTR255-SHA512`, pinned to draft-irtf-cfrg-cpace-21 §7 and §8.3)
  is fixed by [PROTOCOL §3.2](../../spec/PROTOCOL.md); this ADR only selects
  the library that implements it.

## Context

PROTOCOL §3.2 requires `CPace`'s internal algorithms and encodings to come
from a conforming library, never a new implementation in todoke, and must
not silently track later draft revisions. O2 asks whether a reviewed
production Rust implementation with matching vectors exists; until it is
resolved, code pairing stays disabled.

Requirements for the library:

1. Exactly draft-21 §7 (one round, initiator/responder transcript
   `transcript_ir`) and §8.3 (`G.DSI = "CPaceRistretto255"`, the
   `generator_string` with its zero padding, SHA-512 with a 128-byte input
   block, Ristretto255 element derivation from 64 hash bytes, `ISK =
   H(lv_cat(DSI || "_ISK", sid, K) || transcript_ir(Ya, ADa, Yb, ADb))`),
   aborting on undecodable, noncanonical, or neutral elements and on `K = I`.
2. Reproduces the draft's published vectors (Appendix A string functions,
   Appendix B.3 ristretto255).
3. No panic on peer input; secret state zeroized; caller-supplied
   randomness so that todoke's error-handled OS CSPRNG is used.
4. Permissive license, latest release, and no duplicate versions of
   existing dependencies (the maintainer's dependency policy).

## Candidates

Checked on 2026-10-13 against crates.io, the published crate sources, and
the upstream repositories.

| Crate | Version (date) | Finding |
| --- | --- | --- |
| `pakery-cpace` + `pakery-crypto` + `pakery-core` | 0.6.0 (2026-09-22) | Implements draft-21 for ristretto255/SHA-512 (its `lib.rs` still mentions draft-18; its generator and transcript modules cite draft-21). Generic over a ciphersuite trait; the suite constants are ours. Uses `curve25519-dalek` 5.0, `sha2` 0.11, `subtle`, `zeroize`, `rand_core` 0.10 (all already in the graph) plus `hkdf` 0.13, `hmac` 0.13, `const-oid`, and `zeroize_derive`. `#![forbid(unsafe_code)]`, MIT OR Apache-2.0, MSRV 1.85. Single maintainer, created 2026-03-07, eight releases, last push 2026-10-10, 2 stars; the repository has fuzzing and constant-time (`dudect`, Valgrind) CI. No independent review. |
| `pake-cpace` | 0.1.7 (2023-12-15) | An earlier CPace variant: domain strings `CPaceRistretto255-1`/`-2` and its own transcript, not draft-21. `curve25519-dalek` 4.1 (a duplicate version) and `getrandom` 0.2. ISC. |
| `pake-cpace-embedded` | 0.2.2 (2026-09-22) | A fork of `pake-cpace` with the same pre-draft-21 construction. |
| `cpace` | 0.1.0 (2020-05-01) | An early draft (`secret_generator` with a salt), marked experimental by its author; unmaintained since 2020. |
| `aucpace` | 0.1.1 | AuCPace, the augmented protocol: not the balanced CPace §3.2 selects. |
| `cerulion_pairing` | 1.0.0 | An application crate, not a CPace library. |

Only `pakery-cpace` matches draft-21. I compared it against the draft's
own vectors rather than its claims (see "Conformance evidence").

## Decision

Use **`pakery-cpace` 0.6.0** with **`pakery-crypto` 0.6.0**
(`default-features = false`, `features = ["ristretto255"]`), both pinned
exactly as workspace dependencies:

- todoke defines the ciphersuite itself (`Ristretto255Sha512`: DSI
  `CPaceRistretto255`, `HASH_BLOCK_SIZE = 128`, `FIELD_SIZE_BYTES = 32`,
  pakery's `Ristretto255Group` and `Sha512Hash`) rather than taking
  pakery's prebuilt suite, so an upstream change to that suite cannot move
  todoke silently; the vectors pin the result either way.
- Only the initiator/responder transcript mode is used (§3.2: A sends first,
  B responds exactly once). pakery's optional `session_id` output is
  ignored; the ISK feeds the §3.2 PSK formula only.
- Randomness: pakery takes an infallible `rand_core` RNG. todoke draws the
  64 bytes pakery needs for one scalar from the OS CSPRNG beforehand, with
  error handling, and serves them through an adapter; if pakery ever asked
  for more, the adapter records it and the result is discarded. pakery
  samples a scalar by reducing 64 uniform bytes modulo the group order,
  which draft-21 §8.3 permits ("uniform sampling between 1 and
  G.group_order - 1"; zero has negligible probability and would produce
  the neutral element, which the peer rejects).
- The crates are **optional** dependencies of `todoke-crypto`, enabled only
  by the non-default `unaudited-code-pairing` feature (which implies
  `unaudited-suite-0001`) and, for unit tests, by the development
  dependencies. A shipped build without the feature contains no CPace code:
  the backend is a stub whose every call returns "CPace backend
  unavailable", and `UnauditedCodePairing::acknowledge_not_production_ready()`,
  required by every code-pairing entry point, does not exist.
  `scripts/ci/deny-exceptions-dev-only.sh` fails if a shipped graph
  enables the feature; the fuzz workspace enables it.

## Conformance evidence (all in `cargo test --workspace`)

`crates/todoke-crypto/src/pairing/cpace/tests.rs` checks, with values
copied from [draft-irtf-cfrg-cpace-21](https://www.ietf.org/archive/id/draft-irtf-cfrg-cpace-21.txt):

1. Appendix A: `prepend_len`, `lv_cat`, and both `transcript_ir` vectors.
2. Appendix B.3.1: the 170-byte generator string, its SHA-512 hash, and
   the encoded generator.
3. Appendix B.3.2–B.3.5 **through todoke's backend** (`start`, `respond`,
   `finish`), with scripted randomness that makes pakery's scalar equal the
   draft's `ya`/`yb`: both shares, `K`, `transcript_ir`, and the 64-byte
   ISK on both sides.
4. Appendix B.3.10–B.3.11: scalar multiplication with valid inputs, and
   both invalid inputs (an undecodable encoding and the neutral element)
   abort on either side.
5. Additional: noncanonical encodings (a field element at or above p, a
   negative element, a set high bit) abort; changing the password, CI, sid,
   ADa, or ADb changes the ISK; randomness failure and overdraw fail
   closed.

The §3.2 context formulas (CI, sid, ADa, ADb, `pre_noise`, and the PSK
HKDF) are checked byte for byte in `pairing/transcript.rs`, with the PSK
recomputed through an independent HMAC implementation. These are layout
checks, not interoperability vectors: §3.2 still requires conformance
vectors for the todoke context before release.

## Consequences

- New packages (lock and both vet stores): `pakery-core`, `pakery-cpace`,
  `pakery-crypto` 0.6.0, `hkdf` 0.13.0, `const-oid` 0.10.2, and
  `zeroize_derive` 1.5.0, each with a "Not yet reviewed" exemption.
  `hmac` 0.13.0 (previously development-only) needs `safe-to-deploy`;
  its exemption was raised. No new license, source, advisory, or
  duplicate-version exception.
- Zeroization: pakery zeroizes its initiator state, the encoding of `K`, and
  the ISK (`SharedSecret`), and wipes the responder scalar. It does not
  claim to wipe the generator string (which contains the password),
  `curve25519-dalek` and `sha2` internal state, or intermediate vectors
  built by `lv_cat`. These residues join the O6 list (ADR 0001) and are a
  reason the gate stays closed.
- O2 is **not** closed: the library is unreviewed and young, and the
  todoke context needs conformance vectors and a second implementation.
  Closing O2 needs (a) an independent review of pakery-cpace/-crypto/-core
  at the pinned version, or a reviewed alternative, (b) code-pairing
  context vectors reproduced by an independent implementation, and
  (c) a maintainer decision.
