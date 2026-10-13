# ADR 0004: Content AEAD libraries and AES advertisement

- **Status:** proposed (needs maintainer approval).
- **Date:** 2026-10-13
- **Scope:** the libraries behind content suites 1 (AES-256-GCM STREAM) and
  2 (XChaCha20-Poly1305 STREAM), and when a device advertises AES in
  Capabilities. The suites, nonces, key schedule, and AAD are fixed by
  [PROTOCOL §6 and §8](../../spec/PROTOCOL.md).

## Context

§8 uses AES-256-GCM (12-byte nonces) and XChaCha20-Poly1305 (24-byte
nonces), each with a 16-byte tag, under RustCrypto STREAM BE32 nonce
semantics. §6 says every v1 device MUST support XChaCha and SHOULD support
AES; if both peers advertise AES every new file MUST use it, otherwise
XChaCha. A device "may omit AES for lack of an approved constant-time
implementation", never because a peer asks. Nothing may switch suite after
a failure. The project rule is libcrux where it covers a primitive, else
RustCrypto or dalek.

Segments are requested out of order (§7.4), so todoke builds each STREAM
nonce directly from the §8 table (`prefix || BE32 counter || final`) and
calls the AEAD once per segment. It does not use the RustCrypto `aead`
STREAM wrapper, which is sequential. The layout is checked against
`stream-nonces.json`.

## Decision

| Suite | Library | Notes |
| --- | --- | --- |
| 1, AES-256-GCM | [`libcrux-aes`](https://crates.io/crates/libcrux-aes) **0.0.10** (2026-10-07), through its `AesGcm256` multiplexer | New dependency. Same release train as the libcrux crates already in use (`libcrux-intrinsics 0.0.9`, `libcrux-platform 0.0.4`, `libcrux-secrets 0.0.7`, `libcrux-traits 0.0.9`), so it adds one package. Marked "pre-verification" by Cryspen: not formally verified. |
| 2, XChaCha20-Poly1305 | [`libcrux-chacha20poly1305`](https://crates.io/crates/libcrux-chacha20poly1305) **0.0.10**, `xchacha20_poly1305` module | Already a dependency (sessions, sealed storage). ChaCha20-Poly1305 is HACL\*-derived and verified; its HChaCha20 subkey step is marked "not formally verified yet" upstream. |

`libcrux-platform 0.0.4` becomes a direct dependency so that todoke can ask
the same CPU questions as libcrux-aes's dispatcher.

**AES advertisement** (`ContentSuites::local`): advertise AES only where
libcrux-aes runs its hardware path:

- x86_64: AVX2 and libcrux's `aes_ni_support` (AVX, SSE, AES-NI,
  PCLMULQDQ, MOVBE), exactly the dispatcher's condition;
- aarch64: NEON, AES, and PMULL (the dispatcher checks only AES; its NEON
  GHASH needs PMULL, so todoke also requires it);
- everything else: no AES.

The portable bit-sliced implementation is constant time too (below) but
several times slower, so a device that would run it advertises XChaCha
only. `ContentSealer`/`ContentOpener` refuse an AES file on such a device
(`SuiteUnavailable`), so the portable path is never used for content even
if a peer misbehaves. The decision depends only on the local CPU, is stable
for the process, and is never influenced by the peer.

**Build configuration.** The advertisement mirrors libcrux-aes's runtime
dispatch, which only works if libcrux-aes was compiled with its hardware
paths. Its build script honours `LIBCRUX_DISABLE_SIMD256` (x86_64) and
`LIBCRUX_DISABLE_SIMD128` (aarch64): with either set, the hardware AES-GCM
types become aliases of the portable implementation, while
libcrux-platform still reports the CPU features. todoke would then
advertise AES and run bit-sliced AES: still constant time, but several
times slower, and contrary to this decision. **Neither variable may be set
for a release build** (or any build whose output is measured or shipped).
`scripts/ci/deny-exceptions-dev-only.sh` fails if either is set in its
environment or appears in a repository workflow or `.cargo/config*` file;
it cannot see a packager's own environment, so release build scripts must
not set them either.

## Constant-time behavior per target

"Hardware" means AES-NI/PCLMULQDQ on x86_64 or AESE/AESMC/PMULL on
aarch64. Checked against libcrux-aes 0.0.10 and libcrux-platform 0.0.4
sources, RustCrypto documentation, and vendor documentation on 2026-10-13.

| Target (CI-checked or supported) | Advertises AES | libcrux-aes path | Notes |
| --- | --- | --- | --- |
| x86_64 Linux/macOS/Windows with AVX2 + AES-NI + PCLMULQDQ | yes | x64 (AES-NI, CLMUL) | Intel lists AESENC/AESENCLAST/AESDEC/AESKEYGENASSIST and PCLMULQDQ as [data-operand-independent-timing instructions](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/resources/data-operand-independent-timing-instructions.html). Per Intel's [DOIT guidance](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/best-practices/data-operand-independent-timing-isa-guidance.html), processors before Ice Lake (Core) or Gracemont (Atom) behave as if DOITM were on; later ones guarantee it only when the OS sets DOITM, which user space cannot do. |
| x86_64 without AVX2 or AES-NI | no | (portable) | XChaCha. |
| aarch64 macOS (Apple silicon) | yes | NEON (AESE/AESMC, PMULL) | libcrux-platform assumes AES and PMULL on Apple silicon, which all Apple arm64 CPUs have. |
| aarch64 Linux with AES and PMULL hwcaps | yes | NEON | Detected through `getauxval`. |
| aarch64 Android, aarch64 iOS (device and simulator), aarch64 Windows | no | (portable) | libcrux-platform 0.0.4 detects aarch64 features only on Linux and macOS (`target_os` "android" and "ios" are not "linux"/"macos"), so these advertise XChaCha only. RustCrypto `aes` 0.9 has the same limit (runtime ARMv8 detection only on Linux and macOS). |
| armv7 Android, 32-bit x86, wasm32 | no | (portable) | XChaCha. |

On aarch64, the Arm architecture guarantees data-independent timing for
AESD/AESE/AESIMC/AESMC and PMULL/PMULL2 only while `PSTATE.DIT` is 1
([FEAT_DIT, DIT register, Arm DDI 0601](https://developer.arm.com/documentation/ddi0601/latest/AArch64-Registers/DIT--Data-Independent-Timing);
with DIT 0 "the architecture makes no statement about the timing properties
of any instructions"). Apple's Platform Security Guide likewise tells
cryptographic code to enable DIT. Neither libcrux nor RustCrypto sets DIT,
and todoke does not yet. These instructions are not known to vary with
data on shipping cores, but that is not an architectural guarantee; see
open question below.

Portable code: libcrux-aes's fallback is bit-sliced AES (no tables, no
secret-dependent branches) and its portable GHASH uses only shifts, XORs,
and masks, so it does not depend on constant-time multiplication.
RustCrypto's `aes-gcm` documents its portable GHASH as constant time only
on CPUs with constant-time multiplication. libcrux's tag comparison is a
constant-time OR-accumulate.

## Alternatives considered

- **RustCrypto `aes-gcm` 0.11.1 / `chacha20poly1305` 0.11.0.** Also
  constant time with hardware intrinsics (x86 AES-NI/CLMUL; ARMv8 AES on
  Linux/macOS) and a fixsliced software fallback. `aes-gcm` had an NCC
  Group review with no significant findings (of an older release). It would
  add `aead`, `cipher`, `ctr`, `ghash`, `polyval`, `aes`, `ctutils` and
  more, while libcrux already covers both primitives; the project rule
  prefers libcrux. Not chosen.
- **Advertising AES everywhere (portable fallback).** Rejected: §6 would
  then force AES on every pair, so a phone without detected hardware AES
  would run bit-sliced AES at a fraction of XChaCha's speed.

## Conformance evidence (all in `cargo test --workspace`)

- Wycheproof (C2SP, commit `7a325932…`, files and SHA-256 in
  `crates/todoke-crypto/testdata/wycheproof/README.md`): all 66 AES-GCM
  cases with 256-bit keys, 96-bit nonces, and 128-bit tags, and all 306
  XChaCha20-Poly1305 cases with 192-bit nonces, through the same wrappers
  the content layer uses (seal reproduces valid ciphertexts; open accepts
  every valid and rejects every invalid case). Other key and nonce sizes
  are not used by todoke and are skipped; the wrappers reject other nonce
  lengths.
- `stream-nonces.json` (every counter/final case for both suites, the
  `content_key_schedule` contexts, keys, prefixes, first nonces, and the
  123-byte AAD and nonce of the manifest fixture's segment) and
  `manifest-hash.json` (root of `hello\n`).
- Truncation, reordering, cross-epoch, cross-file, cross-transfer,
  cross-manifest, cross-suite, and cross-root substitution, last-flag
  forgery, and final-segment substitution all fail.

## Secret lifecycle (O6)

todoke keeps file masters, the HKDF PRK, epoch keys, and nonce prefixes in
`Zeroizing` buffers and zeroizes decrypted slices on drop. Not covered:
libcrux-aes expands the AES key schedule into a state value it does not
wipe; libcrux's XChaCha keeps the HChaCha20 subkey in an unwiped stack
array; HACL HMAC/HKDF temporaries as noted in ADR 0001. These residues are
part of gate O6.

## Consequences

- Measured on Apple M5 Pro (hardware AES): about 500 MiB/s per segment
  with AES and 330 MiB/s with XChaCha, Bao hashing included
  (`bench/README.md`). x86_64 numbers are not measured yet.
- Android and iOS devices advertise XChaCha only until libcrux-platform
  detects their AES hardware (or a reviewed detection is added), so any
  pair involving a phone uses XChaCha.
