# O1: hybrid Noise construction decision

Decision date: **2026-10-11**. Disposition: **construction selected**; normative
schedules and byte layouts are in [PROTOCOL §4.2](../PROTOCOL.md#42-suite-0x0001-reviewed-hfspsk-construction).
This record is not a new cryptographic audit. Production readiness remains gated
by the other open decisions, including backend secret handling and interoperability.

## Decision

Use the existing generic HFS+PSK state machine present in the Snow revision
independently reviewed by Trail of Bits, instantiated with X25519, FIPS 203
ML-KEM-768, ChaChaPoly, and SHA-256. Preserve its exact modifier composition,
KEM-token processing, and PSK ephemeral-key rules. This does not introduce a new
combiner or synthesize a token schedule from unrelated constructions.

The review anchor is **Snow commit `009411d2035a77ece57b0a6873169de7693a0aa0`**, named
in the [Trail of Bits report dated 2024-03-29](https://github.com/trailofbits/publications/blob/master/reviews/2024-03-agilebits-snow-securityreview.pdf),
printed pp. 8–9. The report describes manual source/specification review. Its
Appendix C discusses Kyber resolver behavior, so the hybrid implementation was not
wholly outside the examined material. The report does not say it specifically
exercised all three HFS+PSK combinations; its coverage command does not enable HFS
explicitly. The report records a coverage limitation: cryptographic dependencies
were not comprehensively tested.

The precise claim is **an instantiation of an existing construction present in
independently reviewed source**. Neither the ML-KEM-768 backend nor todoke's
application binding was part of that audit. There is no claim of a dedicated
three-pattern proof, new audit, or production certification. A parameter-specific
audit is not being invented, and the absence of one is not confused with absence
of review of the generic construction.

## Why the source is a sufficient construction reference

The pinned source does more than expose an unused KEM interface:

| Evidence in the audited revision | Consequence |
| --- | --- |
| [Base patterns and modifier loop](https://github.com/mcginty/snow/blob/009411d2035a77ece57b0a6873169de7693a0aa0/src/params/patterns.rs#L488) | PSK and HFS are composed in the existing state machine, including IK, KK, and XX. |
| [HFS insertion algorithm](https://github.com/mcginty/snow/blob/009411d2035a77ece57b0a6873169de7693a0aa0/src/params/patterns.rs#L535) | `e1` follows the first DH operation in the first message containing `e`, or that `e` if there is no DH; `ekem1` immediately follows `ee`. |
| [Handshake processing](https://github.com/mcginty/snow/blob/009411d2035a77ece57b0a6873169de7693a0aa0/src/handshakestate.rs#L239) | PSK mode includes MixKey(public ephemeral); the KEM key/ciphertext pass through EncryptAndHash; the KEM shared secret enters MixKey afterward. |
| [Generic KEM interface](https://github.com/mcginty/snow/blob/009411d2035a77ece57b0a6873169de7693a0aa0/src/types.rs) | Encapsulation-key, ciphertext, and shared-secret lengths are supplied by the KEM implementation rather than hard-coded into the construction. |

[HFS draft revision 1](https://github.com/noiseprotocol/noise_hfs_spec/blob/025f0f60cb3b94ad75b68e3a4158b9aac234f8cb/noise_hfs.md)
has a contradiction between its DH-before-`e1` prose and its KKhfs table. Todoke
pins the existing Snow algorithm, which gives `e, es, e1, ss`, rather than choosing
its own interpretation. [Noise revision 34](https://noiseprotocol.org/noise.html#pre-shared-symmetric-keys)
also requires MixKey at every `e` in PSK mode. That operation matters even before
the final PSK token: XX's first KEM public key carries a tag under a publicly
derivable key. The tag is not early authentication or confidentiality.

ML-KEM-768 is a standardized CCA KEM with the interface this construction needs.
Its 1184-byte public keys, 1088-byte ciphertexts, and 32-byte shared secrets are
from [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final). Substitution uses the
existing generic operations, with no new secret concatenation or combiner. The
wire names explicitly identify MLKEM768; Kyber1024 is not an alias on the wire.

## Security boundary

HFS adds ephemeral KEM confidentiality to the classical/PSK handshake. It does not
prove possession of a static ML-KEM private key, provide PQ signatures, or make
Ed25519/X25519/CPace post-quantum identity authentication. Todoke retains mutual
post-handshake identity/PSK confirmation before any authorization. Its intended
PQ claim is resistance to recording now and decrypting later, assuming the KEM,
KDF, AEAD, honest randomness, erasure, and surrounding protocol meet their stated
requirements. It makes no SEEC/randomness-exposure resilience claim.

The existing static ML-KEM credential in the draft's QR and DeviceBinding remains
a signed/pinned public credential only. It MUST NOT be reused as the HFS ephemeral
key. Its removal before release is an explicit open wire-format decision (O11),
not a fabricated static-KEM token.

The audit found implementation issues, including nonce/error handling, and raised
secret-zeroization concerns. Reusing its construction does not require using the
old build or inheriting those defects. Todoke requires all-zero X25519 rejection,
FIPS 203 validation/implicit rejection, exact message bounds, and production secret
lifecycle review. Public-fixture tooling is not a waiver for production secrets.

## Reference vectors and provenance

The companion generator uses pinned Snow 0.10.0 (originally 0.9.6; the upgrade
left every protocol byte unchanged) for the state machine and libcrux
for X25519 and ML-KEM. Successful-handshake processing is compared with the audited
revision: the HFS modifier and token operations are unchanged; later bounds/nonce
fixes are not a new construction. The generator's reference adapter is offline,
uses only explicitly published deterministic seeds, and is not production code.
Its exact dependency and adapter constraints are documented with the vectors.

All three complete handshake transcripts, final handshake hashes, split outputs,
and initial transport test messages are reproducible. Positive round trips and
negative authentication cases check the reference integration. They establish
reproducibility and detect deviations; they do not substitute for an audit or
independent implementation interoperability (O10). The original six fixture
families remain separate from these handshake fixtures.

## Other candidates examined

These were useful comparisons, not reasons to reject the selected audited source:

- [PQNoise, CCS 2022](https://eprint.iacr.org/2022/539) supplies a generic KEM/hybrid
  security analysis, including randomness-exposure assumptions. Its reviewed
  foundation must not be dismissed simply because it predates FIPS 203. No mapping
  of all three modern PSK modifiers to todoke's concrete profile was located.
- [Renckens et al., SECITC 2024](https://orbilu.uni.lu/handle/10993/63642) studies
  combined classical/PQ base patterns using X25519/Kyber512. Its legacy NoisePSK
  reference machinery is not the current psk2/psk3 semantics.
- [NoisePQC++, QCE 2026 accepted manuscript](https://arxiv.org/abs/2608.00954)
  describes ML-KEM/HFS and claims PSK support in PQ/hybrid contexts. Its stated
  limitations include interoperability testing and SEEC; a lack of implementation
  audit alone would not invalidate a reviewed generic construction.
- [Nyquist's inspected PQ pattern registry](https://github.com/katzenpost/nyquist/blob/943e9d36818950091692baf25086d5802e350a36/pattern/pattern.go#L223)
  leaves PQ PSK patterns unfinished. Katzenpost's pqXX is not the required three
  modern PSK handshakes.
- [Snow's ML-KEM PR #210](https://github.com/mcginty/snow/pull/210) is separate from
  the 2024 audit. Its existence is neither proof of review of that backend nor a
  reason to disregard the already reviewed generic state machine.

## Open questions

1. Which production backend integration provides reviewed constant-time handling,
   secret-state erasure, platform support, and dependency audit evidence (O6)?
2. Which independent implementation reproduces the complete transcripts and
   adversarial cases, beyond this reference generator (O10)?
3. Should the unused static ML-KEM credential be removed before v1 release (O11)?
4. The existing CPace, persistence, FFI, transport, identity, and filesystem gates
   remain in PROTOCOL §16; this construction decision does not resolve them.
