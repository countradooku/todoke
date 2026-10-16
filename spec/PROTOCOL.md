# todoke protocol v1

**Status: normative draft, not a deployable protocol.** This document replaces the
requirements baseline and is the source of truth for v1 wire encodings, fixtures,
and subsequent implementations. Suite 0x0001 now has an exact hybrid HFS+PSK
construction (§4.2), based on independently reviewed Snow source. Its new ML-KEM
backend and todoke integration are not covered by that audit. Production sessions
remain **disabled** pending the applicable implementation, secret-lifecycle, and
interoperability gates in §16. An implementation MUST NOT substitute ordinary
classical Noise. Fixtures establish deterministic encodings, not production readiness.

The architectural requirements in [DESIGN.md](../docs/DESIGN.md) apply. Rust owns
protocol, cryptography, file handling, and consent; SwiftUI, Jetpack Compose, and
GPUI are thin clients. BoltFFI MUST NOT carry secrets. All transports, the LAN,
Wi-Fi peer-to-peer links, AWDL, and QUIC relays, are untrusted byte pipes. v1 uses
no Bluetooth and no USB transport (§10.1).

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, NOT RECOMMENDED, MAY, and OPTIONAL are interpreted as in
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) only when capitalized.

## 1. Encoding, notation, and validation

A byte is an octet. `u8`, `u16`, `u32`, and `u64` are unsigned integers of exactly
1, 2, 4, and 8 bytes. Integers are **big-endian**, except the explicitly identified
Bao length and Noise AEAD nonce counter. `x[n]` is exactly n bytes; `||` is concatenation; `[..n]` means the
first n bytes. Strings in cryptographic formulas are ASCII bytes without quotes.
`\0` means one zero byte, not two printable characters. No implicit padding,
terminator, alignment, variable integer, JSON, CBOR, or platform-native encoding
is permitted on the wire. Tables list fields in transmission order. Repeated
records have their own layout table; no unspecified field is permitted.

`B3(x)` is the 32-byte unkeyed BLAKE3 hash. `HMAC-BLAKE3` is RFC 2104 HMAC with
unkeyed BLAKE3, 64-byte block size and 32-byte output; it is **not** BLAKE3 keyed
mode. `HKDF(salt, ikm, info, n)` is RFC 5869 HKDF-SHA-256 Extract then Expand,
returning n bytes. `Sign(k,x)` is pure Ed25519 from RFC 8032, not Ed25519ph or
Ed25519ctx. A signature is 64 bytes. Ed25519 verification MUST reject noncanonical
encodings, noncanonical scalars, weak/small-order keys and R points, and invalid
signatures. Strict dalek verification MUST be accompanied by canonical public-key
encoding validation; constructing a dalek VerifyingKey alone does not establish
canonical encoding. Public keys MUST be validated before use. X25519 all-zero shared outputs MUST be rejected. ML-KEM inputs MUST
pass FIPS 203 input checks in the selected library.

All length/count checks, checked arithmetic, enum validation, reserved-zero
checks, and aggregate resource checks MUST precede allocation or indexing.
Trailing bytes, duplicate fields, noncanonical order, overflow, truncated records,
and unknown enum values MUST be rejected unless this document explicitly permits
them. A field with an exact size still has to be received in full. No peer input
MAY panic, cause unchecked allocation, or bypass a core policy decision.

Unix times are integer seconds since 1970-01-01 UTC, without leap seconds, range
0..253402300799. Epochs are `floor(unix_time / 900)`, encoded as u64. Durations use
a monotonic clock. Expiry comparisons allow at most 120 seconds clock skew;
unknown or regressed wall-clock state MUST require local confirmation or re-pairing,
never silent expiry bypass. Zero public IDs/nonces are prohibited in live messages;
zero sentinels are allowed only where stated. Random identifiers/nonces MUST come
from an OS CSPRNG. Fixtures use public deterministic values, never live credentials.

## 2. Identities and revocation

Each device MUST generate its own Ed25519 signing seed, independent X25519 Noise
static secret, and ML-KEM-768 static decapsulation key. Ed25519 keys MUST NOT be
converted into X25519 keys. `device_id = B3(device_ed25519_public_key)[..16]`.
The 16-byte ID is a lookup/display aid; authorization MUST compare the full 32-byte
key. An ID collision MUST NOT merge identities. A person's identity is an
independent Ed25519 root public key; `person_id = B3(person_root)[..16]`. Root
secrets SHOULD remain offline except for issuing device bindings and revocations.
Device private keys MUST NOT be shared between devices.

The existing `kem_static` credential is retained in v1 bindings and QR encodings
for a future assigned PQ-identity profile. Suite 0x0001 MUST NOT use it as the HFS
ephemeral key, encapsulate to it, or claim proof of its decapsulation-key possession.
Its signatures and pairing pin authenticate the public credential only. HFS uses
a separately generated, single-session ML-KEM key (§4.2); no static-KEM token is
introduced. Whether to remove this unused credential before v1 release is O11.

A person certifies a device with the following `DeviceBinding`. Both signatures
are mandatory, including for a person's first device. Possession of another device
under the same root does not inherit that device's pairings or file consent.

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| version | 2 | u16 = 1 |
| person_root | 32 | Valid Ed25519 public key |
| device_public | 32 | Valid device Ed25519 public key |
| noise_static | 32 | Valid independently generated X25519 public key |
| kem_static | 1184 | Valid FIPS 203 ML-KEM-768 public credential; unused by HFS |
| serial | 8 | u64, 1..2^64-1, unique and increasing for this root/device |
| not_before | 8 | Unix time |
| not_after | 8 | Unix time; > not_before, lifetime <= 366 days |
| capabilities | 4 | u32 = 0; reserved for future device authority scopes |
| root_signature | 64 | Sign(root, `todoke/v1/device-binding\0` \|\| preceding 1310 bytes) |
| device_signature | 64 | Sign(device, `todoke/v1/device-possession\0` \|\| preceding 1374 bytes) |

Total: 1438 bytes. Current time MUST be in [not_before, not_after), subject to the
bounded clock-skew policy. Future or expired bindings MUST NOT start a session. An already active
session MUST close on newly learned revocation or binding expiry. Binding renewal
MUST preserve the full device and static keys in v1; rotation of any static key
requires a new pairing. Trust in a person root MUST originate in an authenticated
pairing or explicit locally authorized enrollment, never merely in a self-signature.

`Revoke` (transport type 0x0040) has this layout:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| version | 2 | 1 |
| person_root | 32 | Previously trusted root |
| record_id | 16 | Unique random identifier |
| sequence | 8 | u64, 1..2^64-1, monotonically issued by root |
| issued_at | 8 | Unix time |
| device_public | 32 | Revoked full device key |
| through_serial | 8 | u64, 1..2^64-1; revoke bindings with serial <= this |
| reason | 2 | 1 lost, 2 compromised, 3 retired; no free text |
| signature | 64 | Sign(root, `todoke/v1/revoke\0` \|\| preceding 108 bytes) |

Total: 172 bytes. Records are irrevocable and MUST be retained durably for as long
as the root is trusted. Receiving the same record is idempotent; conflicting signed
records with the same sequence require disabling that root pending local resolution.
A valid older record MUST still be applied; a high sequence is not evidence that
all preceding records were received. Revocation MUST terminate affected sessions,
remove discovery/rendezvous keys, and invalidate resumable authorization. Peers MAY
forward root-signed records in authenticated sessions, at most 64 records/session.
There is no v1 global revocation service or freshness guarantee: an offline peer
may not know a device was revoked. Root replacement/recovery is unresolved (§16).

## 3. Pairing

### 3.1 QR pairing

The QR displayer is the responder; the scanner is the initiator. The displayer
creates a fresh pairing ID and 256-bit one-time PSK, valid for at most 300 seconds.
Scanning is local pairing intent, not file-transfer consent. The QR is sensitive:
anyone who sees it may race to pair. It MUST NOT be uploaded, logged, placed in a
URL query, or passed as raw secret-bearing bytes across FFI. QR rendering/scanning
requires a reviewed core/platform interface that preserves this boundary (§16).

`QrPayload` has this fixed binary layout:

| Offset | Field | Bytes | Limit / semantics |
| ---: | --- | ---: | --- |
| 0 | magic | 4 | ASCII `TDKQ` |
| 4 | version | 2 | u16 = 1 |
| 6 | hybrid_suite | 2 | u16 = 0x0001, assigned in §4.2; production gated by §16 |
| 8 | pairing_id | 16 | Random, one-time |
| 24 | expires_at | 8 | Unix time; no more than 300 seconds after creation |
| 32 | device_public | 32 | Responder Ed25519 public key |
| 64 | noise_static | 32 | Responder X25519 public key |
| 96 | kem_static | 1184 | Responder ML-KEM-768 public credential; not the HFS key |
| 1280 | one_time_psk | 32 | Uniform random bytes |

Total: 1312 bytes. QR text is exactly `TODOKE:` followed by
[RFC 9285 Base45](https://www.rfc-editor.org/rfc/rfc9285) encoding of the binary
payload, without padding or whitespace normalization: 1975 ASCII characters.

| QR text field | Bytes | Limit / semantics |
| --- | ---: | --- |
| prefix | 7 | ASCII `TODOKE:`, exact case |
| base45 | 1968 | 656 three-character groups, one per two payload bytes; RFC 9285 alphabet only |

Spaces in the Base45 alphabet are significant. A decoder MUST enforce both lengths,
the exact prefix, canonical Base45, version, suite, key validation, and expiry.
Future formats MUST use a new version; permissive suffixes/optional fields are forbidden.

The responder MUST reserve an offer for at most one locally authenticated pairing
attempt at a time. Invalid unauthenticated attempts MUST NOT consume it. Once mutual
identity and PSK confirmation succeed, the original QR PSK and offer MUST be burned
durably before application traffic. A successfully used or uncertain committed QR
MUST NOT be replayed after restart; generate a new one. Pairing pins the responder's
three full keys from the QR against its authenticated DeviceBinding.

On a local network the scanner finds the displayer by the stranger token derived
from the QR (§9) and sends the QR's `ClientHello` to no other device, so pairings
shown side by side do not reach each other's displayers.

### 3.2 Human code pairing

The displayer/responder creates a uniformly random 10-digit ASCII decimal code
(including leading zeroes), a random 16-byte pairing ID, and a 300-second offer.
The code MUST NOT be directly hashed into a Noise PSK. V1 selects balanced
**CPACE-RISTR255-SHA512**, pinned to
[draft-irtf-cfrg-cpace-21](https://www.ietf.org/archive/id/draft-irtf-cfrg-cpace-21.html),
§7 and §8.3. CPace is designed for low-entropy shared passwords with transcript
binding. SPAKE2 is not selected: RFC 9382 would also require a specific password
mapping, group profile, and confirmation design; changing PAKEs is a version change.
CPace remains an Internet-Draft, and the conformance/production-library gate in §16
MUST be resolved before enabling this mode. Implementations MUST NOT silently track
later draft revisions.

For local code pairing, the initiator first requests the public offer on its newly
opened stream using the stranger advertisement it selected. These records precede
ClientHello, disclose no code-derived value, and have these bodies:

| CodeOfferRequest field | Bytes | Limit / semantics |
| --- | ---: | --- |
| version | 2 | 1 |
| stranger_token | 8 | Exact currently advertised stranger token |

| CodeOffer field | Bytes | Limit / semantics |
| --- | ---: | --- |
| version | 2 | 1 |
| stranger_token | 8 | Echo request |
| pairing_id | 16 | Current random offer ID |
| expires_at | 8 | Offer expiry, <=now+300 seconds |

Totals: 10 and 34 bytes. Exactly one request and response per stream, within 5 seconds;
only the code mode may use them. A stale/unknown token closes silently. The initiator
uses the returned pairing_id in Hello. This is untrusted bootstrap data, bound into
CPace and Noise below. It is not peer authentication. A code offer MUST allow only
one CPace attempt at a time; concurrent requests can receive the public offer but
MUST NOT run concurrent PAKEs. On mutual identity confirmation it is reserved for
that session; successful ratchet commitment burns the code/offer durably. An uncertain
pending commitment burns the offer as well. Failed pre-authentication attempts consume
the bounded attempt budget, not a new contact's state.

`CodeShareA` and `CodeShareB` use the same fixed layout after both Hellos (§4):

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| pairing_id | 16 | Exact pending code offer |
| role | 1 | 0 for A/initiator, 1 for B/responder |
| element | 32 | Canonical non-neutral Ristretto255 CPace element |

Total: 49 bytes. A sends first; B responds exactly once. Duplicate, wrong-role,
invalid/neutral, truncated, or noncanonical elements MUST abort. Password bytes are
exactly the 10 ASCII digits, with no Unicode or integer normalization. CPace's
internal algorithms and encodings MUST come from a conforming library, not a new
implementation here. Let `code_offer = CodeOfferRequest || CodeOffer`, using their
bodies above. Set `CI = "todoke/v1/cpace-ci\0" || code_offer || ClientHello || ServerHello`,
`sid = client_nonce || server_nonce`, `ADa = "todoke/v1/cpace-a\0"`, and
`ADb = "todoke/v1/cpace-b\0"`; Hello bytes mean the 58-byte bodies below.
The 64-byte ISK feeds:

```
pre_noise = code_offer || ClientHello || ServerHello || CodeShareA || CodeShareB
psk = HKDF(B3(pre_noise), ISK, "todoke/v1/cpace-psk\0", 32)
```

These context choices require conformance vectors before release. The PSK enters
hybrid XXpsk3; application traffic MUST wait for mutual Noise confirmation, identity
binding, and the ratchet commit. No plaintext success/failure distinction for code,
group validation, identity, or Noise authentication MAY be sent. A code offer permits
at most 5 failed attempts total, with at least 2 seconds between attempts; exhaustion
requires a new code and local user action. Global budgets also apply (§13). Attackers
can exhaust an offer; this availability tradeoff does not justify unlimited guesses.

## 4. Session establishment and authentication

Only one session attempt and one active session per device pair are allowed. Transfer
sender/receiver roles are independent of handshake initiator/responder roles. The
QR scanner and code entrant are always initiators, and their displayer is the
responder; these roles hold over relay tunnels too. For direct contact sessions,
the party opening the stream is the initiator. For contact relay sessions, the
lexicographically smaller full device key is initiator, the larger responder,
independent of registration order. For simultaneous direct contacts,
the lexicographically smaller full device key retains its outgoing attempt; the
larger retains its incoming attempt. No 0-RTT, transport resumption ticket, transport
certificate, or discovery match authorizes application traffic.

### 4.1 Prelude layouts

Before Noise transport, each prelude record is `length:u16 || kind:u8 || body`.
Length counts kind+body, is 1..8192, and excludes the two-byte prefix. There are no
unframed bytes. This is not the encrypted transport envelope of §5.

| Prelude envelope field | Bytes | Limit / semantics |
| --- | ---: | --- |
| length | 2 | u16, 1..8192, includes kind and body |
| kind | 1 | Registry below |
| body | length-1 | 0..8191, exact per-kind layout |

| Prelude kind | Message | Body layout / bound |
| --- | --- | --- |
| 0x01 | ClientHello | 58 bytes, table below |
| 0x02 | ServerHello | 58 bytes, table below |
| 0x03 | CodeShareA | 49 bytes, §3.2 |
| 0x04 | CodeShareB | 49 bytes, §3.2 |
| 0x05 | NoiseHandshake | table below and exact inner layouts in §4.2 |
| 0x06 / 0x07 | CodeOfferRequest / CodeOffer | 10 / 34 bytes, §3.2, only before code Hellos |
| 0x00, 0x08..0xff | Reserved | MUST reject/close, no fallback |

ClientHello and ServerHello each have this layout:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| magic | 4 | ASCII `TDKE` |
| version | 2 | 1; exact equality, no version list |
| hybrid_suite | 2 | 0x0001; assigned profile, production gates in §16 |
| mode | 1 | 1 QR/IKpsk2, 2 code/XXpsk3, 3 contact/KKpsk2 |
| flags | 1 | 0 |
| locator | 16 | QR/code pairing_id; contact rendezvous token[..16] (§9) |
| client_nonce | 16 | Random initiator nonce, echoed by ServerHello |
| server_nonce | 16 | Zero in ClientHello; fresh random in ServerHello |

Total: 58 bytes. The responder MUST echo version/suite/mode/locator/client_nonce
exactly. Hello fields are untrusted hints until the full transcript is authenticated.
A Hello carries no ratchet generation: a contact locator is derived from the
current generation's pair secret (§9), so the locator alone resolves the full pair
and its generation, and the handshake then requires that generation's PSK. A
counter on the wire would only link a pair's sessions across epochs. Contact
locators MAY use current/adjacent epochs; a locator that resolves to no committed
pair, or to more than one, is an unknown peer. Nothing about the pair's state is
sent back, and an unresolved or failing contact Hello MUST NOT trigger automatic
re-pairing, previous-PSK trials, suite fallback, or deletion of a contact.
Divergent generations are found locally from the ratchet journal (§4.4); a stale
generation restored from a backup resolves to no pair (§16 O3).

`NoiseHandshake` body:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| message_index | 1 | IK/KK: 1..2; XX: 1..3; strictly increasing, starts at 1 |
| token_bytes | remaining | Exactly the per-pattern/message size in §4.2; 64..1296 bytes |

The kind and message index are framing, not Noise payload. Receivers MUST enforce
the expected pattern, sender role, index, and exact length before handing the
inner bytes to Noise. No retransmission, extra handshake payload, trailing bytes,
or transport bytes embedded inside this record are permitted.

### 4.2 Suite 0x0001: reviewed HFS+PSK construction

| Case | Required logical pattern | Prior authenticated material |
| --- | --- | --- |
| QR | IKpsk2 | Initiator pins responder static keys from QR; both possess one-time PSK |
| Code | XXpsk3 | CPace supplies PSK; no pretrusted peer static key |
| Existing contact | KKpsk2 | Both pin full static keys and the same current pair PSK/generation |

#### 4.2.1 Construction and review provenance

V1 instantiates the existing generic HFS+PSK construction implemented by
[Snow commit 009411d2035a77ece57b0a6873169de7693a0aa0](https://github.com/mcginty/snow/tree/009411d2035a77ece57b0a6873169de7693a0aa0),
the revision identified in the [Trail of Bits security review, 2024-03-29](https://github.com/trailofbits/publications/blob/master/reviews/2024-03-agilebits-snow-securityreview.pdf).
The audit includes manual source/specification review. It does not claim dedicated
testing of these three HFS+PSK cases, nor review of ML-KEM-768 or todoke integration.
This is reuse of an existing reviewed state machine with a standardized KEM
instantiation, **not a claim of a new todoke audit or formal security proof**.

The [O1 decision and evidence](decisions/O1-HYBRID-NOISE.md) pin the construction
and audit boundaries. The source's HFS insertion rule resolves the contradictory
KKhfs table in [HFS draft revision 1](https://github.com/noiseprotocol/noise_hfs_spec/blob/025f0f60cb3b94ad75b68e3a4158b9aac234f8cb/noise_hfs.md):
use `e, es, e1, ss`, as in Snow, not that draft table's `e, e1, es, ss`.
Implementations MUST follow the exact schedules below; the draft is not an
alternative wire profile. PQNoise research supplies useful analysis of other KEM
transformations but is not asserted to prove this todoke profile.

#### 4.2.2 Algorithms and names

The classical state-machine operations are those of
[Noise revision 34](https://noiseprotocol.org/noise.html), with the HFS operations
below. The KEM is **FIPS 203 ML-KEM-768**, not Kyber round 3, ML-KEM-512/1024, or
X-Wing. Hash is SHA-256; transport and handshake cipher are Noise ChaChaPoly
(ChaCha20-Poly1305, 32-byte key, 16-byte tag). Content encryption remains §8.

| Case | Exact ASCII protocol name, no NUL |
| --- | --- |
| QR | `Noise_IKpsk2+hfs_25519+MLKEM768_ChaChaPoly_SHA256` |
| Contacts | `Noise_KKpsk2+hfs_25519+MLKEM768_ChaChaPoly_SHA256` |
| Code | `Noise_XXpsk3+hfs_25519+MLKEM768_ChaChaPoly_SHA256` |

Names are transcript inputs, not transmitted fields or negotiation strings.
Equivalent-looking spellings, modifier reorderings, hash/cipher substitutions,
and alternate KEM identifiers MUST be rejected as different protocols. Initialize
`h = SHA256(protocol_name)` (each name exceeds 32 bytes), `ck = h`, and an empty
CipherState, then MixHash(prologue), then the pre-messages in the order below.

| Primitive value | Exact bytes | Encoding / lifetime |
| --- | ---: | --- |
| X25519 public key | 32 | RFC 7748 u-coordinate; static or fresh session ephemeral as scheduled |
| X25519 secret input / DH result | 32 / 32 | Library-managed secret; never transmitted; all-zero result MUST fail |
| ML-KEM encapsulation key `e1` | 1184 | FIPS 203 public-key encoding and input validation |
| ML-KEM ciphertext `ekem1` | 1088 | FIPS 203 ciphertext encoding |
| ML-KEM shared secret | 32 | Secret; only input to MixKey |
| ML-KEM decapsulation key | 2400 | Secret; single session; never transmitted |
| PSK | 32 | QR, CPace result, or contact generation, exactly one per handshake |
| `h`, `ck`, split keys | 32 each | `h` is public; chaining/traffic keys are secrets |

The initiator MUST generate fresh independent X25519 ephemeral material and a
fresh ML-KEM-768 ephemeral key pair for each attempt. The responder MUST generate
fresh independent X25519 ephemeral material and encapsulation randomness for each
attempt. Follow FIPS 203 KeyGen's independent 32-byte `d` and `z` and Encaps's
32-byte `m`, supplied by a CSPRNG through the reference library. No seed derivation
from the PSK, device key, session nonce, or peer input is permitted. No ephemeral
key or encapsulation randomness MAY be reused after failure, retry, or transport
change. Erase ephemeral secrets and intermediate DH/KEM results after use.

#### 4.2.3 Transcript operations

`MixHash(x)`, `MixKey(x)`, `MixKeyAndHash(x)`, `EncryptAndHash(x)`,
`DecryptAndHash(x)`, and `Split()` MUST have the Noise revision 34 semantics.
Noise's HKDF uses HMAC-SHA-256 with empty info, the current `ck` as salt, and the
specified input as IKM; it is distinct from the labeled application KDFs elsewhere
in this document. Each MixKey or MixKeyAndHash installs the derived cipher key and
resets its nonce to zero. A keyed CipherState uses nonce
`0x00000000 || LE64(counter)`. Handshake EncryptAndHash/DecryptAndHash uses AAD
equal to `h` immediately before encryption; the ciphertext including its tag is
then hashed. Transport AAD is empty (§5). A message is not authenticated
merely because its public-data-derived key can produce a tag.

| Token / step | Sender and receiver operations, in exact order | Wire bytes |
| --- | --- | ---: |
| Pre-message `s` | MixHash(the indicated full X25519 static public key), initiator pre-message before responder pre-message | 0 |
| `e` | Send/read X25519 ephemeral public key; MixHash(key), then MixKey(key) because every v1 pattern has a PSK modifier | 32 |
| `s` | EncryptAndHash / DecryptAndHash(sender's X25519 static public key) | 48 in all scheduled v1 positions |
| `ee` | MixKey(X25519(initiator ephemeral, responder ephemeral)) | 0 |
| `es` | MixKey(X25519(initiator ephemeral, responder static)) | 0 |
| `se` | MixKey(X25519(initiator static, responder ephemeral)) | 0 |
| `ss` | MixKey(X25519(initiator static, responder static)) | 0 |
| `e1` | Initiator generates fresh ML-KEM key pair; EncryptAndHash(1184-byte encapsulation key). Responder DecryptAndHash, then validates the public key | 1200 |
| `ekem1` | Responder Encaps(peer `e1`), then EncryptAndHash(1088-byte KEM ciphertext), then MixKey(32-byte shared secret). Initiator DecryptAndHash **before** Decaps, then MixKey(decapsulated secret) | 1104 |
| `psk` | MixKeyAndHash(32-byte PSK), at the specified message end | 0 |
| Payload | EncryptAndHash / DecryptAndHash(empty string), after all tokens in **every** message | 16 |
| Split | Noise HKDF(ck, empty, 2); output 1 initiator-to-responder, output 2 responder-to-initiator; both transport counters start at 0 | 0 |

The hybrid combination is the scheduled sequential Noise MixKey operations, with
`ee` immediately followed by the AEAD-protected KEM ciphertext and its MixKey. No
secret concatenation, alternate combiner, SEEC transform, extra KEM, or static-KEM
token MAY be added. V1 does not claim resilience to exposed/bias-controlled
ephemeral randomness. The PSK `e` rule applies even before reaching the `psk` token;
omitting it changes both the transcript and the wire sizes.

#### 4.2.4 Exact schedules

`->` is initiator to responder, `<-` is responder to initiator. The dashed line
separates pre-messages (known keys, no wire bytes) from actual handshake messages.
Every message below additionally ends with the empty encrypted payload.

```text
IKpsk2+hfs:
  <- s
  ...
  -> e, es, e1, s, ss
  <- e, ee, ekem1, se, psk

KKpsk2+hfs:
  -> s
  <- s
  ...
  -> e, es, e1, ss
  <- e, ee, ekem1, se, psk

XXpsk3+hfs:
  ...
  -> e, e1
  <- e, ee, ekem1, s, es
  -> s, se, psk
```

#### 4.2.5 Inner byte layouts

Offsets below begin at `token_bytes[0]`, excluding the prelude envelope and
message index. Each `E(x)` contains ciphertext followed by its 16-byte tag. DH,
PSK, and MixKey operations have no encoded bytes. Nonces are implicit counters,
not additional fields. Payloads MUST be empty; application/identity data MUST wait
for the post-Split Identity messages in §4.3.

IK message 1 (`->`), **1296 bytes**:

| Offset | Field | Bytes | Limit / semantics |
| ---: | --- | ---: | --- |
| 0 | `e_i` | 32 | Initiator X25519 ephemeral key |
| 32 | `E(e1)` | 1200 | 1184-byte ML-KEM key + 16-byte tag, after `es` |
| 1232 | `E(s_i)` | 48 | 32-byte static key + 16-byte tag |
| 1280 | `E(empty)` | 16 | Empty payload tag, after `ss` |

IK and KK message 2 (`<-`), **1152 bytes**:

| Offset | Field | Bytes | Limit / semantics |
| ---: | --- | ---: | --- |
| 0 | `e_r` | 32 | Responder X25519 ephemeral key |
| 32 | `E(ekem1)` | 1104 | 1088-byte KEM ciphertext + 16-byte tag, after `ee` |
| 1136 | `E(empty)` | 16 | Empty payload tag, after KEM MixKey, `se`, and `psk` |

KK message 1 and XX message 1 (`->`), **1248 bytes**:

| Offset | Field | Bytes | Limit / semantics |
| ---: | --- | ---: | --- |
| 0 | `e_i` | 32 | Initiator X25519 ephemeral key |
| 32 | `E(e1)` | 1200 | ML-KEM key + tag; KK after `es`, XX after MixKey(public `e_i`) |
| 1232 | `E(empty)` | 16 | Empty payload tag; KK after `ss`, XX immediately after `e1` |

XX message 2 (`<-`), **1200 bytes**:

| Offset | Field | Bytes | Limit / semantics |
| ---: | --- | ---: | --- |
| 0 | `e_r` | 32 | Responder X25519 ephemeral key |
| 32 | `E(ekem1)` | 1104 | KEM ciphertext + tag, after `ee` |
| 1136 | `E(s_r)` | 48 | Responder static key + tag, after KEM MixKey |
| 1184 | `E(empty)` | 16 | Empty payload tag, after `es` |

XX message 3 (`->`), **64 bytes**:

| Offset | Field | Bytes | Limit / semantics |
| ---: | --- | ---: | --- |
| 0 | `E(s_i)` | 48 | Initiator static key + tag, continuing the previous cipher state |
| 48 | `E(empty)` | 16 | Empty payload tag, after `se` and `psk` |

For cross-checking the reset rules, the AEAD counters for encrypted fields in
table order MUST be: IK1 `0,1,0`; IK2/KK2 `0,0`; KK1 `0,0`; XX1 `0,1`;
XX2 `0,0,0`; XX3 `1,0`. These counters belong to different keys where a MixKey
intervenes; they are not transmitted and MUST NOT be replaced with one global
handshake counter.

For the complete prelude record, `length = 2 + inner_length` (kind + index +
inner bytes); the wire record adds the two-byte length prefix. Thus IK record
sizes are 1300/1156, KK 1252/1156, and XX 1252/1204/68 bytes. A receiver MUST
reject any other size for that mode and index. In XX message 1 the AEAD key is
derived only from public inputs: its tags give **no** peer authentication or
confidentiality. No pre-Split payload is accepted for any pattern.

#### 4.2.6 Transcript binding and failure

Required prologue bytes are `"todoke/v1/noise-prologue\0" || pre_noise`, where QR
and contact `pre_noise` consist of ClientHello body followed by ServerHello body;
code mode uses the complete §3.2 formula, including public offer bodies. There is
no implicit domain terminator beyond the one shown. Envelope headers are excluded.
The final handshake hash `h` is exactly 32 bytes.
`session_id = B3("todoke/v1/session\0" || h)`.

On invalid length, malformed ML-KEM public key, all-zero DH output, AEAD failure,
unexpected state, or failure to match a pinned X25519 static key, implementations
MUST close, erase the attempt's secrets, and send no transport traffic. ML-KEM
decapsulation MUST use the library's constant-time implicit rejection; it MUST NOT
expose a ciphertext-validity bit or substitute an explicit rejection oracle.
An implicitly rejected ciphertext produces a different secret and the subsequent
authenticated payload MUST fail. No secret-dependent fallback or retry is allowed.
Peer-controlled failures MUST be reported as the generic authentication error
where an error can safely be sent (§12), without distinguishing DH/KEM/PSK causes.
An unconfirmed responder after IK/KK MUST wait for §4.3 before authorizing a peer.

### 4.3 Identity confirmation

After Noise Split, both peers send `Identity` (0x0001) before any other transport
message, initiator first. It proves the signing identity is bound to the Noise
static keys and the transcript. Merely completing an IK/KK two-message exchange
is insufficient proof to the responder of initiator PSK possession.

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| binding_len | 2 | u16 = 1438 |
| binding | 1438 | Valid DeviceBinding (§2) |
| handshake_hash | 32 | Equals h |
| signature | 64 | Sign(device, `todoke/v1/identity\0` \|\| h \|\| role:u8 \|\| B3(binding)) |

Total: 1536 bytes. Role is 0 initiator or 1 responder and is reconstructed, not
an additional wire field. The Noise X25519 static key MUST exactly match
`binding.noise_static`; QR pins and stored full device/person/static credentials
MUST match. The signed `kem_static` credential is compared as data; this check
MUST NOT be described as a Noise static-KEM possession proof (§2).
Revocation/expiry checks precede identity confirmation. Unknown identity changes
MUST fail closed and require explicit local pairing. The core MUST NOT expose a
peer as authenticated before both proofs and transcript checks succeed.

### 4.4 Pair PSK ratchet and crash policy

Let `psk` be the QR PSK, CPace-derived PSK, or current contact PSK. After mutual
identity confirmation, derive exactly:

```
psk_next = HKDF(h, psk, "todoke/v1/psk-ratchet\0", 32)
generation_next = generation + 1
```

Overflow closes the session and requires new pairing. This formula provides key
separation; because h is not a fresh secret, it MUST NOT be advertised as
post-compromise healing. Derive persistent discovery state only after commit:

```
pair_secret = HKDF(empty, psk_next, "todoke/v1/pair-secret\0", 32)
pair_key    = HKDF(empty, pair_secret, "todoke/v1/discovery-key\0", 32)
```

An empty HKDF salt has RFC 5869 semantics (32 zero bytes). Pair secrets change on
every committed session; generation and matching discovery state are persisted
atomically with psk_next.

`RatchetReady` (0x0002), `RatchetCommit` (0x0003), and `RatchetAck` (0x0004) share
this fixed layout:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| session_id | 32 | Current session |
| generation_next | 8 | Current generation + 1 |
| confirmation | 32 | HMAC-SHA256(psk_next, `todoke/v1/ratchet-confirm\0` \|\| type:u16 \|\| role:u8 \|\| session_id \|\| generation_next:u64) |

Total: 72 bytes. Here role is the sending endpoint's handshake role (0 initiator,
1 responder); type is the exact transport message type. Use constant-time MAC verification. These messages are also Noise
encrypted. Only the following order is valid:

1. Initiator durably journals pending (generation_next, h, psk_next, peer keys),
   disables concurrent sessions, then sends Ready.
2. Responder verifies Ready, durably journals the same pending state, sends Ready.
3. Initiator verifies Ready, atomically replaces old pair secrets with the new state,
   marks the transaction pending acknowledgment, zeroizes old secrets, sends Commit.
4. Responder verifies Commit, atomically commits new state and zeroizes old secrets,
   sends Ack. Its application receive gate opens only after that Ack is queued.
5. Initiator verifies Ack, durably clears its pending marker, and opens its gate.

The responder clears its pending marker when Ack is queued after durable commit.
Reliable in-order transport ensures subsequent responder application messages cannot
arrive ahead of Ack. A lost connection after this point may still leave the initiator
uncertain: this is deliberately fail-closed. Any crash/interruption with a pending
journal MUST disable that pairing and require explicit fresh QR/code pairing; it
MUST NOT restore an old PSK or attempt both generations. Failure before verified
peer identity and before a pending journal leaves the old pairing usable. Divergent
generations MUST be reported locally without revealing contact details to the peer.
No application frame, manifest, file key, or content is permitted before this gate.
Seamless interrupted-ratchet recovery is an open question, not an implicit retry.

## 5. Noise transport framing and rekey

Each ordered byte pipe after Split carries:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| ciphertext_len | 2 | u16, 20..65535; excludes itself |
| ciphertext | ciphertext_len | One Noise transport ciphertext, including 16-byte AEAD tag |

The prefix is untrusted and bounded before buffering. It is not additional Noise
AAD; modification yields a framing or authentication failure, never a decoded
partial message. Noise transport MUST use empty AAD, the directional Split key,
and nonce `0x00000000 || LE64(counter)`; it does not use `h` as transport AAD.
Exactly one complete decrypted frame occupies a ciphertext.
Maximum plaintext is 65519 bytes. No compression is defined. Every pipe is a bounded,
reliable, ordered byte stream; any acknowledgments below it have no protocol authority. Multipath sharing of a CipherState is forbidden.
Moving to a new pipe requires a fresh session and new Accept before resume.

Decrypted frame layout:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| type | 2 | Assigned registry below |
| flags | 2 | u16 = 0 |
| body | remaining | 0..65515; exact per-type layout and tighter limits below |

There is no separate frame sequence: each directional Noise CipherState supplies
its strictly increasing nonce. Failed decryption closes the session immediately.
Counters MUST NOT wrap or be reused. A transport write interrupted midway closes
the session; its cipher state MUST NOT be reused on another pipe.

| Type | Message / section |
| --- | --- |
| 0x0001 | Identity, §4.3 |
| 0x0002..0x0004 | RatchetReady / RatchetCommit / RatchetAck, §4.4 |
| 0x0005 | Capabilities, §6 |
| 0x0006 | KeyUpdate, below |
| 0x0007 / 0x0008 | Ping / Pong, §13 |
| 0x0009 | Error, §12 |
| 0x0010 / 0x0011 | ManifestStart / ManifestPart, §7.1 |
| 0x0012 | Accept (AcceH), §7.3 |
| 0x0013 | Reject, §7.3 |
| 0x0014 | FileKey, §8 |
| 0x0015 / 0x0016 | ChunkRequest / Chunk, §7.4 |
| 0x0017 / 0x0018 | ResumeQuery / ResumeStatus, §7.5 |
| 0x0019 / 0x001a | Cancel / CancelAck, §7.6 |
| 0x001b / 0x001c | Complete / DeliveryReceipt, §7.7 |
| 0x0020 | LinkAbilities, §10.2 |
| 0x0021 / 0x0022 | LinkOffer / LinkAnswer, §10.2 |
| 0x0040 | Revoke, §2 |
| 0x0100..0x01ff | Reserved Tor |
| 0x0200..0x02ff | Reserved PQ variants |
| 0x0300..0x03ff | Reserved receipt extensions |
| 0x0400..0x04ff | Reserved revocation distribution |
| 0x0500..0x05ff | Reserved multi-device enrollment |
| 0x0600..0x06ff | Reserved LocalSend bridge |
| Other 0x0000..0x7fff | Critical/reserved: unknown MUST abort with UNSUPPORTED |
| 0x8000..0xbfff | Noncritical extension space: unknown MAY be skipped within budget |
| 0xc000..0xffff | Experimental/private: MUST reject in v1 |

Unknown noncritical frames MUST have flags=0 and body<=1024, at most 32/session,
and are allowed only after Capabilities. They MUST NOT alter state or carry file
bytes accepted by the core. Known frames in an invalid state MUST abort; a known
frame is never ignorable merely because its type is in an extension range.

`KeyUpdate` body:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| key_epoch | 8 | u64; directional counter starting at 1, increments by exactly 1 |

Each sender MUST send KeyUpdate under the old directional key before its next
ordinary ciphertext would make cumulative ciphertext bytes exceed 2^30 (1 GiB),
or within 120 seconds of the last directional key creation/update, whichever is
first. It MUST then apply the Noise REKEY operation to that direction; the receiver
does so after authenticating KeyUpdate. Noise REKEY does **not** reset its message
nonce. KeyUpdate is the only allowed extra record beyond the byte budget (28 bytes
including tag, excluding prefix); its bytes belong to neither epoch's ordinary
budget. Epoch wrap, duplicate/skipped update, or exceeding the byte budget is fatal.
Updates MAY occur earlier, but at most once/second absent byte-budget exhaustion.
Idle active sessions still update; missing authenticated traffic for 135 seconds
closes a session. Timer behavior cannot authenticate a remote clock. Handshake
CipherStates MUST NOT be rekeyed this way. Content keys have independent limits (§8).

## 6. Capabilities and fixed versioning

After the ratchet gate opens, each peer MUST send exactly one Capabilities before
transfer or revocation frames. It is encrypted and authenticated; local capabilities
MUST be fixed for that session before receiving the peer's message.

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| version | 2 | 1 |
| content_suites | 2 | bit0 AES-256-GCM STREAM; bit1 XChaCha20-Poly1305 STREAM; other bits zero |
| max_manifest_bytes | 4 | 108..4194304 |
| max_entries | 4 | 1..10000, includes directories |
| max_file_bytes | 8 | 0..1099511627776 (1 TiB) |
| max_transfer_bytes | 8 | 0..17592186044416 (16 TiB) |
| max_outstanding_chunks | 2 | 1..16, receive-side request budget |
| extensions | 8 | u64 = 0 in v1 |

Total: 38 bytes. V1 implementations MUST support XChaCha and SHOULD support AES.
If both advertise AES, every new file MUST select AES; otherwise select XChaCha
if common. Absence of a common suite aborts. Network failure, a rejected signature,
AEAD failure, or performance probing MUST NOT trigger a suite change. A local
platform may omit AES for lack of an approved constant-time implementation, never
because an unauthenticated peer requests it. Content suite choice is bound into the
manifest, Accept, key derivation, and AAD. Resume MUST preserve the original suite;
otherwise use a new transfer and fresh consent.

No downgrade exists for version, hybrid KEM, Noise pattern, consent, or chunk
verification. A peer advertising an unsupported version/suite MUST be rejected,
not retried with a weaker protocol. Reserved fields MUST be zero; adding critical
semantics requires a new version or a fully specified future authenticated extension.
Tor routing, PQ variants, receipt formats, revocation synchronization, multi-device
enrollment, and a LocalSend bridge have no enabled v1 extension. A bridge MUST NOT
represent an unauthenticated LocalSend leg as a secure todoke session.

## 7. Transfers and consent

A session can transfer in either direction, with at most 2 concurrent incoming
transfers and 2 active incoming files per endpoint (at most 4 of each across the
session). The receiver owns these budgets. A file is active while it has an
outstanding request or local verification/storage/publication work; a stored FileKey
or idle resume entry does not activate it. Between requests, a file may release its
slot after its current work finishes. There is no separate wire activation message.
Transfer IDs are random 16-byte values, unique across a
device's history; one immutable manifest and exactly one sender/recipient pair are
bound to each. The recipient is a full device key, not a person-wide wildcard.
No batching of several recipients under one file key is defined.

### 7.1 Encrypted manifest delivery

All manifest metadata travels only inside Noise transport after authentication,
ratchet commit, and Capabilities. It may be received for a consent prompt, but MUST
NOT contain file bytes, thumbnails, executable previews, or content-derived samples.
Names and MIME labels remain untrusted display data.

`ManifestStart` body:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| transfer_id | 16 | New transfer ID |
| manifest_hash | 32 | Hash defined below |
| total_len | 4 | u32, 108..min(local cap,4194304) |

Total: 52 bytes. At most one incomplete incoming manifest per endpoint, using <=4 MiB
of assembly storage (two/8 MiB across both endpoints). `ManifestPart` body:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| transfer_id | 16 | Active ManifestStart |
| offset | 4 | u32, exactly next unfilled offset; starts 0 |
| data_len | 2 | u16, 1..60000; <= remaining declared bytes |
| data | data_len | Canonical manifest bytes |

Parts MUST be contiguous, nonoverlapping, without duplicates; completion is exactly
total_len bytes. There is no implicit final marker or compression. Hash mismatch or
incomplete delivery within 30 seconds of Start rejects the transfer before consent.
`manifest_hash = B3("todoke/v1/manifest\0" || canonical_manifest)`.

Canonical manifest header:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| magic | 4 | ASCII `TDKM` |
| version | 2 | 1 |
| transfer_id | 16 | Same as outer Start |
| sender_public | 32 | Authenticated sender's full device Ed25519 key |
| recipient_public | 32 | This receiver's full device Ed25519 key |
| created_at | 8 | Unix time |
| expires_at | 8 | > created_at, no more than 7 days later |
| entry_count | 4 | u32, 1..min(peer cap,10000) |
| flags | 2 | u16 = 0 |
| entries | variable | Exactly entry_count records, table below |

Fixed header: 108 bytes. IDs MUST be consecutive 1..entry_count in wire order.
The implicit root has ID 0 and is not an entry. Each `ManifestEntry` is:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| id | 4 | u32, 1..entry_count |
| parent | 4 | u32, 0 or a preceding directory's ID |
| kind | 1 | 1 regular file, 2 directory |
| name_len | 2 | u16, 1..255 UTF-8 bytes |
| name | name_len | One component, rules below |
| mime_len | 2 | u16, 0..127 |
| mime | mime_len | Empty for directory; file rules below |
| size | 8 | u64, 0..min(peer cap,1 TiB); 0 for directory |
| root | 32 | BLAKE3 plaintext content root; zero for directory |
| content_suite | 2 | 1 AES, 2 XChaCha; 0 for directory |

Fixed entry overhead: 55 bytes. Files, including empty files, MUST have their exact
BLAKE3 root; an empty file is not the zero root. A directory is metadata only and
has no key or segment. Sum of file sizes MUST be checked and <=16 TiB and the peer
cap; at most 10000 regular files and 10000 total entries. Depth <=64, joined relative
UTF-8 path <=4096 bytes including separators. Symlinks, devices, sockets, hardlink
semantics, permissions, timestamps, and alternate data streams are not defined.

Names MUST be valid UTF-8 in NFC. Empty names, `.`, `..`, NUL, `/`, `\`, ASCII control
characters U+0000..001F and U+007F, trailing ASCII spaces/dots, and `: * ? " < > |`
are forbidden. ASCII-case-insensitive DOS stems CON, PRN, AUX, NUL, COM1..COM9,
LPT1..LPT9, before the first dot, are forbidden. Siblings MUST have distinct exact
NFC byte names. The receiver MUST detect additional collisions imposed by its
filesystem (including case folding) before consent and resolve them by a locally
authorized destination mapping or reject; it MUST NOT silently overwrite.

File MIME is 1..127 ASCII bytes: exactly one `/`, nonempty type/subtype, characters
`a-z`, `0-9`, `!#$&^_.+-` in each component, no parameters or whitespace. Unknown
content MUST use `application/octet-stream`. MIME MUST NOT grant execution or
preview privileges. Implementations MUST not normalize accepted manifest bytes
before hashing/signing; invalid normalization is a rejection, not a repair.

### 7.2 Operational consent boundary

AcceH is the protocol's name for the **signed Accept record** below, not a separate
hash-only consent message. The Rust core MUST create it only in response to locally
authorized user intent for the validated immutable manifest and explicit selection.
An FFI caller's boolean, discovery match, trusted contact, person membership, or
transport connection is not a signature and MUST NOT bypass this gate.

On the receiver, before it durably records its own verified AcceH and queues it on
the authenticated session, it MUST NOT issue ChunkRequest, process FileKey, decrypt
content, verify Bao file slices, persist/quarantine file bytes, or run previews. On
the sender, no file key or file content MAY be sent until it verifies that AcceH
against the authenticated receiver and current session. Receiving unsolicited
content before consent MUST close the session with CONSENT_REQUIRED (if safe).

Unavoidable kernel/transport buffers and the bounded outer encrypted record buffer
are not file acceptance. The core MUST discard a forbidden Chunk immediately after
outer authentication/type recognition, without copying, decrypting its content layer,
writing, or releasing payload bytes. Such bytes MUST never become a transfer event.
No pre-consent thumbnail, speculative fetch, or alternate pipe is an exception.

### 7.3 Accept and Reject

`Accept` (AcceH) body is the following canonical record:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| version | 2 | 1 |
| session_id | 32 | Current session; excludes use in another session |
| transfer_id | 16 | Pending manifest |
| manifest_hash | 32 | Exact canonical manifest hash |
| sender_public | 32 | Authenticated sender |
| receiver_public | 32 | Authenticated recipient and signature authority |
| accept_nonce | 16 | Fresh random nonce, unique per session |
| expires_at | 8 | <= manifest expiry and <= now+24 hours; future at receipt |
| selected_count | 4 | u32, 1..number of regular files, <=10000 |
| selection | 4 × selected_count | Strictly increasing distinct regular-file IDs |
| signature | 64 | Sign(receiver, `todoke/v1/accept\0` \|\| all preceding body bytes) |

Unsigned fixed prefix: 174 bytes; signed size: 238 + 4×selected_count, maximum
40238 bytes. Selection contains files only; needed directory ancestors are implied.
An empty file still needs selection and consent. No selection means Reject, not an
Accept with count zero. The expiry covers the transfer authorization, not merely
verification time; expiry pauses content immediately and requires fresh consent.
That expiry is terminal for authorization in the current session. If the manifest
is still valid, the same immutable transfer MAY resume only in a fresh session
with fresh AcceH. Same-session renewal is not defined. Expiry alone is not Cancel
and does not destroy otherwise valid retained partial data.
Each selected file's size/root/path/suite is bound by manifest_hash.

`accept_hash = B3("todoke/v1/accept-hash\0" || complete_signed_AcceH)`.
The sender MUST validate every binding, signature, expiry, selection, current
revocation status, and state before opening its gate. Identical retransmission in
the same active session is idempotent; conflicting records for a live transfer are
STATE errors. A new selection requires cancel and a new transfer ID. A reconnect
requires a new AcceH for the new session even if consent intent is retained locally.

`Reject` body:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| transfer_id | 16 | Pending transfer |
| manifest_hash | 32 | Pending hash |
| reason | 2 | 1 declined, 2 quota, 3 unsupported destination, 4 expired |

Total: 50 bytes. Receiver only; no signature required beyond authenticated session.
Rejection is terminal for that transfer in that session and MUST NOT be reported as
successful delivery. No peer-supplied free text is defined.

### 7.4 Pull-based verified chunks

After valid AcceH, the sender supplies one FileKey per selected file (§8). Only then
may the receiver request segments. Segments cover **16384 logical plaintext bytes**
except the last. Index starts at 0; for size>0, count=ceil(size/16384). An empty file
has exactly one empty final segment at index 0. Maximum count is 67108864 for 1 TiB.

`ChunkRequest` body:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| transfer_id | 16 | Authorized active transfer |
| accept_hash | 32 | Current session's AcceH hash |
| request_id | 4 | u32, 1..2^32-1, strictly increasing within transfer/session |
| file_id | 4 | Selected regular-file ID |
| segment_index | 4 | u32, 0..segment_count-1 |

Total: 60 bytes. One request requests one segment. Each receiver may issue at most
min(its own, peer's max_outstanding_chunks) outstanding requests, <=16 per endpoint
and <=32 across the session, not per file. At most one request for a
particular file/index may be outstanding. Counter exhaustion requires a new session
and fresh AcceH. Requests MAY arrive out of order by segment index.

`Chunk` body:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| transfer_id | 16 | Active transfer |
| accept_hash | 32 | Current AcceH hash |
| request_id | 4 | Exact outstanding request |
| file_id | 4 | Exact requested file |
| segment_index | 4 | Exact requested index |
| content_len | 2 | u16, 24..32784 |
| content_ciphertext | content_len | One encrypted Bao slice, AEAD tag appended (§8) |

Fixed overhead: 62 bytes. No unsolicited chunk, extra segment, aggregate response,
or segment fragment is defined. After successfully verifying and durably storing a
chunk, the receiver retires the request. Before successful verification no payload
MAY be exposed to a UI, application, preview, or final file path.
The sender retires its corresponding request bookkeeping after the complete response
is queued to the ordered stream; it does not infer successful receiver storage from
that event. Receiver processing slots remain occupied until its work is complete.

The content plaintext is the **entire Bao 0.13.1 combined slice encoding** for the
file's requested range, as specified in
[Bao 0.13.1](https://github.com/oconnor663/bao/blob/0.13.1/docs/spec.md):

| Component | Bytes | Limit / semantics |
| --- | ---: | --- |
| total_file_length | 8 | **Little-endian** u64; MUST equal manifest size |
| preorder proof/content stream | variable | Canonical Bao slice; parent nodes are 64 bytes, BLAKE3 leaves up to 1024 bytes; whole slice <=32768 bytes |

This is a dependent tree encoding, not `proof || data`. Its exact node traversal,
chaining value ordering, and root handling are the pinned Bao format; no bespoke
Merkle proof format is allowed. Slice range is start=index×16384 and
length=min(16384,size-start), with checked arithmetic. Zero length is legal only
for the single empty-file segment. The empty encoding is exactly eight zero bytes.

The receiver MUST authenticate the content AEAD before parsing Bao, validate the
header/range, consume the entire canonical slice without trailing bytes, obtain
exactly the requested logical byte count, and verify against the manifest BLAKE3
root. A decoder's permissive past-EOF or partial-read behavior MUST NOT relax these
checks. Proof bytes contain file data and are encrypted with the content, not sent
as public auxiliary metadata. Failures MUST discard the segment and terminate the
transfer; no plaintext from a failed segment may be retained as trusted progress.

### 7.5 Resume

A disconnected transfer MAY retain only previously authorized, verified partial
content and encrypted local key state, bounded by local quota and manifest expiry
(maximum 7 days). Reconnect always performs a new authenticated ratcheted session,
Capabilities, the exact original manifest, and a **new signed AcceH**. Neither an
old signature nor a bitmap is consent. All previously selected files must still be
selected; changing selection requires a new transfer. Pair revocation, cancellation,
manifest mutation, or expired retained state makes resume unavailable.

`ResumeQuery` is sent by the sender only after fresh AcceH and FileKey:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| transfer_id | 16 | Authorized resumable transfer |
| accept_hash | 32 | Current AcceH |
| file_id | 4 | Selected file |
| from_index | 4 | u32, 0..segment_count; starts 0, thereafter prior next_index |

Total: 56 bytes. At most one query outstanding per sending endpoint. `ResumeStatus` replies:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| transfer_id | 16 | Matching query |
| accept_hash | 32 | Current AcceH |
| file_id | 4 | Matching query |
| from_index | 4 | Echo query |
| next_index | 4 | > from_index and <=segment_count, or both equal segment_count for empty final page |
| range_count | 2 | u16, 0..1024 |
| ranges | 8 × range_count | (start:u32, count:u32), count>=1, sorted, disjoint, nonadjacent; each entirely within [from_index,next_index) |

Fixed overhead: 62 bytes. Ranges describe verified segments already present; absent
indices in the page require requests. `next_index=segment_count` ends pagination.

| Resume range field | Bytes | Limit / semantics |
| --- | ---: | --- |
| start | 4 | u32, from_index..next_index-1 |
| count | 4 | u32, 1..next_index-start; checked sum and canonical ordering required |

Peers MUST NOT accept claimed progress from another transfer/file or use it as
proof of delivery. After storage loss/restart the receiver MUST revalidate cached
segments/proofs or rehash a complete file before advertising them; disk metadata
alone is insufficient. Ranges can be streamed; allocating an unbounded full bitmap
for every file is forbidden. Per-session resume metadata in memory is capped at
8 MiB. The sender MAY ignore resume information and resend on explicit requests.

### 7.6 Cancel

Either party MAY cancel an offered or active transfer. `Cancel` and `CancelAck`
share a layout:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| transfer_id | 16 | Known transfer |
| manifest_hash | 32 | Known hash |
| cancel_id | 16 | Random identifier, echoed by Ack |
| reason | 2 | 1 user, 2 expired, 3 revoked, 4 integrity, 5 storage, 6 policy |

Total: 66 bytes. Cancellation closes the consent gate immediately, cancels outstanding
requests, zeroizes keys, and makes the transfer ID permanently unusable locally.
A peer MUST send Ack within 5 seconds or close the session. Repeated identical Cancel
is idempotent. Already in-flight Chunk bodies for a cancelled transfer MAY be
outer-authenticated and discarded without content processing, at most the prior
outstanding count; anything else is STATE. No late Accept, ResumeStatus, Complete,
or receipt may reopen cancellation. A tombstone MUST survive at least through
manifest expiry plus 120 seconds and as long as any session referencing it exists;
ID generation MUST prevent later reuse independently of tombstone retention.
Cancelled temporary data MUST be deleted according to local storage semantics;
secure physical erasure on flash is not promised. Already published files remain
under local user control. Simultaneous cancellation acknowledges each cancel_id.

### 7.7 Completion and signed delivery receipt

When all selected segments are verified and stored, the receiver MUST check exact
file lengths and a whole-file BLAKE3 hash for every selected file before publication.
It MUST publish through filesystem operations that prevent path escape, symlink/race
substitution, and unintended overwrite. Each file is published atomically where the
platform supports it; directory-wide atomicity is not promised. Completion occurs
only after every selected file is successfully published and durable to the platform's
supported guarantees. A storage error MUST NOT produce a successful receipt.

Receiver sends `Complete` then `DeliveryReceipt`; neither may precede all publication:

| Complete field | Bytes | Limit / semantics |
| --- | ---: | --- |
| transfer_id | 16 | Active transfer |
| manifest_hash | 32 | Exact manifest |
| accept_hash | 32 | Current AcceH, hence exact selected files |
| completed_count | 4 | Equals selected_count |
| total_plaintext_bytes | 8 | Sum of selected file sizes, checked <=16 TiB |

Total: 92 bytes. Complete alone is not a signed receipt. DeliveryReceipt is:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| version | 2 | 1 |
| session_id | 32 | Current session |
| transfer_id | 16 | Completed transfer |
| manifest_hash | 32 | Exact manifest |
| accept_hash | 32 | Current AcceH |
| sender_public | 32 | Authenticated sender |
| receiver_public | 32 | Authenticated receiver/signer |
| receipt_id | 16 | Fresh random ID |
| completed_at | 8 | Unix time |
| completed_count | 4 | Equals selection count |
| total_plaintext_bytes | 8 | Equals Complete |
| status | 1 | 1 = all selected files verified and published; all else reserved |
| signature | 64 | Sign(receiver, `todoke/v1/delivery-receipt\0` \|\| preceding 215 bytes) |

Total: 279 bytes. The sender MUST verify every binding and signature before showing
confirmed delivery. A dropped receipt means delivery is unconfirmed even if bytes
may have reached the receiver; it MUST NOT trigger silent overwriting retransfers.
completed_at MUST be no earlier than current session establishment, no later than
AcceH expiry, and no later than the verifier's current time plus 120 seconds. All
publication MUST have completed while consent was valid. A receipt for a Complete
received before authorization expiry MAY arrive during its 10-second receipt window
after that expiry; this exception permits no further file bytes or publication.
A receipt is an authenticated receiver claim, not proof that a human read a file or
that a malicious receiver retained it. Receipt export/retention requires local user
policy; no server telemetry or public receipt log is permitted.

## 8. Per-file content encryption

Each regular file has a fresh 32-byte random file master key. Keys MUST NOT be reused
across files, recipients, or transfer IDs. Directories have none. `FileKey` is sent
only after the sender verifies AcceH and only for selected files:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| transfer_id | 16 | Active authorized transfer |
| accept_hash | 32 | Current AcceH |
| file_id | 4 | Selected regular file |
| content_suite | 2 | Exact manifest suite |
| file_master | 32 | Secret; encrypted inside Noise, never logged or exposed through FFI |

Total: 86 bytes. Exactly one value is permitted per file; an identical retransmission
is idempotent and a different value is fatal. A resumed transfer MUST reuse its
original master and immutable ciphertext. Local master storage MUST be sealed by the
platform's approved secret storage. Sending this field inside end-to-end ciphertext
does not authorize exposing it to a relay, UI, or external diagnostics.
Receiving FileKey does not activate a file-processing slot. Stored masters are
bounded by selected_count (at most 320000 master-key bytes per transfer); inactive
masters SHOULD remain sealed instead of holding every key open in memory.

Define content_epoch=`floor(segment_index / 65536)` (u32, 0..1023 for 1 TiB), and
local_index=`segment_index mod 65536`. Each epoch covers at most 1 GiB of logical
file data. Bao overhead means this is not the session's 1 GiB ciphertext budget.
Derive independent epoch keys and nonce prefixes:

```
context = transfer_id || file_id:u32 || content_suite:u16 || content_epoch:u32
key = HKDF(manifest_hash, file_master, "todoke/v1/content-key\0" || context, 32)
prefix = HKDF(manifest_hash, file_master, "todoke/v1/content-nonce\0" || context, N)
```

| Context field | Bytes | Limit / semantics |
| --- | ---: | --- |
| transfer_id | 16 | Manifest transfer ID |
| file_id | 4 | u32, selected regular file |
| content_suite | 2 | u16, 1 or 2, exact manifest suite |
| content_epoch | 4 | u32, 0..1023 |

Total context: 26 bytes; the HKDF info is the domain string followed by this
context, with no separator. N=7 for AES-256-GCM and N=19 for XChaCha20-Poly1305.
Both use a 16-byte tag and
[RustCrypto STREAM BE32](https://github.com/RustCrypto/traits/blob/aead-v0.5.2/aead/src/stream.rs)
semantics. Do not substitute LE31 or native-endian counters.

| Nonce field | AES bytes | XChaCha bytes | Limit / semantics |
| --- | ---: | ---: | --- |
| epoch prefix | 7 | 19 | Derived above, constant for epoch |
| counter | 4 | 4 | local_index as BE u32, 0..65535 under v1 bounds |
| final | 1 | 1 | 1 for last file segment OR local_index=65535; otherwise 0 |

Nonce lengths: 12 and 24 bytes. Each epoch is a separate STREAM instance. The empty
file uses epoch 0/index 0/final 1 and encrypts the eight-byte empty Bao slice (24-byte
ciphertext including tag). At an exact epoch boundary the last real segment is final;
no synthetic empty terminator follows. The 32-bit primitive's wider counter space is
reserved; v1 MUST NOT use it to avoid deriving the next epoch key.

Associated data is exactly this table, in order, reconstructed from the accepted
manifest and requested segment, not selected by the peer:

| AAD field | Bytes | Limit / semantics |
| --- | ---: | --- |
| domain | 22 | ASCII `todoke/v1/content-aad\0`, including one NUL |
| version | 2 | 1 |
| transfer_id | 16 | Manifest ID |
| manifest_hash | 32 | Accepted canonical hash |
| file_id | 4 | Selected file |
| content_suite | 2 | 1 or 2 |
| content_epoch | 4 | Derived above |
| segment_index | 4 | Global file segment index |
| logical_length | 4 | 0..16384, exact range length |
| final | 1 | Derived marker |
| root | 32 | Manifest's BLAKE3 root |

The content-aad domain is exactly 22 bytes including its zero terminator; total AAD
is 123 bytes. AAD has no session_id or accept_hash because
content ciphertext must survive a fresh consented session during resume. The outer
Chunk binds both the new authorization and outstanding request.

The entire Bao slice is AEAD-encrypted as a single segment with the derived key,
nonce, and AAD; tag appended. No file byte is public. AEAD success alone does not
replace Bao/root verification or consent. Sender MUST snapshot or detect mutation
of source files. Repeated requests MUST return identical ciphertext bytes; a changed
file, key, encoding, or manifest requires a new transfer ID/master/consent. Implementations
MUST never encrypt different plaintext/AAD under the same key+nonce. Cached ciphertext
MAY be retransmitted; recomputation is allowed only from an immutable verified source
with the identical canonical slice. No content AEAD authentication failure is retryable
as a cipher fallback.

## 9. Discovery

Discovery never authenticates a peer. No names, full public keys, file metadata,
static identifiers, or per-person membership may appear in routine advertisements.
For each committed device pair (§4.4):

```
epoch = floor(unix_time / 900)
token = HMAC-BLAKE3(pair_key, epoch:u64)[..8]
rendezvous_token = HKDF(epoch:u64, pair_secret, "todoke/v1/rendezvous\0", 32)
```

A receiver tests only current and adjacent epochs (-1,0,+1, bounded at zero).
Tokens rotate at 15-minute boundaries and on successful ratchet. The truncated
64-bit discovery token is a candidate filter, not an authorization MAC; collisions
MUST lead to full authenticated session checks. Pair keys and PSKs MUST NOT be
advertised. A pair advertises one token at a time; devices with several contacts
SHOULD rotate entries rather than broadcast the entire contact graph in one record.
Discovery state from prior ratchet generations MUST NOT remain enabled after commit.

The application `DiscoveryRecord` embedded in mDNS is:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| version | 1 | 1 |
| mode | 1 | 0 paired, 1 stranger |
| epoch | 8 | u64; current epoch |
| token | 8 | Paired token or stranger token (below) |
| flags | 1 | 0; reserved |

Total: 19 bytes. Stranger mode requires explicit local enablement, expires after
300 seconds, and advertises no identity. Its token MUST rotate every 60 seconds;
it is never a password, PSK, or peer-authentication credential. A stranger must use
QR or code pairing. Enumeration/matching is untrusted and rate-limited.

While a QR offer (§3.1) is shown, its stranger token is derived from the offer, so
that only the scanner of that QR can recognize the displayer:

```
qr_stranger_key = HKDF(pairing_id, one_time_psk, "todoke/v1/qr-stranger\0", 32)
minute = floor(unix_time / 60)
stranger_token = HMAC-BLAKE3(qr_stranger_key, minute:u64)[..8]
```

The token changes at every minute boundary, which is its 60-second rotation, and
the instance label rotates with it. Without the QR it is indistinguishable from
random; anyone who has seen the QR can already race to pair (§3.1). A scanner tests
the minutes within the §1 120-second skew of its own (-2..+2, bounded at zero) and
MUST send the QR's `ClientHello` only to advertisements whose token matches. A match is a candidate
filter, not authentication: a copied token or a collision still goes through the
full authenticated handshake, which pins the QR's keys. Code pairing (§3.2) keeps a
uniform random stranger token: a token derived from the low-entropy code would be an
offline dictionary oracle.

mDNS uses service `_todoke._tcp.local.`, an ephemeral instance name of 16 lowercase
hex characters from 8 random bytes, SRV port 1..65535, and exactly one TXT string
`v1=` plus 38 lowercase hex characters encoding DiscoveryRecord. No other todoke
TXT metadata is permitted. IP/SRV routing data is untrusted.

| TXT string field | Bytes | Limit / semantics |
| --- | ---: | --- |
| key | 3 | ASCII `v1=`, exact |
| record | 38 | Lowercase hex of the 19-byte DiscoveryRecord; uppercase MUST be rejected |

The TXT string is 41 bytes, carried with its standard DNS length octet. Instance
labels rotate with the discovery epoch; cached data MUST expire within 120 seconds. Implementations
MUST NOT put the device name into this service's instance label.

Platform frames, Wi-Fi P2P and AWDL frames, and QUIC/TLS packets are governed by
their respective standards. The only todoke values they carry are the mDNS records
above and, while a §10.2 Wi-Fi Aware offer is open, its service name and service
information. §10.1 to §10.3 assign the direct links that carry the §4 prelude and §5
records.

## 10. Relay, rendezvous, and hole punching

A relay provides matching and forwarding of opaque endpoint traffic. Clients use
QUIC v1/TLS 1.3 to protect against off-path manipulation and authenticate the selected
relay service, but the relay remains untrusted by endpoints. Certificate validation
MUST be normal platform validation or an explicitly pinned relay key; failures MUST
NOT disable validation. Relay-originated route suggestions never authenticate a peer.
QUIC is used only between a device and a relay. Direct paths are the local links
of §10.1 to §10.3; v1 assigns no hole punching (below).

A relay control stream uses `length:u16 || type:u8 || body`, length 1..2048, counting
type+body. Maximum two clients match one rendezvous_token. Room lifetimes are 120
seconds, maximum wait 30 seconds, maximum two simultaneous rooms per endpoint, and
maximum four candidates per endpoint. The relay MUST NOT receive pair_secret,
pair_key, PSK, identity secrets, file keys, manifests, or plaintext content.

| Relay control envelope field | Bytes | Limit / semantics |
| --- | ---: | --- |
| length | 2 | u16, 1..2048, includes type and body |
| type | 1 | Registry below |
| body | length-1 | 0..2047, exact per-type layout |

| Type | Message | Direction |
| --- | --- | --- |
| 0x01 | Register | Client → relay |
| 0x02 | Registered | Relay → client |
| 0x03 | PeerReady | Relay → both clients |
| 0x04 | Candidates | Client → relay → other client |
| 0x05 | Punch | Relay → both clients |
| 0x06 | Forward | Client → relay |
| 0x07 | ForwardReady | Relay → client |
| 0x08 | RelayClose | Either direction |
| Others | Reserved | Close; do not fall back |

`Register`:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| version | 2 | 1 |
| rendezvous_token | 32 | Derived token; QR/code use derivation below |
| client_nonce | 16 | Fresh random value, distinct from peer's |
| ttl_seconds | 2 | u16, 1..120 |

Total: 52 bytes. For unpaired offers use
`HKDF(pairing_id, one_time_psk, "todoke/v1/pairing-rendezvous\0",32)` for QR. Human
code rendezvous MUST use a separate randomly generated 32-byte rendezvous capability
communicated by the pairing UI; it MUST NOT derive a publicly checkable locator from
the low-entropy code. Distribution of that capability for a code-only remote workflow
is unresolved (§16); code-only remote rendezvous MUST remain disabled.

`Registered`:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| room_id | 16 | Random ephemeral relay-assigned ID |
| client_nonce | 16 | Echo Register |
| expires_in | 2 | u16, 1..requested ttl |

Total: 34 bytes. `PeerReady`:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| room_id | 16 | Registered room |
| peer_nonce | 16 | Other endpoint's Register nonce |

Total: 32 bytes. Neither acknowledgment is an authenticated peer claim.
`Candidates`:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| room_id | 16 | Current room |
| candidate_count | 1 | 0..4 |
| candidates | 19 × count | Candidate records below; no duplicates |

Candidate record:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| family | 1 | 4 IPv4, 6 IPv6 |
| address | 16 | IPv4 uses first 4 network-order bytes, remaining 12 zero; IPv6 full network bytes |
| port | 2 | u16, 1..65535 |

v1 gathers, sends, and probes no candidates (below). The bounds that a later
revision keeps: candidate gathering obeys platform permissions; loopback,
unspecified, multicast, broadcast, privileged/admin service endpoints, and routes
inconsistent with explicit local LAN policy are never contacted; at most 4 approved
addresses are probed, at most 3 probes/address, <=1200 bytes/probe; no open proxy
or arbitrary URL fetch. A direct pipe still MUST perform full todoke authentication.

`Punch`:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| room_id | 16 | Matched room |
| delay_ms | 2 | u16, 0..2000, relative to receipt |
| punch_nonce | 16 | Random per attempt |

Total: 34 bytes. In v1 non-local paths are relay-forwarded only: an endpoint MUST
send `Candidates` with count zero (or none), MUST ignore `Punch` and start no probe,
and a relay MUST NOT add an observed candidate. `Candidates` and `Punch` stay in the
registry so v1 relays and endpoints parse them strictly, but carry nothing in v1. A
later revision that enables direct non-local paths MUST at least: carry candidates
only inside an authenticated session (never in the cleartext-to-relay `Candidates`),
learn a reflexive address only from the selected relay and only for the asking
client, be enabled by the user, never gather from interfaces that bypass an active
VPN, keep the bounds above, and start a fresh session and Accept on the direct path.
A connectivity failure may change the pipe but MUST NOT alter the authenticated
protocol or downgrade cryptography.

`Forward` and `ForwardReady` have the same body:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| room_id | 16 | Registered, matched room |

The relay MUST receive Forward from both clients before sending either ForwardReady.
After the relay
sends ForwardReady to both clients, each client's current ordered control stream
switches to an opaque bidirectional byte tunnel; there are no more relay control
records on that stream. Forwarded bytes are exactly the endpoint prelude and Noise
transport frames. RelayClose after switching is QUIC stream closure, not an injected
endpoint plaintext message. Maximum tunnel lifetime 24 hours and maximum 16 TiB
forwarded bytes in each direction; local/relay quotas may be lower. Relay backpressure
MUST be bounded (<=1 MiB buffered per direction) and preserve byte order.

Register, Registered, PeerReady, Forward, and ForwardReady each occur at most once
per client/room, in that order. After PeerReady and before Forward, each endpoint
MAY send one Candidates (including count zero); the relay forwards it once to the
other endpoint. If both Candidates arrive, the relay MAY send one Punch to each
endpoint. Forward MAY skip that optional exchange. Duplicate/out-of-order controls
close the room. Room TTL covers setup only; a successful forwarding switch replaces
it with the bounded tunnel lifetime. Direct connection success closes the unused
room. Endpoints MUST use the handshake roles in §4, not relay registration order.

Before that switch, `RelayClose` is:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| room_id | 16 | Current room or zero if registration failed |
| code | 2 | 1 expired, 2 full, 3 quota, 4 malformed, 5 unavailable |

Total: 18 bytes. No peer error detail or unbounded string is permitted.
The relay observes source/destination IPs and ports, QUIC connection metadata,
rendezvous tokens and their use/linkability during an epoch, room IDs, candidates,
Hello metadata, connection times, lengths, rates, and failures. A malicious relay can
drop, delay, replay, correlate, or misroute traffic; it cannot authorize consent or
forge valid endpoint authentication. This protocol provides no anonymity or traffic
analysis resistance. Relay implementations MUST NOT collect telemetry, persist room
traffic metadata, or log tokens/IPs/identities as analytics. Minimal bounded in-memory
abuse counters MAY be used and MUST expire with the room/connection. A malicious
relay can disregard that policy; endpoint confidentiality must not depend on it.

### 10.1 Direct links

A direct link is an IP link between two devices without a relay: the LAN; an
Android Wi-Fi Aware data path, a Wi-Fi Direct group, or a hotspot one device hosts
for the other, set up by §10.2; Apple peer-to-peer Wi-Fi (AWDL); an Apple Wi-Fi
Aware connection. Every one carries TCP: the §4 prelude and §5 records exactly as on
the LAN. QUIC is not used on direct links: it requires TLS 1.3, which without a
shared PKI authenticates nothing that Noise does not, and §5's single ordered stream
gains nothing from QUIC streams.

v1 uses no Bluetooth and no USB transport: no BLE advertising, GATT service, or
L2CAP channel, and no USB adapter (iPhone usbmux, Android Open Accessory). An IP
interface the operating system provides is part of the LAN whatever its medium, and
nothing is specific to it.

An endpoint connects to and accepts from only private (RFC 1918), unique local
(RFC 4193), and link-local (169.254.0.0/16, fe80::/10 with an interface scope)
addresses, on ports 1024..65535. On a link set up by §10.2 the joiner connects only
to the host address the link API reports for that link (the Wi-Fi Aware peer
address, the group owner address, the hotspot gateway) on the offered port, and the
host accepts only on that link's interface. No address range identifies a link
kind: Android picks a random private /24 for its groups and hotspots.

Apple peer-to-peer Wi-Fi and Apple Wi-Fi Aware need no todoke negotiation: AWDL
carries §9 mDNS discovery when peer-to-peer is enabled, and Apple Wi-Fi Aware
connects devices the operating system paired. Both carry the same TCP stream
through the platform's peer-to-peer networking API; their link-layer security is not
relied on.

### 10.2 Link setup inside a session

Over an authenticated contact session, two devices MAY set up a faster direct link,
only for a transfer the user started or accepted on this device and while it is
pending or running. Credentials are random per offer and travel only inside the
session; nothing about the link is advertised before the offer.

`LinkAbilities` (0x0020) says what an endpoint can do at that moment. Each endpoint
sends it at most once per session, after Capabilities (§6). An endpoint that sends
none takes part in no link setup, and a `LinkOffer` or `LinkAnswer` it receives is
STATE.

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| host_kinds | 1 | Bitmask of link kinds this endpoint can host |
| join_kinds | 1 | Bitmask of link kinds this endpoint can join |
| join_security | 1 | Bitmask of security values (below) it can join with: bit n-1 for value n |

Total: 3 bytes. Link kinds, in order of preference: bit 0 Wi-Fi Aware data path
(kind 1), bit 1 Wi-Fi Direct group (kind 2), bit 2 hotspot (kind 3). Unassigned bits
are reserved zero. Once both endpoints have sent `LinkAbilities`, the first kind in
that order that one endpoint can host and the other can join with at least one
security value of that kind is chosen; if both can host it, the endpoint with the
lexicographically smaller full device key hosts. The host offers the strongest
security of that kind the joiner can join (1 before 2 before 3; 4 before 5). Only
the host sends `LinkOffer`, once per session.

`LinkOffer` (0x0021):

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| offer_id | 16 | Fresh random value, not all zero |
| kind | 1 | 1 Wi-Fi Aware, 2 Wi-Fi Direct, 3 hotspot |
| security | 1 | Below |
| expires_in | 1 | Seconds, 10..120 |
| port | 2 | u16, 1024..65535; the host's listening port |
| ssid_len | 1 | 0 for kind 1; 30 for kind 2; 23 for kind 3 |
| ssid | ssid_len | Network name, exact shape below |
| secret_len | 1 | 32 for kind 1; 63 otherwise |
| secret | secret_len | Kind 1: the data path PMK. Otherwise the passphrase |

| security | Meaning | Kinds |
| --- | --- | --- |
| 1 | WPA3-Personal (SAE only) | 2, 3 |
| 2 | WPA3-Personal transition (SAE or WPA2-PSK) | 2, 3 |
| 3 | WPA2-PSK | 2, 3 |
| 4 | Wi-Fi Aware NCS-SK-256 | 1 |
| 5 | Wi-Fi Aware NCS-SK-128 | 1 |
| Others | Reserved; open, WEP, and WPS are never offered | |

Total: 55 bytes for kind 1, 116 for kind 2, 109 for kind 3. The host generates every
random part from a CSPRNG for each offer:

- the PMK, 32 bytes;
- the passphrase, 63 characters each drawn uniformly from the 64 characters
  `A-Z a-z 0-9 - _` (378 bits: WPA2 under it is not open to offline guessing, so a
  weaker security value weakens only the link layer, never the session);
- the SSID, exactly `todoke-` followed by 16 lowercase hexadecimal digits for a
  hotspot, and exactly `DIRECT-` followed by 2 lowercase hexadecimal digits, `-tdk-`,
  and 16 lowercase hexadecimal digits for a Wi-Fi Direct group (Android requires the
  `DIRECT-` prefix).

A host that cannot choose its own SSID and passphrase (an Android LocalOnlyHotspot
before Android 16) does not host that kind. An offer whose security does not belong
to its kind, or whose SSID, passphrase, or lengths break the rules here, is
MALFORMED; the joiner checks it before passing anything to the operating system.

For kind 1 the host publishes the Wi-Fi Aware service `todoke` with
service-specific information exactly `offer_id[..8]`; the joiner subscribes and
requests a data path with the PMK and the offered security to a publisher whose
information matches, trying each matching publisher at most once before
`expires_in`. WPS, open data paths, persistent groups, and saved or suggested
networks MUST NOT be used.

`LinkAnswer` (0x0022):

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| offer_id | 16 | The offer answered |
| result | 1 | 1 joining, 2 declined, 3 failed |

Total: 17 bytes. The joiner checks the offer and its own ability to join it, then
answers before it asks its operating system to join: a device with one radio leaves
the network that carries the session when it joins another, so an answer sent after
joining could not arrive. `failed` means it cannot join this offer (for example, the
security it requires); `declined` that it will not. Either ends link setup for the
session: there is no second offer. After `joining`, both endpoints close the session
(§4 allows one session per pair), the joiner joins, opens TCP to the host over the
new link (§10.1), and runs a full contact handshake as the initiator. The host accepts one connection for
the offer, only on that link, only before `expires_in`. A transfer resumes on the new
session with a fresh Accept (§5, §7.5); if the new link fails, the endpoints connect
again however they can and resume the same way.

Each endpoint tears the link down when its session on it ends or the offer expires,
and in any case keeps it no longer than the session: it leaves or removes the
group, hotspot, data path, and any network configuration it had to create, and
keeps no copy of the secret. Joins use the platform's app-scoped, temporary
mechanisms (Android `WifiNetworkSpecifier` or the Wi-Fi Aware network request,
`NEHotspotConfiguration` with `joinOnce`, a NetworkManager in-memory connection, a
Windows temporary profile), and the joiner sends only todoke traffic over the link
where the platform lets it bind sockets to the link. A host that controls its access
point offers no default route and no DNS, and forwards nothing between the link and
other networks. A malformed record is MALFORMED; a duplicate, unexpected, or
out-of-order one is STATE.

### 10.3 Platform requirements

- **Permissions.** Implementations request the narrowest permission: on Android 13
  and later `NEARBY_WIFI_DEVICES` with the `neverForLocation` flag; location only
  where the platform has no other permission for the feature, and never background
  location. Local-network prompts are shown while the app is in the foreground, in
  response to a user action.
- **Background.** A transfer on Android runs in a foreground service of type
  `connectedDevice` started by a user action; on iOS, in the foreground or in a
  continued-processing background task the user started. An iOS app closes its TCP
  listeners when it goes to the background. A session interrupted by the platform
  resumes with a fresh session and Accept (§7.5); no platform background mechanism
  extends consent or §13 deadlines.
- **No operating-system trust.** Wi-Fi Direct invitations that ask the user to accept
  a device are never used, and no operating-system pairing is taken as todoke
  authentication. Apple Wi-Fi Aware's system pairing is a precondition the platform
  imposes, not authentication: the todoke handshake still runs on every connection.

## 11. Transfer and session state requirements

These tables are normative transition constraints, not implemented state machines.
Every future state-machine implementation MUST have proptest state-machine tests,
including adversarial transitions and persistence/crash events.

| Session state | Permitted next records / action |
| --- | --- |
| Prelude | Optional code offer exchange, exact Hellos, CPace shares for code, assigned hybrid handshake only after §16 gate |
| Split, identity pending | Identity in designated order; authenticated Error or close |
| Identity confirmed | RatchetReady → RatchetReady → RatchetCommit → RatchetAck in designated directions |
| Ratchet committed | Capabilities once per direction; KeyUpdate and Error |
| Ready | Transfer messages in their states, Revoke, KeyUpdate, Ping/Pong, Error, bounded noncritical extensions |
| Closed / uncertain ratchet | No frames; destroy cipher states; explicit re-pair if journal uncertain |

| Transfer state | Permitted progress |
| --- | --- |
| Unknown | ManifestStart for new ID within quota |
| ReceivingManifest | Contiguous ManifestPart; Cancel/Error |
| Offered | Receiver signs Accept or sends Reject/Cancel; no FileKey or Chunk |
| Accepted | Selected FileKeys; then requested Chunk and bounded ResumeQuery/Status |
| Receiving | Requested verified chunks, resume queries, Cancel; completion only when all selected files validate/publish |
| Completed | Complete followed by valid signed DeliveryReceipt; terminal |
| Rejected / cancelled / expired / failed | No reopen in this session; no file acceptance |

No protocol acknowledgment means local user intent, filesystem success, or durable
storage unless explicitly specified. Signed remote claims do not establish honest
behavior of a malicious authorized recipient.

## 12. Error codes

`Error` (0x0009) is encrypted and available only after Split when sending a bounded
error will not disclose an authentication oracle. Before authentication failure,
close silently. Errors contain no strings, paths, key material, hashes of secrets,
or received data.

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| scope | 1 | 0 session, 1 transfer |
| code | 2 | Registry below |
| transfer_id | 16 | Zero for session; exact active transfer for transfer scope |

Total: 19 bytes. At most one Error per failing operation. Session-scoped errors
close immediately; transfer-scoped errors terminate that transfer and revoke its
authorization. Error records in response to Error are forbidden. Unknown error
codes are a generic failure, never a retry/fallback instruction.

| Code | Name | Scope / action |
| --- | --- | --- |
| 0x0000 | Reserved | MUST NOT be sent; receipt is MALFORMED |
| 0x0001 | MALFORMED | Session; length, canonical encoding, reserved field, overflow |
| 0x0002 | UNSUPPORTED | Session; version/suite/type unsupported, no downgrade |
| 0x0003 | AUTHENTICATION | Session; use indistinguishable close when oracle risk exists |
| 0x0004 | STATE | Session; replay, wrong ordering, unexpected record |
| 0x0005 | LIMIT | Transfer for declared transfer quota, otherwise session |
| 0x0006 | CONSENT_REQUIRED | Session; premature/unselected content or key |
| 0x0007 | MANIFEST | Transfer; hash/schema/path conflict |
| 0x0008 | INTEGRITY | Transfer; content AEAD/Bao/root/length mismatch |
| 0x0009 | EXPIRED | Transfer for transfer/Accept; session for binding |
| 0x000a | REVOKED | Session; no additional identity detail |
| 0x000b | STORAGE | Transfer; insufficient space/write/publish failure |
| 0x000c | TIMEOUT | Affected scope; no automatic protocol downgrade |
| 0x000d | RATCHET | Session; generation/persistence inconsistency |
| 0x000e | RESUME_UNAVAILABLE | Transfer; new transfer requires new consent |
| 0x000f..0xffff | Reserved | Generic failure; never reflect raw peer data |

## 13. Timeouts and limits

All normative maximums are upper bounds; implementations MAY impose smaller local
quotas and advertise the defined limits. They MUST reject excess before expensive
work, with no partial consent or hidden weakening. Numeric limits are not promises
that every device has capacity for the maximum transfer.

| Resource / timer | Bound / behavior |
| --- | --- |
| Unauthenticated attempts | <=4 concurrently/device; <=20 starts/minute globally; code's stricter offer limit also applies |
| Prelude body buffering | <=8192 bytes/attempt; no allocation from an unchecked prefix |
| Handshake | 30 seconds total from ClientHello; <=16 Noise records, <=64 KiB total prelude |
| Identity + ratchet | 10 seconds total after Split including durable I/O; deadline failure closes, pending journal fails closed |
| Capabilities | 5 seconds after ratchet gate; absence closes |
| Pending pairing offer | 300 seconds; QR one-time, code <=5 failed attempts |
| Outer ciphertext | 20..65535 bytes; <=1 complete pending record/direction |
| Session buffered chunk data | <=32 ×32784 content bytes plus bounded framing; global app buffers <=16 MiB/session excluding manifest/resume metadata |
| Session duration | <=24 hours; close and reauthenticate/resume with fresh AcceH |
| Transport rekey | 1 GiB ciphertext or 120 seconds per direction, §5 |
| Idle/dead connection | Ping after 30 seconds without ordinary traffic; Pong within 10 seconds; no authenticated traffic for 135 seconds closes |
| Incomplete manifest | One incoming/endpoint, <=4 MiB each, 30-second assembly deadline |
| Consent prompt | 300 seconds from complete manifest, then Reject/expire |
| Active transfers / files | <=2 incoming transfers and <=2 active incoming files/endpoint, <=4 of each/session |
| Entries / regular files | <=10000 total, therefore <=10000 files |
| Name / path / depth | <=255 UTF-8 bytes/component; <=4096 bytes/path; <=64 levels |
| MIME | <=127 ASCII bytes |
| File / transfer | <=1 TiB/file; <=16 TiB/manifest sum |
| Chunk | 16 KiB logical data; <=32768-byte Bao slice; <=32784-byte content ciphertext |
| Outstanding chunk requests | <=16/receiving endpoint, <=32/session, negotiated; no duplicate outstanding file/index |
| Chunk progress | Request timeout 30 seconds; close/resume, do not duplicate requests on same stream |
| Transfer progress | Only after AcceH: receiver must schedule its next needed request within 120 seconds while no local work is pending; outstanding requests have the 30-second timeout above. Local verification/publication must make measurable local progress every 120 seconds and finish within session/consent lifetime. Sender waits for Complete up to remaining session/consent lifetime when no requests are pending; keepalives still apply. |
| Accept lifetime | <=24 hours, <=manifest expiry; fresh session requires fresh Accept |
| Resume retention | <=7 days, <=manifest expiry; storage quota enforced locally |
| CancelAck | 5 seconds |
| Receipt | Within 10 seconds after Complete; otherwise sender shows unconfirmed delivery |
| Unknown noncritical frames | <=1024-byte body and <=32/session |
| Revocation gossip | <=64 records/session |
| Relay | §10 bounds, plus endpoint limits above |
| Link setup | <=1 LinkAbilities per endpoint and <=1 LinkOffer per session; offers expire after <=120 seconds; one accepted connection per offer; a device hosts at most one offered link at a time |

`Ping` and `Pong` share this body:

| Field | Bytes | Limit / semantics |
| --- | ---: | --- |
| nonce | 8 | Random nonzero nonce, echoed exactly by Pong |

Only one Ping may be outstanding per direction; unsolicited/incorrect Pong is STATE.
Keepalives and unverified progress MUST NOT extend consent, manifest, or chunk
progress deadlines. No peer can indefinitely retain buffers by sending one byte at
a time: deadlines are absolute for the operation, not reset on partial records.

## 14. Threat model and security considerations

### 14.1 Protected assets and assumptions

The protocol protects file contents, authenticated metadata, device/pair secrets,
identity binding, integrity of selected files, and locally authorized consent. It
assumes trustworthy endpoint core code, OS entropy, approved cryptographic libraries,
secret storage, and a user who can authorize the intended pairing and selection.
The attacker may control every network/transport/relay/discovery service, inject,
reorder, replay, truncate, delay, or block bytes, and operate malicious authenticated
peers. No transport, UI input, advertisement, MIME string, file name, or relay assertion
is a trust boundary shortcut.

Out of scope are a fully compromised endpoint OS/core, coercion, physical observation
of a displayed code/QR, malicious recipients redistributing plaintext, guaranteed
erasure from flash/backups, global revocation availability, and anonymity/traffic
analysis resistance. Root/device compromise must be addressed by revocation and
explicit re-pairing; it is not automatically healed by the hash-based PSK ratchet.
The HFS construction's intended quantum threat is an attacker recording traffic
now and attacking classical key agreement later. It combines classical DH and a
fresh ephemeral KEM via the specified Noise KDF, assuming honest independent
randomness, secure KDF/AEAD, and correct erasure. It makes no randomness-exposure
resilience claim and no claim that this new integration has been audited or is
production-ready. Ed25519 signatures, X25519, and the selected CPace group do not
provide post-quantum identity authentication against an active quantum attacker.
An unknown high-entropy PSK supplies additional authentication protection, but
adding HFS does not turn the identity system into a post-quantum signature system.
Full PQ identity migration requires a future reviewed version.

### 14.2 Required defenses

- **MITM/downgrade:** authenticated transcript includes version, mode, suite, roles,
  CPace context, and static bindings. QR/code possession and explicit confirmation
  precede contact creation. There is no unauthenticated or classical fallback.
- **Replay/nonce reuse:** fresh session nonces, monotonic Noise nonces, ratcheted pair
  state, session-bound signed AcceH, request binding, unique file masters, immutable
  ciphertext, and terminal cancellation are mandatory. Clock expiry alone is not a
  replay defense. Rollback-resistant local persistence remains an implementation gate.
- **Consent bypass:** reject content before signed AcceH in core, including previews,
  empty files, alternate pipes, and resumed sessions. Consent to pair is not consent
  to receive. A valid signature for a different sender/session/manifest is useless.
- **Malicious files/peers:** enforce quotas before allocation, checked arithmetic,
  path isolation, local conflict mapping, proof bounds, constant-time verification,
  cancellation, and nonexecuting storage. Authentication does not make content safe.
- **PAKE guessing:** bounded online attempts; never publish a low-entropy-code-derived
  lookup hash. Code relay rendezvous has an unresolved distribution problem, not a
  license to introduce an offline dictionary oracle.
- **Metadata leakage:** a §10.2 hotspot or Wi-Fi Direct SSID and a Wi-Fi Aware
  publish show nearby observers that a todoke link is being set up (random per
  offer, nothing linkable);
  encrypted names/manifests; rotating pseudonyms; untrusted
  candidate addresses. IPs, transfer lengths, timing, discovery presence, and room
  linking remain visible. Padding/Tor cover traffic is not defined.
- **Availability:** a relay can block; a peer can consume allowed quota; a PAKE attacker
  can burn the attempt budget; uncertain ratchets may need re-pairing. Fail closed
  on security state uncertainty. Do not promise availability under active attack.
- **Secrets:** use libcrux where it covers, otherwise RustCrypto/dalek and official
  BLAKE3/Bao libraries. MUST NOT implement primitives. All owned secret buffers and
  secret-bearing library state MUST be zeroized when no longer needed. Libraries'
  internal scratch copies and zeroization guarantees need review; wrapping only an
  outer buffer does not satisfy that requirement. Do not log secrets, QR/code bytes,
  file keys, decrypted content, manifests, or contact tokens. No telemetry. Fixed
  public vector seeds are test data, not production credentials.
- **Boundaries:** all protocol/crypto/file decisions belong to Rust. No secret crosses
  BoltFFI; platform access is narrow and reviewed. `#![forbid(unsafe_code)]` applies
  outside FFI/platform crates; this prohibition does not falsely assert dependencies
  contain no unsafe code. No panics on hostile input. Every parser needs cargo-fuzz;
  every state machine needs proptest state-machine tests and reviewed invariants.

## 15. Conformance evidence and references

`spec/test-vectors/*.json` and the deterministic generator
[`generate_vectors.rs`](../crates/todoke-proto/examples/generate_vectors.rs) define
public fixtures for QR, discovery HMAC, PSK ratchet, STREAM nonces, manifest hash,
and signed Accept. They also chain the QR PSK through the ratchet, pair secret,
discovery key, DiscoveryRecord/mDNS TXT, and rendezvous tokens (§4.4, §9, §10),
and derive §8 content keys, nonce prefixes, and one 123-byte AAD from the manifest
fixture. These are key-schedule vectors only: no content ciphertext or Bao slice
fixture exists yet. The separate
[`generate_handshake_vectors.rs`](../crates/todoke-proto/examples/generate_handshake_vectors.rs)
defines complete IKpsk2+hfs, KKpsk2+hfs, and XXpsk3+hfs **Noise-layer** reference
transcripts for the construction in §4.2. The XX fixture uses an explicitly
synthetic prologue and public PSK; it is not a valid §3.2/§4.2.6 code-session
transcript and does not certify CPace-to-Noise integration. Values are lowercase
hex unless their schema says otherwise.
Fixture JSON is not a wire encoding. Fixtures containing suite 0x0001 do not enable
that suite. The generator MUST use reference crates, fixed public seeds/times,
canonical serialization, and no production secret input or random fixture drift.

Regenerate from repository root and check exact committed bytes:

```sh
cargo run --locked -p todoke-proto --example generate_vectors
cargo run --locked -p todoke-proto --example generate_vectors -- --check
cargo test --locked -p todoke-proto --example generate_vectors
cargo run --locked -p todoke-proto --example generate_handshake_vectors
cargo run --locked -p todoke-proto --example generate_handshake_vectors -- --check
cargo test --locked -p todoke-proto --example generate_handshake_vectors
cargo fmt
cargo clippy --all-targets -- -D warnings -W clippy::pedantic
cargo test
cargo deny check
```

Implementations MUST add negative cases for all bounds, wrong roles/identities,
noncanonical input, signature mutation, wrong session/manifest/selection, pre-consent
content, AEAD/proof tampering, truncated/final-segment substitution, resume after
revocation, and crash/ratchet conflicts. Production parsers/state machines are not
introduced by the vector generator and are not certified by its tests. Interoperability
requires at least two independently checked implementations and full hybrid handshake,
content ciphertext/Bao, identity, ratchet-state, relay, and adversarial vectors.

Primary algorithm references in addition to the linked format specifications:

- [RFC 8032: Ed25519](https://www.rfc-editor.org/rfc/rfc8032)
- [RFC 7748: X25519](https://www.rfc-editor.org/rfc/rfc7748)
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869)
- [RFC 2104: HMAC](https://www.rfc-editor.org/rfc/rfc2104)
- [BLAKE3 reference implementation](https://github.com/BLAKE3-team/BLAKE3)
- [RFC 9496: Ristretto255](https://www.rfc-editor.org/rfc/rfc9496)
- [RFC 9000: QUIC](https://www.rfc-editor.org/rfc/rfc9000)

<a id="open-decisions"></a>

## 16. Open decisions

This section is the complete known open-question register for this revision.
Unspecified behavior MUST NOT be filled in by code. The fixed wire allocations,
limits, and policies above are v1 design decisions; open gates do not weaken them.

| ID | Open question / required evidence | Consequence until resolved |
| --- | --- | --- |
| O1 (resolved) | The exact HFS+PSK construction is pinned to independently reviewed Snow source, instantiated with ML-KEM-768 in §4.2, with schedules, operations, byte layouts, and reproducible handshake vectors. See the [decision and review limits](decisions/O1-HYBRID-NOISE.md). | Construction selection resolved. The new backend/application integration is not covered by that audit; production and independent interoperability gates remain O6/O10. No classical fallback. |
| O2 | Does the pinned CPace draft/profile and the specified embedding have a reviewed production Rust implementation with matching context/ISK/confirmation vectors? If not, should a reviewed SPAKE2 profile replace it through a spec revision? | Code pairing disabled. No homemade PAKE or code-hash PSK. |
| O3 | Can seamless ratchet recovery be proven without rollback, double use, trial-decryption oracles, or permanent desynchronization? Which mobile/desktop storage APIs enforce atomic journal replacement and prevent restored backups from reusing a generation? | Current conservative pending-journal policy requires re-pairing. Production persistence needs crash/rollback testing before sessions ship. |
| O4 | How are person roots provisioned, protected, backed up/recovered, and migrated; how is revocation freshness obtained without telemetry or an online dependency? How are new devices enrolled without transferring device secrets? | Root signatures/bindings/revocations are specified; remote enrollment, global freshness, and root recovery are not enabled. |
| O5 | How does the Rust/platform boundary render/scan secret QR material and handle secret code entry without sending raw secrets across BoltFFI? What verified BoltFFI mobile/web APIs preserve this constraint? | No production pairing UI/binding implementation until resolved. |
| O6 | Which libcrux/reference crate versions provide the required primitive coverage, strict verification, secret-state zeroization, constant-time behavior, target support, and accepted supply-chain audit evidence? | Reference fixtures are not production library approval. Scratch-state/secret-lifecycle coverage is a production gate. |
| O7 (resolved) | BLE allocation, mobile permission and background behavior, AWDL / Wi-Fi P2P / USB packaging, and the direct-path and hole-punch profile. Resolved by §10.1 (no Bluetooth or USB transport in v1; direct links are TCP with the unchanged prelude and records; no direct QUIC), §10.2 (Wi-Fi link setup with per-offer random credentials inside a session), §10.3 (permissions, background, no operating-system trust), and §10 (relay-only non-local paths in v1). See [ADR 0014](../docs/adr/0014-local-links.md). | Each Wi-Fi adapter needs device-lab evidence (T01) before it is enabled by default. Hole punching stays disabled until a later revision. |
| O8 | How is a high-entropy rendezvous capability conveyed for remote human-code-only pairing without an offline dictionary oracle or trusted matching service? | Local code discovery and QR capability derivation are specified; remote code-only rendezvous disabled. |
| O9 | What platform-specific filesystem publication, secret storage, preview isolation, collision mapping, and quota policies satisfy the core invariants on all targets? | No secure file-receipt/platform claim until implementation and adversarial OS tests. |
| O10 | What independent implementation reproduces the hybrid handshakes, and what content encryption/Bao, state-machine, crash, identity/revocation, discovery-adapter, and relay transcripts establish full interoperability? | The six standalone fixture families and new reference handshake transcripts establish reproducibility, not independent full-protocol interoperability. |
| O11 | Should the unused static ML-KEM credential in QR/DeviceBinding be removed before v1 release? | Retain its existing bytes and validation for now; signatures/pins authenticate the public credential only. It MUST NOT be used as an HFS ephemeral key or represented as a static-KEM possession proof. Any removal requires an explicit wire-format revision and regenerated affected fixtures. |
| O12 (resolved) | The contact Hello carried the pair's ratchet `generation` in the clear, linking a pair's sessions across epochs for a passive LAN or relay observer. Resolved in §4.1: the Hello has no generation field (58-byte bodies). The locator already resolves the pair and generation, so the counter added no diagnosis: divergence is found from the ratchet journal (§4.4), and a restored stale generation is O3's. See [ADR 0016](../docs/adr/0016-hello-generation.md). | Handshake fixtures were regenerated for the 58-byte Hellos. A pair's failed attempts within one epoch still share a locator. |
