# ADR 0013: Private discovery and contacts

- **Status:** accepted on 2026-10-15. The maintainer delegated the design
  with the standing priority of maximum security first, then performance.
  Where the P15 build prompt and PROTOCOL differ, PROTOCOL wins.
- **Date:** 2026-10-15
- **Scope:**
  - the paired advertising schedule (`todoke-discovery::advertise`)
  - statistical and clock-skew tests of the discovery tokens
    (`todoke-crypto::discovery`)
  - the matching benchmark (`bench/benches/discovery.rs`) and
    todoke-crypto's `bench-support` feature
  - the core's wake-up for the next record change

## Context

The P15 prompt asks for `crates/todoke-discovery` "per spec section 7":

- advert payloads for BLE and mDNS: rotating 15-minute tokens per contact,
  constant-size, no names or models, randomised timing;
- receiver-side matching against all contacts, efficient for 1,000, with a
  clock-skew window;
- stranger mode: a time-limited generic advert, PAKE required, previews
  disabled by default;
- visibility modes: contacts / everyone 10 min / hidden;
- multi-device: a person's devices recognise each other and sync contacts
  end-to-end;
- tests: tokens unlinkable across epochs (a statistical test), a matching
  performance benchmark, skew handling, vectors from `spec/test-vectors`.

The prompt predates the current spec: discovery is PROTOCOL §9, not §7
(transfers and consent). Most of it was built in P09 (ADR 0007), P10
(ADR 0008), and P12 (ADR 0010), and the QR stranger token in PR #12:

- the 19-byte `DiscoveryRecord` (version, mode, epoch, token, flags), the
  only content of the mDNS TXT string, with a random 16-hex instance label
  per epoch and never a device name;
- per pair, `token = HMAC-BLAKE3(pair_key, epoch)[..8]`, rotating every
  900 seconds and on each committed ratchet, reproduced from
  `spec/test-vectors/discovery-token.json`;
- receiver matching against the local epoch and its neighbours, a
  directory bounded per contact and for strangers, expiring entries after
  120 seconds and rate-limiting matches;
- stranger mode only on an explicit local enable, for at most 300
  seconds, a token rotating every 60 (random for code pairing, the QR's for
  QR pairing);
- hiding (`SetHidden`), which advertises nothing paired.

This step closes what was left.

## Decisions

### Randomised advertising

A device with several contacts showed one record at a time in key order,
each for exactly 3 seconds. An observer could see the period and the
order, and count a device's contacts by the length of its cycle. Now:

- every round shows each available contact once, in a fresh uniformly
  random order (Fisher–Yates, indices drawn by rejection from the OS
  CSPRNG);
- each record stays up for a uniform 2 to 4 seconds, to the millisecond:
  the core wakes at `Advertiser::next_change` rather than at the next of
  its 500 ms ticks, so the times are not quantised and its devices share
  no tick phase;
- a contact that leaves the table (ratchet-uncertain, removed) is
  replaced at once, and a clock that goes back ends the turn;
- no contact is favoured. The schedule used to offer a "priority" contact
  every other turn (never wired into the core): a contact shown more often
  tells an observer whom the device is about to exchange files with, and
  the pair token is the same on both devices, so it was removed;
- without randomness nothing new is advertised, and the round is left as
  it was.

The mDNS instance label stays one random label per epoch: the records are
one device's in any case, and a label per record would show the rotation
just as clearly.

### Matching

Matching was already independent of the contact count: the table maps each
token of the previous, current, and next epochs to its contacts in an
ordered map, built once per epoch and after each committed session. The
benchmark (bench/RESULTS.md, Apple M5 Pro) with 1,000 contacts:

| Operation | Time |
| --- | --- |
| build the table | about 6.8 ms |
| match a contact's record | about 41 ns |
| match an unknown record | about 39 ns |
| a whole sighting: checks, match, store | about 0.93 µs |

The benchmark builds tables from raw pair PSKs through
`DiscoveryTable::from_pair_psks`, behind a new `bench-support` feature of
todoke-crypto; `scripts/ci/deny-exceptions-dev-only.sh` fails if a shipped
graph or any root-workspace graph (dev-dependencies included) enables it.

### Clock skew

A receiver tests the epoch a record claims only if it is its own or a
neighbour (bounded at zero). Peers whose clocks differ by the §1 120
seconds therefore match on both sides of an epoch boundary, and anything
that leaves them in adjacent epochs matches; two epochs apart never does.
Tests now pin this at the boundaries, at epoch 0, and at the last epoch.

### Unlinkability evidence

Tokens are a PRF of the pair key (HMAC-BLAKE3), so their unlinkability
across epochs rests on that assumption, not on a test. The tests are a
check against gross mistakes (a counter, a reused input, a truncation that
keeps structure): one pair's tokens over 20,000 epochs, and 2,000 pairs'
tokens in one epoch, must look like independent uniform 64-bit values
(bit balance per position and overall, neighbours' Hamming distance with
mean 32 and variance 16, no repeats), and the checks are shown to refuse
counting, drifting, and repeating tokens.

### Visibility modes

| Prompt | todoke | Why |
| --- | --- | --- |
| contacts | the default: one paired record at a time, for contacts only | §9 |
| everyone, 10 minutes | stranger mode through a pairing code (`Core::pair_show_code`), for 300 seconds | §9 caps stranger mode at 300 seconds; a stranger must pair by QR or code |
| hidden | `SetHidden`: nothing paired is advertised | |

### Stranger mode: PAKE and previews

A stranger can only become a contact by QR pairing or code pairing (CPace,
§3.2; disabled until O2 closes). There are no previews to disable: the
preview crate (`todoke-preview`) is still empty, and §7.2 forbids any
preview before consent. When previews are built, those of files from
contacts paired by code (whose origin is `TrustOrigin::CodePairing`) must
be off by default.

### Not built: multi-device recognition and contact sync

The prompt asks that a person's devices recognise each other and sync
contacts end-to-end. PROTOCOL forbids it in v1:

- §2: "Possession of another device under the same root does not inherit
  that device's pairings or file consent." Syncing contacts would give a
  device pairings it never made.
- §6: multi-device enrollment has "no enabled v1 extension"; its message
  range (0x0500..0x05ff) is reserved.
- §16 O4: how person roots are provisioned and how new devices are
  enrolled without transferring device secrets is open, and "unspecified
  behavior MUST NOT be filled in by code".

A person's devices can pair with each other like any two devices. Making
them recognise and trust each other as one person needs a spec revision
that closes O4 and assigns the enrollment messages.

### Not built: BLE adverts

BLE would carry the same 19-byte record, but §9 left its allocation open
(§16 O7). O7 has since been closed without Bluetooth: todoke uses no
Bluetooth and no USB at all ([ADR 0014](0014-local-links.md)).

## Consequences

- An observer near a device sees one record at a time, changing at random
  moments; it still learns the exact number of available contacts by
  watching one label through a whole round (every round shows each once).
- With many contacts, any one contact's record comes round once per round:
  2 to 4 seconds times the number of available contacts (about 50 minutes
  on average for 1,000). Two devices find each other as soon as either sees
  the other's record, and a known peer's last addresses (or the relay
  rendezvous) do not wait for discovery.

## Residual risks

- **Contact count leaks over a round:** an observer that watches one label
  through a whole round counts the device's available contacts. Fix: a
  spec revision (for example a fixed number of records per round, padded
  with decoy tokens); §9 defines no decoys.
- **Slow discovery with many contacts** (above). Fix: weight the rotation
  toward recently active contacts, or a spec-defined query, both of which
  need a decision on what they reveal.
- **The statistical tests are not a proof:** unlinkability rests on
  HMAC-BLAKE3 being a PRF.
- **The LAN Hello linked a pair's sessions across epochs** (resolved): the
  contact Hello carried the pair's ratchet `generation` in the clear. The
  Hello no longer carries it ([ADR 0016](0016-hello-generation.md), §16
  O12).
- **The benchmark ran on one machine** (Apple M5 Pro); x86_64 and phone
  numbers are still to measure.
- **Multi-device** waits on O4 (above); BLE is out by decision (ADR 0014).
