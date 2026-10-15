# ADR 0016: The Hello carries no ratchet generation (§16 O12)

- **Status:** accepted on 2026-10-15. Queued after P16 when ADR 0013 found
  the leak; the design was delegated with the standing priority of maximum
  security first, then performance.
- **Date:** 2026-10-15
- **Scope:** PROTOCOL §4.1 and §16 O12; `todoke-proto::session::Hello`, the
  `todoke-crypto` handshake driver and contact authority, the regenerated
  handshake fixtures and fuzz seeds.

## Context

Every `ClientHello` and `ServerHello` carried the pair's ratchet generation
as a cleartext `u64`: 0 for a new pairing, the persisted value for a
contact. The generation grows by one with every committed session, so a
passive observer of the LAN or of a relay could follow a pair from session
to session, across discovery epochs, whatever the rotating tokens and
locators hid (ADR 0013). O12 asked which blinded form would keep a mismatch
diagnosable without the cleartext counter.

What the counter did in practice:

- The responder finds the contact through the Hello's locator, the first 16
  bytes of the epoch's rendezvous token, which is derived from the
  generation's pair secret (§9). The resolved contact fixes the generation:
  the stored one, the only one whose locators the table holds (tables are
  rebuilt on every commit, and prior generations' state is erased).
- The responder then compared the Hello's generation with the stored one.
  An honest initiator whose locator resolved is at that generation, so the
  check could only fail for a Hello forged by someone who copied a locator
  and changed the counter, which the transcript already refuses (the Hello
  bodies are in the Noise prologue).
- The mismatch was never diagnosed: the core dropped the error, and nothing
  reached the peer (§4.4 forbids revealing contact details).
- A device restored from an old backup has an old pair secret: its locator
  resolves to nothing on the other side, with or without the counter. That
  case is §16 O3's (preventing restored backups from reusing a generation).

## Decision

The Hello has no generation field. The body shrinks from 66 to 58 bytes:
magic, version, suite, mode, flags, locator, client nonce, server nonce.

- **Identification:** the locator alone resolves the pair and its
  generation. A locator that resolves to no committed pair, or to more than
  one, is an unknown peer.
- **Binding:** each generation has its own PSK (the ratchet derives
  `psk_next` from the transcript), so a handshake between two sides at
  different generations fails with the generic authentication error when
  the PSK is mixed in. The encrypted ratchet records still carry and MAC
  `generation_next`.
- **Diagnosis:** divergent generations are found locally from the ratchet
  journal (§4.4), as before; nothing about the pair's state goes on the
  wire.

No blinded counter was added. A blinded form would need a key every
generation shares (the static-static Diffie-Hellman, say) and a trial over
every contact for each unresolved Hello, which is a cost a stranger can
impose, to diagnose only the restored-backup case, which O3 owns and which
the counter never diagnosed either.

### Rejected alternatives

| Alternative | Why not |
| --- | --- |
| Keep 8 reserved zero bytes | A dead field; the version is unchanged and v1 is not in production, so the bytes go |
| A MAC tag over the generation under a pair-stable key | Trial work over every contact per unresolved Hello; it would diagnose only a restored backup (O3), and a replayed old Hello could make it report a false divergence |
| The generation encrypted under a pair-stable key | Same costs, and it still needs a tag to say which contact matched |

## Consequences

- An observer of Hellos learns the mode, a locator that changes with every
  epoch and every committed session, and random nonces; nothing links a
  pair's committed sessions.
- Failed attempts within one epoch and generation still share a locator,
  as before.
- `Hello::client` takes no generation; the handshake driver keeps the
  plan's. `SessionError::GenerationMismatch` now comes only from a ratchet
  record.
- The three handshake fixtures were regenerated (their Hello bodies and,
  through the prologue, every hash, record, and key after them), and the
  fuzz seeds that hold Hellos or fixture records were rebuilt from them.

## Residual risks

- **A restored stale generation stays silent:** the peer cannot tell it
  from an unknown device, and the restored device only sees its attempts
  fail. Fix: O3 (backup-proof generation storage, or a local check that
  the state was restored).
- **Attempts within an epoch are linkable** through their shared locator.
  Fix: per-attempt locators would need a trial over several candidates per
  contact; not worth it for attempts that fail.
