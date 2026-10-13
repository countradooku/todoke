# ADR 0007: LAN transport, connection racing, migration, and mDNS discovery

- **Status:** accepted on 2026-10-14. The maintainer delegated the design
  ("choose the best design for this") with the standing priority of
  maximum security first, then performance; every choice below follows
  PROTOCOL where the P09 build prompt differs from it.
- **Date:** 2026-10-14
- **Scope:** `todoke-transport` (links, the LAN address policy, connection
  racing, TCP, the session manager, migration) and `todoke-discovery`
  (mDNS advertising and browsing), PROTOCOL §4, §5, §9, §10, §13, §16 O7.

## Context

The P09 prompt asks for a transport manager that races candidate links,
runs the Noise handshake on each, keeps the fastest authenticated one, and
migrates mid-transfer when a faster link appears; for LAN discovery over
mDNS with blinded tokens; for TCP with Noise and a QUIC option with BBR;
and for socket tuning including UDP GSO/GRO. PROTOCOL constrains several of
these:

- §4: one session attempt and one active session per device pair; for
  simultaneous direct attempts, the smaller device key keeps its outgoing
  attempt and the larger its incoming one.
- §4.4: every session commits a PSK ratchet step, and an interruption with
  a pending journal disables the pairing until it is re-paired.
- §5: multipath sharing of a CipherState is forbidden; moving to a new pipe
  requires a fresh session and a new Accept before resume.
- §7.2, §7.5: a resumed transfer needs a new signed Accept, which the core
  creates only from local user intent.
- §9: the exact mDNS record (service type, 16-hex instance label, one `v1=`
  TXT string with the 19-byte record), one token at a time with rotation,
  120-second cache expiry, stranger mode only on explicit enable.
- §16 O7: the direct-path QUIC/ALPN profile, BLE allocation, and AWDL,
  Wi-Fi P2P, and USB packaging are unassigned, and unspecified adapters
  stay disabled.

## Decisions

1. **Race connections, never handshakes.** Candidates (at most four, as
   §10 bounds direct candidates) connect RFC 8305 style: 250 ms apart, the
   next at once when one fails, five seconds overall. The first link to
   connect wins and the others are dropped before any session byte; the one
   handshake runs on the winner. Racing handshakes would break §4's one
   attempt per pair and could leave a pairing disabled (§4.4).
2. **One slot per device pair, held for the session's lifetime**, with §4's
   key-order rule for simultaneous attempts. The manager's steps are typed
   (claim, connect, handshake) so the contact store, which serializes
   establishment, is needed only while a handshake runs, and conflicts are
   settled before anyone waits for it.
3. **Migration is break before make, and conservative.** A session never
   moves; migrating closes it and starts a fresh one on the new link, after
   which the receiver must accept the resumed transfer again (§7.5). The
   default policy migrates only to a higher-ranked link kind or a link with
   a quarter of the latency; unknown metrics never justify it. A link change
   never changes the session mode, suite, or authentication: every link
   carries the same authenticated session.
4. **TCP only on the LAN; no QUIC, no UDP tuning.** Direct QUIC needs the
   unassigned O7 profile. `TCP_NODELAY` is on (every write is one complete
   record); buffer sizes stay with the system's automatic tuning, which a
   fixed size would turn off. The listener is dual-stack.
5. **A LAN address policy for every connection and accepted source.** Only
   private (RFC 1918, RFC 4193) and link-local addresses, link-local IPv6
   only with an interface, ports 1024 and up; never loopback (except an
   explicit development policy), global, multicast, broadcast, shared,
   documentation, or cloud metadata addresses (§10). A hostile mDNS record
   therefore cannot aim this device at the internet, its own services, or a
   router's administration page.
6. **mDNS through `mdns-sd`, without its `logging` feature**, so tokens,
   labels, and addresses never reach a log. Loopback interfaces are off
   outside development, only interfaces with private or link-local
   addresses announce, and the SRV host name is the instance label, never
   the device name. `mdns-sd` caches PTR and TXT records for 75 minutes, so
   todoke applies the §9 limit itself: every entry expires 120 seconds after
   it was last seen.
7. **Match on arrival, store only matches.** A paired record that matches no
   available contact is dropped at once; matches are kept per contact (at
   most four instances); stranger records only while the user looks for a
   device to pair (at most 32); at most 64 sightings are matched a second.
   A flood of fake instances cannot push real peers out.
8. **Rotation over contacts, one record at a time** (§9's SHOULD), three
   seconds per contact, with an optional priority contact on every other
   slot; a new random instance label every epoch. Stranger mode: explicit
   enable, 300 seconds, new token and label every 60.
9. **tokio** (features `net`, `time`, `rt`) for sockets and timers; links
   are `futures-io` pipes as the session layer takes them. Nothing is built
   for sockets on wasm32.

## Consequences

- Discovery of a device with many contacts takes up to three seconds per
  contact on the peer's side. The core can skip discovery for a known peer
  by racing its last known addresses directly: the handshake authenticates
  whatever answers.
- Migration mid-transfer costs a new consent prompt on the receiver, so the
  core should offer it only when it saves much more time than the prompt
  costs; `MigrationPolicy` is deliberately strict.
- On an Apple M5 Pro the session carries about 540 MiB/s per direction on
  one core per end (`bench/RESULTS.md`), about five times a gigabit link.
  1 GbE and Wi-Fi 6 measurements need two machines and are still to do.
- `mdns-sd`'s TXT decoder merges duplicate keys, so two `v1=` strings in one
  answer cannot be told from one; either way exactly one record is used.
- New dependencies (tokio, socket2, mio, mdns-sd, flume, if-addrs,
  socket-pktinfo, and their dependencies) are exempted in cargo-vet as not
  yet reviewed.

## Not decided here

QUIC (direct or relay), BLE, Wi-Fi P2P, AWDL, and USB (§16 O7); relay and
rendezvous (§10, a later step); how the core stores and reuses last known
addresses; what the UI shows while a migration waits for the receiver's new
Accept.
