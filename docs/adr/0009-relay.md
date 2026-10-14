# ADR 0009: Relay, rendezvous, and hole punching

- **Status:** accepted on 2026-10-14. The maintainer delegated the design
  ("choose the best design") with the standing priority of maximum security
  first, then performance. Every choice below follows PROTOCOL and DESIGN
  where the P11 build prompt differs.
- **Date:** 2026-10-14
- **Scope:**
  - `todoke-proto::relay` (the §10 records)
  - `todoke-relay` (the node, its binary and image)
  - `todoke-transport::relay` (the client)
  - the core's use of relays
  - PROTOCOL §4, §9, §10, §13, §14, and §16 O7, O8, O10

## Context

The P11 prompt asks for:

- a decision between iroh and an own implementation;
- rendezvous under rotating blinded tokens;
- STUN-like endpoint discovery and UDP hole punching with QUIC between
  peers;
- a relay fallback over QUIC/UDP and then HTTPS/WebSocket on 443;
- a tokio + axum server with optional Redis presence, Prometheus metrics, a
  Dockerfile, one-command self-hosting, and a federated relay list;
- NAT simulation, malicious-relay, and load tests (10k concurrent rendezvous
  on one node).

PROTOCOL §10 fixes:

- the relay control records over QUIC v1 / TLS 1.3, and relay authentication
  (platform validation or a pinned key);
- the limits: two clients per token, a 120-second room, a 30-second wait,
  two rooms per endpoint, four candidates, 1 MiB of buffering per direction,
  and a 24-hour, 16 TiB tunnel;
- that the relay receives no secrets, logs no tokens or addresses, and keeps
  nothing.

It also says Punch must not initiate probes until a direct-path profile is
ratified (§16 O7), and remote code-only rendezvous stays disabled (O8). §16
adds: unspecified behavior must not be filled in by code.

## Decisions

1. **Our own implementation of §10, not iroh.** iroh's relay protocol, its
   endpoint identities, and its path selection are a different design. Using
   it would mean a second authentication layer under our sessions and
   records that are not §10's.
   - The node and client are written here on quinn (QUIC v1) and rustls:
     MIT/Apache, maintained, and used widely.
   - Our Noise sessions run inside a QUIC stream, so the relay link adds
     nothing to their security and takes nothing from it.
2. **TLS: aws-lc-rs, TLS 1.3 only, X25519MLKEM768 preferred, no 0-RTT, no
   resumption tickets.**
   - The hybrid key exchange protects relay metadata (rendezvous tokens)
     against later quantum decryption; ring has no ML-KEM.
   - Without tickets or 0-RTT, nothing links two connections.
   - License exceptions, per version, for aws-lc-rs, aws-lc-sys,
     rustls-webpki, untrusted, webpki-root-certs, and matchit; ring is never
     compiled.
3. **Relays are authenticated by the platform's roots or a pinned key**
   (SHA-256 of the certificate's SubjectPublicKeyInfo, written
   `spki-sha256:…`).
   - A pinned relay's handshake signature is still checked.
   - Validation is never skipped.
4. **Rendezvous tokens are the spec's:**
   - contacts: the pair's §9 token for the current epoch, which the
     discovery table now holds;
   - QR offers: `HKDF(pairing_id, one_time_psk,
     "todoke/v1/pairing-rendezvous")`.

   Human-code pairing never uses a relay (O8).
5. **Stateless nodes; no Redis.** A shared presence store would persist
   tokens, which §10 forbids, and would be a target.
   - Both devices pick the same node from their shared relay list by
     rendezvous hashing: the highest `BLAKE3(name || 0 || token)`.
   - Nodes never talk to each other, and a node leaving the list moves only
     its own tokens.
   - The federated relay list is a JSON file (`{"version": 1, "relays":
     [...]}`, the entries `CoreConfig.relays` uses), read only from files
     the user chose.
6. **No hole punching, and no STUN-like discovery.**
   - Candidates and Punch are encoded, decoded, and forwarded by the node
     exactly as §10 says.
   - Clients send no candidates and ignore Punch: §10 forbids probes until
     O7 is ratified, and discovering a public address means probing.
   - The node adds no observed candidate (§10 allows it): that would show
     one client's address to the other before they authenticate.
   - Every byte goes through the relay.
7. **No HTTPS/WebSocket fallback.** §10 specifies QUIC only, and a TCP
   framing of the relay protocol would be unspecified behavior.
8. **The node:**
   - Each bidirectional stream is one room; a connection may hold two
     streams (§10's two rooms).
   - Every new address must answer a QUIC Retry first.
   - Connections are limited in total (20000) and per IPv4 address or IPv6
     /64 (64); rooms are limited per node (50000).
   - Records must come in §10's order, or the room closes with a code.
   - Both Forwards come before either ForwardReady.
   - A tunnel splices the two streams in byte order with at most 1 MiB
     buffered per direction. That bound is enforced by the flow-control
     windows plus one 16 KiB chunk and checked at compile time.
   - The byte quota and lifetime are at most §10's.
   - Nothing is logged and nothing outlives a room.
9. **The client:**
   - At most two rooms at once.
   - A contact with offers waiting and not on the LAN is registered back to
     back.
   - Every available contact is met at a presence window: half of
     `relay_presence_seconds` (300 by default, at least 10), and at most 30
     seconds, at an offset both devices derive from their token.
   - A shown QR offer waits at the relay until it is used, stopped, or
     expires; the scanner tries the relay after the LAN.
   - On a tunnel, the smaller full device key initiates, and the QR scanner
     initiates (§4).
   - A relay error pauses that contact for 30 seconds.
10. **Closing a tunnel waits for its bytes.** Dropping a QUIC connection
    discards data in flight, which lost a session's last handshake message
    in testing. A dropped tunnel finishes its stream and keeps the
    connection until the relay has acknowledged everything and the other end
    has finished too (5 seconds at most).
11. **Operations:**
    - `/metrics` (Prometheus text) and `/healthz` through axum: totals only,
      off by default.
    - A Dockerfile with digest-pinned bases and a distroless non-root
      runtime image, run read-only with no capabilities.
    - `docker compose … up -d` as the one command.
    - A self-signed certificate kept in a state directory, its pin printed
      at start.
12. **The relay client is todoke-transport's `relay` feature**, enabled by
    the core and off in the fuzz and bench workspaces.
13. **Tests:**
    - The room table against §10's order and limits.
    - A node and the client on loopback: tunnels, pins, a full room, a
      missing peer, quotas, the room limit.
    - Malicious-relay tests: flipped, replayed, and dropped bytes in the
      handshake and in a transfer. The handshake never completes; the
      transfer stops with nothing published and no receipt; no plaintext
      crosses the relay.
    - Two cores, and two daemon processes, with the LAN off, pairing by QR
      and transferring through a relay.
    - A Linux network-namespace job in CI: two daemons behind full-cone,
      port-restricted, and symmetric NATs pair and send through a relay
      using the CLI, and are checked never to reach each other directly.
    - A load test in CI: 10000 concurrent rendezvous (20000 connections)
      with every tunnel open together. On an M5 Pro Mac (macOS, both sides in
      one process): all 10000 met in 304 s and carried a byte each way by
      320 s, in 2.3 GB, bound by system time on one UDP socket per side.
    - A fuzz target for the records.

## Residual risks

- **The relay's ALPN is unassigned.** §10 fixes the records but no ALPN;
  `todoke-relay/1` is ours. Fix: assign it in the spec (with O10's relay
  transcripts).
- **Networks that block UDP cannot reach a relay.** There is no TCP or 443
  transport (§10 specifies QUIC only). Fix: a spec revision adding a TCP/TLS
  framing of the same records, then that client and listener.
- **Both devices need the same relay list.**
  - Pairing does not exchange relay preferences, so devices with different
    lists never meet remotely.
  - Fix: carry each device's relay list in a signed record at pairing (needs
    a spec field).
- **Presence costs.**
  - Two idle devices open a session at every presence window (one empty
    session and one ratchet commit per pair per period), and the relay sees
    when each pair meets.
  - A sender reaches an idle receiver only at the receiver's next window (up
    to one period).
  - Fix: a spec'd wake-up (a signed "something waiting" token the relay can
    hold for one window), or push notifications on mobile.
- **Registrations while offers wait** continue back to back for an offer's
  whole lifetime (seven days) when the receiver is away. Fix: back off from
  minutes to an hour after repeated misses, reset by presence.
- **A relay (or anyone who learns a token) can deny a meeting** by occupying
  the room: two members per token. §10 accepts it; the session never
  authenticates a squatter. Fix: none at this layer.
- **Per-source limits behind large carrier-grade NATs:** 64 connections per
  IPv4 address can refuse users sharing one. Fix: raise it per deployment
  (an option), or move to a per-connection token budget.
- **Pin rotation:** a self-signed relay key cannot change without
  reconfiguring every device. Fix: allow two pins per relay entry during a
  rotation, or use a public certificate.
- **One UDP socket per node.**
  - Handshake throughput is bounded by one endpoint task.
  - Under a burst, the loopback load test loses handshakes. Clients retry,
    and the test retries a connection that did not come up, as the app does.
  - Fix: several endpoints sharing the port with `SO_REUSEPORT` (Linux), or
    more nodes in the list.
- **A tunnel lasts at most 24 hours** (§10). A longer transfer is cut and
  resumes with a fresh Accept (§7.5).
- **Supply chain:**
  - AWS-LC is a large C library.
  - The 82 crates of the QUIC, TLS, and HTTP stack are exempted from audit
    (noted per crate), as is rcgen's x509-parser in the lockfile.
  - Windows cannot be cross-checked from macOS any more (AWS-LC needs the
    Windows SDK); CI's native job checks it.
- **Metadata at the relay** (§10): source and destination addresses, timing,
  sizes, and which token meets when, within an epoch. No anonymity is
  provided.

## Not here

Direct QUIC between peers and hole punching (O7), BLE and other adapters,
remote code-only pairing (O8), push wake-ups, and relay lists exchanged at
pairing.
