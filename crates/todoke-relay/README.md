# todoke relay

A relay lets two todoke devices that cannot reach each other directly meet and exchange their end-to-end encrypted traffic (PROTOCOL §10).

The relay is untrusted:

- It sees rendezvous tokens, addresses, timing, and sizes.
- It never sees keys, file names, or file contents.
- It cannot authorize a transfer.
- A relay that tampers with traffic only breaks the session.

## Run one

With Docker, from the repository root:

```sh
docker compose -f crates/todoke-relay/compose.yaml up -d
docker compose -f crates/todoke-relay/compose.yaml logs relay
```

The log shows two lines:

```text
listening on [::]:4433
pin spki-sha256:3f9a…
```

The pin is what devices configure. Without Docker:

```sh
cargo build --release -p todoke-relay
target/release/todoke-relay --listen '[::]:4433' --state /var/lib/todoke-relay --name relay.example.org
```

Without `--cert` and `--key`, the relay makes a self-signed certificate on first start and keeps it in `--state`; its key file is readable by its user only. Devices pin that key. Changing the key means updating every device's pin.

With `--cert` and `--key` (PEM, leaf first), devices may instead validate the certificate with the platform's roots and leave the pin out.

| Option | Default | |
| --- | --- | --- |
| `--listen` | `[::]:4433` | UDP address |
| `--metrics` | off | TCP address for `/metrics` and `/healthz` |
| `--max-connections` | 20000 | |
| `--max-connections-per-source` | 64 | per IPv4 address or IPv6 /64 |
| `--max-rooms` | 50000 | |
| `--tunnel-bytes` | 16 TiB | per direction; §10's maximum |
| `--tunnel-seconds` | 86400 | §10's maximum |

## What it keeps

Nothing outlives a room or a tunnel. It writes no logs about clients and has no database.

`/metrics` shows totals only. No client, token, address, or room is ever counted by name:
- connections, rooms, and tunnels open;
- registers;
- matches;
- closes by reason;
- refusals;
- bytes forwarded.

Bind it to loopback or a private network.

Nodes are stateless. Several nodes are just a longer relay list. Both devices of a pair pick the same node from the shared list (rendezvous hashing on their token), so nodes never talk to each other and need no shared store.

## Configure devices

In the device's `config.json`:

```json
{
  "relays": [
    {
      "name": "home",
      "address": "relay.example.org:4433",
      "server_name": "relay.example.org",
      "pin": "spki-sha256:3f9a…"
    }
  ]
}
```

Both devices of a pair need the same list (same names): the relay a pair meets on is chosen from it.

`relay_presence_seconds` (default 300, at least 10) sets how often two idle devices meet at the relay. A sender reaches a receiver within one period.

## Relay lists

Operators of federated relays publish their nodes as a file in the same format:

```json
{
  "version": 1,
  "relays": [
    { "name": "eu-1", "address": "eu-1.relays.example:4433", "server_name": "eu-1.relays.example", "pin": "spki-sha256:…" },
    { "name": "us-1", "address": "us-1.relays.example:4433", "server_name": "us-1.relays.example" }
  ]
}
```

A device only reads lists from files its user chose; nothing is fetched. An entry without a pin is validated with the platform's roots, never without validation.

## Limits it enforces (§10)

- Two clients per token, two rooms per connection.
- A room lasts 120 seconds, and a member waits at most 30 seconds for the other.
- Records come in order; a duplicate or unknown one closes the room.
- Both members must send `Forward` before either gets `ForwardReady`.
- At most 1 MiB is buffered in each direction of a tunnel.
- Every new address is sent a QUIC Retry first, so a spoofed source gets one packet back and no connection.
- TLS 1.3 only, X25519MLKEM768 preferred, no 0-RTT, no session tickets.
- It adds no candidates of its own, and devices never hole-punch (§16 O7): every byte goes through the relay.
