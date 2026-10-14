#!/usr/bin/env bash
# Two todoke daemons behind separate NATs reach each other only through a
# relay (PROTOCOL §10): they pair by QR and send a file, driven by the CLI.
# Linux network namespaces, root required (CI only).
#
#   client-a 10.1.0.2 -- nat-a 10.1.0.1 | 203.0.113.11 --+
#                                                        wan -- relay 203.0.113.10
#   client-b 10.2.0.2 -- nat-b 10.2.0.1 | 203.0.113.12 --+
#
# NAT types (first argument):
#   full-cone        static 1:1 NETMAP: any outside host may reach the mapping
#   port-restricted  MASQUERADE: replies only from where the client sent to
#   symmetric        MASQUERADE --random-fully: a new port for every peer
#
# todoke never hole-punches (§16 O7), so each type must only let the
# client reach the relay; the clients can never reach each other directly,
# which the script also checks.
#
# Usage: sudo scripts/ci/nat-relay.sh <nat-type> <todoke binary> <todoke-relay binary>
set -euo pipefail

nat_type="${1:?NAT type}"
todoke="$(realpath "${2:?todoke binary}")"
relay_bin="$(realpath "${3:?todoke-relay binary}")"
case "$nat_type" in
    full-cone | port-restricted | symmetric) ;;
    *)
        echo "unknown NAT type: $nat_type" >&2
        exit 2
        ;;
esac

work="$(mktemp -d)"
failed() {
    echo "failed at line $1: $2" >&2
    for log in relay.out relay.err alice.err bob.err pair.err qr.json receive.out; do
        if [[ -s "$work/$log" ]]; then
            echo "--- $log" >&2
            tail -20 "$work/$log" >&2
        fi
    done
}
trap 'failed "$LINENO" "$BASH_COMMAND"' ERR
namespaces=(wan relay nat-a nat-b client-a client-b)
pids=()
cleanup() {
    for pid in ${pids[@]+"${pids[@]}"}; do
        kill "$pid" 2> /dev/null || true
    done
    for ns in "${namespaces[@]}"; do
        ip netns delete "$ns" 2> /dev/null || true
    done
    rm -rf "$work"
}
trap cleanup EXIT

in_ns() {
    local ns="$1"
    shift
    ip netns exec "$ns" "$@"
}

for ns in "${namespaces[@]}"; do
    ip netns add "$ns"
    in_ns "$ns" ip link set lo up
done

# The public network: a bridge in "wan" joining the relay and both NATs.
in_ns wan ip link add br0 type bridge
in_ns wan ip link set br0 up
link_wan() {
    local ns="$1" address="$2"
    ip link add "w-$ns" type veth peer name pub
    ip link set "w-$ns" netns wan
    ip link set pub netns "$ns"
    in_ns wan ip link set "w-$ns" master br0
    in_ns wan ip link set "w-$ns" up
    in_ns "$ns" ip addr add "$address/24" dev pub
    in_ns "$ns" ip link set pub up
}
link_wan relay 203.0.113.10
link_wan nat-a 203.0.113.11
link_wan nat-b 203.0.113.12

# Each client's private network and its NAT.
link_private() {
    local nat="$1" client="$2" net="$3" public="$4"
    ip link add "p-$client" type veth peer name lan
    ip link set "p-$client" netns "$nat"
    ip link set lan netns "$client"
    in_ns "$nat" ip addr add "$net.1/24" dev "p-$client"
    in_ns "$nat" ip link set "p-$client" up
    in_ns "$client" ip addr add "$net.2/24" dev lan
    in_ns "$client" ip link set lan up
    in_ns "$client" ip route add default via "$net.1"
    in_ns "$nat" sysctl -qw net.ipv4.ip_forward=1
    case "$nat_type" in
        full-cone)
            in_ns "$nat" iptables -t nat -A POSTROUTING -o pub -s "$net.2/32" -j SNAT --to-source "$public"
            in_ns "$nat" iptables -t nat -A PREROUTING -i pub -d "$public/32" -j DNAT --to-destination "$net.2"
            ;;
        port-restricted)
            in_ns "$nat" iptables -t nat -A POSTROUTING -o pub -j MASQUERADE
            in_ns "$nat" iptables -A FORWARD -i pub -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
            in_ns "$nat" iptables -A FORWARD -i pub -j DROP
            ;;
        symmetric)
            in_ns "$nat" iptables -t nat -A POSTROUTING -o pub -j MASQUERADE --random-fully
            in_ns "$nat" iptables -A FORWARD -i pub -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
            in_ns "$nat" iptables -A FORWARD -i pub -j DROP
            ;;
    esac
}
link_private nat-a client-a 10.1.0 203.0.113.11
link_private nat-b client-b 10.2.0 203.0.113.12

# The clients reach the relay, never each other's private address.
in_ns client-a ping -c 1 -W 2 203.0.113.10 > /dev/null
in_ns client-b ping -c 1 -W 2 203.0.113.10 > /dev/null
if in_ns client-a ping -c 1 -W 2 10.2.0.2 > /dev/null 2>&1; then
    echo "client-a reaches client-b directly: the topology is wrong" >&2
    exit 1
fi
# (Behind full-cone NATs client-b's public address would forward to it;
# todoke never uses it, as no candidates are exchanged, and the relay's
# byte count below shows the file went through the relay.)

# The relay, with a self-signed certificate; its printed pin goes into
# both devices' configuration.
in_ns relay "$relay_bin" --listen 203.0.113.10:4433 --state "$work/relay" --name relay.test \
    --metrics 127.0.0.1:9184 > "$work/relay.out" 2> "$work/relay.err" &
pids+=($!)
for _ in $(seq 50); do
    grep -q '^pin ' "$work/relay.out" 2> /dev/null && break
    sleep 0.1
done
pin="$(sed -n 's/^pin //p' "$work/relay.out")"
if [[ -z "$pin" ]]; then
    cat "$work/relay.err" >&2
    echo 'the relay did not start' >&2
    exit 1
fi

configure() {
    local home="$1"
    mkdir -p "$home"
    cat > "$home/config.json" << JSON
{
  "state_dir": "$home/state",
  "downloads_dir": "$home/downloads",
  "lan": { "enabled": false, "port": 0 },
  "relays": [
    { "name": "ci", "address": "203.0.113.10:4433", "server_name": "relay.test", "pin": "$pin" }
  ],
  "relay_presence_seconds": 10
}
JSON
}
alice="$work/alice"
bob="$work/bob"
configure "$alice"
configure "$bob"
cli() {
    local ns="$1" home="$2"
    shift 2
    in_ns "$ns" env TODOKE_HOME="$home" "$todoke" "$@"
}

cli client-a "$alice" daemon run 2> "$work/alice.err" &
pids+=($!)
cli client-b "$bob" daemon run 2> "$work/bob.err" &
pids+=($!)
for _ in $(seq 100); do
    if cli client-a "$alice" status > /dev/null 2>&1 && cli client-b "$bob" status > /dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

# Alice shows a QR offer; Bob uses its text through the relay.
cli client-a "$alice" --json pair show > "$work/qr.json" 2> "$work/pair.err" &
show=$!
pids+=("$show")
for _ in $(seq 100); do
    [[ -s "$work/qr.json" ]] && break
    sleep 0.1
done
text="$(head -1 "$work/qr.json" | python3 -c 'import json, sys; print(json.load(sys.stdin)["body"]["text"])')"
cli client-b "$bob" pair scan "$text"
wait "$show"

# Bob sends a file; Alice accepts everything that comes.
head -c 3000000 /dev/urandom > "$work/payload.bin"
alice_device="$(cli client-a "$alice" --json status | python3 -c 'import json, sys; print(json.load(sys.stdin)["body"]["device"])')"
cli client-a "$alice" receive --yes > "$work/receive.out" 2>&1 &
pids+=($!)
timeout 180 bash -c "TODOKE_HOME='$bob' ip netns exec client-b '$todoke' send '${alice_device:0:16}' '$work/payload.bin' --wait"

expected="$(sha256sum < "$work/payload.bin")"
received="$(sha256sum < "$alice/downloads/payload.bin")"
if [[ "$expected" != "$received" ]]; then
    echo 'the received file differs from the one sent' >&2
    exit 1
fi
# The file went through the relay: it forwarded at least the file's bytes.
forwarded="$(in_ns relay curl -s http://127.0.0.1:9184/metrics | sed -n 's/^todoke_relay_forwarded_bytes_total //p')"
if [[ -z "$forwarded" || "$forwarded" -lt 3000000 ]]; then
    echo "the relay forwarded ${forwarded:-nothing}, less than the file" >&2
    exit 1
fi
echo "Paired and transferred through the relay ($forwarded bytes forwarded) behind $nat_type NATs."
