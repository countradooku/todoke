# ADR 0014: Local links (closing PROTOCOL §16 O7)

- **Status:** accepted on 2026-10-15. The maintainer delegated the decisions
  ("you decide the most secure and fastest option"), then decided that
  todoke uses **no Bluetooth and no USB at all**.
- **Date:** 2026-10-15
- **Scope:** PROTOCOL §10 (relay-only non-local paths), §10.1 to §10.3
  (direct links, link setup inside a session, platform requirements), §5
  (three new frame types), §13 (link-setup limits), §14.2, §16 (O7
  resolved, O12 added); the link-setup codecs in `todoke-proto::link` and
  their handling in the transfer engine; `todoke-transport::capabilities`
  and the binding's `LinkKind` without Bluetooth, USB, or direct QUIC. The
  Wi-Fi adapters themselves are built in the radio steps (P18 to P20).

## Context

§16 O7 left open "what registered BLE service UUID/GATT allocation, mobile
permission/background behavior, AWDL/Wi-Fi P2P/USB packaging, and exact
direct-path QUIC/ALPN/hole-punch profile are deployable on each platform",
with every adapter disabled until then. The decisions follow the
maintainer's standing priority: maximum security first, then performance.
Platform facts come from primary documentation (Apple, Android and AOSP,
Microsoft Learn, the Bluetooth SIG, BlueZ, wpa_supplicant, NetworkManager,
IETF RFCs), read on 2026-10-15; the main sources are listed at the end.

A first draft specified a BLE profile (a random 128-bit GATT service,
records read over GATT, L2CAP or GATT pipes). An adversarial review found
real costs in it: a connected central could follow a device across address
rotation, notifications could be dropped on some stacks, and nothing let
an app rotate its address with its payload. The maintainer then removed
Bluetooth and USB from todoke altogether; this ADR records the result.

## Decisions

### No Bluetooth and no USB

v1 has no BLE advertising, GATT service, or L2CAP channel, and no USB
adapter (iPhone usbmux, Android Open Accessory). An IP interface the
operating system provides (USB tethering a user turned on, Thunderbolt
networking, a USB Ethernet adapter) is simply part of the LAN, with
nothing specific to it.

What this removes from the attack surface: a radio that advertises the
app's presence to everyone in range, a GATT server any nearby device can
connect to, link-layer stacks with uneven reliability, and USB paths that
need operating-system trust (Apple calls usbmux unsupported).

What it costs: devices with no shared network cannot find each other
offline. They meet through the relay (internet needed) or, between Apple
devices, through AWDL and Apple Wi-Fi Aware, which need no todoke
discovery. From a relay or LAN session, they can still move to a direct
Wi-Fi link (§10.2).

### Direct links are TCP with the unchanged session

Every direct link (the LAN, Wi-Fi Aware, Wi-Fi Direct, hotspots, AWDL,
Apple Wi-Fi Aware) carries the §4 prelude and §5 records over TCP, exactly
as the LAN does today.

- **Not QUIC.** QUIC is defined with TLS 1.3 (RFC 9001), and quinn's docs
  say other handshakes do not conform to QUIC v1. Between peers with no
  PKI, TLS would be unauthenticated and duplicate Noise, while adding a UDP
  listener, a QUIC/TLS state machine, and certificate parsing before
  authentication. §5 runs one ordered stream per session, so QUIC streams
  remove no head-of-line blocking, and QUIC migration conflicts with §5's
  fresh session per pipe. quinn's BBR is marked experimental. The LAN TCP
  path already measures about 540 MiB/s per session (bench/RESULTS.md).
  QUIC remains the device-to-relay protocol, where a real TLS certificate
  authenticates the relay.
- **One security stack.** Link-layer encryption (WPA3, Wi-Fi Aware NCS) is
  defense in depth; authentication and confidentiality come from the todoke
  handshake on every link.

### Non-local paths are relay-only in v1

Hole punching stays off: no candidates, Punch ignored, no observed
candidate from the relay (ADR 0009's behavior, now normative; the
Candidates and Punch records stay in the registry, parsed strictly, carrying
nothing). Candidate exchange through the relay's cleartext control records
would show a device's addresses to the relay and the peer before
authentication, and STUN would show them to third parties (RFC 8445 §19,
RFC 8828). §10 lists what a later revision must do instead.

### Wi-Fi links: set up inside an authenticated session

A contact session on the LAN or through the relay can move the devices to
a faster Wi-Fi link, only for a transfer the user started or accepted:

- **Abilities.** Each side says, once, which kinds it can host and join and
  which Wi-Fi security values it can join with (`LinkAbilities`). A fixed
  rule picks the kind (Wi-Fi Aware, then Wi-Fi Direct, then a hotspot), the
  host, and the strongest security the joiner supports; both ends compute
  the same result. There is no retry ladder: a `declined` or `failed`
  answer ends link setup for the session, so a peer cannot walk the host
  down the security list (the review's concern), and an iPhone never sees a
  second join prompt.
- **Credentials.** The host generates them from a CSPRNG per offer and
  sends them only inside the session: a 32-byte Wi-Fi Aware PMK, or a
  63-character passphrase (about 378 bits, so even WPA2 under it cannot be
  guessed offline). Credentials are sent, not derived: Noise exposes no
  secret exporter, and the handshake hash is not secret.
- **SSIDs have one fixed shape** (`todoke-` + 16 hex digits, or
  `DIRECT-xy-tdk-` + 16 hex digits for Wi-Fi Direct), checked before
  anything reaches the operating system, so a hostile contact cannot put
  its own text ("Apple ID verification") in a system join dialog. A host
  that cannot choose its SSID and passphrase (an Android LocalOnlyHotspot
  before Android 16) does not host that kind.
- **Break before make.** After `joined`, both close the session (§4 allows
  one per pair, and the session manager enforces it) and the joiner opens
  TCP over the new link and runs a full handshake. The transfer resumes
  with a fresh Accept; if the link fails, the devices reconnect as they
  can and resume the same way.
- **Containment.** Joins use app-scoped, temporary mechanisms
  (`WifiNetworkSpecifier` or the Wi-Fi Aware network request on Android,
  `NEHotspotConfiguration` with `joinOnce` on iOS, NetworkManager in-memory
  connections, Windows temporary profiles), and the joiner binds todoke's
  sockets to the link where it can. A host that controls its access point
  gives no default route or DNS and forwards nothing. Everything is torn
  down with the session.

Which link, per pair:

| Devices | Link | Wi-Fi security | Notes |
| --- | --- | --- | --- |
| Android ↔ Android | Wi-Fi Aware data path with our PMK | NCS-SK-256 or 128 | No user prompt; Aware can be unavailable while a hotspot or Wi-Fi Direct runs |
| Android ↔ Android (fallback) | Wi-Fi Direct group, our SSID and passphrase | WPA3 (Android 16 R2/PCC modes) or WPA2 | The joiner connects with the credentials, so no WPS and no invitation dialog |
| Android ↔ iPhone, Mac, Windows, Linux | Android hosts: a Wi-Fi Direct group (Android 10+) or, on Android 16, a LocalOnlyHotspot with our credentials | WPA3 transition or WPA2 | iOS asks the user once to join |
| iPhone ↔ iPhone | Apple Wi-Fi Aware (iOS 26, iPhone 12+) or AWDL | Wi-Fi Aware: system-managed; AWDL: undocumented | Wi-Fi Aware requires a one-time system pairing with a PIN; AWDL needs none |
| iPhone ↔ Mac, Mac ↔ Mac | AWDL | Undocumented | Discovery is the §9 mDNS service over peer-to-peer Wi-Fi |
| Windows or Linux ↔ iPhone | The PC hosts a hotspot (Windows 11 24H2 per-session Mobile Hotspot, Linux NetworkManager access point) | WPA3 transition | iOS asks once to join |
| PC ↔ PC | One hosts a hotspot, the other joins | WPA3 where both support it | |

Apple's links need no todoke negotiation: AWDL carries mDNS, and Apple
Wi-Fi Aware connects devices the system paired. On Apple platforms they
need Network.framework listeners (a BSD socket listener is not reachable
over AWDL), feeding the same byte stream.

### Platform requirements

- Permissions: Android 13+ `NEARBY_WIFI_DEVICES` with `neverForLocation`;
  location only where nothing else exists (older Android), never
  background location.
- Background: Android transfers in a `connectedDevice` foreground service
  started by the user (`dataSync` is capped at 6 hours a day from Android
  15); iOS in the foreground or a `BGContinuedProcessingTask` (iOS 26)
  started by the user. iOS background URLSession carries only HTTP, so it
  cannot carry a todoke session.
- No operating-system trust (Wi-Fi Direct invitations, system pairing) is
  authentication.

### Code in this change

- `todoke-proto::link`: `LinkAbilities`, `LinkOffer`, `LinkAnswer` with
  strict codecs (exact lengths and shapes, reserved bits, ranges,
  kind/security pairing, nonzero offer IDs), the credential in zeroizing
  memory and out of `Debug`, and `choose`. A fuzz target with seeds checks
  canonical re-encoding and that both ends agree.
- Frame types 0x0020 to 0x0022 are application frames. The transfer engine
  sets up no link: it takes one valid `LinkAbilities` per session and
  treats an offer or answer as STATE.
- `todoke-transport::capabilities` lists the LAN, Wi-Fi peer-to-peer,
  AWDL, and the relay; the binding's `LinkKind` is Wi-Fi peer-to-peer or
  AWDL.

## Consequences

- P18 to P20 build the Wi-Fi adapters against fixed rules; each needs
  device-lab evidence (T01) before it is on by default. The build plan's
  Bluetooth and USB items are dropped.
- Offline discovery between an Android and anything else, with no shared
  network and no internet, is not possible.
- Every faster link starts a new session and a new Accept, so a transfer
  that moves to Wi-Fi asks the receiver again (§5, §7.5).

## Residual risks

- **Setting up a link is visible nearby:** the random SSID or Wi-Fi Aware
  publish shows that a todoke link is being set up (nothing links it to a
  device or person).
- **System-level joins expose the joiner's operating system to the host's
  network** on platforms without app-scoped joins (an iPhone joining a
  hotspot, a PC joining a group): DHCP host names and operating-system
  services on that interface. The host is an authenticated contact, and
  the link lasts only for the transfer. Fix: app-scoped joins where
  platforms add them.
- **The contact Hello's cleartext generation** links a pair's sessions on
  any link (§16 O12). Fix: a wire-format revision.
- **Unconfirmed platform behavior** to settle in the device lab: whether
  iPhone ↔ iPhone and iPhone ↔ Android Wi-Fi Aware work for apps (Apple's
  page centres on accessories; its forums report Android failures), whether
  `NEHotspotConfiguration` joins WPA3-only networks, whether a Windows
  hotspot starts with no upstream connection, AWDL's link security, Wi-Fi
  Aware on macOS, and every link's throughput.
- **Relay-only remote transfers** keep ADR 0009's throughput limit (about 72
  Mbit/s at 50 ms) until a hole-punch revision.

## Main sources

- Core Bluetooth advertising (why BLE could not carry the records): https://developer.apple.com/documentation/corebluetooth/cbperipheralmanager/startadvertising(_:)
- Apple networking choices and peer-to-peer: https://developer.apple.com/documentation/technotes/tn3151-choosing-the-right-networking-api and https://developer.apple.com/documentation/technotes/tn3213-moving-from-multipeer-connectivity-to-network-framework
- Apple Wi-Fi Aware: https://developer.apple.com/documentation/wifiaware
- `NEHotspotConfiguration`: https://developer.apple.com/documentation/networkextension/nehotspotconfigurationmanager
- Android Wi-Fi Aware: https://developer.android.com/develop/connectivity/wifi/wifi-aware and https://developer.android.com/reference/android/net/wifi/aware/WifiAwareNetworkSpecifier.Builder
- Android Wi-Fi Direct: https://developer.android.com/reference/android/net/wifi/p2p/WifiP2pConfig.Builder
- Android LocalOnlyHotspot: https://developer.android.com/reference/android/net/wifi/WifiManager and https://developer.android.com/reference/android/net/wifi/SoftApConfiguration.Builder
- Android network requests: https://developer.android.com/develop/connectivity/wifi/wifi-bootstrap
- Windows Mobile Hotspot: https://learn.microsoft.com/en-us/uwp/api/windows.networking.networkoperators.networkoperatortetheringsessionaccesspointconfiguration
- NetworkManager: https://networkmanager.dev/docs/api/latest/settings-802-11-wireless-security.html
- QUIC and TLS: https://www.rfc-editor.org/rfc/rfc9001.html and https://docs.rs/quinn-proto/latest/quinn_proto/crypto/index.html
- quinn congestion control: https://docs.rs/quinn/latest/quinn/congestion/index.html
- Hole-punching privacy: https://www.rfc-editor.org/rfc/rfc8445.html and https://www.rfc-editor.org/rfc/rfc8828.html
- usbmux (unsupported per Apple DTS): https://developer.apple.com/forums/thread/658393
- Android foreground service types: https://developer.android.com/develop/background-work/services/fgs/service-types
- iOS continued processing: https://developer.apple.com/documentation/backgroundtasks/bgcontinuedprocessingtask
