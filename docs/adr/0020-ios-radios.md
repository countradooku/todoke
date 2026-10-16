# ADR 0020: Radios on iOS (and Apple peer-to-peer Wi-Fi)

- **Status:** accepted on 2026-10-16. The design was delegated with the
  standing priority of maximum security first, then performance. Where the
  P20 build prompt and PROTOCOL differ, PROTOCOL wins (below). Apple's
  current APIs and entitlements were checked against Apple's documentation,
  its developer forums, WWDC25 session 228, and the iOS 27.1 SDK before any
  code (sources below).
- **Date:** 2026-10-16
- **Scope:**
  - `spec/PROTOCOL.md` §10.4: Apple peer ranging (configuration bit 1,
    `PeerRangingStart` 0x0027, `PeerRangingAccept` 0x0028)
  - `todoke-sys-macos`: `p2p` (TCP over Apple peer-to-peer Wi-Fi through
    Network.framework), `route` (a joined network's gateway), `bonjour`
    (peer-to-peer browsing and advertising)
  - `todoke-transport`: bridged LAN links, peer-to-peer connecting and
    accepting; `todoke-discovery` and `todoke-core`: Bonjour on macOS too,
    the peer-to-peer listener and port
  - `todoke-proto`, `todoke-transfer`, `todoke-core`, `todoke-ffi`: peer
    ranging
  - `apps/ios`: `AppleLinks` (joining hotspots and groups), `Pointing`
    (Nearby Interaction) and the Point sheet

## Context

The P20 prompt asks for iOS links feeding the core: AWDL through
Network.framework for iPhone to iPhone and iPhone to Mac; the Wi-Fi Aware
framework (iOS 26) for iPhone to Android; joining Android or PC hotspots
with NEHotspotConfiguration and credentials received inside Noise; usbmux
for wired PC transfers; CoreBluetooth for blinded tokens and a Noise
bootstrap; UWB point-to-share with Nearby Interaction, iPhone to iPhone.
The acceptance: iPhone to Android with no shared network on supported
devices, documented behaviour in the background, and lab throughput.

PROTOCOL wins where they differ: **no Bluetooth and no USB** (§10.1, O7),
so no CoreBluetooth and no usbmux; a USB network interface the system
brings up is part of the LAN.

What Apple allows (sources below):

- **Peer-to-peer Wi-Fi (AWDL)** is supported only through Network.framework
  (TN3151; Apple: "there is no way to set up a listener that supports
  peer-to-peer Wi-Fi using low-level APIs like BSD Sockets").
- **Wi-Fi Aware** connects only devices the system paired (DeviceDiscoveryUI
  or AccessorySetupKit, a six-digit PIN, NAN pairing with PASN), carries
  data only through Network.framework (BSD sockets fail), takes no
  app-supplied key, and needs the `com.apple.developer.wifi-aware`
  entitlement, which may be a managed capability. Interoperability with
  Android is claimed but unproven: it needs Android's Aware pairing
  (Android 14 and later, and few phones report it), and developers report
  iOS not answering Android's data-path requests (open Apple bugs).
- **NEHotspotConfiguration** with `joinOnce` never saves the network, asks
  the user, and removes the network 15 seconds after the app leaves the
  foreground, when the device sleeps, or when released. Its initializer is
  documented for WPA/WPA2; WPA3 is undocumented.
- **Nearby Interaction** ranges iPhone to iPhone with per-session discovery
  tokens exchanged out of band (no FiRa addresses or keys), in the
  foreground only (suspended in the background); ranging with Android needs
  Apple's accessory protocol, which ordinary Android apps do not implement.

## Decisions

### iPhone to Android and PCs: joining their networks

`AppleLinks` (the app's `WifiLinks`) joins a Wi-Fi Direct group (Android,
Windows) or a hotspot (Android 16 QPR2) with exactly the offer's
credentials: NEHotspotConfiguration, `joinOnce`, never saved, the system
asking the user; the link waits until that network is current and Wi-Fi
has its address. iOS hosts nothing (no API runs a hotspot or group). The
network has no internet, so cellular stays the default route: the core's
sockets for the link are bound to Wi-Fi (`IP_BOUND_IF`), and the host's
address is the Wi-Fi interface's default gateway, which the core reads
from the routing table (`todoke-sys-macos::route`; iOS has no API naming a
joined network's router). It announces WPA3 transition and WPA2 (a
transition network takes WPA2 too; WPA3-only joins are undocumented).
Entitlements: Hotspot Configuration and Access Wi-Fi Information (to read
the current network's name, for networks this app configured).

This is the iPhone-to-Android path with no shared network: Android hosts
Wi-Fi Direct groups on every supported release (ADR 0019).

### Apple peer-to-peer Wi-Fi (AWDL): iPhone to iPhone and to Mac

§10.1 already makes AWDL a LAN: §9 discovery over peer-to-peer Wi-Fi, the
same TCP and session. Because only Network.framework reaches it, the core
does it in Rust on every Apple platform, the macOS daemon and desktop app
included:

- `todoke-sys-macos::p2p` makes and accepts TCP connections with
  Network.framework's C API (peer-to-peer included) and bridges each to a
  local socket pair the transport reads as a LAN link (`TcpLink`), with
  backpressure both ways and end of stream as FIN. Nothing waits on a
  connection's dispatch queue: a writer thread writes what arrives to the
  pair and only then receives again, a sender thread sends what the pair
  holds one buffer at a time. The link owns its connection: dropping it
  cancels the connection once the last bytes are sent (at most 10 seconds
  later), so a peer that goes quiet keeps nothing. Network.framework is
  loaded at runtime (`dlopen`), so no consumer of the static library has to
  link it.
- The LAN listener also accepts peer-to-peer connections on a port of its
  own; the TCP connector reaches link-local addresses scoped to a
  peer-to-peer interface (`awdl*`, `llw*`) through Network.framework. The
  LAN policy checks every remote address, both ways; an incoming connection
  from a source it refuses is cancelled before it gets a thread, and at
  most 16 get ready at once.
- Discovery on Apple platforms is the system's Bonjour (macOS too, from
  `mdns-sd` before: only Bonjour reaches peer-to-peer Wi-Fi). Browsing,
  resolving, and lookups include peer-to-peer; on peer-to-peer interfaces
  the same §9 instances and label host records go out with the
  peer-to-peer listener's port.

### Wi-Fi Aware on iPhone: not now

Not built: the system pairing it requires is a second, PIN-based pairing
outside todoke's own (§10.3 takes no operating-system pairing as
authentication, but would have to put up with it), the data path is
Network.framework only and keyed by the system, the entitlement may need
Apple's approval, and Android interoperability is unproven with open
Apple bugs. iPhone to Android goes through Android's groups instead.
Revisit when Apple documents Android interoperability or app-keyed data
paths (residual risks).

### Point to share between iPhones

§10.4 gains configuration bit 1 and two records carrying each side's
archived `NIDiscoveryToken` (1 to 1024 bytes); they share every rule of the
FiRa records (eight starts per side, one ranging at a time, the crossing
rules, `RangingStop`). The iPhone is pointable while the app is on screen
and the device measures precise distance; pointing prepares up to four
`NISession`s (each token serves one contact), and a contact that points
gets a fresh session per ranging. The Point sheet ranks contacts by how
straight ahead each is; choosing one opens the file picker. No token is
logged (the core redacts them in every printout) or kept once its ranging
ends. iPhone to Android ranging is not offered (it needs Apple's accessory
protocol).

### Behaviour in the background

- **No new link and no pointing** once the app leaves the screen: links are
  offered only while it shows, and the app stops being pointable.
- **A joined network goes 15 seconds after the app leaves the screen**
  (`joinOnce`). A transfer the user started keeps running in a
  continued-processing task (ADR 0017), but over its link only for those
  seconds: when the network goes, the session ends and the transfer resumes
  over the relay or the LAN with a fresh Accept (§7.5), as for any broken
  link.
- **AWDL connections** run while the process does (in a
  continued-processing task too); otherwise iOS suspends the app and they
  end, and the core's background mode advertises nothing (§10.3).
- **Nearby Interaction sessions** are suspended by iOS in the background
  and invalidated by the app.

### Testing

- `todoke-sys-macos`: the Network.framework bridge over loopback (bytes both
  ways across chunks, a megabyte each way at once with nobody reading, FIN
  both ways, a dropped end freeing its pump while the peer is quiet or
  still sending, refusals failing at once, accept timeouts, sources not
  admitted, a full backlog, sockaddr conversions, runtime loading); the
  routing table read (synthetic tables, the real one).
- Transport: a peer-to-peer listener's bridged links are LAN links; the
  policy still refuses sources.
- The FFI adapter fills a join's host from the gateway.
- Peer ranging in proto, engine (including an accept of the other kind and
  tokens out of bounds), core, and FFI; the record fuzzed.
- The iOS app's unit and UI tests on iOS 26, `Pointing` against the
  scripted core (not pointable without precise distance, a contact refused
  or answered, readiness and pointing ending off screen). Radios themselves (AWDL,
  joining, Nearby Interaction) need devices: `docs/qa/radios.md`.

## Consequences

- iPhone to Android with no shared network: an Android Wi-Fi Direct group
  (or LocalOnlyHotspot) joined by the iPhone.
- iPhone to iPhone and iPhone to Mac: AWDL, as LAN; Mac to Mac too.
- iPhone to Windows: a Windows Wi-Fi Direct group joined by the iPhone.
- iPhone to Linux: no direct link (Linux hosts nothing).
- macOS discovers through Bonjour like iOS.

## Residual risks

- **No device lab yet:** AWDL between devices, the joins, and Nearby
  Interaction are unmeasured; the bridge is tested over loopback only.
  Fix: `docs/qa/radios.md` before 1.0.
- **Peer-to-peer interfaces are recognized by name** (`awdl*`, `llw*`),
  which is not API. Fix: confirm in the lab; Apple's resolve callbacks
  report the interface, which could be kept with each address instead.
- **An incoming AWDL connection's address may come without its scope**
  (unverified: loopback tests carry none). A link-local source the policy
  cannot place would be refused. Fix: check in the lab; if so, scope it
  with the connection's path interface before the policy check.
- **The peer-to-peer listener listens on every interface** (Network.framework
  has no peer-to-peer-only listener), so its port also answers on the LAN,
  under the same policy (checked before any thread), the 16 at once, and
  the handshake. Fix: none needed beyond these; no switch to turn it off,
  since the same policy already guards the LAN port.
- **Each bridged connection costs two threads** while it lives (and one
  while it gets ready). The session layer bounds unauthenticated
  connections (§13). Fix: an event-driven pump if the lab shows thread
  pressure.
- **A dropped connection can linger up to 10 seconds** sending its last
  bytes to a peer that does not read them. Fix: none needed (bounded).
- **The bridge copies every byte through a socket pair** (and a dispatch
  data buffer): more CPU than direct TCP. Fix: measure AWDL throughput in
  the lab; a zero-copy path if it is the bottleneck.
- **The joined network's gateway comes from the routing table;** a network
  whose DHCP names no router leaves the join without a host address (the
  join fails). Fix: none needed for Android and Windows hosts, which name
  themselves.
- **A joined network outlives a background transfer by 15 seconds only**
  (`joinOnce`); the transfer continues elsewhere. Fix: none in the
  platform.
- **WPA3-only networks are not joined** (undocumented for
  NEHotspotConfiguration). Fix: test on devices; announce WPA3 if it works.
- **No Wi-Fi Aware on iPhone** (above). Fix: when Apple documents
  interoperable, app-keyed data paths, or Android pairing proves
  interoperable.
- **Discovery tokens cross the FFI as bytes** and sit in event queues
  unzeroized, like the STS keys (ADR 0019). Fix: as there.
- **Pointing's ranging with Nearby Interaction is untested off devices:**
  the simulator gives tokens but ranges with nothing, so suspension,
  invalidation, and a peer leaving are handled but unexercised. Fix:
  `docs/qa/radios.md`.

## Sources

- TN3151, Choosing the right networking API: https://developer.apple.com/documentation/technotes/tn3151-choosing-the-right-networking-api
- Peer-to-peer listeners and BSD sockets: https://developer.apple.com/forums/thread/104061, https://developer.apple.com/forums/thread/737743
- `kDNSServiceFlagsIncludeP2P`, `kDNSServiceInterfaceIndexP2P`: https://developer.apple.com/documentation/dnssd/kdnsserviceinterfaceindexp2p
- Wi-Fi Aware: https://developer.apple.com/documentation/wifiaware, https://developer.apple.com/documentation/wifiaware/adopting-wi-fi-aware, https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.wifi-aware, https://developer.apple.com/videos/play/wwdc2025/228/, https://developer.apple.com/forums/thread/791628, https://developer.apple.com/forums/thread/838513, https://developer.apple.com/forums/thread/796446
- Accessory Design Guidelines (Wi-Fi Aware peers): https://developer.apple.com/accessories/Accessory-Design-Guidelines.pdf
- NEHotspotConfiguration: https://developer.apple.com/documentation/networkextension/nehotspotconfiguration/joinonce, https://developer.apple.com/documentation/networkextension/nehotspotconfigurationmanager, https://developer.apple.com/forums/thread/712896
- Nearby Interaction: https://developer.apple.com/documentation/nearbyinteraction/ninearbypeerconfiguration/init(peertoken:), https://developer.apple.com/documentation/nearbyinteraction/nisession/discoverytoken, https://developer.apple.com/nearby-interaction/
- Continued processing: https://developer.apple.com/documentation/backgroundtasks/bgcontinuedprocessingtask
