# ADR 0014: Local links (closing PROTOCOL §16 O7)

- **Status:** accepted on 2026-10-15. The maintainer delegated the decisions
  ("you decide the most secure and fastest option") and chose the free
  random 128-bit BLE UUID over a paid Bluetooth SIG 16-bit UUID.
- **Date:** 2026-10-15
- **Scope:** PROTOCOL §9.1 (BLE profile), §10 (relay-only non-local paths),
  §10.1 to §10.3 (direct IP links, link setup, platform requirements), §5
  (three new frame types), §13 (BLE and link-setup limits), §16 (O7
  resolved, O12 added). Specification only: the adapters are built in
  P18 to P20.

## Context

§16 O7 left open "what registered BLE service UUID/GATT allocation, mobile
permission/background behavior, AWDL/Wi-Fi P2P/USB packaging, and exact
direct-path QUIC/ALPN/hole-punch profile are deployable on each platform",
with every adapter disabled until then. The build plan's step 4 (P18
desktop radios and USB, P19 Android radios, P20 iOS radios) needs those
answers. The decisions below follow the maintainer's standing priority:
maximum security first, then performance. Platform facts come from primary
documentation (Apple, Android and AOSP, Microsoft Learn, the Bluetooth SIG,
BlueZ, wpa_supplicant, NetworkManager, IETF RFCs), read on 2026-10-15; the
main sources are listed at the end.

## Decisions

### Direct links are TCP with the unchanged session

Every direct link (LAN, Wi-Fi Aware, Wi-Fi Direct, hotspots, AWDL, Apple
Wi-Fi Aware, USB networking) carries the §4 prelude and §5 records over
TCP, exactly as the LAN does today.

- **Not QUIC.** QUIC is defined with TLS 1.3 (RFC 9001), and quinn's docs
  say other handshakes do not conform to QUIC v1. Between peers with no
  PKI, TLS would be unauthenticated and duplicate Noise, while adding a
  UDP listener, a QUIC/TLS state machine, and certificate parsing before
  authentication. §5 runs one ordered stream per session, so QUIC streams
  remove no head-of-line blocking, and QUIC migration conflicts with §5's
  fresh session per pipe. quinn's BBR is marked experimental. The LAN TCP
  path already measures about 540 MiB/s per session (bench/RESULTS.md).
- **One security stack.** Link-layer encryption (WPA3, Wi-Fi Aware NCS) is
  defense in depth; authentication and confidentiality come from the todoke
  handshake on every link.

### Non-local paths are relay-only in v1

Hole punching stays off: no candidates, Punch ignored, no observed
candidate from the relay (already ADR 0009's behavior, now normative).
Candidate exchange through the relay's cleartext control records would
show a device's addresses to the relay and the peer before
authentication, and STUN would show them to third parties (RFC 8445 §19,
RFC 8828). §10 lists what a later revision must do instead: candidates
only inside an authenticated session, the reflexive address only from the
chosen relay, user opt-in, respect for VPNs, the existing bounds.

### BLE: a random 128-bit service, records over GATT

- **What the platforms allow.** iOS and macOS apps can advertise only a
  local name and service UUIDs, never service data, and in the background
  the UUIDs move to an "overflow" area only iOS scanners see (Core
  Bluetooth `startAdvertising`). A legacy advertisement holds 31 bytes; a
  128-bit UUID with the 19-byte record as service data takes 37. Only a
  SIG-assigned 16-bit UUID ($3,750 once) fits the record in the
  advertisement (30 bytes, the Exposure Notification layout), and even then
  iPhones and Macs could not send it.
- **Decision.** The maintainer chose the free random 128-bit UUID. The
  advertisement carries only that UUID; a central connects and reads (or
  subscribes to) `paired_record` and `stranger_record`, the same records
  mDNS shows. The cost is a connection per nearby device instead of a
  passive scan. A 16-bit UUID can be added later if the device lab shows
  that cost matters.
- **Pipes.** An L2CAP connection-oriented channel where both sides support
  one (iOS 11+, macOS 10.14+, Android 10+, BlueZ), else a GATT pipe
  (write-without-response in, notifications out): Windows has no L2CAP
  channel API for apps, and Android 7 to 9 has none either. Both carry the
  plain §4/§5 byte stream; §5 already requires a reliable ordered stream.
- **No BLE pairing or bonding.** LE pairing without user confirmation gives
  no protection against an active attacker anyway, bonding stores an
  identity key that makes the device recognisable, and both bring system
  UI. todoke's handshake is the only authentication.
- **Privacy limits that stay.** The UUID marks a device as running todoke
  (as the mDNS service type does on a LAN). No platform lets an app change
  its address together with its payload (Exposure Notification did that
  inside the OS), so the private address and the record rotate on separate
  schedules; restarting advertising at each epoch boundary is a best effort.
  BlueZ ships with privacy off, so §9.1 requires it on.

### Wi-Fi links: set up inside an authenticated session

A session on any pipe, typically BLE, can move the devices to a faster
Wi-Fi link. The host generates the credential from a CSPRNG per offer (a
32-byte Wi-Fi Aware PMK, or a 63-character passphrase, about 378 bits) and
sends it in a `LinkOffer` inside the session; nothing is advertised. The
joiner answers, connects over the new link, and runs a fresh full
handshake; the old session closes and the transfer resumes with a fresh
Accept. Credentials are sent, not derived: Noise exposes no secret
exporter, and the handshake hash is not secret.

Which link, per pair (the order in §10.2 picks the first that fits):

| Devices | Link | Wi-Fi security | Notes |
| --- | --- | --- | --- |
| Android ↔ Android | Wi-Fi Aware data path with our PMK | NCS-SK-256 or 128 | No user prompt; Aware can be unavailable while a hotspot or Wi-Fi Direct runs |
| Android ↔ Android (fallback) | Wi-Fi Direct group, our SSID and passphrase | WPA3 (Android 16 R2/PCC modes) or WPA2 | The joiner connects with the credentials, so no WPS and no invitation dialog |
| Android ↔ iPhone, Mac, Windows, Linux | Android hosts a hotspot (LocalOnlyHotspot) | WPA3 transition by default | Android 16 lets the app set the passphrase; earlier, the system's (~75 bits) is sent inside the session. iOS asks the user once to join |
| iPhone ↔ iPhone | Apple Wi-Fi Aware (iOS 26, iPhone 12+) or AWDL | Wi-Fi Aware: system-managed; AWDL: undocumented | Wi-Fi Aware requires a one-time system pairing with a PIN; AWDL needs none |
| iPhone ↔ Mac, Mac ↔ Mac | AWDL | Undocumented | Discovery is the §9 mDNS service over peer-to-peer Wi-Fi |
| Windows or Linux ↔ iPhone | The PC hosts a hotspot (Windows 11 24H2 per-session Mobile Hotspot, Linux NetworkManager access point) | WPA3 transition | iOS asks once to join |
| PC ↔ PC | One hosts a hotspot, the other joins | WPA3 where both support it | Thunderbolt/USB4 networking needs no setup |

Apple's links need no todoke negotiation: AWDL carries mDNS, and Apple
Wi-Fi Aware connects devices the system paired. On Apple platforms they
need Network.framework listeners (a BSD socket listener is not reachable
over AWDL), feeding the same byte stream.

### USB: only links that are already IP

Android USB tethering (the user turns it on; apps cannot), USB4 and
Thunderbolt networking, and USB Ethernet adapters appear as ordinary
network interfaces with private or link-local addresses: §10.1 covers them
unchanged. Raw USB byte pipes stay off in v1:

- **iPhone usbmux.** The only way to reach an app on an iPhone over USB, and
  Apple DTS calls it unsupported; it needs the system's "Trust This
  Computer" grant, far broader than todoke needs.
- **Android Open Accessory.** Workable on Linux and macOS, but Windows needs
  a signed WinUSB driver package for Google's accessory IDs, and it is
  unconfirmed whether the handshake works while Windows binds the phone to
  its MTP driver. A later revision can enable it.

### Platform requirements

- Permissions: Android 12+ Bluetooth and Android 13+ `NEARBY_WIFI_DEVICES`
  with `neverForLocation`; location only where nothing else exists (older
  Android), never background location.
- Background: Android transfers in a `connectedDevice` foreground service
  started by the user (`dataSync` is capped at 6 hours a day from Android
  15); iOS in the foreground or a `BGContinuedProcessingTask` (iOS 26)
  started by the user. iOS background URLSession carries only HTTP, so it
  cannot carry a todoke session.
- No OS-level trust (bonding, invitations, USB trust) is authentication.

## Consequences

- P18 to P20 can build the adapters against fixed allocations; each needs
  device-lab evidence (T01) before it is on by default.
- Discovery over BLE costs a connection per nearby todoke device; between
  two backgrounded iPhones it depends on iOS's best-effort overflow area.
- Every faster link starts a new session and a new Accept, so a transfer
  that moves from BLE to Wi-Fi asks the receiver again (§5, §7.5).

## Residual risks

- **BLE address and payload rotate separately:** an observer can link the
  records a device shows across a record change while its private address
  stays the same (Android rotates it every 5 to 15 minutes). Fix: platform
  support for synchronised rotation; none exists for apps.
- **The UUID identifies todoke users nearby,** as the mDNS service type does
  on a LAN.
- **The contact Hello's cleartext generation** links a pair's sessions on
  any link (§16 O12). Fix: a wire-format revision.
- **Unconfirmed platform behavior** to settle in the device lab: iPhone ↔
  Android Wi-Fi Aware interoperability (Apple's forums report failures),
  whether `NEHotspotConfiguration` joins WPA3-only networks, whether a
  Windows hotspot starts with no upstream connection, AWDL's link security,
  Wi-Fi Aware on macOS, and every link's throughput.
- **Relay-only remote transfers** keep ADR 0009's throughput limit (about 72
  Mbit/s at 50 ms) until a hole-punch revision.

## Main sources

- Core Bluetooth advertising: https://developer.apple.com/documentation/corebluetooth/cbperipheralmanager/startadvertising(_:)
- Core Bluetooth background: https://developer.apple.com/library/archive/documentation/NetworkingInternetWeb/Conceptual/CoreBluetooth_concepts/CoreBluetoothBackgroundProcessingForIOSApps/PerformingTasksWhileYourAppIsInTheBackground.html
- L2CAP channels: https://developer.apple.com/documentation/corebluetooth/cbperipheralmanager/publishl2capchannel(withencryption:) and https://developer.android.com/reference/android/bluetooth/BluetoothDevice
- Bluetooth data types and fees: https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/CSS_v11/out/en/supplement-to-the-bluetooth-core-specification/data-types-specification.html and https://www.bluetooth.com/fee-schedule/
- Exposure Notification BLE spec: https://covid19-static.cdn-apple.com/applications/covid19/current/static/contact-tracing/pdf/ExposureNotification-BluetoothSpecificationv1.2.pdf
- Windows advertising: https://learn.microsoft.com/en-us/uwp/api/windows.devices.bluetooth.advertisement.bluetoothleadvertisementpublisher
- BlueZ privacy: https://git.kernel.org/pub/scm/bluetooth/bluez.git/plain/src/main.conf
- Apple networking choices and peer-to-peer: https://developer.apple.com/documentation/technotes/tn3151-choosing-the-right-networking-api and https://developer.apple.com/documentation/technotes/tn3213-moving-from-multipeer-connectivity-to-network-framework
- Apple Wi-Fi Aware: https://developer.apple.com/documentation/wifiaware
- Android Wi-Fi Aware: https://developer.android.com/develop/connectivity/wifi/wifi-aware and https://developer.android.com/reference/android/net/wifi/aware/WifiAwareNetworkSpecifier.Builder
- Android Wi-Fi Direct: https://developer.android.com/reference/android/net/wifi/p2p/WifiP2pConfig.Builder
- Android LocalOnlyHotspot: https://developer.android.com/reference/android/net/wifi/WifiManager and https://developer.android.com/reference/android/net/wifi/SoftApConfiguration.Builder
- Windows Mobile Hotspot: https://learn.microsoft.com/en-us/uwp/api/windows.networking.networkoperators.networkoperatortetheringsessionaccesspointconfiguration
- NetworkManager: https://networkmanager.dev/docs/api/latest/settings-802-11-wireless-security.html
- QUIC and TLS: https://www.rfc-editor.org/rfc/rfc9001.html and https://docs.rs/quinn-proto/latest/quinn_proto/crypto/index.html
- Hole-punching privacy: https://www.rfc-editor.org/rfc/rfc8445.html and https://www.rfc-editor.org/rfc/rfc8828.html
- usbmux: https://developer.apple.com/forums/thread/658393
- Android Open Accessory: https://source.android.com/docs/core/interaction/accessories/aoa
- Android tethering is a system API: https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/heads/main/Tethering/common/TetheringLib/src/android/net/TetheringManager.java
- USB4 networking: https://learn.microsoft.com/en-us/windows-hardware/design/component-guidelines/usb4-interdomain-connections
- Android foreground service types: https://developer.android.com/develop/background-work/services/fgs/service-types
- iOS continued processing: https://developer.apple.com/documentation/backgroundtasks/bgcontinuedprocessingtask
