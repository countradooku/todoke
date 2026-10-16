# ADR 0019: Radios on Android

- **Status:** accepted on 2026-10-16. The maintainer decided three points
  (below) and delegated the rest with the standing priority of maximum
  security first, then performance. Where the P19 build prompt and
  PROTOCOL differ, PROTOCOL wins.
- **Date:** 2026-10-16
- **Scope:**
  - `spec/PROTOCOL.md`: §3.1.1 (the NFC carrier), §10.2 (hosts forward
    nothing; Wi-Fi Direct is WPA2), §10.4 (pointing), §13 limits
  - `todoke-proto`: `nfc`, `ranging`; `todoke-transfer`: pointing in the
    session; `todoke-core`: `runtime/pointing.rs`, scoped hosting
  - `todoke-transport`: `LanListener::bind_direct_scoped`, `BindSocket`
  - `todoke-ffi`: `WifiLinks` (replacing `RadioLink`), `links.rs`,
    `NfcTag`, `Core::pair_scan_nfc`, the pointing calls and events
  - `apps/android`: `radio/`, the NFC and pointing screens, the
    permissions in Settings
  - `todoke-sys-windows::wifi_host` and the daemon's `links` (Windows
    hosts Wi-Fi Direct groups)
  - Amends ADR 0018 (Windows hosts) and ADR 0015 (Android 13 minimum).

## Context

The P19 prompt asks for Android links feeding the core through BoltFFI:
Wi-Fi Aware with data paths, Wi-Fi Direct, a LocalOnlyHotspot for iPhones
and Macs, BLE for blinded tokens and a Noise bootstrap over L2CAP, USB
tethering, NFC tap-to-pair, UWB point-to-share (Android to Android), a
permission UX that explains each permission once and degrades when one is
denied, and duty-cycled scanning that stops in the background unless a
transfer runs. The acceptance: the device-lab matrix, Android to Android
without shared Wi-Fi, and Android to iPhone over Wi-Fi Aware and a
hotspot.

PROTOCOL wins where they differ:

- **No Bluetooth and no USB** (§10.1, O7): no BLE advertising, scanning,
  or L2CAP. USB tethering is an IP interface like any other, part of the
  LAN; nothing is built for it.
- **Every link is set up inside an authenticated session** (§10.2), so
  nothing scans or advertises to find contacts: discovery stays §9's, and
  radios work only for a transfer the user started or accepted.

The maintainer decided:

1. **Hosts forward nothing.** A host may not forward between the link and
   other networks; a router or DNS offer it cannot avoid (Android's system
   DHCP for groups and hotspots, Windows' Wi-Fi Direct access point) is
   allowed, and joiners take neither where they can. So Android hosts
   Wi-Fi Direct groups and Windows may host through its Wi-Fi Direct
   legacy access point. (macOS joining stays on hold, ADR 0018.)
2. **NFC tap-to-pair:** add it, carrying the QR offer.
3. **UWB point-to-share:** build it.

On 2026-10-16 the maintainer also allowed raising the Android and iOS
minimums so that every supported device has the full feature set.

## Decisions

### Direct links (§10.2)

The core decides everything protocol-side; the app only brings links up
and down through `WifiLinks` (`abilities`, `host`, `join`, `bind_socket`,
`release`). `AppLinks` in `todoke-ffi` adapts it to the core's
`LinkPlatform`: it checks each lease (addresses that parse, a host address
for every join, real interfaces for a scoped host) and releases one the
core cannot use or no longer wants; dropping the core's lease releases the
app's, on a thread of its own (releasing calls into the app).

| Kind | Host | Join |
| --- | --- | --- |
| Wi-Fi Aware | Publish `todoke` with `offer_id[..8]`; a data path from any subscriber with the PMK (`WifiAwareNetworkSpecifier.Builder(PublishDiscoverySession)`) | Subscribe; a data path to each matching publisher once, NCS-SK-128 or NCS-SK-256 where the hardware lists it |
| Wi-Fi Direct | A group with exactly the offer's name and WPA2 passphrase, never persistent (`WifiP2pConfig.Builder`) | The same builder, as a client |
| Hotspot | A LocalOnlyHotspot with the offer's name and passphrase, from Android 16 QPR2 (`startLocalOnlyHotspotWithConfiguration`); none before (§10.2: a host that cannot choose them does not host) | `WifiNetworkSpecifier` without internet: the app's network, never saved or suggested |

- **Wi-Fi Direct groups are WPA2-PSK only** (a §10.2 change). The choice
  took the strongest security the joiner can join, and a weaker offer is
  a violation, but Android's groups and Windows' access point give WPA2
  only: every WPA3-capable joiner failed. WPA3 values now belong to
  hotspots; the session's encryption protects the data either way.
- **A Wi-Fi Aware host's address comes with the joiner.** The data path,
  and the publisher's address on it, exist only once the subscriber sets
  it up, after the offer. The host's lease gives `::` and the indexes of
  the Aware data interfaces (`aware_data0` to `3`, which exist while Aware
  is enabled); the core listens on every IPv6 address and accepts only
  link-local peers arriving on those interfaces, still under the LAN
  policy and only once per offer.
- **Sockets are bound to links that are networks of their own** (Aware
  data paths, joined hotspots): the core hands each socket's descriptor to
  `bind_socket` before it listens or connects, and the app calls
  `Network.bindSocket`. Wi-Fi Direct interfaces are not networks; the
  core binds to their address.
- **Secrets:** the passphrase or PMK reaches the app in the request's
  byte array, which is wiped once the platform has it.
- **Windows hosts Wi-Fi Direct groups** through the legacy access point
  (WinRT `WiFiDirectAdvertisementPublisher`): exactly the offer's name and
  WPA2 passphrase, not discoverable as a Wi-Fi Direct device, nothing
  routed or shared. Its address is the Wi-Fi Direct adapter that comes up
  with one. Linux still hosts nothing (its access point mode is NAT and
  DNS).

### When radios run

Only while one of the app's screens is started or the transfer service
runs (a transfer the user started or accepted): `abilities` is empty
otherwise, so the core sets up nothing. Nothing scans or advertises on its
own: the core's discovery is §9's, links exist only for transfers, NFC
reads only on the scan screen, and ranging only while pointing or while a
screen shows. This meets the prompt's battery requirement without a duty
cycle.

### Permissions

Android 13 or later: `NEARBY_WIFI_DEVICES` with `neverForLocation` for the
links (todoke never asks for location), `UWB_RANGING` for pointing (play
flavor), `NFC` (normal). Settings explains each once in a dialog before the
system asks; once refused, it offers the system settings instead. Without
one, its feature is off and transfers go over the LAN and the relay.

### NFC tap-to-pair (§3.1.1)

The displayer emulates a read-only NFC Forum Type 4 Tag (host card
emulation, AID `D2760000850101`, unlocked devices only) whose one NDEF
record carries the QR text; `todoke-proto`'s `Type4Tag` answers every
command in Rust, bounded by the file it reads; its capability container
keeps every field in the Type 4 Tag ranges readers check. It answers only
while the QR offer is on screen and unexpired: from the activity's resume
to its pause (the app is the preferred service meanwhile); otherwise "not
found". The scanner reads in reader mode on
the scan screen and passes the NDEF message to `Core::pair_scan_nfc`,
which checks it (`pairing_text`) before pairing exactly as from a scanned
QR code.

### Pointing (§10.4)

On Android a UWB address serves one ranging session
(`androidx.core.uwb`: "a local address can only be used for a single
ranging session"), so the protocol carries addresses per ranging: the
controlee answers each `RangingStart` with `RangingAccept` (0x0026) and a
fresh address; `RangingReady` says only which configurations it can
range with. Each side starts at most eight rangings per session. Records
cross on the wire, so an accept or stop for a ranging that ended here is
ignored, a new start from the controller replaces its ranging, and when
both sides start at once the larger session ID stands on both (an R1
finding: these crossings failed the whole session, and any transfer in
it). Pointing passes the core a pool of up to four controller
sessions (one per contact ranged); the core makes each ranging's session
ID and provisioned STS key (FiRa unicast DS-TWR). The app ranks the
contacts by how straight ahead each is; choosing one opens the file
picker for it. Ranging is a hint for the screen only.

`androidx.core.uwb` depends on Google Play services, so pointing is in
the play flavor only; the F-Droid flavor stays free of proprietary code
and has no pointing.

### Minimums

Android 13 (API 33) and iOS 26. Android 13 has every radio API used here
and the nearby-devices permission; only the LocalOnlyHotspot with chosen
credentials needs Android 16 QPR2, and Wi-Fi Direct groups serve the same
joiners before it. iOS 26 is the first with Wi-Fi Aware, Liquid Glass,
and the continued-processing background task the app already used behind
availability checks. The Rust Swift package keeps its iOS 17 floor (the
app links it unchanged; its macOS tests run on CI's macOS 15).

### Testing

- Proto: the pointing records and the NFC tag, exact layouts and every
  limit, fuzzed (`proto_ranging_records`, `proto_nfc_tag`).
- Engine: rangings started, accepted once at the controlee's own address,
  stopped, and expired; every out-of-line record STATE or MALFORMED.
- Core: two cores point and range (pool, accept, refusal, re-pointing),
  parameters checked; Wi-Fi Direct choices are WPA2.
- Transport: a scoped listener takes only link-local peers on its
  interfaces.
- FFI (Rust, Kotlin, Swift): the links adapter (leases checked, released
  when dropped or unusable, sockets bound through the app); NFC pairing
  between two cores through the tag; pointing between two cores; the
  `ffi_commands` fuzz target drives pointing and NFC.
- Android, on emulators: tap-to-pair between two real cores through the
  tag service; pointing with a scripted core and UWB; links taking no
  part without a reason, and wiping secrets. Real radios are the lab's
  (`docs/qa/radios.md`).

## Consequences

- Android to Android without shared Wi-Fi: a Wi-Fi Aware data path, else
  a Wi-Fi Direct group, once a relay session exists.
- Android to iPhone: an Android Wi-Fi Direct group joined as a network,
  or a LocalOnlyHotspot on Android 16 QPR2 (P20 builds the iPhone side);
  Wi-Fi Aware once iOS joins Android's publishers (P20).
- PC to Android and PC to PC: a Windows-hosted Wi-Fi Direct group.
- Devices on Android 12 or older, and iPhones before iOS 26, no longer
  run todoke.

## Residual risks

- **No device lab yet.** Nothing here ran on real radios: Aware data
  paths, groups, hotspots, HCE, and UWB are unmeasured. Fix: run
  `docs/qa/radios.md` before 1.0.
- **Secrets cross BoltFFI into the JVM** (§16 O5 stays open): the link
  passphrase or PMK (wiped in Rust's `LinkRequest` when it goes, and in
  the app's byte array once handed over, but BoltFFI's own buffers are
  not, and Android's builders take
  the passphrase as a `String`, which cannot be wiped), the STS key in
  `PointTarget` and `RangingRequested` (copied into every subscriber's
  event queue, not zeroized there, and kept in core events as hex text),
  and the QR text in the tag's responses and the NDEF message read. Fix:
  zeroizing event queues; a one-shot secret handle that the app passes to
  the platform without a `String`, where the platform allows.
- **Windows: the passphrase passes through `HSTRING`s** (WinRT), not
  zeroized. Fix: none in WinRT; keep the copies short-lived.
- **A scoped Aware host accepts any link-local peer on the Aware data
  interfaces,** including another app's data path sharing one; such a
  peer would fail the handshake, but could take the offer's one
  connection and fail the move (it falls back to the relay). It also
  relies on `aware_data*` existing before the data path; where they do
  not, Aware hosting is off. Fix: confirm in the lab; if needed, ask the
  app for the data path's interface at accept time.
- **Wi-Fi Direct is WPA2 only** at the link layer. Fix: WPA3 groups (Wi-Fi
  Direct R2) once Android and Windows expose them, with a host-security
  field in `LinkAbilities`.
- **Joining a hotspot shows Android's approval dialog** each time
  (`WifiNetworkSpecifier`). Fix: none (platform).
- **The LocalOnlyHotspot with chosen credentials is a flagged API** on
  Android 16 QPR2: a release without the flag fails the host (the core
  backs off). Fix: confirm in the lab which builds have it.
- **Windows' access point:** what its DHCP offers joiners, whether Windows
  asks the user before a legacy client joins, and whether it keeps the
  SSID exactly as given are unverified. Fix: the lab checks in
  `docs/qa/radios.md`.
- **The NDEF application ID is shared:** another app registered for
  `D2760000850101` could be routed instead while todoke is not the
  preferred service (then the reader gets that app's tag and pairing
  fails, never succeeds with the wrong device). Fix: none needed.
- **Pointing ranges with at most four contacts at once** and needs the
  play flavor. Fix: a larger pool if the lab shows the chips allow it.
- **The core asks the app for its abilities on its own thread** (once per
  session that can set up a link, several binder calls on Android) and
  binds sockets there through JNI: short stalls of the core loop. Fix: ask
  off the thread (`spawn_blocking`) and cache for a few seconds.
- **Windows finds the group's adapter by its description** ("Wi-Fi
  Direct"); a driver with another description makes hosting time out.
  Fix: the lab check; else match the adapter that appears after the
  start by interface type alone.

## Sources

- Wi-Fi Aware: https://developer.android.com/develop/connectivity/wifi/wifi-aware, `WifiAwareNetworkSpecifier.Builder` (SDK 36.1 sources)
- Wi-Fi Direct with a configuration: https://developer.android.com/reference/android/net/wifi/p2p/WifiP2pConfig.Builder
- `WifiNetworkSpecifier`: https://developer.android.com/develop/connectivity/wifi/wifi-bootstrap
- LocalOnlyHotspot with a configuration: `WifiManager.startLocalOnlyHotspotWithConfiguration`, `SoftApConfiguration.Builder` (SDK 36.1 sources)
- Nearby Wi-Fi devices permission: https://developer.android.com/develop/connectivity/wifi/wifi-permissions
- Host card emulation: https://developer.android.com/develop/connectivity/nfc/hce
- NFC Forum Type 4 Tag and NDEF: NFC Forum T4T 1.2, NDEF 1.0
- `androidx.core.uwb` 1.0.0 sources (`UwbClientSessionScope.localAddress`, `RangingParameters`)
- Windows Wi-Fi Direct legacy mode: https://learn.microsoft.com/en-us/uwp/api/windows.devices.wifidirect.wifidirectlegacysettings
