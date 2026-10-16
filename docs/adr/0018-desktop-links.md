# ADR 0018: Direct links on desktops

- **Status:** accepted on 2026-10-16. The design was delegated with the
  standing priority of maximum security first, then performance. Where the
  P18 build prompt and PROTOCOL differ, PROTOCOL wins (below).
- **Date:** 2026-10-16
- **Scope:**
  - `todoke-transfer`: link setup in the session (`LinkAbilities`,
    `LinkOffer`, `LinkAnswer`)
  - `todoke-core`: `link` (the `LinkPlatform` a platform implements,
    credentials, the `DirectLinks` policy), `Core::start_with_links`, and
    moving a session onto a link (`runtime/link.rs`)
  - `todoke-transport`: `LinkKind::Direct`, `LanListener::bind_direct`,
    `TcpConnector::connect_direct`
  - `todoke-sys-linux::wifi`, `todoke-sys-windows::wifi`, and the daemon's
    `links`
  - Supersedes ADR 0014's plan for PCs to host (below).

## Context

The P18 prompt asks for desktop radios and USB: Wi-Fi Direct, BLE, and a
Mobile Hotspot on Windows; AWDL, CoreBluetooth, and joining an Android
LocalOnlyHotspot on macOS; Wi-Fi Direct, BLE, and a hotspot on Linux;
iPhone usbmux and Android USB tethering; credentials exchanged only inside
an authenticated session; a capability probe with silent fallback. The
acceptance asks for a device-lab matrix of measured throughput
(`docs/qa/radios.md`) and automated tests with mocked operating-system
APIs.

PROTOCOL wins where they differ:

- **No Bluetooth and no USB** (§10.1, the O7 revision, the maintainer's
  decision of 2026-10-15): no BLE, no CoreBluetooth, no usbmux, no USB
  tethering adapter. An IP interface the operating system brings up over
  USB is part of the LAN, as any other.
- **§10.2 binds hosts and joiners:** credentials random per offer and only
  inside the session; joins only through app-scoped, temporary mechanisms
  (never a saved or suggested network, WPS, or an open network); a host
  that controls its access point offers no default route and no DNS and
  forwards nothing between the link and other networks.

What the platforms allow (sources below, checked on 2026-10-16):

| | Join a hosted network | Host |
| --- | --- | --- |
| Linux | NetworkManager in-memory connection (`volatile`, bound to the process), this user's only (no administrator) | Access point with DHCP only in `shared` mode, which always does NAT, forwarding, and a DNS server |
| Windows | Native Wifi temporary profile, never saved | Mobile Hotspot is Internet Connection Sharing (NAT, DNS proxy); the Wi-Fi Direct legacy access point forwards nothing, but what its DHCP offers (router, DNS) is undocumented |
| macOS | CoreWLAN joins, but by all evidence saves the network and its password, and removing them needs an administrator | No public API |

## Decisions

### Link setup in the session

The engine sequences and checks the records: abilities once each after
Capabilities; the choice made once (`todoke_proto::link::choose`); only the
chosen host offering, once, exactly the chosen kind with exactly the
security the choice gives, the strongest the joiner can join, so a weaker
offer is STATE and never reaches the joiner's operating system; only the
joiner answering, once. An endpoint that sent no abilities takes no part.

The core decides the rest:

- **Whether:** with a `LinkPlatform` and the `direct_links` policy: `off`,
  `from_relay` (the default: only to move a session off a relay, since
  devices that share a network have a direct path already and joining
  another network takes this one off its own), or `always`. Never from a
  session already on a direct link. A device whose platform can neither
  host nor join anything sends no abilities.
- **When:** the host brings the link up (off the core thread) only while a
  transfer this device's user started or accepted with the peer is
  pending or running; the joiner joins only for such a transfer, and
  otherwise declines.
- **Credentials:** from the system's CSPRNG for every offer, in the exact
  §10.2 shapes (`todoke-` and 16 hexadecimal digits for a hotspot;
  `DIRECT-xx-tdk-` and 16 digits for a Wi-Fi Direct group; 63 characters
  drawn uniformly from 64; a 32-byte PMK for Wi-Fi Aware), in zeroized
  buffers, never printed.
- **The move:** after `joined` both close the session (one session per
  pair, §4) and no other connection to the peer starts meanwhile. The
  joiner connects from its address on the link to the host's address
  there (sockets bound to the link's address); the host listens on its
  address on the link only and accepts one connection, from that
  contact, before the offer expires (60 seconds). The session runs again
  there with a full handshake, reported as `Route::Direct`.
- **Consent across the move:** §7.3 requires a fresh signed Accept on the
  new session "even if consent intent is retained locally". The core
  keeps, in memory and for the offer's life plus a minute, the selection
  this user accepted for each incoming transfer with that peer, and the
  fresh Accept repeats it without asking again. It is used once, only for
  the same transfer with the same selection, and never survives the core.
- **Teardown:** each side drops the link (leaving the network, removing
  the profile or connection) when the session on it ends, when the offer
  expires unanswered, when the join fails, or when the move fails; the
  devices then reconnect however they can and resume (§7.5).

### Desktop platforms

- **Linux joins** Wi-Fi Direct groups and hotspots through NetworkManager:
  an in-memory connection (`volatile`, `bind-activation` to this process),
  `permissions` for this user only (polkit's `settings.modify.own`, no
  administrator), no autoconnect, and from the host only an address: no
  default route, routes, or DNS (`never-default`, `ignore-auto-routes`,
  `ignore-auto-dns`). SAE where `wpa_supplicant` reports it (WPA3, PMF
  required), else WPA2-PSK; CCMP. The host's address is the DHCP router
  option, which Android's hosts set to themselves.
- **Windows joins** with a Native Wifi temporary profile, never saved: the
  SSID in hexadecimal and the passphrase checked to the §10.2 alphabet, so
  nothing reaches the profile's XML unescaped; `WPA3SAE` with transition
  mode off where the driver lists SAE, else `WPA2PSK`; AES; no 802.1X. Its
  address, the gateway (the host), and the interface index come from the
  IP Helper.
- **No desktop hosts.** Linux's access point with DHCP only exists with
  NAT, forwarding, and DNS; Windows' Mobile Hotspot is Internet Connection
  Sharing; the Wi-Fi Direct legacy access point (no forwarding) stays off
  until the device lab shows what its DHCP offers. This supersedes ADR
  0014's rows where a PC hosts for an iPhone or another PC: those pairs use
  the LAN or a relay.
- **macOS takes no part in §10.2** until a join that saves nothing is
  available: CoreWLAN's join keeps the network and password, which §10.2
  forbids, and removing them needs an administrator. macOS cannot host.
- **AWDL moves to P20.** Apple supports peer-to-peer Wi-Fi only through
  Network.framework (`includePeerToPeer`); from BSD sockets it needs a
  private option or a listener bound to `awdl0`, with discovery through
  `dns_sd` with `kDNSServiceFlagsIncludeP2P`. It serves Mac to iPhone and
  Mac to Mac; P20 builds both Apple sides together.
- **Capability probe:** at start, the daemon looks for a Wi-Fi device
  NetworkManager or Native Wifi manages and whether it supports SAE; with
  none, the core gets no platform and sends no abilities (silent
  fallback). A failed join answers `failed`; the session goes on.

### Testing

- The engine: a link chosen, offered, and answered; abilities once and only
  when ready; the smaller key hosting when both can; a weaker or other
  offer, a second offer, an answer to no offer, a second answer, and an
  offer to an endpoint that sent no abilities are STATE.
- The core, two cores with a platform that brings links up on loopback: a
  48 MiB transfer moves mid-way onto the link, the receiver is asked once,
  the file arrives intact, the route is `Direct`, and both links are torn
  down when the devices stop; a failed join answers `failed`, the host's
  link goes at once, and the transfer completes where it was.
- The credentials' shapes and uniformity; nothing secret printed.
- Transport: a direct link listens and connects on the link's address only,
  both ends are `Direct`, and the policy still applies.
- The platforms, without radios: the NetworkManager settings (unsaved,
  this user's, nothing taken from the host, the security asked) and the
  Windows profile (exact, inert, refusing a passphrase that could break
  out of the XML) are checked as data; the calls themselves are checked
  in the device lab (`docs/qa/radios.md`).

## Consequences

- Android hosts and desktops join: Android to Linux or Windows gets a
  direct link when they share no network. PC to iPhone and PC to PC do
  not; they use the LAN or a relay.
- Joining takes the desktop's Wi-Fi off its own network while the link is
  up (one radio). By default this happens only for sessions on a relay.
- The receiver is not asked again for a transfer that moves.

## Residual risks

- **No device lab yet:** nothing here ran against real radios; the matrix
  in `docs/qa/radios.md` is empty. Fix: run it on the lab devices before
  1.0.
- **Hosts on Android give a default route and DNS** (their DHCP server is
  the system's). Desktop joiners take neither (Linux: by setting; Windows
  cannot refuse them but leaves its own network meanwhile anyway). Fix: on
  Windows, raise the link's route metric or remove its default route after
  joining; record what Android hosts offer in the lab.
- **The PSK reaches NetworkManager's in-memory store** (`/run`, root only)
  for the connection's life. Fix: a secret agent with `psk-flags` set to
  agent-owned.
- **Windows may need location consent** for Wi-Fi APIs (24H2); the
  `WlanQueryInterface` state checks may then fail and the join time out.
  Fix: check `wiFiControl` access first and say why in the UI.
- **No PC hosts:** PC to iPhone and PC to PC have no direct link. Fix:
  host with the Wi-Fi Direct legacy access point on Windows once the lab
  shows its DHCP offers no router or DNS; on Linux, an access point with
  link-local addressing and no DHCP, if joiners can use it.
- **macOS joins nothing.** Fix: a join that saves no network (verify
  CoreWLAN's behaviour in the lab; or Network.framework when Apple adds
  one).
- **The host's link listener accepts the first connection only;** a
  device on the hosted network that is not the joiner could take it before
  the joiner (it would fail the handshake and the move would fail). Only
  the joiner has the credentials. Fix: none needed beyond that.

## Sources

- NetworkManager: https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.html, https://networkmanager.dev/docs/api/latest/settings-ipv4.html
- wpa_supplicant D-Bus: https://w1.fi/cgit/hostap/tree/doc/dbus.doxygen
- Native Wifi: https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ns-wlanapi-wlan_connection_parameters, https://learn.microsoft.com/en-us/windows/win32/nativewifi/wlan-profileschema-authencryption-security-element, https://learn.microsoft.com/en-us/windows/win32/nativewifi/wi-fi-access-location-changes
- Wi-Fi Direct legacy mode: https://learn.microsoft.com/en-us/samples/microsoft/windows-classic-samples/wifi-direct-legacy/
- Mobile Hotspot: https://learn.microsoft.com/en-us/uwp/api/windows.networking.networkoperators.networkoperatortetheringmanager
- CoreWLAN: https://developer.apple.com/documentation/corewlan/cwinterface/associate(to:password:), https://developer.apple.com/forums/thread/732431
- AWDL and Network.framework: https://developer.apple.com/documentation/technotes/tn3151-choosing-the-right-networking-api
- Android's DHCP for groups and hotspots: AOSP `packages/modules/Connectivity` `Tethering/src/android/net/ip/IpServer.java`
