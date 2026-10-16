# Direct links: device-lab matrix

The direct Wi-Fi links of PROTOCOL §10.2 on real devices. Automated tests
cover the protocol, the move between sessions, and the platform settings
as data ([ADR 0018](../adr/0018-desktop-links.md)); only real radios show
whether a link comes up, what the host's network offers, and how fast it
is. **Nothing below has been measured yet**: this file is the gate.

## How to run a row

1. Two devices, paired, on no shared network: each reaches the other only
   through a relay (`direct_links` is `from_relay`, the default).
2. Send a 2 GiB file (`dd if=/dev/urandom of=2g.bin bs=1M count=2048`) and
   accept it.
3. Record:
   - whether the session moved (`todoke contacts` shows "connected over a
     direct Wi-Fi link"; the desktop shows "Direct (Wi-Fi link)");
   - the seconds from accepting to the first byte over the link;
   - the throughput over the link (the transfer's bytes per second once it
     settles), and over the relay before;
   - that the receiver was asked once;
   - that the link is gone after the transfer (below).
4. Afterwards, on the joiner: no saved network (Linux: `nmcli connection`
   shows no "todoke direct link"; Windows: `netsh wlan show profiles`;
   Android and iOS: no saved or suggested network), and its usual network
   is back.

## Matrix

| Host | Joiner | Kind | Security | Moved | Time to link (s) | Link throughput (MB/s) | Relay throughput (MB/s) | Asked once | Torn down | Notes |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | --- | --- | --- |
| Android (Pixel) | Linux (Intel AX210) | Wi-Fi Direct group | WPA2 | | | | | | | |
| Android (Pixel) | Linux (MediaTek) | Wi-Fi Direct group | WPA2 | | | | | | | |
| Android (Samsung) | Windows 11 (Intel) | Wi-Fi Direct group | WPA2 | | | | | | | |
| Android (Samsung) | Windows 11 (Qualcomm) | Wi-Fi Direct group | WPA2 | | | | | | | |
| Android (Pixel) | Android (Samsung) | Wi-Fi Aware | NCS-SK-256 or -128 | | | | | | | No shared Wi-Fi; both Android 13+ with Aware |
| Android (Samsung) | Android (Pixel) | Wi-Fi Direct group | WPA2 | | | | | | | A device without Aware |
| Android 16 QPR2 | Linux | LocalOnlyHotspot | WPA3 transition | | | | | | | Only builds with the flagged API |
| Android 16 QPR2 | Windows 11 | LocalOnlyHotspot | WPA3 transition | | | | | | | As above |
| Android | iPhone | Wi-Fi Direct group | WPA2 | | | | | | | P20 (iPhone joins as a network) |
| Android 16 QPR2 | iPhone | LocalOnlyHotspot | WPA3 | | | | | | | P20 |
| Android | iPhone | Wi-Fi Aware | NCS-SK-128 | | | | | | | P20, iOS 26 |
| Windows 11 | Android | Wi-Fi Direct group (legacy AP) | WPA2 | | | | | | | ADR 0019 |
| Windows 11 | Linux | Wi-Fi Direct group (legacy AP) | WPA2 | | | | | | | |
| Windows 11 | Windows 11 | Wi-Fi Direct group (legacy AP) | WPA2 | | | | | | | |
| iPhone | Mac | AWDL | (system) | | | | | | | P20 |

Linux hosts nothing (ADR 0018), so Linux to Linux and Linux to iPhone have
no rows.

## Tap and point

| Check | Devices | Result | Notes |
| --- | --- | --- | --- |
| Tap-to-pair: one shows its QR code, the other on the scan screen taps it | Two Android phones | | Pairs once; reading again after leaving the QR screen gets nothing |
| Tap-to-pair with the phone locked | Two Android phones | | The tag must not answer (unlock required) |
| Tap-to-pair while another HCE app claims the NDEF application | Two Android phones | | todoke is the preferred service while its QR shows |
| Point to share: two contacts nearby, point at one | Three Android phones with UWB (play) | | The one pointed at comes first, within 20° |
| Pointing stops: close the sheet, leave the app, 120 s | Two Android phones with UWB | | Both stop ranging |
| Pointed at in the background | Two Android phones with UWB | | Refused: nothing ranges |

## Checks the lab settles

Each one may change what a platform offers; record the answer and the date.

- **Windows Wi-Fi Direct legacy access point** (it hosts since ADR 0019):
  on a client, `ipconfig /all` and the routing table (what its DHCP
  offers); that the SSID is exactly the offer's; that Windows asks no one
  before a legacy client joins; that nothing is routed (`route print`,
  ICS off).
- **Android Wi-Fi Aware hosting:** that `aware_data0` exists before any
  data path (`adb shell ip link`), and that a publisher's data path comes
  up on one of the interfaces the host named.
- **Android 16 QPR2 LocalOnlyHotspot:** whether
  `startLocalOnlyHotspotWithConfiguration` is present and keeps the name
  and passphrase given.
- **What Android hosts offer joiners:** a default route and DNS (expected:
  the host's own address for both). Confirm that the Linux joiner takes
  neither (`ip route`, `resolvectl status`) and what Windows takes.
- **macOS CoreWLAN:** after `associate(to:password:)`, whether the network
  appears in System Settings and the password in the keychain. If it can
  join without either, macOS can join.
- **Windows location consent (24H2 and later):** a join with location off
  for desktop apps: the error, and whether the UI says why.
- **WPA3:** that SAE is used where both sides report it (Linux: `iw dev
  <if> link`; Windows: `netsh wlan show interfaces`).
- **Teardown on failure:** stop the host mid-transfer; the joiner leaves
  the network and the devices continue over the relay.
- **Battery** (phones as hosts): the drain per gigabyte, against the relay.
