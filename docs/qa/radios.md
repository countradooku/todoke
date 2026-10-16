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
| Android 16 | Linux | LocalOnlyHotspot | WPA3 transition | | | | | | | Only if Android 16 lets the app set the SSID and passphrase |
| Android 16 | Windows 11 | LocalOnlyHotspot | WPA3 transition | | | | | | | As above |
| Android | Android | Wi-Fi Aware | NCS-SK-128 | | | | | | | P19 |
| Android | iPhone | Wi-Fi Direct group | WPA2 | | | | | | | P20 |
| iPhone | Mac | AWDL | (system) | | | | | | | P20 |

Desktops host nothing yet (ADR 0018), so PC to iPhone and PC to PC have no
rows.

## Checks the lab settles

Each one may change what a platform offers; record the answer and the date.

- **Windows Wi-Fi Direct legacy access point:** on a client, `ipconfig
  /all` and the routing table. If it offers no default gateway and no DNS
  server, Windows may host Wi-Fi Direct groups (ADR 0018, residual risks).
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
