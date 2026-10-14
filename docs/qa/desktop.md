# Desktop app: manual checklist

The UI tests drive every flow against a mock core in GPUI's test platform
(`cargo test -p todoke-desktop`). This list covers what they cannot: real
windows, real platforms, real peers, and assistive technology. Run it on
macOS, Windows, and a Linux desktop (one Wayland and one X11 session)
before a release, and record the platform, build, and result of each item.

Build a development app (sessions are disabled in release builds, PROTOCOL
§16) and keep it away from your own profile:

```bash
cargo build --release -p todoke-desktop --features unaudited-dev
```

```bash
TODOKE_HOME="$(mktemp -d)" target/release/todoke-desktop
```

Use a second machine (or a second `TODOKE_HOME` with
`"lan": {"allow_loopback": true}` in its `config.json`) as the peer.

## Start and stop

- [ ] With no daemon running, the window opens and Settings → About says
      the window runs todoke; `todoke status` (same `TODOKE_HOME`) answers.
- [ ] With `todoke daemon run` already running, the window attaches: About
      says the daemon runs in the background, and quitting the window
      leaves the daemon running.
- [ ] `todoke daemon stop` while the window hosts the core: a banner says
      todoke was stopped; Start again restores it.
- [ ] A release build (no `unaudited-dev`) shows the sessions-disabled
      banner and does nothing on Send or Pair.
- [ ] Nothing freezes: drag the window and switch pages while a large
      folder is being hashed for an offer.

## Pairing

- [ ] Show QR code: the code is black on white in both themes, scans from a
      phone camera, and the countdown runs from 5:00; Stop withdraws it
      (the peer's paste then fails).
- [ ] Copy as text, paste on the peer (Paste QR text): both list each other
      in Contacts, and the QR offer is gone.
- [ ] Show code: ten digits in two groups of five; on the peer (same
      network) Enter code lists one nearby device, chosen already; a wrong
      code fails; five wrong codes end the offer; the right one pairs.
- [ ] Settings → Visibility → Everyone for 5 minutes opens Show code.
- [ ] No step asks to compare emoji or numbers (§3 has none).

## Home and sending

- [ ] Contacts show Nearby (green) on the same network, Through relay
      (amber) when connected through a relay, Offline otherwise.
- [ ] Hidden (Settings → Visibility): the peer stops seeing this device as
      nearby within a few seconds; this device can still send to it.
- [ ] Drag a file onto one contact: only that contact gets an offer.
- [ ] Select two contacts, drag a folder onto the drop zone: both get it.
- [ ] Drop with nothing selected and several contacts: a notice asks who
      to send to; nothing is sent.
- [ ] Choose files… (⌘O / Ctrl+O) opens the system picker for files and
      folders.
- [ ] Copy text and press ⌘⇧V / Ctrl+Shift+V: the peer is offered
      `Clipboard <date> <time>.txt` with the text; after it is received,
      `outbox/` under the state directory is empty again.
- [ ] Copy files in Finder / Explorer / the file manager, then Send
      clipboard: those files are offered.

## Receiving

- [ ] An offer opens the sheet over the window with "Verified contact",
      counts, total size, and kinds; it takes focus.
- [ ] Clicking Accept within the first moment does nothing; then it works.
- [ ] A file named with a right-to-left override shows the escaped
      `\u{202e}` instead of a reversed name; an `.exe` or `.sh` is flagged
      as a program even when its MIME type says otherwise.
- [ ] Choose…: tick some files, Accept n files; only those arrive.
- [ ] Decline: the peer sees it was declined.
- [ ] Escape hides the sheet; the Home badge still counts the offer; it is
      declined after 5 minutes.
- [ ] Two offers at once: after deciding the first, the second appears.

## Transfers

- [ ] Progress, speed, and time left update smoothly; the badge says
      Direct (LAN) or Through relay.
- [ ] Cancel on either side ends the transfer on both.
- [ ] Unplug the network mid-transfer: it shows Paused, and resumes (after
      accepting again) when the peer is back.

## History

- [ ] Finished transfers appear with direction, names, size, time (UTC),
      outcome, manifest hash, and receipt; Copy puts the full value on the
      clipboard; the sender's and receiver's receipt IDs match.
- [ ] Search by part of a name, a device fingerprint, a hash, or a state.
- [ ] Clear history needs a second click; afterwards `history.bin` is gone.
- [ ] Retention Off (Settings, Apply): no `history.bin` is written.

## Settings

- [ ] Changing Downloads, the LAN switch, relays (Import relay list…),
      presence, or retention shows the Apply bar; Discard reverts; Apply
      restarts todoke with the new `config.json` and transfers resume.
- [ ] A malformed relay list is refused with a reason.
- [ ] Theme System follows the OS appearance live; Light and Dark override
      it and persist across restarts.
- [ ] Contacts and devices lists every contact with both fingerprints.

## Keyboard

- [ ] ⌘1–⌘5 / Ctrl+1–5 switch pages; ⌘F / Ctrl+F searches history.
- [ ] Tab reaches the navigation, every contact, the drop zone, and every
      button with a visible focus ring; Space selects a contact; Return on
      the drop zone opens the picker.
- [ ] In the sheet, Tab cycles its buttons, ⌘↩ / Ctrl+Enter accepts all,
      Escape hides it.

## Screen readers

Check with VoiceOver (macOS), Narrator and NVDA (Windows), and Orca (Linux):

- [ ] Every control is announced with its label and role; contacts as
      checkboxes with their proximity and whether selected.
- [ ] The receive sheet is announced as a dialog with sender, counts, and
      kinds when it opens.
- [ ] Notices are announced (errors as alerts).
- [ ] The QR code is announced as a secret image without its contents; the
      pairing code is read digit by digit.
- [ ] Transfer rows announce progress, speed, time left, and route; history
      rows announce their outcome and receipt.

## Appearance and motion

- [ ] Light and dark match `docs/qa/screenshots/` (regenerate on macOS
      with `cargo run -p todoke-desktop --example screenshots --features
      mock`).
- [ ] With the system's reduce-motion setting on, the sheet appears without
      sliding and nothing pulses.
- [ ] On a 120 Hz display, scrolling history and the sheet's entrance are
      smooth (no dropped frames visible in the OS frame-rate overlay).
- [ ] The window keeps its layout at the minimum size (720 × 520) and at
      200% scaling.

## This computer (ADR 0011)

Use an installed package (not `cargo run`) for these, on each OS.

- [ ] Settings → Security names what keeps the storage key (Keychain or
      Secure Enclave, DPAPI or TPM, Secret Service); `todoke status` says
      the same. A profile from before this release migrates: the key file
      is gone afterwards and the history still opens.
- [ ] Launching the app again, or `todoke-desktop --send FILE`, brings the
      running window forward instead of opening a second one; `--send`
      opens "Send to…" with FILE listed.
- [ ] "Send to…": Send is disabled for a moment after it opens; Escape
      and Cancel send nothing; the receive sheet goes over it when an offer
      arrives, and Escape hides the sheet first.
- [ ] Tray / menu bar: Open, Send clipboard…, Quit work; closing the
      window keeps the tray item, and an offer then shows a system
      notification with no file name; clicking it shows the window with
      the sheet. On GNOME without the AppIndicator extension there is no
      tray item, and closing quits.
- [ ] Settings → This computer → Start todoke when you log in: after
      logging out and in, todoke runs with only the tray item (macOS: it
      is listed in System Settings → General → Login Items; Windows: in
      Task Manager → Startup apps; Flatpak: the desktop asked first).
- [ ] The global shortcut (⌃⌥⌘T, Ctrl+Alt+Shift+T) with text copied
      opens "Send to…" with its start shown; on Linux X11, with text
      selected (not copied), the selection is offered. On Wayland,
      switching it on asks the desktop.
- [ ] macOS: Finder → right-click files → Quick Actions → Send with todoke;
      selected text in TextEdit → Services → Send text with todoke; Share →
      todoke (signed builds only).
- [ ] Windows 11: right-click files → Send with todoke at the top of the
      menu (MSIX), and in Share; the zip install: Settings → This computer
      adds it under Show more options, and selecting several files gathers
      them in one "Send to…".
- [ ] Linux: Dolphin, Nemo, and Nautilus (Scripts with the AppImage, the
      menu itself with a package) send the selection; Flatpak: Open With →
      todoke.
- [ ] Nothing above asked for an administrator password (installing a
      system package aside).

