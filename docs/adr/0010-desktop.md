# ADR 0010: The desktop app

- **Status:** accepted on 2026-10-14. The maintainer chose the toolkit
  ("use gpui-kit") and delegated the rest of the design with the standing
  priority of maximum security first, then performance. Where the P12 build
  prompt and PROTOCOL differ, PROTOCOL wins (below).
- **Date:** 2026-10-14
- **Scope:**
  - `todoke-desktop` (the window, its model, and its tests)
  - additions to `todoke-core` (history, hidden mode, routes, MIME types,
    `escape`), `todoke-transfer` (manifest hash and receipt in events),
    `todoke-daemon` (`host`), and `todoke-cli` (`history`, `visibility`)
  - `deny-desktop.toml`, the supply-chain store, the MSRV (1.95)

## Context

The P12 prompt asks for a GPUI desktop app on macOS, Windows, and Linux
that uses only the core, with:

- Home (contacts with proximity, a drop zone, recent transfers), Send (drag
  onto a contact, several at once, clipboard and text), a receive sheet
  (Verified seal, counts, sizes, types, Accept all / Choose / Decline), a
  transfer view (progress, speed, time left, transport), pairing (QR, code,
  "emoji verification"), searchable history with hashes, receipts, and
  auto-expiry, and settings (visibility "contacts / everyone 10 min /
  hidden", receiving, connections, security, contacts and devices, about);
- 120 fps animations, keyboard-first navigation, full screen-reader labels,
  light and dark themes, nothing blocking the UI thread, state driven by the
  core's event stream, and design tokens in one module;
- UI tests of every flow against a mock core, a manual checklist, and
  screenshots of every screen in both themes.

PROTOCOL fixes what pairing verifies (§3: a one-time QR secret, or a
ten-digit code run through CPace; no comparison step), stranger mode (§9:
explicit, 300 seconds, no identity), consent (§7.2: only the user's
decision, after the complete manifest; nothing before it), that names and
MIME types are untrusted claims that grant nothing (§7.1), and that receipt
retention is local policy (§7.7).

## Decisions

1. **gpui-kit 0.7.3** (the maintainer's choice): GPUI as the `gpui-pre`
   0.3.9 snapshot it pins, its platform layer with runtime-compiled
   shaders, and the styled components. Only the default features
   (components and the component icon set); no tree-sitter, speech,
   inspector, or JavaScript runtime. GPUI needs Rust 1.95
   (`std::hint::cold_path`), so the workspace MSRV rises from 1.94.
2. **One core per user, wherever it runs.** The app attaches to a daemon
   already serving the IPC endpoint (started at login, say); otherwise it
   hosts the daemon itself (`todoke_daemon::host`): the core, served on the
   same endpoint from a thread of its own, so `todoke` commands and
   notifiers reach it while the window is open. A second core can never
   open the profile (the endpoint and the quarantine lock both refuse).
   - `todoke daemon stop` stops a hosted core's endpoint; the window then
     lets the core go (stopping it, off the UI thread), says todoke
     stopped, and offers to start again. Starting again first releases any
     core the window still holds: it holds the profile.
   - In attached mode requests go over a small pool of connections, so a
     slow request (an offer of a large folder is hashed first) never holds
     up the rest. A pooled connection idle for 60 seconds is dropped
     unused: the daemon closes idle connections after two minutes, and a
     request (an offer is not idempotent) must never be sent twice. Only
     the end of the daemon's event stream means it is gone; a request that
     fails is reported as unanswered (it may have been carried out).
   - Release builds (sessions disabled, §16) start, say so in a banner, and
     can still attach to a development daemon.
3. **The window is only a client of the core.** Every action is a
   `Request`; every change comes from an answer or an `Event`
   (`model.rs`, pure and unit-tested). Proximity and progress carry no
   event, so contacts, transfers, and status are fetched every two seconds
   (cheap channel requests). A subscriber that falls behind is told how
   many events it missed and fetches everything again. Nothing blocks the
   UI thread: requests are futures over executor-agnostic channels;
   profile, configuration, outbox, and preference I/O run on the
   background executor, and so does dropping a core (it joins threads).
4. **What the core gained for the screens**, all behind its API:
   - `ContactInfo.route` (LAN or relay) for the open session: proximity
     and the transport badge.
   - `Request::SetHidden` and the `hidden` setting: no paired LAN
     advertisement and no relay presence; sends still reach contacts, and
     pairing still advertises in stranger mode while an offer is shown.
   - A **history** of finished transfers, sealed under the storage key in
     `history.bin` (atomic replacement), for `history_days` (default 30,
     at most 3650, 0 keeps none and deletes the file): direction, peer,
     outcome, counts, the first eight top-level names, the manifest hash,
     and the signed receipt's ID and time on both sides (the engine now
     reports the manifest hash and the receiver's own receipt). At most
     2000 entries. `Request::History`, `Request::ClearHistory`; the CLI's
     `todoke history [--clear]`.
   - `EntryInfo.mime`, the sender's claimed type, for the sheet's summary.
   - `escape`, moved from the CLI into `todoke_core::api`, so every
     interface shows peer-chosen names the same way.
5. **PROTOCOL over the prompt:**
   - **No emoji verification.** §3 has no comparison step: a QR code
     carries a one-time 256-bit secret; a code runs CPace, which a wrong
     guess fails (five tries per offer). Inventing a SAS would be a second,
     unspecified protocol.
   - **"Everyone for 10 minutes" is stranger mode, 300 seconds,** and it
     exists only to pair (§9): choosing it shows a pairing code. Contacts
     (the default) and Hidden are the other choices.
   - **"Scan" on a computer is pasting the QR text** (a masked field);
     the shown QR can be copied as text for a device without a camera.
   - **History is local policy** (§7.7): sealed, retained as configured,
     clearable; no export.
6. **The decision is the user's, made deliberately.**
   - The sender's seal reads "Verified contact": only paired contacts can
     offer, and the session authenticated this one. Nothing else is
     claimed.
   - Names are escaped (`invoice\u{202e}fdp.exe` stays visibly odd), and
     the extension is drawn apart from the rest of the name, so shortening
     a long name never hides it. Programs, scripts, script-host files,
     HTML and SVG, and macro-enabled documents are flagged by extension or
     by claimed MIME type; MIME types otherwise only label.
   - Decline, Choose, and Accept stay disabled for 700 ms after an offer
     appears, so a click or key press aimed at what was there before cannot
     accept it. The delay belongs to the offer shown: each change of offer
     starts a new generation, and a timer from an earlier one arms nothing
     (a sender cannot time a second offer into the first one's delay). The
     sheet takes focus as a dialog; Escape hides it (the offer waits until
     it expires, §13); the command key with Return accepts only on a fresh
     press, never from a key held since before. A decision the core refuses
     re-arms the same offer after the delay. Choosing nothing is refused; a
     resumed transfer can only repeat its earlier selection (§7.5).
7. **Pairing secrets** are held in `Zeroizing` strings and dropped when the
   offer goes. The QR code is drawn black on white whatever the theme; its
   screen-reader label says it is secret and never reads it out.
8. **Clipboard text** is written to `outbox/` in the private state
   directory (0700, files 0600, created exclusively) and offered as a file;
   the file is removed as soon as no offer is pending for it and no
   offered transfer uses it (one file can go to several contacts; an offer
   no one accepted removes it at once), and any older than a week (the
   longest resume, §13) at start. Files copied in a file manager are
   offered as they are.
9. **Design tokens in one module** (`tokens.rs`): two palettes, a 4-pixel
   spacing scale, radii, type sizes, sizes, and durations; `apply` carries
   the palette into the component library's theme. A test holds every text
   and status color to WCAG 2.2 AA (4.5:1) on every surface in both themes.
   The theme follows the system unless Settings chooses one (`desktop.json`
   beside `config.json`).
10. **Motion:** GPUI draws on the display's frame clock (120 Hz where
    offered), on the GPU; the sheet slides in, progress fills, a bar with
    nothing measured pulses. Animations follow the system's reduced-motion
    setting. Lists that can be long (history, 2000 entries) are virtual.
11. **Keyboard and screen readers:** every page has a key (the command key
    with 1 to 5; O chooses files, Shift-V sends the clipboard, F searches);
    contacts, the drop zone, navigation, and tabs are tab stops activated
    with Space or Return. Every control and every row has a role and a
    label (`aria_label`), lists announce their counts, notices are status
    or alert regions.
12. **Tests:** a mock core (`backend::mock`, scripted answers, recorded
    requests, injected events) drives every flow in headless windows under
    the same `Root` as the app (gpui-kit's test harness: find, click,
    press, type, drop files). One test walks every page with the sheet
    open and fails on any control without a label. Screenshots of every
    screen in both themes are rendered off screen by Metal against the
    mock (`examples/screenshots.rs`, the never-shipped `mock` feature).
13. **Supply chain:** the toolkit is about 670 crates across the targets.
    `deny.toml` keeps everything else to the existing policy and leaves
    `todoke-desktop` out; `deny-desktop.toml` checks the whole graph with
    the toolkit's exceptions, each for an exact version with a reason:
    permissive licenses (Unicode-3.0, BSD-2/3-Clause, Zlib, ISC, 0BSD,
    CC0-1.0) and MPL-2.0 (dwrote, option-ext, cbindgen, unmodified), five
    unmaintained crates (instant, paste, rustls-pemfile on wasm only,
    rustybuzz, ttf-parser; none parses peer data), and the older version
    of each duplicate. The exception guard checks `deny.toml`'s claims on
    the graph it covers and the forbidden gate features on every shipped
    graph, the desktop's included. The new crates are exempted from audit
    in cargo-vet with a note each.

## Residual risks

- **Contacts have no names.** The protocol carries none, so a contact is
  "Device" and the start of its fingerprint. Fix: local nicknames, sealed
  in the core's contact store, set at pairing and in Settings.
- **Contacts cannot be removed, blocked, or revoked from the app.** The
  core has no request for it. Fix: `Request::RemoveContact` and
  `Request::Revoke` in the core (§2), then a Settings action with
  confirmation.
- **Secrets outlive their `Zeroizing` copies.** GPUI's text layout caches
  the shaped pairing code, the QR text field's contents live in the
  input's rope, and "Copy as text" puts a QR secret on the clipboard, where
  a clipboard manager may keep it. Fix: draw the code as glyph quads
  without the text cache, clear the input's buffer on submit, and clear
  the clipboard when the offer ends if it still holds the secret (and mark
  it concealed: `org.nspasteboard.ConcealedType` on macOS,
  `ExcludeClipboardContentFromMonitorProcessing` on Windows).
- **Clipboard text sits in a plaintext file** in the private outbox until
  its transfer ends (up to seven days). Fix: offer in-memory content
  through a core request (a sealed, in-memory source).
- **Closing the window stops a hosted core**, and with it receiving. Fix: a
  menu-bar or tray presence and a login item that runs the daemon; the app
  then always attaches.
- **No system notification** announces an offer while the window is in
  the background. Fix: GPUI's system notifications on `OfferReceived`
  (sender and counts only, never names).
- **The history keeps names and peers at rest** (sealed, but under the
  storage key file, which has no platform protection yet, §16 O9) for 30
  days by default. Fix: O9's platform key storage; reconsider the default
  retention.
- **History writes on the core's thread:** every finished transfer seals
  and syncs the whole history (up to 2000 entries) synchronously, briefly
  stalling sessions on slow storage. Fix: append-only sealed records, or the
  write on the blocking pool with the core awaiting it.
- **History follows the wall clock:** entries older than the retention are
  pruned against the current time, so a clock set far forward drops them
  for good. Fix: prune only by entry count when the clock jumps past the
  newest entry, or keep a monotonic record of the last write.
- **Hiding is not instant at relays:** a presence registration already
  started stays at the relay for the rest of its window (at most 30
  seconds). Fix: cancel open presence registrations when hiding.
- **The saved name may differ from the one shown:** the sheet shows the
  manifest name (escaped); `todoke-fs` may rename it on disk (§7.1 safe
  names, collisions). Fix: expose the planned local names in `OfferInfo`
  and show them.
- **The desktop's toolkit exceptions are not machine-checked:** the guard
  script checks `deny.toml`'s claims (never compiled, build time only) on
  the graph that file covers; `deny-desktop.toml`'s are runtime by design,
  and their reasons (getrandom 0.2 at build time only, rustls-pemfile only
  on wasm) are checked by review only. Fix: run the guard over the
  desktop's graph with its own list of runtime-allowed exceptions.
- **A hosted core can stop on the UI thread** if a request's reply holds
  the last handle to it when the window has already let it go (a stop that
  races a request): its threads are joined there, briefly. Fix: keep the
  backend's last handle in a background task.
- **"Through relay" is optimistic** for a contact without a session: any
  contact counts as remote when relays are configured, though it may never
  have been met there. Fix: the core reports when each contact was last
  met through a relay.
- **Speed and time left** come from the core's recent throughput; time left
  is the remaining bytes over it, with no smoothing across files. Fix: an
  exponentially weighted rate in the model.
- **120 fps is not measured.** Nothing tests frame times. Fix: a frame-time
  budget test on GPUI's benchmark context in CI on macOS.
- **Static text is not exposed to screen readers** as separate nodes: each
  region, row, and control carries the label that summarizes it, but text
  between them is not navigable by itself. The tests check labels on
  controls, not the experience in VoiceOver, Narrator, or Orca, which the
  manual checklist covers.
- **Arrow keys do not move between contacts;** Tab does. Fix: a roving tab
  index over the grid.
- **Applying settings restarts the core** (sessions close; transfers resume
  with a fresh Accept, §7.5), and when attached, stops the daemon, which a
  service manager may restart with the new file before the app attaches
  again. Fix: a core request to reload the configuration in place.
- **The relay list is replaced by name on import** and checked for shape
  only; a pinless entry trusts the platform roots (as the core does).
- **Supply chain:** about 570 crates of the toolkit are unaudited
  (exempted with notes), five are unmaintained, GPUI is a snapshot
  republished by gpui-kit (`gpui-pre`), and MPL-2.0 code ships in the
  binary on Windows (dwrote) and everywhere (option-ext). Fix: audits of
  the crates that touch untrusted input first (none should: names reach
  the toolkit as escaped text only), and following gpui-kit as GPUI
  converges.
- **Screenshots are rendered only on macOS** (the off-screen renderer is
  Metal); Windows and Linux appearance is checked by hand
  (`docs/qa/desktop.md`).

## Known test gaps

- **Real platforms:** the UI tests run in GPUI's test platform. Native
  drag and drop, the file and folder pickers, the clipboard's file lists,
  and focus behaviour on each OS are manual (`docs/qa/desktop.md`).
- **Applying settings while attached** (stop the daemon, then host
  anew) runs only by hand: a test process would still hold the first
  core's profile. Hosting, attaching, stopping, the pool's freshness rule,
  and Apply while hosting are tested. Fix: a test that runs the daemon as a
  separate process.
- **Hidden mode and urgent relay registrations:** hiding suppresses presence
  (tested); registrations for waiting offers continue by design, untested
  while hidden.

## Not here

Mobile apps, previews of received files (`todoke-preview`), contact names,
tray and login items, system notifications, and localization.
