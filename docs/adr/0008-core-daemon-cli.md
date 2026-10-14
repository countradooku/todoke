# ADR 0008: The core facade, the daemon, and the CLI

- **Status:** accepted on 2026-10-14. The maintainer delegated the design
  ("choose the best design") with the standing priority of maximum
  security first, then performance; every choice below follows PROTOCOL
  and DESIGN where the P10 build prompt differs.
- **Date:** 2026-10-14
- **Scope:** `todoke-core` (the one API every interface uses), `todoke-daemon`
  (the background service and its local IPC), and `todoke-cli` (the
  `todoke` command), PROTOCOL §3, §4, §6, §7, §9, §13, §14, §16 O2, O5, O6,
  O9, O10; DESIGN's open decisions on daemon IPC authorization and platform
  secret storage.

## Context

The P10 prompt asks for a core facade with commands and an event stream,
a CLI with pairing, sending, receiving, contacts, status, `--json`, and
shell completions, a daemon with a user-only local IPC socket, OS service
files, and a notifications hook, configuration in the platform directory,
and an acceptance test in which two daemons pair by code, send a 2 GB
folder, survive the receiver being killed, resume, and verify hashes and
the receipt.

PROTOCOL keeps suite 0x0001 sessions (O6, O10) and human-code pairing (O2)
out of production, leaves the QR rendering boundary (O5) and platform
secret storage (O9) open, requires every new file of an offer to use the
session's negotiated content suite (§6), and requires a fresh signed Accept
from local user intent for every resumed transfer (§7.2, §7.5).

## Decisions

1. **Development-gated.** `todoke-core`, `todoke-daemon`, and `todoke-cli`
   have a non-default `unaudited-dev` feature that enables the crypto gates.
   Without it the core reports that sessions are disabled. The
   deny-exceptions guard forbids the feature in shipped graphs.
2. **One thread owns the core.** `Core::start` runs the profile, the
   quarantine, the LAN listener, discovery, pairing, and every session on
   one thread with a single-threaded runtime. Sessions borrow the device
   identity for their whole life (the engine signs Accepts and receipts)
   and no key material crosses threads. Interfaces send `Request`s and
   receive `Event`s through channels.
3. **Identity at rest.** The profile creates the person root and device
   keys (sealed key store), an X25519 Noise static key, an unused ML-KEM
   credential (O11; its secret half is not kept), and a one-year binding,
   renewed with the next serial within 30 days of expiry. Everything is
   sealed under one storage key in a 0700 state directory that is refused
   if others can read it; a file that does not authenticate is reported and
   never replaced.
4. **The storage key** comes from a `StorageKeySource`. Until the platform
   keystores of P13 exist (O9), `KeyFile` keeps it in a 0600 file opened
   without following links.
5. **Offers are built when a session is ready.** `Send` walks the chosen
   paths without following links (sending only regular files and
   directories, names in NFC, within §13's 10000 entries and 64 levels).
   Names another system could not use (§7.1), a second sibling with the
   same name, and paths over 4096 bytes are skipped and counted in the
   answer, so an offer never fails later on a name; two chosen paths with
   the same name are refused. Walking and hashing run on the blocking
   pool, so the core keeps serving sessions meanwhile. Each file is opened
   without following a link or waiting on a FIFO and must be the file the
   walk saw (device, inode, change time), and stays open; a send that
   would pass the open-file limit is refused up front, and the daemon
   raises its limit toward the hard limit at start. The files then go to
   the source that serves the contact: the live session's, or the queue's.
   The transfer is named with a fresh random ID from the OS CSPRNG, and
   the manifest is built at `Ready` with the negotiated suite and the
   receiver's limits (§6).
6. **Resumption.** When a session ends, its unfinished offers (resumable
   ones included) and the source serving them wait for the next session;
   the sender reconnects with back-off to discovered or last-known
   addresses; the back-off restarts only after a session that lasted 30
   seconds. The receiver sees the resumed offer as a new decision; the
   CLI's `receive --yes` or an explicit `accept` makes it, repeating the
   earlier selection (§7.5). When a session ends, its undecided and moving
   transfers become `interrupted`. An outgoing offer waiting for a
   session can be cancelled, expires with its manifest, and is refused
   for a blocked or revoked contact.
7. **No decision is missed.** Events are not replayed, so an interface
   subscribes first and then asks for `Offers` (received offers awaiting
   a decision, with their entries); `send --wait` subscribes before it
   sends. An offer nobody decides is refused by the engine after the
   consent timeout (five minutes). Transfer states are typed (`offered`
   through `delivered`, `unconfirmed`, `rejected`, `cancelled`, `failed`
   with the protocol error code); the last 256 finished or interrupted
   transfers are remembered. A subscriber that falls behind is sent
   `missed` and re-reads `Offers` and `Transfers`. One `Offers` answer
   lists at most 40000 entries, so it fits one IPC message.
8. **Pairing.** `pair show` creates a QR or code offer and advertises in
   stranger mode for its lifetime; `pair scan` tries the nearby strangers;
   `pair code` sends the code to one chosen stranger. The QR text and code
   leave the core only to be shown (they are redacted from `Debug`), cross
   the daemon's same-user IPC, and are printed on the user's terminal. O5's
   boundary concerns FFI; there is none here. One offer is shown at a
   time: showing another, stopping, pairing, or ending `pair show`
   (Ctrl-C or expiry) withdraws every offer, and a QR answer is accepted
   only while a QR is shown. `pair code` and `pair scan` read the secret
   from the terminal, keeping it out of the process list and history.
9. **Daemon IPC, this user only.** On Unix a socket in the private state
   directory (0600), or, when that path is too long for a socket address,
   in `$XDG_RUNTIME_DIR`, `$TMPDIR` (macOS), or a `/tmp/todoke-<uid>`
   directory that must be ours and 0700; every connection's peer user ID
   must be the daemon's. On Windows a loopback TCP port and a 32-byte random
   token from a file in the user's state directory, compared in constant
   time (no `unsafe` code; a named pipe with a restrictive DACL would need
   it). Messages are length-prefixed JSON, at most 1 MiB from a client
   (checked before allocating), parsed strictly. At most 32 connections:
   one more is told the daemon is busy; the hello must come within 5
   seconds; a request connection idle for 2 minutes is closed; a
   subscriber is dropped as soon as it closes. A socket outside the state
   directory goes only in a directory this user owns that nobody else can
   enter, and on Unix the client checks that the daemon runs as this user.
   A second daemon, or one whose configuration names another state
   directory, stops before it opens the identity.
10. **No command execution.** The "notifications hook" is the event stream
    (`todoke events --json`); the daemon runs nothing, so no
    peer-controlled name ever reaches a shell.
11. **Service definitions** are printed for the user to install: a systemd
    user unit, a launchd agent, and on Windows a Task Scheduler task at
    logon (a Windows service would run under another account). All run as
    the user; paths are escaped for each format.
12. **Terminal safety.** The CLI escapes every peer-chosen string before
    printing it: control characters and every character that hides or
    reorders text (`todoke_fs::is_invisible`: bidi controls, tags,
    fillers, joiners, variation selectors, every default-ignorable code
    point). `--json` output writes the same characters as `\u` escapes,
    so it is ASCII apart from visible text and means the same.
13. **Paths** follow each platform (XDG on Linux, Application Support on
    macOS, `%APPDATA%`/`%LOCALAPPDATA%` on Windows) without the
    `directories` crate, whose dependency tree includes MPL-2.0 code;
    `TODOKE_HOME` puts everything under one directory. A socket outside
    the state directory is named by a hash of the state directory's
    normalized path, so every spelling of it finds the same daemon.
14. **Acceptance test.** `crates/todoke-cli/tests/e2e.rs` starts two daemon
    processes, pairs them by code, sends a folder, kills the receiver with
    SIGKILL at a fifth, restarts it, accepts the resumed offer, and checks
    every file's BLAKE3 and the signed receipt: 96 MiB on every run, 2 GiB
    in release in CI (34 seconds on an M-series Mac). A transfer that ends
    for good fails the test at once with its reason. Discovery goes through a shared folder (a
    development-only backend) because CI runners do not reliably carry
    multicast.

## Residual risks

- **Storage key in a file (O9).** Malware running as the user, or a copy of
  the whole state directory with its key file, opens the identity. Fix:
  platform keystores (Keychain, DPAPI/TPM, Secret Service, StrongBox,
  Secure Enclave) behind `StorageKeySource` (P13 and the mobile steps).
- **The contact store during handshakes.** It is locked for each whole
  handshake, so one slow or stalled peer delays every other session
  start, pairing, and `Contacts` request for up to the 30-second deadline
  (ADR 0007 records the replay case). The core loop itself never waits on
  it.
  Fix: split the store borrow in `todoke-crypto` so it starts after Noise
  message 1, or make it per contact.
- **Sender restarts lose outgoing resumption.** Prepared files and their
  outboards live in memory; a sender that restarts must offer again. Fix:
  persist prepared offers (paths, metadata, roots) and re-verify the files
  on start.
- **The ML-KEM secret half** generated for the unused credential is not
  wiped by libcrux when it goes out of scope (O6).
- **QR text and codes on the terminal** stay in scrollback. They stop
  working when `pair show` ends (the offer is withdrawn), but while it
  runs, anyone who reads the screen or scrollback can use them (300
  seconds, one use). Fix: none beyond the short lifetime; a GUI shows
  the QR without text.
- **One storage key for all state;** a compromise of the key file exposes
  identity and contacts together.
- **Windows IPC.** Any local user can open TCP connections before the
  token check; each holds a slot for at most the 5-second hello deadline,
  so a user who keeps 32 open keeps this user's CLI out. The client does
  not authenticate the daemon: a process that takes the port of a stale
  endpoint file receives the user's requests (codes and paths). The state
  directory, the storage key, and the endpoint file inherit their
  directory's ACL; under a shared parent such as `C:\todoke` other users
  may read them. Fix: a named pipe with a user-only DACL, a server check
  of the pipe's owner, and explicit DACLs on the state directory, in
  `todoke-sys-windows` (P13).
- **Pairing secrets in memory.** QR text and codes cross the IPC as plain
  strings (in the JSON buffers and the request), which are not zeroized.
  Fix: zeroizing buffers for requests that carry secrets.
- **Open files per offer.** Each queued file holds two descriptors until
  its offer ends; many large queued offers can still reach the limit the
  daemon raised. Fix: open files lazily and re-verify their identity.
- **Session idle timeout:** a session with nothing to do closes after 30
  seconds, so a long-idle receiver reconnects for each new offer (a cost,
  not a weakness).

## Known test gaps

- **The session idle close** (30 seconds) and its guard for transfers
  still awaiting a decision are not exercised: no test waits that long.
  Fix: a test-only idle period, then assert an undecided offer survives
  three of them and an idle session closes and reconnects.
- **Offer races at a session's end** (an offer sent as the session stops
  reading, or before it is ready) are handled in `finish` and `apply`
  but not driven deterministically. Fix: a session test seam that pauses
  the loop between the last read and the drain.
- **Windows links**: the junction walk test runs only on the Windows CI
  runner; owner checks of socket directories need a second user and are
  covered by the same comparison as the mode checks.

## Not here

QR scanning from a camera, desktop notifications, the GUI (P12), OS
integration and packaging (P13), relay (P11).
