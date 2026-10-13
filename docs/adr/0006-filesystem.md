# ADR 0006: Filesystem access, quarantine, and publication

- **Status:** proposed (P08), for the maintainer's review.
- **Date:** 2026-10-13
- **Scope:** how `todoke-fs` maps peer names onto local names, keeps
  partial transfers at rest, publishes verified files, detects content
  types, and abstracts platform storage (PROTOCOL §7.1, §7.4–§7.7, §8,
  §14.2), and which libraries it uses for that.

## Context

PROTOCOL §7.1 makes names untrusted display data and leaves the receiver to
detect collisions its own filesystem imposes (case folding, Unicode
normalization) before consent, resolving them "by a locally authorized
destination mapping or reject", never by silent overwrite. §7.7 requires
publication "through filesystem operations that prevent path escape,
symlink/race substitution, and unintended overwrite", atomic per file where
the platform allows, and durable before the receipt. §7.5 and §8 limit what
may be retained (verified partial content and encrypted key state; masters
sealed by the platform's approved secret storage), §7.6 requires deletion of
cancelled temporary data without promising physical erasure, and §14.2
forbids logging paths and names.

The maintainer's binding decisions for P08: no NFC repair (the manifest
decoder already rejects non-NFC names); a local mapping computed before
consent, shown to the user, deterministic and visible; ciphertext and sealed
masters only at rest; never auto-open or set execute bits; a capability-style
API evaluated against rustix; no `unsafe` in `todoke-fs`; desktop storage
implemented, Android SAF and the iOS sandbox as trait contracts.

## Decision

### 1. Filesystem API: rustix on Unix, the standard library on Windows

Every destination operation is relative to a directory handle and takes one
component that the destination plan produced:

| Need | Linux, Android, macOS, iOS (rustix 1.1.5) | Windows (std only) |
| --- | --- | --- |
| Walk below the root without following links | `openat(O_DIRECTORY \| O_NOFOLLOW)` per component | `CreateFile` with `FILE_FLAG_OPEN_REPARSE_POINT`, then refuse a reparse point or non-directory; every handle from the root down held without `FILE_SHARE_DELETE` while the operation runs |
| Create without touching an existing entry | `mkdirat`; `openat(O_CREAT \| O_EXCL \| O_NOFOLLOW)`, mode `0666` (umask applies, never execute bits) | `CreateDirectoryW`; `CREATE_NEW` |
| Publish without replacing | `renameat2(RENAME_NOREPLACE)` on Linux, `renameatx_np(RENAME_EXCL)` on Apple platforms; if the filesystem refuses, `linkat` then `unlinkat`; if hard links are refused too, an exclusive copy read from the staged handle | `CreateHardLinkW` then delete the temporary name (`std::fs::rename` always replaces); if hard links are refused (FAT, exFAT, some shares), an exclusive copy read from the staged handle |
| Bind publication to the hashed file | The staged file stays open from creation to publication; before the rename or link, `fstat` of it and `statat(temp, AT_SYMLINK_NOFOLLOW)` must give the same `(st_dev, st_ino)` with one link, and after it the final name must (one link after a rename, two after a hard link); otherwise nothing is journaled or acknowledged and the substitute is left as it is | The staged file is created without `FILE_SHARE_DELETE` and held until publication is done, so the temporary name (and, after the link, the final one) can be neither renamed, deleted, nor replaced; identity cannot be compared with the standard library (`file_index` is unstable, `GetFileInformationByHandle` is `unsafe` FFI), so the held handle is the protection |
| Read back for re-verification | `openat(O_NOFOLLOW \| O_NONBLOCK)`, then `fstat` must say regular file (a planted FIFO cannot block) | `FILE_FLAG_OPEN_REPARSE_POINT`, then refuse a reparse point or non-file |
| Durability | `fsync` of the file (`F_FULLFSYNC` on Apple) and of the directory | `FlushFileBuffers` of the file; NTFS journals the directory (the standard library has no directory flush) |

Windows paths are the canonical verbatim (`\\?\`) form of the root plus
components, so Win32 name munging (device names, trailing dots and spaces)
does not apply and long paths work.

**Residual risks, stated honestly.**

- *Windows:* there is no `openat` in the standard library, so each call
  re-resolves a path, starting from the root's canonical path. The threat
  is any principal who can write the root's parent (or the parent of any
  of its ancestors): that is enough to rename the folder away and put a
  junction, a symbolic link, or another directory at its path, and it does
  not need rights over the user's profile when, for example, the
  destination sits in a shared or removable folder. The root is therefore
  reopened with `FILE_FLAG_OPEN_REPARSE_POINT` and a reparse point there is
  refused, exactly as for every directory below it; and for as long as the
  sink retains any transfer (whose recorded names refer to this root), it
  holds the root without `FILE_SHARE_DELETE`, so it can be neither renamed,
  deleted, nor replaced (`Destination::hold_root`). If the folder is gone
  or was replaced when it is needed, the sink fails closed (`STORAGE`, or
  an error at start-up). During an operation every directory from the root
  to the entry is pinned too. While no transfer is retained the root is not
  held, so the user can move their Downloads folder; a plain directory put
  at the same path in that time is used as the destination (the standard
  library cannot compare directory identities). What remains is a swap of
  one of the root's ancestors, unverified on Windows. A fully
  handle-relative implementation needs `NtCreateFile` with a root directory
  handle, which is `unsafe` FFI and would belong in `todoke-sys-windows`.
  A reparse point at the root is refused whatever its kind, so a
  destination that is itself a cloud-files placeholder (for example a
  OneDrive-backed folder) is refused too; telling those apart from
  junctions and links is left as an open question.
- *Exclusive-copy fallback:* nothing is overwritten, but the final name
  exists while the copy runs, and a crash leaves a truncated file there. Only
  filesystems with neither rename-without-replace nor hard links reach it.
- *Substitution race on Unix:* anyone who can write the destination
  directory sees the temporary name. The check before the rename refuses a
  substitute; one planted between that check and the rename is moved to the
  final name by the rename itself, and the check after it then refuses
  publication (no journal entry, no `Complete`, no receipt) and leaves the
  substitute there untouched rather than delete something this crate did
  not create.
- *Android:* bionic declares `renameat2` with `__INTRODUCED_IN(30)`, so the
  libc wrapper exists from API level 30 (Android 11), not from Android 14 as
  an earlier draft of this ADR said. Whether the app seccomp filter of every
  supported release allows the `renameat2` system call is **unverified** (a
  disallowed call kills the process, and the libc wrapper's existence says
  nothing about the filter). Android therefore keeps the hard link first.
  P16 verifies the seccomp question on devices and enables `renameat2` where
  it is allowed.
- *Crash between publication and journaling:* the file is published, the
  journal does not know, and a resume publishes it again under the next
  suffix. Nothing is lost or overwritten; the user may see a duplicate.
  Failures after a successful rename or link no longer cause this: a
  temporary name that cannot be removed after a hard link leaves the
  publication successful (start-up removes that name once it is a second
  link to the published file, and nothing else under it), and the file is
  journaled before a failed directory sync is reported. If the journal
  itself cannot be written, the transfer fails with `STORAGE` and the same
  session does not publish the file again; only a restart before the
  journal recovers can still lead to the duplicate.

**Alternatives.** `cap-std`/`cap-fs-ext` 4.0.3 (Bytecode Alliance, used by
Wasmtime) give the same sandboxing on all three systems without `unsafe` in
this crate, but add about 35 packages, three `windows-sys` and two
`io-lifetimes` versions (new duplicate-version exceptions, against the
latest-version policy), and still have no rename-without-replace. Linux
`openat2(RESOLVE_BENEATH)` is Linux-only and unnecessary when every lookup is a
single component. Direct `libc` calls would need `unsafe` here. rustix keeps
`todoke-fs` at `#![forbid(unsafe_code)]`; its `unsafe` is inside the crate,
which the Bytecode Alliance maintains (imported orgs trust its publisher; it
has an exact-version cargo-vet exemption, see `supply-chain/README.md`).

### 2. Names: one portable rule set, the plan computed before consent

`sanitize_component` applies the same rules on every platform, so names stay
safe when files are copied elsewhere. Each rewrite is recorded as a `Change`:
bidi controls (U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069), C1
controls, zero-width and other default-ignorable or invisible characters, tags,
and noncharacters become U+FFFD (joiners and variation selectors are kept
inside non-ASCII text, where emoji sequences and Persian or Indic scripts need
them); a full-stop look-alike before a known extension, look-alike letters in
the final extension, and document extensions in front of a risky one become
`_`; spaces padding the final extension away are removed; files the Windows
shell processes when it merely lists a folder (`.lnk`, `.url`, `.scf`,
`.library-ms`, `.searchConnector-ms`, `.settingcontent-ms`, `.website`,
`desktop.ini`, `autorun.inf`, `folder.htt`) get `.txt` appended, because
displaying the folder can leak NTLM credentials to a remote icon or target
(for example CVE-2025-24054); Windows device names beyond §7.1 (Microsoft's
superscript forms, device stems followed by spaces, and conservatively
`COM0`, `LPT0`, `CONIN$`, `CONOUT$`, `CLOCK$`), NTFS metafile names, and this
crate's `.todoke-` prefix get `_` prepended; names shaped like 8.3 short names
have `~` replaced; overlong components are truncated at a grapheme-safe
boundary keeping the extension. A component must fit two limits: 255 UTF-8
bytes (ext4, APFS, f2fs; NTFS and exFAT count 255 UTF-16 units, never
fewer) and 255 UTF-16 units of its canonical decomposition (HFS+, and some
SMB and NFS servers, store names as NFD UTF-16; U+1F82 is 3 bytes but 4
units). Both are checked in the plan, before consent, so a name the
manifest allows is shortened visibly rather than failing with
`ENAMETOOLONG` after consent. The function is idempotent.

`DestinationPlan` then separates siblings whose collision keys match (NFD,
each character upper- then lower-cased twice, NFD: a superset of NTFS, APFS,
HFS+, exFAT, and FAT equivalences, so "ß"/"SS", "ı"/"I", and the Greek sigmas
collide) with `" (n)"` suffixes, avoids names the destination root already
holds (bounded work inside frame handling: the root is listed once, up to
100,000 names, so a candidate whose collision key is listed costs nothing,
each top-level entry's chosen name is confirmed with one lookup, and one
plan makes at most 20,000 lookups; what the budget cannot settle is
rejected, visibly, before consent), checks the per-OS path limit (4095 bytes on Linux and Android, 1023 on
Apple platforms, 32,760 UTF-16 units on Windows, warning above 259), and adds
warnings: risky extensions per platform, macOS bundle directories, hidden
names, and MIME labels that do not fit the extension. Rejected entries
(path too long, no free name) can be deselected; an offer with no storable
file is refused as an unsupported destination. The peer's name stays
available as `UntrustedName`; `Debug` prints no names.

### 3. Quarantine: verified ciphertext and sealed masters only

Each accepted transfer gets a private directory in application storage with
the canonical manifest, a journal, one sealed master per keyed file, and one
slot file per file. Slots hold the content ciphertext exactly as received
(already AEAD-encrypted under the file's master, §8), at a fixed stride per
file: a two-byte length and the ciphertext. The stride is an upper bound on
the Bao slice for the file's tree depth (`8 + data + 64 × (15 + depth) + 16`),
about 1.5% over the real size.

This needs the file master in the sink, which the P07 trait did not pass.
`ReceiveSink::record_file_key` (new) hands the sink the master and this
session's `AcceptedFile` when the `FileKey` passes the consent gate, before
any segment of the file is stored or revalidated. `FileMaster::seal` /
`open_sealed` (new, in `todoke-crypto`) pass the master's bytes only to the
`Sealer`, under a context binding the transfer, manifest hash, and file ID.
This supersedes ADR 0005's note that the receiver keeps no masters across
sessions: it keeps them sealed (§8 allows "encrypted local key state"), and a
resumed transfer whose `FileKey` brings a different master discards that
file's retained ciphertext. Publication opens the master, decrypts and
re-verifies every segment through the content layer into the destination's
temporary file, and checks length and whole-file BLAKE3. A key for a file
the sink already published is refused and creates no sealed master: the
engine sends none for a file it counts as published, and if it asks again
because the published file was removed or changed since, the transfer fails
with `STORAGE` rather than publish nothing and claim delivery. The slot
stride is checked against real Bao slices of many tree shapes, and through
a model of the Bao tree that those slices validate, for trees deeper than 20
levels up to 1 TiB.

The journal (`TDKJ`, versioned, BLAKE3 check values) records the accepted
selection and expiry, a secret salt from which temporary names are derived,
the local names the user consented to (every selected file and each
directory on its path, written with the header in one atomic write at the
Accept), top-level directories created, and files published; a torn tail is
cut, a damaged header discards the transfer, and so does a journal missing a
consented name. The journal is bounded: the sink writes at most one
consented name per entry, one publication per file, four records per
top-level directory (one only when a re-created directory changes name, and
publication fails with `STORAGE` beyond that), and the end marker, at most
50,001 entries; a journal with more than 80,000 intact entries is damaged as
a whole rather than cut at the bound, since the next append would truncate
the intact entries after it. Publication and restarts use the consented names and never
map the manifest again against the destination as it is later; an Accept
whose plan is no longer kept (the sink keeps the last 16 offers' plans) is
refused rather than mapped again. If a consented name (a file's, or a
top-level directory's) was taken by the time of publication, nothing is
overwritten: the next free `" (n)"` name is used and the deviation is
reported per file (`FsSink::renamed`, which survives restarts); a retained
transfer whose consented entry cannot be published at all fails with
`STORAGE`. Start-up deletes a transfer only when
its records are positively damaged (or missing) or expired: a journal or
manifest that cannot be read now (permissions, an I/O error, too many open
files) is kept on disk, unused, and no new Accept may replace it that run. Tombstones (`TDKT`) are a sorted,
checked list replaced atomically; a damaged list fails closed at start-up.
A failed write of the list is retried on every sweep, offer, and Accept;
until a retry succeeds the sink reports the tombstones as not durable
(`FsSink::tombstones_durable`) and takes no new or resumed transfer, so a
crash cannot forget a cancel that was already acknowledged.
Cancel, revocation, expiry, and start-up clean-up delete the
quarantine and leftover temporary files; deleting the sealed master leaves any
ciphertext remnant unreadable. Physical erasure on flash is not promised
(§7.6). A quota (default 64 GiB) bounds what transfers may reserve. One sink
per state directory is enforced with an OS file lock; `SharedSink` shares it
between sessions.

### 4. Durability

Records (journal header, appended entries, tombstones, sealed masters) and
published files get the strongest sync the platform offers (`F_FULLFSYNC` on
Apple). Each stored segment is synced before `store_segment` returns, as §7.4
asks, but with `fsync` on Apple platforms rather than `F_FULLFSYNC`: measured
on this Mac, 8 MiB of segments took 1.95 s with `F_FULLFSYNC` per segment
(about 4 MB/s) and 22 ms with `fsync` (about 370 MB/s); without a per-segment
sync, 4 ms. Linux and Android use `fdatasync`, Windows `FlushFileBuffers`
(not measured here). `Durability::Periodic` syncs segments every N bytes
instead; a power loss can then lose recent segments, which §7.5 revalidation
fetches again. Correctness never depends on segment durability: retained
segments count only after they open under the new session's key.

**Accepted deviation from §7.4 on Apple platforms.** §7.4 retires a request
only after "durably storing" the chunk. With `Durability::EverySegment` on
macOS and iOS each segment gets a plain `fsync`, which hands the data to the
drive but does not flush the drive's own cache, so a power loss (not an app
or kernel crash) can lose segments whose requests were already retired.
This is accepted, deliberately and only for segments, because it cannot
cause a wrong result: on resume every retained segment is revalidated under
the new session's key before it counts (§7.5), and a lost or torn segment is
simply requested again. Everything whose loss would change a decision gets
`F_FULLFSYNC` (the standard library's `sync_all`/`sync_data` on Apple, and
`fcntl_fullfsync` for destination directories): the journal header and
every appended entry, the manifest, sealed masters, the tombstone list (and
its directory) before `tombstone` returns, so before the engine reports the
cancel, in both durability modes, and every published file and its
directory before the file is journaled as published.

### 5. Content type detection

After the whole-file check, the first 36 KiB are compared with a fixed table
of about 45 signatures (no parsing beyond fixed offsets), giving UI warnings:
executables and installers per platform (PE, ELF, Mach-O, Java, DEX, Wasm,
shebang scripts, shell links, MSI/OLE, cabinets, xar, deb, rpm, ISO 9660),
active markup (HTML, SVG), and mismatches between the content and the
extension or MIME label. It never gates consent (content exists only after
Accept) and never opens or previews anything. A detection crate (for
example `infer`) was not used: the table needed is small and bounded, and it
avoids a new dependency.

### 6. Platform storage

`Destination` is the publication abstraction (root, exists, exclusive
directory and file creation, publish without replacement, discard, open for
re-verification, directory sync). `DirDestination` implements it for desktop
filesystems and any POSIX directory on Android and iOS. The Android SAF
adapter (P16) maps it onto `DocumentsContract` (providers choose free names
and never overwrite; publication there is a copy, not atomic); the iOS adapter
(P17) brackets security-scoped access and coordinates with
`NSFileCoordinator` over the same POSIX calls. The quarantine always lives in
app-private POSIX storage. `OriginMarker` is the hook for the Mark of the Web
(Windows Attachment Services, `IAttachmentExecute::Save`) and
`com.apple.quarantine` (`NSURLQuarantinePropertiesKey` with the
`LSQuarantine.h` keys), applied to the staged file before it gets its final
name; the platform crates implement it (P13).

On the sending side, `FsSource` holds each offered file open from hashing on,
keeps its Bao outboard in private storage, and refuses a file whose size,
modification time, or identity changed; the content layer re-verifies every
slice against the manifest root as well (§8).

## Consequences

- No peer-controlled name reaches a path outside the destination, follows a
  link, or replaces an entry; foreign files are never modified.
- What is published is the file whose length and whole-file BLAKE3 were
  checked: a file substituted under the temporary name is never published,
  journaled, or acknowledged.
- Nothing but ciphertext and sealed masters is at rest before publication;
  the temporary plaintext file exists in the destination only during
  publication (and after a crash until the next start).
- The `ReceiveSink` trait gained `record_file_key`; `todoke-crypto` gained
  `FileMaster::seal`/`open_sealed`.
- Windows protection against local races is weaker than on Unix, as
  described above.
- Shell-processed Windows files arrive renamed with `.txt`; legitimate
  shortcuts need the user to rename them.
