//! Filesystem operations and safe destination handling for transfers.
//!
//! # Trust boundary
//!
//! Remote filenames, paths, MIME labels, and content are untrusted, and so
//! is the local filesystem, which other processes can change at any time.
//! Nothing here follows a link, overwrites an entry, opens or executes a
//! received file, or logs a path or peer file name (PROTOCOL §14.2).
//!
//! # Pieces
//!
//! | Piece | What it does | Spec |
//! | --- | --- | --- |
//! | [`sanitize_component`] | Rewrites one manifest name for local use, visibly and deterministically ([`name`] lists every rule) | §7.1 |
//! | [`DestinationPlan`] | Before consent: every entry's exact local name, renames, warnings, and rejections, including filesystem collisions (case, Unicode normalization) and per-OS length limits | §7.1 |
//! | [`detect`] | After verification: the content's real type from its signature, executables per platform, and mismatches with the claimed extension or MIME label, as UI warnings | §7.1 (MIME grants nothing) |
//! | [`dest`] | The publication target: [`dest::Destination`] (link-refusing, exclusive, no-replace operations), [`dest::DirDestination`] for desktop filesystems, the Android SAF and iOS adapters' contract, and the origin-marker hook (Mark of the Web, `com.apple.quarantine`) | §7.7 |
//! | `FsSink` | `todoke_transfer::ReceiveSink` on disk: the per-transfer quarantine (verified content ciphertext and sealed file masters only), journals, tombstones, quota, cleanup at start-up, and publication | §7.4–§7.7, §8 |
//! | `SharedSink` | One `FsSink` (one writer per state directory, enforced by an OS file lock) shared by several sessions' engines | — |
//! | `FsSource` | `todoke_transfer::SendSource` on disk: files held open from hashing on, outboards in private storage, mutation detection | §8 |
//! | [`quarantine::codec`] | The quarantine's local journal and tombstone formats | — |

//!
//! # Receiving, step by step
//!
//! 1. **Before consent** (`ReceiveSink::check_offer`): the
//!    [`DestinationPlan`] gives every entry its exact local name, avoiding
//!    names the destination already holds, and lists renames, warnings,
//!    and rejections for the receive sheet (`FsSink::plan`). Nothing is
//!    created. An offer with no storable file is refused as an unsupported
//!    destination; one whose smallest file exceeds the quarantine quota,
//!    as quota.
//! 2. **At consent** (`record_accept`): a private quarantine directory for
//!    the transfer gets the manifest and a journal with the local names the
//!    user was shown, durably, before the Accept is sent. A selection with
//!    a rejected file, over the quota, or whose plan is no longer kept, is
//!    refused and nothing is sent.
//! 3. **Keys** (`record_file_key`): each file's master is sealed with the
//!    platform `Sealer` (§8) and kept only sealed.
//! 4. **Segments** (`store_segment`): only the verified content
//!    ciphertext, exactly as received, is stored, one fixed-size slot per
//!    segment, synced before the request retires ([`Durability`]). No
//!    plaintext is at rest in the quarantine.
//! 5. **Publication** (`publish`): every stored segment is decrypted and
//!    verified again into a temporary file in the destination directory,
//!    the exact length and whole-file BLAKE3 root are checked (§7.7), the
//!    file is marked ([`dest::OriginMarker`]), synced, and published under
//!    its consented name, or, if that was taken since, the next free
//!    `" (n)"` name (reported by `FsSink::renamed`), without replacing
//!    anything and atomically where the filesystem allows. Its ciphertext
//!    and sealed master are deleted. Its content type is checked
//!    ([`detect`]) for UI warnings (`FsSink::content_report`).
//! 6. **Resume, cancel, expiry**: retained ciphertext is revalidated by the
//!    engine under the new session's key; cancel, revocation, and expiry
//!    delete the quarantine (the sealed masters with it, which leaves any
//!    remnant on flash unreadable; physical erasure is not promised, §7.6)
//!    and keep a tombstone. Start-up removes expired and positively damaged
//!    state and temporary files a crash left; state it cannot read now (an
//!    I/O or permission error) is kept, unused, for a later start.
//!
//! # Guarantees and limits
//!
//! - **No path escape:** every local name is one sanitized component, and
//!   every operation is relative to a directory opened from the
//!   destination root without following links (`openat` with
//!   `O_NOFOLLOW` on Unix; symbolic links and junctions opened and refused on
//!   Windows, while cloud-files placeholders, such as `OneDrive` ones, are allowed).
//! - **Bound to the verified file:** the staged file stays open from
//!   creation to publication, and publication requires the final name to
//!   be that file (same device and inode on Unix; on Windows the handle is
//!   held without `FILE_SHARE_DELETE`, so the temporary name cannot be
//!   replaced, and the final name is compared with it after the hard link
//!   by size, attributes, and times), so a file substituted under the
//!   temporary name is never published, journaled, or acknowledged.
//! - **No overwrite:** files and directories are created exclusively;
//!   publication uses rename-without-replace, a hard link, or, on
//!   filesystems with neither (FAT, exFAT, some network shares), an
//!   exclusive copy, which is not atomic.
//! - **Nothing runs:** no execute permission, no opening, no previews.
//! - **Windows residual race:** paths are re-resolved per call. A symbolic
//!   link or junction at the root's path is refused like one anywhere below
//!   it, the root is held (it cannot be renamed, deleted, or replaced) for
//!   as long as any transfer is retained, and every directory from the root
//!   down is pinned while an operation runs. Any principal who can write the
//!   parent of one of the root's ancestors can still swap that ancestor;
//!   see `docs/adr/0006-filesystem.md`.
//! - **Not here:** the Android Storage Access Framework and iOS
//!   security-scoped folder adapters ([`dest`] documents their contract),
//!   and the Mark of the Web and `com.apple.quarantine` implementations
//!   (platform crates).
//!
//! # Logging
//!
//! Nothing here logs. `Debug` output shows no names, paths, keys, or
//! content; errors carry codes.

#![forbid(unsafe_code)]

pub mod dest;
pub mod detect;
/// Fuzzing entry points: built only with `--cfg fuzzing` (cargo-fuzz).
#[cfg(fuzzing)]
pub mod fuzzing;
pub mod name;
mod plan;
pub mod quarantine;
#[cfg(any(unix, windows))]
mod shared;
#[cfg(any(unix, windows))]
mod sink;
#[cfg(any(unix, windows))]
mod source;

#[cfg(test)]
mod tests;

pub use name::extension::{ExtensionRisk, Platforms, RiskKind, extension_risk};
pub use name::{
    Change, Kind, MAX_COMPONENT_BYTES, MAX_COMPONENT_NFD_UNITS, NameRules, sanitize_component,
};
pub use plan::{
    DestinationPlan, FsProfile, LocalName, PathLimit, PathUnits, PlannedEntry, Rejection, Renamed,
    UntrustedName, Warning,
};
#[cfg(any(unix, windows))]
pub use shared::SharedSink;
#[cfg(any(unix, windows))]
pub use sink::{Durability, FsSink, OpenError, SinkConfig};
#[cfg(any(unix, windows))]
pub use source::{FsSource, PreparedFile};
