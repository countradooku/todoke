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

#![forbid(unsafe_code)]

pub mod dest;
pub mod detect;
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
pub use name::{Change, Kind, MAX_COMPONENT_BYTES, NameRules, sanitize_component};
pub use plan::{
    DestinationPlan, FsProfile, LocalName, PathLimit, PathUnits, PlannedEntry, Rejection,
    UntrustedName, Warning,
};
#[cfg(any(unix, windows))]
pub use shared::SharedSink;
#[cfg(any(unix, windows))]
pub use sink::{Durability, FsSink, OpenError, SinkConfig};
#[cfg(any(unix, windows))]
pub use source::{FsSource, PreparedFile};
