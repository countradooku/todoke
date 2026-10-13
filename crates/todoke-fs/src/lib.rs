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

#![forbid(unsafe_code)]

pub mod dest;
pub mod detect;
pub mod name;
mod plan;

#[cfg(test)]
mod tests;

pub use name::extension::{ExtensionRisk, Platforms, RiskKind, extension_risk};
pub use name::{Change, Kind, MAX_COMPONENT_BYTES, NameRules, sanitize_component};
pub use plan::{
    DestinationPlan, FsProfile, LocalName, PathLimit, PathUnits, PlannedEntry, Rejection,
    UntrustedName, Warning,
};
