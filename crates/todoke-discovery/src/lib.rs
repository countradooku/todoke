//! Candidate peer discovery and reachability information.
//!
//! # Trust boundary
//!
//! Advertisements, device names, addresses, and proximity are untrusted hints.
//! Only the authenticated core session may establish a peer's identity.
//!
//! # Pieces
//!
//! | Piece | What it does | Spec |
//! | --- | --- | --- |
//! | [`Sighting`] | Checks one resolved mDNS instance: service type, 16-hex label, exactly one `v1=` TXT string with a valid record, addresses the LAN policy allows | §9, §10 |
//! | [`Directory`] | Matches sightings against the current discovery table, keeps only useful ones within fixed bounds, expires them after 120 seconds, rate-limits matching | §9 |
//! | [`Advertiser`] | One paired record at a time, rotating over contacts; the instance label renewed every epoch; stranger mode only on explicit enable, 300 seconds, rotating every 60 | §9 |
//! | `Mdns` | The `mdns-sd` responder and browser for `_todoke._tcp.local.`, without logging, on private and link-local interfaces only | §9 |
//!
//! The tokens and locators come from `todoke_crypto::discovery`; nothing
//! here holds key material. A discovered contact is only a candidate for
//! the transport race and the authenticated session
//! (`todoke_transport::TransportManager`).
//!
//! # Not here
//!
//! BLE discovery: §9 leaves its service UUID and GATT allocation unassigned
//! (§16 O7), so no BLE advertising exists.

#![forbid(unsafe_code)]

pub mod advertise;
pub mod directory;
#[cfg(not(target_family = "wasm"))]
pub mod mdns;
pub mod sighting;

#[cfg(all(test, not(target_family = "wasm")))]
mod support;

pub use advertise::{Advertisement, Advertiser, OsRandom, Plan, Random};
pub use directory::{Directory, Observed, Reachable};
#[cfg(not(target_family = "wasm"))]
pub use mdns::{Event, Mdns, MdnsError};
pub use sighting::{Dropped, Sighting};
