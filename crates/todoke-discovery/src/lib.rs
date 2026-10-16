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
//! | [`Advertiser`] | One paired record at a time, rotating over contacts; the instance label renewed every epoch; stranger mode only on explicit enable, 300 seconds, rotating every 60 (random for code pairing, the QR's token for each minute while a QR is shown) | §9 |
//! | `Mdns` | The `mdns-sd` responder and browser for `_todoke._tcp.local.`, without logging, on private and link-local interfaces only (not on iOS) | §9 |
//! | `Bonjour` | The same records through the system's Bonjour (`dns_sd`) on Apple platforms, for iOS, where raw multicast needs a restricted entitlement | §9 |
//!
//! The tokens and locators come from `todoke_crypto::discovery`; nothing
//! here holds key material. A discovered contact is only a candidate for
//! the transport race and the authenticated session
//! (`todoke_transport::TransportManager`).
//!
//! # Not here
//!
//! Bluetooth discovery: todoke uses no Bluetooth (PROTOCOL §10.1).

#![forbid(unsafe_code)]

pub mod advertise;
#[cfg(not(target_family = "wasm"))]
mod backend;
#[cfg(target_vendor = "apple")]
pub mod bonjour;
pub mod directory;
#[cfg(not(any(target_family = "wasm", target_os = "ios")))]
pub mod mdns;
pub mod sighting;

#[cfg(all(test, not(target_family = "wasm")))]
mod support;

pub use advertise::{Advertisement, Advertiser, OsRandom, Plan, Random};
#[cfg(not(target_family = "wasm"))]
pub use backend::{MdnsError, STRANGER_MAX};
#[cfg(target_vendor = "apple")]
pub use bonjour::Bonjour;
pub use directory::{Directory, Observed, Reachable};
#[cfg(not(any(target_family = "wasm", target_os = "ios")))]
pub use mdns::{Event, Mdns};
pub use sighting::{Dropped, Sighting};
