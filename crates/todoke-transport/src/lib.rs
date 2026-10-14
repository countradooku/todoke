//! Transport interfaces for BLE, Wi-Fi P2P, AWDL, USB, LAN, and QUIC relay.
//!
//! # Trust boundary
//!
//! Every transport is an untrusted byte pipe. Connectivity and transport-layer
//! security must never grant peer identity, consent, or content authenticity.
//!
//! # Pieces
//!
//! | Piece | What it does | Spec |
//! | --- | --- | --- |
//! | [`Link`], [`LinkInfo`] | An ordered, reliable byte pipe (`futures-io`) and what is known about it: kind, addresses, latency, bandwidth | §5 |
//! | [`LanPolicy`] | Which addresses may be contacted or accepted: private and link-local only, no privileged ports | §9, §10 |
//! | [`race`](race::race) | Races connections (never sessions) to a peer's candidates, RFC 8305 style, within §10's bounds | §4, §10 |
//! | [`TcpConnector`], [`LanListener`] | TCP links on the local network, dual-stack, `TCP_NODELAY` | §9 |
//! | [`TransportManager`] | One attempt and one session per device pair, simultaneous-open resolution, the contact handshake on the winning link, the §13 unauthenticated-attempt budget, and the migration policy | §4, §5, §13 |
//! | [`capabilities`] | Which link kinds this build can use | §16 O7 |
//!
//! # What is not here
//!
//! - **QUIC on the LAN, BLE, Wi-Fi P2P, AWDL, and USB:** PROTOCOL §16 (O7)
//!   leaves the direct-path QUIC/ALPN profile and every other adapter's
//!   packaging unassigned, and requires unspecified adapters to stay
//!   disabled. So there is no QUIC (and no UDP GSO/GRO tuning) yet.
//! - **Relay** (§10): a later step.
//! - **Sessions racing:** only connections race; see [`race`].
//!
//! Sessions are suite 0x0001, which is not production-enabled (§16 O6,
//! O10): [`TransportManager`] needs the `UnauditedSuite0001` gate.

#![forbid(unsafe_code)]

pub mod capabilities;
pub mod link;
#[cfg(not(target_family = "wasm"))]
pub mod manager;
pub mod policy;
#[cfg(not(target_family = "wasm"))]
pub mod race;
#[cfg(not(target_family = "wasm"))]
pub mod tcp;
#[cfg(not(target_family = "wasm"))]
pub mod timer;

#[cfg(all(test, not(target_family = "wasm")))]
mod sim;
#[cfg(all(test, not(target_family = "wasm")))]
#[allow(
    clippy::large_futures,
    reason = "test sessions are awaited in place; with the workspace's \
              development features their futures pass 16 KiB"
)]
mod tests;

pub use link::{Link, LinkInfo, LinkKind};
#[cfg(not(target_family = "wasm"))]
pub use manager::{
    ClaimedIncoming, ConnectError, Connected, Established, Incoming, IncomingContact,
    MigrationPolicy, OutgoingClaim, SlotGuard, TransportManager,
};
pub use policy::{LanPolicy, Refusal};
#[cfg(not(target_family = "wasm"))]
pub use race::{Candidate, Connector, RaceConfig, RaceError};
#[cfg(not(target_family = "wasm"))]
pub use tcp::{LanListener, TcpConnector, TcpLink};
#[cfg(not(target_family = "wasm"))]
pub use timer::TokioTimer;
