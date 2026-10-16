//! Transport interfaces for the LAN, Wi-Fi peer-to-peer links, AWDL, and the
//! QUIC relay.
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
//! | [`relay`] | QUIC v1 / TLS 1.3 to an untrusted relay (platform validation or a pinned key), a rendezvous on a token, and the tunnel as a [`Link`]; no candidates and no probes (§10: relay-only in v1) | §10 |
//! | [`TransportManager`] | One attempt and one session per device pair, simultaneous-open resolution, the contact handshake on the winning link, the §13 unauthenticated-attempt budget, and the migration policy | §4, §5, §13 |
//! | [`capabilities`] | Which link kinds this build can use | §10.1 |
//!
//! # What is not here
//!
//! - **Wi-Fi peer-to-peer and AWDL adapters:** PROTOCOL §10.1 to §10.3
//!   define them (TCP carrying the unchanged session); they are built with
//!   the platform radio steps.
//! - **Bluetooth, USB, direct QUIC, and hole punching:** v1 has none
//!   (§10, §10.1). QUIC is used only to reach a relay.
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
#[cfg(all(feature = "relay", not(target_family = "wasm")))]
pub mod relay;
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
pub use tcp::{BindSocket, LanListener, TcpConnector, TcpLink};
#[cfg(not(target_family = "wasm"))]
pub use timer::TokioTimer;
