//! The untrusted relay for encrypted todoke traffic (PROTOCOL §10).
//!
//! # Trust boundary
//!
//! Network clients and routing requests are untrusted, and endpoints treat
//! the relay itself as untrusted: it only matches two clients that know the
//! same rendezvous token and forwards their ciphertext. It never receives
//! pairing secrets, keys, manifests, or plaintext, and cannot authorize
//! anything. A malicious relay can drop, delay, replay, or misroute
//! traffic; the endpoints' Noise sessions detect it.
//!
//! # Pieces
//!
//! | Piece | What it does | Spec |
//! | --- | --- | --- |
//! | [`Relay`] | A node: QUIC v1 / TLS 1.3 (X25519MLKEM768 preferred, no 0-RTT, no resumption), address validation, per-source connection limits, two rooms per connection | §10 |
//! | rooms | The room table: two members per token, the record order, the 120-second room and 30-second wait, candidates passed once, `Forward` from both before `ForwardReady` | §10 |
//! | tunnels | Byte-ordered splicing, at most 1 MiB buffered per direction, a byte quota and lifetime (16 TiB, 24 hours at most) | §10 |
//! | [`Identity`] | A PEM certificate, or a self-signed one clients pin by key | §10 |
//! | [`Metrics`], [`serve_metrics`] | Totals only, for the operator (no client, token, address, or room) | §10, §14 |
//!
//! # What it never does
//!
//! It logs nothing about clients, keeps nothing after a room or tunnel
//! ends, adds no candidates of its own (which would reveal one client's
//! address to the other before they authenticate), and has no fallback for
//! an unknown record type.

#![forbid(unsafe_code)]

#[cfg(not(target_family = "wasm"))]
mod http;
#[cfg(not(target_family = "wasm"))]
mod rooms;
#[cfg(not(target_family = "wasm"))]
mod server;
#[cfg(not(target_family = "wasm"))]
mod tls;

#[cfg(not(target_family = "wasm"))]
pub use http::serve_metrics;
#[cfg(not(target_family = "wasm"))]
pub use server::{ALPN, Config, Metrics, Relay};
#[cfg(not(target_family = "wasm"))]
pub use tls::{Identity, PIN_PREFIX, format_pin, spki_pin};
