//! The public Rust facade for todoke sessions and transfers.
//!
//! # Trust boundary
//!
//! All UI, CLI, daemon, and binding requests are untrusted inputs to the core.
//! Protocol, cryptography, file logic, and consent remain owned by Rust.
//!
//! # Status
//!
//! Read `docs/DESIGN.md`, `spec/PROTOCOL.md`, and
//! `docs/adr/0008-core-daemon-cli.md` before adding behavior.

#![forbid(unsafe_code)]

pub mod api;
pub mod config;
#[cfg(all(not(target_family = "wasm"), feature = "unaudited-dev"))]
mod discovery;
#[cfg(not(target_family = "wasm"))]
pub mod history;
pub mod link;
pub mod profile;
#[cfg(not(target_family = "wasm"))]
pub mod runtime;
#[cfg(not(target_family = "wasm"))]
pub mod send;
pub mod storage_key;

pub use profile::{Profile, ProfileError};
#[cfg(not(target_family = "wasm"))]
pub use runtime::{Core, StartError};
pub use storage_key::{KeyFile, StorageKeySource};
