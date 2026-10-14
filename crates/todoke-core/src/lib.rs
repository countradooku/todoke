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

pub mod profile;
pub mod storage_key;

pub use profile::{Profile, ProfileError};
pub use storage_key::{KeyFile, StorageKeySource};
