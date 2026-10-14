//! Linux platform integration behind safe Rust interfaces.
//!
//! # Trust boundary
//!
//! OS APIs, foreign buffers, callbacks, and lifetimes form this boundary.
//! Reviewed unsafe code may bridge platform APIs, but no protocol, cryptographic,
//! or transfer consent logic belongs here.
//!
//! # Pieces
//!
//! | Module | What it binds |
//! | --- | --- |
//! | [`secret_service`] | The storage key in the freedesktop Secret Service |
//! | [`tray`] | Whether a StatusNotifierItem host shows tray items |
//!
//! Read `docs/adr/0011-os-integration.md` before adding behavior.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_os = "linux")]
pub mod secret_service;
#[cfg(target_os = "linux")]
pub mod tray;
