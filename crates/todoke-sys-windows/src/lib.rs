//! Windows platform integration behind safe Rust interfaces.
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
//! | [`autostart`] | Starting at login (the package's startup task, or the `Run` key) |
//! | [`context_menu`] | "Send with todoke" verbs in Explorer (unpackaged installs) |
//! | [`dpapi`] | The storage key under DPAPI, wrapped by the TPM where present |
//! | [`package`] | Whether todoke runs from its MSIX package |
//! | [`share_target`] | Files shared to todoke (MSIX) |
//!
//! Read `docs/adr/0011-os-integration.md` before adding behavior.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(windows)]
pub mod autostart;
#[cfg(windows)]
pub mod context_menu;
#[cfg(windows)]
pub mod dpapi;
#[cfg(windows)]
pub mod package;
#[cfg(windows)]
pub mod share_target;
