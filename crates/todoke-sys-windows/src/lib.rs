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
//! | [`activation`] | How the package was started: at login, by the Share sheet |
//! | [`autostart`] | Starting at login (the package's startup task, or the `Run` key) |
//! | [`context_menu`] | "Send with todoke" verbs in Explorer (unpackaged installs) |
//! | [`dpapi`] | The storage key under DPAPI, wrapped by the TPM where present |
//! | [`package`] | Whether todoke runs from its MSIX package |
//!
//! Read `docs/adr/0011-os-integration.md` before adding behavior.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(all(windows, feature = "desktop"))]
pub mod activation;
#[cfg(all(windows, feature = "desktop"))]
pub mod autostart;
#[cfg(all(windows, feature = "desktop"))]
pub mod context_menu;
#[cfg(windows)]
pub mod dpapi;
#[cfg(all(windows, feature = "desktop"))]
pub mod package;
