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
//! | [`dpapi`] | The storage key under DPAPI, wrapped by the TPM where present |
//!
//! Read `docs/adr/0011-os-integration.md` before adding behavior.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(windows)]
pub mod dpapi;
