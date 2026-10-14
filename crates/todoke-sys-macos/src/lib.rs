//! macOS platform integration behind safe Rust interfaces.
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
//! | [`keychain`] | The storage key in the Keychain, wrapped by the Secure Enclave where entitled |
//! | [`login_item`] | Starting at login (a bundled launch agent, `SMAppService`) |
//! | [`services`] | "Send with todoke" in Finder's Quick Actions and the Services menu |
//!
//! Read `docs/adr/0011-os-integration.md` before adding behavior.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_os = "macos")]
pub mod keychain;
#[cfg(all(target_os = "macos", feature = "desktop"))]
pub mod login_item;
#[cfg(all(target_os = "macos", feature = "desktop"))]
pub mod services;
