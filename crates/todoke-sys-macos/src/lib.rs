//! Apple platform integration behind safe Rust interfaces: macOS, and the
//! Keychain on iOS.
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
//! | [`bonjour`] | `_todoke._tcp` through `dns_sd` (mDNSResponder), for iOS, where raw multicast needs a restricted entitlement |
//! | [`keychain`] | The storage key in the Keychain (macOS and iOS), wrapped by the Secure Enclave where entitled, optionally needing the user's presence |
//! | [`login_item`] | Starting at login (a bundled launch agent, `SMAppService`) |
//! | [`services`] | "Send with todoke" in Finder's Quick Actions and the Services menu |
//!
//! Read `docs/adr/0011-os-integration.md` before adding behavior.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod bonjour;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod keychain;
#[cfg(all(target_os = "macos", feature = "desktop"))]
pub mod login_item;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod p2p;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod route;
#[cfg(all(target_os = "macos", feature = "desktop"))]
pub mod services;
