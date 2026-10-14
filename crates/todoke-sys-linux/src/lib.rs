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
//! | [`autostart`] | Starting at login (XDG autostart, or the Background portal) |
//! | [`desktop_entry`] | Quoting for desktop entries |
//! | [`file_managers`] | "Send with todoke" in Dolphin, Nemo, and Nautilus |
//! | [`global_shortcuts`] | A global shortcut through the `GlobalShortcuts` portal |
//! | [`portal`] | XDG desktop portal requests |
//! | [`secret_service`] | The storage key in the freedesktop Secret Service |
//! | [`tray`] | Whether a `StatusNotifierItem` host shows tray items |
//!
//! Read `docs/adr/0011-os-integration.md` before adding behavior.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(all(target_os = "linux", feature = "desktop"))]
pub mod autostart;
#[cfg(all(target_os = "linux", feature = "desktop"))]
pub mod desktop_entry;
#[cfg(all(target_os = "linux", feature = "desktop"))]
pub mod file_managers;
#[cfg(all(target_os = "linux", feature = "desktop"))]
pub mod global_shortcuts;
#[cfg(all(target_os = "linux", feature = "desktop"))]
pub mod portal;
#[cfg(target_os = "linux")]
pub mod secret_service;
#[cfg(all(target_os = "linux", feature = "desktop"))]
pub mod tray;
