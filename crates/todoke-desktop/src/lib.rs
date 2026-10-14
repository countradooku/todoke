//! The todoke desktop app: a GPUI window (through gpui-kit) over the public
//! todoke core, for macOS, Windows, and Linux.
//!
//! # Trust boundary
//!
//! The window is a client of the core, nothing more. It holds no key, makes
//! no protocol or consent decision, and touches no received file: every
//! action is a [`todoke_core::api::Request`], every state change comes from
//! the core's answers and event stream ([`model`]). Names a peer chose are
//! escaped before they are shown ([`format::name`]); the receive sheet's
//! decisions are disabled for a moment after it appears, so a click aimed
//! at what was there before cannot accept an offer.
//!
//! # Pieces
//!
//! | Module | What it holds |
//! | --- | --- |
//! | [`tokens`] | Every color, space, radius, type size, and duration |
//! | [`format`] | Sizes, durations, fingerprints, kinds of file, escaping |
//! | [`icon`] | The todoke mark, drawn in code (tray, packaged icons) |
//! | [`launch`] | Command-line arguments, and handing them to a running window |
//! | [`model`] | The state, driven by events and answers (pure) |
//! | [`backend`] | Hosting the daemon, or attaching to a running one |
//! | [`prefs`] | `config.json`, relay lists, and the theme preference |
//! | [`outbox`] | Clipboard text sent as a private file |
//! | [`tray`] | The tray or menu-bar item |
//! | [`ui`] | The window: pages, the receive sheet, key bindings |
//!
//! Read `docs/adr/0010-desktop.md` before changing behavior.

#![forbid(unsafe_code)]

pub mod tokens;

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub mod backend;
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub mod format;
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub mod icon;
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub mod launch;
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub mod model;
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub mod outbox;
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub mod prefs;
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub mod tray;
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub mod ui;

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub use ui::run;
