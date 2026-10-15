//! The thin `BoltFFI` boundary for mobile and web clients: the core as
//! Swift, Kotlin, and TypeScript see it.
//!
//! # Trust boundary
//!
//! Foreign callers, handles, buffers, lifetimes, and cancellation are
//! untrusted. What crosses is opaque handles ([`Core`], [`ContactHandle`],
//! [`TransferHandle`], [`QrOffer`], [`CodeOffer`], [`Events`]), blocking
//! commands (no Rust future crosses), plain values without secrets, events,
//! and typed errors. No identity key, pairing key,
//! session state, or file byte crosses: the core reads and writes files
//! at the paths the app passes in. The exceptions, each explicit:
//!
//! - the storage key, between the core and the app's [`KeyStore`] (the
//!   only way to keep it in Android's Keystore);
//! - a pairing offer's text, only when the app calls [`QrOffer::text`],
//!   and a pairing code, only through [`CodeOffer::code`] (the user must
//!   see it).
//!
//! Peer-chosen names are escaped before they cross. The glue `BoltFFI`
//! generates is the only unsafe code (docs/adr/0012-bindings.md).
//!
//! # Pieces
//!
//! | Module | What it holds |
//! | --- | --- |
//! | [`engine`] | [`Core`]: starting, commands, subscriptions |
//! | [`events`] | [`Events`]: a subscription's queue |
//! | [`handles`] | [`ContactHandle`], [`TransferHandle`] |
//! | [`hooks`] | What the app implements: [`KeyStore`], [`Notifier`], [`RadioLink`] |
//! | [`types`] | Plain values: statuses, contacts, transfers, offers, events |
//! | [`error`] | [`TodokeError`] |
//! | [`qr`] | [`QrOffer`], drawn as modules |
//! | [`code`] | [`CodeOffer`] |

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(target_family = "wasm"))]
mod block;
pub mod code;
mod config;
pub mod engine;
pub mod error;
pub mod events;
#[cfg(unix)]
mod fds;
#[cfg(not(target_family = "wasm"))]
mod forward;
pub mod handles;
pub mod hooks;
mod keys;
pub mod qr;
pub mod types;

pub use code::CodeOffer;
pub use engine::Core;
pub use error::TodokeError;
pub use events::Events;
pub use handles::{ContactHandle, TransferHandle};
pub use hooks::{KeyStore, KeyStoreError, LinkError, LinkKind, Notifier, OfferNotice, RadioLink};
pub use qr::QrOffer;
