//! The public Rust facade for todoke sessions and transfers.
//!
//! # Trust boundary
//!
//! All UI, CLI, daemon, and binding requests are untrusted inputs to the core.
//! Protocol, cryptography, file logic, and consent remain owned by Rust.
//! This facade exports no operations until their protocol behavior is specified.
//!
//! # Status
//!
//! Empty scaffold: no protocol behavior or security guarantees are implemented.
//! Read `docs/DESIGN.md` and `spec/PROTOCOL.md` before adding behavior.

#![forbid(unsafe_code)]
