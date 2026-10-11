//! The thin GPUI desktop interface to the public todoke core.
//!
//! # Trust boundary
//!
//! UI events, displayed peer data, and platform callbacks are untrusted.
//! The core owns protocol, cryptography, consent, and file operations.
//! This library scaffold does not yet create a window or depend on GPUI.
//!
//! # Status
//!
//! Empty scaffold: no protocol behavior or security guarantees are implemented.
//! Read `docs/DESIGN.md` and `spec/PROTOCOL.md` before adding behavior.

#![forbid(unsafe_code)]
