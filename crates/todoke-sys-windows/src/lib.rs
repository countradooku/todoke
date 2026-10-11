//! Windows platform integration behind safe Rust interfaces.
//!
//! # Trust boundary
//!
//! OS APIs, foreign buffers, callbacks, and lifetimes form this boundary.
//! Reviewed unsafe code may bridge platform APIs, but no protocol, cryptographic,
//! or transfer consent logic belongs here. No Windows API is bound yet.
//!
//! # Status
//!
//! Empty scaffold: no protocol behavior or security guarantees are implemented.
//! Read `docs/DESIGN.md` and `spec/PROTOCOL.md` before adding behavior.

#![deny(unsafe_op_in_unsafe_fn)]
