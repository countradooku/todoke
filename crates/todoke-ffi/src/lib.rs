//! The thin `BoltFFI` boundary for mobile and web clients.
//!
//! # Trust boundary
//!
//! Foreign callers, handles, buffers, lifetimes, and cancellation are untrusted.
//! No secret may cross FFI. Keep protocol, cryptographic, and file logic in the
//! Rust core. Future unsafe code is limited to reviewed binding mechanics.
//!
//! # Status
//!
//! Empty scaffold: no protocol behavior or security guarantees are implemented.
//! Read `docs/DESIGN.md` and `spec/PROTOCOL.md` before adding behavior.

#![deny(unsafe_op_in_unsafe_fn)]
