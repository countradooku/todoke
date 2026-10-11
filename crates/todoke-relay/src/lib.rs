//! The untrusted QUIC relay service for encrypted todoke traffic.
//!
//! # Trust boundary
//!
//! Network clients and routing requests are untrusted. The relay must never own
//! endpoint secrets or plaintext file content, and cannot authorize transfers.
//! This library scaffold does not yet provide a relay executable.
//!
//! # Status
//!
//! Empty scaffold: no protocol behavior or security guarantees are implemented.
//! Read `docs/DESIGN.md` and `spec/PROTOCOL.md` before adding behavior.

#![forbid(unsafe_code)]
