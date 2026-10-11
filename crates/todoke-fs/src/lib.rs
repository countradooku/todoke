//! Filesystem operations and safe destination handling for transfers.
//!
//! # Trust boundary
//!
//! Remote filenames, paths, metadata, and local filesystem races are untrusted.
//! File operations must enforce the core's consent and verified-chunk decisions.
//!
//! # Status
//!
//! Empty scaffold: no protocol behavior or security guarantees are implemented.
//! Read `docs/DESIGN.md` and `spec/PROTOCOL.md` before adding behavior.

#![forbid(unsafe_code)]
