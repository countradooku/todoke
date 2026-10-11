//! Constrained previews of consented, verified file content.
//!
//! # Trust boundary
//!
//! File contents and metadata remain hostile even after sender authentication.
//! Preview work must not bypass core consent, chunk verification, or resource limits.
//!
//! # Status
//!
//! Empty scaffold: no protocol behavior or security guarantees are implemented.
//! Read `docs/DESIGN.md` and `spec/PROTOCOL.md` before adding behavior.

#![forbid(unsafe_code)]
