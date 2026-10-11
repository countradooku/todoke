//! Candidate peer discovery and reachability information.
//!
//! # Trust boundary
//!
//! Advertisements, device names, addresses, and proximity are untrusted hints.
//! Only the authenticated core session may establish a peer's identity.
//!
//! # Status
//!
//! Empty scaffold: no protocol behavior or security guarantees are implemented.
//! Read `docs/DESIGN.md` and `spec/PROTOCOL.md` before adding behavior.

#![forbid(unsafe_code)]
