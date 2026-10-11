//! Transfer coordination, consent enforcement, and verified file delivery.
//!
//! # Trust boundary
//!
//! Peer input and transport delivery are untrusted. No file byte may be accepted
//! before a signed `AcceH` is verified by the core. Future state machines require
//! proptest state-machine tests; this scaffold defines no transitions.
//!
//! # Status
//!
//! Empty scaffold: no protocol behavior or security guarantees are implemented.
//! Read `docs/DESIGN.md` and `spec/PROTOCOL.md` before adding behavior.

#![forbid(unsafe_code)]
