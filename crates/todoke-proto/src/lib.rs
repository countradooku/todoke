//! Wire-format definitions and bounded parsing for the todoke protocol.
//!
//! # Trust boundary
//!
//! Every peer-provided field is untrusted. Parsing must be bounded and fallible;
//! syntactic validity must never imply authentication or consent.
//!
//! # Status
//!
//! Empty scaffold: no protocol behavior or security guarantees are implemented.
//! Read `docs/DESIGN.md` and `spec/PROTOCOL.md` before adding behavior.

#![forbid(unsafe_code)]
