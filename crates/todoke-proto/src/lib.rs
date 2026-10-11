//! Wire-format definitions and bounded parsing for the todoke protocol.
//!
//! # Trust boundary
//!
//! Every peer-provided field is untrusted. Parsing must be bounded and fallible;
//! syntactic validity must never imply authentication or consent.
//!
//! # Status
//!
//! Implemented: the fixed layouts of `DeviceBinding` and `Revoke` (PROTOCOL §2)
//! and the protocol Unix time range (§1). Decoding checks layout only; key
//! validation and signature verification belong to `todoke-crypto`. No other
//! wire message, framing, or state machine is implemented yet.
//! Read `docs/DESIGN.md` and `spec/PROTOCOL.md` before adding behavior.

#![forbid(unsafe_code)]

pub mod identity;
pub mod time;
