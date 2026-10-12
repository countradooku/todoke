//! Wire-format definitions and bounded parsing for the todoke protocol.
//!
//! # Trust boundary
//!
//! Every peer-provided field is untrusted. Parsing must be bounded and fallible;
//! syntactic validity must never imply authentication or consent.
//!
//! # Status
//!
//! Implemented: the fixed layouts of `DeviceBinding` and `Revoke` (PROTOCOL §2),
//! the protocol Unix time range (§1), and the session records of [`session`]:
//! prelude framing, `ClientHello`/`ServerHello`, `NoiseHandshake` framing
//! (§4.1, §4.2.5), the transport frame header and registry (§5), and the
//! `Identity`, ratchet, `KeyUpdate`, `Ping`/`Pong`, and `Error` bodies (§4.3,
//! §4.4, §12, §13). Decoding checks layout only; key validation, signature
//! verification, decryption, and state machines belong to `todoke-crypto`.
//! Code-pairing bodies (§3.2), Capabilities, transfer, and discovery records
//! are not implemented yet.
//! Read `docs/DESIGN.md` and `spec/PROTOCOL.md` before adding behavior.

#![forbid(unsafe_code)]

pub mod identity;
pub mod session;
pub mod time;
