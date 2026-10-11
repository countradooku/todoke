//! Cryptographic orchestration and secret ownership for todoke.
//!
//! # Trust boundary
//!
//! Use reviewed libcrux, `RustCrypto`, or dalek implementations only. Secrets remain
//! inside Rust, are zeroized, and never reach logs or foreign interfaces.
//!
//! # Status
//!
//! Implemented: device and person identities, `DeviceBinding` and `Revoke`
//! issuance and verification, a key store interface with an encrypted software
//! backend, and a contact store (see [`identity`]). Noise sessions, the PSK
//! ratchet, and content encryption are not implemented yet; production sessions
//! remain disabled by PROTOCOL §16.
//! Read `docs/DESIGN.md` and `spec/PROTOCOL.md` before adding behavior.

#![forbid(unsafe_code)]

pub mod identity;
mod rng;
