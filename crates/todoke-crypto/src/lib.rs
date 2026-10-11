//! Cryptographic orchestration and secret ownership for todoke.
//!
//! # Trust boundary
//!
//! Use reviewed libcrux, `RustCrypto`, or dalek implementations only. Secrets remain
//! inside Rust, are zeroized, and never reach logs or foreign interfaces.
//! Cryptographic primitives and hybrid handshake composition are not implemented here yet.
//!
//! # Status
//!
//! Empty scaffold: no protocol behavior or security guarantees are implemented.
//! Read `docs/DESIGN.md` and `spec/PROTOCOL.md` before adding behavior.

#![forbid(unsafe_code)]
