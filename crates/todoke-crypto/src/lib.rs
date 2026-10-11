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
//! backend, and a contact store (see [`identity`]); and suite 0x0001 sessions
//! (see [`session`]): the hybrid `IKpsk2`/`KKpsk2`/`XXpsk3` handshakes, identity
//! confirmation, the PSK ratchet with its durable journal and crash policy,
//! encrypted framing, rekey, and keepalive. Sessions are **not production
//! enabled**: every entry point takes an
//! [`UnauditedSuite0001`](session::UnauditedSuite0001) acknowledgement because
//! PROTOCOL §16 keeps the suite disabled until gates O6 and O10 close
//! (`docs/adr/0001-noise-crate.md`). Pairing flows, Capabilities, transfers, and
//! content encryption are not implemented yet.
//! Read `docs/DESIGN.md` and `spec/PROTOCOL.md` before adding behavior.

#![forbid(unsafe_code)]

pub mod identity;
mod rng;
pub mod session;
